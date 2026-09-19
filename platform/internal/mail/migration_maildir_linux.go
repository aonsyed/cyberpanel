//go:build linux

package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

const MailBrokerMaildirImport MailBrokerOperation = "maildir_import"
const maximumMaildirChunkBytes = int(migration.MaildirTransportChunkMax)

// This boundary is deliberately dark-only. It cannot publish a mailbox or
// accept an asserted source-fence token. The migration coordinator must verify
// its durable source fence before any separate mail configuration activation.
type MaildirImportRequest struct {
	Operation     string                     `json:"operation"`
	ImportID      string                     `json:"import_id"`
	TenantID      string                     `json:"tenant_id"`
	SiteID        string                     `json:"site_id"`
	DomainID      DomainID                   `json:"domain_id"`
	MailboxID     MailboxID                  `json:"mailbox_id"`
	Domain        string                     `json:"domain"`
	Local         string                     `json:"local"`
	CredentialRef MailboxCredentialRef       `json:"credential_ref"`
	QuotaBytes    uint64                     `json:"quota_bytes"`
	SourceDigest  string                     `json:"source_digest"`
	ManifestRoot  string                     `json:"manifest_root"`
	Manifest      *migration.MaildirManifest `json:"manifest,omitempty"`
	Sequence      uint64                     `json:"sequence,omitempty"`
	ChunkDigest   string                     `json:"chunk_digest,omitempty"`
	Data          []byte                     `json:"data,omitempty"`
}

func (request MaildirImportRequest) Validate() error {
	if !validOpaque(request.ImportID) || !validOpaque(request.TenantID) || !validOpaque(request.SiteID) || !validOpaque(string(request.DomainID)) || !validOpaque(string(request.MailboxID)) || !validHostname(request.Domain) || request.Domain != strings.ToLower(request.Domain) || !validLocalPart(request.Local) || request.Local != strings.ToLower(request.Local) || request.CredentialRef == "" || !validOpaque(string(request.CredentialRef)) || request.QuotaBytes == 0 || request.QuotaBytes > migration.MaildirMailboxMaxBytes || !validMailEvidenceDigest(request.SourceDigest) || !validMailEvidenceDigest(request.ManifestRoot) {
		return ErrInvalidCommand
	}
	switch request.Operation {
	case "begin":
		if request.Manifest == nil || request.Manifest.Validate() != nil || request.Manifest.RootDigest != request.ManifestRoot || request.Manifest.TotalBytes > request.QuotaBytes || request.Sequence != 0 || request.ChunkDigest != "" || len(request.Data) != 0 {
			return ErrInvalidCommand
		}
	case "chunk":
		if request.Manifest != nil || len(request.Data) == 0 || len(request.Data) > maximumMaildirChunkBytes || !validMailEvidenceDigest(request.ChunkDigest) {
			return ErrInvalidCommand
		}
		sum := sha256.Sum256(request.Data)
		if hex.EncodeToString(sum[:]) != request.ChunkDigest {
			return ErrInvalidCommand
		}
	case "seal", "observe", "discard":
		if request.Manifest != nil || request.Sequence != 0 || request.ChunkDigest != "" || len(request.Data) != 0 {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

type MaildirImportReceipt struct {
	ImportID       string    `json:"import_id"`
	SourceDigest   string    `json:"source_digest"`
	ManifestRoot   string    `json:"manifest_root"`
	EvidenceDigest string    `json:"evidence_digest"`
	State          string    `json:"state"`
	NextChunk      uint64    `json:"next_chunk"`
	Bytes          uint64    `json:"bytes"`
	Objects        uint64    `json:"objects"`
	ObservedAt     time.Time `json:"observed_at"`
}

func (receipt MaildirImportReceipt) valid(request MaildirImportRequest) bool {
	return receipt.ImportID == request.ImportID && receipt.SourceDigest == request.SourceDigest && receipt.ManifestRoot == request.ManifestRoot && validMailEvidenceDigest(receipt.EvidenceDigest) && (receipt.State == "receiving" || receipt.State == "sealed" || receipt.State == "discarded") && receipt.Bytes <= request.QuotaBytes && receipt.Objects <= migration.MaildirManifestMaxFiles && !receipt.ObservedAt.IsZero()
}

func (client *MailDaemonClient) ImportMaildir(ctx context.Context, request MaildirImportRequest) (MaildirImportReceipt, error) {
	response, err := client.request(ctx, MailBrokerRequest{Operation: MailBrokerMaildirImport, Maildir: &request})
	if response.Maildir == nil {
		if err != nil {
			return MaildirImportReceipt{}, err
		}
		return MaildirImportReceipt{}, ErrInvalidReceipt
	}
	return *response.Maildir, err
}

type maildirManifest struct {
	Version  uint8
	Binding  maildirImportBinding
	Manifest migration.MaildirManifest
	UID, GID uint32
}
type maildirImportBinding struct {
	ImportID      string
	TenantID      string
	SiteID        string
	DomainID      DomainID
	MailboxID     MailboxID
	Domain        string
	Local         string
	CredentialRef MailboxCredentialRef
	QuotaBytes    uint64
	SourceDigest  string
	ManifestRoot  string
}
type maildirTransferJournal struct {
	Version   uint8
	State     string
	NextChunk uint64
	UID, GID  uint32
	UpdatedAt time.Time
}

func (host *LinuxMailHost) mailboxIdentity(tenant, siteID string) (siteops.RuntimeBinding, error) {
	if host == nil || host.SiteRegistry == nil {
		return siteops.RuntimeBinding{}, ErrUnauthorized
	}
	identity, found, err := host.SiteRegistry.BindingForSite(siteID)
	if err != nil || !found || identity.Validate() != nil || identity.TenantID != tenant || identity.SiteID != siteID || identity.State != siteops.BindingActive && identity.State != siteops.BindingSuspended || identity.UID < 200000 || identity.UID > 599999 {
		return identity, ErrUnauthorized
	}
	return identity, nil
}

func (host *LinuxMailHost) ImportMaildir(ctx context.Context, request MaildirImportRequest) (MaildirImportReceipt, error) {
	if ctx == nil || request.Validate() != nil {
		return MaildirImportReceipt{}, ErrInvalidCommand
	}
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	identity, err := host.mailboxIdentity(request.TenantID, request.SiteID)
	if err != nil {
		return MaildirImportReceipt{}, err
	}
	root, err := openMailProductRoot()
	if err != nil {
		return MaildirImportReceipt{}, err
	}
	defer syscall.Close(root)
	imports, err := mailDirectory(root, "mail-imports", request.Operation == "begin")
	if err != nil {
		if request.Operation != "begin" && errors.Is(err, syscall.ENOENT) {
			return MaildirImportReceipt{}, ErrNotFound
		}
		return MaildirImportReceipt{}, err
	}
	defer syscall.Close(imports)
	id := digestMailEvidence(request.TenantID, string(request.DomainID), string(request.MailboxID), request.ImportID)
	directory, err := mailDirectory(imports, id, request.Operation == "begin")
	if err != nil {
		if request.Operation != "begin" && errors.Is(err, syscall.ENOENT) {
			return MaildirImportReceipt{}, ErrNotFound
		}
		return MaildirImportReceipt{}, err
	}
	defer syscall.Close(directory)
	if err = cleanupMaildirTemporaries(directory); err != nil {
		return MaildirImportReceipt{}, err
	}
	if request.Operation == "begin" {
		return host.beginMaildirTransfer(ctx, directory, request, identity)
	}
	receipt, err := host.mutateMaildirTransfer(ctx, directory, request, identity)
	if request.Operation == "observe" && errors.Is(err, syscall.ENOENT) {
		return MaildirImportReceipt{}, ErrNotFound
	}
	return receipt, err
}

// The kernel confines every relative read/write to one mount beneath this
// root, with no symlink or magic-link traversal. Kernels lacking openat2 fail
// closed. No process executable, environment PATH or caller filesystem path.
func mailOpenAt(directory int, name string, flags int, mode uint32, crossMount bool) (int, error) {
	value, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	resolve := uint64(0x0f)
	if crossMount {
		resolve = 0x0e
	}
	how := struct{ Flags, Mode, Resolve uint64 }{uint64(flags | syscall.O_CLOEXEC | syscall.O_NOFOLLOW), uint64(mode), resolve}
	fd, _, errno := syscall.Syscall6(437, uintptr(directory), uintptr(unsafe.Pointer(value)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func openMailProductRoot() (int, error) {
	root, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range []string{"var", "lib", "cyberpanel"} {
		fd, err := mailOpenAt(root, component, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, true)
		syscall.Close(root)
		if err != nil {
			return -1, err
		}
		var stat syscall.Stat_t
		if syscall.Fstat(fd, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 {
			syscall.Close(fd)
			return -1, ErrUnauthorized
		}
		root = fd
	}
	return root, nil
}

func mailDirectory(root int, name string, create bool) (int, error) {
	if create {
		parent, err := mailOpenAt(root, path.Dir(name), syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		if err != nil {
			return -1, err
		}
		err = syscall.Mkdirat(parent, path.Base(name), 0700)
		if err == nil {
			err = syscall.Fsync(parent)
		}
		syscall.Close(parent)
		if err != nil && err != syscall.EEXIST {
			return -1, err
		}
	}
	fd, err := mailOpenAt(root, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
	if err != nil {
		return -1, err
	}
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Uid != 0 || stat.Mode&0077 != 0 {
		syscall.Close(fd)
		return -1, ErrUnauthorized
	}
	return fd, nil
}

func readMailImportFile(root int, name string, maximum int64) ([]byte, error) {
	fd, err := mailOpenAt(root, name, syscall.O_RDONLY, 0, false)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "mail-import")
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || stat.Uid != 0 || stat.Nlink != 1 || before.Size() > maximum {
		return nil, ErrUnauthorized
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		wipeMailBytes(content)
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || int64(len(content)) != before.Size() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		wipeMailBytes(content)
		return nil, ErrConflict
	}
	return content, nil
}

func writeMailImportFile(root int, name string, content []byte) error {
	prior, err := readMailImportFile(root, name, int64(len(content)))
	defer wipeMailBytes(prior)
	if err == nil {
		if !bytes.Equal(prior, content) {
			return ErrConflict
		}
		return nil
	}
	if err != syscall.ENOENT {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := path.Join(path.Dir(name), ".import-"+hex.EncodeToString(random[:]))
	fd, err := mailOpenAt(root, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600, false)
	if err != nil {
		return err
	}
	defer syscall.Unlinkat(root, temporary)
	file := os.NewFile(uintptr(fd), "mail-import")
	defer file.Close()
	if _, err := io.Copy(file, bytes.NewReader(content)); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(root, temporary, root, name); err != nil {
		return err
	}
	parent, err := mailOpenAt(root, path.Dir(name), syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
	if err != nil {
		return err
	}
	defer syscall.Close(parent)
	return syscall.Fsync(parent)
}

func (host *LinuxMailHost) mailboxArtifacts(ctx context.Context, snapshot ConfigSnapshot) ([]daemoncfg.Artifact, error) {
	resolver, ok := host.Material.(interface {
		ResolveMailboxHash(context.Context, string, DomainID, MailboxID, MailboxCredentialRef) ([]byte, error)
	})
	var users bytes.Buffer
	defer func() { wipeMailBytes(users.Bytes()) }()
	seen := make(map[string]bool)
	for _, projection := range snapshot.Domains {
		for _, mailbox := range projection.Mailboxes {
			if !mailbox.Enabled {
				continue
			}
			if !ok || !validLocalPart(mailbox.Local) || mailbox.Domain != projection.Domain.ID || mailbox.CredentialRef == "" || len(seen) >= 10000 {
				return nil, ErrInvalidCommand
			}
			address := mailbox.Local + "@" + projection.Domain.Name
			if seen[address] || ValidateAddress(Address(address)) != nil {
				return nil, ErrInvalidCommand
			}
			seen[address] = true
			identity, err := host.mailboxIdentity(projection.Domain.Tenant, mailbox.SiteID)
			if err != nil {
				return nil, err
			}
			// Ordinary generations require the already-published tenant Maildir.
			// A reserved migration generation is rendered while its exact Maildir
			// is still dark; its publisher verifies and moves that owned tree before
			// this candidate can become current.
			if !projection.Domain.StaticRoutes {
				root, err := openMailProductRoot()
				if err != nil {
					return nil, err
				}
				fd, err := mailOpenAt(root, "mailboxes/"+projection.Domain.Name+"/"+mailbox.Local+"/Maildir", syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
				syscall.Close(root)
				if err != nil {
					return nil, err
				}
				var stat syscall.Stat_t
				statErr := syscall.Fstat(fd, &stat)
				syscall.Close(fd)
				if statErr != nil || stat.Uid != identity.UID || stat.Gid != identity.GID || stat.Mode&0077 != 0 {
					return nil, ErrUnauthorized
				}
			}
			hash, err := resolver.ResolveMailboxHash(ctx, projection.Domain.Tenant, projection.Domain.ID, mailbox.ID, mailbox.CredentialRef)
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(&users, "%s:%s:%d:%d::/var/lib/cyberpanel/mailboxes/%s/%s::userdb_quota_rule=*:storage=%dB\n", address, hash, identity.UID, identity.GID, projection.Domain.Name, mailbox.Local, mailbox.QuotaBytes)
			wipeMailBytes(hash)
			if users.Len() > 4<<20 {
				return nil, ErrInvalidCommand
			}
		}
	}
	content := append([]byte(nil), users.Bytes()...)
	sum := sha256.Sum256(content)
	return []daemoncfg.Artifact{{Path: "dovecot/users", Mode: 0440, GID: host.Ownership.DovecotGID, Content: content, SHA256: hex.EncodeToString(sum[:])}}, nil
}
