//go:build linux

package management

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

const privateTLSRoot = "/var/lib/cyberpanel/certificates"

func validatePrivateTLSMaterials(render native.RenderRequest, values []PrivateTLSMaterial, now time.Time) error {
	if len(values) == 0 || len(values) > 16 || now.IsZero() {
		return ErrInvalid
	}
	seen := make(map[native.MaterialKey]bool, len(values))
	for _, value := range values {
		if seen[value.MaterialKey] || !validPrivateTLSKey(string(value.MaterialKey)) || value.Generation == 0 || !validSHA256(value.FingerprintSHA256) {
			return ErrInvalid
		}
		seen[value.MaterialKey] = true
		hostname, err := webengine.ParseHostname(value.Hostname)
		if err != nil || hostname.String() != value.Hostname {
			return ErrInvalid
		}
		var policy webengine.ResourceRef
		for _, material := range render.Snapshot.TLSMaterials {
			if material.MaterialKey != value.MaterialKey || material.Generation != value.Generation {
				continue
			}
			if policy != "" {
				return ErrConflict
			}
			policy = material.PolicyRef
		}
		if policy == "" {
			return ErrConflict
		}
		bound := false
		for _, binding := range render.Desired.Bindings {
			if binding.TLSPolicyRef != policy || binding.RoutingState != webengine.RoutingServe {
				continue
			}
			for _, candidate := range binding.Hostnames {
				if candidate.String() == value.Hostname {
					bound = true
				}
			}
		}
		if !bound || validatePrivateTLSCandidate(value, now) != nil {
			return ErrConflict
		}
	}
	return nil
}

func validatePrivateTLSCandidate(value PrivateTLSMaterial, now time.Time) error {
	root := filepath.Join(privateTLSRoot, "generations", "webengine", string(value.MaterialKey))
	path := filepath.Clean(value.CandidatePath)
	if !filepath.IsAbs(path) || !pathBelow(root, path) {
		return ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !privateTLSDirectory(info, 0o750) {
		return ErrInvalid
	}
	files := map[string]os.FileMode{"certificate.pem": 0o440, "chain.pem": 0o440, "fullchain.pem": 0o440, "private.key": 0o400, ".stage-owner": 0o400}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != len(files) {
		return ErrInvalid
	}
	for _, entry := range entries {
		mode, ok := files[entry.Name()]
		if !ok {
			return ErrInvalid
		}
		fileInfo, statErr := os.Lstat(filepath.Join(path, entry.Name()))
		if statErr != nil || !privateTLSFile(fileInfo, mode) {
			return ErrInvalid
		}
	}
	fullchain, err := os.ReadFile(filepath.Join(path, "fullchain.pem"))
	if err != nil || len(fullchain) == 0 || len(fullchain) > 1<<20 {
		return ErrInvalid
	}
	privateKey, err := os.ReadFile(filepath.Join(path, "private.key"))
	if err != nil || len(privateKey) == 0 || len(privateKey) > 1<<20 {
		wipePrivateTLS(privateKey)
		return ErrInvalid
	}
	defer wipePrivateTLS(privateKey)
	pair, err := tls.X509KeyPair(fullchain, privateKey)
	if err != nil || len(pair.Certificate) == 0 {
		return ErrInvalid
	}
	certificates := make([]*x509.Certificate, 0, len(pair.Certificate))
	for _, raw := range pair.Certificate {
		certificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return ErrInvalid
		}
		certificates = append(certificates, certificate)
	}
	leaf := certificates[0]
	if leaf.NotBefore.After(now.Add(time.Minute)) || !leaf.NotAfter.After(now) || leaf.VerifyHostname(value.Hostname) != nil {
		return ErrConflict
	}
	for index := 1; index < len(certificates); index++ {
		if !certificates[index].IsCA || certificates[index-1].CheckSignatureFrom(certificates[index]) != nil {
			return ErrInvalid
		}
	}
	sum := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(sum[:]) != value.FingerprintSHA256 {
		return ErrConflict
	}
	return nil
}

func mountPrivateTLSMaterials(values []PrivateTLSMaterial) error {
	for _, value := range values {
		consumerRoot := filepath.Join(privateTLSRoot, "consumers", "webengine", string(value.MaterialKey))
		info, err := os.Lstat(consumerRoot)
		if err != nil || !privateTLSDirectory(info, 0o750) {
			return ErrInvalid
		}
		resolved, err := filepath.EvalSymlinks(consumerRoot)
		if err != nil || resolved != consumerRoot {
			return ErrInvalid
		}
		if err = syscall.Mount("tmpfs", consumerRoot, "tmpfs", syscall.MS_NODEV|syscall.MS_NOSUID|syscall.MS_NOEXEC, "mode=0750,size=1m"); err != nil {
			return err
		}
		current := filepath.Join(consumerRoot, "current")
		if err = os.Mkdir(current, 0o700); err != nil {
			return err
		}
		if err = syscall.Mount(value.CandidatePath, current, "", syscall.MS_BIND, ""); err != nil {
			return err
		}
		if err = syscall.Mount("", current, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NODEV|syscall.MS_NOSUID|syscall.MS_NOEXEC, ""); err != nil {
			return err
		}
	}
	return nil
}

func validPrivateTLSKey(value string) bool {
	if value == "" || len(value) > 96 || value == "." || value == ".." || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if character != '-' && character != '_' && character != '.' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func pathBelow(root, target string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	return err == nil && relative != "." && relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}
func privateTLSDirectory(info os.FileInfo, mode os.FileMode) bool {
	metadata, ok := fileOwner(info)
	return ok && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == mode.Perm() && metadata.Uid == 0 && metadata.Gid == 0
}
func privateTLSFile(info os.FileInfo, mode os.FileMode) bool {
	metadata, ok := fileOwner(info)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == mode.Perm() && metadata.Uid == 0 && metadata.Gid == 0 && metadata.Nlink == 1
}
func fileOwner(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	return metadata, ok
}
func wipePrivateTLS(values ...[]byte) {
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
	}
}
