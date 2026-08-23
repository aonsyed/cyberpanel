//go:build linux

// Package cyberpanelbackup is the disposable boundary for legacy CyberPanel
// backup artifacts. Nothing outside this package interprets meta.xml or archive
// layout, and admission only quarantines verified evidence; it never imports it.
package cyberpanelbackup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	legacy "github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanel"
)

const (
	DefaultIntakePath = "/var/lib/cyberpanel/migration/cyberpanel-backup-intake"
	DefaultQuarantinePath = "/var/lib/cyberpanel/migration/cyberpanel-backup-quarantine"
	maximumManifestBytes = int64(32<<20) + 1
	maximumMetadataBytes = int64(16 << 20)
	maximumCompressedBytes = int64(2 << 40)
	maximumExpandedBytes = uint64(2 << 40)
	maximumArchiveEntries = 250000
	maximumExpansionRatio = uint64(512)
	backupSchemaContract = "cyberpanel-backup-meta-v1:VERSION,BUILD,BackupWholeDir,masterDomain,phpSelection,externalApp,userName,userPassword,token;ChildDomains(domain,phpSelection,path);Databases(dbName,databaseUsers(dbUser,dbHost,password));Aliases(alias);dnsrecords(type,name,content,priority);emails(email,password)"
)

type Admission struct { Manifest migration.Manifest; SourceEndpoint string }

type Intake struct {
	verifier migration.ManifestVerifier
	clock func() time.Time
	mu sync.Mutex
}

type admissionReceipt struct {
	Version uint32 `json:"version"`
	TenantID string `json:"tenant_id"`
	MigrationID migration.ID `json:"migration_id"`
	ManifestRoot string `json:"manifest_root"`
	SourcePathDigest string `json:"source_path_digest"`
	AdmittedAt time.Time `json:"admitted_at"`
}

type verifiedBundle struct { manifest migration.Manifest; path string; identity os.FileInfo }
type fileEvidence struct { digest string; size uint64 }
type archiveIndex struct {
	files map[string]fileEvidence
	directories map[string]struct{}
	metadata map[string][]byte
	digest string
	generation uint64
}

type backupMetadata struct {
	XMLName xml.Name `xml:"metaFile"`
	Version string `xml:"VERSION"`; Build string `xml:"BUILD"`; Whole string `xml:"BackupWholeDir"`
	MasterDomain string `xml:"masterDomain"`; PHP string `xml:"phpSelection"`; ExternalApp string `xml:"externalApp"`
	UserName string `xml:"userName"`; UserPassword []byte `xml:"userPassword"`; Token []byte `xml:"token"`
	Children []backupChild `xml:"ChildDomains>domain"`
	Databases []backupDatabase `xml:"Databases>database"`
	Aliases []string `xml:"Aliases>alias"`
	DNS []backupDNS `xml:"dnsrecords>dnsrecord"`
	Emails []backupEmail `xml:"emails>emailAccount"`
}
type backupChild struct { Domain string `xml:"domain"`; PHP string `xml:"phpSelection"`; Path string `xml:"path"` }
type backupDatabase struct { Name string `xml:"dbName"`; Users []backupDatabaseUser `xml:"databaseUsers"` }
type backupDatabaseUser struct { Name string `xml:"dbUser"`; Host string `xml:"dbHost"`; Password []byte `xml:"password"` }
type backupDNS struct { Type string `xml:"type"`; Name string `xml:"name"`; Content string `xml:"content"`; Priority string `xml:"priority"` }
type backupEmail struct { Address string `xml:"email"`; Password []byte `xml:"password"` }

func New(verifier migration.ManifestVerifier) (*Intake, error) {
	if verifier == nil { return nil, migration.ErrInvalid }
	for _, root := range []string{DefaultIntakePath, DefaultQuarantinePath} {
		if err := ensureRoot(root); err != nil { return nil, err }
	}
	left, err := os.Lstat(DefaultIntakePath); if err != nil { return nil, err }
	right, err := os.Lstat(DefaultQuarantinePath)
	if err != nil || !sameFilesystem(left, right) { return nil, errors.Join(migration.ErrBlocked, err) }
	return &Intake{verifier:verifier, clock:time.Now}, nil
}

func (intake *Intake) Ready() bool { return intake != nil && intake.verifier != nil && validateRoots() == nil }

func (intake *Intake) Admit(ctx context.Context, tenantID, endpoint string) (Admission, error) {
	if !intake.Ready() || ctx == nil || !scopeText(tenantID) { return Admission{}, migration.ErrInvalid }
	bundlePath, err := intakePath(endpoint); if err != nil { return Admission{}, err }
	verified, err := intake.verifyBundle(ctx, bundlePath); if err != nil { return Admission{}, err }
	receipt := admissionReceipt{Version:1, TenantID:tenantID, MigrationID:verified.manifest.MigrationID, ManifestRoot:verified.manifest.MerkleRoot, SourcePathDigest:pathDigest(bundlePath), AdmittedAt:intake.clock().UTC()}
	claimPath := filepath.Join(DefaultQuarantinePath, receipt.ManifestRoot)
	quarantinedPath := filepath.Join(claimPath, "bundle")
	intake.mu.Lock(); defer intake.mu.Unlock()
	if err = ctx.Err(); err != nil { return Admission{}, err }
	if err = os.Mkdir(claimPath, 0o700); err != nil { return Admission{}, errors.Join(migration.ErrConflict, err) }
	moved := false
	defer func(){ if !moved { _ = os.Remove(filepath.Join(claimPath, "admission.json")); _ = os.Remove(claimPath) } }()
	if err = writeReceipt(claimPath, receipt); err != nil { return Admission{}, err }
	current, err := os.Lstat(bundlePath)
	if err != nil || !sameDirectory(verified.identity, current) { return Admission{}, errors.Join(migration.ErrConflict, err) }
	if err = os.Rename(bundlePath, quarantinedPath); err != nil { return Admission{}, err }
	moved = true
	if err = errors.Join(syncDirectory(DefaultIntakePath), syncDirectory(claimPath), syncDirectory(DefaultQuarantinePath)); err != nil { return Admission{}, errors.Join(migration.ErrAmbiguous, err) }
	quarantined, err := intake.verifyBundle(ctx, quarantinedPath)
	if err != nil || quarantined.manifest.MigrationID != receipt.MigrationID || quarantined.manifest.MerkleRoot != receipt.ManifestRoot || !os.SameFile(verified.identity, quarantined.identity) {
		return Admission{}, errors.Join(migration.ErrConflict, err)
	}
	return Admission{Manifest:quarantined.manifest, SourceEndpoint:fileEndpoint(quarantinedPath)}, nil
}

func (intake *Intake) Discover(ctx context.Context, scope migration.RuntimeScope) (migration.Manifest, error) {
	bundle, err := intake.bundle(ctx, scope); if err != nil { return migration.Manifest{}, err }; return bundle.manifest, nil
}
func (intake *Intake) Generation(ctx context.Context, scope migration.RuntimeScope) (uint64, error) {
	manifest, err := intake.Discover(ctx, scope); if err != nil { return 0, err }; return manifest.SourceGeneration, nil
}
func (intake *Intake) OpenChunk(ctx context.Context, scope migration.RuntimeScope, digest string, offset, length uint64) ([]byte, error) {
	bundle, err := intake.bundle(ctx, scope); if err != nil { return nil, err }
	var descriptor migration.Chunk; found := false
	for _, candidate := range bundle.manifest.Chunks { if candidate.Digest == digest { descriptor, found = candidate, true; break } }
	if !found || length == 0 || offset > descriptor.Size || length > descriptor.Size-offset { return nil, migration.ErrInvalid }
	store, err := migration.OpenChunkStore(filepath.Join(bundle.path, "chunks"), maximumExpandedBytes); if err != nil { return nil, err }
	defer store.Close(); return store.ReadRange(ctx, digest, offset, length)
}

func (intake *Intake) OwnsEndpoint(endpoint string) bool {
	pathValue, err := parseFileEndpoint(endpoint); if err != nil { return false }
	relative, err := filepath.Rel(DefaultQuarantinePath, pathValue); if err != nil { return false }
	parts := strings.Split(filepath.ToSlash(relative), "/")
	return len(parts) == 2 && isDigest(parts[0]) && parts[1] == "bundle"
}

func (intake *Intake) bundle(ctx context.Context, scope migration.RuntimeScope) (verifiedBundle, error) {
	if !intake.Ready() || ctx == nil || !scope.MigrationID.Valid() || !scopeText(scope.TenantID) || !intake.OwnsEndpoint(scope.SourceEndpoint) { return verifiedBundle{}, migration.ErrInvalid }
	bundlePath, err := parseFileEndpoint(scope.SourceEndpoint); if err != nil { return verifiedBundle{}, err }
	claimPath := filepath.Dir(bundlePath)
	receipt, err := readReceipt(filepath.Join(claimPath, "admission.json")); if err != nil { return verifiedBundle{}, err }
	if receipt.Version != 1 || receipt.TenantID != scope.TenantID || receipt.MigrationID != scope.MigrationID || receipt.ManifestRoot != filepath.Base(claimPath) || !isDigest(receipt.SourcePathDigest) || receipt.AdmittedAt.IsZero() { return verifiedBundle{}, migration.ErrConflict }
	claimInfo, err := os.Lstat(claimPath); if err != nil || !ownedDirectory(claimInfo) { return verifiedBundle{}, errors.Join(migration.ErrBlocked, err) }; resolved, err := filepath.EvalSymlinks(claimPath); if err != nil || resolved != claimPath { return verifiedBundle{}, errors.Join(migration.ErrBlocked, err) }
	bundle, err := intake.verifyBundle(ctx, bundlePath); if err != nil { return verifiedBundle{}, err }
	if bundle.manifest.MigrationID != scope.MigrationID || bundle.manifest.MerkleRoot != receipt.ManifestRoot { return verifiedBundle{}, migration.ErrConflict }
	return bundle, nil
}

func (intake *Intake) verifyBundle(ctx context.Context, bundlePath string) (verifiedBundle, error) {
	if ctx == nil || !canonicalPath(bundlePath) { return verifiedBundle{}, migration.ErrInvalid }
	identity, err := os.Lstat(bundlePath)
	if err != nil || !ownedDirectory(identity) { return verifiedBundle{}, errors.Join(migration.ErrBlocked, err) }
	resolved, err := filepath.EvalSymlinks(bundlePath); if err != nil || resolved != bundlePath { return verifiedBundle{}, errors.Join(migration.ErrBlocked, err) }
	entries, err := os.ReadDir(bundlePath); if err != nil { return verifiedBundle{}, err }
	manifestName := ""; archivePresent := false; chunksPresent := false
	for _, entry := range entries {
		switch { case entry.Name() == "source.tar.gz" && !entry.IsDir(): archivePresent = true
		case entry.Name() == "chunks" && entry.IsDir(): chunksPresent = true
		case !entry.IsDir() && strings.HasSuffix(entry.Name(), ".manifest.json") && manifestName == "": manifestName = entry.Name()
		default: return verifiedBundle{}, migration.ErrInvalid }
	}
	if len(entries) != 3 || !archivePresent || !chunksPresent || manifestName == "" { return verifiedBundle{}, migration.ErrInvalid }
	manifestPath := filepath.Join(bundlePath, manifestName)
	raw, _, err := readOwnedFile(manifestPath, maximumManifestBytes); if err != nil { return verifiedBundle{}, err }
	decoder := json.NewDecoder(bytes.NewReader(raw)); decoder.DisallowUnknownFields(); var manifest migration.Manifest
	if err = decoder.Decode(&manifest); err != nil { return verifiedBundle{}, migration.ErrInvalid }
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) { return verifiedBundle{}, migration.ErrInvalid }
	canonical, err := json.Marshal(manifest); if err != nil { return verifiedBundle{}, err }; canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) || manifest.Source != migration.SourceCyberPanelBackup || manifestName != manifest.MigrationID.String()+".manifest.json" || manifest.Validate() != nil { return verifiedBundle{}, migration.ErrInvalid }
	if err = intake.verifier.Verify(ctx, manifest); err != nil { return verifiedBundle{}, err }
	index, metadata, err := auditArchive(ctx, filepath.Join(bundlePath, "source.tar.gz")); if err != nil { return verifiedBundle{}, err }
	defer metadata.clearSecrets(); defer index.clearMetadata()
	if err = validateMapping(index, metadata, manifest); err != nil { return verifiedBundle{}, err }
	references, err := referencedChunks(manifest); if err != nil { return verifiedBundle{}, err }
	store, err := migration.OpenChunkStore(filepath.Join(bundlePath, "chunks"), maximumExpandedBytes); if err != nil { return verifiedBundle{}, err }
	total := uint64(0)
	for _, descriptor := range manifest.Chunks {
		if descriptor.Size == 0 || descriptor.ObjectCount == 0 || descriptor.Size > maximumExpandedBytes-total { err = migration.ErrCapacity; break }
		total += descriptor.Size; if _, used := references[descriptor.Digest]; !used { err = migration.ErrInvalid; break }
		if err = store.Verify(ctx, descriptor); err != nil { break }
	}
	err = errors.Join(err, store.Close()); if err != nil { return verifiedBundle{}, err }
	if err = auditBundleTree(ctx, bundlePath, manifest); err != nil { return verifiedBundle{}, err }
	finalRaw, _, err := readOwnedFile(manifestPath, maximumManifestBytes)
	if err != nil || !bytes.Equal(raw, finalRaw) { return verifiedBundle{}, errors.Join(migration.ErrConflict, err) }
	current, err := os.Lstat(bundlePath); if err != nil || !sameDirectory(identity, current) { return verifiedBundle{}, errors.Join(migration.ErrConflict, err) }
	return verifiedBundle{manifest:manifest, path:bundlePath, identity:identity}, nil
}

type boundedExpandedReader struct { source io.Reader; count uint64 }
func (reader *boundedExpandedReader) Read(value []byte) (int, error) {
	if reader.count >= maximumExpandedBytes { return 0, migration.ErrCapacity }
	if uint64(len(value)) > maximumExpandedBytes-reader.count { value = value[:maximumExpandedBytes-reader.count] }
	count, err := reader.source.Read(value); reader.count += uint64(count); return count, err
}

func (index archiveIndex) clearMetadata(){for name,value:=range index.metadata{wipe(value);delete(index.metadata,name)}}

func auditArchive(ctx context.Context, archivePath string) (archiveIndex, backupMetadata, error) {
	index := archiveIndex{files:map[string]fileEvidence{}, directories:map[string]struct{}{}, metadata:map[string][]byte{}}
	accepted:=false;defer func(){if !accepted{index.clearMetadata()}}()
	before, err := os.Lstat(archivePath)
	if err != nil || !ownedFile(before) || before.Size() < 1 || before.Size() > maximumCompressedBytes { return index, backupMetadata{}, errors.Join(migration.ErrBlocked, err) }
	file, err := os.Open(archivePath); if err != nil { return index, backupMetadata{}, err }; defer file.Close()
	opened, err := file.Stat(); if err != nil || !sameFile(before, opened) { return index, backupMetadata{}, errors.Join(migration.ErrConflict, err) }
	rawHash := sha256.New(); buffered := bufio.NewReader(io.TeeReader(file, rawHash))
	gzipReader, err := gzip.NewReader(buffered); if err != nil { return index, backupMetadata{}, migration.ErrInvalid }
	if gzipReader.Name != "" || gzipReader.Comment != "" || len(gzipReader.Extra) != 0 { gzipReader.Close(); return index, backupMetadata{}, migration.ErrInvalid }
	gzipReader.Multistream(false); expanded := &boundedExpandedReader{source:gzipReader}; reader := tar.NewReader(expanded)
	seen := map[string]struct{}{}; entries := 0
	for {
		if err = ctx.Err(); err != nil { gzipReader.Close(); return index, backupMetadata{}, err }
		header, nextErr := reader.Next(); if errors.Is(nextErr, io.EOF) { break }; if nextErr != nil { gzipReader.Close(); return index, backupMetadata{}, migration.ErrInvalid }
		entries++; if entries > maximumArchiveEntries || header == nil || header.Size < 0 || header.Mode&0o7000 != 0 || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 { gzipReader.Close(); return index, backupMetadata{}, migration.ErrCapacity }
		name, cleanErr := archiveName(header.Name); if cleanErr != nil || !allowedMember(name) { gzipReader.Close(); return index, backupMetadata{}, migration.ErrInvalid }
		if _, duplicate := seen[name]; duplicate { gzipReader.Close(); return index, backupMetadata{}, migration.ErrInvalid }; seen[name] = struct{}{}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 { gzipReader.Close(); return index, backupMetadata{}, migration.ErrInvalid }; index.directories[name] = struct{}{}
		case tar.TypeReg, tar.TypeRegA:
			if name == "." || uint64(header.Size) > maximumExpandedBytes { gzipReader.Close(); return index, backupMetadata{}, migration.ErrCapacity }
			hash := sha256.New(); var capture bytes.Buffer; destination := io.Writer(hash)
			if captureMember(name) { if header.Size > maximumMetadataBytes { gzipReader.Close(); return index, backupMetadata{}, migration.ErrCapacity }; destination = io.MultiWriter(hash, &capture) }
			written, copyErr := io.CopyBuffer(destination, reader, make([]byte, 128<<10))
			if copyErr != nil || written != header.Size { gzipReader.Close(); return index, backupMetadata{}, errors.Join(migration.ErrInvalid, copyErr) }
			index.files[name] = fileEvidence{digest:hex.EncodeToString(hash.Sum(nil)), size:uint64(written)}
			if captureMember(name) { index.metadata[name] = append([]byte(nil), capture.Bytes()...) }
		case tar.TypeSymlink:
			if header.Size != 0 || !safeArchiveLink(name, header.Linkname) { gzipReader.Close(); return index, backupMetadata{}, migration.ErrBlocked }
		default:
			gzipReader.Close(); return index, backupMetadata{}, migration.ErrBlocked
		}
	}
	_, drainErr := io.CopyBuffer(io.Discard, expanded, make([]byte, 128<<10)); closeErr := gzipReader.Close()
	_, trailingErr := buffered.Peek(1); if !errors.Is(trailingErr, io.EOF) { trailingErr = migration.ErrInvalid } else { trailingErr = nil }
	final, statErr := file.Stat()
	if drainErr != nil || closeErr != nil || trailingErr != nil || statErr != nil || !sameFile(opened, final) { return index, backupMetadata{}, errors.Join(migration.ErrConflict, drainErr, closeErr, trailingErr, statErr) }
	compressed := uint64(before.Size()); if expanded.count > maximumExpandedBytes || compressed == 0 || expanded.count > compressed*maximumExpansionRatio { return index, backupMetadata{}, migration.ErrCapacity }
	if _, found := index.files["meta.xml"]; !found { return index, backupMetadata{}, migration.ErrInvalid }
	if _, found := index.directories["public_html"]; !found { return index, backupMetadata{}, migration.ErrInvalid }
	_, cron := index.files["cron"]; _, crontab := index.files["crontab"]; if cron && crontab { return index, backupMetadata{}, migration.ErrInvalid }
	index.digest = hex.EncodeToString(rawHash.Sum(nil)); decoded, _ := hex.DecodeString(index.digest); index.generation = binary.BigEndian.Uint64(decoded[:8])
	if index.generation == 0 { return index, backupMetadata{}, migration.ErrInvalid }
	metadata, err := parseMetadata(index.metadata["meta.xml"]); wipe(index.metadata["meta.xml"]); delete(index.metadata, "meta.xml")
	if err != nil { return archiveIndex{}, backupMetadata{}, err }
	accepted=true;return index, metadata, nil
}

func archiveName(value string) (string, error) {
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\\\x00") || strings.HasPrefix(value, "/") || strings.Contains(value, "//") { return "", migration.ErrInvalid }
	value = strings.TrimSuffix(value, "/"); if value == "." { return value, nil }; if strings.HasPrefix(value, "./") { value = strings.TrimPrefix(value, "./") }
	if value == "" || path.Clean(value) != value || value == ".." || strings.HasPrefix(value, "../") || len(strings.Split(value, "/")) > 64 { return "", migration.ErrInvalid }
	return value, nil
}

func allowedMember(name string) bool {
	if name == "." { return true }; first := strings.Split(name, "/")[0]
	if first == "public_html" || first == "vmail" { return true }
	if strings.Contains(name, "/") { return false }
	if name == "meta.xml" || name == "cron" || name == "crontab" || name == "vhost.conf" || name == "apache.conf" { return true }
	for _, suffix := range []string{".sql", ".sql.gz", ".backup.json", ".cert.pem", ".fullchain.pem", ".privkey.pem", ".vhost.conf", ".apache.conf"} { if strings.HasSuffix(name, suffix) && len(name) > len(suffix) { return true } }
	return false
}

func captureMember(name string) bool {
	if name == "meta.xml" || name == "cron" || name == "crontab" || name == "public_html/.ssh/authorized_keys" || name == "public_html/.ssh/authorized_keys2" { return true }
	return strings.HasSuffix(name, ".cert.pem") || strings.HasSuffix(name, ".fullchain.pem") || strings.HasSuffix(name, ".privkey.pem")
}

func safeArchiveLink(name, target string) bool {
	if target == "" || len(target) > 4096 || path.IsAbs(target) || strings.ContainsAny(target, "\\\x00") { return false }
	resolved := path.Clean(path.Join(path.Dir(name), target)); if resolved == ".." || strings.HasPrefix(resolved, "../") { return false }
	return strings.Split(name, "/")[0] == strings.Split(resolved, "/")[0] && (strings.HasPrefix(name, "public_html/") || strings.HasPrefix(name, "vmail/"))
}

type xmlFrame struct { path string; children map[string]int; container bool }

func parseMetadata(raw []byte) (backupMetadata, error) {
	if len(raw) == 0 || int64(len(raw)) > maximumMetadataBytes || bytes.IndexByte(raw, 0) >= 0 { return backupMetadata{}, migration.ErrInvalid }
	decoder := xml.NewDecoder(bytes.NewReader(raw)); decoder.Strict = true; frames := []xmlFrame{}; rootSeen := false
	for {
		token, err := decoder.Token(); if errors.Is(err, io.EOF) { break }; if err != nil { return backupMetadata{}, migration.ErrInvalid }
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Space != "" || len(value.Attr) != 0 || len(frames) >= 8 { return backupMetadata{}, migration.ErrInvalid }
			if len(frames) == 0 { if rootSeen || value.Name.Local != "metaFile" { return backupMetadata{}, migration.ErrInvalid }; rootSeen = true; frames = append(frames, xmlFrame{path:"metaFile", children:map[string]int{}, container:true}); continue }
			parent := &frames[len(frames)-1]; if !parent.container || !allowedXMLChild(parent.path, value.Name.Local) { return backupMetadata{}, migration.ErrInvalid }
			parent.children[value.Name.Local]++; if parent.children[value.Name.Local] > 1 && !repeatXMLChild(parent.path, value.Name.Local) { return backupMetadata{}, migration.ErrInvalid }
			childPath := parent.path + "/" + value.Name.Local; frames = append(frames, xmlFrame{path:childPath, children:map[string]int{}, container:isXMLContainer(childPath)})
		case xml.EndElement:
			if len(frames) == 0 { return backupMetadata{}, migration.ErrInvalid }; frame := frames[len(frames)-1]
			if err := requiredXMLChildren(frame); err != nil { return backupMetadata{}, err }; frames = frames[:len(frames)-1]
		case xml.CharData:
			if len(frames) == 0 { if strings.TrimSpace(string(value)) != "" { return backupMetadata{}, migration.ErrInvalid } } else if frames[len(frames)-1].container && strings.TrimSpace(string(value)) != "" { return backupMetadata{}, migration.ErrInvalid }
		case xml.Directive:
			return backupMetadata{}, migration.ErrBlocked
		case xml.ProcInst:
			if value.Target != "xml" || rootSeen { return backupMetadata{}, migration.ErrInvalid }
		}
	}
	if !rootSeen || len(frames) != 0 { return backupMetadata{}, migration.ErrInvalid }
	var metadata backupMetadata; if err := xml.Unmarshal(raw, &metadata); err != nil { metadata.clearSecrets(); return backupMetadata{}, migration.ErrInvalid }
	if err := metadata.validate(); err != nil { metadata.clearSecrets(); return backupMetadata{}, err }; return metadata, nil
}

func allowedXMLChild(parent, child string) bool {
	var allowed string
	switch parent {
	case "metaFile": allowed = " VERSION BUILD BackupWholeDir masterDomain phpSelection externalApp userName userPassword firstName lastName email type owner token api securityLevel state initWebsitesLimit aclName ChildDomains Databases Aliases dnsrecords emails "
	case "metaFile/ChildDomains": allowed = " domain "
	case "metaFile/ChildDomains/domain": allowed = " domain phpSelection path "
	case "metaFile/Databases": allowed = " database "
	case "metaFile/Databases/database": allowed = " dbName databaseUsers "
	case "metaFile/Databases/database/databaseUsers": allowed = " dbUser dbHost password "
	case "metaFile/Aliases": allowed = " alias "
	case "metaFile/dnsrecords": allowed = " dnsrecord "
	case "metaFile/dnsrecords/dnsrecord": allowed = " type name content priority "
	case "metaFile/emails": allowed = " emailAccount "
	case "metaFile/emails/emailAccount": allowed = " email password "
	default: return false
	}
	return strings.Contains(allowed, " "+child+" ")
}

func repeatXMLChild(parent, child string) bool {
	return (parent == "metaFile/ChildDomains" && child == "domain") || (parent == "metaFile/Databases" && child == "database") || (parent == "metaFile/Databases/database" && child == "databaseUsers") || (parent == "metaFile/Aliases" && child == "alias") || (parent == "metaFile/dnsrecords" && child == "dnsrecord") || (parent == "metaFile/emails" && child == "emailAccount")
}
func isXMLContainer(value string) bool {
	return value == "metaFile" || value == "metaFile/ChildDomains" || value == "metaFile/ChildDomains/domain" || value == "metaFile/Databases" || value == "metaFile/Databases/database" || value == "metaFile/Databases/database/databaseUsers" || value == "metaFile/Aliases" || value == "metaFile/dnsrecords" || value == "metaFile/dnsrecords/dnsrecord" || value == "metaFile/emails" || value == "metaFile/emails/emailAccount"
}

func requiredXMLChildren(frame xmlFrame) error {
	var required []string
	switch frame.path {
	case "metaFile": required = []string{"VERSION","BUILD","BackupWholeDir","masterDomain","phpSelection","externalApp","userName","userPassword","token","ChildDomains","Databases","Aliases","dnsrecords","emails"}
	case "metaFile/ChildDomains/domain": required = []string{"domain","phpSelection","path"}
	case "metaFile/Databases/database": required = []string{"dbName"}
	case "metaFile/Databases/database/databaseUsers": required = []string{"dbUser","dbHost","password"}
	case "metaFile/dnsrecords/dnsrecord": required = []string{"type","name","content","priority"}
	case "metaFile/emails/emailAccount": required = []string{"email","password"}
	}
	for _, name := range required { if frame.children[name] != 1 { return migration.ErrInvalid } }; return nil
}

func (metadata *backupMetadata) validate() error {
	metadata.Version = strings.TrimSpace(metadata.Version); metadata.Build = strings.TrimSpace(metadata.Build); metadata.MasterDomain = normalizeHost(metadata.MasterDomain)
	metadata.PHP = strings.TrimSpace(metadata.PHP); metadata.ExternalApp = strings.TrimSpace(metadata.ExternalApp); metadata.UserName = strings.TrimSpace(metadata.UserName)
	if !plainText(metadata.Version, 64) || !plainText(metadata.Build, 32) || metadata.Whole != "1" || !validHost(metadata.MasterDomain) || !plainText(metadata.PHP, 64) || !safeIdentity(metadata.ExternalApp) || !safeIdentity(metadata.UserName) || len(metadata.UserPassword)>1<<20 || len(metadata.Token)>1<<20 { return migration.ErrInvalid }
	if _, err := strconv.ParseUint(metadata.Build, 10, 64); err != nil { return migration.ErrInvalid }
	seen := map[string]struct{}{metadata.MasterDomain:{}}
	for index := range metadata.Children { child := &metadata.Children[index]; child.Domain = normalizeHost(child.Domain); child.PHP = strings.TrimSpace(child.PHP); child.Path = strings.TrimSpace(child.Path); if !validHost(child.Domain) || !plainText(child.PHP,64) || childRelativePath(metadata.MasterDomain,child.Path)=="" { return migration.ErrInvalid }; if _, exists := seen[child.Domain]; exists { return migration.ErrInvalid }; seen[child.Domain]=struct{}{} }
	aliases := map[string]struct{}{}; for index := range metadata.Aliases { metadata.Aliases[index]=normalizeHost(metadata.Aliases[index]); value:=metadata.Aliases[index]; if !validHost(value) { return migration.ErrInvalid }; if _, exists:=seen[value]; exists{return migration.ErrInvalid}; if _, exists:=aliases[value]; exists{return migration.ErrInvalid}; aliases[value]=struct{}{} }
	databaseNames:=map[string]struct{}{}; for databaseIndex:=range metadata.Databases { database:=&metadata.Databases[databaseIndex]; database.Name=strings.TrimSpace(database.Name); if !safeDatabaseName(database.Name){return migration.ErrInvalid}; key:=strings.ToLower(database.Name); if _,duplicate:=databaseNames[key];duplicate{return migration.ErrInvalid};databaseNames[key]=struct{}{}; users:=map[string][sha256.Size]byte{}; hosts:=map[string]struct{}{}; for userIndex:=range database.Users { user:=&database.Users[userIndex];user.Name=strings.TrimSpace(user.Name);user.Host=strings.TrimSpace(user.Host);if !safeDatabaseName(user.Name)||!plainText(user.Host,255)||len(user.Password)==0||len(user.Password)>1<<20{return migration.ErrInvalid}; userKey:=strings.ToLower(user.Name);passwordDigest:=sha256.Sum256(user.Password);if prior,present:=users[userKey];present&&prior!=passwordDigest{return migration.ErrInvalid};users[userKey]=passwordDigest;hostKey:=userKey+"\x00"+strings.ToLower(user.Host);if _,duplicate:=hosts[hostKey];duplicate{return migration.ErrInvalid};hosts[hostKey]=struct{}{}} }
	dnsKeys:=map[string]struct{}{}; for index:=range metadata.DNS { record:=&metadata.DNS[index];record.Type=strings.ToUpper(strings.TrimSpace(record.Type));record.Name=normalizeDNS(record.Name);record.Content=strings.TrimSpace(record.Content);record.Priority=strings.TrimSpace(record.Priority);if !knownDNS(record.Type)||!validDNSName(record.Name)||!plainText(record.Content,4096){return migration.ErrInvalid};priority,err:=strconv.ParseUint(record.Priority,10,16);if err!=nil{return migration.ErrInvalid};if priority!=0&&record.Type!="MX"&&record.Type!="SRV"{return migration.ErrInvalid};key:=record.Name+"\x00"+record.Type+"\x00"+strconv.FormatUint(priority,10)+"\x00"+record.Content;if _,duplicate:=dnsKeys[key];duplicate{return migration.ErrInvalid};dnsKeys[key]=struct{}{} }
	emails:=map[string]struct{}{}; for index:=range metadata.Emails { email:=&metadata.Emails[index];email.Address=strings.ToLower(strings.TrimSpace(email.Address));if !validEmail(email.Address)||len(email.Password)==0||len(email.Password)>1<<20{return migration.ErrInvalid};if _,duplicate:=emails[email.Address];duplicate{return migration.ErrInvalid};emails[email.Address]=struct{}{} }
	return nil
}

func (metadata *backupMetadata) clearSecrets() { wipe(metadata.UserPassword);wipe(metadata.Token);metadata.UserPassword=nil;metadata.Token=nil;for i:=range metadata.Databases{for j:=range metadata.Databases[i].Users{wipe(metadata.Databases[i].Users[j].Password);metadata.Databases[i].Users[j].Password=nil}};for i:=range metadata.Emails{wipe(metadata.Emails[i].Password);metadata.Emails[i].Password=nil} }

type mappingContext struct { index archiveIndex; metadata backupMetadata; manifest migration.Manifest; version string; secrets map[string]migration.SecretEnvelope; usedSecrets map[string]struct{}; mainID migration.ID }

func validateMapping(index archiveIndex, metadata backupMetadata, manifest migration.Manifest) error {
	fingerprint:=schemaFingerprint(metadata); expectedInstallation:=installationID(metadata.MasterDomain,fingerprint)
	if validateArchiveMembers(index,metadata)!=nil||manifest.SourceGeneration!=index.generation||manifest.SourceInstallationID!=expectedInstallation||len(manifest.Repositories)!=0||len(manifest.Containers)!=0||len(manifest.BackupPolicies)!=0||len(manifest.Conflicts)!=0{return migration.ErrInvalid}
	context:=mappingContext{index:index,metadata:metadata,manifest:manifest,version:"cyberpanel-backup-intake-v1:"+fingerprint,secrets:map[string]migration.SecretEnvelope{},usedSecrets:map[string]struct{}{}}
	for _,secret:=range manifest.Secrets{if _,duplicate:=context.secrets[secret.SecretID];duplicate{return migration.ErrInvalid};context.secrets[secret.SecretID]=secret}
	if err:=context.sites();err!=nil{return err};if err:=context.databases();err!=nil{return err};if err:=context.dns();err!=nil{return err};if err:=context.mail();err!=nil{return err};if err:=context.certificates();err!=nil{return err};if err:=context.credentials();err!=nil{return err};if err:=context.schedules();err!=nil{return err}
	if len(context.usedSecrets)!=len(context.secrets){return migration.ErrInvalid};return nil
}

func (context *mappingContext) sites() error {
	expected:=map[string]backupChild{context.metadata.MasterDomain:{Domain:context.metadata.MasterDomain,PHP:context.metadata.PHP,Path:"public_html"}};children:=[]string{}
	for _,child:=range context.metadata.Children{child.Path=childRelativePath(context.metadata.MasterDomain,child.Path);expected[child.Domain]=child;children=append(children,child.Domain)};sort.Strings(children)
	if len(context.manifest.Sites)!=len(expected){return migration.ErrInvalid};byHost:=map[string]migration.Site{}
	for _,site:=range context.manifest.Sites{host:=normalizeHost(site.PrimaryHostname);source:=expected[host];if source.Domain==""||site.TargetID!=""||site.TenantID!=""||site.ProjectID!=""||len(site.Redirects)!=0||len(site.ResourceProfile)!=0||site.PHPVersion!=source.PHP||site.DocumentRootRelative!=source.Path||site.RuntimeKind!="php_lsapi"||len(site.Conflicts)!=0||!context.provenance(site.Provenance){return migration.ErrInvalid};if _,duplicate:=byHost[host];duplicate{return migration.ErrInvalid};byHost[host]=site }
	main:=byHost[context.metadata.MasterDomain];if !main.SourceID.Valid()||len(main.Content)==0||!sameStrings(main.Aliases,context.metadata.Aliases)||!sameStrings(main.Children,children){return migration.ErrInvalid};context.mainID=main.SourceID
	for host,site:=range byHost{if host!=context.metadata.MasterDomain&&(len(site.Aliases)!=0||len(site.Children)!=0||len(site.DatabaseIDs)!=0||len(site.MailDomainIDs)!=0||len(site.CredentialIDs)!=0||len(site.CronIDs)!=0){return migration.ErrInvalid}}
	return nil
}

func (context *mappingContext) databases() error {
	if len(context.manifest.Databases)!=len(context.metadata.Databases){return migration.ErrInvalid};byName:=map[string]migration.Database{};ids:=[]migration.ID{}
	for _,database:=range context.manifest.Databases{key:=strings.ToLower(database.Name);if _,duplicate:=byName[key];duplicate{return migration.ErrInvalid};byName[key]=database;ids=append(ids,database.SourceID)}
	for _,source:=range context.metadata.Databases{database:=byName[strings.ToLower(source.Name)];if !database.SourceID.Valid()||database.TargetID!=""||database.SiteID!=context.mainID||database.Charset!="utf8mb4"||database.Collation!="utf8mb4_unicode_ci"||len(database.Conflicts)!=0||!context.provenance(database.Provenance){return migration.ErrInvalid};evidence,compressed,err:=databaseEvidence(context.index,source.Name);if err!=nil||len(database.Dump)!=1||database.Dump[0].Digest!=evidence.digest||database.Dump[0].Size!=evidence.size||database.Dump[0].MediaType!="application/sql"||database.Dump[0].Compression!=compressed{return migration.ErrInvalid};expected:=map[string][]backupDatabaseUser{};for _,user:=range source.Users{expected[strings.ToLower(user.Name)]=append(expected[strings.ToLower(user.Name)],user)};if len(database.Principals)!=len(expected){return migration.ErrInvalid};for _,principal:=range database.Principals{users:=expected[strings.ToLower(principal.Name)];if len(users)==0{return migration.ErrInvalid};grants:=[]string{};for _,user:=range users{grants=append(grants,"legacy-database-owner@"+user.Host)};if !sameStrings(principal.GrantSets,grants)||principal.CredentialDisposition!=migration.CredentialPreserved||context.bind(principal.SecretID,"database-principal","database:"+database.SourceID.String()+":"+principal.Name)!=nil{return migration.ErrInvalid};delete(expected,strings.ToLower(principal.Name))};if len(expected)!=0{return migration.ErrInvalid}}
	main:=context.site(context.mainID);if !sameIDs(main.DatabaseIDs,ids){return migration.ErrInvalid};return nil
}

func (context *mappingContext) dns() error {
	if len(context.manifest.DNSZones)!=1{return migration.ErrInvalid};zone:=context.manifest.DNSZones[0];if zone.TargetID!=""||normalizeHost(zone.Name)!=context.metadata.MasterDomain||zone.Mode!="native"||zone.DNSSEC||len(zone.Conflicts)!=0||!context.provenance(zone.Provenance){return migration.ErrInvalid}
	expected:=map[string][]string{};for _,record:=range context.metadata.DNS{value:=record.Content;if record.Type=="MX"||record.Type=="SRV"{priority,_:=strconv.ParseUint(record.Priority,10,16);value=strconv.FormatUint(priority,10)+" "+value};key:=record.Name+"\x00"+record.Type;expected[key]=append(expected[key],value)}
	if len(zone.RecordSets)!=len(expected){return migration.ErrInvalid};for _,set:=range zone.RecordSets{key:=normalizeDNS(set.Name)+"\x00"+strings.ToUpper(set.Type);if set.TTL!=3600||!sameStrings(set.Values,expected[key]){return migration.ErrInvalid};delete(expected,key)};if len(expected)!=0{return migration.ErrInvalid};return nil
}

func (context *mappingContext) mail() error {
	if len(context.manifest.MailDomains)!=1{return migration.ErrInvalid};domain:=context.manifest.MailDomains[0]
	if domain.TargetID!=""||domain.SiteID!=context.mainID||normalizeHost(domain.Name)!=context.metadata.MasterDomain||len(domain.Aliases)!=0||len(domain.Forwarders)!=0||len(domain.CatchAll)!=0||domain.DKIMSecretID!=""||len(domain.Conflicts)!=0||!context.provenance(domain.Provenance){return migration.ErrInvalid}
	expected:=map[string]backupEmail{};for _,mailbox:=range context.metadata.Emails{expected[mailbox.Address]=mailbox};if len(domain.Mailboxes)!=len(expected){return migration.ErrInvalid}
	mailData:=len(domain.MailData)>0;for _,mailbox:=range domain.Mailboxes{address:=strings.ToLower(mailbox.Address);source:=expected[address];if source.Address==""||mailbox.TargetID!=""||mailbox.QuotaBytes!=0||mailbox.CredentialDisposition!=migration.CredentialPreserved||context.bind(mailbox.CredentialSecretID,"mailbox-credential","mailbox:"+mailbox.SourceID.String())!=nil{return migration.ErrInvalid};mailData=mailData||len(mailbox.Data)>0;delete(expected,address)}
	_,vmail:=context.index.directories["vmail"];if len(expected)!=0||vmail!=mailData{return migration.ErrInvalid};main:=context.site(context.mainID);if !sameIDs(main.MailDomainIDs,[]migration.ID{domain.SourceID}){return migration.ErrInvalid};return nil
}

func (context *mappingContext) certificates() error {
	hosts:=map[string]struct{}{};for _,site:=range context.manifest.Sites{hosts[normalizeHost(site.PrimaryHostname)]=struct{}{}}
	certFiles:=[]string{};for name:=range context.index.files{if strings.HasSuffix(name,".cert.pem"){certFiles=append(certFiles,name)}};sort.Strings(certFiles)
	if len(context.manifest.Certificates)!=len(certFiles){return migration.ErrInvalid};used:=map[migration.ID]struct{}{}
	for _,name:=range certFiles{host:=normalizeHost(strings.TrimSuffix(name,".cert.pem"));if !validHost(host){return migration.ErrInvalid};if _,present:=hosts[host];!present{return migration.ErrInvalid};fullName,keyName:=host+".fullchain.pem",host+".privkey.pem";certificateRaw,fullRaw,keyRaw:=context.index.metadata[name],context.index.metadata[fullName],context.index.metadata[keyName];fullEvidence,fullFound:=context.index.files[fullName];keyEvidence,keyFound:=context.index.files[keyName];_ = keyEvidence;if len(certificateRaw)==0||len(fullRaw)==0||len(keyRaw)==0||!fullFound||!keyFound{return migration.ErrInvalid};parsed,err:=firstCertificate(certificateRaw);if err!=nil||legacy.ValidatePrivateKeyForCertificate(keyRaw,parsed)!=nil{return migration.ErrInvalid};names,err:=legacy.ConcreteCertificateNames(parsed,host);if err!=nil{return migration.ErrInvalid}
		var target migration.Certificate;found:=false;for _,candidate:=range context.manifest.Certificates{if _,done:=used[candidate.SourceID];!done&&containsString(candidate.Names,host){target,found=candidate,true;break}};if !found||target.TargetID!=""||!sameStrings(target.Names,names)||target.Issuer!=parsed.Issuer.String()||!target.NotAfter.Equal(parsed.NotAfter)||len(target.Certificate)!=1||len(target.Chain)!=1||target.Certificate[0].Digest!=context.index.files[name].digest||target.Certificate[0].Size!=context.index.files[name].size||target.Chain[0].Digest!=fullEvidence.digest||target.Chain[0].Size!=fullEvidence.size||!context.provenance(target.Provenance)||context.bind(target.PrivateKeySecretID,"tls-private-key","certificate:"+target.SourceID.String())!=nil{return migration.ErrInvalid};used[target.SourceID]=struct{}{};wipe(keyRaw)}
	return nil
}

func (context *mappingContext) credentials() error {
	expected:=map[string]legacy.AuthorizedPublicKey{};for _,name:=range []string{"public_html/.ssh/authorized_keys","public_html/.ssh/authorized_keys2"}{raw:=context.index.metadata[name];if len(raw)==0{continue};keys,err:=legacy.ParseAuthorizedKeys(raw);if err!=nil{return err};for _,key:=range keys{if _,duplicate:=expected[key.PublicKey];duplicate{return migration.ErrInvalid};expected[key.PublicKey]=key}}
	if len(context.manifest.Credentials)!=len(expected)+1{return migration.ErrInvalid};admin:=false;ids:=[]migration.ID{}
	for _,credential:=range context.manifest.Credentials{ids=append(ids,credential.SourceID);if credential.TargetID!=""||credential.SiteID!=context.mainID||credential.RootRelative!="public_html"||!context.provenance(credential.Provenance){return migration.ErrInvalid};if credential.Kind=="legacy-admin"{if admin||credential.Label!=context.metadata.UserName||credential.CredentialDisposition!=migration.CredentialResetRequired||credential.SecretID!=""||credential.PublicKey!=""{return migration.ErrInvalid};admin=true;continue};if credential.Kind!="ssh-public-key"||credential.CredentialDisposition!=migration.CredentialPublicOnly||credential.SecretID!=""{return migration.ErrInvalid};key:=expected[credential.PublicKey];label:=key.Label;if label==""{label=context.metadata.UserName};if key.PublicKey==""||credential.Label!=label{return migration.ErrInvalid};delete(expected,credential.PublicKey)}
	if !admin||len(expected)!=0||!sameIDs(context.site(context.mainID).CredentialIDs,ids){return migration.ErrInvalid};return nil
}

type cronEvidence struct{ expression,timezone,invocation string }
func (context *mappingContext) schedules() error {
	raw:=context.index.metadata["cron"];if len(raw)==0{raw=context.index.metadata["crontab"]};expected,err:=parseCron(raw);if err!=nil{return err};if len(context.manifest.Schedules)!=len(expected){return migration.ErrInvalid};used:=make([]bool,len(expected));ids:=[]migration.ID{}
	for _,schedule:=range context.manifest.Schedules{ids=append(ids,schedule.SourceID);if schedule.TargetID!=""||schedule.SiteID!=context.mainID||schedule.Kind!="legacy-command"||!schedule.Enabled||!context.provenance(schedule.Provenance){return migration.ErrInvalid};found:=-1;for index,candidate:=range expected{if !used[index]&&schedule.Expression==candidate.expression&&schedule.Timezone==candidate.timezone&&schedule.InvocationID==candidate.invocation{found=index;break}};if found<0{return migration.ErrInvalid};used[found]=true}
	if !sameIDs(context.site(context.mainID).CronIDs,ids){return migration.ErrInvalid};return nil
}

func (context *mappingContext) site(id migration.ID) migration.Site { for _,site:=range context.manifest.Sites{if site.SourceID==id{return site}};return migration.Site{} }
func (context *mappingContext) provenance(values []migration.Provenance) bool { return len(values)==1&&values[0].SourceKind==string(migration.SourceCyberPanelBackup)&&strings.HasPrefix(values[0].SourceLocation,"cyberpanel_backup:")&&values[0].ExtractorVersion==context.version&&values[0].Digest==context.index.digest&&values[0].Confidence=="authoritative"&&values[0].Authoritative&&!values[0].ObservedAt.IsZero() }
func (context *mappingContext) bind(secretID,purpose,locator string) error { secret,found:=context.secrets[secretID];if !found||secret.Purpose!=purpose||secret.AudienceDigest!=audienceDigest(context.manifest,purpose,locator){return migration.ErrInvalid};if _,duplicate:=context.usedSecrets[secretID];duplicate{return migration.ErrInvalid};context.usedSecrets[secretID]=struct{}{};return nil }

func parseCron(raw []byte)([]cronEvidence,error){if len(raw)==0{return nil,nil};values:=[]cronEvidence{};scanner:=bufio.NewScanner(bytes.NewReader(raw));scanner.Buffer(make([]byte,4096),1<<20);timezone:="source-local";for scanner.Scan(){line:=strings.TrimSpace(scanner.Text());if line==""||strings.HasPrefix(line,"#"){continue};if key,value,ok:=cronEnvironment(line);ok{if strings.EqualFold(key,"CRON_TZ"){timezone=value};continue};expression,command,present,err:=legacy.ParseLegacyCronEntry(line);if err!=nil{return nil,err};if !present{continue};sum:=sha256.Sum256([]byte(command));values=append(values,cronEvidence{expression:expression,timezone:timezone,invocation:"legacy_invocation_"+hex.EncodeToString(sum[:16])})};return values,scanner.Err()}
func cronEnvironment(value string)(string,string,bool){equals:=strings.IndexByte(value,'=');space:=strings.IndexAny(value," \t");if equals<=0||(space>=0&&space<equals){return "","",false};key:=strings.TrimSpace(value[:equals]);result:=strings.TrimSpace(value[equals+1:]);if len(result)>=2&&((result[0]=='"'&&result[len(result)-1]=='"')||(result[0]=='\''&&result[len(result)-1]=='\'')){result=result[1:len(result)-1]};if !plainText(key,128)||!plainText(result,255){return "","",false};return key,result,true}

func referencedChunks(manifest migration.Manifest)(map[string]struct{},error){catalog:=map[string]migration.Chunk{};for _,chunk:=range manifest.Chunks{catalog[chunk.Digest]=chunk};used:=map[string]struct{}{};add:=func(values []migration.Chunk)error{for _,value:=range values{if catalog[value.Digest]!=value{return migration.ErrInvalid};used[value.Digest]=struct{}{}};return nil};for _,site:=range manifest.Sites{if add(site.Content)!=nil{return nil,migration.ErrInvalid}};for _,database:=range manifest.Databases{if add(database.Dump)!=nil{return nil,migration.ErrInvalid}};for _,domain:=range manifest.MailDomains{if add(domain.MailData)!=nil{return nil,migration.ErrInvalid};for _,mailbox:=range domain.Mailboxes{if add(mailbox.Data)!=nil{return nil,migration.ErrInvalid}}};for _,certificate:=range manifest.Certificates{if add(certificate.Certificate)!=nil||add(certificate.Chain)!=nil{return nil,migration.ErrInvalid}};return used,nil}

func validateArchiveMembers(index archiveIndex,metadata backupMetadata)error{databases:=map[string]struct{}{};for _,database:=range metadata.Databases{databases[database.Name]=struct{}{}};hosts:=map[string]struct{}{metadata.MasterDomain:{}};for _,child:=range metadata.Children{hosts[child.Domain]=struct{}{}};for name:=range index.files{if strings.Contains(name,"/")||name=="meta.xml"||name=="cron"||name=="crontab"||name=="vhost.conf"||name=="apache.conf"{continue};matched:=false;for _,suffix:=range []string{".sql.gz",".sql",".backup.json"}{if strings.HasSuffix(name,suffix){_,matched=databases[strings.TrimSuffix(name,suffix)];break}};if matched{continue};for _,suffix:=range []string{".cert.pem",".fullchain.pem",".privkey.pem",".vhost.conf",".apache.conf"}{if strings.HasSuffix(name,suffix){host:=normalizeHost(strings.TrimSuffix(name,suffix));_,matched=hosts[host];if matched&&(suffix==".cert.pem"||suffix==".fullchain.pem"||suffix==".privkey.pem"){_,cert:=index.files[host+".cert.pem"];_,full:=index.files[host+".fullchain.pem"];_,key:=index.files[host+".privkey.pem"];matched=cert&&full&&key};break}};if !matched{return migration.ErrInvalid}};return nil}
func databaseEvidence(index archiveIndex,name string)(fileEvidence,string,error){plain,plainFound:=index.files[name+".sql"];compressed,compressedFound:=index.files[name+".sql.gz"];if plainFound==compressedFound{return fileEvidence{},"",migration.ErrInvalid};if compressedFound{return compressed,"gzip",nil};return plain,"identity",nil}
func schemaFingerprint(metadata backupMetadata)string{sum:=sha256.Sum256([]byte(backupSchemaContract+"\x00"+metadata.Version+"\x00"+metadata.Build));return hex.EncodeToString(sum[:])}
func installationID(host,fingerprint string)string{sum:=sha256.Sum256([]byte("cyberpanel-backup-installation-v1\x00"+host+"\x00"+fingerprint));return "cyberpanel-backup-"+hex.EncodeToString(sum[:16])}
func audienceDigest(manifest migration.Manifest,purpose,locator string)string{sum:=sha256.Sum256([]byte(manifest.MigrationID.String()+"\x00"+manifest.TargetInstallationID+"\x00"+purpose+"\x00"+locator));return hex.EncodeToString(sum[:])}
func firstCertificate(raw []byte)(*x509.Certificate,error){block,rest:=pem.Decode(raw);if block==nil||block.Type!="CERTIFICATE"||strings.TrimSpace(string(rest))!=""{return nil,migration.ErrInvalid};certificate,err:=x509.ParseCertificate(block.Bytes);if err!=nil{return nil,migration.ErrInvalid};return certificate,nil}
func childRelativePath(host,value string)string{value=filepath.ToSlash(strings.TrimSpace(value));prefix:="/home/"+host+"/";if strings.HasPrefix(value,"/"){if !strings.HasPrefix(value,prefix){return ""};value=strings.TrimPrefix(value,prefix)};if value==""||path.Clean(value)!=value||value==".."||strings.HasPrefix(value,"../")||strings.Contains(value,"\\"){return ""};return value}
func normalizeHost(value string)string{return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)),".")}
func normalizeDNS(value string)string{return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)),".")}
func validHost(value string)bool{value=normalizeHost(value);if value==""||len(value)>253||netip.ParseAddr(value).IsValid(){return false};labels:=strings.Split(value,".");if len(labels)<2{return false};for _,label:=range labels{if len(label)<1||len(label)>63||label[0]=='-'||label[len(label)-1]=='-'{return false};for _,character:=range label{if(character<'a'||character>'z')&&(character<'0'||character>'9')&&character!='-'{return false}}};return true}
func validDNSName(value string)bool{value=normalizeDNS(value);if value=="@"||value=="*"{return true};if value==""||len(value)>253||netip.ParseAddr(value).IsValid(){return false};for index,label:=range strings.Split(value,"."){if label=="*"&&index==0{continue};if len(label)<1||len(label)>63||label[0]=='-'||label[len(label)-1]=='-'{return false};for _,character:=range label{if(character<'a'||character>'z')&&(character<'0'||character>'9')&&character!='-'&&character!='_'{return false}}};return true}
func validEmail(value string)bool{parts:=strings.Split(value,"@");return plainText(value,320)&&len(parts)==2&&parts[0]!=""&&len(parts[0])<=64&&validHost(parts[1])}
func knownDNS(value string)bool{switch value{case"A","AAAA","CAA","CNAME","MX","NS","PTR","SOA","SRV","TXT":return true};return false}
func safeIdentity(value string)bool{if !plainText(value,128){return false};for _,character:=range value{if(character<'a'||character>'z')&&(character<'A'||character>'Z')&&(character<'0'||character>'9')&&character!='_'&&character!='-'{return false}};return true}
func safeDatabaseName(value string)bool{if !plainText(value,128){return false};for _,character:=range value{if(character<'a'||character>'z')&&(character<'A'||character>'Z')&&(character<'0'||character>'9')&&character!='_'&&character!='-'&&character!='.'&&character!='$'{return false}};return true}
func plainText(value string,maximum int)bool{return value!=""&&len(value)<=maximum&&!strings.ContainsAny(value,"\r\n\x00")}
func sameStrings(left,right []string)bool{if len(left)!=len(right){return false};left=append([]string(nil),left...);right=append([]string(nil),right...);sort.Strings(left);sort.Strings(right);for index:=range left{if left[index]!=right[index]{return false}};return true}
func sameIDs(left,right []migration.ID)bool{if len(left)!=len(right){return false};left=append([]migration.ID(nil),left...);right=append([]migration.ID(nil),right...);sort.Slice(left,func(i,j int)bool{return left[i]<left[j]});sort.Slice(right,func(i,j int)bool{return right[i]<right[j]});for index:=range left{if left[index]!=right[index]{return false}};return true}
func containsString(values []string,value string)bool{for _,candidate:=range values{if normalizeHost(candidate)==value{return true}};return false}
func wipe(value []byte){for index:=range value{value[index]=0}}

func auditBundleTree(ctx context.Context,root string,manifest migration.Manifest)error{expected:=map[string]bool{".":true,"source.tar.gz":false,manifest.MigrationID.String()+".manifest.json":false,"chunks":true,filepath.Join("chunks","sha256"):true};for _,descriptor:=range manifest.Chunks{prefix:=filepath.Join("chunks","sha256",descriptor.Digest[:2]);expected[prefix]=true;expected[filepath.Join(prefix,descriptor.Digest)]=false};seen:=map[string]struct{}{};err:=filepath.WalkDir(root,func(value string,entry os.DirEntry,walkErr error)error{if walkErr!=nil{return walkErr};if err:=ctx.Err();err!=nil{return err};relative,err:=filepath.Rel(root,value);if err!=nil{return err};directory,allowed:=expected[relative];if !allowed{return migration.ErrInvalid};info,err:=entry.Info();if err!=nil||directory&&!ownedDirectory(info)||!directory&&!ownedFile(info){return errors.Join(migration.ErrBlocked,err)};seen[relative]=struct{}{};return nil});if err!=nil||len(seen)!=len(expected){return errors.Join(migration.ErrInvalid,err)};return nil}

func writeReceipt(claimPath string,receipt admissionReceipt)error{raw,err:=json.Marshal(receipt);if err!=nil{return err};raw=append(raw,'\n');file,err:=os.OpenFile(filepath.Join(claimPath,"admission.json"),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0o600);if err!=nil{return err};if err=writeAll(file,raw);err==nil{err=file.Sync()};if err==nil{err=file.Chmod(0o400)};err=errors.Join(err,file.Close());if err!=nil{return err};return syncDirectory(claimPath)}
func readReceipt(value string)(admissionReceipt,error){var receipt admissionReceipt;raw,_,err:=readOwnedFile(value,16<<10);if err!=nil{return receipt,err};decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();if err=decoder.Decode(&receipt);err!=nil{return admissionReceipt{},migration.ErrInvalid};if err=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){return admissionReceipt{},migration.ErrInvalid};return receipt,nil}

func ensureRoot(value string)error{if !canonicalPath(value){return migration.ErrInvalid};info,err:=os.Lstat(value);if errors.Is(err,os.ErrNotExist){if err=os.Mkdir(value,0o700);err!=nil{return err};info,err=os.Lstat(value)};if err!=nil||!ownedDirectory(info){return errors.Join(migration.ErrBlocked,err)};resolved,err:=filepath.EvalSymlinks(value);if err!=nil||resolved!=value{return errors.Join(migration.ErrBlocked,err)};return nil}
func validateRoots()error{left,err:=os.Lstat(DefaultIntakePath);if err!=nil||!ownedDirectory(left){return errors.Join(migration.ErrBlocked,err)};right,err:=os.Lstat(DefaultQuarantinePath);if err!=nil||!ownedDirectory(right)||!sameFilesystem(left,right){return errors.Join(migration.ErrBlocked,err)};for _,value:=range []string{DefaultIntakePath,DefaultQuarantinePath}{resolved,resolveErr:=filepath.EvalSymlinks(value);if resolveErr!=nil||resolved!=value{return errors.Join(migration.ErrBlocked,resolveErr)}};return nil}
func intakePath(endpoint string)(string,error){value,err:=parseFileEndpoint(endpoint);if err!=nil||filepath.Dir(value)!=DefaultIntakePath||filepath.Base(value)=="."{return "",migration.ErrInvalid};resolved,err:=filepath.EvalSymlinks(value);if err!=nil||resolved!=value{return "",errors.Join(migration.ErrBlocked,err)};return value,nil}
func parseFileEndpoint(endpoint string)(string,error){parsed,err:=url.Parse(endpoint);if err!=nil||parsed.Scheme!="file"||parsed.Host!=""||parsed.User!=nil||parsed.Opaque!=""||parsed.RawPath!=""||parsed.RawQuery!=""||parsed.Fragment!=""||!canonicalPath(parsed.Path)||fileEndpoint(parsed.Path)!=endpoint{return "",migration.ErrInvalid};return parsed.Path,nil}
func fileEndpoint(value string)string{return (&url.URL{Scheme:"file",Path:value}).String()}
func canonicalPath(value string)bool{return value!=""&&filepath.IsAbs(value)&&filepath.Clean(value)==value}
func pathDigest(value string)string{sum:=sha256.Sum256([]byte("cyberpanel-backup-intake-path-v1\x00"+value));return hex.EncodeToString(sum[:])}
func isDigest(value string)bool{if len(value)!=sha256.Size*2||strings.ToLower(value)!=value{return false};decoded,err:=hex.DecodeString(value);return err==nil&&len(decoded)==sha256.Size}
func scopeText(value string)bool{return value!=""&&len(value)<=128&&!strings.ContainsAny(value,"\r\n\x00")}

func readOwnedFile(value string,maximum int64)([]byte,os.FileInfo,error){before,err:=os.Lstat(value);if err!=nil||maximum<1||!ownedFile(before)||before.Size()<1||before.Size()>maximum{return nil,nil,errors.Join(migration.ErrBlocked,err)};file,err:=os.Open(value);if err!=nil{return nil,nil,err};defer file.Close();opened,err:=file.Stat();if err!=nil||!sameFile(before,opened){return nil,nil,errors.Join(migration.ErrConflict,err)};raw,err:=io.ReadAll(io.LimitReader(file,maximum+1));if err!=nil||int64(len(raw))!=opened.Size()||int64(len(raw))>maximum{return nil,nil,errors.Join(migration.ErrInvalid,err)};final,err:=file.Stat();if err!=nil||!sameFile(opened,final){return nil,nil,errors.Join(migration.ErrConflict,err)};return raw,final,nil}
func ownedDirectory(info os.FileInfo)bool{stat,ok:=fileStat(info);return ok&&info.IsDir()&&info.Mode()&os.ModeSymlink==0&&info.Mode().Perm()==0o700&&int(stat.Uid)==os.Geteuid()}
func ownedFile(info os.FileInfo)bool{stat,ok:=fileStat(info);return ok&&info.Mode().IsRegular()&&info.Mode()&os.ModeSymlink==0&&info.Mode().Perm()==0o400&&stat.Nlink==1&&int(stat.Uid)==os.Geteuid()}
func sameDirectory(left,right os.FileInfo)bool{return ownedDirectory(left)&&ownedDirectory(right)&&os.SameFile(left,right)&&left.ModTime().Equal(right.ModTime())}
func sameFile(left,right os.FileInfo)bool{return ownedFile(left)&&ownedFile(right)&&os.SameFile(left,right)&&left.Size()==right.Size()&&left.ModTime().Equal(right.ModTime())}
func sameFilesystem(left,right os.FileInfo)bool{leftStat,leftOK:=fileStat(left);rightStat,rightOK:=fileStat(right);return leftOK&&rightOK&&leftStat.Dev==rightStat.Dev}
func fileStat(info os.FileInfo)(*syscall.Stat_t,bool){if info==nil{return nil,false};value,ok:=info.Sys().(*syscall.Stat_t);return value,ok}
func writeAll(writer io.Writer,value []byte)error{for len(value)>0{count,err:=writer.Write(value);if err!=nil{return err};if count==0{return io.ErrNoProgress};value=value[count:]};return nil}
func syncDirectory(value string)error{directory,err:=os.Open(value);if err!=nil{return err};return errors.Join(directory.Sync(),directory.Close())}
