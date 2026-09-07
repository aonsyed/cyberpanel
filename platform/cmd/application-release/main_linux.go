//go:build linux

// application-release assembles an offline panel component from real release
// inputs. It does not download, sign, invent product versions, or certify apps.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
)

type releaseInput struct {
	CatalogID string `json:"catalog_id"`
	ReleaseID string `json:"release_id"`
	Sequence uint64 `json:"sequence"`
	MinimumEpoch uint64 `json:"minimum_epoch"`
	CreatedAt time.Time `json:"created_at"`
	PanelBinary string `json:"panel_binary"`
	PanelBinarySHA256 string `json:"panel_binary_sha256"`
	Keys []releaseKey `json:"keys"`
	Recipes []string `json:"recipes"`
	Artifacts []releaseArtifact `json:"artifacts"`
	N8NRecipe string `json:"n8n_recipe"`
}

type releaseKey struct {
	ID string `json:"id"`
	Path string `json:"path"`
	MinimumEpoch uint64 `json:"minimum_epoch"`
	MaximumEpoch uint64 `json:"maximum_epoch"`
}

type releaseArtifact struct {
	SHA256 string `json:"sha256"`
	Path string `json:"path"`
}

type packageEntry struct {
	name string
	path string
	data []byte
	size int64
	digest string
	mode int64
}

type releaseVerifier struct {
	keys map[string]ed25519.PublicKey
	epochs map[string]releaseKey
	minimum uint64
}

func (verifier releaseVerifier) VerifyRecipe(ctx context.Context, id string, epoch uint64, payload, signature []byte) error {
	if err := ctx.Err(); err != nil { return err }
	key, ok := verifier.epochs[id]
	if !ok || epoch < verifier.minimum || epoch < key.MinimumEpoch || epoch > key.MaximumEpoch || !ed25519.Verify(verifier.keys[id], payload, signature) { return apps.ErrRecipeUntrusted }
	return nil
}

func main() {
	flags := flag.NewFlagSet("application-release", flag.ContinueOnError)
	inputPath := flags.String("input", "", "release input JSON; relative files resolve beside it")
	outputPath := flags.String("output", "", "new panel component .tar.gz (never overwritten)")
	if err := flags.Parse(os.Args[1:]); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }
	if *inputPath == "" || *outputPath == "" || flags.NArg() != 0 { flags.Usage(); os.Exit(2) }
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := assemble(ctx, *inputPath, *outputPath); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}

func assemble(ctx context.Context, inputPath, outputPath string) error {
	inputPath, err := filepath.Abs(inputPath)
	if err != nil { return err }
	payload, err := readInput(inputPath, 4<<20)
	if err != nil { return err }
	var input releaseInput
	if err = strictJSON(payload, &input); err != nil { return err }
	if input.CreatedAt.IsZero() || input.CreatedAt.Nanosecond() != 0 || input.CreatedAt.After(time.Now().UTC()) || len(input.Keys) == 0 || len(input.Keys) > 64 || len(input.Recipes) < 5 || len(input.Recipes) > 512 || len(input.Artifacts) == 0 || len(input.Artifacts) > 512 || input.PanelBinary == "" || input.N8NRecipe == "" { return errors.New("invalid release metadata or missing real release inputs") }
	binaryDigest, err := hex.DecodeString(input.PanelBinarySHA256)
	if err != nil || len(binaryDigest) != sha256.Size || input.PanelBinarySHA256 != strings.ToLower(input.PanelBinarySHA256) { return errors.New("panel_binary_sha256 must pin the actual release executable") }
	base := filepath.Dir(inputPath)
	resolve := func(path string) string { if filepath.IsAbs(path) { return filepath.Clean(path) }; return filepath.Join(base, path) }
	manifest := apps.LinuxApplicationCatalogManifest{SchemaVersion: 1, CatalogID: input.CatalogID, ReleaseID: input.ReleaseID, Sequence: input.Sequence, MinimumEpoch: input.MinimumEpoch, CreatedAt: input.CreatedAt.UTC()}
	verifier := releaseVerifier{keys: map[string]ed25519.PublicKey{}, epochs: map[string]releaseKey{}, minimum: input.MinimumEpoch}
	entries := []packageEntry{}
	for _, key := range input.Keys {
		if key.ID == "" || strings.ContainsAny(key.ID, "/\\") || key.Path == "" { return errors.New("invalid key input") }
		if _, exists := verifier.keys[key.ID]; exists { return errors.New("duplicate signing key") }
		encoded, readErr := readInput(resolve(key.Path), 4096)
		if readErr != nil { return readErr }
		publicKey, decodeErr := decodeKey(encoded)
		if decodeErr != nil { return decodeErr }
		verifier.keys[key.ID], verifier.epochs[key.ID] = publicKey, key
		manifest.Keys = append(manifest.Keys, apps.LinuxApplicationCatalogKey{ID: key.ID, SHA256: digest(encoded), Size: int64(len(encoded)), MinimumEpoch: key.MinimumEpoch, MaximumEpoch: key.MaximumEpoch})
		entries = append(entries, memoryEntry("application-catalog/keys/"+key.ID+".pub", encoded))
	}
	products := map[apps.ApplicationKind]bool{}
	artifacts := map[string]int64{}
	recipeIDs := map[apps.RecipeID]bool{}
	for _, path := range input.Recipes {
		if err = ctx.Err(); err != nil { return err }
		encoded, readErr := readInput(resolve(path), 4<<20)
		if readErr != nil { return readErr }
		var document apps.SignedRecipeDocument
		if err = strictJSON(encoded, &document); err != nil { return err }
		definition, verifyErr := apps.VerifySignedRecipeDocument(ctx, document, verifier, input.CreatedAt)
		if verifyErr != nil { return fmt.Errorf("%s: %w", path, verifyErr) }
		if err = apps.ValidateCertifiedProductDefinition(definition, input.CreatedAt); err != nil { return fmt.Errorf("%s: %w", path, err) }
		if recipeIDs[document.Reference.ID] { return errors.New("duplicate recipe ID") }
		recipeIDs[document.Reference.ID] = true
		products[definition.Kind] = true
		if size, exists := artifacts[definition.Artifact.Digest]; exists && size != definition.Artifact.Size { return errors.New("artifact size conflict") }
		artifacts[definition.Artifact.Digest] = definition.Artifact.Size
		// Normalize only the unsigned envelope serialization; signed bytes remain exact.
		encoded, err = json.Marshal(document)
		if err != nil { return err }
		manifest.Recipes = append(manifest.Recipes, apps.LinuxApplicationCatalogRecipe{ID: document.Reference.ID, SHA256: digest(encoded), Size: int64(len(encoded))})
		entries = append(entries, memoryEntry("application-catalog/recipes/"+string(document.Reference.ID)+".json", encoded))
	}
	for kind := range apps.CertifiedProductContracts() { if !products[kind] { return fmt.Errorf("missing required %s definition", kind) } }
	if len(artifacts) != len(input.Artifacts) { return errors.New("artifact inventory must exactly match signed recipes") }
	seenArtifacts := map[string]bool{}
	for _, artifact := range input.Artifacts {
		size, exists := artifacts[artifact.SHA256]
		if !exists || seenArtifacts[artifact.SHA256] || artifact.Path == "" { return errors.New("unreferenced or duplicate artifact input") }
		seenArtifacts[artifact.SHA256] = true
		path := resolve(artifact.Path)
		if err = apps.ValidateReleaseApplicationArchive(path); err != nil { return fmt.Errorf("%s: %w", path, err) }
		entries = append(entries, packageEntry{name: "application-catalog/artifacts/"+artifact.SHA256+".tar.gz", path: path, size: size, digest: artifact.SHA256, mode: 0444})
		manifest.Artifacts = append(manifest.Artifacts, apps.LinuxApplicationCatalogArtifact{SHA256: artifact.SHA256, Size: size})
	}
	sort.Slice(manifest.Keys, func(i, j int) bool { return manifest.Keys[i].ID < manifest.Keys[j].ID })
	sort.Slice(manifest.Recipes, func(i, j int) bool { return manifest.Recipes[i].ID < manifest.Recipes[j].ID })
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].SHA256 < manifest.Artifacts[j].SHA256 })
	manifest.ContentDigest, err = manifest.Digest()
	if err != nil { return err }
	if err = manifest.Validate(input.CreatedAt); err != nil { return err }
	encoded, err := json.Marshal(manifest)
	if err != nil { return err }
	entries = append(entries, memoryEntry("application-catalog/manifest.json", encoded))
	n8nBytes, err := readInput(resolve(input.N8NRecipe), 4<<20)
	if err != nil { return err }
	var n8n containers.ApplicationRecipe
	if err = strictJSON(n8nBytes, &n8n); err != nil { return err }
	n8nVerifier, err := containers.NewSignedRecipeVerifier(verifier.keys)
	if err != nil { return err }
	if err = n8nVerifier.Verify(ctx, n8n); err != nil { return fmt.Errorf("n8n signature: %w", err) }
	if err = integrations.ValidateN8NApplicationRecipe(n8n); err != nil { return fmt.Errorf("n8n contract: %w", err) }
	n8nBytes, err = json.Marshal(n8n)
	if err != nil { return err }
	entries = append(entries, memoryEntry("container-recipes/n8n.json", n8nBytes))
	binary, err := openInput(resolve(input.PanelBinary), 1<<30)
	if err != nil { return err }
	defer binary.Close()
	executable, err := elf.NewFile(binary)
	if err != nil { return errors.New("panel binary must be an ELF executable") }
	platform := ""
	if executable.Class == elf.ELFCLASS64 && (executable.Type == elf.ET_EXEC || executable.Type == elf.ET_DYN) {
		if executable.Machine == elf.EM_X86_64 { platform = "linux/amd64" }
		if executable.Machine == elf.EM_AARCH64 { platform = "linux/arm64" }
	}
	if platform == "" { return errors.New("unsupported panel executable architecture") }
	for _, workload := range n8n.Workloads { if workload.Spec.Image.Platform != platform { return errors.New("n8n image platform must match the panel executable") } }
	info, err := binary.Stat()
	closeErr := binary.Close()
	if err != nil || closeErr != nil { return errors.Join(err, closeErr) }
	entries = append(entries, packageEntry{name: "cyberpanel", path: resolve(input.PanelBinary), size: info.Size(), digest: input.PanelBinarySHA256, mode: 0555})
	return publish(ctx, outputPath, input.CreatedAt.UTC(), entries)
}

func memoryEntry(name string, payload []byte) packageEntry {
	return packageEntry{name: name, data: payload, size: int64(len(payload)), digest: digest(payload), mode: 0444}
}

func publish(ctx context.Context, output string, created time.Time, entries []packageEntry) (err error) {
	output, err = filepath.Abs(output)
	if err != nil { return err }
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) { return errors.New("output already exists or cannot be inspected") }
	file, err := os.CreateTemp(filepath.Dir(output), ".application-release-*.tar.gz")
	if err != nil { return err }
	temporary := file.Name()
	defer func() { _ = file.Close(); _ = os.Remove(temporary) }()
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	// Stable directory headers make installer ownership/modes independent of umask.
	for _, directory := range []string{"application-catalog", "application-catalog/artifacts", "application-catalog/keys", "application-catalog/recipes", "container-recipes"} {
		if err = archive.WriteHeader(&tar.Header{Name: directory+"/", Typeflag: tar.TypeDir, Mode: 0755, ModTime: created, Format: tar.FormatPAX}); err != nil { return err }
	}
	for _, entry := range entries {
		if err = writeEntry(ctx, archive, entry, created); err != nil { return err }
	}
	if err = archive.Close(); err != nil { return err }
	if err = compressed.Close(); err != nil { return err }
	if err = file.Chmod(0444); err != nil { return err }
	if err = file.Sync(); err != nil { return err }
	if err = file.Close(); err != nil { return err }
	if err = ctx.Err(); err != nil { return err }
	// Link is atomic and fails if another producer already published this name.
	if err = os.Link(temporary, output); err != nil { return err }
	parent, err := os.Open(filepath.Dir(output))
	if err != nil { return err }
	defer parent.Close()
	return parent.Sync()
}

func writeEntry(ctx context.Context, archive *tar.Writer, entry packageEntry, created time.Time) error {
	if err := ctx.Err(); err != nil { return err }
	var reader io.Reader = bytes.NewReader(entry.data)
	if entry.path != "" {
		file, err := openInput(entry.path, entry.size)
		if err != nil { return err }
		defer file.Close()
		info, err := file.Stat()
		if err != nil || info.Size() != entry.size { return errors.New("input size changed") }
		reader = file
	}
	if err := archive.WriteHeader(&tar.Header{Name: entry.name, Typeflag: tar.TypeReg, Mode: entry.mode, Size: entry.size, ModTime: created, Format: tar.FormatPAX}); err != nil { return err }
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(archive, hash), &contextReader{ctx: ctx, reader: io.LimitReader(reader, entry.size+1)})
	if err != nil { return err }
	if count != entry.size || entry.digest != "" && hex.EncodeToString(hash.Sum(nil)) != entry.digest { return fmt.Errorf("%s: signed artifact digest/size mismatch", entry.name) }
	return nil
}

type contextReader struct { ctx context.Context; reader io.Reader }
func (reader *contextReader) Read(buffer []byte) (int, error) { if err := reader.ctx.Err(); err != nil { return 0, err }; return reader.reader.Read(buffer) }

func openInput(path string, maximum int64) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil { return nil, err }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum { _ = file.Close(); return nil, errors.New("input must be a bounded regular file, not a symlink") }
	return file, nil
}

func readInput(path string, maximum int64) ([]byte, error) {
	file, err := openInput(path, maximum)
	if err != nil { return nil, err }
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum { return nil, errors.New("oversized release input") }
	return payload, nil
}

func strictJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return err }
	if decoder.Decode(&struct{}{}) != io.EOF { return errors.New("trailing JSON data") }
	return nil
}

func decodeKey(encoded []byte) (ed25519.PublicKey, error) {
	if block, rest := pem.Decode(encoded); block != nil {
		if block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 { return nil, errors.New("invalid public key PEM") }
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil { return nil, err }
		key, ok := parsed.(ed25519.PublicKey)
		if !ok { return nil, errors.New("public key must be Ed25519") }
		return key, nil
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(key) != ed25519.PublicKeySize { return nil, errors.New("invalid Ed25519 public key") }
	return ed25519.PublicKey(key), nil
}

func digest(payload []byte) string { sum := sha256.Sum256(payload); return hex.EncodeToString(sum[:]) }
