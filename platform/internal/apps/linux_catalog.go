//go:build linux

package apps

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultApplicationCatalogRoot = "/usr/share/cyberpanel/application-catalog"

type LinuxRecipeCatalogAuthority struct{ Root string }

func NewLinuxRecipeCatalogAuthority(root string) (*LinuxRecipeCatalogAuthority, error) {
	if root == "" {
		root = DefaultApplicationCatalogRoot
	}
	if !validCatalogAbsolutePath(root) {
		return nil, ErrInvalid
	}
	return &LinuxRecipeCatalogAuthority{Root: root}, nil
}

func (authority *LinuxRecipeCatalogAuthority) FetchRecipe(_ context.Context, reference RecipeReference) (SignedRecipeDocument, error) {
	if authority == nil || !validID(string(reference.ID)) {
		return SignedRecipeDocument{}, ErrInvalid
	}
	root, manifest, err := linuxApplicationCatalogSnapshot(authority.Root, time.Now().UTC())
	if err != nil {
		return SignedRecipeDocument{}, err
	}
	return authority.fetchRecipeFrom(root, manifest, reference.ID, true)
}

func (authority *LinuxRecipeCatalogAuthority) fetchRecipeFrom(root string, manifest LinuxApplicationCatalogManifest, id RecipeID, immutable bool) (SignedRecipeDocument, error) {
	entry, found := catalogManifestRecipe(manifest, id)
	if !found {
		return SignedRecipeDocument{}, ErrRecipeUnavailable
	}
	path := filepath.Join(root, "recipes", string(id)+".json")
	if !strings.HasPrefix(path, filepath.Join(root, "recipes")+string(os.PathSeparator)) {
		return SignedRecipeDocument{}, ErrPolicyDenied
	}
	payload, err := readRootCatalogFile(path, entry.Size, immutable)
	if err != nil || int64(len(payload)) != entry.Size || linuxApplicationCatalogDigest(payload) != entry.SHA256 {
		return SignedRecipeDocument{}, errors.Join(ErrRecipeUntrusted, err)
	}
	var document SignedRecipeDocument
	if decodeLinuxApplicationCatalogJSON(payload, &document) != nil || len(document.CanonicalPayload) == 0 || len(document.CanonicalPayload) > 4<<20 || len(document.Signature) != ed25519.SignatureSize || document.Reference.ID != id {
		return SignedRecipeDocument{}, ErrRecipeUntrusted
	}
	return document, nil
}

func (authority *LinuxRecipeCatalogAuthority) ReferenceByID(ctx context.Context, id RecipeID) (RecipeReference, error) {
	if authority == nil || !validID(string(id)) {
		return RecipeReference{}, ErrInvalid
	}
	root, manifest, err := linuxApplicationCatalogSnapshot(authority.Root, time.Now().UTC())
	if err != nil {
		return RecipeReference{}, err
	}
	document, err := authority.fetchRecipeFrom(root, manifest, id, true)
	if err != nil {
		return RecipeReference{}, err
	}
	if document.Reference.Validate(time.Now().UTC()) != nil || document.Reference.CatalogEpoch < manifest.MinimumEpoch {
		return RecipeReference{}, ErrRecipeUntrusted
	}
	if err = authority.verifyRecipeFrom(root, manifest, document.Reference.SigningKeyID, document.Reference.CatalogEpoch, document.CanonicalPayload, document.Signature, true); err != nil {
		return RecipeReference{}, err
	}
	return document.Reference, nil
}

func (authority *LinuxRecipeCatalogAuthority) References(ctx context.Context) ([]RecipeReference, error) {
	if authority == nil {
		return nil, ErrInvalid
	}
	now := time.Now().UTC()
	root, manifest, err := linuxApplicationCatalogSnapshot(authority.Root, now)
	if err != nil {
		return nil, err
	}
	references := make([]RecipeReference, 0, len(manifest.Recipes))
	for _, entry := range manifest.Recipes {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		document, fetchErr := authority.fetchRecipeFrom(root, manifest, entry.ID, true)
		if fetchErr != nil || document.Reference.Validate(now) != nil || document.Reference.CatalogEpoch < manifest.MinimumEpoch || authority.verifyRecipeFrom(root, manifest, document.Reference.SigningKeyID, document.Reference.CatalogEpoch, document.CanonicalPayload, document.Signature, true) != nil {
			return nil, ErrRecipeUntrusted
		}
		references = append(references, document.Reference)
	}
	return references, nil
}

func (authority *LinuxRecipeCatalogAuthority) VerifyRecipe(_ context.Context, keyID string, epoch uint64, payload, signature []byte) error {
	if authority == nil {
		return ErrRecipeUntrusted
	}
	root, manifest, err := linuxApplicationCatalogSnapshot(authority.Root, time.Now().UTC())
	if err != nil {
		return ErrRecipeUntrusted
	}
	return authority.verifyRecipeFrom(root, manifest, keyID, epoch, payload, signature, true)
}

func (authority *LinuxRecipeCatalogAuthority) verifyRecipeFrom(root string, manifest LinuxApplicationCatalogManifest, keyID string, epoch uint64, payload, signature []byte, immutable bool) error {
	if !validID(keyID) || epoch < manifest.MinimumEpoch || len(payload) == 0 || len(payload) > 4<<20 || len(signature) != ed25519.SignatureSize {
		return ErrRecipeUntrusted
	}
	entry, found := catalogManifestKey(manifest, keyID, epoch)
	if !found {
		return ErrRecipeUntrusted
	}
	path := filepath.Join(root, "keys", keyID+".pub")
	if !strings.HasPrefix(path, filepath.Join(root, "keys")+string(os.PathSeparator)) {
		return ErrRecipeUntrusted
	}
	encoded, err := readRootCatalogFile(path, entry.Size, immutable)
	if err != nil || int64(len(encoded)) != entry.Size || linuxApplicationCatalogDigest(encoded) != entry.SHA256 {
		return ErrRecipeUntrusted
	}
	publicKey, err := decodeLinuxApplicationCatalogPublicKey(encoded)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrRecipeUntrusted
	}
	return nil
}

func decodeLinuxApplicationCatalogPublicKey(encoded []byte) (ed25519.PublicKey, error) {
	block, remainder := pem.Decode(encoded)
	if block != nil {
		if block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(remainder))) != 0 {
			return nil, ErrRecipeUntrusted
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrRecipeUntrusted
		}
		publicKey, ok := parsed.(ed25519.PublicKey)
		if !ok || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrRecipeUntrusted
		}
		return publicKey, nil
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, ErrRecipeUntrusted
	}
	return ed25519.PublicKey(decoded), nil
}

func (authority *LinuxRecipeCatalogAuthority) VerifyAutologinBridge(_ context.Context, keyID, digest, signature string) error {
	if !validDigest(digest) || signature == "" {
		return ErrRecipeUntrusted
	}
	decoded, err := hex.DecodeString(signature)
	if err != nil {
		return ErrRecipeUntrusted
	}
	return authority.VerifyRecipe(context.Background(), keyID, 1, []byte(digest), decoded)
}

func NewLinuxPinnedApplicationCatalog(root string) (*PinnedCatalog, *LinuxRecipeCatalogAuthority, error) {
	authority, err := NewLinuxRecipeCatalogAuthority(root)
	if err != nil {
		return nil, nil, err
	}
	_, manifest, err := linuxApplicationCatalogSnapshot(authority.Root, time.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	catalog := &PinnedCatalog{Source: authority, Verifier: authority, MinimumEpoch: manifest.MinimumEpoch, MaximumPayload: 4 << 20}
	return catalog, authority, nil
}

var _ RecipeSource = (*LinuxRecipeCatalogAuthority)(nil)
var _ RecipeVerifier = (*LinuxRecipeCatalogAuthority)(nil)
var _ AutologinBridgeVerifier = (*LinuxRecipeCatalogAuthority)(nil)
