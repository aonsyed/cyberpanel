package themes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

const manifestSignatureDomain = "cyberpanel-theme-manifest-v1"

type Verifier struct{ policy TrustPolicy }

func NewVerifier(policy TrustPolicy) (*Verifier, error) {
	if len(policy.Keys) == 0 || !validVersion(policy.PlatformVersion) {
		return nil, ErrInvalid
	}
	if policy.MaximumAssets == 0 {
		policy.MaximumAssets = DefaultMaximumAssets
	}
	if policy.MaximumAssetBytes == 0 {
		policy.MaximumAssetBytes = DefaultMaximumAssetBytes
	}
	if policy.MaximumTotalBytes == 0 {
		policy.MaximumTotalBytes = DefaultMaximumTotalBytes
	}
	if policy.Clock == nil {
		policy.Clock = time.Now
	}
	if policy.MaximumAssets < 1 || policy.MaximumAssets > 4096 || policy.MaximumAssetBytes < 1 || policy.MaximumTotalBytes < policy.MaximumAssetBytes {
		return nil, ErrInvalid
	}
	keys := make(map[string]TrustedKey, len(policy.Keys))
	for id, key := range policy.Keys {
		if id != key.ID || !validIdentifier(id) || key.Issuer == "" || key.Issuer != strings.TrimSpace(key.Issuer) || len(key.Issuer) > 128 || len(key.PublicKey) != ed25519.PublicKeySize || key.NotBefore.IsZero() || key.NotAfter.IsZero() || !key.NotAfter.After(key.NotBefore) {
			return nil, ErrInvalid
		}
		key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
		keys[id] = key
	}
	policy.Keys = keys
	return &Verifier{policy: policy}, nil
}

func (verifier *Verifier) VerifyManifest(ctx context.Context, manifest Manifest) (Manifest, error) {
	if verifier == nil || ctx == nil {
		return Manifest{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	canonical, err := validateAndCanonicalizeManifest(manifest, verifier.policy.MaximumAssets, verifier.policy.MaximumAssetBytes, verifier.policy.MaximumTotalBytes)
	if err != nil {
		return Manifest{}, err
	}
	if !compatible(verifier.policy.PlatformVersion, canonical.Compatibility) {
		return Manifest{}, ErrUnsupported
	}
	now := verifier.policy.Clock().UTC()
	key, trusted := verifier.policy.Keys[canonical.SigningKeyID]
	if !trusted || key.Revoked || key.Issuer != canonical.Issuer || now.Before(key.NotBefore) || now.After(key.NotAfter) || canonical.IssuedAt.Before(key.NotBefore) || canonical.IssuedAt.After(key.NotAfter) || canonical.IssuedAt.After(now.Add(5*time.Minute)) {
		return Manifest{}, ErrDenied
	}
	unsigned, err := unsignedManifestBytes(canonical)
	if err != nil {
		return Manifest{}, ErrIntegrity
	}
	actual := sha256.Sum256(unsigned)
	if hex.EncodeToString(actual[:]) != canonical.Digest {
		return Manifest{}, ErrIntegrity
	}
	message := manifestSignatureMessage(canonical.Digest, unsigned)
	if len(canonical.Signature) != ed25519.SignatureSize || !ed25519.Verify(key.PublicKey, message, canonical.Signature) {
		return Manifest{}, ErrDenied
	}
	return canonical, nil
}

func (verifier *Verifier) VerifyPackage(ctx context.Context, candidate Package) (VerifiedPackage, error) {
	manifest, err := verifier.VerifyManifest(ctx, candidate.Manifest)
	if err != nil {
		return VerifiedPackage{}, err
	}
	if len(candidate.Assets) != len(manifest.Assets) {
		return VerifiedPackage{}, ErrIntegrity
	}
	byPath := make(map[string]PackageAsset, len(candidate.Assets))
	casePaths := make(map[string]struct{}, len(candidate.Assets))
	for _, asset := range candidate.Assets {
		if err := ctx.Err(); err != nil {
			return VerifiedPackage{}, err
		}
		if !safeAssetPath(asset.Path) || asset.LinkTarget != "" || asset.Mode.Type() != 0 || asset.Mode.Perm()&0o111 != 0 || asset.Mode.Perm()&0o022 != 0 {
			return VerifiedPackage{}, ErrDenied
		}
		folded := strings.ToLower(asset.Path)
		if _, duplicate := byPath[asset.Path]; duplicate {
			return VerifiedPackage{}, ErrInvalid
		}
		if _, collision := casePaths[folded]; collision {
			return VerifiedPackage{}, ErrDenied
		}
		casePaths[folded] = struct{}{}
		asset.Content = append([]byte(nil), asset.Content...)
		byPath[asset.Path] = asset
	}
	verified := VerifiedPackage{Manifest: manifest, assets: make([]PackageAsset, 0, len(manifest.Assets))}
	canonicalManifest, _ := json.Marshal(manifest)
	verified.total = uint64(len(canonicalManifest))
	for _, descriptor := range manifest.Assets {
		asset, exists := byPath[descriptor.Path]
		if !exists || uint64(len(asset.Content)) != descriptor.Size || descriptor.Size > verifier.policy.MaximumAssetBytes || !validMagic(descriptor.MIME, asset.Content) {
			return VerifiedPackage{}, ErrIntegrity
		}
		sum := sha256.Sum256(asset.Content)
		if hex.EncodeToString(sum[:]) != descriptor.SHA256 {
			return VerifiedPackage{}, ErrIntegrity
		}
		verified.total += descriptor.Size
		if verified.total > verifier.policy.MaximumTotalBytes {
			return VerifiedPackage{}, ErrCapacity
		}
		asset.Mode = 0o600
		verified.assets = append(verified.assets, asset)
	}
	return verified, nil
}

func SignManifest(manifest Manifest, keyID string, privateKey ed25519.PrivateKey) (Manifest, error) {
	if !validIdentifier(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, ErrInvalid
	}
	manifest.SigningKeyID = keyID
	manifest.Signature = nil
	manifest.Digest = strings.Repeat("0", 64)
	manifest.Assets = append([]AssetDescriptor(nil), manifest.Assets...)
	sort.Slice(manifest.Assets, func(i, j int) bool { return manifest.Assets[i].Path < manifest.Assets[j].Path })
	canonical, err := validateAndCanonicalizeManifest(manifest, 4096, DefaultMaximumAssetBytes, 1<<40)
	if err != nil {
		return Manifest{}, err
	}
	canonical.Digest = ""
	unsigned, err := unsignedManifestBytes(canonical)
	if err != nil {
		return Manifest{}, err
	}
	sum := sha256.Sum256(unsigned)
	canonical.Digest = hex.EncodeToString(sum[:])
	canonical.Signature = ed25519.Sign(privateKey, manifestSignatureMessage(canonical.Digest, unsigned))
	return canonical, nil
}

func validateAndCanonicalizeManifest(manifest Manifest, maximumAssets int, maximumAssetBytes, maximumTotalBytes uint64) (Manifest, error) {
	if manifest.SchemaVersion != 1 || !themeIDPattern.MatchString(manifest.ThemeID) || !validVersion(manifest.Version) || manifest.Issuer == "" || manifest.Issuer != strings.TrimSpace(manifest.Issuer) || len(manifest.Issuer) > 128 || !validIdentifier(manifest.SigningKeyID) || manifest.IssuedAt.IsZero() || !validDigest(manifest.Digest) || len(manifest.Assets) == 0 {
		return Manifest{}, ErrInvalid
	}
	if !validVersion(manifest.Compatibility.Minimum) || !validVersion(manifest.Compatibility.Maximum) || compareVersions(manifest.Compatibility.Minimum, manifest.Compatibility.Maximum) > 0 || len(manifest.Assets) > maximumAssets {
		return Manifest{}, ErrInvalid
	}
	canonical := manifest
	canonical.Signature = append([]byte(nil), manifest.Signature...)
	canonical.Assets = append([]AssetDescriptor(nil), manifest.Assets...)
	sort.Slice(canonical.Assets, func(i, j int) bool { return canonical.Assets[i].Path < canonical.Assets[j].Path })
	seen, folded := map[string]struct{}{}, map[string]struct{}{}
	var total uint64
	assetTypes := make(map[string]string, len(canonical.Assets))
	for index, asset := range canonical.Assets {
		if !safeAssetPath(asset.Path) || !validAssetMIME(asset.Path, asset.MIME) || asset.Size == 0 || asset.Size > maximumAssetBytes || !validDigest(asset.SHA256) {
			return Manifest{}, ErrInvalid
		}
		lower := strings.ToLower(asset.Path)
		if _, exists := seen[asset.Path]; exists {
			return Manifest{}, ErrInvalid
		}
		if _, exists := folded[lower]; exists {
			return Manifest{}, ErrDenied
		}
		if index > 0 && manifest.Assets[index-1].Path >= manifest.Assets[index].Path {
			return Manifest{}, ErrInvalid
		}
		seen[asset.Path], folded[lower], assetTypes[asset.Path] = struct{}{}, struct{}{}, asset.MIME
		if asset.Size > maximumTotalBytes-total {
			return Manifest{}, ErrCapacity
		}
		total += asset.Size
	}
	if err := validateTokens(canonical.Tokens, assetTypes); err != nil {
		return Manifest{}, err
	}
	return canonical, nil
}

func validateTokens(tokens DesignTokens, assets map[string]string) error {
	if tokens.BrandName == "" || tokens.BrandName != strings.TrimSpace(tokens.BrandName) || len(tokens.BrandName) > 80 || strings.ContainsAny(tokens.BrandName, "\x00\r\n<>") {
		return ErrInvalid
	}
	for _, color := range []string{tokens.PrimaryColor, tokens.AccentColor, tokens.LightSurface, tokens.LightText, tokens.DarkSurface, tokens.DarkText} {
		if !validColor(color) {
			return ErrInvalid
		}
	}
	for _, reference := range []struct {
		path string
		font bool
	}{{tokens.LogoAsset, false}, {tokens.FaviconAsset, false}, {tokens.FontRegularAsset, true}, {tokens.FontBoldAsset, true}} {
		if reference.path == "" {
			continue
		}
		mime, exists := assets[reference.path]
		if !exists || reference.font && mime != "font/woff2" || !reference.font && !strings.HasPrefix(mime, "image/") {
			return ErrInvalid
		}
	}
	return nil
}

func validColor(value string) bool {
	if len(value) != 7 && len(value) != 9 || value[0] != '#' {
		return false
	}
	for _, character := range value[1:] {
		if character < '0' || character > '9' && character < 'A' || character > 'F' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func safeAssetPath(value string) bool {
	if value == "" || len(value) > 240 || !fs.ValidPath(value) || path.Clean(value) != value || strings.ContainsAny(value, "\\\x00") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || strings.HasPrefix(component, ".") || len(component) > 120 {
			return false
		}
	}
	return true
}

func validAssetMIME(name, mime string) bool {
	extension := strings.ToLower(path.Ext(name))
	switch mime {
	case "image/png":
		return extension == ".png"
	case "image/jpeg":
		return extension == ".jpg" || extension == ".jpeg"
	case "image/webp":
		return extension == ".webp"
	case "font/woff2":
		return extension == ".woff2"
	default:
		return false
	}
}

func validMagic(mime string, content []byte) bool {
	switch mime {
	case "image/png":
		return len(content) >= 8 && bytes.Equal(content[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	case "image/jpeg":
		return len(content) >= 3 && content[0] == 0xff && content[1] == 0xd8 && content[2] == 0xff
	case "image/webp":
		return len(content) >= 12 && string(content[:4]) == "RIFF" && string(content[8:12]) == "WEBP"
	case "font/woff2":
		return len(content) >= 4 && string(content[:4]) == "wOF2"
	default:
		return false
	}
}

func unsignedManifestBytes(manifest Manifest) ([]byte, error) {
	manifest.Digest = ""
	manifest.Signature = nil
	return json.Marshal(manifest)
}

func manifestSignatureMessage(digest string, canonical []byte) []byte {
	message := make([]byte, 0, len(manifestSignatureDomain)+len(digest)+len(canonical)+2)
	message = append(message, manifestSignatureDomain...)
	message = append(message, 0)
	message = append(message, digest...)
	message = append(message, 0)
	return append(message, canonical...)
}

func validDigest(value string) bool {
	return len(value) == sha256.Size*2 && strings.Trim(value, "0123456789abcdef") == ""
}

func validVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 9 || len(part) > 1 && part[0] == '0' {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func compareVersions(left, right string) int {
	leftParts, rightParts := strings.Split(left, "."), strings.Split(right, ".")
	for index := 0; index < 3; index++ {
		leftValue, _ := strconv.ParseUint(leftParts[index], 10, 32)
		rightValue, _ := strconv.ParseUint(rightParts[index], 10, 32)
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}

func compatible(current string, allowed CompatibilityRange) bool {
	return compareVersions(current, allowed.Minimum) >= 0 && compareVersions(current, allowed.Maximum) <= 0
}
