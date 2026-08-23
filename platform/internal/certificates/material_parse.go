package certificates

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"sort"
	"strings"
	"time"
)

type MaterialNamePolicy struct {
	DNSNames             []string
	IPAddresses          []string
	AllowAdditionalNames bool
	AllowWildcards       bool
}

// MaterialImportPolicy must carry roots selected by trusted product policy.
// Certificates included in the import are never promoted to trust anchors.
type MaterialImportPolicy struct {
	Names                   MaterialNamePolicy
	TrustRoots              *x509.CertPool
	TrustLabel              MaterialTrustLabel
	AllowedKeyAlgorithms    []MaterialKeyAlgorithm
	MinimumRSAKeyBits       int
	MinimumRemainingLifetime time.Duration
	MaximumLifetime         time.Duration
	MaximumFutureSkew       time.Duration
	Now                     time.Time
}

type parsedImportedMaterial struct {
	Subject                string
	DNSNames               []string
	IPAddresses            []string
	Issuer                 string
	SerialHex              string
	LeafFingerprintSHA256  string
	SPKIFingerprintSHA256  string
	ChainFingerprintSHA256 string
	KeyAlgorithm           MaterialKeyAlgorithm
	KeyBits                int
	NotBefore              time.Time
	NotAfter               time.Time
	LeafDER                []byte
	Chain                  []MaterialCertificateEntry
	PrivateKeyPKCS8        []byte
}

func parseImportedMaterial(content []byte, policy MaterialImportPolicy) (parsedImportedMaterial, error) {
	if len(content) == 0 || len(content) > MaximumMaterialPEMBytes {
		return parsedImportedMaterial{}, ErrMaterialInvalid
	}
	policy, err := normalizeMaterialImportPolicy(policy)
	if err != nil {
		return parsedImportedMaterial{}, err
	}
	certificates := make([]*x509.Certificate, 0, 4)
	var keyDER []byte
	var keyType string
	rest := content
	for len(bytes.TrimSpace(rest)) != 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			wipeMaterialBytes(keyDER)
			return parsedImportedMaterial{}, ErrMaterialInvalid
		}
		block, next := pem.Decode(rest)
		if block == nil || len(block.Headers) != 0 || len(next) >= len(rest) {
			wipeMaterialBytes(keyDER)
			return parsedImportedMaterial{}, ErrMaterialInvalid
		}
		switch block.Type {
		case "CERTIFICATE":
			if len(certificates) >= MaximumMaterialCertificates {
				wipeMaterialBytes(keyDER, block.Bytes)
				return parsedImportedMaterial{}, ErrMaterialInvalid
			}
			certificate, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr != nil {
				wipeMaterialBytes(keyDER, block.Bytes)
				return parsedImportedMaterial{}, ErrMaterialInvalid
			}
			certificates = append(certificates, certificate)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if keyDER != nil {
				wipeMaterialBytes(keyDER, block.Bytes)
				return parsedImportedMaterial{}, ErrMaterialInvalid
			}
			keyType = block.Type
			keyDER = append([]byte(nil), block.Bytes...)
			wipeMaterialBytes(block.Bytes)
		default:
			wipeMaterialBytes(keyDER, block.Bytes)
			return parsedImportedMaterial{}, ErrMaterialInvalid
		}
		rest = next
	}
	defer wipeMaterialBytes(keyDER)
	if len(certificates) == 0 || len(certificates) > MaximumMaterialCertificates || keyDER == nil {
		return parsedImportedMaterial{}, ErrMaterialInvalid
	}
	privateKey, err := parseMaterialPrivateKey(keyType, keyDER)
	if err != nil {
		return parsedImportedMaterial{}, err
	}
	defer wipeParsedMaterialPrivateKey(privateKey)
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return parsedImportedMaterial{}, ErrMaterialInvalid
	}
	algorithm, keyBits, err := validateMaterialSigner(signer, policy.AllowedKeyAlgorithms, policy.MinimumRSAKeyBits)
	if err != nil {
		return parsedImportedMaterial{}, err
	}
	leaf := certificates[0]
	if leaf.IsCA || bytes.Equal(leaf.RawIssuer, leaf.RawSubject) || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return parsedImportedMaterial{}, ErrMaterialInvalid
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(publicDER, leaf.RawSubjectPublicKeyInfo) {
		wipeMaterialBytes(publicDER)
		return parsedImportedMaterial{}, ErrMaterialInvalid
	}
	wipeMaterialBytes(publicDER)
	if err = validateMaterialCertificateAlgorithms(certificates); err != nil {
		return parsedImportedMaterial{}, err
	}
	dnsNames, ipAddresses, err := validateMaterialCertificateNames(leaf, policy.Names)
	if err != nil {
		return parsedImportedMaterial{}, err
	}
	if err = validateMaterialLifetime(leaf, policy); err != nil {
		return parsedImportedMaterial{}, err
	}
	if err = validateMaterialChain(certificates, policy.TrustRoots, policy.Now); err != nil {
		return parsedImportedMaterial{}, err
	}
	privateKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil || len(privateKeyPKCS8) == 0 || len(privateKeyPKCS8) > MaximumMaterialPEMBytes/2 {
		wipeMaterialBytes(privateKeyPKCS8)
		return parsedImportedMaterial{}, ErrMaterialInvalid
	}
	entries := make([]MaterialCertificateEntry, len(certificates))
	chainHash := sha256.New()
	for index, certificate := range certificates {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(certificate.Raw)))
		_, _ = chainHash.Write(size[:])
		_, _ = chainHash.Write(certificate.Raw)
		fingerprint := sha256.Sum256(certificate.Raw)
		entries[index] = MaterialCertificateEntry{
			DER: append([]byte(nil), certificate.Raw...),
			FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
			Subject: certificate.Subject.String(),
			Issuer: certificate.Issuer.String(),
			SerialHex: strings.ToLower(certificate.SerialNumber.Text(16)),
			NotBefore: certificate.NotBefore.UTC(),
			NotAfter: certificate.NotAfter.UTC(),
		}
	}
	leafFingerprint := sha256.Sum256(leaf.Raw)
	spkiFingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return parsedImportedMaterial{
		Subject: leaf.Subject.String(),
		DNSNames: dnsNames,
		IPAddresses: ipAddresses,
		Issuer: leaf.Issuer.String(),
		SerialHex: strings.ToLower(leaf.SerialNumber.Text(16)),
		LeafFingerprintSHA256: hex.EncodeToString(leafFingerprint[:]),
		SPKIFingerprintSHA256: hex.EncodeToString(spkiFingerprint[:]),
		ChainFingerprintSHA256: hex.EncodeToString(chainHash.Sum(nil)),
		KeyAlgorithm: algorithm,
		KeyBits: keyBits,
		NotBefore: leaf.NotBefore.UTC(),
		NotAfter: leaf.NotAfter.UTC(),
		LeafDER: append([]byte(nil), leaf.Raw...),
		Chain: entries,
		PrivateKeyPKCS8: privateKeyPKCS8,
	}, nil
}

func normalizeMaterialImportPolicy(policy MaterialImportPolicy) (MaterialImportPolicy, error) {
	if policy.TrustRoots == nil || (policy.TrustLabel != MaterialTrustPublicValidated && policy.TrustLabel != MaterialTrustPrivateValidated) {
		return MaterialImportPolicy{}, ErrMaterialInvalid
	}
	if policy.Now.IsZero() {
		policy.Now = time.Now().UTC()
	} else {
		policy.Now = policy.Now.UTC()
	}
	if len(policy.AllowedKeyAlgorithms) == 0 {
		policy.AllowedKeyAlgorithms = []MaterialKeyAlgorithm{MaterialKeyRSA, MaterialKeyECDSA, MaterialKeyEd25519}
	}
	if len(policy.AllowedKeyAlgorithms) > 3 {
		return MaterialImportPolicy{}, ErrMaterialInvalid
	}
	seenAlgorithms := make(map[MaterialKeyAlgorithm]struct{}, len(policy.AllowedKeyAlgorithms))
	for _, algorithm := range policy.AllowedKeyAlgorithms {
		if algorithm != MaterialKeyRSA && algorithm != MaterialKeyECDSA && algorithm != MaterialKeyEd25519 {
			return MaterialImportPolicy{}, ErrMaterialInvalid
		}
		if _, exists := seenAlgorithms[algorithm]; exists {
			return MaterialImportPolicy{}, ErrMaterialInvalid
		}
		seenAlgorithms[algorithm] = struct{}{}
	}
	if policy.MinimumRSAKeyBits == 0 {
		policy.MinimumRSAKeyBits = 2048
	}
	if policy.MinimumRSAKeyBits < 2048 || policy.MinimumRSAKeyBits > 8192 {
		return MaterialImportPolicy{}, ErrMaterialInvalid
	}
	if policy.MinimumRemainingLifetime == 0 {
		policy.MinimumRemainingLifetime = time.Hour
	}
	if policy.MaximumLifetime == 0 {
		policy.MaximumLifetime = 398 * 24 * time.Hour
	}
	if policy.MaximumFutureSkew == 0 {
		policy.MaximumFutureSkew = 5 * time.Minute
	}
	if policy.MinimumRemainingLifetime < time.Minute || policy.MinimumRemainingLifetime > 90*24*time.Hour ||
		policy.MaximumLifetime < time.Hour || policy.MaximumLifetime > 5*365*24*time.Hour ||
		policy.MaximumFutureSkew < 0 || policy.MaximumFutureSkew > 24*time.Hour {
		return MaterialImportPolicy{}, ErrMaterialInvalid
	}
	dnsNames, ipAddresses, err := validateRequestedMaterialNames(policy.Names.DNSNames, policy.Names.IPAddresses, policy.Names.AllowWildcards)
	if err != nil {
		return MaterialImportPolicy{}, err
	}
	policy.Names.DNSNames = dnsNames
	policy.Names.IPAddresses = ipAddresses
	return policy, nil
}

func parseMaterialPrivateKey(blockType string, content []byte) (any, error) {
	var key any
	var err error
	switch blockType {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(content)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(content)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(content)
	default:
		return nil, ErrMaterialInvalid
	}
	if err != nil {
		return nil, ErrMaterialInvalid
	}
	return key, nil
}

func validateMaterialSigner(signer crypto.Signer, allowed []MaterialKeyAlgorithm, minimumRSAKeyBits int) (MaterialKeyAlgorithm, int, error) {
	algorithm, bits, err := materialPublicKeyMetadata(signer.Public())
	if err != nil {
		return "", 0, err
	}
	if public, ok := signer.Public().(*rsa.PublicKey); ok {
		if bits < minimumRSAKeyBits || bits > 8192 || public.E != 65537 {
			return "", 0, ErrMaterialInvalid
		}
	}
	for _, candidate := range allowed {
		if candidate == algorithm {
			return algorithm, bits, nil
		}
	}
	return "", 0, ErrMaterialInvalid
}

func materialPublicKeyMetadata(value any) (MaterialKeyAlgorithm, int, error) {
	switch public := value.(type) {
	case *rsa.PublicKey:
		bits := public.N.BitLen()
		if bits < 2048 || bits > 8192 || public.E != 65537 {
			return "", 0, ErrMaterialInvalid
		}
		return MaterialKeyRSA, bits, nil
	case *ecdsa.PublicKey:
		if public.Curve == nil || public.Curve.Params() == nil {
			return "", 0, ErrMaterialInvalid
		}
		bits := public.Curve.Params().BitSize
		if public.Curve != elliptic.P256() && public.Curve != elliptic.P384() && public.Curve != elliptic.P521() {
			return "", 0, ErrMaterialInvalid
		}
		return MaterialKeyECDSA, bits, nil
	case ed25519.PublicKey:
		if len(public) != ed25519.PublicKeySize {
			return "", 0, ErrMaterialInvalid
		}
		return MaterialKeyEd25519, len(public) * 8, nil
	default:
		return "", 0, ErrMaterialInvalid
	}
}

func validateMaterialCertificateAlgorithms(certificates []*x509.Certificate) error {
	for _, certificate := range certificates {
		switch certificate.SignatureAlgorithm {
		case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.UnknownSignatureAlgorithm:
			return ErrMaterialInvalid
		}
		if certificate.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm || certificate.PublicKeyAlgorithm == x509.DSA {
			return ErrMaterialInvalid
		}
		if _, _, err := materialPublicKeyMetadata(certificate.PublicKey); err != nil {
			return ErrMaterialInvalid
		}
	}
	return nil
}

func validateMaterialCertificateNames(certificate *x509.Certificate, policy MaterialNamePolicy) ([]string, []string, error) {
	if certificate == nil || len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 0 ||
		len(certificate.DNSNames)+len(certificate.IPAddresses) == 0 || len(certificate.DNSNames)+len(certificate.IPAddresses) > MaximumMaterialNames {
		return nil, nil, ErrMaterialInvalid
	}
	dnsNames, ipAddresses, err := validateRequestedMaterialNames(certificate.DNSNames, materialIPStrings(certificate.IPAddresses), policy.AllowWildcards)
	if err != nil || len(dnsNames) != len(certificate.DNSNames) || len(ipAddresses) != len(certificate.IPAddresses) {
		return nil, nil, ErrMaterialInvalid
	}
	if !materialNamesContain(dnsNames, policy.DNSNames) || !materialNamesContain(ipAddresses, policy.IPAddresses) {
		return nil, nil, ErrMaterialInvalid
	}
	if !policy.AllowAdditionalNames && (!equalMaterialStrings(dnsNames, policy.DNSNames) || !equalMaterialStrings(ipAddresses, policy.IPAddresses)) {
		return nil, nil, ErrMaterialInvalid
	}
	return dnsNames, ipAddresses, nil
}

func validateRequestedMaterialNames(dnsValues, ipValues []string, allowWildcards bool) ([]string, []string, error) {
	if len(dnsValues)+len(ipValues) == 0 || len(dnsValues)+len(ipValues) > MaximumMaterialNames {
		return nil, nil, ErrMaterialInvalid
	}
	dnsNames := canonicalMaterialDNSNames(dnsValues)
	ipAddresses := canonicalMaterialIPAddresses(ipValues)
	if len(dnsNames) != len(dnsValues) || len(ipAddresses) != len(ipValues) {
		return nil, nil, ErrMaterialInvalid
	}
	for _, name := range dnsNames {
		wildcard := strings.HasPrefix(name, "*.")
		if wildcard && !allowWildcards {
			return nil, nil, ErrMaterialInvalid
		}
		if !validMaterialDNSName(strings.TrimPrefix(name, "*.")) || strings.Contains(strings.TrimPrefix(name, "*."), "*") {
			return nil, nil, ErrMaterialInvalid
		}
	}
	for _, address := range ipAddresses {
		if address == "" || net.ParseIP(address) == nil {
			return nil, nil, ErrMaterialInvalid
		}
	}
	return dnsNames, ipAddresses, nil
}

func validMaterialDNSName(value string) bool {
	if len(value) < 3 || len(value) > 253 || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character == '-' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
				return false
			}
		}
	}
	return true
}

func validateMaterialLifetime(certificate *x509.Certificate, policy MaterialImportPolicy) error {
	if certificate.NotBefore.IsZero() || certificate.NotAfter.IsZero() || !certificate.NotAfter.After(certificate.NotBefore) ||
		certificate.NotAfter.Sub(certificate.NotBefore) > policy.MaximumLifetime ||
		certificate.NotBefore.After(policy.Now.Add(policy.MaximumFutureSkew)) ||
		!certificate.NotAfter.After(policy.Now.Add(policy.MinimumRemainingLifetime)) {
		return ErrMaterialInvalid
	}
	return nil
}

func validateMaterialChain(certificates []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
	if len(certificates) == 0 || len(certificates) > MaximumMaterialCertificates || roots == nil {
		return ErrMaterialInvalid
	}
	intermediates := x509.NewCertPool()
	for index := 1; index < len(certificates); index++ {
		if !certificates[index].BasicConstraintsValid || !certificates[index].IsCA || certificates[index].MaxPathLen < -1 {
			return ErrMaterialInvalid
		}
		if err := certificates[index-1].CheckSignatureFrom(certificates[index]); err != nil {
			return ErrMaterialInvalid
		}
		intermediates.AddCert(certificates[index])
	}
	paths, err := certificates[0].Verify(x509.VerifyOptions{
		Roots: roots,
		Intermediates: intermediates,
		CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return ErrMaterialInvalid
	}
	for _, path := range paths {
		if len(path) < len(certificates) {
			continue
		}
		ordered := true
		for index := range certificates {
			if !bytes.Equal(path[index].Raw, certificates[index].Raw) {
				ordered = false
				break
			}
		}
		if ordered {
			return nil
		}
	}
	return ErrMaterialInvalid
}

func materialNamesContain(have, required []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, value := range have {
		set[value] = struct{}{}
	}
	for _, value := range required {
		if _, exists := set[value]; !exists {
			return false
		}
	}
	return true
}

func equalMaterialStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func materialIPStrings(values []net.IP) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func wipeParsedMaterialPrivateKey(value any) {
	switch key := value.(type) {
	case *rsa.PrivateKey:
		if key.D != nil {
			key.D.SetInt64(0)
		}
		for _, prime := range key.Primes {
			if prime != nil {
				prime.SetInt64(0)
			}
		}
		key.Precomputed = rsa.PrecomputedValues{}
	case *ecdsa.PrivateKey:
		if key.D != nil {
			key.D.SetInt64(0)
		}
	case ed25519.PrivateKey:
		wipeMaterialBytes(key)
	case *big.Int:
		key.SetInt64(0)
	}
}

func wipeMaterialBytes(values ...[]byte) {
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
	}
}
