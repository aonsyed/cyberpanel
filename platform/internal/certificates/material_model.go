package certificates

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	MaximumMaterialPEMBytes       = 1 << 20
	MaximumMaterialCertificates  = 12
	MaximumMaterialNames         = 100
	MaximumMaterialConsumers     = 128
	MaximumMaterialListLimit     = 200
	MaximumMaterialIdentifierLen = 192
)

var (
	ErrMaterialInvalid          = errors.New("invalid certificate material")
	ErrMaterialConflict         = errors.New("certificate material generation conflict")
	ErrMaterialDuplicate        = errors.New("duplicate certificate material")
	ErrMaterialOwnership        = errors.New("certificate material belongs to another resource")
	ErrMaterialNotFound         = errors.New("certificate material not found")
	ErrMaterialUnauthorized     = errors.New("certificate material operation unauthorized")
	ErrMaterialStepUpRequired   = errors.New("certificate material step-up required")
	ErrMaterialNotRetirable     = errors.New("certificate material is not retirement eligible")
	ErrMaterialAmbiguous        = errors.New("certificate material operation is ambiguous")
	errMaterialIdempotentReplay = errors.New("certificate material idempotent replay")
)

type MaterialSource string

const (
	MaterialSourceImport             MaterialSource = "custom_import"
	MaterialSourceDevelopment        MaterialSource = "development_self_signed"
	MaterialSourceRecoverySelfSigned MaterialSource = "recovery_self_signed"
)

type MaterialTrustLabel string

const (
	MaterialTrustPublicValidated  MaterialTrustLabel = "public_roots_validated"
	MaterialTrustPrivateValidated MaterialTrustLabel = "private_roots_validated"
	MaterialTrustDevelopment      MaterialTrustLabel = "untrusted_development_self_signed"
	MaterialTrustRecovery         MaterialTrustLabel = "untrusted_recovery_self_signed"
)

type MaterialLifecycleState string

const (
	MaterialStateStaged  MaterialLifecycleState = "staged"
	MaterialStateStandby MaterialLifecycleState = "standby"
	MaterialStateActive  MaterialLifecycleState = "active"
	MaterialStateRetired MaterialLifecycleState = "retired"
)

type MaterialKeyAlgorithm string

const (
	MaterialKeyRSA     MaterialKeyAlgorithm = "rsa"
	MaterialKeyECDSA   MaterialKeyAlgorithm = "ecdsa"
	MaterialKeyEd25519 MaterialKeyAlgorithm = "ed25519"
)

type MaterialDeploymentState string

const (
	MaterialDeploymentPending   MaterialDeploymentState = "pending"
	MaterialDeploymentSucceeded MaterialDeploymentState = "succeeded"
	MaterialDeploymentDegraded  MaterialDeploymentState = "degraded"
	MaterialDeploymentFailed    MaterialDeploymentState = "failed"
	MaterialDeploymentAmbiguous MaterialDeploymentState = "ambiguous"
)

type MaterialPrivateKeyReference struct {
	ID      string `json:"id"`
	Purpose string `json:"purpose"`
	Version uint64 `json:"version"`
}

type MaterialCertificateEntry struct {
	DER               []byte    `json:"der"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	SerialHex         string    `json:"serial_hex"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
}

type MaterialConsumerBinding struct {
	ConsumerID             string    `json:"consumer_id"`
	ConsumerKind           string    `json:"consumer_kind"`
	ConsumerGeneration     uint64    `json:"consumer_generation"`
	Bound                   bool      `json:"bound"`
	DeployedFingerprint    string    `json:"deployed_fingerprint,omitempty"`
	DeploymentGeneration   uint64    `json:"deployment_generation,omitempty"`
	DeploymentObservedAt   time.Time `json:"deployment_observed_at,omitempty"`
	DeploymentReasonCode   string    `json:"deployment_reason_code,omitempty"`
}

type MaterialDeploymentResult struct {
	DeploymentID          string                  `json:"deployment_id"`
	ConsumerID            string                  `json:"consumer_id"`
	ConsumerGeneration    uint64                  `json:"consumer_generation"`
	CertificateFingerprint string                 `json:"certificate_fingerprint"`
	State                 MaterialDeploymentState `json:"state"`
	ReasonCode            string                  `json:"reason_code,omitempty"`
	ObservedAt            time.Time               `json:"observed_at"`
}

// ManagedCertificateGeneration contains the private-key reference needed by the
// runtime, but never private-key bytes. Call Inspection before returning data to
// a management or console caller.
type ManagedCertificateGeneration struct {
	ID                    string                       `json:"id"`
	TenantID              string                       `json:"tenant_id"`
	ResourceID            string                       `json:"resource_id"`
	CertificateGeneration uint64                       `json:"certificate_generation"`
	RecordGeneration      uint64                       `json:"record_generation"`
	Source                MaterialSource               `json:"source"`
	TrustLabel            MaterialTrustLabel           `json:"trust_label"`
	DisplayLabel          string                       `json:"display_label"`
	State                 MaterialLifecycleState       `json:"state"`
	Subject               string                       `json:"subject"`
	DNSNames              []string                     `json:"dns_names,omitempty"`
	IPAddresses           []string                     `json:"ip_addresses,omitempty"`
	Issuer                string                       `json:"issuer"`
	SerialHex             string                       `json:"serial_hex"`
	LeafFingerprintSHA256 string                       `json:"leaf_fingerprint_sha256"`
	SPKIFingerprintSHA256 string                       `json:"spki_fingerprint_sha256"`
	ChainFingerprintSHA256 string                      `json:"chain_fingerprint_sha256"`
	KeyAlgorithm          MaterialKeyAlgorithm         `json:"key_algorithm"`
	KeyBits               int                          `json:"key_bits"`
	NotBefore             time.Time                    `json:"not_before"`
	NotAfter              time.Time                    `json:"not_after"`
	LeafDER               []byte                       `json:"leaf_der"`
	Chain                 []MaterialCertificateEntry   `json:"chain"`
	PrivateKeyReference   MaterialPrivateKeyReference  `json:"private_key_reference"`
	Consumers             []MaterialConsumerBinding    `json:"consumers,omitempty"`
	LastDeployment        *MaterialDeploymentResult    `json:"last_deployment,omitempty"`
	IdentityDigest        string                       `json:"identity_digest"`
	RecordDigest          string                       `json:"record_digest"`
	CreatedAt             time.Time                    `json:"created_at"`
	UpdatedAt             time.Time                    `json:"updated_at"`
	RetiredAt             time.Time                    `json:"retired_at,omitempty"`
}

type MaterialCertificateSummary struct {
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	SerialHex         string    `json:"serial_hex"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
}

// MaterialInspection is the only management projection. It deliberately has no
// private-key bytes, secret reference, storage path, or reusable material handle.
type MaterialInspection struct {
	ID                     string                       `json:"id"`
	TenantID               string                       `json:"tenant_id"`
	ResourceID             string                       `json:"resource_id"`
	CertificateGeneration  uint64                       `json:"certificate_generation"`
	RecordGeneration       uint64                       `json:"record_generation"`
	Source                 MaterialSource               `json:"source"`
	TrustLabel             MaterialTrustLabel           `json:"trust_label"`
	DisplayLabel           string                       `json:"display_label"`
	State                  MaterialLifecycleState       `json:"state"`
	Subject                string                       `json:"subject"`
	DNSNames               []string                     `json:"dns_names,omitempty"`
	IPAddresses            []string                     `json:"ip_addresses,omitempty"`
	Issuer                 string                       `json:"issuer"`
	SerialHex              string                       `json:"serial_hex"`
	LeafFingerprintSHA256  string                       `json:"leaf_fingerprint_sha256"`
	SPKIFingerprintSHA256  string                       `json:"spki_fingerprint_sha256"`
	ChainFingerprintSHA256 string                       `json:"chain_fingerprint_sha256"`
	KeyAlgorithm           MaterialKeyAlgorithm         `json:"key_algorithm"`
	KeyBits                int                          `json:"key_bits"`
	NotBefore              time.Time                    `json:"not_before"`
	NotAfter               time.Time                    `json:"not_after"`
	Chain                  []MaterialCertificateSummary `json:"chain"`
	Consumers              []MaterialConsumerBinding    `json:"consumers,omitempty"`
	LastDeployment         *MaterialDeploymentResult    `json:"last_deployment,omitempty"`
	Retirement             MaterialRetirementEligibility `json:"retirement"`
	CreatedAt              time.Time                    `json:"created_at"`
	UpdatedAt              time.Time                    `json:"updated_at"`
	RetiredAt              time.Time                    `json:"retired_at,omitempty"`
}

type MaterialRetirementEligibility struct {
	Eligible    bool     `json:"eligible"`
	ReasonCodes []string `json:"reason_codes,omitempty"`
}

func (generation ManagedCertificateGeneration) Inspection() MaterialInspection {
	chain := make([]MaterialCertificateSummary, len(generation.Chain))
	for index, certificate := range generation.Chain {
		chain[index] = MaterialCertificateSummary{
			FingerprintSHA256: certificate.FingerprintSHA256,
			Subject: certificate.Subject,
			Issuer: certificate.Issuer,
			SerialHex: certificate.SerialHex,
			NotBefore: certificate.NotBefore.UTC(),
			NotAfter: certificate.NotAfter.UTC(),
		}
	}
	consumers := append([]MaterialConsumerBinding(nil), generation.Consumers...)
	var deployment *MaterialDeploymentResult
	if generation.LastDeployment != nil {
		copy := *generation.LastDeployment
		deployment = &copy
	}
	return MaterialInspection{
		ID: generation.ID,
		TenantID: generation.TenantID,
		ResourceID: generation.ResourceID,
		CertificateGeneration: generation.CertificateGeneration,
		RecordGeneration: generation.RecordGeneration,
		Source: generation.Source,
		TrustLabel: generation.TrustLabel,
		DisplayLabel: generation.DisplayLabel,
		State: generation.State,
		Subject: generation.Subject,
		DNSNames: append([]string(nil), generation.DNSNames...),
		IPAddresses: append([]string(nil), generation.IPAddresses...),
		Issuer: generation.Issuer,
		SerialHex: generation.SerialHex,
		LeafFingerprintSHA256: generation.LeafFingerprintSHA256,
		SPKIFingerprintSHA256: generation.SPKIFingerprintSHA256,
		ChainFingerprintSHA256: generation.ChainFingerprintSHA256,
		KeyAlgorithm: generation.KeyAlgorithm,
		KeyBits: generation.KeyBits,
		NotBefore: generation.NotBefore.UTC(),
		NotAfter: generation.NotAfter.UTC(),
		Chain: chain,
		Consumers: consumers,
		LastDeployment: deployment,
		Retirement: generation.RetirementEligibility(),
		CreatedAt: generation.CreatedAt.UTC(),
		UpdatedAt: generation.UpdatedAt.UTC(),
		RetiredAt: generation.RetiredAt.UTC(),
	}
}

func (generation ManagedCertificateGeneration) RetirementEligibility() MaterialRetirementEligibility {
	reasons := make([]string, 0, 3)
	if generation.State == MaterialStateRetired {
		reasons = append(reasons, "already_retired")
	}
	if generation.LastDeployment != nil {
		switch generation.LastDeployment.State {
		case MaterialDeploymentPending, MaterialDeploymentAmbiguous:
			reasons = append(reasons, "deployment_state_uncertain")
		}
	}
	for _, consumer := range generation.Consumers {
		if consumer.Bound && consumer.DeployedFingerprint == generation.LeafFingerprintSHA256 {
			reasons = append(reasons, "consumer_still_bound")
			break
		}
		if consumer.Bound && consumer.DeployedFingerprint == "" {
			reasons = append(reasons, "consumer_deployment_unknown")
			break
		}
	}
	sort.Strings(reasons)
	return MaterialRetirementEligibility{Eligible: len(reasons) == 0, ReasonCodes: reasons}
}

func sealManagedCertificateGeneration(generation *ManagedCertificateGeneration) error {
	if generation == nil {
		return ErrMaterialInvalid
	}
	canonicalizeManagedCertificateGeneration(generation)
	generation.IdentityDigest = ""
	generation.RecordDigest = ""
	identity := struct {
		ID                    string
		TenantID              string
		ResourceID            string
		CertificateGeneration uint64
		Source                MaterialSource
		TrustLabel            MaterialTrustLabel
		Subject               string
		DNSNames              []string
		IPAddresses           []string
		Issuer                string
		SerialHex             string
		LeafFingerprint       string
		SPKIFingerprint       string
		ChainFingerprint      string
		KeyAlgorithm          MaterialKeyAlgorithm
		KeyBits               int
		NotBefore             time.Time
		NotAfter              time.Time
		LeafDER               []byte
		Chain                 []MaterialCertificateEntry
		PrivateKeyReference   MaterialPrivateKeyReference
	}{
		ID: generation.ID,
		TenantID: generation.TenantID,
		ResourceID: generation.ResourceID,
		CertificateGeneration: generation.CertificateGeneration,
		Source: generation.Source,
		TrustLabel: generation.TrustLabel,
		Subject: generation.Subject,
		DNSNames: generation.DNSNames,
		IPAddresses: generation.IPAddresses,
		Issuer: generation.Issuer,
		SerialHex: generation.SerialHex,
		LeafFingerprint: generation.LeafFingerprintSHA256,
		SPKIFingerprint: generation.SPKIFingerprintSHA256,
		ChainFingerprint: generation.ChainFingerprintSHA256,
		KeyAlgorithm: generation.KeyAlgorithm,
		KeyBits: generation.KeyBits,
		NotBefore: generation.NotBefore,
		NotAfter: generation.NotAfter,
		LeafDER: generation.LeafDER,
		Chain: generation.Chain,
		PrivateKeyReference: generation.PrivateKeyReference,
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	generation.IdentityDigest = hex.EncodeToString(sum[:])
	encoded, err = json.Marshal(generation)
	if err != nil {
		return err
	}
	sum = sha256.Sum256(encoded)
	generation.RecordDigest = hex.EncodeToString(sum[:])
	return validateManagedCertificateGeneration(*generation)
}

func validateManagedCertificateGeneration(generation ManagedCertificateGeneration) error {
	if !validMaterialIdentifier(generation.ID) || !validMaterialIdentifier(generation.TenantID) || !validMaterialIdentifier(generation.ResourceID) ||
		generation.CertificateGeneration == 0 || generation.CertificateGeneration > uint64(1<<63-1) || generation.RecordGeneration == 0 ||
		generation.RecordGeneration > uint64(1<<63-1) || !validMaterialDisplayLabel(generation.DisplayLabel) ||
		generation.Subject == "" || generation.Issuer == "" || generation.SerialHex == "" || len(generation.LeafDER) == 0 ||
		len(generation.Chain) == 0 || len(generation.Chain) > MaximumMaterialCertificates || generation.NotBefore.IsZero() || generation.NotAfter.IsZero() ||
		!generation.NotAfter.After(generation.NotBefore) || generation.CreatedAt.IsZero() || generation.UpdatedAt.IsZero() ||
		!validSHA256Hex(generation.LeafFingerprintSHA256) || !validSHA256Hex(generation.SPKIFingerprintSHA256) ||
		!validSHA256Hex(generation.ChainFingerprintSHA256) || !validSHA256Hex(generation.IdentityDigest) || !validSHA256Hex(generation.RecordDigest) ||
		!validMaterialPrivateKeyReference(generation.PrivateKeyReference) || len(generation.DNSNames)+len(generation.IPAddresses) == 0 ||
		len(generation.DNSNames)+len(generation.IPAddresses) > MaximumMaterialNames || len(generation.Consumers) > MaximumMaterialConsumers {
		return ErrMaterialInvalid
	}
	if generation.Source != MaterialSourceImport && generation.Source != MaterialSourceDevelopment && generation.Source != MaterialSourceRecoverySelfSigned {
		return ErrMaterialInvalid
	}
	switch generation.Source {
	case MaterialSourceImport:
		if generation.TrustLabel != MaterialTrustPublicValidated && generation.TrustLabel != MaterialTrustPrivateValidated {
			return ErrMaterialInvalid
		}
	case MaterialSourceDevelopment:
		if generation.TrustLabel != MaterialTrustDevelopment || generation.State != MaterialStateStandby {
			return ErrMaterialInvalid
		}
	case MaterialSourceRecoverySelfSigned:
		if generation.TrustLabel != MaterialTrustRecovery || generation.State != MaterialStateStandby {
			return ErrMaterialInvalid
		}
	}
	if generation.State != MaterialStateStaged && generation.State != MaterialStateStandby && generation.State != MaterialStateActive && generation.State != MaterialStateRetired {
		return ErrMaterialInvalid
	}
	if generation.KeyAlgorithm != MaterialKeyRSA && generation.KeyAlgorithm != MaterialKeyECDSA && generation.KeyAlgorithm != MaterialKeyEd25519 {
		return ErrMaterialInvalid
	}
	if generation.Chain[0].FingerprintSHA256 != generation.LeafFingerprintSHA256 || !strings.EqualFold(generation.Chain[0].SerialHex, generation.SerialHex) {
		return ErrMaterialInvalid
	}
	leaf, err := x509.ParseCertificate(generation.LeafDER)
	if err != nil || !bytes.Equal(leaf.Raw, generation.Chain[0].DER) || leaf.Subject.String() != generation.Subject || leaf.Issuer.String() != generation.Issuer ||
		strings.ToLower(leaf.SerialNumber.Text(16)) != generation.SerialHex || !leaf.NotBefore.Equal(generation.NotBefore) || !leaf.NotAfter.Equal(generation.NotAfter) ||
		!equalMaterialStrings(canonicalMaterialDNSNames(leaf.DNSNames), generation.DNSNames) ||
		!equalMaterialStrings(canonicalMaterialIPAddresses(materialIPStrings(leaf.IPAddresses)), generation.IPAddresses) {
		return ErrMaterialInvalid
	}
	leafFingerprint := sha256.Sum256(leaf.Raw)
	spkiFingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(leafFingerprint[:]) != generation.LeafFingerprintSHA256 || hex.EncodeToString(spkiFingerprint[:]) != generation.SPKIFingerprintSHA256 {
		return ErrMaterialInvalid
	}
	algorithm, bits, err := materialPublicKeyMetadata(leaf.PublicKey)
	if err != nil || algorithm != generation.KeyAlgorithm || bits != generation.KeyBits {
		return ErrMaterialInvalid
	}
	chainDER := make([][]byte, 0, len(generation.Chain))
	var previous *x509.Certificate
	for index, certificate := range generation.Chain {
		if len(certificate.DER) == 0 || !validSHA256Hex(certificate.FingerprintSHA256) || certificate.Subject == "" || certificate.Issuer == "" ||
			certificate.SerialHex == "" || certificate.NotBefore.IsZero() || certificate.NotAfter.IsZero() || !certificate.NotAfter.After(certificate.NotBefore) {
			return ErrMaterialInvalid
		}
		parsed, parseErr := x509.ParseCertificate(certificate.DER)
		fingerprint := sha256.Sum256(certificate.DER)
		if parseErr != nil || hex.EncodeToString(fingerprint[:]) != certificate.FingerprintSHA256 || parsed.Subject.String() != certificate.Subject ||
			parsed.Issuer.String() != certificate.Issuer || strings.ToLower(parsed.SerialNumber.Text(16)) != certificate.SerialHex ||
			!parsed.NotBefore.Equal(certificate.NotBefore) || !parsed.NotAfter.Equal(certificate.NotAfter) {
			return ErrMaterialInvalid
		}
		if previous != nil && previous.CheckSignatureFrom(parsed) != nil {
			return ErrMaterialInvalid
		}
		previous = parsed
		chainDER = append(chainDER, certificate.DER)
		if index > 0 && certificate.FingerprintSHA256 == generation.LeafFingerprintSHA256 {
			return ErrMaterialInvalid
		}
	}
	if materialDERChainFingerprint(chainDER) != generation.ChainFingerprintSHA256 {
		return ErrMaterialInvalid
	}
	if (generation.Source == MaterialSourceDevelopment || generation.Source == MaterialSourceRecoverySelfSigned) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
		return ErrMaterialInvalid
	}
	for index, consumer := range generation.Consumers {
		if !validMaterialIdentifier(consumer.ConsumerID) || consumer.ConsumerKind == "" || len(consumer.ConsumerKind) > 64 || consumer.ConsumerGeneration == 0 ||
			(consumer.DeployedFingerprint != "" && !validSHA256Hex(consumer.DeployedFingerprint)) ||
			(index > 0 && generation.Consumers[index-1].ConsumerID >= consumer.ConsumerID) {
			return ErrMaterialInvalid
		}
	}
	if generation.LastDeployment != nil {
		deployment := generation.LastDeployment
		if !validMaterialIdentifier(deployment.DeploymentID) || !validMaterialIdentifier(deployment.ConsumerID) || deployment.ConsumerGeneration == 0 ||
			!validSHA256Hex(deployment.CertificateFingerprint) || deployment.ObservedAt.IsZero() || !validMaterialDeploymentState(deployment.State) {
			return ErrMaterialInvalid
		}
	}
	return nil
}

func canonicalizeManagedCertificateGeneration(generation *ManagedCertificateGeneration) {
	generation.NotBefore = generation.NotBefore.UTC()
	generation.NotAfter = generation.NotAfter.UTC()
	generation.CreatedAt = generation.CreatedAt.UTC()
	generation.UpdatedAt = generation.UpdatedAt.UTC()
	generation.RetiredAt = generation.RetiredAt.UTC()
	generation.LeafFingerprintSHA256 = strings.ToLower(generation.LeafFingerprintSHA256)
	generation.SPKIFingerprintSHA256 = strings.ToLower(generation.SPKIFingerprintSHA256)
	generation.ChainFingerprintSHA256 = strings.ToLower(generation.ChainFingerprintSHA256)
	generation.SerialHex = strings.ToLower(generation.SerialHex)
	generation.DNSNames = canonicalMaterialDNSNames(generation.DNSNames)
	generation.IPAddresses = canonicalMaterialIPAddresses(generation.IPAddresses)
	sort.Slice(generation.Consumers, func(left, right int) bool {
		return generation.Consumers[left].ConsumerID < generation.Consumers[right].ConsumerID
	})
	for index := range generation.Chain {
		generation.Chain[index].NotBefore = generation.Chain[index].NotBefore.UTC()
		generation.Chain[index].NotAfter = generation.Chain[index].NotAfter.UTC()
		generation.Chain[index].FingerprintSHA256 = strings.ToLower(generation.Chain[index].FingerprintSHA256)
		generation.Chain[index].SerialHex = strings.ToLower(generation.Chain[index].SerialHex)
	}
	if generation.LastDeployment != nil {
		generation.LastDeployment.ObservedAt = generation.LastDeployment.ObservedAt.UTC()
		generation.LastDeployment.CertificateFingerprint = strings.ToLower(generation.LastDeployment.CertificateFingerprint)
	}
}

func canonicalMaterialDNSNames(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canonicalMaterialIPAddresses(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		address := net.ParseIP(strings.TrimSpace(value))
		if address == nil {
			value = ""
		} else {
			value = address.String()
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func validMaterialIdentifier(value string) bool {
	if value == "" || len(value) > MaximumMaterialIdentifierLen {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == '.' || character == ':' || character == '/' ||
			character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validMaterialPrivateKeyReference(reference MaterialPrivateKeyReference) bool {
	return validMaterialIdentifier(reference.ID) && strings.HasPrefix(reference.Purpose, "certificate_material_") &&
		validSHA256Hex(strings.TrimPrefix(reference.Purpose, "certificate_material_")) && reference.Version > 0
}

func validMaterialDisplayLabel(value string) bool {
	if strings.TrimSpace(value) != value || value == "" || len(value) > 192 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validMaterialDeploymentState(state MaterialDeploymentState) bool {
	return state == MaterialDeploymentPending || state == MaterialDeploymentSucceeded || state == MaterialDeploymentDegraded ||
		state == MaterialDeploymentFailed || state == MaterialDeploymentAmbiguous
}
