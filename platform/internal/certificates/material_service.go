package certificates

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

type MaterialAction string

const (
	MaterialActionImport     MaterialAction = "certificate_material.import"
	MaterialActionSelfSigned MaterialAction = "certificate_material.self_signed"
	MaterialActionInspect    MaterialAction = "certificate_material.inspect"
	MaterialActionList       MaterialAction = "certificate_material.list"
	MaterialActionRetire     MaterialAction = "certificate_material.retire"
)

type MaterialPrincipal struct {
	TenantID  string
	SubjectID string
	SessionID string
}

type MaterialScope struct {
	TenantID   string
	ResourceID string
	MaterialID string
}

type MaterialAuthorizer interface {
	AuthorizeMaterial(context.Context, MaterialPrincipal, MaterialAction, MaterialScope) error
}

type MaterialStepUpVerifier interface {
	VerifyMaterialStepUp(context.Context, MaterialPrincipal, string, string, time.Time) error
}

type MaterialAuditEvent struct {
	EventID               string         `json:"event_id"`
	TenantID              string         `json:"tenant_id"`
	SubjectID             string         `json:"subject_id"`
	Action                MaterialAction `json:"action"`
	ResourceID            string         `json:"resource_id,omitempty"`
	MaterialID            string         `json:"material_id,omitempty"`
	CertificateFingerprint string        `json:"certificate_fingerprint,omitempty"`
	Outcome               string         `json:"outcome"`
	ReasonCode            string         `json:"reason_code,omitempty"`
	OccurredAt            time.Time      `json:"occurred_at"`
}

type MaterialAuditSink interface {
	RecordMaterialAudit(context.Context, MaterialAuditEvent) error
}

// OneUseCertificateMaterial must reject a second Consume call. Destroy must
// invalidate the underlying handle even when parsing fails.
type OneUseCertificateMaterial interface {
	Consume(context.Context, int64) ([]byte, error)
	Destroy(context.Context) error
}

type MaterialSecretPurpose struct {
	TenantID   string
	ResourceID string
	Operation  string
	Binding    string
}

func (purpose MaterialSecretPurpose) Canonical() (string, error) {
	if !validMaterialIdentifier(purpose.TenantID) || !validMaterialIdentifier(purpose.ResourceID) ||
		(purpose.Operation != "import" && purpose.Operation != "self_signed") || !validSHA256Hex(purpose.Binding) {
		return "", ErrMaterialInvalid
	}
	sum := sha256.Sum256([]byte("certificate-private-key-purpose-v1\x00" + purpose.TenantID + "\x00" + purpose.ResourceID + "\x00" + purpose.Operation + "\x00" + purpose.Binding))
	return "certificate_material_" + hex.EncodeToString(sum[:]), nil
}

type MaterialKeySpec struct {
	Algorithm MaterialKeyAlgorithm `json:"algorithm"`
	Bits      int                  `json:"bits"`
}

// PurposeBoundMaterialStore owns the cross-store durability boundary. It must
// keep the key unreachable until bind returns nil, durably publish the key and
// metadata as one effect, abort both on callback failure, call bind at most once,
// and erase transient key bytes. GeneratePrivateKeyAtomic must generate locally.
type PurposeBoundMaterialStore interface {
	StoreImportedPrivateKeyAtomic(context.Context, MaterialSecretPurpose, []byte, func(MaterialPrivateKeyReference) error) error
	GeneratePrivateKeyAtomic(context.Context, MaterialSecretPurpose, MaterialKeySpec, func(crypto.Signer, MaterialPrivateKeyReference) error) error
}

type MaterialImportPolicyResolver interface {
	ResolveMaterialImportPolicy(context.Context, MaterialPrincipal, MaterialScope) (MaterialImportPolicy, error)
}

type SelfSignedMode string

const (
	SelfSignedDevelopment SelfSignedMode = "development"
	SelfSignedRecovery    SelfSignedMode = "recovery"
)

type SelfSignedMaterialPolicy struct {
	DevelopmentEnabled    bool
	RecoveryEnabled       bool
	MinimumLifetime       time.Duration
	MaximumDevelopmentTTL time.Duration
	MaximumRecoveryTTL    time.Duration
	Backdate              time.Duration
	AllowedKeyAlgorithms  []MaterialKeyAlgorithm
	MinimumRSAKeyBits     int
	AllowWildcards        bool
}

type SelfSignedMaterialPolicyResolver interface {
	ResolveSelfSignedMaterialPolicy(context.Context, MaterialPrincipal, MaterialScope) (SelfSignedMaterialPolicy, error)
}

type MaterialService struct {
	Repository       MaterialRepository
	Secrets          PurposeBoundMaterialStore
	ImportPolicies   MaterialImportPolicyResolver
	SelfSignedPolicy SelfSignedMaterialPolicyResolver
	Authorizer       MaterialAuthorizer
	StepUp           MaterialStepUpVerifier
	Audit            MaterialAuditSink
	Now              func() time.Time
}

type ImportMaterialRequest struct {
	TenantID                    string
	ResourceID                  string
	DisplayLabel                string
	DNSNames                    []string
	IPAddresses                 []string
	ExpectedCertificateGeneration uint64
	IdempotencyKey              string
	Material                    OneUseCertificateMaterial
}

type GenerateSelfSignedMaterialRequest struct {
	TenantID                    string
	ResourceID                  string
	DisplayLabel                string
	Mode                        SelfSignedMode
	DNSNames                    []string
	IPAddresses                 []string
	Lifetime                    time.Duration
	Key                         MaterialKeySpec
	ExpectedCertificateGeneration uint64
	AcknowledgeNoPublicReplacement bool
	IdempotencyKey              string
	StepUpProof                 string
}

type InspectMaterialRequest struct {
	TenantID   string
	ResourceID string
	MaterialID string
}

type ListMaterialRequest struct {
	TenantID   string
	ResourceID string
	Cursor     string
	Limit      int
}

type MaterialInspectionPage struct {
	Items      []MaterialInspection `json:"items"`
	NextCursor string               `json:"next_cursor,omitempty"`
}

type RetireMaterialRequest struct {
	TenantID                string
	ResourceID              string
	MaterialID              string
	ExpectedRecordGeneration uint64
	IdempotencyKey          string
	StepUpProof             string
}

func (service MaterialService) Import(ctx context.Context, principal MaterialPrincipal, request ImportMaterialRequest) (MaterialInspection, error) {
	scope := MaterialScope{TenantID: request.TenantID, ResourceID: request.ResourceID}
	if err := service.validateWriteRequest(ctx, principal, MaterialActionImport, scope, request.DisplayLabel, request.IdempotencyKey); err != nil || request.Material == nil {
		if err == nil {
			err = ErrMaterialInvalid
		}
		return MaterialInspection{}, err
	}
	policy, err := service.ImportPolicies.ResolveMaterialImportPolicy(ctx, principal, scope)
	if err != nil {
		service.auditFailure(ctx, principal, MaterialActionImport, scope, "policy_denied")
		return MaterialInspection{}, err
	}
	policy.Names.DNSNames = append([]string(nil), request.DNSNames...)
	policy.Names.IPAddresses = append([]string(nil), request.IPAddresses...)
	policy.Now = service.now()
	content, err := request.Material.Consume(ctx, MaximumMaterialPEMBytes)
	if err != nil || len(content) == 0 || len(content) > MaximumMaterialPEMBytes {
		wipeMaterialBytes(content)
		_ = request.Material.Destroy(ctx)
		service.auditFailure(ctx, principal, MaterialActionImport, scope, "material_unavailable")
		if err == nil {
			err = ErrMaterialInvalid
		}
		return MaterialInspection{}, err
	}
	parsed, parseErr := parseImportedMaterial(content, policy)
	wipeMaterialBytes(content)
	destroyErr := request.Material.Destroy(ctx)
	if parseErr != nil {
		service.auditFailure(ctx, principal, MaterialActionImport, scope, "validation_failed")
		return MaterialInspection{}, parseErr
	}
	defer wipeMaterialBytes(parsed.PrivateKeyPKCS8)
	if destroyErr != nil {
		service.auditFailure(ctx, principal, MaterialActionImport, scope, "one_use_destroy_failed")
		return MaterialInspection{}, destroyErr
	}
	requestDigest, err := digestImportMaterialRequest(request, parsed, policy.TrustLabel)
	if err != nil {
		return MaterialInspection{}, err
	}
	prior, found, err := service.Repository.ResolveIdempotency(ctx, request.TenantID, request.ResourceID, "import", request.IdempotencyKey, requestDigest)
	if err != nil {
		return MaterialInspection{}, err
	}
	if found {
		if err = service.auditSuccess(ctx, principal, MaterialActionImport, scope, prior.ID, prior.LeafFingerprintSHA256, "idempotent_replay"); err != nil {
			return MaterialInspection{}, errors.Join(ErrMaterialAmbiguous, err)
		}
		return prior.Inspection(), nil
	}
	if err = service.Repository.PreflightCreate(ctx, request.TenantID, request.ResourceID, parsed.LeafFingerprintSHA256, request.ExpectedCertificateGeneration); err != nil {
		service.auditFailure(ctx, principal, MaterialActionImport, scope, materialReasonCode(err))
		return MaterialInspection{}, err
	}
	materialID, err := NewManagedMaterialID(request.TenantID, request.ResourceID, parsed.LeafFingerprintSHA256)
	if err != nil {
		return MaterialInspection{}, err
	}
	purpose := MaterialSecretPurpose{TenantID: request.TenantID, ResourceID: request.ResourceID, Operation: "import", Binding: requestDigest}
	expectedPurpose, err := purpose.Canonical()
	if err != nil {
		return MaterialInspection{}, err
	}
	now := service.now()
	var stored ManagedCertificateGeneration
	var replay bool
	invoked := false
	err = service.Secrets.StoreImportedPrivateKeyAtomic(ctx, purpose, parsed.PrivateKeyPKCS8, func(reference MaterialPrivateKeyReference) error {
		if invoked {
			return ErrMaterialAmbiguous
		}
		invoked = true
		if !validMaterialPrivateKeyReference(reference) || reference.Purpose != expectedPurpose {
			return ErrMaterialInvalid
		}
		candidate := managedGenerationFromImport(request, parsed, policy.TrustLabel, materialID, reference, now)
		if sealErr := sealManagedCertificateGeneration(&candidate); sealErr != nil {
			return sealErr
		}
		createdGeneration, created, createErr := service.Repository.CreateCAS(ctx, candidate, request.ExpectedCertificateGeneration, "import", request.IdempotencyKey, requestDigest)
		if createErr != nil {
			return createErr
		}
		stored = createdGeneration
		if !created {
			replay = true
			return errMaterialIdempotentReplay
		}
		return nil
	})
	if errors.Is(err, errMaterialIdempotentReplay) && replay {
		err = nil
	}
	if err != nil || !invoked || stored.ID == "" {
		service.auditFailure(ctx, principal, MaterialActionImport, scope, materialReasonCode(err))
		if err == nil {
			err = ErrMaterialAmbiguous
		}
		return MaterialInspection{}, err
	}
	scope.MaterialID = stored.ID
	if err = service.auditSuccess(ctx, principal, MaterialActionImport, scope, stored.ID, stored.LeafFingerprintSHA256, "stored"); err != nil {
		return MaterialInspection{}, errors.Join(ErrMaterialAmbiguous, err)
	}
	return stored.Inspection(), nil
}

func (service MaterialService) GenerateSelfSigned(ctx context.Context, principal MaterialPrincipal, request GenerateSelfSignedMaterialRequest) (MaterialInspection, error) {
	scope := MaterialScope{TenantID: request.TenantID, ResourceID: request.ResourceID}
	if err := service.validateWriteRequest(ctx, principal, MaterialActionSelfSigned, scope, request.DisplayLabel, request.IdempotencyKey); err != nil {
		return MaterialInspection{}, err
	}
	if service.StepUp == nil || len(request.StepUpProof) == 0 || len(request.StepUpProof) > 4096 || !request.AcknowledgeNoPublicReplacement ||
		(request.Mode != SelfSignedDevelopment && request.Mode != SelfSignedRecovery) {
		service.auditFailure(ctx, principal, MaterialActionSelfSigned, scope, "step_up_required")
		return MaterialInspection{}, ErrMaterialStepUpRequired
	}
	policy, err := service.SelfSignedPolicy.ResolveSelfSignedMaterialPolicy(ctx, principal, scope)
	if err != nil {
		service.auditFailure(ctx, principal, MaterialActionSelfSigned, scope, "policy_denied")
		return MaterialInspection{}, err
	}
	policy, err = normalizeSelfSignedMaterialPolicy(policy, request.Mode, request.Lifetime, request.Key)
	if err != nil {
		service.auditFailure(ctx, principal, MaterialActionSelfSigned, scope, "policy_denied")
		return MaterialInspection{}, err
	}
	dnsNames, ipAddresses, err := validateRequestedMaterialNames(request.DNSNames, request.IPAddresses, policy.AllowWildcards)
	if err != nil {
		return MaterialInspection{}, err
	}
	request.DNSNames = dnsNames
	request.IPAddresses = ipAddresses
	requestDigest, err := digestSelfSignedMaterialRequest(request)
	if err != nil {
		return MaterialInspection{}, err
	}
	binding := "self_signed:" + requestDigest
	if err = service.StepUp.VerifyMaterialStepUp(ctx, principal, request.StepUpProof, binding, service.now()); err != nil {
		service.auditFailure(ctx, principal, MaterialActionSelfSigned, scope, "step_up_failed")
		return MaterialInspection{}, ErrMaterialStepUpRequired
	}
	prior, found, err := service.Repository.ResolveIdempotency(ctx, request.TenantID, request.ResourceID, "self_signed", request.IdempotencyKey, requestDigest)
	if err != nil {
		return MaterialInspection{}, err
	}
	if found {
		if err = service.auditSuccess(ctx, principal, MaterialActionSelfSigned, scope, prior.ID, prior.LeafFingerprintSHA256, "idempotent_replay"); err != nil {
			return MaterialInspection{}, errors.Join(ErrMaterialAmbiguous, err)
		}
		return prior.Inspection(), nil
	}
	if err = service.Repository.PreflightGeneration(ctx, request.TenantID, request.ResourceID, request.ExpectedCertificateGeneration); err != nil {
		return MaterialInspection{}, err
	}
	purpose := MaterialSecretPurpose{TenantID: request.TenantID, ResourceID: request.ResourceID, Operation: "self_signed", Binding: requestDigest}
	expectedPurpose, err := purpose.Canonical()
	if err != nil {
		return MaterialInspection{}, err
	}
	var stored ManagedCertificateGeneration
	var replay bool
	invoked := false
	err = service.Secrets.GeneratePrivateKeyAtomic(ctx, purpose, request.Key, func(signer crypto.Signer, reference MaterialPrivateKeyReference) error {
		if invoked {
			return ErrMaterialAmbiguous
		}
		invoked = true
		if signer == nil || !validMaterialPrivateKeyReference(reference) || reference.Purpose != expectedPurpose {
			return ErrMaterialInvalid
		}
		candidate, createErr := createSelfSignedManagedGeneration(request, policy, signer, reference, service.now())
		if createErr != nil {
			return createErr
		}
		createdGeneration, created, createErr := service.Repository.CreateCAS(ctx, candidate, request.ExpectedCertificateGeneration, "self_signed", request.IdempotencyKey, requestDigest)
		if createErr != nil {
			return createErr
		}
		stored = createdGeneration
		if !created {
			replay = true
			return errMaterialIdempotentReplay
		}
		return nil
	})
	if errors.Is(err, errMaterialIdempotentReplay) && replay {
		err = nil
	}
	if err != nil || !invoked || stored.ID == "" {
		service.auditFailure(ctx, principal, MaterialActionSelfSigned, scope, materialReasonCode(err))
		if err == nil {
			err = ErrMaterialAmbiguous
		}
		return MaterialInspection{}, err
	}
	scope.MaterialID = stored.ID
	if err = service.auditSuccess(ctx, principal, MaterialActionSelfSigned, scope, stored.ID, stored.LeafFingerprintSHA256, "standby_untrusted"); err != nil {
		return MaterialInspection{}, errors.Join(ErrMaterialAmbiguous, err)
	}
	return stored.Inspection(), nil
}

func (service MaterialService) Inspect(ctx context.Context, principal MaterialPrincipal, request InspectMaterialRequest) (MaterialInspection, error) {
	scope := MaterialScope{TenantID: request.TenantID, ResourceID: request.ResourceID, MaterialID: request.MaterialID}
	if err := service.authorizeAndAudit(ctx, principal, MaterialActionInspect, scope); err != nil {
		return MaterialInspection{}, err
	}
	generation, err := service.Repository.Get(ctx, request.TenantID, request.ResourceID, request.MaterialID)
	if err != nil {
		service.auditFailure(ctx, principal, MaterialActionInspect, scope, materialReasonCode(err))
		return MaterialInspection{}, err
	}
	if err = service.auditSuccess(ctx, principal, MaterialActionInspect, scope, generation.ID, generation.LeafFingerprintSHA256, "read"); err != nil {
		return MaterialInspection{}, err
	}
	return generation.Inspection(), nil
}

func (service MaterialService) List(ctx context.Context, principal MaterialPrincipal, request ListMaterialRequest) (MaterialInspectionPage, error) {
	scope := MaterialScope{TenantID: request.TenantID, ResourceID: request.ResourceID}
	if request.Limit < 1 || request.Limit > MaximumMaterialListLimit {
		return MaterialInspectionPage{}, ErrMaterialInvalid
	}
	if err := service.authorizeAndAudit(ctx, principal, MaterialActionList, scope); err != nil {
		return MaterialInspectionPage{}, err
	}
	generations, next, err := service.Repository.List(ctx, request.TenantID, request.ResourceID, request.Cursor, request.Limit)
	if err != nil {
		service.auditFailure(ctx, principal, MaterialActionList, scope, materialReasonCode(err))
		return MaterialInspectionPage{}, err
	}
	items := make([]MaterialInspection, len(generations))
	for index, generation := range generations {
		items[index] = generation.Inspection()
	}
	if err = service.auditSuccess(ctx, principal, MaterialActionList, scope, "", "", "read_bounded"); err != nil {
		return MaterialInspectionPage{}, err
	}
	return MaterialInspectionPage{Items: items, NextCursor: next}, nil
}

func (service MaterialService) Retire(ctx context.Context, principal MaterialPrincipal, request RetireMaterialRequest) (MaterialInspection, error) {
	scope := MaterialScope{TenantID: request.TenantID, ResourceID: request.ResourceID, MaterialID: request.MaterialID}
	if err := service.validateWriteRequest(ctx, principal, MaterialActionRetire, scope, "retire", request.IdempotencyKey); err != nil {
		return MaterialInspection{}, err
	}
	if request.ExpectedRecordGeneration == 0 || service.StepUp == nil || len(request.StepUpProof) == 0 || len(request.StepUpProof) > 4096 {
		return MaterialInspection{}, ErrMaterialStepUpRequired
	}
	generation, err := service.Repository.Get(ctx, request.TenantID, request.ResourceID, request.MaterialID)
	if err != nil {
		return MaterialInspection{}, err
	}
	requestDigest := digestMaterialStrings("retire-v1", request.TenantID, request.ResourceID, request.MaterialID,
		generation.LeafFingerprintSHA256, request.IdempotencyKey, uint64String(request.ExpectedRecordGeneration))
	binding := "retire:" + requestDigest
	if err = service.StepUp.VerifyMaterialStepUp(ctx, principal, request.StepUpProof, binding, service.now()); err != nil {
		service.auditFailure(ctx, principal, MaterialActionRetire, scope, "step_up_failed")
		return MaterialInspection{}, ErrMaterialStepUpRequired
	}
	retired, _, err := service.Repository.RetireCAS(ctx, request.TenantID, request.ResourceID, request.MaterialID, request.IdempotencyKey,
		requestDigest, request.ExpectedRecordGeneration, service.now())
	if err != nil {
		service.auditFailure(ctx, principal, MaterialActionRetire, scope, materialReasonCode(err))
		return MaterialInspection{}, err
	}
	if err = service.auditSuccess(ctx, principal, MaterialActionRetire, scope, retired.ID, retired.LeafFingerprintSHA256, "retired_metadata_only"); err != nil {
		return MaterialInspection{}, errors.Join(ErrMaterialAmbiguous, err)
	}
	return retired.Inspection(), nil
}

func managedGenerationFromImport(request ImportMaterialRequest, parsed parsedImportedMaterial, trust MaterialTrustLabel, materialID string, reference MaterialPrivateKeyReference, now time.Time) ManagedCertificateGeneration {
	return ManagedCertificateGeneration{
		ID: materialID,
		TenantID: request.TenantID,
		ResourceID: request.ResourceID,
		CertificateGeneration: request.ExpectedCertificateGeneration + 1,
		RecordGeneration: 1,
		Source: MaterialSourceImport,
		TrustLabel: trust,
		DisplayLabel: strings.TrimSpace(request.DisplayLabel),
		State: MaterialStateStaged,
		Subject: parsed.Subject,
		DNSNames: append([]string(nil), parsed.DNSNames...),
		IPAddresses: append([]string(nil), parsed.IPAddresses...),
		Issuer: parsed.Issuer,
		SerialHex: parsed.SerialHex,
		LeafFingerprintSHA256: parsed.LeafFingerprintSHA256,
		SPKIFingerprintSHA256: parsed.SPKIFingerprintSHA256,
		ChainFingerprintSHA256: parsed.ChainFingerprintSHA256,
		KeyAlgorithm: parsed.KeyAlgorithm,
		KeyBits: parsed.KeyBits,
		NotBefore: parsed.NotBefore,
		NotAfter: parsed.NotAfter,
		LeafDER: append([]byte(nil), parsed.LeafDER...),
		Chain: append([]MaterialCertificateEntry(nil), parsed.Chain...),
		PrivateKeyReference: reference,
		CreatedAt: now.UTC(),
		UpdatedAt: now.UTC(),
	}
}

func createSelfSignedManagedGeneration(request GenerateSelfSignedMaterialRequest, policy SelfSignedMaterialPolicy, signer crypto.Signer, reference MaterialPrivateKeyReference, now time.Time) (ManagedCertificateGeneration, error) {
	algorithm, bits, err := validateMaterialSigner(signer, policy.AllowedKeyAlgorithms, policy.MinimumRSAKeyBits)
	if err != nil || algorithm != request.Key.Algorithm || bits != request.Key.Bits {
		return ManagedCertificateGeneration{}, ErrMaterialInvalid
	}
	serialBytes := make([]byte, 20)
	if _, err = rand.Read(serialBytes); err != nil {
		return ManagedCertificateGeneration{}, err
	}
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	wipeMaterialBytes(serialBytes)
	if serial.Sign() == 0 {
		return ManagedCertificateGeneration{}, ErrMaterialInvalid
	}
	commonName := ""
	if len(request.DNSNames) != 0 {
		commonName = request.DNSNames[0]
	} else {
		commonName = request.IPAddresses[0]
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{CommonName: commonName, Organization: []string{"CyberPanel local recovery"}},
		NotBefore: now.UTC().Add(-policy.Backdate),
		NotAfter: now.UTC().Add(-policy.Backdate).Add(request.Lifetime),
		DNSNames: append([]string(nil), request.DNSNames...),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if algorithm == MaterialKeyRSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, value := range request.IPAddresses {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(value))
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return ManagedCertificateGeneration{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil || leaf.IsCA {
		return ManagedCertificateGeneration{}, ErrMaterialInvalid
	}
	dnsNames, ipAddresses, err := validateMaterialCertificateNames(leaf, MaterialNamePolicy{
		DNSNames: request.DNSNames,
		IPAddresses: request.IPAddresses,
		AllowWildcards: policy.AllowWildcards,
	})
	if err != nil {
		return ManagedCertificateGeneration{}, err
	}
	leafFingerprint := sha256.Sum256(leaf.Raw)
	spkiFingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	chainFingerprint := materialDERChainFingerprint([][]byte{leaf.Raw})
	materialID, err := NewManagedMaterialID(request.TenantID, request.ResourceID, hex.EncodeToString(leafFingerprint[:]))
	if err != nil {
		return ManagedCertificateGeneration{}, err
	}
	source := MaterialSourceDevelopment
	trust := MaterialTrustDevelopment
	label := "[UNTRUSTED DEVELOPMENT] " + strings.TrimSpace(request.DisplayLabel)
	if request.Mode == SelfSignedRecovery {
		source = MaterialSourceRecoverySelfSigned
		trust = MaterialTrustRecovery
		label = "[UNTRUSTED RECOVERY] " + strings.TrimSpace(request.DisplayLabel)
	}
	generation := ManagedCertificateGeneration{
		ID: materialID,
		TenantID: request.TenantID,
		ResourceID: request.ResourceID,
		CertificateGeneration: request.ExpectedCertificateGeneration + 1,
		RecordGeneration: 1,
		Source: source,
		TrustLabel: trust,
		DisplayLabel: label,
		State: MaterialStateStandby,
		Subject: leaf.Subject.String(),
		DNSNames: dnsNames,
		IPAddresses: ipAddresses,
		Issuer: leaf.Issuer.String(),
		SerialHex: strings.ToLower(leaf.SerialNumber.Text(16)),
		LeafFingerprintSHA256: hex.EncodeToString(leafFingerprint[:]),
		SPKIFingerprintSHA256: hex.EncodeToString(spkiFingerprint[:]),
		ChainFingerprintSHA256: chainFingerprint,
		KeyAlgorithm: algorithm,
		KeyBits: bits,
		NotBefore: leaf.NotBefore.UTC(),
		NotAfter: leaf.NotAfter.UTC(),
		LeafDER: append([]byte(nil), leaf.Raw...),
		Chain: []MaterialCertificateEntry{{
			DER: append([]byte(nil), leaf.Raw...),
			FingerprintSHA256: hex.EncodeToString(leafFingerprint[:]),
			Subject: leaf.Subject.String(),
			Issuer: leaf.Issuer.String(),
			SerialHex: strings.ToLower(leaf.SerialNumber.Text(16)),
			NotBefore: leaf.NotBefore.UTC(),
			NotAfter: leaf.NotAfter.UTC(),
		}},
		PrivateKeyReference: reference,
		CreatedAt: now.UTC(),
		UpdatedAt: now.UTC(),
	}
	if err = sealManagedCertificateGeneration(&generation); err != nil {
		return ManagedCertificateGeneration{}, err
	}
	return generation, nil
}

func normalizeSelfSignedMaterialPolicy(policy SelfSignedMaterialPolicy, mode SelfSignedMode, lifetime time.Duration, key MaterialKeySpec) (SelfSignedMaterialPolicy, error) {
	if (mode == SelfSignedDevelopment && !policy.DevelopmentEnabled) || (mode == SelfSignedRecovery && !policy.RecoveryEnabled) {
		return SelfSignedMaterialPolicy{}, ErrMaterialUnauthorized
	}
	if policy.MinimumLifetime == 0 {
		policy.MinimumLifetime = time.Hour
	}
	if policy.MaximumDevelopmentTTL == 0 {
		policy.MaximumDevelopmentTTL = 7 * 24 * time.Hour
	}
	if policy.MaximumRecoveryTTL == 0 {
		policy.MaximumRecoveryTTL = 24 * time.Hour
	}
	if policy.Backdate == 0 {
		policy.Backdate = 5 * time.Minute
	}
	if policy.MinimumRSAKeyBits == 0 {
		policy.MinimumRSAKeyBits = 3072
	}
	if len(policy.AllowedKeyAlgorithms) == 0 {
		policy.AllowedKeyAlgorithms = []MaterialKeyAlgorithm{MaterialKeyECDSA, MaterialKeyRSA, MaterialKeyEd25519}
	}
	if len(policy.AllowedKeyAlgorithms) > 3 {
		return SelfSignedMaterialPolicy{}, ErrMaterialInvalid
	}
	seenAlgorithms := make(map[MaterialKeyAlgorithm]struct{}, len(policy.AllowedKeyAlgorithms))
	for _, algorithm := range policy.AllowedKeyAlgorithms {
		if algorithm != MaterialKeyRSA && algorithm != MaterialKeyECDSA && algorithm != MaterialKeyEd25519 {
			return SelfSignedMaterialPolicy{}, ErrMaterialInvalid
		}
		if _, exists := seenAlgorithms[algorithm]; exists {
			return SelfSignedMaterialPolicy{}, ErrMaterialInvalid
		}
		seenAlgorithms[algorithm] = struct{}{}
	}
	maximum := policy.MaximumDevelopmentTTL
	if mode == SelfSignedRecovery {
		maximum = policy.MaximumRecoveryTTL
	}
	if lifetime < policy.MinimumLifetime || maximum < policy.MinimumLifetime || lifetime > maximum || maximum > 30*24*time.Hour ||
		policy.Backdate < 0 || policy.Backdate > time.Hour || policy.MinimumRSAKeyBits < 2048 || policy.MinimumRSAKeyBits > 8192 {
		return SelfSignedMaterialPolicy{}, ErrMaterialInvalid
	}
	found := false
	for _, algorithm := range policy.AllowedKeyAlgorithms {
		if algorithm == key.Algorithm {
			found = true
		}
	}
	if !found || !validMaterialKeySpec(key, policy.MinimumRSAKeyBits) {
		return SelfSignedMaterialPolicy{}, ErrMaterialInvalid
	}
	return policy, nil
}

func validMaterialKeySpec(spec MaterialKeySpec, minimumRSAKeyBits int) bool {
	switch spec.Algorithm {
	case MaterialKeyRSA:
		return spec.Bits >= minimumRSAKeyBits && spec.Bits <= 8192
	case MaterialKeyECDSA:
		return spec.Bits == 256 || spec.Bits == 384 || spec.Bits == 521
	case MaterialKeyEd25519:
		return spec.Bits == 256
	default:
		return false
	}
}

func digestImportMaterialRequest(request ImportMaterialRequest, parsed parsedImportedMaterial, trust MaterialTrustLabel) (string, error) {
	payload := struct {
		Version                    string
		TenantID                   string
		ResourceID                 string
		DisplayLabel               string
		DNSNames                   []string
		IPAddresses                []string
		ExpectedGeneration         uint64
		CertificateFingerprint     string
		SPKIFingerprint            string
		TrustLabel                 MaterialTrustLabel
	}{
		Version: "certificate-import-v1",
		TenantID: request.TenantID,
		ResourceID: request.ResourceID,
		DisplayLabel: strings.TrimSpace(request.DisplayLabel),
		DNSNames: parsed.DNSNames,
		IPAddresses: parsed.IPAddresses,
		ExpectedGeneration: request.ExpectedCertificateGeneration,
		CertificateFingerprint: parsed.LeafFingerprintSHA256,
		SPKIFingerprint: parsed.SPKIFingerprintSHA256,
		TrustLabel: trust,
	}
	return digestMaterialJSON(payload)
}

func digestSelfSignedMaterialRequest(request GenerateSelfSignedMaterialRequest) (string, error) {
	payload := struct {
		Version              string
		TenantID             string
		ResourceID           string
		DisplayLabel         string
		Mode                 SelfSignedMode
		DNSNames             []string
		IPAddresses          []string
		LifetimeNanoseconds  int64
		Key                  MaterialKeySpec
		ExpectedGeneration   uint64
		NoPublicReplacement  bool
	}{
		Version: "certificate-self-signed-v1",
		TenantID: request.TenantID,
		ResourceID: request.ResourceID,
		DisplayLabel: strings.TrimSpace(request.DisplayLabel),
		Mode: request.Mode,
		DNSNames: request.DNSNames,
		IPAddresses: request.IPAddresses,
		LifetimeNanoseconds: int64(request.Lifetime),
		Key: request.Key,
		ExpectedGeneration: request.ExpectedCertificateGeneration,
		NoPublicReplacement: request.AcknowledgeNoPublicReplacement,
	}
	return digestMaterialJSON(payload)
}

func digestMaterialJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func digestMaterialStrings(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func materialDERChainFingerprint(values [][]byte) string {
	hash := sha256.New()
	for _, value := range values {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (service MaterialService) validateWriteRequest(ctx context.Context, principal MaterialPrincipal, action MaterialAction, scope MaterialScope, displayLabel, idempotencyKey string) error {
	if service.Repository.DB == nil || service.Secrets == nil || service.Authorizer == nil || service.Audit == nil || ctx == nil ||
		!validMaterialIdentifier(scope.TenantID) || !validMaterialIdentifier(scope.ResourceID) ||
		!validMaterialDisplayLabel(displayLabel) || len(displayLabel) > 128 || !validMaterialIdempotencyKey(idempotencyKey) {
		return ErrMaterialInvalid
	}
	if action == MaterialActionImport && service.ImportPolicies == nil {
		return ErrMaterialInvalid
	}
	if action == MaterialActionSelfSigned && service.SelfSignedPolicy == nil {
		return ErrMaterialInvalid
	}
	return service.authorizeAndAudit(ctx, principal, action, scope)
}

func (service MaterialService) authorizeAndAudit(ctx context.Context, principal MaterialPrincipal, action MaterialAction, scope MaterialScope) error {
	if service.Authorizer == nil || service.Audit == nil || ctx == nil || !validMaterialIdentifier(principal.TenantID) ||
		!validMaterialIdentifier(principal.SubjectID) || principal.TenantID != scope.TenantID || !validMaterialIdentifier(scope.TenantID) ||
		(scope.ResourceID != "" && !validMaterialIdentifier(scope.ResourceID)) || (scope.MaterialID != "" && !validMaterialIdentifier(scope.MaterialID)) {
		return ErrMaterialUnauthorized
	}
	if err := service.Authorizer.AuthorizeMaterial(ctx, principal, action, scope); err != nil {
		_ = service.recordAudit(ctx, principal, action, scope, "denied", "authorization_denied", "")
		return ErrMaterialUnauthorized
	}
	if err := service.recordAudit(ctx, principal, action, scope, "admitted", "authorization_succeeded", ""); err != nil {
		return err
	}
	return nil
}

func (service MaterialService) auditSuccess(ctx context.Context, principal MaterialPrincipal, action MaterialAction, scope MaterialScope, materialID, fingerprint, reason string) error {
	scope.MaterialID = materialID
	return service.recordAudit(ctx, principal, action, scope, "succeeded", reason, fingerprint)
}

func (service MaterialService) auditFailure(ctx context.Context, principal MaterialPrincipal, action MaterialAction, scope MaterialScope, reason string) {
	_ = service.recordAudit(ctx, principal, action, scope, "failed", reason, "")
}

func (service MaterialService) recordAudit(ctx context.Context, principal MaterialPrincipal, action MaterialAction, scope MaterialScope, outcome, reason, fingerprint string) error {
	if service.Audit == nil {
		return ErrMaterialInvalid
	}
	now := service.now()
	eventID := digestMaterialStrings("material-audit-v1", principal.TenantID, principal.SubjectID, string(action), scope.ResourceID, scope.MaterialID,
		outcome, reason, fingerprint, materialTimeText(now))
	event := MaterialAuditEvent{
		EventID: "material_audit_" + eventID[:48],
		TenantID: principal.TenantID,
		SubjectID: principal.SubjectID,
		Action: action,
		ResourceID: scope.ResourceID,
		MaterialID: scope.MaterialID,
		CertificateFingerprint: fingerprint,
		Outcome: outcome,
		ReasonCode: reason,
		OccurredAt: now,
	}
	return service.Audit.RecordMaterialAudit(ctx, event)
}

func (service MaterialService) now() time.Time {
	if service.Now != nil {
		return service.Now().UTC()
	}
	return time.Now().UTC()
}

func materialReasonCode(err error) string {
	switch {
	case err == nil:
		return "ambiguous_result"
	case errors.Is(err, ErrMaterialInvalid):
		return "invalid"
	case errors.Is(err, ErrMaterialConflict):
		return "stale_generation"
	case errors.Is(err, ErrMaterialDuplicate):
		return "duplicate"
	case errors.Is(err, ErrMaterialOwnership):
		return "ownership_conflict"
	case errors.Is(err, ErrMaterialNotRetirable):
		return "not_retirable"
	case errors.Is(err, ErrMaterialUnauthorized):
		return "unauthorized"
	default:
		return "operation_failed"
	}
}

func uint64String(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[position:])
}
