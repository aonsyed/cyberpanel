package emailmarketing

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"time"
)

type BackupRecordType string

const (
	BackupLists         BackupRecordType = "lists"
	BackupSubscribers   BackupRecordType = "subscribers"
	BackupConsent       BackupRecordType = "consent"
	BackupSuppression   BackupRecordType = "suppression"
	BackupTemplates     BackupRecordType = "templates"
	BackupCampaigns     BackupRecordType = "campaigns"
	BackupAttempts      BackupRecordType = "attempts"
	BackupProviderRefs  BackupRecordType = "provider_refs"
)

type BackupDataClass string

const (
	BackupClassContact    BackupDataClass = "contact"
	BackupClassConsent    BackupDataClass = "consent_evidence"
	BackupClassSuppression BackupDataClass = "suppression_evidence"
	BackupClassContent    BackupDataClass = "message_content"
	BackupClassDelivery   BackupDataClass = "delivery_metadata"
	BackupClassProviderRef BackupDataClass = "provider_reference"
)

type BackupRetentionRule struct {
	DataClass   BackupDataClass
	RetainUntil time.Time
	LegalHold   bool
}

type CampaignBackupManifest struct {
	FormatVersion       uint32
	ManifestID          string
	TenantID            TenantID
	SourceRevision      string
	SchemaDigest        string
	PolicyDigest        string
	DataClasses         []BackupDataClass
	Retention           []BackupRetentionRule
	CreatedAt           time.Time
	ContentDigest       string
	RecordCount         uint64
	ReauthorizationRequired bool
}

type CampaignBackupRecord struct {
	Sequence                uint64
	Type                    BackupRecordType
	DataClass               BackupDataClass
	ResourceID              string
	Generation              uint64
	Payload                  json.RawMessage
	PayloadDigest            string
	RetainUntil              time.Time
	ReauthorizationRequired bool
}

type CampaignBackupTrailer struct {
	ManifestID    string
	RecordCount   uint64
	ContentDigest string
	CompletedAt   time.Time
}

type CampaignBackupScope struct {
	TenantID       TenantID
	SourceRevision string
	SchemaDigest   string
	PolicyDigest   string
	Retention      []BackupRetentionRule
	CreatedAt      time.Time
	MaximumRecords uint64
	MaximumBytes   int64
}

type CampaignBackupSource interface {
	StreamCampaignBackup(context.Context, CampaignBackupScope, func(CampaignBackupRecord) error) error
}

func (r *SQLiteRepository) StreamCampaignBackup(ctx context.Context, scope CampaignBackupScope, emit func(CampaignBackupRecord) error) error {
	if r == nil || r.db == nil || emit == nil || validateBackupScope(scope) != nil {
		return ErrInvalid
	}
	type table struct {
		RecordType BackupRecordType
		DataClass  BackupDataClass
		Query      string
	}
	tables := []table{
		{BackupLists, BackupClassContact, `SELECT 'list:'||list_id,generation,document FROM email_marketing_lists_v1 WHERE tenant_id=? ORDER BY list_id`},
		{BackupSubscribers, BackupClassContact, `SELECT 'tag:'||tag_id,generation,document FROM email_marketing_tags_v1 WHERE tenant_id=? ORDER BY tag_id`},
		{BackupSubscribers, BackupClassContact, `SELECT 'subscriber:'||subscriber_id,generation,document FROM email_marketing_subscribers_v1 WHERE tenant_id=? ORDER BY subscriber_id`},
		{BackupSubscribers, BackupClassContact, `SELECT 'membership:'||list_id||':'||subscriber_id,generation,document FROM email_marketing_memberships_v1 WHERE tenant_id=? ORDER BY list_id,subscriber_id`},
		{BackupConsent, BackupClassConsent, `SELECT 'consent:'||consent_id,1,document FROM email_marketing_consents_v1 WHERE tenant_id=? ORDER BY consent_id`},
		{BackupSuppression, BackupClassSuppression, `SELECT 'suppression:'||record_id,1,document FROM email_marketing_suppression_history_v1 WHERE tenant_id=? ORDER BY record_id`},
		{BackupTemplates, BackupClassContent, `SELECT 'template:'||template_id,generation,document FROM email_marketing_templates_v1 WHERE tenant_id=? ORDER BY template_id`},
		{BackupTemplates, BackupClassContent, `SELECT 'template_version:'||template_id||':'||version,version,document FROM email_marketing_template_versions_v1 WHERE tenant_id=? ORDER BY template_id,version`},
		{BackupCampaigns, BackupClassDelivery, `SELECT 'campaign:'||campaign_id,generation,document FROM email_marketing_campaigns_v1 WHERE tenant_id=? ORDER BY campaign_id`},
		{BackupCampaigns, BackupClassDelivery, `SELECT 'recipient:'||campaign_id||':'||ordinal,campaign_revision,document FROM email_marketing_campaign_recipients_v1 WHERE tenant_id=? ORDER BY campaign_id,campaign_revision,ordinal`},
		{BackupAttempts, BackupClassDelivery, `SELECT 'attempt:'||attempt_id,attempt_number+1,document FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? ORDER BY attempt_id`},
		{BackupAttempts, BackupClassDelivery, `SELECT 'receipt:'||receipt_id,1,document FROM email_marketing_campaign_receipts_v1 WHERE tenant_id=? ORDER BY receipt_id`},
		{BackupAttempts, BackupClassDelivery, `SELECT 'event:'||provider_ref||':'||event_id,1,document FROM email_marketing_delivery_events_v1 WHERE tenant_id=? ORDER BY provider_ref,event_id`},
		{BackupProviderRefs, BackupClassProviderRef, `SELECT 'sender:'||domain,generation,document FROM email_marketing_sender_admission_v1 WHERE tenant_id=? ORDER BY domain`},
		{BackupProviderRefs, BackupClassProviderRef, `SELECT 'capacity:'||profile_ref,generation,document FROM email_marketing_delivery_capacity_v1 WHERE tenant_id=? ORDER BY profile_ref`},
	}
	var sequence uint64
	for _, sourceTable := range tables {
		rows, err := r.db.QueryContext(ctx, sourceTable.Query, scope.TenantID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var resourceID string
			var generation uint64
			var payload []byte
			if rows.Scan(&resourceID, &generation, &payload) != nil {
				rows.Close()
				return ErrIntegrity
			}
			sequence++
			record := CampaignBackupRecord{Sequence: sequence, Type: sourceTable.RecordType, DataClass: sourceTable.DataClass, ResourceID: resourceID, Generation: generation, Payload: append(json.RawMessage(nil), payload...), PayloadDigest: DigestEvidence(payload), RetainUntil: retentionDeadline(scope.Retention, sourceTable.DataClass), ReauthorizationRequired: sourceTable.RecordType == BackupProviderRefs}
			if err = emit(record); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

type CampaignBackupService struct {
	Authorizer Authorizer
	StepUp     StepUpVerifier
	Audit      AuditSink
	Now        func() time.Time
}

func (service CampaignBackupService) Export(ctx context.Context, access AdministrativeContext, stepUpProof string, source CampaignBackupSource, output io.Writer, scope CampaignBackupScope) (CampaignBackupManifest, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.backup.export", "backup:"+string(access.TenantID))
	if err != nil || scope.TenantID != access.TenantID {
		return CampaignBackupManifest{}, ErrUnauthorized
	}
	if _, err = service.stepUp(ctx, request, stepUpProof); err != nil {
		return CampaignBackupManifest{}, err
	}
	manifest, err := ExportCampaignBackup(ctx, source, output, scope)
	if err != nil {
		return CampaignBackupManifest{}, err
	}
	if err = service.audit(ctx, request, "exported", manifest.ContentDigest); err != nil {
		return CampaignBackupManifest{}, err
	}
	return manifest, nil
}

func (service CampaignBackupService) Restore(ctx context.Context, access AdministrativeContext, stepUpProof string, input io.Reader, activation CampaignRestoreActivation, limits CampaignRestoreLimits) (CampaignRestoreValidation, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.backup.restore", "restore:"+string(access.TenantID))
	if err != nil || limits.ExpectedTenant != access.TenantID {
		return CampaignRestoreValidation{}, ErrUnauthorized
	}
	if _, err = service.stepUp(ctx, request, stepUpProof); err != nil {
		return CampaignRestoreValidation{}, err
	}
	validation, err := RestoreCampaignBackup(ctx, input, activation, limits)
	if err != nil {
		return CampaignRestoreValidation{}, err
	}
	if err = service.audit(ctx, request, "activated", validation.ValidationDigest); err != nil {
		return CampaignRestoreValidation{}, err
	}
	return validation, nil
}

func (service CampaignBackupService) authorize(ctx context.Context, access AdministrativeContext, action, resource string) (AuthorizationRequest, error) {
	request := AuthorizationRequest{TenantID: access.TenantID, ActorID: access.ActorID, Action: action, Resource: resource, DataClass: "contact_consent_and_delivery_backup"}
	if service.Authorizer == nil || service.Audit == nil || service.Now == nil || validateIdentifier(string(access.TenantID)) != nil || validateIdentifier(string(access.ActorID)) != nil || service.Authorizer.Authorize(ctx, request) != nil {
		return request, ErrUnauthorized
	}
	return request, nil
}

func (service CampaignBackupService) stepUp(ctx context.Context, request AuthorizationRequest, proof string) (string, error) {
	if service.StepUp == nil || proof == "" {
		return "", ErrUnauthorized
	}
	receipt, err := service.StepUp.VerifyStepUp(ctx, request, proof)
	if err != nil || receipt == "" {
		return "", ErrUnauthorized
	}
	return receipt, nil
}

func (service CampaignBackupService) audit(ctx context.Context, request AuthorizationRequest, outcome, evidence string) error {
	return service.Audit.RecordAudit(ctx, AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: outcome, EvidenceDigest: evidence, OccurredAt: service.Now().UTC()})
}

type CampaignRestoreLimits struct {
	MaximumRecords uint64
	MaximumBytes   int64
	MaximumLineBytes int
	ExpectedTenant TenantID
	ExpectedSchemaDigest string
	ExpectedPolicyDigest string
	ExpectedActivationGeneration uint64
}

type CampaignRestoreValidation struct {
	ManifestID       string
	RecordCount      uint64
	ContentDigest    string
	ValidationDigest string
	ReauthorizationRequired bool
}

// CampaignRestoreActivation stages into isolated authority and exposes only a
// CAS activation. Implementations must make Abort idempotent.
type CampaignRestoreActivation interface {
	BeginIsolatedCampaignRestore(context.Context, CampaignBackupManifest) (string, error)
	StageCampaignRestoreRecord(context.Context, string, CampaignBackupRecord) error
	ValidateIsolatedCampaignRestore(context.Context, string, CampaignBackupManifest) (CampaignRestoreValidation, error)
	ActivateCampaignRestoreCAS(context.Context, string, uint64, CampaignRestoreValidation) error
	AbortCampaignRestore(context.Context, string) error
}

type campaignBackupLine struct {
	Kind     string
	Manifest *CampaignBackupManifest
	Record   *CampaignBackupRecord
	Trailer  *CampaignBackupTrailer
}

func ExportCampaignBackup(ctx context.Context, source CampaignBackupSource, output io.Writer, scope CampaignBackupScope) (CampaignBackupManifest, error) {
	if source == nil || output == nil || validateBackupScope(scope) != nil {
		return CampaignBackupManifest{}, ErrInvalid
	}
	classes := []BackupDataClass{BackupClassContact, BackupClassConsent, BackupClassSuppression, BackupClassContent, BackupClassDelivery, BackupClassProviderRef}
	manifest := CampaignBackupManifest{FormatVersion: 1, ManifestID: "backup:" + DigestEvidence([]byte(string(scope.TenantID)+":"+scope.SourceRevision+":"+dbTime(scope.CreatedAt)))[:40], TenantID: scope.TenantID, SourceRevision: scope.SourceRevision, SchemaDigest: scope.SchemaDigest, PolicyDigest: scope.PolicyDigest, DataClasses: classes, Retention: append([]BackupRetentionRule(nil), scope.Retention...), CreatedAt: scope.CreatedAt.UTC(), ReauthorizationRequired: true}
	sort.Slice(manifest.Retention, func(i, j int) bool { return manifest.Retention[i].DataClass < manifest.Retention[j].DataClass })
	written := int64(0)
	writeLine := func(value campaignBackupLine) ([]byte, error) {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, '\n')
		if written+int64(len(encoded)) > scope.MaximumBytes {
			return nil, ErrConflict
		}
		n, err := output.Write(encoded)
		written += int64(n)
		if err != nil {
			return nil, err
		}
		if n != len(encoded) {
			return nil, io.ErrShortWrite
		}
		return encoded, nil
	}
	if _, err := writeLine(campaignBackupLine{Kind: "manifest", Manifest: &manifest}); err != nil {
		return CampaignBackupManifest{}, err
	}
	hasher := sha256.New()
	var count uint64
	err := source.StreamCampaignBackup(ctx, scope, func(record CampaignBackupRecord) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if count >= scope.MaximumRecords || validateBackupRecord(record, count+1, manifest) != nil {
			return ErrInvalid
		}
		if record.Type == BackupProviderRefs {
			record.ReauthorizationRequired = true
			manifest.ReauthorizationRequired = true
		}
		encoded, err := json.Marshal(campaignBackupLine{Kind: "record", Record: &record})
		if err != nil {
			return err
		}
		encoded = append(encoded, '\n')
		if written+int64(len(encoded)) > scope.MaximumBytes {
			return ErrConflict
		}
		n, err := output.Write(encoded)
		written += int64(n)
		if err != nil {
			return err
		}
		if n != len(encoded) {
			return io.ErrShortWrite
		}
		_, _ = hasher.Write(encoded)
		count++
		return nil
	})
	if err != nil {
		return CampaignBackupManifest{}, err
	}
	manifest.RecordCount = count
	manifest.ContentDigest = hex.EncodeToString(hasher.Sum(nil))
	trailer := CampaignBackupTrailer{ManifestID: manifest.ManifestID, RecordCount: count, ContentDigest: manifest.ContentDigest, CompletedAt: scope.CreatedAt.UTC()}
	if _, err = writeLine(campaignBackupLine{Kind: "trailer", Trailer: &trailer}); err != nil {
		return CampaignBackupManifest{}, err
	}
	return manifest, nil
}

func RestoreCampaignBackup(ctx context.Context, input io.Reader, activation CampaignRestoreActivation, limits CampaignRestoreLimits) (CampaignRestoreValidation, error) {
	if input == nil || activation == nil || validateRestoreLimits(limits) != nil {
		return CampaignRestoreValidation{}, ErrInvalid
	}
	scanner := bufio.NewScanner(io.LimitReader(input, limits.MaximumBytes+1))
	scanner.Buffer(make([]byte, 64*1024), limits.MaximumLineBytes)
	if !scanner.Scan() {
		return CampaignRestoreValidation{}, ErrIntegrity
	}
	bytesRead := int64(len(scanner.Bytes()) + 1)
	var first campaignBackupLine
	if json.Unmarshal(scanner.Bytes(), &first) != nil || first.Kind != "manifest" || first.Manifest == nil || validateBackupManifest(*first.Manifest, limits) != nil {
		return CampaignRestoreValidation{}, ErrIntegrity
	}
	manifest := *first.Manifest
	stagingID, err := activation.BeginIsolatedCampaignRestore(ctx, manifest)
	if err != nil {
		return CampaignRestoreValidation{}, err
	}
	if stagingID == "" {
		return CampaignRestoreValidation{}, ErrIntegrity
	}
	activated := false
	defer func() {
		if !activated {
			_ = activation.AbortCampaignRestore(context.Background(), stagingID)
		}
	}()
	hasher := sha256.New()
	var count uint64
	var trailer CampaignBackupTrailer
	for scanner.Scan() {
		lineBytes := append([]byte(nil), scanner.Bytes()...)
		bytesRead += int64(len(lineBytes) + 1)
		if bytesRead > limits.MaximumBytes {
			return CampaignRestoreValidation{}, ErrConflict
		}
		var line campaignBackupLine
		if json.Unmarshal(lineBytes, &line) != nil {
			return CampaignRestoreValidation{}, ErrIntegrity
		}
		if line.Kind == "trailer" {
			if line.Trailer == nil || trailer.ManifestID != "" {
				return CampaignRestoreValidation{}, ErrIntegrity
			}
			trailer = *line.Trailer
			continue
		}
		if line.Kind != "record" || line.Record == nil || trailer.ManifestID != "" || count >= limits.MaximumRecords {
			return CampaignRestoreValidation{}, ErrIntegrity
		}
		record := *line.Record
		if validateBackupRecord(record, count+1, manifest) != nil {
			return CampaignRestoreValidation{}, ErrIntegrity
		}
		if record.Type == BackupProviderRefs && !record.ReauthorizationRequired {
			return CampaignRestoreValidation{}, ErrIntegrity
		}
		canonical, _ := json.Marshal(campaignBackupLine{Kind: "record", Record: &record})
		canonical = append(canonical, '\n')
		if string(canonical[:len(canonical)-1]) != string(lineBytes) {
			return CampaignRestoreValidation{}, ErrIntegrity
		}
		_, _ = hasher.Write(canonical)
		if err = activation.StageCampaignRestoreRecord(ctx, stagingID, record); err != nil {
			return CampaignRestoreValidation{}, err
		}
		count++
	}
	if err = scanner.Err(); err != nil {
		return CampaignRestoreValidation{}, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if trailer.ManifestID != manifest.ManifestID || trailer.RecordCount != count || trailer.ContentDigest != digest || trailer.CompletedAt.Before(manifest.CreatedAt) || !validDigest(digest) || manifest.RecordCount != 0 || manifest.ContentDigest != "" {
		return CampaignRestoreValidation{}, ErrIntegrity
	}
	manifest.RecordCount, manifest.ContentDigest, manifest.ReauthorizationRequired = count, digest, manifest.ReauthorizationRequired || backupNeedsReauthorization(manifest)
	validation, err := activation.ValidateIsolatedCampaignRestore(ctx, stagingID, manifest)
	if err != nil || validation.ManifestID != manifest.ManifestID || validation.RecordCount != count || validation.ContentDigest != digest || !validDigest(validation.ValidationDigest) || manifest.ReauthorizationRequired && !validation.ReauthorizationRequired {
		return CampaignRestoreValidation{}, ErrIntegrity
	}
	if err = activation.ActivateCampaignRestoreCAS(ctx, stagingID, limits.ExpectedActivationGeneration, validation); err != nil {
		return CampaignRestoreValidation{}, err
	}
	activated = true
	return validation, nil
}

func validateBackupScope(scope CampaignBackupScope) error {
	if validateIdentifier(string(scope.TenantID)) != nil || validateIdentifier(scope.SourceRevision) != nil || !validDigest(scope.SchemaDigest) || !validDigest(scope.PolicyDigest) ||
		scope.CreatedAt.IsZero() || scope.MaximumRecords == 0 || scope.MaximumRecords > 100_000_000 || scope.MaximumBytes < 1024 || scope.MaximumBytes > 1<<40 ||
		validateRetention(scope.Retention, scope.CreatedAt) != nil || !retentionCoversAllClasses(scope.Retention) {
		return ErrInvalid
	}
	return nil
}

func validateBackupManifest(manifest CampaignBackupManifest, limits CampaignRestoreLimits) error {
	if manifest.FormatVersion != 1 || validateIdentifier(manifest.ManifestID) != nil || manifest.TenantID != limits.ExpectedTenant ||
		validateIdentifier(manifest.SourceRevision) != nil || manifest.SchemaDigest != limits.ExpectedSchemaDigest || manifest.PolicyDigest != limits.ExpectedPolicyDigest ||
		manifest.CreatedAt.IsZero() || manifest.ContentDigest != "" || manifest.RecordCount != 0 || !manifest.ReauthorizationRequired || !manifestClassesValid(manifest.DataClasses) || validateRetention(manifest.Retention, manifest.CreatedAt) != nil || !retentionCoversAllClasses(manifest.Retention) {
		return ErrInvalid
	}
	return nil
}

func validateRestoreLimits(limits CampaignRestoreLimits) error {
	if limits.MaximumRecords == 0 || limits.MaximumRecords > 100_000_000 || limits.MaximumBytes < 1024 || limits.MaximumBytes > 1<<40 ||
		limits.MaximumLineBytes < 1024 || limits.MaximumLineBytes > 16<<20 || validateIdentifier(string(limits.ExpectedTenant)) != nil ||
		!validDigest(limits.ExpectedSchemaDigest) || !validDigest(limits.ExpectedPolicyDigest) {
		return ErrInvalid
	}
	return nil
}

func validateBackupRecord(record CampaignBackupRecord, sequence uint64, manifest CampaignBackupManifest) error {
	if record.Sequence != sequence || !backupRecordTypeValid(record.Type) || !backupDataClassValid(record.DataClass) || validateBackupResourceID(record.ResourceID) != nil ||
		record.Generation == 0 || len(record.Payload) == 0 || len(record.Payload) > 8<<20 || !json.Valid(record.Payload) || !validDigest(record.PayloadDigest) ||
		record.PayloadDigest != DigestEvidence(record.Payload) || record.RetainUntil.Before(manifest.CreatedAt) || !backupRecordClassMatches(record.Type, record.DataClass) ||
		!record.RetainUntil.Equal(retentionDeadline(manifest.Retention, record.DataClass)) || containsNonportableSecret(record.Payload) {
		return ErrInvalid
	}
	return nil
}

func validateBackupResourceID(value string) error {
	if value == "" || len(value) > 512 {
		return ErrInvalid
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return ErrInvalid
		}
	}
	return nil
}

func validateRetention(rules []BackupRetentionRule, createdAt time.Time) error {
	if len(rules) == 0 || len(rules) > 16 {
		return ErrInvalid
	}
	seen := make(map[BackupDataClass]struct{}, len(rules))
	for _, rule := range rules {
		if !backupDataClassValid(rule.DataClass) || rule.RetainUntil.Before(createdAt) {
			return ErrInvalid
		}
		if _, duplicate := seen[rule.DataClass]; duplicate {
			return ErrInvalid
		}
		seen[rule.DataClass] = struct{}{}
	}
	return nil
}

func backupRecordTypeValid(value BackupRecordType) bool {
	switch value {
	case BackupLists, BackupSubscribers, BackupConsent, BackupSuppression, BackupTemplates, BackupCampaigns, BackupAttempts, BackupProviderRefs:
		return true
	default:
		return false
	}
}

func backupDataClassValid(value BackupDataClass) bool {
	switch value {
	case BackupClassContact, BackupClassConsent, BackupClassSuppression, BackupClassContent, BackupClassDelivery, BackupClassProviderRef:
		return true
	default:
		return false
	}
}

func backupRecordClassMatches(recordType BackupRecordType, dataClass BackupDataClass) bool {
	switch recordType {
	case BackupLists, BackupSubscribers:
		return dataClass == BackupClassContact
	case BackupConsent:
		return dataClass == BackupClassConsent
	case BackupSuppression:
		return dataClass == BackupClassSuppression
	case BackupTemplates:
		return dataClass == BackupClassContent
	case BackupCampaigns, BackupAttempts:
		return dataClass == BackupClassDelivery
	case BackupProviderRefs:
		return dataClass == BackupClassProviderRef
	default:
		return false
	}
}

func retentionCoversAllClasses(rules []BackupRetentionRule) bool {
	for _, class := range []BackupDataClass{BackupClassContact, BackupClassConsent, BackupClassSuppression, BackupClassContent, BackupClassDelivery, BackupClassProviderRef} {
		if retentionDeadline(rules, class).IsZero() {
			return false
		}
	}
	return true
}

func retentionDeadline(rules []BackupRetentionRule, class BackupDataClass) time.Time {
	for _, rule := range rules {
		if rule.DataClass == class {
			return rule.RetainUntil
		}
	}
	return time.Time{}
}

func containsNonportableSecret(payload json.RawMessage) bool {
	var value any
	if json.Unmarshal(payload, &value) != nil {
		return true
	}
	var inspect func(any) bool
	inspect = func(current any) bool {
		switch typed := current.(type) {
		case map[string]any:
			for key, nested := range typed {
				switch key {
				case "secret", "password", "passwd", "api_key", "access_token", "refresh_token", "credential", "private_key", "smtp_password":
					return true
				}
				if inspect(nested) {
					return true
				}
			}
		case []any:
			for _, nested := range typed {
				if inspect(nested) {
					return true
				}
			}
		}
		return false
	}
	return inspect(value)
}

func backupNeedsReauthorization(manifest CampaignBackupManifest) bool {
	for _, class := range manifest.DataClasses {
		if class == BackupClassProviderRef {
			return true
		}
	}
	return false
}

func manifestClassesValid(classes []BackupDataClass) bool {
	expected := []BackupDataClass{BackupClassContact, BackupClassConsent, BackupClassSuppression, BackupClassContent, BackupClassDelivery, BackupClassProviderRef}
	if len(classes) != len(expected) {
		return false
	}
	seen := make(map[BackupDataClass]struct{}, len(classes))
	for _, class := range classes {
		if !backupDataClassValid(class) {
			return false
		}
		seen[class] = struct{}{}
	}
	for _, class := range expected {
		if _, present := seen[class]; !present {
			return false
		}
	}
	return true
}
