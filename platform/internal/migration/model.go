package migration

import (
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid       = errors.New("migration: invalid value")
	ErrNotFound      = errors.New("migration: not found")
	ErrConflict      = errors.New("migration: conflict")
	ErrBlocked       = errors.New("migration: blocked by policy")
	ErrCapacity      = errors.New("migration: insufficient capacity")
	ErrAmbiguous     = errors.New("migration: ambiguous effect")
	ErrWriteFrontier = errors.New("migration: target write frontier crossed")
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,95}$`)

type ID string

func NewID(value string) (ID, error) {
	value = strings.TrimSpace(value)
	if !idPattern.MatchString(value) {
		return "", ErrInvalid
	}
	return ID(value), nil
}
func (id ID) Valid() bool    { return idPattern.MatchString(string(id)) }
func (id ID) String() string { return string(id) }

type Phase string

const (
	PhaseCreated            Phase = "created"
	PhaseDiscovering        Phase = "discovering"
	PhaseInventoried        Phase = "inventoried"
	PhasePlanned            Phase = "planned"
	PhaseReady              Phase = "ready"
	PhaseBaseSync           Phase = "base_sync"
	PhaseQuiescing          Phase = "quiescing"
	PhaseFinalSync          Phase = "final_sync"
	PhaseCutoverReady       Phase = "cutover_ready"
	PhaseCutoverCommitting  Phase = "cutover_committing"
	PhaseVerifying          Phase = "verifying"
	PhaseCommitted          Phase = "committed"
	PhaseCleanup            Phase = "cleanup"
	PhasePausedRetryable    Phase = "paused_retryable"
	PhaseBlockedPolicy      Phase = "blocked_policy"
	PhaseFailedTerminal     Phase = "failed_terminal"
	PhaseRollingBack        Phase = "rolling_back"
	PhaseRolledBack         Phase = "rolled_back"
	PhaseCanceled           Phase = "canceled"
)

type SourceKind string

const (
	SourceCyberPanel       SourceKind = "cyberpanel"
	SourceCyberPanelBackup SourceKind = "cyberpanel_backup"
	SourceCPanel           SourceKind = "cpanel"
	SourceCanonical        SourceKind = "canonical"
)

type Provenance struct {
	SourceKind       string
	SourceLocation   string
	ExtractorVersion string
	ObservedAt       time.Time
	Digest           string
	Confidence       string
	Authoritative    bool
}

type Conflict struct {
	Field      string
	Values     []ProvenancedValue
	Resolution string
	Blocking   bool
}

type ProvenancedValue struct {
	Value      string
	Provenance Provenance
}

type Chunk struct {
	Digest           string
	Size             uint64
	MediaType        string
	Compression      string
	EncryptionDomain string
	ObjectCount      uint64
}

type SecretEnvelope struct {
	SecretID        string
	Purpose         string
	AudienceDigest  string
	Algorithm       string
	KeyID           string
	Version         uint64
	EncapsulatedKey []byte
	Ciphertext      []byte
}

type Site struct {
	SourceID               ID
	TargetID               ID
	TenantID               ID
	ProjectID              ID
	PrimaryHostname        string
	Aliases                []string
	Redirects              []string
	Children               []string
	PHPVersion             string
	DocumentRootRelative   string
	RuntimeKind            string
	ResourceProfile        map[string]uint64
	Content                []Chunk
	DatabaseIDs            []ID
	MailDomainIDs          []ID
	CredentialIDs          []ID
	CronIDs                []ID
	RepositoryIDs          []ID
	ContainerApplicationIDs []ID
	Provenance             []Provenance
	Conflicts              []Conflict
}

type Database struct {
	SourceID  ID
	TargetID  ID
	SiteID    ID
	Name      string
	Charset   string
	Collation string
	Dump      []Chunk
	Principals []DatabasePrincipal
	Provenance []Provenance
	Conflicts  []Conflict
}

type DatabasePrincipal struct {
	Name      string
	GrantSets []string
	SecretID  string
	CredentialDisposition CredentialDisposition
}

type CredentialDisposition string

const (
	CredentialPreserved     CredentialDisposition = "preserved"
	CredentialResetRequired CredentialDisposition = "reset_required"
	CredentialPublicOnly    CredentialDisposition = "public_only"
)

type DNSZone struct {
	SourceID   ID
	TargetID   ID
	Name       string
	Mode       string
	RecordSets []DNSRecordSet
	DNSSEC     bool
	Provenance []Provenance
	Conflicts  []Conflict
}

type DNSRecordSet struct {
	Name   string
	Type   string
	TTL    uint32
	Values []string
}

type MailDomain struct {
	SourceID    ID
	TargetID    ID
	SiteID      ID
	Name        string
	Mailboxes   []Mailbox
	Aliases     []string
	Forwarders  []string
	CatchAll    []string
	DKIMSecretID string
	MailData    []Chunk
	Provenance  []Provenance
	Conflicts   []Conflict
}

type Mailbox struct {
	SourceID          ID
	TargetID          ID
	Address           string
	QuotaBytes        uint64
	CredentialSecretID string
	CredentialDisposition CredentialDisposition
	Data              []Chunk
}

type Certificate struct {
	SourceID          ID
	TargetID          ID
	Names             []string
	Certificate       []Chunk
	Chain             []Chunk
	PrivateKeySecretID string
	Issuer            string
	NotAfter          time.Time
	Provenance        []Provenance
}

type AccessCredential struct {
	SourceID    ID
	TargetID    ID
	SiteID      ID
	Kind        string
	Label       string
	RootRelative string
	PublicKey   string
	SecretID    string
	CredentialDisposition CredentialDisposition
	Provenance  []Provenance
}

type Schedule struct {
	SourceID    ID
	TargetID    ID
	SiteID      ID
	Kind        string
	Expression  string
	Timezone    string
	InvocationID string
	Enabled     bool
	Provenance  []Provenance
}

type RepositoryBinding struct {
	SourceID          ID
	TargetID          ID
	SiteID            ID
	Provider          string
	Origin            string
	Branch            string
	CredentialSecretID string
	AutoDeploy        bool
	Provenance        []Provenance
}

type ContainerApplication struct {
	SourceID     ID
	TargetID     ID
	SiteID       ID
	RecipeID     string
	RecipeVersion string
	Descriptor   []Chunk
	VolumeData   []Chunk
	SecretIDs    []string
	Provenance   []Provenance
	Conflicts    []Conflict
}

type BackupPolicy struct {
	SourceID          ID
	TargetID          ID
	SiteID            ID
	Schedule          string
	Retention         string
	Provider          string
	Repository        string
	CredentialSecretID string
	Provenance        []Provenance
}

type Manifest struct {
	SchemaVersion       uint32
	MigrationID         ID
	Source              SourceKind
	SourceInstallationID string
	TargetInstallationID string
	SourceGeneration    uint64
	CreatedAt           time.Time
	Sites               []Site
	Databases           []Database
	DNSZones            []DNSZone
	MailDomains         []MailDomain
	Certificates        []Certificate
	Credentials         []AccessCredential
	Schedules           []Schedule
	Repositories        []RepositoryBinding
	Containers          []ContainerApplication
	BackupPolicies      []BackupPolicy
	Secrets             []SecretEnvelope
	Chunks              []Chunk
	Conflicts           []Conflict
	MerkleRoot          string
	SchemaHash          string
	SigningKeyID        string
	Signature           []byte
}

func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != 1 || !manifest.MigrationID.Valid() || !validSource(manifest.Source) || manifest.SourceInstallationID == "" || manifest.TargetInstallationID == "" || manifest.SourceGeneration == 0 || manifest.CreatedAt.IsZero() || !isDigest(manifest.SchemaHash) || !isDigest(manifest.MerkleRoot) || !validSigningKeyID(manifest.SigningKeyID) || len(manifest.Signature) != 64 {
		return ErrInvalid
	}
	chunks := make(map[string]Chunk, len(manifest.Chunks))
	for _, chunk := range manifest.Chunks {
		if !validManifestChunk(chunk) {
			return ErrInvalid
		}
		if _, duplicate := chunks[chunk.Digest]; duplicate {
			return ErrInvalid
		}
		chunks[chunk.Digest] = chunk
	}
	secrets := make(map[string]uint64, len(manifest.Secrets))
	for _, secret := range manifest.Secrets {
		if !validSecretEnvelope(secret) {
			return ErrInvalid
		}
		if prior, duplicate := secrets[secret.SecretID]; duplicate && secret.Version <= prior {
			return ErrInvalid
		}
		secrets[secret.SecretID] = secret.Version
	}
	if !validateSites(manifest.Sites, chunks) || !validateDatabases(manifest.Databases, chunks) || !validateDNSZones(manifest.DNSZones) || !validateMailDomains(manifest.MailDomains, chunks) || !validateCertificates(manifest.Certificates, chunks) || !validateCredentials(manifest.Credentials) || !validateSchedules(manifest.Schedules) || !validateRepositories(manifest.Repositories) || !validateContainers(manifest.Containers, chunks) || !validateBackupPolicies(manifest.BackupPolicies) || !validConflicts(manifest.Conflicts) {
		return ErrInvalid
	}
	return nil
}

type ResourceDisposition string

const (
	DispositionCreate  ResourceDisposition = "create"
	DispositionMerge   ResourceDisposition = "merge"
	DispositionReplace ResourceDisposition = "replace"
	DispositionSkip    ResourceDisposition = "skip"
	DispositionBlock   ResourceDisposition = "block"
)

type Mapping struct {
	SourceKind string
	SourceID   ID
	TargetID   ID
	Disposition ResourceDisposition
	Reason     string
	Capacity   map[string]uint64
	Warnings   []string
}

type Plan struct {
	ID                ID
	MigrationID       ID
	ManifestRoot      string
	Mappings          []Mapping
	RequiredCapacity  map[string]uint64
	AvailableCapacity map[string]uint64
	Unsupported       []string
	Warnings          []string
	QuiesceMode       string
	CutoverMethod      string
	TTLLoweredAt      time.Time
	RollbackWindow    time.Duration
	DryRunDigest      string
	ApprovedAt        *time.Time
	ApprovalDigest    string
}

type Migration struct {
	ID                   ID
	Source               SourceKind
	Phase                Phase
	AttemptID            string
	ManifestRoot         string
	PlanDigest           string
	SourceGeneration     uint64
	TargetGeneration     uint64
	Fence                uint64
	LastCheckpoint       string
	TargetWriteWatermark string
	RollbackDeadline     time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
	ErrorCode            string
	ErrorMessage         string
}

type ResourceProgress struct {
	MigrationID       ID
	Kind              string
	SourceID          ID
	TargetID          ID
	Phase             Phase
	Checkpoint        string
	EffectID          string
	InputDigest       string
	OutputDigest      string
	BytesTransferred  uint64
	ObjectsTransferred uint64
	Attempt           uint32
	UpdatedAt         time.Time
	ErrorCode         string
}

func canonicalChunks(values []Chunk) []Chunk {
	out := append([]Chunk(nil), values...)
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out
}

func validSource(value SourceKind) bool {
	return value == SourceCyberPanel || value == SourceCyberPanelBackup || value == SourceCPanel || value == SourceCanonical
}

func validManifestChunk(value Chunk) bool {
	return isDigest(value.Digest) && value.MediaType != "" && len(value.MediaType) <= 255 && len(value.Compression) <= 64 && len(value.EncryptionDomain) <= 128
}

func validSecretEnvelope(value SecretEnvelope) bool {
	return value.SecretID != "" && len(value.SecretID) <= 128 && value.Purpose != "" && value.Version > 0 && isDigest(value.AudienceDigest) && value.Algorithm != "" && value.KeyID != "" && len(value.EncapsulatedKey) > 0 && len(value.EncapsulatedKey) <= 8192 && len(value.Ciphertext) > 0 && len(value.Ciphertext) <= 1<<20
}

func validateSites(values []Site, chunks map[string]Chunk) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !validHostname(value.PrimaryHostname) || value.PHPVersion == "" || value.RuntimeKind == "" || !validRelativePath(value.DocumentRootRelative) || !validChunkReferences(value.Content, chunks) || !validOptionalID(value.TargetID) || !validOptionalID(value.TenantID) || !validOptionalID(value.ProjectID) || !validHostnames(value.Aliases) || !validHostnames(value.Children) || !validConflicts(value.Conflicts) {
			return false
		}
	}
	return true
}

func validateDatabases(values []Database, chunks map[string]Chunk) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !value.SiteID.Valid() || value.Name == "" || len(value.Name) > 128 || !validChunkReferences(value.Dump, chunks) || !validOptionalID(value.TargetID) || !validConflicts(value.Conflicts) {
			return false
		}
		for _, principal := range value.Principals {
			if principal.Name == "" || len(principal.Name) > 128 || !validCredentialDisposition(principal.CredentialDisposition, principal.SecretID, "") || len(principal.GrantSets) == 0 {
				return false
			}
		}
	}
	return true
}

func validateDNSZones(values []DNSZone) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !validOptionalID(value.TargetID) || !validHostname(value.Name) || (value.Mode != "primary" && value.Mode != "secondary" && value.Mode != "native") || !validConflicts(value.Conflicts) {
			return false
		}
		sets := map[string]struct{}{}
		for _, set := range value.RecordSets {
			key := strings.ToLower(set.Name) + "\x00" + strings.ToUpper(set.Type)
			if !validDNSName(set.Name) || set.Type == "" || set.TTL == 0 || len(set.Values) == 0 {
				return false
			}
			if _, duplicate := sets[key]; duplicate {
				return false
			}
			sets[key] = struct{}{}
		}
	}
	return true
}

func validateMailDomains(values []MailDomain, chunks map[string]Chunk) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !validOptionalID(value.TargetID) || !value.SiteID.Valid() || !validHostname(value.Name) || !validChunkReferences(value.MailData, chunks) || !validConflicts(value.Conflicts) {
			return false
		}
		mailboxes := map[ID]struct{}{}
		for _, mailbox := range value.Mailboxes {
			if !uniqueID(mailbox.SourceID, mailboxes) || !validOptionalID(mailbox.TargetID) || !validEmail(mailbox.Address) || !validCredentialDisposition(mailbox.CredentialDisposition, mailbox.CredentialSecretID, "") || !validChunkReferences(mailbox.Data, chunks) {
				return false
			}
		}
	}
	return true
}

func validateCertificates(values []Certificate, chunks map[string]Chunk) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !validOptionalID(value.TargetID) || len(value.Names) == 0 || !validHostnames(value.Names) || !validChunkReferences(value.Certificate, chunks) || !validChunkReferences(value.Chain, chunks) || value.PrivateKeySecretID == "" || value.NotAfter.IsZero() {
			return false
		}
	}
	return true
}

func validateCredentials(values []AccessCredential) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !validOptionalID(value.TargetID) || !value.SiteID.Valid() || value.Kind == "" || value.Label == "" || !validRelativePath(value.RootRelative) || !validCredentialDisposition(value.CredentialDisposition, value.SecretID, value.PublicKey) {
			return false
		}
	}
	return true
}

func validCredentialDisposition(disposition CredentialDisposition, secretID, publicKey string) bool {
	switch disposition {
	case CredentialPreserved:
		return secretID != "" && publicKey == ""
	case CredentialResetRequired:
		return secretID == "" && publicKey == ""
	case CredentialPublicOnly:
		return secretID == "" && publicKey != ""
	default:
		return false
	}
}

func validateSchedules(values []Schedule) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !validOptionalID(value.TargetID) || !value.SiteID.Valid() || value.Kind == "" || value.Expression == "" || value.Timezone == "" || value.InvocationID == "" {
			return false
		}
	}
	return true
}

func validateRepositories(values []RepositoryBinding) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !validOptionalID(value.TargetID) || !value.SiteID.Valid() || value.Provider == "" || value.Origin == "" || value.Branch == "" {
			return false
		}
	}
	return true
}

func validateContainers(values []ContainerApplication, chunks map[string]Chunk) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !validOptionalID(value.TargetID) || !value.SiteID.Valid() || value.RecipeID == "" || value.RecipeVersion == "" || !validChunkReferences(value.Descriptor, chunks) || !validChunkReferences(value.VolumeData, chunks) || !validConflicts(value.Conflicts) {
			return false
		}
	}
	return true
}

func validateBackupPolicies(values []BackupPolicy) bool {
	seen := map[ID]struct{}{}
	for _, value := range values {
		if !uniqueID(value.SourceID, seen) || !validOptionalID(value.TargetID) || !value.SiteID.Valid() || value.Schedule == "" || value.Retention == "" || value.Provider == "" || value.Repository == "" {
			return false
		}
	}
	return true
}

func validChunkReferences(values []Chunk, catalog map[string]Chunk) bool {
	for _, value := range values {
		canonical, present := catalog[value.Digest]
		if !present || canonical != value {
			return false
		}
	}
	return true
}

func validOptionalID(value ID) bool { return value == "" || value.Valid() }

func uniqueID(value ID, seen map[ID]struct{}) bool {
	if !value.Valid() {
		return false
	}
	if _, duplicate := seen[value]; duplicate {
		return false
	}
	seen[value] = struct{}{}
	return true
}

func validRelativePath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validHostnames(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		canonical := strings.ToLower(strings.TrimSuffix(value, "."))
		if !validHostname(canonical) {
			return false
		}
		if _, duplicate := seen[canonical]; duplicate {
			return false
		}
		seen[canonical] = struct{}{}
	}
	return true
}

func validHostname(value string) bool {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 || netip.ParseAddr(value).IsValid() {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validDNSName(value string) bool {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "@" || value == "*" {
		return true
	}
	if len(value) == 0 || len(value) > 253 || netip.ParseAddr(value).IsValid() {
		return false
	}
	labels := strings.Split(value, ".")
	for index, label := range labels {
		if label == "*" && index == 0 {
			continue
		}
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

func validEmail(value string) bool {
	parts := strings.Split(value, "@")
	return len(parts) == 2 && parts[0] != "" && len(parts[0]) <= 64 && validHostname(parts[1])
}

func validConflicts(values []Conflict) bool {
	for _, value := range values {
		if value.Field == "" || len(value.Values) < 2 || (value.Blocking && value.Resolution != "") {
			return false
		}
		for _, candidate := range value.Values {
			if candidate.Provenance.SourceKind == "" || candidate.Provenance.SourceLocation == "" || candidate.Provenance.ObservedAt.IsZero() || candidate.Provenance.Digest == "" {
				return false
			}
		}
	}
	return true
}
