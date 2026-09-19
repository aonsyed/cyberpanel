package cyberpanel

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

var (
	ErrInvalid = errors.New("cyberpanel extractor: invalid value")
	ErrDenied = errors.New("cyberpanel extractor: source plan not locally approved")
	ErrChanged = errors.New("cyberpanel extractor: source changed while collecting")
	containerVolumeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

var opaqueIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:@-]{2,191}$`)

const CanonicalManifestSchemaDescriptor="cyberpanel-migration-manifest/v1:sites,databases,dns-zones,mail-domains,certificates,credentials,credential-dispositions,schedules,repositories,containers,backup-policies,secrets,chunks,provenance,conflicts"

func CanonicalManifestSchemaHash()string{return digestText(CanonicalManifestSchemaDescriptor)}

type ArtifactID string
type SecretRef string

func (id ArtifactID) Valid() bool {
	value := string(id)
	return opaqueIDPattern.MatchString(value) && !strings.Contains(value, "..") && !strings.ContainsAny(value, `/\\`)
}

func (id SecretRef) Valid() bool {
	value := string(id)
	return opaqueIDPattern.MatchString(value) && !strings.Contains(value, "..") && !strings.ContainsAny(value, `/\\`)
}

type ResourceSelection struct {
	Sites bool `json:"sites"`
	Databases bool `json:"databases"`
	DNS bool `json:"dns"`
	Mail bool `json:"mail"`
	Certificates bool `json:"certificates"`
	Credentials bool `json:"credentials"`
	Schedules bool `json:"schedules"`
	Repositories bool `json:"repositories"`
	Containers bool `json:"containers"`
	BackupPolicies bool `json:"backup_policies"`
}

func (s ResourceSelection) any() bool {
	return s.Sites || s.Databases || s.DNS || s.Mail || s.Certificates || s.Credentials || s.Schedules || s.Repositories || s.Containers || s.BackupPolicies
}

type SourcePlan struct {
	MigrationID migration.ID `json:"migration_id"`
	SourceInstallationID string `json:"source_installation_id"`
	TargetInstallationID string `json:"target_installation_id"`
	SchemaHash string `json:"schema_hash"`
	SiteSourceIDs []string `json:"site_source_ids"`
	Selection ResourceSelection `json:"selection"`
	TargetPlanDigest string `json:"target_plan_digest,omitempty"`
	QuiesceMode string `json:"quiesce_mode"`
	NotBefore time.Time `json:"not_before"`
	ExpiresAt time.Time `json:"expires_at"`
	Nonce string `json:"nonce"`
}

type ApprovedPlan struct {
	Plan SourcePlan `json:"plan"`
	ApprovedAt time.Time `json:"approved_at"`
	ApproverKeyID string `json:"approver_key_id"`
	Signature []byte `json:"signature"`
}

type PlanStore interface {
	ApprovedPlan(context.Context, migration.ID) (ApprovedPlan, error)
}

type PlanVerifier interface {
	VerifyApprovedPlan(context.Context, ApprovedPlan, time.Time) error
}

type CollectRequest struct {
	MigrationID migration.ID
	SiteSourceIDs []string
	Selection ResourceSelection
}

type Collector interface {
	Collect(context.Context, CollectRequest) (Snapshot, error)
}

type ArtifactCatalog interface {
	Describe(context.Context, ArtifactID) (migration.Chunk, error)
	Open(context.Context, ArtifactID) (io.ReadCloser, error)
}

type SecretSource interface {
	ReadSecret(context.Context, SecretRef) ([]byte, error)
}

type SecretMaterial struct {
	Ref SecretRef
	Purpose string
	AudienceDigest string
}

type SecretSealer interface {
	Seal(context.Context, migration.ID, SecretMaterial, []byte) (migration.SecretEnvelope, error)
}

type Snapshot struct {
	InstallationID string
	Revision string
	ObservedAt time.Time
	Sites []SiteRecord
	Databases []DatabaseRecord
	DNSZones []DNSZoneRecord
	MailDomains []MailDomainRecord
	Certificates []CertificateRecord
	Credentials []CredentialRecord
	Schedules []ScheduleRecord
	Repositories []RepositoryRecord
	Containers []ContainerRecord
	BackupPolicies []BackupPolicyRecord
}

type SiteRecord struct {
	SourceID string
	ParentSourceID string
	OwnerSourceID string
	PackageSourceID string
	PrimaryHostname string
	Aliases []string
	Redirects []string
	ChildHostnames []string
	PHPVersion string
	DocumentRootRelative string
	RuntimeKind string
	RuntimeUser string
	Enabled bool
	DiskBytes uint64
	TransferBytes uint64
	MemoryBytes uint64
	CPUMilli uint64
	IOBytesPerSecond uint64
	MaxConnections uint64
	ContentArtifact ArtifactID
}

type DatabaseRecord struct {
	SourceID string
	SiteSourceID string
	Name string
	Charset string
	Collation string
	DumpArtifact ArtifactID
	Principals []DatabasePrincipalRecord
}

type DatabasePrincipalRecord struct {
	Name string
	GrantSets []string
	Password SecretRef
}

type DNSZoneRecord struct {
	SourceID string
	Name string
	Mode string
	DNSSEC bool
	RecordSets []DNSRecordSet
}

type DNSRecordSet struct {
	Name string
	Type string
	TTL uint32
	Values []string
}

type MailDomainRecord struct {
	SourceID string
	SiteSourceID string
	Name string
	Mailboxes []MailboxRecord
	Aliases []string
	Forwarders []string
	CatchAll []string
	DKIMPrivateKey SecretRef
}

type MailboxRecord struct {
	SourceID string
	Address string
	Format string
	QuotaBytes uint64
	Password SecretRef
	DataArtifact ArtifactID
}

type CertificateRecord struct {
	SourceID string
	Names []string
	CertificateArtifact ArtifactID
	ChainArtifact ArtifactID
	PrivateKey SecretRef
	Issuer string
	NotAfter time.Time
}

type CredentialRecord struct {
	SourceID string
	SiteSourceID string
	Kind string
	Label string
	RootRelative string
	PublicKey string
	Secret SecretRef
}

type ScheduleRecord struct {
	SourceID string
	SiteSourceID string
	Kind string
	Expression string
	Timezone string
	InvocationID string
	Enabled bool
}

type RepositoryRecord struct {
	SourceID string
	SiteSourceID string
	Provider string
	Origin string
	Branch string
	Credential SecretRef
	AutoDeploy bool
}

type ContainerRecord struct {
	SourceID string
	SiteSourceID string
	RecipeID string
	RecipeVersion string
	DescriptorArtifact ArtifactID
	VolumeArtifacts []ArtifactID
	Volumes []ContainerVolumeRecord
	SecretBindings []ContainerSecretRecord
	Secrets []SecretRef
}
type ContainerVolumeRecord struct {SourceName,RecipeVolume string; Artifact ArtifactID}
type ContainerSecretRecord struct {Slot string;Secret SecretRef}

type BackupPolicyRecord struct {
	SourceID string
	SiteSourceID string
	Schedule string
	Retention string
	Provider string
	Repository string
	Credential SecretRef
}

func (p SourcePlan) validate(now time.Time) error {
	if !p.MigrationID.Valid() || strings.TrimSpace(p.SourceInstallationID) == "" || strings.TrimSpace(p.TargetInstallationID) == "" || p.SchemaHash!=CanonicalManifestSchemaHash() || !p.Selection.any() || p.NotBefore.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.NotBefore) || strings.TrimSpace(p.Nonce) == "" {
		return ErrInvalid
	}
	if now.Before(p.NotBefore) || !now.Before(p.ExpiresAt) {
		return ErrDenied
	}
	if p.QuiesceMode != "write_fence" && p.QuiesceMode != "service_fence" {
		return ErrInvalid
	}
	if p.TargetPlanDigest!=""&&!isDigest(p.TargetPlanDigest){return ErrInvalid}
	if len(p.Nonce)<16||len(p.Nonce)>256{return ErrInvalid}
	seen := make(map[string]struct{}, len(p.SiteSourceIDs))
	for _, id := range p.SiteSourceIDs {
		if !validSourceID(id) {
			return ErrInvalid
		}
		if _, exists := seen[id]; exists {
			return ErrInvalid
		}
		seen[id] = struct{}{}
	}
	return nil
}

func (s Snapshot) validate(plan SourcePlan) error {
	if strings.TrimSpace(s.InstallationID) == "" || s.InstallationID != plan.SourceInstallationID || strings.TrimSpace(s.Revision) == "" || s.ObservedAt.IsZero() {
		return ErrInvalid
	}
	allowed := make(map[string]struct{}, len(plan.SiteSourceIDs))
	for _, id := range plan.SiteSourceIDs {
		allowed[id] = struct{}{}
	}
	seenSites := make(map[string]struct{}, len(s.Sites))
	for _, site := range s.Sites {
		if !validSourceID(site.SourceID) || !validHostname(site.PrimaryHostname) || strings.TrimSpace(site.PHPVersion) == "" || strings.HasPrefix(site.DocumentRootRelative, "/") || strings.Contains(site.DocumentRootRelative, "..") {
			return ErrInvalid
		}
		if len(allowed) != 0 {
			if _, included := allowed[site.SourceID]; !included {
				if _, parentIncluded := allowed[site.ParentSourceID]; !parentIncluded {
					return ErrDenied
				}
			}
		}
		if _, exists := seenSites[site.SourceID]; exists {
			return ErrInvalid
		}
		seenSites[site.SourceID] = struct{}{}
		if site.ContentArtifact != "" && !site.ContentArtifact.Valid() {
			return ErrInvalid
		}
	}
	for _, database := range s.Databases {
		if !validSourceID(database.SourceID) || !validSourceID(database.SiteSourceID) || database.Name == "" || (database.DumpArtifact != "" && !database.DumpArtifact.Valid()) {
			return ErrInvalid
		}
		for _, principal := range database.Principals {
			if principal.Name == "" || (principal.Password != "" && !principal.Password.Valid()) {
				return ErrInvalid
			}
		}
	}
	for _, zone := range s.DNSZones {
		if !validSourceID(zone.SourceID) || !validHostname(zone.Name) {
			return ErrInvalid
		}
	}
	for _, domain := range s.MailDomains {
		if !validSourceID(domain.SourceID) || !validHostname(domain.Name) || (domain.DKIMPrivateKey != "" && !domain.DKIMPrivateKey.Valid()) {
			return ErrInvalid
		}
		for _, mailbox := range domain.Mailboxes {
			if !validSourceID(mailbox.SourceID) || !strings.Contains(mailbox.Address, "@") || (mailbox.Format!="maildir"&&mailbox.Format!="mdbox") || (mailbox.Password != "" && !mailbox.Password.Valid()) || (mailbox.DataArtifact != "" && !mailbox.DataArtifact.Valid()) {
				return ErrInvalid
			}
		}
	}
	seen:=map[string]struct{}{}
	for _,certificate:=range s.Certificates{if !validSourceID(certificate.SourceID)||len(certificate.Names)==0||certificate.NotAfter.IsZero()||(certificate.CertificateArtifact!=""&&!certificate.CertificateArtifact.Valid())||(certificate.ChainArtifact!=""&&!certificate.ChainArtifact.Valid())||(certificate.PrivateKey!=""&&!certificate.PrivateKey.Valid()){return ErrInvalid};for _,name:=range certificate.Names{if !validHostname(name){return ErrInvalid}};if _,duplicate:=seen["certificate:"+certificate.SourceID];duplicate{return ErrInvalid};seen["certificate:"+certificate.SourceID]=struct{}{}}
	for _,credential:=range s.Credentials{if !validSourceID(credential.SourceID)||!validSourceID(credential.SiteSourceID)||credential.Kind==""||credential.Label==""||filepathUnsafe(credential.RootRelative)||(credential.Secret!=""&&!credential.Secret.Valid())||(credential.Secret!=""&&strings.TrimSpace(credential.PublicKey)!=""){return ErrInvalid};if _,duplicate:=seen["credential:"+credential.SourceID];duplicate{return ErrInvalid};seen["credential:"+credential.SourceID]=struct{}{}}
	for _,schedule:=range s.Schedules{if !validSourceID(schedule.SourceID)||!validSourceID(schedule.SiteSourceID)||schedule.Kind==""||schedule.Expression==""||schedule.InvocationID==""||strings.ContainsAny(schedule.Expression,"\r\n"){return ErrInvalid};if _,duplicate:=seen["schedule:"+schedule.SourceID];duplicate{return ErrInvalid};seen["schedule:"+schedule.SourceID]=struct{}{}}
	for _,repository:=range s.Repositories{if !validSourceID(repository.SourceID)||!validSourceID(repository.SiteSourceID)||repository.Provider==""||repository.Origin==""||strings.ContainsAny(repository.Origin,"\r\n\x00")||(repository.Credential!=""&&!repository.Credential.Valid()){return ErrInvalid};if _,duplicate:=seen["repository:"+repository.SourceID];duplicate{return ErrInvalid};seen["repository:"+repository.SourceID]=struct{}{}}
	for _,container:=range s.Containers{if !validSourceID(container.SourceID)||!validSourceID(container.SiteSourceID)||!migration.ID(container.RecipeID).Valid()||container.RecipeVersion==""||container.DescriptorArtifact!=""||len(container.VolumeArtifacts)!=0||len(container.Volumes)!=1||len(container.Secrets)!=0||len(container.SecretBindings)!=0{return ErrInvalid};volume:=container.Volumes[0];if !containerVolumeNamePattern.MatchString(volume.SourceName)||!containerVolumeNamePattern.MatchString(volume.RecipeVolume)||!volume.Artifact.Valid(){return ErrInvalid};if _,duplicate:=seen["container:"+container.SourceID];duplicate{return ErrInvalid};seen["container:"+container.SourceID]=struct{}{}}
	for _,policy:=range s.BackupPolicies{if !validSourceID(policy.SourceID)||!validSourceID(policy.SiteSourceID)||policy.Schedule==""||policy.Provider==""||(policy.Credential!=""&&!policy.Credential.Valid()){return ErrInvalid};if _,duplicate:=seen["backup:"+policy.SourceID];duplicate{return ErrInvalid};seen["backup:"+policy.SourceID]=struct{}{}}
	return nil
}

func (s Snapshot) artifactIDs(plan SourcePlan) []ArtifactID {
	set := map[ArtifactID]struct{}{}
	add := func(id ArtifactID) {
		if id != "" {
			set[id] = struct{}{}
		}
	}
	if plan.Selection.Sites {
		for _, value := range s.Sites { add(value.ContentArtifact) }
	}
	if plan.Selection.Databases {
		for _, value := range s.Databases { add(value.DumpArtifact) }
	}
	if plan.Selection.Mail {
		for _, domain := range s.MailDomains {
			for _, mailbox := range domain.Mailboxes { add(mailbox.DataArtifact) }
		}
	}
	if plan.Selection.Certificates {
		for _, value := range s.Certificates { add(value.CertificateArtifact); add(value.ChainArtifact) }
	}
	if plan.Selection.Containers {
		for _, value := range s.Containers {
			add(value.DescriptorArtifact)
			for _, artifact := range value.VolumeArtifacts { add(artifact) }
			for _, volume := range value.Volumes { add(volume.Artifact) }
		}
	}
	out := make([]ArtifactID, 0, len(set))
	for id := range set { out = append(out, id) }
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s Snapshot) secrets(plan SourcePlan) []SecretMaterial {
	values := map[SecretRef]SecretMaterial{}
	add := func(ref SecretRef, purpose string) {
		if ref != "" { values[ref] = SecretMaterial{Ref: ref, Purpose: purpose} }
	}
	if plan.Selection.Databases {
		for _, database := range s.Databases {
			for _, principal := range database.Principals { add(principal.Password, "database-principal") }
		}
	}
	if plan.Selection.Mail {
		for _, domain := range s.MailDomains {
			add(domain.DKIMPrivateKey, "mail-dkim-private-key")
			for _, mailbox := range domain.Mailboxes { add(mailbox.Password, "mailbox-credential") }
		}
	}
	if plan.Selection.Certificates {
		for _, certificate := range s.Certificates { add(certificate.PrivateKey, "tls-private-key") }
	}
	if plan.Selection.Credentials {
		for _, credential := range s.Credentials { add(credential.Secret, "access-credential") }
	}
	if plan.Selection.Repositories {
		for _, repository := range s.Repositories { add(repository.Credential, "repository-credential") }
	}
	if plan.Selection.Containers {
		for _, container := range s.Containers {
			for _, secret := range container.Secrets { add(secret, "container-secret") }
			for _, binding := range container.SecretBindings { add(binding.Secret, "container-secret") }
		}
	}
	if plan.Selection.BackupPolicies {
		for _, policy := range s.BackupPolicies { add(policy.Credential, "backup-repository-credential") }
	}
	out := make([]SecretMaterial, 0, len(values))
	for _, value := range values { out = append(out, value) }
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

func validSourceID(value string) bool {
	return opaqueIDPattern.MatchString(value) && !strings.Contains(value, "..") && !strings.ContainsAny(value, `/\\`)
}

func validHostname(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if len(value) < 1 || len(value) > 253 || netip.ParseAddr(value).IsValid() || strings.ContainsAny(value, `/\\:@`) {
		return false
	}
	labels:=strings.Split(value,".")
	if len(labels)<2{return false}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
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

func filepathUnsafe(value string)bool{if value==""||value=="."||strings.HasPrefix(value,"/")||strings.Contains(value,"\\")||strings.ContainsRune(value,'\x00'){return true};for _,part:=range strings.Split(value,"/"){if part==".."||part==""||part=="."{return true}};return false}
