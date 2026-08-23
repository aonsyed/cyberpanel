package mail

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SpamMaximumPolicies          = 4096
	SpamMaximumIdentities        = 512
	SpamMaximumListLimit         = 200
	SpamMaximumQuarantineBytes   = 64 << 20
	SpamMaximumRetentionDays     = 365
	SpamMaximumFeedbackPerHour   = 1000
	SpamMaximumStatisticsDays    = 3650
	spamMinimumScore       int32 = -20000
	spamMaximumScore       int32 = 50000
)

type SpamScopeKind string

const (
	SpamScopeGlobal  SpamScopeKind = "global"
	SpamScopeDomain  SpamScopeKind = "domain"
	SpamScopeMailbox SpamScopeKind = "mailbox"
)

type SpamScope struct {
	TenantID  string        `json:"tenant_id"`
	Kind      SpamScopeKind `json:"kind"`
	DomainID  DomainID      `json:"domain_id,omitempty"`
	MailboxID MailboxID     `json:"mailbox_id,omitempty"`
}

func (scope SpamScope) Validate() error {
	if !validOpaque(scope.TenantID) {
		return ErrInvalidCommand
	}
	switch scope.Kind {
	case SpamScopeGlobal:
		if scope.DomainID != "" || scope.MailboxID != "" {
			return ErrInvalidCommand
		}
	case SpamScopeDomain:
		if !validOpaque(string(scope.DomainID)) || scope.MailboxID != "" {
			return ErrInvalidCommand
		}
	case SpamScopeMailbox:
		if !validOpaque(string(scope.DomainID)) || !validOpaque(string(scope.MailboxID)) {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func (scope SpamScope) key() string {
	return scope.TenantID + "\x00" + string(scope.Kind) + "\x00" + string(scope.DomainID) + "\x00" + string(scope.MailboxID)
}

type SpamAction string

const (
	SpamActionTag        SpamAction = "tag"
	SpamActionJunk       SpamAction = "junk_folder"
	SpamActionQuarantine SpamAction = "quarantine"
	SpamActionReject     SpamAction = "reject"
)

type SpamThresholds struct {
	TagMilli        int32 `json:"tag_milli"`
	JunkMilli       int32 `json:"junk_milli"`
	QuarantineMilli int32 `json:"quarantine_milli"`
	RejectMilli     int32 `json:"reject_milli"`
}

func (thresholds SpamThresholds) Validate() error {
	values := []int32{thresholds.TagMilli, thresholds.JunkMilli, thresholds.QuarantineMilli, thresholds.RejectMilli}
	for index, value := range values {
		if value < spamMinimumScore || value > spamMaximumScore || index > 0 && value <= values[index-1] {
			return ErrInvalidCommand
		}
	}
	return nil
}

func (thresholds SpamThresholds) noLooserThan(parent SpamThresholds) bool {
	return thresholds.TagMilli <= parent.TagMilli && thresholds.JunkMilli <= parent.JunkMilli && thresholds.QuarantineMilli <= parent.QuarantineMilli && thresholds.RejectMilli <= parent.RejectMilli
}

type SpamIdentityKind string

const (
	SpamIdentityAddress SpamIdentityKind = "address"
	SpamIdentityDomain  SpamIdentityKind = "domain"
	SpamIdentityCIDR    SpamIdentityKind = "cidr"
)

type SpamIdentity struct {
	Kind  SpamIdentityKind `json:"kind"`
	Value string           `json:"value"`
}

func NormalizeSpamIdentity(identity SpamIdentity) (SpamIdentity, error) {
	identity.Value = strings.TrimSpace(strings.ToLower(identity.Value))
	switch identity.Kind {
	case SpamIdentityAddress:
		address := Address(identity.Value)
		if ValidateAddress(address) != nil || string(address) != identity.Value {
			return SpamIdentity{}, ErrInvalidCommand
		}
	case SpamIdentityDomain:
		if identity.Value == "" || identity.Value != canonicalRoutingDomain(identity.Value) {
			return SpamIdentity{}, ErrInvalidCommand
		}
	case SpamIdentityCIDR:
		prefix, err := netip.ParsePrefix(identity.Value)
		if err != nil || prefix.String() != identity.Value || prefix != prefix.Masked() {
			return SpamIdentity{}, ErrInvalidCommand
		}
	default:
		return SpamIdentity{}, ErrInvalidCommand
	}
	return identity, nil
}

func (identity SpamIdentity) key() string { return string(identity.Kind) + ":" + identity.Value }

type SpamSecurityControl uint32

const (
	SpamControlMalware       SpamSecurityControl = 1 << iota
	SpamControlPhishing
	SpamControlAuthentication
	SpamControlDangerousAttachment
	SpamControlMandatory = SpamControlMalware | SpamControlPhishing | SpamControlAuthentication | SpamControlDangerousAttachment
)

type SpamLearningPolicy struct {
	BayesEnabled       bool   `json:"bayes_enabled"`
	AutolearnEnabled   bool   `json:"autolearn_enabled"`
	HamBelowMilli      int32  `json:"ham_below_milli"`
	SpamAboveMilli     int32  `json:"spam_above_milli"`
	MaxFeedbackPerHour uint16 `json:"max_feedback_per_hour"`
	StatisticsDays     uint16 `json:"statistics_days"`
}

func (policy SpamLearningPolicy) Validate() error {
	if policy.HamBelowMilli < spamMinimumScore || policy.SpamAboveMilli > spamMaximumScore || policy.HamBelowMilli >= policy.SpamAboveMilli || policy.MaxFeedbackPerHour == 0 || policy.MaxFeedbackPerHour > SpamMaximumFeedbackPerHour || policy.StatisticsDays == 0 || policy.StatisticsDays > SpamMaximumStatisticsDays || policy.AutolearnEnabled && !policy.BayesEnabled {
		return ErrInvalidCommand
	}
	return nil
}

type SpamPolicy struct {
	Scope            SpamScope            `json:"scope"`
	DomainName       string               `json:"domain_name,omitempty"`
	MailboxAddress   Address              `json:"mailbox_address,omitempty"`
	Revision         uint64               `json:"revision"`
	Generation       uint64               `json:"generation"`
	ParentRevision   uint64               `json:"parent_revision"`
	ParentDigest     string               `json:"parent_digest,omitempty"`
	Thresholds       SpamThresholds       `json:"thresholds"`
	Allow            []SpamIdentity       `json:"allow"`
	Deny             []SpamIdentity       `json:"deny"`
	SecurityControls SpamSecurityControl  `json:"security_controls"`
	Learning         SpamLearningPolicy   `json:"learning"`
	RetentionDays    uint16               `json:"retention_days"`
	EffectiveAt      time.Time            `json:"effective_at"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
}

func NormalizeSpamPolicy(policy SpamPolicy) (SpamPolicy, error) {
	if policy.Scope.Validate() != nil || policy.Revision == 0 || policy.Generation == 0 || policy.Thresholds.Validate() != nil || policy.Learning.Validate() != nil || policy.RetentionDays == 0 || policy.RetentionDays > SpamMaximumRetentionDays || policy.SecurityControls&SpamControlMandatory != SpamControlMandatory || policy.SecurityControls&^SpamControlMandatory != 0 || !canonicalSpamTime(policy.EffectiveAt) || !canonicalSpamTime(policy.CreatedAt) || !canonicalSpamTime(policy.UpdatedAt) || policy.UpdatedAt.Before(policy.CreatedAt) {
		return SpamPolicy{}, ErrInvalidCommand
	}
	if policy.Scope.Kind == SpamScopeGlobal {
		if policy.ParentRevision != 0 || policy.ParentDigest != "" || policy.DomainName != "" || policy.MailboxAddress != "" {
			return SpamPolicy{}, ErrInvalidCommand
		}
	} else if policy.ParentRevision == 0 || !validSpamDigest(policy.ParentDigest) {
		return SpamPolicy{}, ErrInvalidCommand
	}
	if policy.Scope.Kind != SpamScopeGlobal && (policy.DomainName == "" || policy.DomainName != canonicalRoutingDomain(policy.DomainName)) {
		return SpamPolicy{}, ErrInvalidCommand
	}
	if policy.Scope.Kind == SpamScopeDomain && policy.MailboxAddress != "" {
		return SpamPolicy{}, ErrInvalidCommand
	}
	if policy.Scope.Kind == SpamScopeMailbox {
		if ValidateAddress(policy.MailboxAddress) != nil || string(policy.MailboxAddress) != strings.ToLower(strings.TrimSpace(string(policy.MailboxAddress))) || !strings.HasSuffix(string(policy.MailboxAddress), "@"+policy.DomainName) {
			return SpamPolicy{}, ErrInvalidCommand
		}
	}
	allow, err := normalizeSpamIdentities(policy.Allow)
	if err != nil {
		return SpamPolicy{}, err
	}
	deny, err := normalizeSpamIdentities(policy.Deny)
	if err != nil {
		return SpamPolicy{}, err
	}
	denied := make(map[string]struct{}, len(deny))
	for _, identity := range deny {
		denied[identity.key()] = struct{}{}
	}
	for _, identity := range allow {
		if _, exists := denied[identity.key()]; exists {
			return SpamPolicy{}, ErrInvalidCommand
		}
	}
	policy.Allow = allow
	policy.Deny = deny
	return policy, nil
}

func ValidateSpamChild(parent, child SpamPolicy) error {
	var err error
	parent, err = NormalizeSpamPolicy(parent)
	if err != nil {
		return err
	}
	child, err = NormalizeSpamPolicy(child)
	if err != nil {
		return err
	}
	if parent.Scope.TenantID != child.Scope.TenantID || child.Scope.Kind == SpamScopeGlobal || child.ParentRevision != parent.Revision || parent.Scope.Kind == SpamScopeDomain && parent.DomainName != child.DomainName {
		return ErrConflict
	}
	digest, err := SpamPolicyDigest(parent)
	if err != nil || child.ParentDigest != digest {
		return ErrConflict
	}
	if child.Scope.Kind == SpamScopeDomain && parent.Scope.Kind != SpamScopeGlobal || child.Scope.Kind == SpamScopeMailbox && (parent.Scope.Kind != SpamScopeDomain || parent.Scope.DomainID != child.Scope.DomainID) {
		return ErrConflict
	}
	if !child.Thresholds.noLooserThan(parent.Thresholds) || child.SecurityControls&parent.SecurityControls != parent.SecurityControls || child.RetentionDays > parent.RetentionDays || child.Learning.BayesEnabled && !parent.Learning.BayesEnabled || child.Learning.AutolearnEnabled && !parent.Learning.AutolearnEnabled || child.Learning.HamBelowMilli > parent.Learning.HamBelowMilli || child.Learning.SpamAboveMilli < parent.Learning.SpamAboveMilli || child.Learning.MaxFeedbackPerHour > parent.Learning.MaxFeedbackPerHour || child.Learning.StatisticsDays > parent.Learning.StatisticsDays || !spamIdentitySubset(child.Allow, parent.Allow) || !spamIdentitySubset(parent.Deny, child.Deny) {
		return ErrConflict
	}
	return nil
}

func SpamPolicyDigest(policy SpamPolicy) (string, error) {
	normalized, err := NormalizeSpamPolicy(policy)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

type SpamPolicySnapshot struct {
	TenantID   string       `json:"tenant_id"`
	Generation uint64       `json:"generation"`
	Policies   []SpamPolicy `json:"policies"`
	CreatedAt  time.Time    `json:"created_at"`
}

func NormalizeSpamSnapshot(snapshot SpamPolicySnapshot) (SpamPolicySnapshot, error) {
	if !validOpaque(snapshot.TenantID) || snapshot.Generation == 0 || len(snapshot.Policies) == 0 || len(snapshot.Policies) > SpamMaximumPolicies || !canonicalSpamTime(snapshot.CreatedAt) {
		return SpamPolicySnapshot{}, ErrInvalidCommand
	}
	result := snapshot
	result.Policies = append([]SpamPolicy(nil), snapshot.Policies...)
	sort.Slice(result.Policies, func(i, j int) bool { return result.Policies[i].Scope.key() < result.Policies[j].Scope.key() })
	byScope := make(map[string]SpamPolicy, len(result.Policies))
	for index := range result.Policies {
		policy, err := NormalizeSpamPolicy(result.Policies[index])
		if err != nil || policy.Scope.TenantID != snapshot.TenantID || policy.Generation > snapshot.Generation {
			return SpamPolicySnapshot{}, ErrInvalidCommand
		}
		if _, exists := byScope[policy.Scope.key()]; exists {
			return SpamPolicySnapshot{}, ErrConflict
		}
		result.Policies[index] = policy
		byScope[policy.Scope.key()] = policy
	}
	global, exists := byScope[SpamScope{TenantID: snapshot.TenantID, Kind: SpamScopeGlobal}.key()]
	if !exists {
		return SpamPolicySnapshot{}, ErrConflict
	}
	for _, policy := range result.Policies {
		if policy.Scope.Kind == SpamScopeGlobal {
			continue
		}
		parent := global
		if policy.Scope.Kind == SpamScopeMailbox {
			if domain, found := byScope[SpamScope{TenantID: snapshot.TenantID, Kind: SpamScopeDomain, DomainID: policy.Scope.DomainID}.key()]; found {
				parent = domain
			}
		}
		if ValidateSpamChild(parent, policy) != nil {
			return SpamPolicySnapshot{}, ErrConflict
		}
	}
	return result, nil
}

type SpamConfigArtifact struct {
	Path    string `json:"path"`
	Mode    uint32 `json:"mode"`
	Content []byte `json:"-"`
	SHA256  string `json:"sha256"`
}

type SpamConfigGeneration struct {
	ID             string               `json:"id"`
	TenantID       string               `json:"tenant_id"`
	PolicyGeneration uint64             `json:"policy_generation"`
	SnapshotDigest string               `json:"snapshot_digest"`
	ArtifactDigest string               `json:"artifact_digest"`
	Artifacts      []SpamConfigArtifact `json:"-"`
	CreatedAt      time.Time            `json:"created_at"`
}

func CompileSpamGeneration(snapshot SpamPolicySnapshot) (SpamConfigGeneration, error) {
	normalized, err := NormalizeSpamSnapshot(snapshot)
	if err != nil {
		return SpamConfigGeneration{}, err
	}
	rawSnapshot, err := json.Marshal(normalized)
	if err != nil {
		return SpamConfigGeneration{}, err
	}
	snapshotSum := sha256.Sum256(rawSnapshot)
	snapshotDigest := hex.EncodeToString(snapshotSum[:])
	var settings, allow, deny strings.Builder
	settings.WriteString("settings {\n")
	for index, policy := range normalized.Policies {
		name := fmt.Sprintf("cp_%06d_%s", index, spamScopeToken(policy.Scope))
		settings.WriteString("  \"")
		settings.WriteString(name)
		settings.WriteString("\" {\n")
		if policy.Scope.Kind == SpamScopeDomain {
			settings.WriteString("    rcpt = \"@")
			settings.WriteString(policy.DomainName)
			settings.WriteString("\";\n")
		} else if policy.Scope.Kind == SpamScopeMailbox {
			settings.WriteString("    rcpt = \"")
			settings.WriteString(string(policy.MailboxAddress))
			settings.WriteString("\";\n")
		}
		settings.WriteString("    actions { add_header = ")
		settings.WriteString(spamScore(policy.Thresholds.TagMilli))
		settings.WriteString("; rewrite_subject = ")
		settings.WriteString(spamScore(policy.Thresholds.JunkMilli))
		settings.WriteString("; quarantine = ")
		settings.WriteString(spamScore(policy.Thresholds.QuarantineMilli))
		settings.WriteString("; greylist = null; reject = ")
		settings.WriteString(spamScore(policy.Thresholds.RejectMilli))
		settings.WriteString("; }\n")
		settings.WriteString("  }\n")
		for _, identity := range policy.Allow {
			allow.WriteString(spamMapLine(policy.Scope, identity))
		}
		for _, identity := range policy.Deny {
			deny.WriteString(spamMapLine(policy.Scope, identity))
		}
	}
	settings.WriteString("}\n")
	global := normalized.Policies[0]
	for _, policy := range normalized.Policies {
		if policy.Scope.Kind == SpamScopeGlobal {
			global = policy
			break
		}
	}
	actions := "actions {\n  add_header = " + spamScore(global.Thresholds.TagMilli) + ";\n  rewrite_subject = " + spamScore(global.Thresholds.JunkMilli) + ";\n  quarantine = " + spamScore(global.Thresholds.QuarantineMilli) + ";\n  greylist = null;\n  reject = " + spamScore(global.Thresholds.RejectMilli) + ";\n}\n"
	bayes := "classifier \"bayes\" {\n  enabled = " + strconv.FormatBool(global.Learning.BayesEnabled) + ";\n  backend = \"redis\";\n  autolearn = " + strconv.FormatBool(global.Learning.AutolearnEnabled) + ";\n  min_tokens = 11;\n}\n"
	security := "antivirus {\n  clamav { symbol = \"MALWARE\"; action = \"reject\"; }\n}\nphishing { enabled = true; }\n"
	main := ".include \"actions.conf\"\n.include \"settings.conf\"\n.include \"classifier-bayes.conf\"\n.include \"security.conf\"\n"
	artifacts := []SpamConfigArtifact{
		spamConfigArtifact("actions.conf", actions),
		spamConfigArtifact("allow.map", allow.String()),
		spamConfigArtifact("classifier-bayes.conf", bayes),
		spamConfigArtifact("deny.map", deny.String()),
		spamConfigArtifact("policy-snapshot.json", string(rawSnapshot)),
		spamConfigArtifact("rspamd.conf", main),
		spamConfigArtifact("security.conf", security),
		spamConfigArtifact("settings.conf", settings.String()),
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	artifactHasher := sha256.New()
	for _, artifact := range artifacts {
		fmt.Fprintf(artifactHasher, "%s\x00%o\x00%s\x00", artifact.Path, artifact.Mode, artifact.SHA256)
	}
	artifactDigest := hex.EncodeToString(artifactHasher.Sum(nil))
	return SpamConfigGeneration{ID: fmt.Sprintf("spamg_%020d_%s", normalized.Generation, artifactDigest[:16]), TenantID: normalized.TenantID, PolicyGeneration: normalized.Generation, SnapshotDigest: snapshotDigest, ArtifactDigest: artifactDigest, Artifacts: artifacts, CreatedAt: normalized.CreatedAt}, nil
}

type SpamQuarantineID string
type SpamObjectID string

type SpamQuarantineState string

const (
	SpamQuarantineHeld      SpamQuarantineState = "held"
	SpamQuarantineReleased  SpamQuarantineState = "released"
	SpamQuarantineDelivered SpamQuarantineState = "delivered"
	SpamQuarantineDeleted   SpamQuarantineState = "deleted"
)

type SpamQuarantineAction string

const (
	SpamQuarantineAccess        SpamQuarantineAction = "access"
	SpamQuarantineRelease       SpamQuarantineAction = "release"
	SpamQuarantineDeliver       SpamQuarantineAction = "deliver"
	SpamQuarantineDelete        SpamQuarantineAction = "delete"
	SpamQuarantineFalsePositive SpamQuarantineAction = "false_positive"
)

type SpamQuarantineItem struct {
	ID             SpamQuarantineID    `json:"id"`
	ObjectID       SpamObjectID        `json:"object_id"`
	TenantID       string              `json:"tenant_id"`
	DomainID       DomainID            `json:"domain_id"`
	MailboxID      MailboxID           `json:"mailbox_id"`
	MessageDigest  string              `json:"message_digest"`
	ObjectDigest   string              `json:"object_digest"`
	Size           uint64              `json:"size"`
	Verdict        string              `json:"verdict"`
	Malware        bool                `json:"malware"`
	EvidenceHold   bool                `json:"evidence_hold"`
	State          SpamQuarantineState `json:"state"`
	PolicyGeneration uint64            `json:"policy_generation"`
	Generation     uint64              `json:"generation"`
	RetainUntil    time.Time           `json:"retain_until"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
}

func (item SpamQuarantineItem) Validate() error {
	if !validSpamID(string(item.ID), "spamq_") || !validSpamID(string(item.ObjectID), "spamobj_") || !validOpaque(item.TenantID) || !validOpaque(string(item.DomainID)) || !validOpaque(string(item.MailboxID)) || !validSpamDigest(item.MessageDigest) || !validSpamDigest(item.ObjectDigest) || item.Size == 0 || item.Size > SpamMaximumQuarantineBytes || len(item.Verdict) == 0 || len(item.Verdict) > 160 || strings.ContainsAny(item.Verdict, "\r\n\x00") || item.PolicyGeneration == 0 || item.Generation == 0 || !canonicalSpamTime(item.RetainUntil) || !canonicalSpamTime(item.CreatedAt) || !canonicalSpamTime(item.UpdatedAt) || item.RetainUntil.Before(item.CreatedAt) || item.UpdatedAt.Before(item.CreatedAt) {
		return ErrInvalidCommand
	}
	switch item.State {
	case SpamQuarantineHeld, SpamQuarantineReleased, SpamQuarantineDelivered, SpamQuarantineDeleted:
	default:
		return ErrInvalidCommand
	}
	if item.Malware && !item.EvidenceHold {
		return ErrInvalidCommand
	}
	return nil
}

type SpamQuarantineReceipt struct {
	OperationID        string               `json:"operation_id"`
	RequestDigest      string               `json:"request_digest"`
	ItemID             SpamQuarantineID     `json:"item_id"`
	ObjectID           SpamObjectID         `json:"object_id"`
	Action             SpamQuarantineAction `json:"action"`
	ActorID            string               `json:"actor_id"`
	EffectKey          string               `json:"effect_key,omitempty"`
	PreviousGeneration uint64               `json:"previous_generation"`
	ResultGeneration   uint64               `json:"result_generation"`
	State              SpamQuarantineState  `json:"state"`
	ArtifactDigest     string               `json:"artifact_digest,omitempty"`
	EffectDigest       string               `json:"effect_digest,omitempty"`
	Completed          bool                 `json:"completed"`
	OccurredAt         time.Time            `json:"occurred_at"`
}

type SpamHealthState string

const (
	SpamHealthHealthy     SpamHealthState = "healthy"
	SpamHealthDrifted     SpamHealthState = "drifted"
	SpamHealthUnavailable SpamHealthState = "unavailable"
)

type SpamHealthStatus struct {
	State             SpamHealthState `json:"state"`
	DesiredGeneration string          `json:"desired_generation"`
	DesiredDigest     string          `json:"desired_digest"`
	ActiveGeneration  string          `json:"active_generation"`
	ActiveDigest      string          `json:"active_digest"`
	Code              string          `json:"code"`
	CheckedAt         time.Time       `json:"checked_at"`
}

func normalizeSpamIdentities(input []SpamIdentity) ([]SpamIdentity, error) {
	if len(input) > SpamMaximumIdentities {
		return nil, ErrInvalidCommand
	}
	result := make([]SpamIdentity, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, candidate := range input {
		identity, err := NormalizeSpamIdentity(candidate)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[identity.key()]; exists {
			return nil, ErrInvalidCommand
		}
		seen[identity.key()] = struct{}{}
		result = append(result, identity)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].key() < result[j].key() })
	return result, nil
}

func spamIdentitySubset(subset, superset []SpamIdentity) bool {
	set := make(map[string]struct{}, len(superset))
	for _, identity := range superset {
		set[identity.key()] = struct{}{}
	}
	for _, identity := range subset {
		if _, exists := set[identity.key()]; !exists {
			return false
		}
	}
	return true
}

func canonicalSpamTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func validSpamDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validSpamID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) < len(prefix)+16 || len(value) > 128 {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !(character == '-' || character == '_' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z') {
			return false
		}
	}
	return true
}

func spamScopeToken(scope SpamScope) string {
	value := string(scope.Kind)
	if scope.DomainID != "" {
		value += "_" + string(scope.DomainID)
	}
	if scope.MailboxID != "" {
		value += "_" + string(scope.MailboxID)
	}
	return strings.NewReplacer(".", "_", "-", "_").Replace(value)
}

func spamScore(value int32) string { return strconv.FormatFloat(float64(value)/1000, 'f', 3, 64) }

func spamMapLine(scope SpamScope, identity SpamIdentity) string {
	return string(identity.Kind) + ":" + identity.Value + "\t" + spamScopeToken(scope) + "\n"
}

func spamConfigArtifact(path, content string) SpamConfigArtifact {
	raw := []byte(content)
	sum := sha256.Sum256(raw)
	return SpamConfigArtifact{Path: path, Mode: 0440, Content: raw, SHA256: hex.EncodeToString(sum[:])}
}
