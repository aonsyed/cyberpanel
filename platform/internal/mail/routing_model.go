package mail

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	RoutingMaximumRules       uint32 = 512
	RoutingMaximumList        uint32 = 200
	RoutingMaximumTargets            = 32
	RoutingMaximumHops               = 16
	RoutingMaximumExpansion          = 128
	RoutingMaximumGeneration  uint64 = 1<<63 - 1
	RoutingMaximumSourceBytes        = 4 << 20
)

type RoutingRuleID string

type RoutingRuleKind string

const (
	RoutingAlias     RoutingRuleKind = "alias"
	RoutingForwarder RoutingRuleKind = "forwarder"
	RoutingPattern   RoutingRuleKind = "pattern"
)

type RoutingRuleState string

const (
	RoutingRuleEnabled  RoutingRuleState = "enabled"
	RoutingRuleDisabled RoutingRuleState = "disabled"
	RoutingRuleDeleted  RoutingRuleState = "deleted"
)

type RoutingPatternKind string

const (
	RoutingPrefixPattern RoutingPatternKind = "prefix"
	RoutingSuffixPattern RoutingPatternKind = "suffix"
)

// RoutingPatternSpec is the entire accepted pattern grammar: one typed
// prefix or suffix literal. It cannot represent a regex, command, or pipe.
type RoutingPatternSpec struct {
	Kind    RoutingPatternKind `json:"kind"`
	Literal string             `json:"literal"`
}

func (pattern RoutingPatternSpec) Validate() error {
	if pattern.Kind != RoutingPrefixPattern && pattern.Kind != RoutingSuffixPattern || !validRoutingPatternLiteral(pattern.Literal) {
		return ErrInvalidCommand
	}
	return nil
}

func (pattern RoutingPatternSpec) Matches(local string) bool {
	if pattern.Validate() != nil || !validRoutingLocal(local) {
		return false
	}
	if pattern.Kind == RoutingPrefixPattern {
		return strings.HasPrefix(local, pattern.Literal) && len(local) > len(pattern.Literal)
	}
	return strings.HasSuffix(local, pattern.Literal) && len(local) > len(pattern.Literal)
}

type RoutingTargetKind string

const (
	RoutingLocalMailbox RoutingTargetKind = "local_mailbox"
	RoutingExternal      RoutingTargetKind = "external_address"
)

type RoutingTarget struct {
	Kind              RoutingTargetKind `json:"kind"`
	Address           Address           `json:"address"`
	TenantID          string            `json:"tenant_id,omitempty"`
	DomainID          DomainID          `json:"domain_id,omitempty"`
	MailboxID         MailboxID         `json:"mailbox_id,omitempty"`
	MailboxGeneration uint64            `json:"mailbox_generation,omitempty"`
}

func (target RoutingTarget) Validate(ownerTenant string, ownerDomain DomainID, ownerName string) error {
	canonical, err := CanonicalRoutingAddress(target.Address)
	if err != nil || canonical != target.Address {
		return ErrInvalidCommand
	}
	switch target.Kind {
	case RoutingLocalMailbox:
		if target.TenantID != ownerTenant || target.DomainID != ownerDomain || !validOpaque(string(target.MailboxID)) || target.MailboxGeneration == 0 || target.MailboxGeneration > RoutingMaximumGeneration || routingAddressDomain(target.Address) != ownerName {
			return ErrInvalidCommand
		}
	case RoutingExternal:
		if target.TenantID != "" || target.DomainID != "" || target.MailboxID != "" || target.MailboxGeneration != 0 || routingAddressDomain(target.Address) == ownerName {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

type RoutingRule struct {
	ID               RoutingRuleID      `json:"id"`
	TenantID         string             `json:"tenant_id"`
	DomainID         DomainID           `json:"domain_id"`
	DomainName       string             `json:"domain_name"`
	Kind             RoutingRuleKind    `json:"kind"`
	Source           Address            `json:"source,omitempty"`
	Pattern          RoutingPatternSpec `json:"pattern,omitempty"`
	Priority         uint16             `json:"priority"`
	Targets          []RoutingTarget    `json:"targets"`
	State            RoutingRuleState   `json:"state"`
	Revision         uint64             `json:"revision"`
	DomainGeneration uint64             `json:"domain_generation"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

func NormalizeRoutingRule(rule RoutingRule) (RoutingRule, error) {
	rule.DomainName = canonicalRoutingDomain(rule.DomainName)
	if rule.Source != "" {
		address, err := CanonicalRoutingAddress(rule.Source)
		if err != nil {
			return RoutingRule{}, err
		}
		rule.Source = address
	}
	rule.Pattern.Literal = strings.ToLower(strings.TrimSpace(rule.Pattern.Literal))
	rule.Targets = append([]RoutingTarget(nil), rule.Targets...)
	for index := range rule.Targets {
		address, err := CanonicalRoutingAddress(rule.Targets[index].Address)
		if err != nil {
			return RoutingRule{}, err
		}
		rule.Targets[index].Address = address
	}
	if err := rule.Validate(); err != nil {
		return RoutingRule{}, err
	}
	return rule, nil
}

func (rule RoutingRule) Validate() error {
	if !validOpaque(string(rule.ID)) || !validOpaque(rule.TenantID) || !validOpaque(string(rule.DomainID)) || rule.DomainName == "" || canonicalRoutingDomain(rule.DomainName) != rule.DomainName || rule.Revision == 0 || rule.Revision > RoutingMaximumGeneration || rule.DomainGeneration == 0 || rule.DomainGeneration > RoutingMaximumGeneration || !routingCanonicalTime(rule.CreatedAt) || !routingCanonicalTime(rule.UpdatedAt) || rule.UpdatedAt.Before(rule.CreatedAt) || len(rule.Targets) == 0 || len(rule.Targets) > RoutingMaximumTargets {
		return ErrInvalidCommand
	}
	if rule.State != RoutingRuleEnabled && rule.State != RoutingRuleDisabled && rule.State != RoutingRuleDeleted {
		return ErrInvalidCommand
	}
	switch rule.Kind {
	case RoutingAlias:
		if rule.Priority != 0 || rule.Pattern != (RoutingPatternSpec{}) || len(rule.Targets) != 1 || !routingSourceInDomain(rule.Source, rule.DomainName) {
			return ErrInvalidCommand
		}
	case RoutingForwarder:
		if rule.Priority != 0 || rule.Pattern != (RoutingPatternSpec{}) || !routingSourceInDomain(rule.Source, rule.DomainName) {
			return ErrInvalidCommand
		}
	case RoutingPattern:
		if rule.Source != "" || rule.Priority == 0 || rule.Priority > 10000 || rule.Pattern.Validate() != nil {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	seen := make(map[Address]bool, len(rule.Targets))
	for _, target := range rule.Targets {
		if target.Validate(rule.TenantID, rule.DomainID, rule.DomainName) != nil || seen[target.Address] {
			return ErrInvalidCommand
		}
		seen[target.Address] = true
	}
	return nil
}

type RoutingPlusMode string

const (
	RoutingPlusDisabled RoutingPlusMode = "disabled"
	RoutingPlusStripTag RoutingPlusMode = "strip_tag"
)

type RoutingCatchAllAction string

const (
	RoutingCatchAllReject     RoutingCatchAllAction = "reject"
	RoutingCatchAllDiscard    RoutingCatchAllAction = "discard"
	RoutingCatchAllQuarantine RoutingCatchAllAction = "quarantine"
	RoutingCatchAllDeliver    RoutingCatchAllAction = "deliver"
)

type RoutingDomainPolicy struct {
	TenantID         string                `json:"tenant_id"`
	DomainID         DomainID              `json:"domain_id"`
	DomainName       string                `json:"domain_name"`
	DirectoryGeneration uint64             `json:"directory_generation"`
	Revision         uint64                `json:"revision"`
	Generation       uint64                `json:"generation"`
	PlusMode         RoutingPlusMode       `json:"plus_mode"`
	PlusDelimiter    string                `json:"plus_delimiter,omitempty"`
	MaximumTagBytes  uint16                `json:"maximum_tag_bytes"`
	CatchAll         RoutingCatchAllAction `json:"catch_all"`
	CatchAllTarget   *RoutingTarget        `json:"catch_all_target,omitempty"`
	CreatedAt        time.Time             `json:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at"`
}

func NormalizeRoutingDomainPolicy(policy RoutingDomainPolicy) (RoutingDomainPolicy, error) {
	policy.DomainName = canonicalRoutingDomain(policy.DomainName)
	if policy.CatchAllTarget != nil {
		target := *policy.CatchAllTarget
		address, err := CanonicalRoutingAddress(target.Address)
		if err != nil {
			return RoutingDomainPolicy{}, err
		}
		target.Address = address
		policy.CatchAllTarget = &target
	}
	if err := policy.Validate(); err != nil {
		return RoutingDomainPolicy{}, err
	}
	return policy, nil
}

func (policy RoutingDomainPolicy) Validate() error {
	if !validOpaque(policy.TenantID) || !validOpaque(string(policy.DomainID)) || policy.DomainName == "" || canonicalRoutingDomain(policy.DomainName) != policy.DomainName || policy.DirectoryGeneration == 0 || policy.DirectoryGeneration > RoutingMaximumGeneration || policy.Revision == 0 || policy.Revision > RoutingMaximumGeneration || policy.Generation == 0 || policy.Generation > RoutingMaximumGeneration || !routingCanonicalTime(policy.CreatedAt) || !routingCanonicalTime(policy.UpdatedAt) || policy.UpdatedAt.Before(policy.CreatedAt) {
		return ErrInvalidCommand
	}
	switch policy.PlusMode {
	case RoutingPlusDisabled:
		if policy.PlusDelimiter != "" || policy.MaximumTagBytes != 0 {
			return ErrInvalidCommand
		}
	case RoutingPlusStripTag:
		if policy.PlusDelimiter != "+" || policy.MaximumTagBytes == 0 || policy.MaximumTagBytes > 64 {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	switch policy.CatchAll {
	case RoutingCatchAllReject, RoutingCatchAllDiscard:
		if policy.CatchAllTarget != nil {
			return ErrInvalidCommand
		}
	case RoutingCatchAllQuarantine, RoutingCatchAllDeliver:
		if policy.CatchAllTarget == nil || policy.CatchAllTarget.Kind != RoutingLocalMailbox || policy.CatchAllTarget.Validate(policy.TenantID, policy.DomainID, policy.DomainName) != nil {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

type RoutingSnapshot struct {
	Policy RoutingDomainPolicy `json:"policy"`
	Rules  []RoutingRule       `json:"rules"`
	Digest string              `json:"digest"`
}

func NewRoutingSnapshot(policy RoutingDomainPolicy, rules []RoutingRule) (RoutingSnapshot, error) {
	snapshot := RoutingSnapshot{Policy: policy, Rules: append([]RoutingRule(nil), rules...)}
	sortRoutingRules(snapshot.Rules)
	if err := validateRoutingGraph(snapshot.Policy, snapshot.Rules); err != nil {
		return RoutingSnapshot{}, err
	}
	digest, err := routingDigest("mail-routing-snapshot-v1", struct {
		Policy RoutingDomainPolicy `json:"policy"`
		Rules  []RoutingRule       `json:"rules"`
	}{snapshot.Policy, snapshot.Rules})
	if err != nil {
		return RoutingSnapshot{}, err
	}
	snapshot.Digest = digest
	return snapshot, snapshot.Validate()
}

func (snapshot RoutingSnapshot) Validate() error {
	if snapshot.Policy.Validate() != nil || len(snapshot.Rules) > int(RoutingMaximumRules) || !validRoutingDigest(snapshot.Digest) {
		return ErrInvalidReceipt
	}
	canonical, err := NewRoutingSnapshotWithoutDigest(snapshot.Policy, snapshot.Rules)
	if err != nil || canonical.Digest != snapshot.Digest || !sameRoutingRuleOrder(canonical.Rules, snapshot.Rules) {
		return ErrInvalidReceipt
	}
	return nil
}

func NewRoutingSnapshotWithoutDigest(policy RoutingDomainPolicy, rules []RoutingRule) (RoutingSnapshot, error) {
	if err := validateRoutingGraph(policy, rules); err != nil {
		return RoutingSnapshot{}, err
	}
	canonical := append([]RoutingRule(nil), rules...)
	sortRoutingRules(canonical)
	digest, err := routingDigest("mail-routing-snapshot-v1", struct {
		Policy RoutingDomainPolicy `json:"policy"`
		Rules  []RoutingRule       `json:"rules"`
	}{policy, canonical})
	return RoutingSnapshot{Policy: policy, Rules: canonical, Digest: digest}, err
}

type RoutingGenerationReceipt struct {
	OperationID    string    `json:"operation_id"`
	TenantID       string    `json:"tenant_id"`
	DomainID       DomainID  `json:"domain_id"`
	Generation     uint64    `json:"generation"`
	SnapshotDigest string    `json:"snapshot_digest"`
	OccurredAt     time.Time `json:"occurred_at"`
	ReceiptDigest  string    `json:"receipt_digest"`
}

func (receipt RoutingGenerationReceipt) Validate() error {
	if !validOpaque(receipt.OperationID) || !validOpaque(receipt.TenantID) || !validOpaque(string(receipt.DomainID)) || receipt.Generation == 0 || receipt.Generation > RoutingMaximumGeneration || !validRoutingDigest(receipt.SnapshotDigest) || !routingCanonicalTime(receipt.OccurredAt) || !validRoutingDigest(receipt.ReceiptDigest) {
		return ErrInvalidReceipt
	}
	copyReceipt := receipt
	copyReceipt.ReceiptDigest = ""
	digest, err := routingDigest("mail-routing-generation-receipt-v1", copyReceipt)
	if err != nil || digest != receipt.ReceiptDigest {
		return ErrInvalidReceipt
	}
	return nil
}

type RoutingDecisionAction string

const (
	RoutingDeliver    RoutingDecisionAction = "deliver"
	RoutingReject     RoutingDecisionAction = "reject"
	RoutingDiscard    RoutingDecisionAction = "discard"
	RoutingQuarantine RoutingDecisionAction = "quarantine"
)

type RoutingDecision struct {
	Recipient      Address               `json:"recipient"`
	Action         RoutingDecisionAction `json:"action"`
	Code           string                `json:"code"`
	Targets        []RoutingTarget       `json:"targets"`
	Generation     uint64                `json:"generation"`
	SnapshotDigest string                `json:"snapshot_digest"`
	Hops           uint16                `json:"hops"`
	DecisionDigest string                `json:"decision_digest"`
}

type RoutingResolutionInput struct {
	Recipient Address
	Direct    *RoutingTarget
	PlusBase  *RoutingTarget
}

func ResolveRouting(snapshot RoutingSnapshot, input RoutingResolutionInput) (RoutingDecision, error) {
	if snapshot.Validate() != nil {
		return RoutingDecision{}, ErrInvalidReceipt
	}
	recipient, err := CanonicalRoutingAddress(input.Recipient)
	if err != nil || routingAddressDomain(recipient) != snapshot.Policy.DomainName {
		return RoutingDecision{}, ErrInvalidCommand
	}
	if err = validateRoutingResolutionTarget(input.Direct, snapshot.Policy); err != nil {
		return RoutingDecision{}, err
	}
	if err = validateRoutingResolutionTarget(input.PlusBase, snapshot.Policy); err != nil {
		return RoutingDecision{}, err
	}
	decision := RoutingDecision{Recipient: recipient, Action: RoutingDeliver, Generation: snapshot.Policy.Generation, SnapshotDigest: snapshot.Digest}
	start := recipient
	rule := findRoutingRule(snapshot.Rules, start)
	if rule == nil && snapshot.Policy.PlusMode == RoutingPlusStripTag {
		base, tagged := stripRoutingTag(start, snapshot.Policy)
		if tagged {
			start = base
			rule = findRoutingRule(snapshot.Rules, base)
			if rule == nil && input.PlusBase != nil && input.PlusBase.Address == base {
				decision.Targets = []RoutingTarget{*input.PlusBase}
				decision.Code = "plus_local_mailbox"
			}
		}
	}
	if rule != nil {
		visited := map[Address]bool{}
		targets, hops, expandErr := expandRoutingRule(snapshot.Rules, *rule, visited, 0)
		if expandErr != nil {
			return RoutingDecision{}, expandErr
		}
		decision.Targets = targets
		decision.Hops = hops
		decision.Code = "rule_" + string(rule.Kind)
	} else if len(decision.Targets) == 0 && input.Direct != nil && input.Direct.Address == recipient {
		decision.Targets = []RoutingTarget{*input.Direct}
		decision.Code = "local_mailbox"
	}
	if len(decision.Targets) == 0 {
		switch snapshot.Policy.CatchAll {
		case RoutingCatchAllReject:
			decision.Action = RoutingReject
			decision.Code = "catch_all_reject"
		case RoutingCatchAllDiscard:
			decision.Action = RoutingDiscard
			decision.Code = "catch_all_discard"
		case RoutingCatchAllQuarantine:
			decision.Action = RoutingQuarantine
			decision.Code = "catch_all_quarantine"
			decision.Targets = []RoutingTarget{*snapshot.Policy.CatchAllTarget}
		case RoutingCatchAllDeliver:
			decision.Code = "catch_all_deliver"
			decision.Targets = []RoutingTarget{*snapshot.Policy.CatchAllTarget}
		default:
			return RoutingDecision{}, ErrInvalidReceipt
		}
	}
	if len(decision.Targets) > RoutingMaximumExpansion {
		return RoutingDecision{}, ErrRateLimited
	}
	digestInput := decision
	digestInput.DecisionDigest = ""
	decision.DecisionDigest, err = routingDigest("mail-routing-decision-v1", digestInput)
	return decision, err
}

type RoutingMapProbe struct {
	Map      string `json:"map"`
	Key      string `json:"key"`
	Expected string `json:"expected"`
}

type RoutingMapGeneration struct {
	ID               string            `json:"id"`
	TenantID         string            `json:"tenant_id"`
	DomainID         DomainID          `json:"domain_id"`
	Generation       uint64            `json:"generation"`
	SnapshotDigest   string            `json:"snapshot_digest"`
	VirtualAliases   []byte            `json:"-"`
	RoutingActions   []byte            `json:"-"`
	PatternRoutes    []byte            `json:"-"`
	PolicyMetadata   []byte            `json:"-"`
	Probes           []RoutingMapProbe `json:"probes"`
	SourceDigest     string            `json:"source_digest"`
}

func CompileRoutingMapGeneration(snapshot RoutingSnapshot) (RoutingMapGeneration, error) {
	if snapshot.Validate() != nil {
		return RoutingMapGeneration{}, ErrInvalidReceipt
	}
	var virtual bytes.Buffer
	var actions bytes.Buffer
	var patterns bytes.Buffer
	probes := make([]RoutingMapProbe, 0, 18)
	for _, rule := range snapshot.Rules {
		if rule.State != RoutingRuleEnabled {
			continue
		}
		value := routingTargetList(rule.Targets)
		if rule.Kind == RoutingPattern {
			pattern := routingPostfixPattern(rule.Pattern, rule.DomainName)
			patterns.WriteString(pattern + " " + value + "\n")
			continue
		}
		virtual.WriteString(string(rule.Source) + " " + value + "\n")
		if len(probes) < 16 {
			probes = append(probes, RoutingMapProbe{Map: "virtual_aliases", Key: string(rule.Source), Expected: value})
		}
	}
	catchKey := "@" + snapshot.Policy.DomainName
	switch snapshot.Policy.CatchAll {
	case RoutingCatchAllDeliver:
		value := string(snapshot.Policy.CatchAllTarget.Address)
		virtual.WriteString(catchKey + " " + value + "\n")
		probes = append(probes, RoutingMapProbe{Map: "virtual_aliases", Key: catchKey, Expected: value})
	case RoutingCatchAllQuarantine:
		value := "QUARANTINE " + string(snapshot.Policy.CatchAllTarget.Address)
		actions.WriteString(catchKey + " " + value + "\n")
		probes = append(probes, RoutingMapProbe{Map: "routing_actions", Key: catchKey, Expected: value})
	case RoutingCatchAllDiscard:
		actions.WriteString(catchKey + " DISCARD\n")
		probes = append(probes, RoutingMapProbe{Map: "routing_actions", Key: catchKey, Expected: "DISCARD"})
	case RoutingCatchAllReject:
		value := "REJECT 550 5.1.1 unknown local recipient"
		actions.WriteString(catchKey + " " + value + "\n")
		probes = append(probes, RoutingMapProbe{Map: "routing_actions", Key: catchKey, Expected: value})
	}
	metadata, err := json.Marshal(struct {
		Version            uint8           `json:"version"`
		Snapshot           RoutingSnapshot `json:"snapshot"`
		VirtualLookupOrder []string        `json:"virtual_lookup_order"`
		RecipientActionMap string          `json:"recipient_action_map"`
		Plus               RoutingPlusMode `json:"plus_mode"`
		Delimiter          string          `json:"plus_delimiter,omitempty"`
	}{1, snapshot, []string{"hash:virtual_aliases", "regexp:routing_patterns.regexp"}, "hash:routing_actions", snapshot.Policy.PlusMode, snapshot.Policy.PlusDelimiter})
	if err != nil || len(metadata) > RoutingMaximumSourceBytes {
		return RoutingMapGeneration{}, errors.Join(ErrInvalidCommand, err)
	}
	generation := RoutingMapGeneration{TenantID: snapshot.Policy.TenantID, DomainID: snapshot.Policy.DomainID, Generation: snapshot.Policy.Generation, SnapshotDigest: snapshot.Digest, VirtualAliases: virtual.Bytes(), RoutingActions: actions.Bytes(), PatternRoutes: patterns.Bytes(), PolicyMetadata: metadata, Probes: probes}
	digest, err := generation.computeDigest()
	if err != nil {
		return RoutingMapGeneration{}, err
	}
	generation.SourceDigest = digest
	generation.ID = "routing-" + strconv.FormatUint(generation.Generation, 10) + "-" + digest[:20]
	return generation, generation.Validate()
}

func (generation RoutingMapGeneration) Validate() error {
	if !validOpaque(generation.ID) || !validOpaque(generation.TenantID) || !validOpaque(string(generation.DomainID)) || generation.Generation == 0 || generation.Generation > RoutingMaximumGeneration || !validRoutingDigest(generation.SnapshotDigest) || !validRoutingDigest(generation.SourceDigest) || len(generation.VirtualAliases) > RoutingMaximumSourceBytes || len(generation.RoutingActions) > RoutingMaximumSourceBytes || len(generation.PatternRoutes) > RoutingMaximumSourceBytes || len(generation.PolicyMetadata) == 0 || len(generation.PolicyMetadata) > RoutingMaximumSourceBytes || len(generation.Probes) > 18 {
		return ErrInvalidCommand
	}
	for _, content := range [][]byte{generation.VirtualAliases, generation.RoutingActions, generation.PatternRoutes} {
		if bytes.IndexByte(content, 0) >= 0 || len(content) != 0 && content[len(content)-1] != '\n' {
			return ErrInvalidCommand
		}
	}
	for _, probe := range generation.Probes {
		if probe.Map != "virtual_aliases" && probe.Map != "routing_actions" || len(probe.Key) == 0 || len(probe.Key) > 320 || len(probe.Expected) == 0 || len(probe.Expected) > 4096 || strings.ContainsAny(probe.Key+probe.Expected, "\x00\r\n") {
			return ErrInvalidCommand
		}
	}
	digest, err := generation.computeDigest()
	if err != nil || digest != generation.SourceDigest || generation.ID != "routing-"+strconv.FormatUint(generation.Generation, 10)+"-"+digest[:20] {
		return ErrInvalidCommand
	}
	return nil
}

func (generation RoutingMapGeneration) computeDigest() (string, error) {
	return routingDigest("mail-routing-map-generation-v1", struct {
		TenantID       string            `json:"tenant_id"`
		DomainID       DomainID          `json:"domain_id"`
		Generation     uint64            `json:"generation"`
		SnapshotDigest string            `json:"snapshot_digest"`
		Virtual        []byte            `json:"virtual"`
		Actions        []byte            `json:"actions"`
		Patterns       []byte            `json:"patterns"`
		Metadata       []byte            `json:"metadata"`
		Probes         []RoutingMapProbe `json:"probes"`
	}{generation.TenantID, generation.DomainID, generation.Generation, generation.SnapshotDigest, generation.VirtualAliases, generation.RoutingActions, generation.PatternRoutes, generation.PolicyMetadata, generation.Probes})
}

func validateRoutingGraph(policy RoutingDomainPolicy, rules []RoutingRule) error {
	if policy.Validate() != nil || len(rules) > int(RoutingMaximumRules) {
		return ErrInvalidCommand
	}
	exact := map[Address]bool{}
	patterns := map[string]bool{}
	enabled := make([]RoutingRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Validate() != nil || rule.TenantID != policy.TenantID || rule.DomainID != policy.DomainID || rule.DomainName != policy.DomainName || rule.DomainGeneration > policy.Generation {
			return ErrInvalidCommand
		}
		if rule.State != RoutingRuleEnabled {
			continue
		}
		if rule.Kind == RoutingPattern {
			key := string(rule.Pattern.Kind) + "\x00" + rule.Pattern.Literal
			if patterns[key] {
				return ErrConflict
			}
			patterns[key] = true
		} else {
			if exact[rule.Source] {
				return ErrConflict
			}
			exact[rule.Source] = true
		}
		enabled = append(enabled, rule)
	}
	sortRoutingRules(enabled)
	for _, rule := range enabled {
		visited := map[Address]bool{}
		if rule.Source != "" {
			visited[rule.Source] = true
		}
		if _, _, err := expandRoutingRule(enabled, rule, visited, 0); err != nil {
			return err
		}
	}
	if policy.CatchAllTarget != nil {
		if findRoutingRule(enabled, policy.CatchAllTarget.Address) != nil {
			return ErrConflict
		}
	}
	return nil
}

func expandRoutingRule(rules []RoutingRule, rule RoutingRule, visited map[Address]bool, hops int) ([]RoutingTarget, uint16, error) {
	if hops >= RoutingMaximumHops {
		return nil, 0, ErrRateLimited
	}
	result := make([]RoutingTarget, 0, len(rule.Targets))
	maximumHops := uint16(hops + 1)
	for _, target := range rule.Targets {
		if target.Kind == RoutingExternal {
			result = append(result, target)
			continue
		}
		if visited[target.Address] {
			return nil, 0, ErrConflict
		}
		next := findRoutingRule(rules, target.Address)
		if next == nil {
			result = append(result, target)
			continue
		}
		visited[target.Address] = true
		expanded, childHops, err := expandRoutingRule(rules, *next, visited, hops+1)
		delete(visited, target.Address)
		if err != nil {
			return nil, 0, err
		}
		if childHops > maximumHops {
			maximumHops = childHops
		}
		result = append(result, expanded...)
		if len(result) > RoutingMaximumExpansion {
			return nil, 0, ErrRateLimited
		}
	}
	return result, maximumHops, nil
}

func findRoutingRule(rules []RoutingRule, address Address) *RoutingRule {
	for index := range rules {
		if rules[index].State == RoutingRuleEnabled && rules[index].Kind != RoutingPattern && rules[index].Source == address {
			return &rules[index]
		}
	}
	local := routingAddressLocal(address)
	for index := range rules {
		if rules[index].State == RoutingRuleEnabled && rules[index].Kind == RoutingPattern && rules[index].DomainName == routingAddressDomain(address) && rules[index].Pattern.Matches(local) {
			return &rules[index]
		}
	}
	return nil
}

func sortRoutingRules(rules []RoutingRule) {
	sort.Slice(rules, func(left, right int) bool {
		a, b := rules[left], rules[right]
		if a.Kind == RoutingPattern && b.Kind != RoutingPattern {
			return false
		}
		if a.Kind != RoutingPattern && b.Kind == RoutingPattern {
			return true
		}
		if a.Kind == RoutingPattern && a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.ID < b.ID
	})
}

func sameRoutingRuleOrder(left, right []RoutingRule) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID || left[index].Revision != right[index].Revision {
			return false
		}
	}
	return true
}

func validateRoutingResolutionTarget(target *RoutingTarget, policy RoutingDomainPolicy) error {
	if target == nil {
		return nil
	}
	if target.Kind != RoutingLocalMailbox || target.Validate(policy.TenantID, policy.DomainID, policy.DomainName) != nil {
		return ErrInvalidCommand
	}
	return nil
}

func stripRoutingTag(address Address, policy RoutingDomainPolicy) (Address, bool) {
	local := routingAddressLocal(address)
	separator := strings.Index(local, policy.PlusDelimiter)
	if separator <= 0 || len(local)-separator-1 == 0 || len(local)-separator-1 > int(policy.MaximumTagBytes) {
		return address, false
	}
	base := Address(local[:separator] + "@" + routingAddressDomain(address))
	return base, true
}

func routingPostfixPattern(pattern RoutingPatternSpec, domain string) string {
	literal := regexp.QuoteMeta(pattern.Literal)
	if pattern.Kind == RoutingPrefixPattern {
		return "/^" + literal + "[^@]+@" + regexp.QuoteMeta(domain) + "$/"
	}
	return "/^[^@]+" + literal + "@" + regexp.QuoteMeta(domain) + "$/"
}

func routingTargetList(targets []RoutingTarget) string {
	values := make([]string, len(targets))
	for index := range targets {
		values[index] = string(targets[index].Address)
	}
	return strings.Join(values, ",")
}

func CanonicalRoutingAddress(value Address) (Address, error) {
	raw := strings.TrimSpace(string(value))
	if strings.Count(raw, "@") != 1 || strings.ContainsAny(raw, "\x00\r\n\t") {
		return "", ErrInvalidCommand
	}
	parts := strings.SplitN(raw, "@", 2)
	local := strings.ToLower(parts[0])
	domain := canonicalRoutingDomain(parts[1])
	canonical := Address(local + "@" + domain)
	if domain == "" || ValidateAddress(canonical) != nil || !validRoutingLocal(local) {
		return "", ErrInvalidCommand
	}
	return canonical, nil
}

func canonicalRoutingDomain(value string) string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if !validHostname(value) {
		return ""
	}
	return value
}

func routingSourceInDomain(address Address, domain string) bool {
	canonical, err := CanonicalRoutingAddress(address)
	return err == nil && canonical == address && routingAddressDomain(address) == domain
}

func routingAddressLocal(address Address) string {
	value := string(address)
	separator := strings.LastIndexByte(value, '@')
	if separator <= 0 {
		return ""
	}
	return value[:separator]
}

func routingAddressDomain(address Address) string {
	value := string(address)
	separator := strings.LastIndexByte(value, '@')
	if separator < 0 || separator == len(value)-1 {
		return ""
	}
	return value[separator+1:]
}

func validRoutingPatternLiteral(value string) bool {
	if len(value) == 0 || len(value) > 48 || value != strings.ToLower(value) {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validRoutingLocal(value string) bool {
	if !validLocalPart(value) || value != strings.ToLower(value) || len(value) == 0 || !(value[0] >= 'a' && value[0] <= 'z' || value[0] >= '0' && value[0] <= '9') {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '+' || character == '-') {
			return false
		}
	}
	return true
}

func routingCanonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func routingDigest(label string, value any) (string, error) {
	raw, err := json.Marshal(struct {
		Version uint8  `json:"version"`
		Label   string `json:"label"`
		Value   any    `json:"value"`
	}{1, label, value})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func validRoutingDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func encodeRoutingValue(value any, maximum int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return nil, errors.Join(ErrInvalidCommand, err)
	}
	return raw, nil
}

func decodeRoutingValue(raw []byte, maximum int, value any) error {
	if len(raw) == 0 || len(raw) > maximum || value == nil {
		return ErrInvalidReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidReceipt
	}
	return nil
}
