package webmaildata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ConditionKind string

const (
	ConditionAddress ConditionKind = "address"
	ConditionHeader  ConditionKind = "header"
	ConditionSize    ConditionKind = "size"
	ConditionSpam    ConditionKind = "spam"
)

type MatchOperator string

const (
	MatchIs       MatchOperator = "is"
	MatchContains MatchOperator = "contains"
	MatchMatches  MatchOperator = "matches"
	MatchOver     MatchOperator = "over"
	MatchUnder    MatchOperator = "under"
)

type SieveCondition struct {
	Kind      ConditionKind `json:"kind"`
	Operator  MatchOperator `json:"operator"`
	Field     string        `json:"field,omitempty"`
	Values    []string      `json:"values,omitempty"`
	Bytes     uint64        `json:"bytes,omitempty"`
	SpamScore int           `json:"spam_score,omitempty"`
}

type ActionKind string

const (
	ActionKeep     ActionKind = "keep"
	ActionFileInto ActionKind = "fileinto"
	ActionRedirect ActionKind = "redirect"
	ActionDiscard  ActionKind = "discard"
	ActionStop     ActionKind = "stop"
)

type SieveAction struct {
	Kind   ActionKind `json:"kind"`
	Target string     `json:"target,omitempty"`
}

type SieveRule struct {
	Scope             Scope                       `json:"scope"`
	ID                string                      `json:"id"`
	Name              string                      `json:"name"`
	Enabled           bool                        `json:"enabled"`
	Order             int                         `json:"order"`
	MatchAll          bool                        `json:"match_all"`
	Conditions        []SieveCondition            `json:"conditions,omitempty"`
	Actions           []SieveAction               `json:"actions,omitempty"`
	CanonicalVacation *CanonicalVacationReference `json:"canonical_vacation,omitempty"`
	Revision          uint64                      `json:"revision"`
	UpdatedAt         time.Time                   `json:"updated_at"`
}

var headerNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,77}$`)

func NormalizeSieveRule(rule SieveRule) (SieveRule, error) {
	if !rule.Scope.Valid() || !opaquePattern.MatchString(rule.ID) || rule.Revision == 0 || rule.Revision > MaximumRevision || rule.UpdatedAt.IsZero() || rule.Order < 0 || rule.Order >= MaximumSieveRules {
		return SieveRule{}, ErrInvalid
	}
	rule.Name = cleanText(rule.Name, 256)
	if rule.Name == "" { return SieveRule{}, ErrInvalid }
	if rule.CanonicalVacation != nil {
		if !rule.CanonicalVacation.Valid() || len(rule.Conditions) != 0 || len(rule.Actions) != 0 { return SieveRule{}, ErrInvalid }
		rule.UpdatedAt = rule.UpdatedAt.UTC().Truncate(time.Second)
		return rule, nil
	}
	if len(rule.Conditions) == 0 || len(rule.Conditions) > MaximumSieveConditions || len(rule.Actions) == 0 || len(rule.Actions) > MaximumSieveActions { return SieveRule{}, ErrInvalid }
	for index := range rule.Conditions {
		condition, err := normalizeCondition(rule.Conditions[index])
		if err != nil { return SieveRule{}, err }
		rule.Conditions[index] = condition
	}
	redirects := 0
	terminal := false
	seenRedirect := map[string]bool{}
	for index := range rule.Actions {
		action := &rule.Actions[index]
		if terminal { return SieveRule{}, ErrInvalid }
		switch action.Kind {
		case ActionKeep:
			if action.Target != "" { return SieveRule{}, ErrInvalid }
		case ActionFileInto:
			action.Target = cleanText(action.Target, 512)
			if action.Target == "" || unsafeMailboxName(action.Target) { return SieveRule{}, ErrInvalid }
		case ActionRedirect:
			address, err := normalizeAddress(action.Target)
			if err != nil || seenRedirect[address] { return SieveRule{}, ErrInvalid }
			action.Target = address; seenRedirect[address] = true; redirects++
			if redirects > MaximumSieveRedirects { return SieveRule{}, ErrLimit }
		case ActionDiscard, ActionStop:
			if action.Target != "" { return SieveRule{}, ErrInvalid }
			terminal = true
		default:
			return SieveRule{}, ErrInvalid
		}
	}
	rule.UpdatedAt = rule.UpdatedAt.UTC().Truncate(time.Second)
	return rule, nil
}

func normalizeCondition(condition SieveCondition) (SieveCondition, error) {
	switch condition.Kind {
	case ConditionAddress:
		if condition.Operator != MatchIs && condition.Operator != MatchContains && condition.Operator != MatchMatches || !validAddressField(condition.Field) || len(condition.Values) == 0 || len(condition.Values) > 32 || condition.Bytes != 0 || condition.SpamScore != 0 { return SieveCondition{}, ErrInvalid }
	case ConditionHeader:
		if condition.Operator != MatchIs && condition.Operator != MatchContains && condition.Operator != MatchMatches || !headerNamePattern.MatchString(condition.Field) || len(condition.Values) == 0 || len(condition.Values) > 32 || condition.Bytes != 0 || condition.SpamScore != 0 { return SieveCondition{}, ErrInvalid }
	case ConditionSize:
		if condition.Operator != MatchOver && condition.Operator != MatchUnder || condition.Field != "" || len(condition.Values) != 0 || condition.Bytes == 0 || condition.Bytes > 1<<40 || condition.SpamScore != 0 { return SieveCondition{}, ErrInvalid }
	case ConditionSpam:
		if condition.Operator != MatchOver && condition.Operator != MatchUnder || condition.Field != "" || len(condition.Values) != 0 || condition.Bytes != 0 || condition.SpamScore < -1000 || condition.SpamScore > 1000 { return SieveCondition{}, ErrInvalid }
	default:
		return SieveCondition{}, ErrInvalid
	}
	for index := range condition.Values {
		condition.Values[index] = cleanText(condition.Values[index], 1024)
		if condition.Values[index] == "" || strings.ContainsAny(condition.Values[index], "\r\n\x00") { return SieveCondition{}, ErrInvalid }
	}
	return condition, nil
}

type SieveProgram struct {
	Scope              Scope                        `json:"scope"`
	Generation         uint64                       `json:"generation"`
	Rules              []SieveRule                  `json:"rules"`
	VacationReferences []CanonicalVacationReference `json:"vacation_references,omitempty"`
	RedirectBudget     int                          `json:"redirect_budget"`
	Script             string                       `json:"script"`
	Digest             string                       `json:"digest"`
	CreatedAt          time.Time                    `json:"created_at"`
}

func CompileSieveProgram(scope Scope, generation uint64, rules []SieveRule, createdAt time.Time) (SieveProgram, error) {
	if !scope.Valid() || generation == 0 || generation > MaximumRevision || createdAt.IsZero() || len(rules) > MaximumSieveRules { return SieveProgram{}, ErrInvalid }
	copyRules := append([]SieveRule(nil), rules...)
	redirects := 0
	for index := range copyRules {
		normalized, err := NormalizeSieveRule(copyRules[index])
		if err != nil || normalized.Scope != scope { return SieveProgram{}, ErrInvalid }
		copyRules[index] = normalized
		if normalized.Enabled { for _, action := range normalized.Actions { if action.Kind == ActionRedirect { redirects++ } } }
	}
	if redirects > MaximumSieveRedirects { return SieveProgram{}, ErrLimit }
	sort.Slice(copyRules, func(i, j int) bool { if copyRules[i].Order == copyRules[j].Order { return copyRules[i].ID < copyRules[j].ID }; return copyRules[i].Order < copyRules[j].Order })
	for index := 1; index < len(copyRules); index++ { if copyRules[index-1].Order == copyRules[index].Order { return SieveProgram{}, ErrConflict } }
	return compileSieve(scope, generation, copyRules, createdAt.UTC().Truncate(time.Second))
}

func compileSieve(scope Scope, generation uint64, rules []SieveRule, createdAt time.Time) (SieveProgram, error) {
	var script strings.Builder
	script.WriteString("# Generated by CyberPanel from validated typed rules.\nrequire [\"fileinto\", \"relational\", \"comparator-i;ascii-numeric\"];\n")
	references := make([]CanonicalVacationReference, 0)
	for _, rule := range rules {
		if !rule.Enabled { continue }
		if rule.CanonicalVacation != nil { references = append(references, *rule.CanonicalVacation); continue }
		tests := make([]string, 0, len(rule.Conditions))
		for _, condition := range rule.Conditions { tests = append(tests, renderCondition(condition)) }
		join := "allof"; if !rule.MatchAll { join = "anyof" }
		script.WriteString("if " + join + "(" + strings.Join(tests, ", ") + ") {\n")
		for _, action := range rule.Actions { script.WriteString("  " + renderAction(action) + "\n") }
		script.WriteString("}\n")
	}
	program := SieveProgram{Scope: scope, Generation: generation, Rules: rules, VacationReferences: references, RedirectBudget: MaximumSieveRedirects, Script: script.String(), CreatedAt: createdAt}
	payload, err := json.Marshal(struct { Scope Scope `json:"scope"`; Generation uint64 `json:"generation"`; Rules []SieveRule `json:"rules"`; Vacation []CanonicalVacationReference `json:"vacation"`; RedirectBudget int `json:"redirect_budget"`; Script string `json:"script"` }{scope, generation, rules, references, program.RedirectBudget, program.Script})
	if err != nil { return SieveProgram{}, err }
	sum := sha256.Sum256(payload); program.Digest = hex.EncodeToString(sum[:])
	return program, nil
}

func (program SieveProgram) Validate() error {
	if len(program.Script) == 0 || len(program.Script) > MaximumSieveTextBytes || !validDigest(program.Digest) || program.CreatedAt.IsZero() || program.RedirectBudget != MaximumSieveRedirects { return ErrInvalid }
	compiled, err := CompileSieveProgram(program.Scope, program.Generation, program.Rules, program.CreatedAt)
	if err != nil || compiled.Digest != program.Digest || compiled.Script != program.Script || !sameVacationReferences(compiled.VacationReferences, program.VacationReferences) { return ErrIntegrity }
	return nil
}

type ExpertSieveParser interface {
	ParseAndNormalize(context.Context, Scope, string, ExpertSieveLimits) ([]SieveRule, error)
}

type ExpertSieveLimits struct { MaximumBytes int; MaximumRules int; MaximumConditions int; MaximumActions int }

func ParseExpertSieve(ctx context.Context, parser ExpertSieveParser, scope Scope, text string) ([]SieveRule, error) {
	if ctx == nil || parser == nil || !scope.Valid() || text == "" || len(text) > MaximumSieveTextBytes || strings.ContainsRune(text, '\x00') { return nil, ErrInvalid }
	rules, err := parser.ParseAndNormalize(ctx, scope, text, ExpertSieveLimits{MaximumBytes: MaximumSieveTextBytes, MaximumRules: MaximumSieveRules, MaximumConditions: MaximumSieveConditions, MaximumActions: MaximumSieveActions})
	if err != nil { return nil, ErrInvalid }
	if len(rules) == 0 || len(rules) > MaximumSieveRules { return nil, ErrInvalid }
	for index := range rules {
		if rules[index].Revision == 0 { rules[index].Revision = 1 }
		if rules[index].UpdatedAt.IsZero() { rules[index].UpdatedAt = time.Unix(0, 0).UTC() }
		rules[index], err = NormalizeSieveRule(rules[index])
		if err != nil || rules[index].Scope != scope { return nil, ErrInvalid }
	}
	return rules, nil
}

type SieveTestMessage struct {
	EnvelopeFrom string
	EnvelopeTo   string
	Headers      map[string][]string
	Size         uint64
	SpamScore    int
}

type SieveEvaluation struct { MatchedRuleIDs []string `json:"matched_rule_ids"`; Actions []SieveAction `json:"actions"`; Stopped bool `json:"stopped"` }

func EvaluateSieve(program SieveProgram, message SieveTestMessage) (SieveEvaluation, error) {
	if err := program.Validate(); err != nil || len(message.Headers) > 256 || message.Size > 1<<40 || message.SpamScore < -1000 || message.SpamScore > 1000 { return SieveEvaluation{}, ErrInvalid }
	if message.EnvelopeFrom != "" { if _, err := normalizeAddress(message.EnvelopeFrom); err != nil { return SieveEvaluation{}, ErrInvalid } }
	if _, err := normalizeAddress(message.EnvelopeTo); err != nil { return SieveEvaluation{}, ErrInvalid }
	result := SieveEvaluation{}
	for _, rule := range program.Rules {
		if !rule.Enabled || rule.CanonicalVacation != nil { continue }
		matched := rule.MatchAll
		for index, condition := range rule.Conditions {
			value := evaluateCondition(condition, message)
			if index == 0 { matched = value } else if rule.MatchAll { matched = matched && value } else { matched = matched || value }
		}
		if !matched { continue }
		result.MatchedRuleIDs = append(result.MatchedRuleIDs, rule.ID)
		result.Actions = append(result.Actions, rule.Actions...)
		for _, action := range rule.Actions { if action.Kind == ActionStop || action.Kind == ActionDiscard { result.Stopped = true } }
		if result.Stopped { break }
	}
	return result, nil
}

type ManageSieveStageRequest struct { OperationID string; Program SieveProgram }
type ManageSieveValidationRequest struct { Scope Scope; Generation uint64; Digest string }
type ManageSieveActivationRequest struct { OperationID string; Scope Scope; ExpectedDigest string; Program SieveProgram; Remove bool; Rollback bool }
type ManageSieveReceipt struct { OperationID string; Scope Scope; Generation uint64; Digest string; PreviousDigest string; Validated bool; Activated bool }

type ManageSieveRuntime interface {
	Stage(context.Context, ManageSieveStageRequest) (ManageSieveReceipt, error)
	ValidateCompile(context.Context, ManageSieveValidationRequest) (ManageSieveReceipt, error)
	ActivateCAS(context.Context, ManageSieveActivationRequest) (ManageSieveReceipt, error)
	Test(context.Context, SieveProgram, SieveTestMessage) (SieveEvaluation, error)
}

type SieveActivation struct { Scope Scope `json:"scope"`; Generation uint64 `json:"generation"`; Digest string `json:"digest"`; UpdatedAt time.Time `json:"updated_at"` }

func renderCondition(condition SieveCondition) string {
	switch condition.Kind {
	case ConditionAddress:
		return "address :" + string(condition.Operator) + " \"" + sieveEscape(condition.Field) + "\" " + renderStringList(condition.Values)
	case ConditionHeader:
		return "header :" + string(condition.Operator) + " \"" + sieveEscape(condition.Field) + "\" " + renderStringList(condition.Values)
	case ConditionSize:
		return "size :" + string(condition.Operator) + " " + strconv.FormatUint(condition.Bytes, 10)
	case ConditionSpam:
		comparison := "gt"; if condition.Operator == MatchUnder { comparison = "lt" }
		return "header :value \"" + comparison + "\" :comparator \"i;ascii-numeric\" \"X-Spam-Score\" \"" + strconv.Itoa(condition.SpamScore) + "\""
	default:
		panic("closed sieve condition violated")
	}
}

func renderAction(action SieveAction) string {
	switch action.Kind {
	case ActionKeep, ActionDiscard, ActionStop: return string(action.Kind) + ";"
	case ActionFileInto, ActionRedirect: return string(action.Kind) + " \"" + sieveEscape(action.Target) + "\";"
	default: panic("closed sieve action violated")
	}
}

func renderStringList(values []string) string { escaped := make([]string, len(values)); for index, value := range values { escaped[index] = "\"" + sieveEscape(value) + "\"" }; if len(escaped) == 1 { return escaped[0] }; return "[" + strings.Join(escaped, ", ") + "]" }
func sieveEscape(value string) string { return strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value) }
func validAddressField(value string) bool { switch strings.ToLower(value) { case "from", "to", "cc", "bcc", "sender", "resent-from", "resent-to": return true }; return false }
func unsafeMailboxName(value string) bool { for _, part := range strings.Split(value, "/") { if part == "" || part == "." || part == ".." { return true } }; return strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\r\n\x00") }
func sameVacationReferences(left, right []CanonicalVacationReference) bool { if len(left) != len(right) { return false }; for index := range left { if left[index] != right[index] { return false } }; return true }

func evaluateCondition(condition SieveCondition, message SieveTestMessage) bool {
	if condition.Kind == ConditionSize { if condition.Operator == MatchOver { return message.Size > condition.Bytes }; return message.Size < condition.Bytes }
	if condition.Kind == ConditionSpam { if condition.Operator == MatchOver { return message.SpamScore > condition.SpamScore }; return message.SpamScore < condition.SpamScore }
	values := []string{}
	if condition.Kind == ConditionAddress {
		switch strings.ToLower(condition.Field) { case "from", "sender": values = append(values, message.EnvelopeFrom); case "to": values = append(values, message.EnvelopeTo); default: values = append(values, headerValues(message.Headers, condition.Field)...)}
	} else { values = headerValues(message.Headers, condition.Field) }
	for _, actual := range values { for _, expected := range condition.Values { if stringMatch(actual, expected, condition.Operator) { return true } } }
	return false
}

func headerValues(headers map[string][]string, name string) []string { for key, values := range headers { if strings.EqualFold(key, name) { return values } }; return nil }
func stringMatch(actual, expected string, operator MatchOperator) bool { actual = strings.ToLower(actual); expected = strings.ToLower(expected); switch operator { case MatchIs: return actual == expected; case MatchContains: return strings.Contains(actual, expected); case MatchMatches: pattern := regexp.QuoteMeta(expected); pattern = strings.ReplaceAll(pattern, `\*`, `.*`); pattern = strings.ReplaceAll(pattern, `\?`, `.`); matched, _ := regexp.MatchString("^"+pattern+"$", actual); return matched }; return false }
