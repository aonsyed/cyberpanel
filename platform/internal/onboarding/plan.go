package onboarding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
)

type WarningCode string
type WarningClass string

const (
	WarningPublicSSH         WarningCode = "public_ssh_exposure"
	WarningAdminLockout      WarningCode = "admin_source_lockout"
	WarningDNSDelegation     WarningCode = "dns_delegation_cutover"
	WarningLiteSpeedLicense  WarningCode = "litespeed_license_required"
	WarningMailExposure      WarningCode = "public_mail_listeners"
	WarningIrreversibleClaim WarningCode = "irreversible_node_claim"

	WarningRisk    WarningClass = "risk"
	WarningLockout WarningClass = "lockout"
)

type PlanWarning struct {
	Code    WarningCode  `json:"code"`
	Class   WarningClass `json:"class"`
	Message string       `json:"message"`
}

func (warning PlanWarning) Validate() error {
	expected := warningFor(warning.Code)
	if expected.Code == "" || warning != expected {
		return ErrInvalid
	}
	return nil
}

func warningFor(code WarningCode) PlanWarning {
	switch code {
	case WarningPublicSSH:
		return PlanWarning{code, WarningRisk, "SSH remains reachable from all source addresses."}
	case WarningAdminLockout:
		return PlanWarning{code, WarningLockout, "Incorrect administrative source ranges can lock out local operators."}
	case WarningDNSDelegation:
		return PlanWarning{code, WarningRisk, "Delegation before authoritative DNS is observed can interrupt resolution."}
	case WarningLiteSpeedLicense:
		return PlanWarning{code, WarningRisk, "LiteSpeed Enterprise requires a valid external license entitlement."}
	case WarningMailExposure:
		return PlanWarning{code, WarningRisk, "Public mail listeners increase abuse and reputation risk."}
	case WarningIrreversibleClaim:
		return PlanWarning{code, WarningLockout, "The final node claim is irreversible through this workflow."}
	default:
		return PlanWarning{}
	}
}

func sortedWarnings(values []WarningCode) bool {
	for index, value := range values {
		if warningFor(value).Code == "" || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

type AnswerBinding struct {
	Step     Step   `json:"step"`
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}

type OperationKind string

const (
	OperationSetHostname          OperationKind = "set_hostname"
	OperationBindPublicAddresses OperationKind = "bind_public_addresses"
	OperationConfigureOwner      OperationKind = "configure_owner"
	OperationSetTimezone         OperationKind = "set_timezone"
	OperationSelectWebEngine     OperationKind = "select_web_engine"
	OperationApplyServiceProfile OperationKind = "apply_service_profile"
	OperationConfigureDNS        OperationKind = "configure_authoritative_dns"
	OperationApplyFirewall       OperationKind = "apply_firewall_listeners"
	OperationEnrollRecovery      OperationKind = "enroll_recovery"
	OperationClaimNode           OperationKind = "claim_node"
)

func operationForStep(step Step) OperationKind {
	switch step {
	case StepHostname:
		return OperationSetHostname
	case StepPublicAddresses:
		return OperationBindPublicAddresses
	case StepOwnerContact:
		return OperationConfigureOwner
	case StepTimezone:
		return OperationSetTimezone
	case StepWebEngine:
		return OperationSelectWebEngine
	case StepServiceProfile:
		return OperationApplyServiceProfile
	case StepAuthoritativeDNS:
		return OperationConfigureDNS
	case StepFirewallListeners:
		return OperationApplyFirewall
	case StepRecoveryEnrollment:
		return OperationEnrollRecovery
	case StepFinalClaim:
		return OperationClaimNode
	default:
		return ""
	}
}

type OperationIntent struct {
	ID                       string      `json:"id"`
	WizardID                 WizardID    `json:"wizard_id"`
	Scope                    Scope       `json:"scope"`
	PlanGeneration           uint64      `json:"plan_generation"`
	Step                     Step        `json:"step"`
	Kind                     OperationKind `json:"kind"`
	Answer                   *StepAnswer `json:"answer,omitempty"`
	AnswerDigest             string      `json:"answer_digest"`
	PrerequisiteGeneration   uint64      `json:"prerequisite_generation"`
	PrerequisiteDigest       string      `json:"prerequisite_digest"`
	IdempotencyKey           string      `json:"idempotency_key"`
	InputDigest              string      `json:"input_digest"`
	Mandatory                bool        `json:"mandatory"`
	Reversible               bool        `json:"reversible"`
	RequiresRecentStepUp     bool        `json:"requires_recent_step_up"`
}

func (intent OperationIntent) Validate() error {
	if !validID(intent.ID) || !validID(string(intent.WizardID)) || intent.Scope.Validate() != nil || intent.PlanGeneration == 0 || !intent.Step.valid() || intent.Kind != operationForStep(intent.Step) || !validDigest(intent.AnswerDigest) || intent.PrerequisiteGeneration == 0 || !validDigest(intent.PrerequisiteDigest) || !validID(intent.IdempotencyKey) || !validDigest(intent.InputDigest) || !intent.Mandatory {
		return ErrInvalid
	}
	if intent.Step == StepFinalClaim {
		if intent.Answer != nil || intent.Reversible || !intent.RequiresRecentStepUp {
			return ErrInvalid
		}
	} else {
		if intent.Answer == nil || intent.Answer.Validate() != nil {
			return ErrInvalid
		}
		step, _ := intent.Answer.Step()
		if step != intent.Step || !intent.Reversible || intent.RequiresRecentStepUp != (intent.Step == StepOwnerContact || intent.Step == StepRecoveryEnrollment) {
			return ErrInvalid
		}
	}
	expected, err := intentDigest(intent)
	if err != nil || intent.InputDigest != expected {
		return ErrInvalid
	}
	return nil
}

func intentDigest(intent OperationIntent) (string, error) {
	copy := intent
	copy.ID, copy.IdempotencyKey, copy.InputDigest = "", "", ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	return domainDigest("intent", encoded), nil
}

type ReviewPlan struct {
	WizardID                 WizardID               `json:"wizard_id"`
	Scope                    Scope                  `json:"scope"`
	Generation               uint64                 `json:"generation"`
	SourceRevision           uint64                 `json:"source_revision"`
	PrerequisiteGeneration   uint64                 `json:"prerequisite_generation"`
	PrerequisiteDigest       string                 `json:"prerequisite_digest"`
	Tuple                    PlatformTuple          `json:"tuple"`
	Answers                  []AnswerBinding        `json:"answers"`
	Warnings                 []PlanWarning          `json:"warnings"`
	Intents                  []OperationIntent      `json:"intents"`
	IrreversibleFrontier     Step                   `json:"irreversible_frontier"`
	CreatedAt                time.Time              `json:"created_at"`
	Digest                   string                 `json:"digest"`
}

func BuildReviewPlan(wizard Wizard, answers map[Step]AnswerRecord, observation PrerequisiteObservation, now time.Time) (ReviewPlan, error) {
	if wizard.Validate() != nil || wizard.State != StateCollecting && wizard.State != StateReview && wizard.State != StateReady || wizard.IrreversibleCrossed || wizard.CurrentStep != StepFinalClaim || observation.Validate(wizard.Scope.NodeID, now) != nil || wizard.PlanGeneration == ^uint64(0) || now.Location() != time.UTC {
		return ReviewPlan{}, ErrInvalid
	}
	bindings := make([]AnswerBinding, 0, len(configurationSteps))
	intents := make([]OperationIntent, 0, len(configurationSteps)+1)
	for _, step := range configurationSteps {
		record, ok := answers[step]
		if !ok || record.Validate() != nil || record.WizardID != wizard.ID || record.Step != step || record.Revision > wizard.Revision {
			return ReviewPlan{}, ErrIncomplete
		}
		if err := validateAnswerCapability(record.Answer, observation); err != nil {
			return ReviewPlan{}, err
		}
		bindings = append(bindings, AnswerBinding{Step: step, Revision: record.Revision, Digest: record.Digest})
		answer := record.Answer
		intent, err := newIntent(wizard, wizard.PlanGeneration+1, step, &answer, record.Digest, observation)
		if err != nil {
			return ReviewPlan{}, err
		}
		intents = append(intents, intent)
	}
	if err := validateAnswerSet(answers); err != nil {
		return ReviewPlan{}, err
	}
	claimSeed, err := json.Marshal(struct {
		Scope Scope `json:"scope"`; Generation uint64 `json:"generation"`
	}{wizard.Scope, wizard.PlanGeneration + 1})
	if err != nil {
		return ReviewPlan{}, err
	}
	claimDigest := domainDigest("claim-answer", claimSeed)
	claimIntent, err := newIntent(wizard, wizard.PlanGeneration+1, StepFinalClaim, nil, claimDigest, observation)
	if err != nil {
		return ReviewPlan{}, err
	}
	intents = append(intents, claimIntent)
	warnings := planWarnings(answers)
	plan := ReviewPlan{
		WizardID: wizard.ID, Scope: wizard.Scope, Generation: wizard.PlanGeneration + 1,
		SourceRevision: wizard.Revision, PrerequisiteGeneration: observation.Generation,
		PrerequisiteDigest: observation.Digest, Tuple: observation.Tuple, Answers: bindings,
		Warnings: warnings, Intents: intents, IrreversibleFrontier: StepFinalClaim, CreatedAt: now,
	}
	encoded, err := plan.unsignedJSON()
	if err != nil {
		return ReviewPlan{}, err
	}
	plan.Digest = domainDigest("plan", encoded)
	if plan.Validate() != nil {
		return ReviewPlan{}, ErrInvalid
	}
	return plan, nil
}

func (plan ReviewPlan) Validate() error {
	if !validID(string(plan.WizardID)) || plan.Scope.Validate() != nil || plan.Generation == 0 || plan.SourceRevision == 0 || plan.PrerequisiteGeneration == 0 || !validDigest(plan.PrerequisiteDigest) || plan.Tuple.Validate() != nil || len(plan.Answers) != len(configurationSteps) || len(plan.Intents) != len(configurationSteps)+1 || plan.IrreversibleFrontier != StepFinalClaim || plan.CreatedAt.Location() != time.UTC || !validDigest(plan.Digest) {
		return ErrInvalid
	}
	for index, step := range configurationSteps {
		binding := plan.Answers[index]
		if binding.Step != step || binding.Revision == 0 || binding.Revision > plan.SourceRevision || !validDigest(binding.Digest) {
			return ErrInvalid
		}
	}
	answerValues := make(map[Step]AnswerRecord, len(configurationSteps))
	for index, intent := range plan.Intents {
		expectedStep := StepFinalClaim
		if index < len(configurationSteps) {
			expectedStep = configurationSteps[index]
		}
		if intent.Validate() != nil || intent.WizardID != plan.WizardID || intent.Scope != plan.Scope || intent.PlanGeneration != plan.Generation || intent.Step != expectedStep || intent.PrerequisiteGeneration != plan.PrerequisiteGeneration || intent.PrerequisiteDigest != plan.PrerequisiteDigest {
			return ErrInvalid
		}
		if index < len(configurationSteps) {
			encoded, err := json.Marshal(intent.Answer)
			if err != nil || intent.AnswerDigest != plan.Answers[index].Digest || intent.AnswerDigest != domainDigest("answer", encoded) {
				return ErrInvalid
			}
			answerValues[intent.Step] = AnswerRecord{Answer: *intent.Answer}
		}
	}
	claimSeed, err := json.Marshal(struct {
		Scope Scope `json:"scope"`; Generation uint64 `json:"generation"`
	}{plan.Scope, plan.Generation})
	if err != nil || plan.Intents[len(plan.Intents)-1].AnswerDigest != domainDigest("claim-answer", claimSeed) || validateAnswerSet(answerValues) != nil || !slices.Equal(plan.Warnings, planWarnings(answerValues)) {
		return ErrInvalid
	}
	for index, warning := range plan.Warnings {
		if warning.Validate() != nil || index > 0 && plan.Warnings[index-1].Code >= warning.Code {
			return ErrInvalid
		}
	}
	encoded, err := plan.unsignedJSON()
	if err != nil || plan.Digest != domainDigest("plan", encoded) {
		return ErrInvalid
	}
	return nil
}

func (plan ReviewPlan) unsignedJSON() ([]byte, error) {
	copy := plan
	copy.Digest = ""
	return json.Marshal(copy)
}

func newIntent(wizard Wizard, generation uint64, step Step, answer *StepAnswer, answerDigest string, observation PrerequisiteObservation) (OperationIntent, error) {
	intent := OperationIntent{
		WizardID: wizard.ID, Scope: wizard.Scope, PlanGeneration: generation, Step: step,
		Kind: operationForStep(step), Answer: answer, AnswerDigest: answerDigest,
		PrerequisiteGeneration: observation.Generation, PrerequisiteDigest: observation.Digest,
		Mandatory: true, Reversible: step != StepFinalClaim,
		RequiresRecentStepUp: step == StepOwnerContact || step == StepRecoveryEnrollment || step == StepFinalClaim,
	}
	digest, err := intentDigest(intent)
	if err != nil {
		return OperationIntent{}, err
	}
	intent.InputDigest = digest
	intent.ID = "intent-" + digest[:32]
	intent.IdempotencyKey = "onboard-" + digest[:40]
	if intent.Validate() != nil {
		return OperationIntent{}, ErrInvalid
	}
	return intent, nil
}

func validateAnswerSet(answers map[Step]AnswerRecord) error {
	profile := answers[StepServiceProfile].Answer.ServiceProfile.Profile
	dns := answers[StepAuthoritativeDNS].Answer.AuthoritativeDNS
	listeners := answers[StepFirewallListeners].Answer.FirewallListeners.Listeners
	if (profile == ProfileWeb) == dns.Enabled {
		return ErrInvalid
	}
	expected := []Listener{ListenerHTTP, ListenerHTTPS, ListenerSSH}
	if dns.Enabled {
		expected = append(expected, ListenerDNSTCP, ListenerDNSUDP)
	}
	if profile == ProfileFull {
		expected = append(expected, ListenerIMAPTLS, ListenerSMTP, ListenerSubmission)
	}
	slices.Sort(expected)
	if !slices.Equal(expected, listeners) {
		return ErrInvalid
	}
	return nil
}

func planWarnings(answers map[Step]AnswerRecord) []PlanWarning {
	codes := []WarningCode{WarningIrreversibleClaim}
	firewall := answers[StepFirewallListeners].Answer.FirewallListeners
	if len(firewall.AdminSources) == 0 {
		codes = append(codes, WarningPublicSSH)
	} else {
		codes = append(codes, WarningAdminLockout)
	}
	if answers[StepAuthoritativeDNS].Answer.AuthoritativeDNS.Enabled {
		codes = append(codes, WarningDNSDelegation)
	}
	if answers[StepWebEngine].Answer.WebEngine.Engine == EngineLiteSpeedEnterprise {
		codes = append(codes, WarningLiteSpeedLicense)
	}
	if answers[StepServiceProfile].Answer.ServiceProfile.Profile == ProfileFull {
		codes = append(codes, WarningMailExposure)
	}
	slices.Sort(codes)
	warnings := make([]PlanWarning, 0, len(codes))
	for _, code := range codes {
		warnings = append(warnings, warningFor(code))
	}
	return warnings
}

type IntentState string

const (
	IntentPending      IntentState = "pending"
	IntentDispatching  IntentState = "dispatching"
	IntentObserved     IntentState = "observed"
	IntentCompensating IntentState = "compensating"
	IntentCompensated  IntentState = "compensated"
)

type OperationReceipt struct {
	IntentID          string        `json:"intent_id"`
	WizardID         WizardID      `json:"wizard_id"`
	PlanGeneration   uint64        `json:"plan_generation"`
	PlanDigest       string        `json:"plan_digest"`
	Step             Step          `json:"step"`
	Kind             OperationKind `json:"kind"`
	IdempotencyKey   string        `json:"idempotency_key"`
	InputDigest      string        `json:"input_digest"`
	Fence            uint64        `json:"fence"`
	ObservedGeneration uint64      `json:"observed_generation"`
	ObservedAt       time.Time     `json:"observed_at"`
	Digest           string        `json:"digest"`
}

func (receipt OperationReceipt) Validate(plan ReviewPlan, intent OperationIntent, now time.Time) error {
	if receipt.IntentID != intent.ID || receipt.WizardID != plan.WizardID || receipt.PlanGeneration != plan.Generation || receipt.PlanDigest != plan.Digest || receipt.Step != intent.Step || receipt.Kind != intent.Kind || receipt.IdempotencyKey != intent.IdempotencyKey || receipt.InputDigest != intent.InputDigest || receipt.Fence == 0 || receipt.ObservedGeneration == 0 || receipt.ObservedAt.Location() != time.UTC || receipt.ObservedAt.After(now) || receipt.ObservedAt.Before(plan.CreatedAt) || !validDigest(receipt.Digest) {
		return ErrStale
	}
	expected, err := receipt.ExpectedDigest()
	if err != nil || receipt.Digest != expected {
		return ErrStale
	}
	return nil
}

func (receipt OperationReceipt) ExpectedDigest() (string, error) {
	copy := receipt
	copy.Digest = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	return domainDigest("operation-receipt", encoded), nil
}

type CompensationReceipt struct {
	IntentID             string    `json:"intent_id"`
	WizardID            WizardID  `json:"wizard_id"`
	PlanGeneration      uint64    `json:"plan_generation"`
	PlanDigest          string    `json:"plan_digest"`
	OriginalReceiptDigest string  `json:"original_receipt_digest"`
	Fence               uint64    `json:"fence"`
	CompensatedAt       time.Time `json:"compensated_at"`
	Digest              string    `json:"digest"`
}

func (receipt CompensationReceipt) Validate(plan ReviewPlan, intent OperationIntent, original OperationReceipt, now time.Time) error {
	if !intent.Reversible || receipt.IntentID != intent.ID || receipt.WizardID != plan.WizardID || receipt.PlanGeneration != plan.Generation || receipt.PlanDigest != plan.Digest || receipt.OriginalReceiptDigest != original.Digest || receipt.Fence == 0 || receipt.CompensatedAt.Location() != time.UTC || receipt.CompensatedAt.After(now) || receipt.CompensatedAt.Before(original.ObservedAt) || !validDigest(receipt.Digest) {
		return ErrStale
	}
	expected, err := receipt.ExpectedDigest()
	if err != nil || receipt.Digest != expected {
		return ErrStale
	}
	return nil
}

func (receipt CompensationReceipt) ExpectedDigest() (string, error) {
	copy := receipt
	copy.Digest = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	return domainDigest("compensation-receipt", encoded), nil
}

type IntentRecord struct {
	Intent              OperationIntent     `json:"intent"`
	State               IntentState         `json:"state"`
	Attempt             uint32              `json:"attempt"`
	Fence               uint64              `json:"fence"`
	LeaseToken          string              `json:"lease_token,omitempty"`
	LeaseUntil          time.Time           `json:"lease_until,omitempty"`
	Receipt             *OperationReceipt   `json:"receipt,omitempty"`
	Compensation        *CompensationReceipt `json:"compensation,omitempty"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

type IntentLease struct {
	Record IntentRecord `json:"record"`
	Token  string       `json:"token"`
	Fence  uint64       `json:"fence"`
	Until  time.Time    `json:"until"`
}

func (record IntentRecord) Validate() error {
	if record.Intent.Validate() != nil || record.Attempt > 1_000_000 || record.UpdatedAt.Location() != time.UTC {
		return ErrInvalid
	}
	switch record.State {
	case IntentPending:
		if record.LeaseToken != "" || !record.LeaseUntil.IsZero() || record.Receipt != nil || record.Compensation != nil {
			return ErrInvalid
		}
	case IntentDispatching:
		if record.Attempt == 0 || record.Fence == 0 || !validID(record.LeaseToken) || record.LeaseUntil.Location() != time.UTC || record.Receipt != nil || record.Compensation != nil {
			return ErrInvalid
		}
	case IntentObserved:
		if record.Receipt == nil || record.Fence < record.Receipt.Fence || record.LeaseToken != "" || !record.LeaseUntil.IsZero() || record.Compensation != nil {
			return ErrInvalid
		}
	case IntentCompensating:
		if record.Receipt == nil || record.Attempt == 0 || record.Fence == 0 || !validID(record.LeaseToken) || record.LeaseUntil.Location() != time.UTC || record.Compensation != nil {
			return ErrInvalid
		}
	case IntentCompensated:
		if record.Receipt == nil || record.Compensation == nil || record.Fence != record.Compensation.Fence || record.LeaseToken != "" || !record.LeaseUntil.IsZero() {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type ManifestReceipt struct {
	Step               Step   `json:"step"`
	IntentID           string `json:"intent_id"`
	ReceiptDigest      string `json:"receipt_digest"`
	ObservedGeneration uint64 `json:"observed_generation"`
}

type ManifestSignature struct {
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Digest    string    `json:"digest"`
	Value     string    `json:"value"`
	SignedAt  time.Time `json:"signed_at"`
}

func (signature ManifestSignature) Validate(digest string, completedAt time.Time) error {
	if signature.Algorithm != "ed25519" || !validID(signature.KeyID) || signature.Digest != digest || len(signature.Value) != 128 || !validLowerHex(signature.Value) || !signature.SignedAt.Equal(completedAt) {
		return ErrInvalid
	}
	return nil
}

type CompletionManifest struct {
	WizardID               WizardID          `json:"wizard_id"`
	Scope                  Scope             `json:"scope"`
	PlanGeneration         uint64            `json:"plan_generation"`
	PlanDigest             string            `json:"plan_digest"`
	PrerequisiteGeneration uint64            `json:"prerequisite_generation"`
	PrerequisiteDigest     string            `json:"prerequisite_digest"`
	Answers                []AnswerBinding   `json:"answers"`
	Receipts               []ManifestReceipt `json:"receipts"`
	IrreversibleFrontier   Step              `json:"irreversible_frontier"`
	FrontierCrossedAt      time.Time         `json:"frontier_crossed_at"`
	CompletedAt            time.Time         `json:"completed_at"`
	Digest                 string            `json:"digest"`
	Signature              ManifestSignature `json:"signature"`
}

func (manifest CompletionManifest) UnsignedDigest() (string, error) {
	copy := manifest
	copy.Digest, copy.Signature = "", ManifestSignature{}
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	return domainDigest("completion-manifest", encoded), nil
}

func (manifest CompletionManifest) Validate(plan ReviewPlan) error {
	if plan.Validate() != nil || manifest.WizardID != plan.WizardID || manifest.Scope != plan.Scope || manifest.PlanGeneration != plan.Generation || manifest.PlanDigest != plan.Digest || manifest.PrerequisiteGeneration != plan.PrerequisiteGeneration || manifest.PrerequisiteDigest != plan.PrerequisiteDigest || !slices.Equal(manifest.Answers, plan.Answers) || len(manifest.Receipts) != len(plan.Intents) || manifest.IrreversibleFrontier != StepFinalClaim || manifest.FrontierCrossedAt.Location() != time.UTC || manifest.CompletedAt.Location() != time.UTC || manifest.CompletedAt.Before(manifest.FrontierCrossedAt) || !validDigest(manifest.Digest) {
		return ErrInvalid
	}
	for index, receipt := range manifest.Receipts {
		intent := plan.Intents[index]
		if receipt.Step != intent.Step || receipt.IntentID != intent.ID || !validDigest(receipt.ReceiptDigest) || receipt.ObservedGeneration == 0 {
			return ErrInvalid
		}
	}
	digest, err := manifest.UnsignedDigest()
	if err != nil || manifest.Digest != digest || manifest.Signature.Validate(digest, manifest.CompletedAt) != nil {
		return ErrInvalid
	}
	return nil
}

func domainDigest(domain string, encoded []byte) string {
	sum := sha256.Sum256(append([]byte("cyberpanel:onboarding:"+domain+":v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

func validLowerHex(value string) bool {
	for index := range value {
		if value[index] < '0' || value[index] > '9' && value[index] < 'a' || value[index] > 'f' {
			return false
		}
	}
	return value != ""
}
