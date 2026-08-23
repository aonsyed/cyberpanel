package notificationrules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

type Service struct {
	repository Repository
	authorizer Authorizer
	auditor    Auditor
	now        func() time.Time
}

func NewService(repository Repository, authorizer Authorizer, auditor Auditor) (*Service, error) {
	if repository == nil || authorizer == nil || auditor == nil { return nil, ErrInvalid }
	return &Service{repository: repository, authorizer: authorizer, auditor: auditor, now: time.Now}, nil
}

func auditDigest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(strconv.Itoa(len(value))))
		hash.Write([]byte{':'})
		hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func auditValueDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil { return "", err }
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (service *Service) valid() bool {
	return service != nil && service.repository != nil && service.authorizer != nil && service.auditor != nil && service.now != nil
}

func (service *Service) audit(ctx context.Context, action AuthorizationAction, actor Actor, tenantID, resourceID string, expectedRevision, resultRevision uint64, outcome string, digest string) error {
	if !service.valid() || ctx == nil || actor.Validate() != nil || !validTenantAndID(tenantID, resourceID) || outcome == "" || len(digest) != 64 {
		return ErrInvalid
	}
	record := AuditRecord{
		Action: action, Actor: actor, TenantID: tenantID, ResourceID: resourceID,
		ExpectedRevision: expectedRevision, ResultRevision: resultRevision,
		Outcome: outcome, Digest: digest, OccurredAt: service.now().UTC(),
	}
	return service.auditor.RecordNotificationPolicy(ctx, record)
}

func (service *Service) authorize(ctx context.Context, actor Actor, action AuthorizationAction, tenantID, resourceID string) error {
	if !service.valid() || ctx == nil || actor.Validate() != nil || !validTenantAndID(tenantID, resourceID) { return ErrInvalid }
	if err := service.authorizer.Authorize(ctx, actor, action, tenantID, resourceID); err != nil {
		digest := auditDigest(string(action), tenantID, resourceID, "denied")
		auditErr := service.audit(ctx, action, actor, tenantID, resourceID, 0, 0, "denied", digest)
		return errors.Join(ErrUnauthorized, err, auditErr)
	}
	return nil
}

func (service *Service) GetRule(ctx context.Context, actor Actor, tenantID, ruleID string) (Rule, error) {
	if err := service.authorize(ctx, actor, AuthorizeRuleRead, tenantID, ruleID); err != nil { return Rule{}, err }
	return service.repository.GetRule(ctx, tenantID, ruleID)
}

func (service *Service) ListRules(ctx context.Context, actor Actor, tenantID string, request RulePageRequest) (RulePage, error) {
	if err := service.authorize(ctx, actor, AuthorizeRuleRead, tenantID, "rules"); err != nil { return RulePage{}, err }
	return service.repository.ListRules(ctx, tenantID, request)
}

func (service *Service) UpsertRule(ctx context.Context, actor Actor, rule Rule, expectedRevision uint64) (Rule, error) {
	if err := service.authorize(ctx, actor, AuthorizeRuleWrite, rule.TenantID, rule.ID); err != nil { return Rule{}, err }
	digest, digestErr := auditValueDigest(rule)
	if digestErr != nil { return Rule{}, digestErr }
	stored, err := service.repository.UpsertRule(ctx, rule, expectedRevision)
	if err != nil {
		auditErr := service.audit(ctx, AuthorizeRuleWrite, actor, rule.TenantID, rule.ID, expectedRevision, 0, "failed", digest)
		return Rule{}, errors.Join(err, auditErr)
	}
	auditErr := service.audit(ctx, AuthorizeRuleWrite, actor, stored.TenantID, stored.ID, expectedRevision, stored.Revision, "committed", digest)
	return stored, auditErr
}

func (service *Service) DeleteRule(ctx context.Context, actor Actor, tenantID, ruleID string, expectedRevision uint64) error {
	if err := service.authorize(ctx, actor, AuthorizeRuleWrite, tenantID, ruleID); err != nil { return err }
	digest := auditDigest(tenantID, ruleID, strconv.FormatUint(expectedRevision, 10), "delete")
	err := service.repository.DeleteRule(ctx, tenantID, ruleID, expectedRevision)
	if err != nil {
		return errors.Join(err, service.audit(ctx, AuthorizeRuleWrite, actor, tenantID, ruleID, expectedRevision, 0, "failed", digest))
	}
	return service.audit(ctx, AuthorizeRuleWrite, actor, tenantID, ruleID, expectedRevision, 0, "deleted", digest)
}

func (service *Service) Evaluate(ctx context.Context, actor Actor, input EvaluationInput) ([]RoutePlan, error) {
	if err := service.authorize(ctx, actor, AuthorizeEvaluate, input.Event.TenantID, input.Event.ID); err != nil { return nil, err }
	plans, err := Evaluate(input)
	digest := auditDigest(input.Event.TenantID, input.Event.ID, string(input.Event.Source), string(input.Event.Kind), strconv.Itoa(len(plans)))
	if err != nil {
		return nil, errors.Join(err, service.audit(ctx, AuthorizeEvaluate, actor, input.Event.TenantID, input.Event.ID, 0, 0, "failed", digest))
	}
	auditErr := service.audit(ctx, AuthorizeEvaluate, actor, input.Event.TenantID, input.Event.ID, 0, 0, "evaluated", digest)
	return plans, auditErr
}

func (service *Service) GetDelivery(ctx context.Context, actor Actor, tenantID, deliveryID string) (DeliveryState, error) {
	if err := service.authorize(ctx, actor, AuthorizeDeliveryRead, tenantID, deliveryID); err != nil { return DeliveryState{}, err }
	return service.repository.GetDelivery(ctx, tenantID, deliveryID)
}

func (service *Service) ListDueDeliveries(ctx context.Context, actor Actor, tenantID string, request DeliveryPageRequest) (DeliveryPage, error) {
	if err := service.authorize(ctx, actor, AuthorizeDeliveryRead, tenantID, "deliveries"); err != nil { return DeliveryPage{}, err }
	return service.repository.ListDueDeliveries(ctx, tenantID, request)
}

func (service *Service) UpsertDelivery(ctx context.Context, actor Actor, state DeliveryState, expectedRevision uint64) (DeliveryState, error) {
	if err := service.authorize(ctx, actor, AuthorizeDeliveryWrite, state.TenantID, state.ID); err != nil { return DeliveryState{}, err }
	digest, digestErr := auditValueDigest(state)
	if digestErr != nil { return DeliveryState{}, digestErr }
	stored, err := service.repository.UpsertDelivery(ctx, state, expectedRevision)
	if err != nil {
		return DeliveryState{}, errors.Join(err, service.audit(ctx, AuthorizeDeliveryWrite, actor, state.TenantID, state.ID, expectedRevision, 0, "failed", digest))
	}
	auditErr := service.audit(ctx, AuthorizeDeliveryWrite, actor, stored.TenantID, stored.ID, expectedRevision, stored.Revision, "committed", digest)
	return stored, auditErr
}

func (service *Service) DeleteDelivery(ctx context.Context, actor Actor, tenantID, deliveryID string, expectedRevision uint64) error {
	if err := service.authorize(ctx, actor, AuthorizeDeliveryWrite, tenantID, deliveryID); err != nil { return err }
	digest := auditDigest(tenantID, deliveryID, strconv.FormatUint(expectedRevision, 10), "delete")
	err := service.repository.DeleteDelivery(ctx, tenantID, deliveryID, expectedRevision)
	if err != nil { return errors.Join(err, service.audit(ctx, AuthorizeDeliveryWrite, actor, tenantID, deliveryID, expectedRevision, 0, "failed", digest)) }
	return service.audit(ctx, AuthorizeDeliveryWrite, actor, tenantID, deliveryID, expectedRevision, 0, "deleted", digest)
}

func dedupResourceID(key DedupState) string {
	return hashParts("nd_", key.RuleID, strconv.FormatUint(uint64(key.Stage), 10), string(key.DestinationKind), key.DestinationID, key.DedupDigest)
}

func (service *Service) GetDedup(ctx context.Context, actor Actor, key DedupState) (DedupState, error) {
	resourceID := dedupResourceID(key)
	if err := service.authorize(ctx, actor, AuthorizeDeliveryRead, key.TenantID, resourceID); err != nil { return DedupState{}, err }
	return service.repository.GetDedup(ctx, key)
}

func (service *Service) UpsertDedup(ctx context.Context, actor Actor, state DedupState, expectedRevision uint64) (DedupState, error) {
	resourceID := dedupResourceID(state)
	if err := service.authorize(ctx, actor, AuthorizeDeliveryWrite, state.TenantID, resourceID); err != nil { return DedupState{}, err }
	digest, digestErr := auditValueDigest(state)
	if digestErr != nil { return DedupState{}, digestErr }
	stored, err := service.repository.UpsertDedup(ctx, state, expectedRevision)
	if err != nil {
		return DedupState{}, errors.Join(err, service.audit(ctx, AuthorizeDeliveryWrite, actor, state.TenantID, resourceID, expectedRevision, 0, "failed", digest))
	}
	auditErr := service.audit(ctx, AuthorizeDeliveryWrite, actor, stored.TenantID, resourceID, expectedRevision, stored.Revision, "committed", digest)
	return stored, auditErr
}

func (service *Service) DeleteDedup(ctx context.Context, actor Actor, key DedupState, expectedRevision uint64) error {
	resourceID := dedupResourceID(key)
	if err := service.authorize(ctx, actor, AuthorizeDeliveryWrite, key.TenantID, resourceID); err != nil { return err }
	digest := auditDigest(key.TenantID, resourceID, strconv.FormatUint(expectedRevision, 10), "delete")
	err := service.repository.DeleteDedup(ctx, key, expectedRevision)
	if err != nil { return errors.Join(err, service.audit(ctx, AuthorizeDeliveryWrite, actor, key.TenantID, resourceID, expectedRevision, 0, "failed", digest)) }
	return service.audit(ctx, AuthorizeDeliveryWrite, actor, key.TenantID, resourceID, expectedRevision, 0, "deleted", digest)
}
