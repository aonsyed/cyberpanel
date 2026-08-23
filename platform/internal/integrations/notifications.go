package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type NotificationCoordinator struct { Store Store; Provider NotificationProvider; Signer NotificationSigner; Now func() time.Time; MaximumAttempts uint32; BaseRetry time.Duration }
func (coordinator NotificationCoordinator) now() time.Time { if coordinator.Now != nil { return coordinator.Now().UTC() }; return time.Now().UTC() }

type NotificationTarget struct { SMTP *SMTPNotificationTarget `json:"smtp,omitempty"`; Webhook *WebhookNotificationTarget `json:"webhook,omitempty"` }

func (coordinator NotificationCoordinator) Enqueue(ctx context.Context, notification Notification, route NotificationRoute, attemptID DeliveryID) (NotificationAttempt, bool, error) {
	if coordinator.Store == nil || errIs(notification.Validate()) { return NotificationAttempt{}, false, ErrInvalid }
	if !route.Enabled || !validID(string(route.ID)) || !validID(string(route.BindingID)) || route.Generation == 0 || route.RatePerHour == 0 { return NotificationAttempt{}, false, ErrPolicyDenied }
	persisted, created, err := coordinator.Store.CreateNotification(ctx, notification); if err != nil { return NotificationAttempt{}, false, err }; if !created && persisted.DataDigest != notification.DataDigest { return NotificationAttempt{}, false, ErrConflict }
	attempt := NotificationAttempt{ID: attemptID, NotificationID: persisted.ID, RouteID: route.ID, BindingID: route.BindingID, Attempt: 0, IdempotencyKey: string(persisted.ID)+":"+string(route.ID), State: AttemptPending, NextAttemptAt: coordinator.now(), CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	if err := coordinator.Store.CreateNotificationAttempt(ctx, attempt); err != nil { existing, loadErr := coordinator.Store.LoadNotificationAttempt(ctx, attemptID); if loadErr == nil && existing.NotificationID == attempt.NotificationID && existing.RouteID == attempt.RouteID { return existing, false, nil }; return NotificationAttempt{}, false, err }
	return attempt, true, nil
}

func (coordinator NotificationCoordinator) Deliver(ctx context.Context, attemptID DeliveryID, notification Notification, target NotificationTarget) (NotificationAttempt, error) {
	if coordinator.Store == nil || coordinator.Provider == nil || coordinator.Signer == nil { return NotificationAttempt{}, ErrInvalid }
	attempt, err := coordinator.Store.LoadNotificationAttempt(ctx, attemptID); if err != nil { return NotificationAttempt{}, err }; if attempt.State == AttemptDelivered { return attempt, nil }; if attempt.State == AttemptFailed || attempt.State == AttemptExpired { return NotificationAttempt{}, ErrConflict }
	if !attempt.NextAttemptAt.IsZero() && coordinator.now().Before(attempt.NextAttemptAt) { return NotificationAttempt{}, ErrRateLimited }
	binding, err := coordinator.Store.LoadBinding(ctx, attempt.BindingID); if err != nil { return NotificationAttempt{}, err }; if binding.State != BindingActive || binding.Kind != ProviderNotificationSMTP && binding.Kind != ProviderNotificationWebhook { return NotificationAttempt{}, ErrPolicyDenied }
	body, err := json.Marshal(notification); if err != nil { return NotificationAttempt{}, err }; bodyDigest, err := digest(notification); if err != nil { return NotificationAttempt{}, err }
	audience := "notification.smtp"; var keyRef SecretRef; var keyVersion uint64
	if target.Webhook != nil { audience, keyRef, keyVersion = target.Webhook.Audience, target.Webhook.SigningKeyRef, target.Webhook.KeyVersion } else { keyRef, keyVersion = binding.SecretRef, binding.SecretVersion }
	signature, keyID, err := coordinator.Signer.SignNotification(ctx, keyRef, keyVersion, body); if err != nil { return NotificationAttempt{}, err }
	envelope := NotificationEnvelope{DeliveryID: attempt.ID, Notification: notification, Audience: audience, IssuedAt: coordinator.now(), ExpiresAt: coordinator.now().Add(5*time.Minute), BodyDigest: bodyDigest, Signature: signature, SigningKeyID: keyID, SigningKeyVersion: keyVersion}
	attempt.State, attempt.Attempt, attempt.UpdatedAt = AttemptDelivering, attempt.Attempt+1, coordinator.now(); if err := coordinator.Store.UpdateNotificationAttempt(ctx, attempt); err != nil { return NotificationAttempt{}, err }
	var receipt NotificationReceipt
	if target.Webhook != nil && binding.Kind == ProviderNotificationWebhook { if err := target.Webhook.Endpoint.Validate(); err != nil { return NotificationAttempt{}, err }; receipt, err = coordinator.Provider.DeliverWebhook(ctx, binding, *target.Webhook, envelope) } else if target.SMTP != nil && binding.Kind == ProviderNotificationSMTP { receipt, err = coordinator.Provider.DeliverSMTP(ctx, binding, *target.SMTP, envelope) } else { return NotificationAttempt{}, ErrConflict }
	if err != nil { return coordinator.retry(ctx, attempt, notification, err) }
	if receipt.DeliveryID != attempt.ID || receipt.ProviderReceipt == "" || !validDigest(receipt.ReceiptDigest) || receipt.DeliveredAt.IsZero() { return coordinator.retry(ctx, attempt, notification, ErrIntegrity) }
	attempt.State, attempt.ProviderReceipt, attempt.NextAttemptAt, attempt.UpdatedAt = AttemptDelivered, receipt.ProviderReceipt, time.Time{}, coordinator.now(); if err := coordinator.Store.UpdateNotificationAttempt(ctx, attempt); err != nil { return NotificationAttempt{}, err }; return attempt, nil
}

func (coordinator NotificationCoordinator) retry(ctx context.Context, attempt NotificationAttempt, notification Notification, cause error) (NotificationAttempt, error) { maximum := coordinator.MaximumAttempts; if maximum == 0 { maximum = 8 }; if !notification.ExpiresAt.IsZero() && !coordinator.now().Before(notification.ExpiresAt) { attempt.State, attempt.Failure, attempt.NextAttemptAt, attempt.UpdatedAt = AttemptExpired, cause.Error(), time.Time{}, coordinator.now() } else if attempt.Attempt >= maximum { attempt.State, attempt.Failure, attempt.NextAttemptAt, attempt.UpdatedAt = AttemptFailed, cause.Error(), time.Time{}, coordinator.now() } else { base := coordinator.BaseRetry; if base <= 0 { base = 30*time.Second }; delay := base*time.Duration(1<<minUint32(attempt.Attempt-1, 10)); var providerError *ProviderError; if errors.As(cause, &providerError) && providerError.RetryAfter > delay { delay = providerError.RetryAfter }; attempt.State, attempt.Failure, attempt.NextAttemptAt, attempt.UpdatedAt = AttemptRetry, cause.Error(), coordinator.now().Add(delay), coordinator.now() }; _ = coordinator.Store.UpdateNotificationAttempt(ctx, attempt); return attempt, cause }
func minUint32(left, right uint32) uint32 { if left < right { return left }; return right }
func errIs(err error) bool { return err != nil }

type RelayCoordinator struct { Store Store; Provider MailRelayProvider; Now func() time.Time }
func (coordinator RelayCoordinator) Deliver(ctx context.Context, binding ProviderBinding, configuration MailRelayBinding, effect ProviderEffect, message RelayMessage) (RelayReceipt, error) { if coordinator.Store == nil || coordinator.Provider == nil || binding.Kind != ProviderExternalMail || binding.State != BindingActive { return RelayReceipt{}, ErrPolicyDenied }; if err := configuration.Validate(); err != nil { return RelayReceipt{}, err }; if configuration.BindingID != binding.ID || !validID(string(message.DeliveryID)) || !validID(string(message.TenantID)) || !validDigest(message.MessageDigest) || !validID(message.IdempotencyKey) || len(message.EnvelopeTo) == 0 || message.Size <= 0 { return RelayReceipt{}, ErrInvalid }; effect.RequestDigest, effect.State, effect.CreatedAt, effect.UpdatedAt = message.MessageDigest, EffectAdmitted, time.Now().UTC(), time.Now().UTC(); effect, created, err := coordinator.Store.AdmitEffect(ctx, effect); if err != nil { return RelayReceipt{}, err }; if !created { return RelayReceipt{}, ErrConflict }; receipt, err := coordinator.Provider.Deliver(ctx, binding, configuration, message); if err != nil { effect.State, effect.Failure, effect.UpdatedAt = classifyEffect(err), err.Error(), time.Now().UTC(); _ = coordinator.Store.UpdateEffect(ctx, effect); return RelayReceipt{}, err }; if receipt.DeliveryID != message.DeliveryID || !validDigest(receipt.ReceiptDigest) { return RelayReceipt{}, ErrIntegrity }; effect.State, effect.OutputDigest, effect.ProviderReceipt, effect.UpdatedAt = EffectCommitted, receipt.ReceiptDigest, receipt.ProviderMessageID, time.Now().UTC(); if err := coordinator.Store.UpdateEffect(ctx, effect); err != nil { return RelayReceipt{}, err }; return receipt, nil }

type ImunifyCoordinator struct { Store Store; Provider ImunifyProvider; Now func() time.Time }
func (coordinator ImunifyCoordinator) Apply(ctx context.Context, binding ProviderBinding, effect ProviderEffect, action ImunifyAction) (ImunifyReceipt, error) { if coordinator.Store == nil || coordinator.Provider == nil || binding.Kind != ProviderImunify || binding.State != BindingActive { return ImunifyReceipt{}, ErrPolicyDenied }; if err := ValidateImunifyAction(action); err != nil { return ImunifyReceipt{}, err }; requestDigest, _ := digest(action); effect.RequestDigest, effect.State, effect.CreatedAt, effect.UpdatedAt = requestDigest, EffectAdmitted, time.Now().UTC(), time.Now().UTC(); effect, created, err := coordinator.Store.AdmitEffect(ctx, effect); if err != nil { return ImunifyReceipt{}, err }; if !created { return ImunifyReceipt{}, ErrConflict }; receipt, err := coordinator.Provider.ApplyAction(ctx, binding, action); if err != nil { effect.State, effect.Failure, effect.UpdatedAt = classifyEffect(err), err.Error(), time.Now().UTC(); _ = coordinator.Store.UpdateEffect(ctx, effect); return ImunifyReceipt{}, err }; if receipt.EffectID != effect.ID || !validDigest(receipt.OutputDigest) || receipt.CompletedAt.IsZero() { return ImunifyReceipt{}, fmt.Errorf("%w: Imunify receipt", ErrIntegrity) }; effect.State, effect.OutputDigest, effect.ProviderReceipt, effect.UpdatedAt = EffectCommitted, receipt.OutputDigest, receipt.ProviderObjectID, time.Now().UTC(); if err := coordinator.Store.UpdateEffect(ctx, effect); err != nil { return ImunifyReceipt{}, err }; return receipt, nil }
