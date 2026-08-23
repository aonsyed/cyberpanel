package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

type UnsubscribeService struct {
	Store  MarketingStore
	Signer UnsubscribeSigner
	Now    func() time.Time
}

func (service *UnsubscribeService) Honor(ctx context.Context, token string) (ConsentEvent, error) {
	if service == nil || service.Store.DB == nil || ctx == nil || len(token) < 32 || len(token) > 4096 {
		return ConsentEvent{}, ErrInvalidCommand
	}
	tenant, _, contact, address, err := service.Signer.Verify(token)
	if err != nil {
		return ConsentEvent{}, err
	}
	current, found, err := service.Store.CurrentConsent(ctx, tenant, address)
	if err != nil {
		return ConsentEvent{}, err
	}
	if found && current.State == Suppressed && current.SuppressionReason == SuppressionUnsubscribe && current.ContactID == contact {
		return current, nil
	}
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	priorID := "none"
	if found {
		priorID = current.ID
	}
	digest := sha256.Sum256([]byte("cyberpanel-unsubscribe-event-v1\x00" + token + "\x00" + priorID))
	event := ConsentEvent{
		ID:"unsubscribe_" + hex.EncodeToString(digest[:24]), TenantID:tenant,
		ContactID:contact, Address:address, State:Suppressed,
		SuppressionReason:SuppressionUnsubscribe,
		EvidenceRef:"unsubscribe_" + hex.EncodeToString(digest[:]), At:now,
	}
	if err = service.Store.RecordConsent(ctx, event); err != nil {
		latest, latestFound, loadErr := service.Store.CurrentConsent(ctx, tenant, address)
		if loadErr == nil && latestFound && latest.ID == event.ID && latest.State == event.State && latest.ContactID == event.ContactID {
			return latest, nil
		}
		return ConsentEvent{}, errors.Join(err, loadErr)
	}
	return event, nil
}

