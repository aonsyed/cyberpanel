package mail

import (
	"context"
	"errors"
)

// ControlDeliveryLimitResolver binds Postfix and campaign admission to the
// same tenant-scoped mailbox/domain/policy projection. The defaults are hard
// ceilings; a domain policy may only reduce the per-message recipient bound.
func ControlDeliveryLimitResolver(store SQLControlRepository, defaults DeliveryLimit) func(context.Context, string, DomainID, MailboxID) (DeliveryLimit, error) {
	return func(ctx context.Context, tenant string, domainID DomainID, mailboxID MailboxID) (DeliveryLimit, error) {
		if store.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(domainID)) || !validOpaque(string(mailboxID)) || defaults.MaxMessageBytes == 0 || defaults.MaxRecipientsPerMessage == 0 {
			return DeliveryLimit{}, ErrInvalidCommand
		}
		mailboxResource, found, err := store.Load(ctx, tenant, ResourceMailbox, string(mailboxID))
		if err != nil {
			return DeliveryLimit{}, err
		}
		if !found || mailboxResource.State != StateActive {
			return DeliveryLimit{}, ErrNotFound
		}
		var mailbox Mailbox
		if err = strictJSON(mailboxResource.Spec, &mailbox); err != nil || mailbox.ID != mailboxID || mailbox.Domain != domainID || !mailbox.Enabled {
			return DeliveryLimit{}, errors.Join(ErrInvalidReceipt, err)
		}
		domainResource, found, err := store.Load(ctx, tenant, ResourceDomain, string(domainID))
		if err != nil {
			return DeliveryLimit{}, err
		}
		if !found || domainResource.State != StateActive {
			return DeliveryLimit{}, ErrNotFound
		}
		var domain Domain
		if err = strictJSON(domainResource.Spec, &domain); err != nil || domain.ID != domainID || domain.Tenant != tenant || domain.Policy == "" {
			return DeliveryLimit{}, errors.Join(ErrInvalidReceipt, err)
		}
		policyResource, found, err := store.Load(ctx, tenant, ResourcePolicy, string(domain.Policy))
		if err != nil {
			return DeliveryLimit{}, err
		}
		if !found || policyResource.State != StateActive {
			return DeliveryLimit{}, ErrNotFound
		}
		var policy Policy
		if err = strictJSON(policyResource.Spec, &policy); err != nil || policy.ID != domain.Policy || policy.MaxRecipients == 0 {
			return DeliveryLimit{}, errors.Join(ErrInvalidReceipt, err)
		}
		limit := defaults
		if policy.MaxRecipients < limit.MaxRecipientsPerMessage {
			limit.MaxRecipientsPerMessage = policy.MaxRecipients
		}
		return limit, nil
	}
}

