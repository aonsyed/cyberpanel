//go:build linux

package mail

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"
)

const CampaignUnsubscribeCredentialPath = "/run/credentials/panel-core.service/marketing-unsubscribe.key"

type CampaignSubmission struct {
	CampaignID      CampaignID    `json:"campaign_id"`
	Sender          WebmailBinding `json:"sender"`
	Recipient       Address       `json:"recipient"`
	ReplyTo         Address       `json:"reply_to,omitempty"`
	Subject         string        `json:"subject"`
	Text            string        `json:"text"`
	SanitizedHTML   string        `json:"sanitized_html"`
	UnsubscribeURL  string        `json:"unsubscribe_url"`
	IdempotencyKey  string        `json:"idempotency_key"`
}

func (submission CampaignSubmission) Validate() error {
	if !validOpaque(string(submission.CampaignID)) || submission.Sender.Validate() != nil || ValidateAddress(submission.Recipient) != nil || submission.ReplyTo != "" && ValidateAddress(submission.ReplyTo) != nil || submission.Subject == "" || len(submission.Subject) > 998 || strings.ContainsAny(submission.Subject, "\x00\r\n") || submission.Text == "" || len(submission.Text) > maximumCampaignTemplateBytes || len(submission.SanitizedHTML) > maximumCampaignTemplateBytes || strings.ContainsRune(submission.Text+submission.SanitizedHTML, '\x00') || !validHTTPSURL(submission.UnsubscribeURL) || !validOpaque(submission.IdempotencyKey) {
		return ErrInvalidCommand
	}
	return nil
}

type LocalCampaignSender struct {
	Store     MarketingStore
	Control   SQLControlRepository
	Delivery  DeliveryPolicyStore
	Directory SQLWebmailDirectory
	Client    *MailDaemonClient
	Signer    UnsubscribeSigner
	Now       func() time.Time
}

func NewLocalCampaignSender(store MarketingStore, control SQLControlRepository, delivery DeliveryPolicyStore, serverName string, unsubscribeKey []byte, unsubscribeBaseURL string) (*LocalCampaignSender, error) {
	if store.DB == nil || control.DB == nil || delivery.DB == nil || delivery.ResolveLimit == nil || !validHostname(serverName) || len(unsubscribeKey) != 32 || !validHTTPSURL(unsubscribeBaseURL) {
		return nil, ErrInvalidCommand
	}
	parsed, err := url.Parse(unsubscribeBaseURL)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrInvalidCommand
	}
	key := append([]byte(nil), unsubscribeKey...)
	return &LocalCampaignSender{
		Store:store, Control:control, Delivery:delivery,
		Directory:SQLWebmailDirectory{Store:control, ServerName:serverName},
		Client:NewLocalMailDaemonClient(),
		Signer:UnsubscribeSigner{KeyID:"campaign-v1", Key:key, BaseURL:strings.TrimSuffix(unsubscribeBaseURL, "/")},
	}, nil
}

func (sender *LocalCampaignSender) SubmitCampaign(ctx context.Context, tenant string, campaign Campaign, contact CampaignRecipient, idempotencyKey string) (QueueID, error) {
	if sender == nil || sender.Client == nil || ctx == nil || !validOpaque(tenant) || validateCampaignRecord(tenant, campaign) != nil || campaign.State != "running" || validateCampaignRecipient(contact) != nil || !validOpaque(idempotencyKey) {
		return "", ErrInvalidCommand
	}
	template, err := sender.currentCampaignTemplate(ctx, tenant, campaign)
	if err != nil { return "", err }
	binding, domain, err := sender.resolveSender(ctx, tenant, campaign.FromMailbox)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if sender.Now != nil {
		now = sender.Now().UTC()
	}
	token, err := sender.Signer.Issue(tenant, campaign.ID, contact.ContactID, contact.Address, now.Add(180*24*time.Hour))
	if err != nil {
		return "", err
	}
	unsubscribeURL := sender.Signer.BaseURL + "?token=" + url.QueryEscape(token)
	text, htmlBody, err := RenderCampaignTemplate(template, CampaignTemplateVariables{ContactID:contact.ContactID, Address:contact.Address, UnsubscribeURL:unsubscribeURL})
	if err != nil {
		return "", err
	}
	messageBytes := uint64(len(campaign.Subject) + len(text) + len(htmlBody) + len(unsubscribeURL) + 4096)
	decision, err := sender.Delivery.CheckAndReserve(ctx, DeliveryRequest{ID:idempotencyKey, TenantID:tenant, DomainID:domain.ID, MailboxID:campaign.FromMailbox, Authenticated:true, ClientIP:"127.0.0.1", EnvelopeFrom:binding.Address, Recipients:[]Address{contact.Address}, MessageBytes:messageBytes, At:now})
	if err != nil {
		return "", err
	}
	if decision.Decision != DeliveryPermit {
		return "", ErrRateLimited
	}
	// This second lookup is intentionally adjacent to the privileged broker
	// call: an unsubscribe or complaint that raced rendering/admission wins.
	consent, consentFound, err := sender.Store.CurrentConsent(ctx, tenant, contact.Address)
	if err != nil {
		return "", err
	}
	if !consentFound || consent.State != Consented || consent.ContactID != contact.ContactID {
		return "", ErrSuppressed
	}
	// Re-read both mutable stop signals immediately beside submission. A pause,
	// cancellation, campaign generation change, or template archive wins the
	// race without sending another message.
	if _, err = sender.currentCampaignTemplate(ctx, tenant, campaign); err != nil { return "", err }
	submission := CampaignSubmission{CampaignID:campaign.ID, Sender:binding, Recipient:contact.Address, ReplyTo:campaign.ReplyTo, Subject:campaign.Subject, Text:text, SanitizedHTML:htmlBody, UnsubscribeURL:unsubscribeURL, IdempotencyKey:idempotencyKey}
	return sender.Client.SubmitCampaign(ctx, submission)
}

func (sender *LocalCampaignSender) currentCampaignTemplate(ctx context.Context, tenant string, expected Campaign) (CampaignTemplate, error) {
	current, found, err := sender.Store.Campaign(ctx, tenant, expected.ID)
	if err != nil { return CampaignTemplate{}, err }
	if !found { return CampaignTemplate{}, ErrCampaignStopped }
	if current.State == "paused" { return CampaignTemplate{}, ErrCampaignPaused }
	if current.State != "running" || current.Generation != expected.Generation || current.SnapshotRef != expected.SnapshotRef || current.TemplateRef != expected.TemplateRef {
		return CampaignTemplate{}, ErrCampaignStopped
	}
	template, found, err := sender.Store.ApprovedTemplateVersion(ctx, tenant, current.TemplateRef)
	if errors.Is(err, ErrConflict) || err == nil && !found { return CampaignTemplate{}, ErrCampaignStopped }
	if err != nil { return CampaignTemplate{}, err }
	return template, nil
}

func (sender *LocalCampaignSender) resolveSender(ctx context.Context, tenant string, mailboxID MailboxID) (WebmailBinding, Domain, error) {
	binding, err := sender.Directory.ResolveWebmailBinding(ctx, tenant, mailboxID)
	if err != nil {
		return WebmailBinding{}, Domain{}, err
	}
	mailboxResource, found, err := sender.Control.Load(ctx, tenant, ResourceMailbox, string(mailboxID))
	if err != nil {
		return WebmailBinding{}, Domain{}, err
	}
	if !found || mailboxResource.State != StateActive {
		return WebmailBinding{}, Domain{}, ErrNotFound
	}
	var mailbox Mailbox
	if err = strictJSON(mailboxResource.Spec, &mailbox); err != nil || mailbox.ID != mailboxID || mailbox.Domain == "" || !mailbox.Enabled {
		return WebmailBinding{}, Domain{}, errors.Join(ErrInvalidReceipt, err)
	}
	domainResource, found, err := sender.Control.Load(ctx, tenant, ResourceDomain, string(mailbox.Domain))
	if err != nil {
		return WebmailBinding{}, Domain{}, err
	}
	if !found || domainResource.State != StateActive {
		return WebmailBinding{}, Domain{}, ErrNotFound
	}
	var domain Domain
	if err = strictJSON(domainResource.Spec, &domain); err != nil || domain.ID != mailbox.Domain || domain.Tenant != tenant || !domain.DKIM.Enabled || domain.DKIM.Selector == "" || domain.DKIM.PublicKey == "" || domain.DKIM.PrivateKeyRef == "" {
		return WebmailBinding{}, Domain{}, errors.Join(ErrInvalidReceipt, err)
	}
	return binding, domain, nil
}

func LoadCampaignUnsubscribeCredential(path string) ([]byte, error) {
	if path != CampaignUnsubscribeCredentialPath {
		return nil, ErrInvalidCommand
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		return nil, ErrUnauthorized
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(content) != 32 {
		wipeMailBytes(content)
		return nil, ErrUnauthorized
	}
	return content, nil
}

var _ MarketingSender = (*LocalCampaignSender)(nil)
