// Package mail contains the durable control-plane model for hosted mail.
package mail

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type DomainID string; type MailboxID string; type AliasID string; type PolicyID string; type QueueID string; type EventID string; type ContactID string; type ListID string; type CampaignID string; type CampaignTemplateID string; type AttemptID string
type Address string; type Capability string
const ( CapabilityPlus Capability = "plus"; CapabilityPattern Capability = "pattern"; CapabilityPipe Capability = "pipe" )
type Domain struct { ID DomainID `json:"id"`; Name string `json:"name"`; Tenant string `json:"tenant"`; DKIM DKIM `json:"dkim"`; Relay Relay `json:"relay"`; Policy PolicyID `json:"policy"` }
type Mailbox struct { ID MailboxID `json:"id"`; Domain DomainID `json:"domain"`; Local string `json:"local"`; QuotaBytes uint64 `json:"quota_bytes"`; Enabled bool `json:"enabled"` }
type Alias struct { ID AliasID `json:"id"`; Domain DomainID `json:"domain"`; Source Address `json:"source"`; Targets []Address `json:"targets"`; CatchAll bool `json:"catch_all"`; Capability Capability `json:"capability,omitempty"`; PipeRef string `json:"pipe_ref,omitempty"` }
type Policy struct { ID PolicyID `json:"id"`; MaxMailboxBytes uint64 `json:"max_mailbox_bytes"`; MaxRecipients uint32 `json:"max_recipients"`; SpamThreshold float64 `json:"spam_threshold"`; RetainDays uint32 `json:"retain_days"`; Log LogPolicy `json:"log"` }
type DKIM struct { Selector string `json:"selector"`; PublicKey string `json:"public_key"`; PrivateKeyRef string `json:"private_key_ref"`; Enabled bool `json:"enabled"` }
type Relay struct { Host string `json:"host"`; Port uint16 `json:"port"`; CredentialRef string `json:"credential_ref"`; RequiredTLS bool `json:"required_tls"` }
type QueueItem struct { ID QueueID `json:"id"`; EnvelopeFrom Address `json:"from"`; Recipients []Address `json:"recipients"`; State string `json:"state"`; Attempts uint32 `json:"attempts"`; NextAttempt time.Time `json:"next_attempt"` }
type Event struct { ID EventID `json:"id"`; Queue QueueID `json:"queue"`; Kind string `json:"kind"`; At time.Time `json:"at"`; Data map[string]string `json:"data"` }
type LogPolicy struct { RetainDays uint32 `json:"retain_days"`; RedactBodies bool `json:"redact_bodies"`; AuditDeliveries bool `json:"audit_deliveries"` }

// Executors intentionally accept closed desired-state values, never shell text.
type Postfix interface { ApplyDomain(context.Context, Domain, []Mailbox, []Alias, Policy) error; Queue(context.Context, QueueItem) error }
type Dovecot interface { ApplyMailbox(context.Context, Mailbox, Policy) error }
type Rspamd interface { ApplyPolicy(context.Context, Domain, Policy) error }
type OpenDKIM interface { ApplyKey(context.Context, Domain, DKIM) error }

const Schema = `CREATE TABLE IF NOT EXISTS mail_domains (id TEXT PRIMARY KEY, domain_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS mail_mailboxes (id TEXT PRIMARY KEY, domain_id TEXT NOT NULL, mailbox_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS mail_aliases (id TEXT PRIMARY KEY, domain_id TEXT NOT NULL, alias_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS mail_policies (id TEXT PRIMARY KEY, policy_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS mail_queue (id TEXT PRIMARY KEY, queue_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS mail_events (id TEXT PRIMARY KEY, queue_id TEXT NOT NULL, event_json TEXT NOT NULL);`
type Repository struct { DB *sql.DB }
func (r Repository) Bootstrap(ctx context.Context) error { if r.DB == nil { return errors.New("mail database required") }; _, err := r.DB.ExecContext(ctx, Schema); return err }
func (r Repository) PutDomain(ctx context.Context, domain Domain, policy Policy) error { return r.put(ctx, `INSERT INTO mail_domains (id, domain_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET domain_json = excluded.domain_json`, domain.ID, domain) }
func (r Repository) PutMailbox(ctx context.Context, mailbox Mailbox) error { if mailbox.ID == "" || mailbox.Domain == "" { return errors.New("invalid mailbox") }; return r.put(ctx, `INSERT INTO mail_mailboxes (id, domain_id, mailbox_json) VALUES (?, ?, ?) ON CONFLICT (id) DO UPDATE SET mailbox_json = excluded.mailbox_json`, mailbox.ID, mailbox.Domain, mailbox) }
func (r Repository) PutAlias(ctx context.Context, alias Alias) error { if alias.ID == "" || alias.Domain == "" || len(alias.Targets) == 0 { return errors.New("invalid alias") }; return r.put(ctx, `INSERT INTO mail_aliases (id, domain_id, alias_json) VALUES (?, ?, ?) ON CONFLICT (id) DO UPDATE SET alias_json = excluded.alias_json`, alias.ID, alias.Domain, alias) }
func (r Repository) PutPolicy(ctx context.Context, policy Policy) error { return r.put(ctx, `INSERT INTO mail_policies (id, policy_json) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET policy_json = excluded.policy_json`, policy.ID, policy) }
func (r Repository) Enqueue(ctx context.Context, item QueueItem) error { return r.put(ctx, `INSERT INTO mail_queue (id, queue_json) VALUES (?, ?)`, item.ID, item) }
func (r Repository) Record(ctx context.Context, event Event) error { return r.put(ctx, `INSERT INTO mail_events (id, queue_id, event_json) VALUES (?, ?, ?)`, event.ID, event.Queue, event) }
func (r Repository) put(ctx context.Context, query string, values ...any) error { if r.DB == nil { return errors.New("mail database required") }; last := len(values)-1; raw, err := json.Marshal(values[last]); if err != nil { return err }; values[last] = raw; _, err = r.DB.ExecContext(ctx, query, values...); return err }
type Service struct { Store Repository; Postfix Postfix; Dovecot Dovecot; Rspamd Rspamd; OpenDKIM OpenDKIM }
func (s Service) Provision(ctx context.Context, domain Domain, policy Policy, mailboxes []Mailbox, aliases []Alias) error { if s.Postfix == nil || s.Dovecot == nil || s.Rspamd == nil || s.OpenDKIM == nil { return errors.New("mail executors required") }; if err := s.Store.PutPolicy(ctx, policy); err != nil { return err }; if err := s.Store.PutDomain(ctx, domain, policy); err != nil { return err }; for _, mailbox := range mailboxes { if err := s.Store.PutMailbox(ctx, mailbox); err != nil { return err }; if err := s.Dovecot.ApplyMailbox(ctx, mailbox, policy); err != nil { return err } }; for _, alias := range aliases { if err := s.Store.PutAlias(ctx, alias); err != nil { return err } }; if err := s.OpenDKIM.ApplyKey(ctx, domain, domain.DKIM); err != nil { return err }; if err := s.Rspamd.ApplyPolicy(ctx, domain, policy); err != nil { return err }; return s.Postfix.ApplyDomain(ctx, domain, mailboxes, aliases, policy) }

type FolderID string; type MessageID string; type AttachmentID string; type DraftID string; type SieveID string; type GroupID string
type Folder struct { ID FolderID `json:"id"`; Mailbox MailboxID `json:"mailbox"`; Name string `json:"name"` }
type Message struct { ID MessageID `json:"id"`; Folder FolderID `json:"folder"`; Subject string `json:"subject"`; From Address `json:"from"`; To []Address `json:"to"`; Flags []string `json:"flags"`; ReceivedAt time.Time `json:"received_at"` }
type Attachment struct { ID AttachmentID `json:"id"`; Message MessageID `json:"message"`; Name string `json:"name"`; BlobRef string `json:"blob_ref"` }
type Draft struct { ID DraftID `json:"id"`; Mailbox MailboxID `json:"mailbox"`; RawRef string `json:"raw_ref"` }
type Contact struct { ID ContactID `json:"id"`; Mailbox MailboxID `json:"mailbox"`; Name string `json:"name"`; Addresses []Address `json:"addresses"` }
type Group struct { ID GroupID `json:"id"`; Mailbox MailboxID `json:"mailbox"`; Name string `json:"name"`; Contacts []ContactID `json:"contacts"` }
type SieveRule struct { ID SieveID `json:"id"`; Mailbox MailboxID `json:"mailbox"`; Script string `json:"script"`; Active bool `json:"active"` }
type Webmail interface { Folders(context.Context, MailboxID) ([]Folder, error); Search(context.Context, MailboxID, string) ([]Message, error); Message(context.Context, MessageID) (Message, error); Attachments(context.Context, MessageID) ([]Attachment, error); SaveDraft(context.Context, Draft) error; Send(context.Context, DraftID) error; Move(context.Context, MessageID, FolderID) error; SetFlags(context.Context, MessageID, []string) error; Contacts(context.Context, MailboxID) ([]Contact, error); Groups(context.Context, MailboxID) ([]Group, error); PutSieve(context.Context, SieveRule) error }

type ConsentState string; const ( Consented ConsentState = "consented"; Suppressed ConsentState = "suppressed" )
type SubscriberState string; const ( SubscriberActive SubscriberState = "active"; SubscriberArchived SubscriberState = "archived" )
type VerificationState string; const ( VerificationUnverified VerificationState = "unverified"; VerificationVerified VerificationState = "verified"; VerificationInvalid VerificationState = "invalid"; VerificationRisky VerificationState = "risky"; VerificationUnknown VerificationState = "unknown" )
type Subscriber struct { ID ContactID `json:"id"`; Address Address `json:"address"`; Name string `json:"name,omitempty"`; Tags []string `json:"tags,omitempty"`; State SubscriberState `json:"state"`; Verification VerificationState `json:"verification"`; VerificationRef string `json:"verification_ref,omitempty"`; Generation uint64 `json:"generation"`; CreatedAt time.Time `json:"created_at"`; UpdatedAt time.Time `json:"updated_at"` }
type Suppression struct { Address Address `json:"address"`; Reason string `json:"reason"`; At time.Time `json:"at"` }
type List struct { ID ListID `json:"id"`; Name string `json:"name"`; Contacts []ContactID `json:"contacts"` }
type CampaignTemplate struct { ID CampaignTemplateID `json:"id"`; Name string `json:"name"`; Text string `json:"text"`; State string `json:"state"`; Generation uint64 `json:"generation"`; UpdatedAt time.Time `json:"updated_at"` }
type CampaignRecipient struct { ContactID ContactID `json:"contact_id"`; Address Address `json:"address"`; SubscriberGeneration uint64 `json:"subscriber_generation"`; ConsentEventID string `json:"consent_event_id"` }
type CampaignSnapshot struct { ID string `json:"id"`; CampaignID CampaignID `json:"campaign_id"`; ListID ListID `json:"list_id"`; ListDigest string `json:"list_digest"`; RecipientDigest string `json:"recipient_digest"`; Requested uint64 `json:"requested"`; Eligible uint64 `json:"eligible"`; Excluded map[string]uint64 `json:"excluded"`; CreatedAt time.Time `json:"created_at"`; ApprovedBy string `json:"approved_by"` }
type Campaign struct { ID CampaignID `json:"id"`; List ListID `json:"list"`; Subject string `json:"subject"`; TemplateRef string `json:"template_ref"`; FromMailbox MailboxID `json:"from_mailbox"`; ReplyTo Address `json:"reply_to,omitempty"`; Schedule string `json:"schedule,omitempty"`; SnapshotRef string `json:"snapshot_ref,omitempty"`; RecipientCount uint64 `json:"recipient_count,omitempty"`; ApprovedAt *time.Time `json:"approved_at,omitempty"`; ApprovedBy string `json:"approved_by,omitempty"`; State string `json:"state"`; Generation uint64 `json:"generation"` }
type Attempt struct { ID AttemptID `json:"id"`; Campaign CampaignID `json:"campaign"`; Contact ContactID `json:"contact"`; State string `json:"state"`; At time.Time `json:"at"` }
