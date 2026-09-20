package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type ArtifactRole string

const (
	ArtifactPostfixMain            ArtifactRole = "postfix_main"
	ArtifactPostfixMaster          ArtifactRole = "postfix_master"
	ArtifactPostfixTLSMap          ArtifactRole = "postfix_tls_map"
	ArtifactPostfixRelay           ArtifactRole = "postfix_relay_transport"
	ArtifactPostfixRelayTLS        ArtifactRole = "postfix_relay_tls_policy"
	ArtifactPostfixStaticDomains   ArtifactRole = "postfix_static_domains"
	ArtifactPostfixStaticMailboxes ArtifactRole = "postfix_static_mailboxes"
	ArtifactPostfixStaticAliases   ArtifactRole = "postfix_static_aliases"
	ArtifactDovecot                ArtifactRole = "dovecot"
	ArtifactRspamd                 ArtifactRole = "rspamd"
	ArtifactRspamdRedis            ArtifactRole = "rspamd_redis"
	ArtifactRspamdAntivirus        ArtifactRole = "rspamd_antivirus"
	ArtifactRspamdMilter           ArtifactRole = "rspamd_milter"
	ArtifactOpenDKIM               ArtifactRole = "opendkim"
	ArtifactOpenDKIMKeyTable       ArtifactRole = "opendkim_key_table"
	ArtifactOpenDKIMSigningTable   ArtifactRole = "opendkim_signing_table"
	ArtifactOpenDKIMTrustedHosts   ArtifactRole = "opendkim_trusted_hosts"
	ArtifactRedis                  ArtifactRole = "redis"
	ArtifactClamAV                 ArtifactRole = "clamav"
)

type ConfigArtifact struct {
	Role    ArtifactRole `json:"role"`
	Key     string       `json:"key"`
	Mode    uint32       `json:"mode"`
	Content []byte       `json:"content"`
	SHA256  string       `json:"sha256"`
}
type ConfigGeneration struct {
	ID                 string           `json:"id"`
	NodeID             string           `json:"node_id"`
	SnapshotGeneration uint64           `json:"snapshot_generation"`
	Digest             string           `json:"digest"`
	Snapshot           ConfigSnapshot   `json:"snapshot"`
	Artifacts          []ConfigArtifact `json:"artifacts"`
}
type TLSMaterial struct {
	Key       string   `json:"key"`
	Hostnames []string `json:"hostnames"`
}
type DomainProjection struct {
	Domain    Domain      `json:"domain"`
	Policy    Policy      `json:"policy"`
	Mailboxes []Mailbox   `json:"mailboxes"`
	Aliases   []Alias     `json:"aliases"`
	TLS       TLSMaterial `json:"tls"`
}
type ConfigSnapshot struct {
	NodeID           string             `json:"node_id"`
	Generation       uint64             `json:"generation"`
	Hostname         string             `json:"hostname"`
	Postmaster       Address            `json:"postmaster"`
	MessageSizeBytes uint64             `json:"message_size_bytes"`
	Domains          []DomainProjection `json:"domains"`
}

type ConfigRenderer struct{}

func (ConfigRenderer) Render(snapshot ConfigSnapshot) (ConfigGeneration, error) {
	if err := validateSnapshot(snapshot); err != nil {
		return ConfigGeneration{}, err
	}
	normalized := normalizeSnapshot(snapshot)
	artifacts := []ConfigArtifact{
		artifact(ArtifactPostfixMain, "postfix/main.cf", 0640, renderPostfixMain(normalized)),
		artifact(ArtifactPostfixMaster, "postfix/master.cf", 0640, renderPostfixMaster()),
		artifact(ArtifactPostfixTLSMap, "postfix/tls_sni.map", 0640, renderPostfixTLS(normalized)),
		artifact(ArtifactPostfixRelay, "postfix/relay_transport.map", 0640, renderPostfixRelayTransport(normalized)),
		artifact(ArtifactPostfixRelayTLS, "postfix/relay_tls_policy.map", 0640, renderPostfixRelayTLSPolicy(normalized)),
		artifact(ArtifactPostfixStaticDomains, "postfix/static_domains.map", 0640, renderPostfixStaticDomains(normalized)),
		artifact(ArtifactPostfixStaticMailboxes, "postfix/static_mailboxes.map", 0640, renderPostfixStaticMailboxes(normalized)),
		artifact(ArtifactPostfixStaticAliases, "postfix/static_aliases.map", 0640, renderPostfixStaticAliases(normalized)),
		artifact(ArtifactDovecot, "dovecot/dovecot.conf", 0640, renderDovecot(normalized)),
		artifact(ArtifactDovecot, "dovecot/oauth2.conf", 0640, renderDovecotOAuth()),
		artifact(ArtifactRspamd, "rspamd/worker-controller.inc", 0640, renderRspamd(normalized)),
		artifact(ArtifactRspamdRedis, "rspamd/redis.conf", 0640, renderRspamdRedis()),
		artifact(ArtifactRspamdAntivirus, "rspamd/antivirus.conf", 0640, renderRspamdAntivirus()),
		artifact(ArtifactRspamdMilter, "rspamd/worker-proxy.inc", 0640, renderRspamdMilter()),
		artifact(ArtifactOpenDKIM, "opendkim/opendkim.conf", 0640, renderOpenDKIM()),
		artifact(ArtifactOpenDKIMKeyTable, "opendkim/KeyTable", 0640, renderKeyTable(normalized)),
		artifact(ArtifactOpenDKIMSigningTable, "opendkim/SigningTable", 0640, renderSigningTable(normalized)),
		artifact(ArtifactOpenDKIMTrustedHosts, "opendkim/TrustedHosts", 0640, renderOpenDKIMTrustedHosts()),
		artifact(ArtifactRedis, "redis/redis.conf", 0640, renderMailRedis()),
		artifact(ArtifactClamAV, "clamav/clamd.conf", 0640, renderClamAV(normalized)),
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Key < artifacts[j].Key })
	binding := struct {
		Version   uint8          `json:"version"`
		Snapshot  ConfigSnapshot `json:"snapshot"`
		Artifacts []struct {
			Role   ArtifactRole `json:"role"`
			Key    string       `json:"key"`
			Mode   uint32       `json:"mode"`
			SHA256 string       `json:"sha256"`
			Size   int          `json:"size"`
		} `json:"artifacts"`
	}{Version: 1, Snapshot: normalized}
	for _, item := range artifacts {
		binding.Artifacts = append(binding.Artifacts, struct {
			Role   ArtifactRole `json:"role"`
			Key    string       `json:"key"`
			Mode   uint32       `json:"mode"`
			SHA256 string       `json:"sha256"`
			Size   int          `json:"size"`
		}{item.Role, item.Key, item.Mode, item.SHA256, len(item.Content)})
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return ConfigGeneration{}, err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	return ConfigGeneration{ID: "mailgen_" + digest[:32], NodeID: normalized.NodeID, SnapshotGeneration: normalized.Generation, Digest: digest, Snapshot: normalized, Artifacts: artifacts}, nil
}

type SnapshotProjector interface {
	ProjectMail(context.Context, EffectRequest) (ConfigSnapshot, error)
}
type ConfigActivator interface {
	ObserveOrApplyMail(context.Context, EffectRequest, ConfigGeneration) (EffectReceipt, error)
}
type GenerationExecutor struct {
	Projector SnapshotProjector
	Renderer  ConfigRenderer
	Activator ConfigActivator
}

func (e GenerationExecutor) ObserveOrApply(ctx context.Context, request EffectRequest) (EffectReceipt, error) {
	if e.Projector == nil || e.Activator == nil {
		return EffectReceipt{}, errors.New("mail generation executor is incomplete")
	}
	snapshot, err := e.Projector.ProjectMail(ctx, request)
	if err != nil {
		return EffectReceipt{}, err
	}
	generation, err := e.Renderer.Render(snapshot)
	if err != nil {
		return EffectReceipt{}, err
	}
	receipt, err := e.Activator.ObserveOrApplyMail(ctx, request, generation)
	if receipt.AppliedGeneration == "" {
		receipt.AppliedGeneration = generation.Digest
	}
	return receipt, err
}

// RepositorySnapshotProjector creates the complete node mail generation from
// durable tenant resources plus the admitted effect that has not yet been
// committed. It never exposes repository SQL or host configuration paths.
type NodeSnapshotRepository interface {
	ListAll(context.Context, ResourceKind, int, string) ([]ResourceEnvelope, string, error)
}

type RepositorySnapshotProjector struct {
	Store            NodeSnapshotRepository
	NodeID           string
	Hostname         string
	Postmaster       Address
	MessageSizeBytes uint64
}

func (projector RepositorySnapshotProjector) ProjectMail(ctx context.Context, request EffectRequest) (ConfigSnapshot, error) {
	if projector.Store == nil || ctx == nil || !validOpaque(projector.NodeID) || !validHostname(projector.Hostname) || ValidateAddress(projector.Postmaster) != nil || projector.MessageSizeBytes < 1<<20 || projector.MessageSizeBytes > 2<<30 || !validOpaque(request.TenantID) {
		return ConfigSnapshot{}, ErrInvalidCommand
	}
	resources := map[ResourceKind][]ResourceEnvelope{}
	for _, kind := range []ResourceKind{ResourceDomain, ResourceMailbox, ResourceAlias, ResourcePolicy} {
		cursor := ""
		for {
			items, next, err := projector.Store.ListAll(ctx, kind, 500, cursor)
			if err != nil {
				return ConfigSnapshot{}, err
			}
			resources[kind] = append(resources[kind], items...)
			if next == "" {
				break
			}
			if next == cursor {
				return ConfigSnapshot{}, ErrInvalidReceipt
			}
			cursor = next
		}
	}
	if request.Desired != nil {
		list := resources[request.Kind]
		replaced := false
		for index := range list {
			if list[index].ID == request.ResourceID {
				list[index] = *request.Desired
				replaced = true
				break
			}
		}
		if !replaced {
			list = append(list, *request.Desired)
		}
		resources[request.Kind] = list
	}
	resourceKey := func(tenant, id string) string { return tenant + "\x00" + id }
	policies := make(map[string]Policy)
	for _, envelope := range resources[ResourcePolicy] {
		if envelope.State == StateDeleted {
			continue
		}
		var value Policy
		if json.Unmarshal(envelope.Spec, &value) != nil || value.ID == "" || envelope.TenantID == "" {
			return ConfigSnapshot{}, ErrInvalidReceipt
		}
		policies[resourceKey(envelope.TenantID, string(value.ID))] = value
	}
	mailboxes := make(map[string][]Mailbox)
	for _, envelope := range resources[ResourceMailbox] {
		if envelope.State == StateDeleted || envelope.State == StateSuspended {
			continue
		}
		var value Mailbox
		if json.Unmarshal(envelope.Spec, &value) != nil || value.ID == "" || value.Domain == "" || envelope.TenantID == "" {
			return ConfigSnapshot{}, ErrInvalidReceipt
		}
		key := resourceKey(envelope.TenantID, string(value.Domain))
		mailboxes[key] = append(mailboxes[key], value)
	}
	aliases := make(map[string][]Alias)
	for _, envelope := range resources[ResourceAlias] {
		if envelope.State == StateDeleted || envelope.State == StateSuspended {
			continue
		}
		var value Alias
		if json.Unmarshal(envelope.Spec, &value) != nil || value.ID == "" || value.Domain == "" || envelope.TenantID == "" {
			return ConfigSnapshot{}, ErrInvalidReceipt
		}
		key := resourceKey(envelope.TenantID, string(value.Domain))
		aliases[key] = append(aliases[key], value)
	}
	snapshot := ConfigSnapshot{NodeID: projector.NodeID, Generation: request.Generation, Hostname: projector.Hostname, Postmaster: projector.Postmaster, MessageSizeBytes: projector.MessageSizeBytes}
	for _, envelope := range resources[ResourceDomain] {
		if envelope.State == StateDeleted || envelope.State == StateSuspended {
			continue
		}
		var domain Domain
		if json.Unmarshal(envelope.Spec, &domain) != nil || domain.ID == "" || domain.Tenant == "" || domain.Tenant != envelope.TenantID {
			return ConfigSnapshot{}, ErrInvalidReceipt
		}
		policy, ok := policies[resourceKey(domain.Tenant, string(domain.Policy))]
		if !ok {
			return ConfigSnapshot{}, ErrNotFound
		}
		key := resourceKey(domain.Tenant, string(domain.ID))
		snapshot.Domains = append(snapshot.Domains, DomainProjection{Domain: domain, Policy: policy, Mailboxes: mailboxes[key], Aliases: aliases[key], TLS: TLSMaterial{Key: "mail-" + string(domain.ID), Hostnames: []string{domain.Name, "mail." + domain.Name}}})
	}
	return snapshot, nil
}

func validateSnapshot(snapshot ConfigSnapshot) error {
	if !validOpaque(snapshot.NodeID) || snapshot.Generation == 0 || !validHostname(snapshot.Hostname) || ValidateAddress(snapshot.Postmaster) != nil || snapshot.MessageSizeBytes < 1<<20 || snapshot.MessageSizeBytes > 2<<30 || len(snapshot.Domains) > 100000 {
		return fmt.Errorf("%w: mail snapshot", ErrInvalidCommand)
	}
	seen := map[string]struct{}{}
	for _, projection := range snapshot.Domains {
		domain := strings.ToLower(strings.TrimSuffix(projection.Domain.Name, "."))
		if !validHostname(domain) || !validOpaque(projection.Domain.Tenant) || projection.Policy.ID == "" || projection.Domain.Policy != projection.Policy.ID {
			return fmt.Errorf("%w: domain projection", ErrInvalidCommand)
		}
		if _, exists := seen[domain]; exists {
			return fmt.Errorf("%w: duplicate domain", ErrInvalidCommand)
		}
		seen[domain] = struct{}{}
		if projection.Domain.DKIM.Enabled {
			if !validDKIMSelector(projection.Domain.DKIM.Selector) || !validOpaque(projection.Domain.DKIM.PrivateKeyRef) || len(projection.Domain.DKIM.PublicKey) < 32 || len(projection.Domain.DKIM.PublicKey) > 16384 {
				return fmt.Errorf("%w: dkim", ErrInvalidCommand)
			}
		}
		relay := projection.Domain.Relay
		relayConfigured := relay.Host != "" || relay.Port != 0 || relay.CredentialRef != "" || relay.RequiredTLS
		if relayConfigured && (!validHostname(relay.Host) || relay.Port == 0 || !validOpaque(relay.CredentialRef) || !relay.RequiredTLS) {
			return fmt.Errorf("%w: relay", ErrInvalidCommand)
		}
		if !validOpaque(projection.TLS.Key) || len(projection.TLS.Hostnames) == 0 {
			return fmt.Errorf("%w: tls material", ErrInvalidCommand)
		}
		for _, host := range projection.TLS.Hostnames {
			if !validHostname(host) {
				return fmt.Errorf("%w: tls hostname", ErrInvalidCommand)
			}
		}
		mailboxes := map[MailboxID]struct{}{}
		for _, mailbox := range projection.Mailboxes {
			if mailbox.Domain != projection.Domain.ID || mailbox.ID == "" || !validLocalPart(mailbox.Local) || mailbox.QuotaBytes == 0 {
				return fmt.Errorf("%w: mailbox", ErrInvalidCommand)
			}
			if _, ok := mailboxes[mailbox.ID]; ok {
				return fmt.Errorf("%w: duplicate mailbox", ErrInvalidCommand)
			}
			mailboxes[mailbox.ID] = struct{}{}
		}
		for _, alias := range projection.Aliases {
			if alias.Domain != projection.Domain.ID || alias.ID == "" || len(alias.Targets) == 0 {
				return fmt.Errorf("%w: alias", ErrInvalidCommand)
			}
			if ValidateAddress(alias.Source) != nil || strings.TrimSpace(string(alias.Source)) != string(alias.Source) {
				return fmt.Errorf("%w: alias source", ErrInvalidCommand)
			}
			if _, err := NormalizeAddresses(alias.Targets); err != nil {
				return err
			}
			for _, target := range alias.Targets {
				if strings.TrimSpace(string(target)) != string(target) {
					return fmt.Errorf("%w: alias target whitespace", ErrInvalidCommand)
				}
			}
			if alias.Capability == CapabilityPipe && !validOpaque(alias.PipeRef) {
				return fmt.Errorf("%w: pipe handler", ErrInvalidCommand)
			}
		}
	}
	return nil
}
func normalizeSnapshot(snapshot ConfigSnapshot) ConfigSnapshot {
	snapshot.Hostname = strings.ToLower(strings.TrimSuffix(snapshot.Hostname, "."))
	snapshot.Postmaster = Address(strings.ToLower(string(snapshot.Postmaster)))
	sort.Slice(snapshot.Domains, func(i, j int) bool { return snapshot.Domains[i].Domain.Name < snapshot.Domains[j].Domain.Name })
	for index := range snapshot.Domains {
		projection := &snapshot.Domains[index]
		projection.Domain.Name = strings.ToLower(strings.TrimSuffix(projection.Domain.Name, "."))
		sort.Slice(projection.Mailboxes, func(i, j int) bool { return projection.Mailboxes[i].Local < projection.Mailboxes[j].Local })
		sort.Slice(projection.Aliases, func(i, j int) bool { return projection.Aliases[i].Source < projection.Aliases[j].Source })
		sort.Strings(projection.TLS.Hostnames)
	}
	return snapshot
}
func artifact(role ArtifactRole, key string, mode uint32, content []byte) ConfigArtifact {
	sum := sha256.Sum256(content)
	return ConfigArtifact{Role: role, Key: key, Mode: mode, Content: append([]byte(nil), content...), SHA256: hex.EncodeToString(sum[:])}
}
func renderPostfixMain(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	line := func(key, value string) { fmt.Fprintf(&out, "%s = %s\n", key, value) }
	line("compatibility_level", "3.6")
	line("myhostname", snapshot.Hostname)
	line("myorigin", "$myhostname")
	line("mydestination", "localhost")
	line("inet_interfaces", "all")
	line("inet_protocols", "all")
	line("smtpd_tls_security_level", "may")
	line("smtpd_tls_auth_only", "yes")
	line("smtpd_tls_cert_file", "/var/lib/cyberpanel/mail/tls/default/fullchain.pem")
	line("smtpd_tls_key_file", "/var/lib/cyberpanel/mail/tls/default/private.key")
	line("tls_server_sni_maps", "texthash:/var/lib/cyberpanel/mail/current/postfix/tls_sni.map")
	line("smtpd_sasl_type", "dovecot")
	line("smtpd_sasl_path", "private/auth")
	line("smtpd_sasl_auth_enable", "yes")
	line("smtpd_recipient_restrictions", "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, check_policy_service unix:private/cyberpanel-policy")
	line("virtual_mailbox_domains", "texthash:/var/lib/cyberpanel/mail/current/postfix/static_domains.map")
	line("virtual_mailbox_maps", "texthash:/var/lib/cyberpanel/mail/current/postfix/static_mailboxes.map")
	line("virtual_alias_maps", "texthash:/var/lib/cyberpanel/mail/current/postfix/static_aliases.map")
	line("virtual_transport", "lmtp:unix:private/dovecot-lmtp")
	line("message_size_limit", strconv.FormatUint(snapshot.MessageSizeBytes, 10))
	line("smtp_sender_dependent_authentication", "yes")
	line("sender_dependent_relayhost_maps", "texthash:/var/lib/cyberpanel/mail/current/postfix/relay_transport.map")
	line("smtp_sasl_auth_enable", "yes")
	line("smtp_sasl_security_options", "noanonymous")
	line("smtp_sasl_tls_security_options", "noanonymous")
	line("smtp_sasl_password_maps", "texthash:/var/lib/cyberpanel/mail/current/postfix/relay_sasl.map")
	line("smtp_tls_security_level", "may")
	line("smtp_tls_policy_maps", "texthash:/var/lib/cyberpanel/mail/current/postfix/relay_tls_policy.map")
	line("milter_default_action", "tempfail")
	line("milter_protocol", "6")
	line("milter_connect_timeout", "10s")
	line("milter_command_timeout", "30s")
	line("milter_content_timeout", "120s")
	line("smtpd_milters", "unix:/run/opendkim/opendkim.sock, unix:/run/rspamd/milter.sock")
	line("non_smtpd_milters", "$smtpd_milters")
	return out.Bytes()
}
func renderPostfixMaster() []byte {
	// Keep internal transports alongside listeners. Chroot is disabled because
	// immutable maps, TLS material and broker sockets live outside the spool.
	return []byte(`smtp      inet  n       -       n       -       -       smtpd
submission inet n       -       n       -       -       smtpd -o syslog_name=postfix/submission -o smtpd_tls_security_level=encrypt -o smtpd_sasl_auth_enable=yes
smtps     inet  n       -       n       -       -       smtpd -o syslog_name=postfix/smtps -o smtpd_tls_wrappermode=yes -o smtpd_sasl_auth_enable=yes
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -      -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
cyberpanel-policy unix - n n - 0 spawn user=cyberpanel argv=/usr/libexec/cyberpanel/mail-policy
`)
}
func renderPostfixTLS(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	for _, projection := range snapshot.Domains {
		for _, hostname := range projection.TLS.Hostnames {
			fmt.Fprintf(&out, "%s /var/lib/cyberpanel/certificates/%s/private.key /var/lib/cyberpanel/certificates/%s/fullchain.pem\n", hostname, projection.TLS.Key, projection.TLS.Key)
		}
	}
	return out.Bytes()
}
func renderPostfixRelayTransport(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	for _, projection := range snapshot.Domains {
		relay := projection.Domain.Relay
		if relay.Host != "" {
			fmt.Fprintf(&out, "@%s [%s]:%d\n", projection.Domain.Name, relay.Host, relay.Port)
		}
	}
	return out.Bytes()
}
func renderPostfixRelayTLSPolicy(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	seen := map[string]bool{}
	for _, projection := range snapshot.Domains {
		relay := projection.Domain.Relay
		if relay.Host != "" {
			endpoint := fmt.Sprintf("[%s]:%d", relay.Host, relay.Port)
			if !seen[endpoint] {
				fmt.Fprintf(&out, "%s encrypt\n", endpoint)
				seen[endpoint] = true
			}
		}
	}
	return out.Bytes()
}
func renderPostfixStaticDomains(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	for _, projection := range snapshot.Domains {
		fmt.Fprintf(&out, "%s OK\n", projection.Domain.Name)
	}
	return out.Bytes()
}
func renderPostfixStaticMailboxes(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	for _, projection := range snapshot.Domains {
		for _, mailbox := range projection.Mailboxes {
			if mailbox.Enabled {
				fmt.Fprintf(&out, "%s@%s %s/%s/Maildir/\n", mailbox.Local, projection.Domain.Name, projection.Domain.Name, mailbox.Local)
			}
		}
	}
	return out.Bytes()
}
func renderPostfixStaticAliases(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	for _, projection := range snapshot.Domains {
		for _, alias := range projection.Aliases {
			targets := make([]string, len(alias.Targets))
			for index := range alias.Targets {
				targets[index] = string(alias.Targets[index])
			}
			fmt.Fprintf(&out, "%s %s\n", alias.Source, strings.Join(targets, ","))
		}
	}
	return out.Bytes()
}
func renderDovecot(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, `protocols = imap lmtp sieve
listen = *, ::
mail_home = /var/lib/cyberpanel/mailboxes/%%d/%%n
mail_location = maildir:~/Maildir
first_valid_uid = 200000
last_valid_uid = 299999
ssl = required
ssl_cert = </var/lib/cyberpanel/mail/tls/default/fullchain.pem
ssl_key = </var/lib/cyberpanel/mail/tls/default/private.key
auth_mechanisms = plain login oauthbearer
auth_cache_size = 0
disable_plaintext_auth = yes
auth_master_user_separator = *
passdb {
  driver = passwd-file
  master = yes
  mechanisms = plain login
  args = /etc/cyberpanel/secrets/mail-webmail-master
  result_success = continue
}
passdb {
  driver = oauth2
  mechanisms = oauthbearer
  args = /var/lib/cyberpanel/mail/current/dovecot/oauth2.conf
}
passdb {
  driver = passwd-file
  mechanisms = plain login
  args = scheme=ARGON2ID /run/cyberpanel/mail/dovecot-users
}
userdb {
  driver = passwd-file
  args = /run/cyberpanel/mail/dovecot-users
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service managesieve-login {
  inet_listener sieve {
    port = 0
  }
  unix_listener /run/dovecot/cyberpanel-managesieve {
    mode = 0600
    user = cyberpanel
    group = cyberpanel
  }
}
protocol imap {
  mail_plugins = quota imap_quota
}
protocol lmtp {
  mail_plugins = quota sieve
}
plugin {
  quota = count:User quota
  quota_rule = *:storage=0
  sieve = file:~/sieve;active=~/.dovecot.sieve
}
postmaster_address = %s
`, snapshot.Postmaster)
	return out.Bytes()
}
func renderDovecotOAuth() []byte {
	return []byte("introspection_url = http://127.0.0.1:18090/tokeninfo\nintrospection_mode = auth\nusername_attribute = username\nactive_attribute = active\nactive_value = true\n")
}
func renderRspamd(snapshot ConfigSnapshot) []byte {
	return []byte("bind_socket = \"127.0.0.1:11334\";\nsecure_ip = \"127.0.0.1\";\n.include(try=true,priority=1) \"/run/cyberpanel/mail/rspamd-controller-password.inc\"\n")
}
func renderRspamdRedis() []byte {
	return []byte("servers = \"/run/cyberpanel-mail-redis/redis.sock\";\ntimeout = 1s;\ndb = \"0\";\n")
}
func renderRspamdMilter() []byte {
	return []byte("bind_socket = \"/run/rspamd/milter.sock mode=0660\";\nmilter = yes;\n")
}
func renderRspamdAntivirus() []byte {
	return []byte("clamav {\n  symbol = \"CLAM_VIRUS\";\n  type = \"clamav\";\n  servers = \"/run/clamd/cyberpanel.sock\";\n  scan_mime_parts = true;\n  scan_text_mime = true;\n  action = \"reject\";\n}\n")
}
func renderMailRedis() []byte {
	return []byte("bind 127.0.0.1 ::1\nprotected-mode yes\nport 0\nunixsocket /run/cyberpanel-mail-redis/redis.sock\nunixsocketperm 0660\nsupervised systemd\ndaemonize no\ndir /var/lib/cyberpanel-mail-redis\ndbfilename mail.rdb\nappendonly yes\nappendfilename mail.aof\nappendfsync everysec\nmaxmemory 268435456\nmaxmemory-policy noeviction\nrename-command FLUSHALL \"\"\nrename-command FLUSHDB \"\"\nrename-command CONFIG \"\"\n")
}
func renderClamAV(snapshot ConfigSnapshot) []byte {
	_ = snapshot
	return []byte("LocalSocket /run/clamd/cyberpanel.sock\nLocalSocketMode 0660\nFixStaleSocket yes\nUser clamav\nDatabaseDirectory /var/lib/clamav\nLogSyslog yes\nLogTime yes\nForeground yes\nDetectPUA yes\nHeuristicAlerts yes\nScanMail yes\nScanArchive yes\nStreamMaxLength 268435456\nMaxFileSize 268435456\nMaxScanSize 536870912\n")
}
func renderOpenDKIM() []byte {
	return []byte("Mode sv\nCanonicalization relaxed/simple\nSocket local:/run/opendkim/opendkim.sock\nPidFile /run/opendkim/opendkim.pid\nUserID opendkim:opendkim\nUMask 007\nKeyTable file:/var/lib/cyberpanel/mail/current/opendkim/KeyTable\nSigningTable refile:/var/lib/cyberpanel/mail/current/opendkim/SigningTable\nExternalIgnoreList refile:/var/lib/cyberpanel/mail/current/opendkim/TrustedHosts\nInternalHosts refile:/var/lib/cyberpanel/mail/current/opendkim/TrustedHosts\n")
}
func renderOpenDKIMTrustedHosts() []byte { return []byte("127.0.0.1\n::1\nlocalhost\n") }
func renderKeyTable(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	for _, projection := range snapshot.Domains {
		dkim := projection.Domain.DKIM
		if dkim.Enabled {
			fmt.Fprintf(&out, "%s._domainkey.%s %s:%s:/var/lib/cyberpanel/mail/current/opendkim/keys/%s/%s/private.key\n", dkim.Selector, projection.Domain.Name, projection.Domain.Name, dkim.Selector, projection.Domain.Name, dkim.Selector)
		}
	}
	return out.Bytes()
}
func renderSigningTable(snapshot ConfigSnapshot) []byte {
	var out bytes.Buffer
	for _, projection := range snapshot.Domains {
		if projection.Domain.DKIM.Enabled {
			fmt.Fprintf(&out, "*@%s %s._domainkey.%s\n", projection.Domain.Name, projection.Domain.DKIM.Selector, projection.Domain.Name)
		}
	}
	return out.Bytes()
}
func validDKIMSelector(value string) bool {
	if len(value) < 1 || len(value) > 63 {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}
