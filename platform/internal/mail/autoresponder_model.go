package mail

import (
	"strings"
	"time"
)

const (
	AutoresponderMinimumRepeatInterval = time.Hour
	AutoresponderMaximumRepeatInterval = 30 * 24 * time.Hour
	AutoresponderDefaultRepeatInterval = 24 * time.Hour
	AutoresponderMaximumListLimit = 200
	AutoresponderMaximumGeneration = uint64(1<<63 - 1)
)

type AutoresponderID string

type AutoresponderState string

const (
	AutoresponderSuspended AutoresponderState = "suspended"
	AutoresponderScheduled AutoresponderState = "scheduled"
	AutoresponderActive AutoresponderState = "active"
	AutoresponderExpired AutoresponderState = "expired"
	AutoresponderDeleted AutoresponderState = "deleted"
)

type AutoresponderSenderPolicy struct {
	Allow []Address `json:"allow"`
	Deny []Address `json:"deny"`
	ExcludedDomains []string `json:"excluded_domains"`
}

type AutoresponderSettings struct {
	Subject string `json:"subject"`
	Body string `json:"body"`
	StartAt *time.Time `json:"start_at,omitempty"`
	EndAt *time.Time `json:"end_at,omitempty"`
	Timezone string `json:"timezone"`
	RepeatInterval time.Duration `json:"repeat_interval"`
	Senders AutoresponderSenderPolicy `json:"senders"`
}

type AutoresponderRule struct {
	ID AutoresponderID `json:"id"`
	TenantID string `json:"tenant_id"`
	DomainID DomainID `json:"domain_id"`
	MailboxID MailboxID `json:"mailbox_id"`
	MailboxAddress Address `json:"mailbox_address"`
	MailboxGeneration uint64 `json:"mailbox_generation"`
	Settings AutoresponderSettings `json:"settings"`
	Enabled bool `json:"enabled"`
	State AutoresponderState `json:"state"`
	Generation uint64 `json:"generation"`
	AppliedDigest string `json:"applied_digest"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NormalizeAutoresponderSettings(settings AutoresponderSettings) (AutoresponderSettings, error) {
	if strings.ContainsAny(settings.Subject, "\x00\r\n") || len(settings.Subject) > 998 {
		return AutoresponderSettings{}, ErrInvalidCommand
	}
	settings.Subject = strings.Join(strings.Fields(settings.Subject), " ")
	if settings.Subject == "" || len(settings.Subject) > 200 {
		return AutoresponderSettings{}, ErrInvalidCommand
	}
	if strings.ContainsRune(settings.Body, '\x00') || len(settings.Body) > 32<<10 {
		return AutoresponderSettings{}, ErrInvalidCommand
	}
	settings.Body = strings.ReplaceAll(settings.Body, "\r\n", "\n")
	settings.Body = strings.ReplaceAll(settings.Body, "\r", "\n")
	settings.Body = strings.TrimSpace(settings.Body)
	if settings.Body == "" || len(settings.Body) > 32<<10 || hasUnsafeAutoresponderControl(settings.Body) {
		return AutoresponderSettings{}, ErrInvalidCommand
	}
	if len(settings.Timezone) < 1 || len(settings.Timezone) > 64 || !safeAutoresponderTimezone(settings.Timezone) {
		return AutoresponderSettings{}, ErrInvalidCommand
	}
	location, err := time.LoadLocation(settings.Timezone)
	if err != nil {
		return AutoresponderSettings{}, ErrInvalidCommand
	}
	settings.Timezone = location.String()
	settings.StartAt = normalizeAutoresponderTime(settings.StartAt)
	settings.EndAt = normalizeAutoresponderTime(settings.EndAt)
	if settings.StartAt != nil && settings.EndAt != nil && !settings.EndAt.After(*settings.StartAt) {
		return AutoresponderSettings{}, ErrInvalidCommand
	}
	if settings.RepeatInterval < AutoresponderMinimumRepeatInterval || settings.RepeatInterval > AutoresponderMaximumRepeatInterval || settings.RepeatInterval%time.Second != 0 {
		return AutoresponderSettings{}, ErrInvalidCommand
	}
	settings.Senders, err = normalizeAutoresponderSenderPolicy(settings.Senders)
	if err != nil {
		return AutoresponderSettings{}, err
	}
	return settings, nil
}

func (rule AutoresponderRule) Validate() error {
	return validateAutoresponderRule(rule, true)
}

func validateAutoresponderRule(rule AutoresponderRule, requireDigest bool) error {
	if !validOpaque(string(rule.ID)) || !validOpaque(rule.TenantID) || !validOpaque(string(rule.DomainID)) || !validOpaque(string(rule.MailboxID)) || rule.MailboxGeneration == 0 || rule.MailboxGeneration > AutoresponderMaximumGeneration || rule.Generation == 0 || rule.Generation > AutoresponderMaximumGeneration || rule.CreatedAt.IsZero() || rule.UpdatedAt.Before(rule.CreatedAt) || rule.CreatedAt.Location() != time.UTC || rule.UpdatedAt.Location() != time.UTC || rule.CreatedAt.Nanosecond() != 0 || rule.UpdatedAt.Nanosecond() != 0 {
		return ErrInvalidCommand
	}
	normalizedAddress := Address(strings.ToLower(strings.TrimSpace(string(rule.MailboxAddress))))
	if ValidateAddress(normalizedAddress) != nil || normalizedAddress != rule.MailboxAddress {
		return ErrInvalidCommand
	}
	normalized, err := NormalizeAutoresponderSettings(rule.Settings)
	if err != nil || !sameAutoresponderSettings(normalized, rule.Settings) {
		return ErrInvalidCommand
	}
	if rule.Enabled {
		if rule.State != AutoresponderActive && rule.State != AutoresponderScheduled && rule.State != AutoresponderExpired {
			return ErrInvalidCommand
		}
	} else if rule.State != AutoresponderSuspended {
		return ErrInvalidCommand
	}
	if requireDigest && !validAutoresponderDigest(rule.AppliedDigest) || !requireDigest && rule.AppliedDigest != "" && !validAutoresponderDigest(rule.AppliedDigest) {
		return ErrInvalidCommand
	}
	return nil
}

func (rule AutoresponderRule) EffectiveState(at time.Time) AutoresponderState {
	if !rule.Enabled {
		return AutoresponderSuspended
	}
	at = at.UTC()
	if rule.Settings.StartAt != nil && at.Before(*rule.Settings.StartAt) {
		return AutoresponderScheduled
	}
	if rule.Settings.EndAt != nil && !at.Before(*rule.Settings.EndAt) {
		return AutoresponderExpired
	}
	return AutoresponderActive
}

func (rule AutoresponderRule) EffectiveAt(at time.Time) bool {
	return rule.EffectiveState(at) == AutoresponderActive
}

func (rule AutoresponderRule) SenderAllowed(sender Address) bool {
	sender = Address(strings.ToLower(strings.TrimSpace(string(sender))))
	if ValidateAddress(sender) != nil || sender == rule.MailboxAddress || autoresponderSelfSender(rule.MailboxAddress, sender) {
		return false
	}
	domain := strings.SplitN(string(sender), "@", 2)[1]
	if containsAutoresponderAddress(rule.Settings.Senders.Deny, sender) || containsAutoresponderString(rule.Settings.Senders.ExcludedDomains, domain) {
		return false
	}
	return len(rule.Settings.Senders.Allow) == 0 || containsAutoresponderAddress(rule.Settings.Senders.Allow, sender)
}

func autoresponderSelfSender(mailbox, sender Address) bool {
	mailboxParts := strings.SplitN(string(mailbox), "@", 2)
	senderParts := strings.SplitN(string(sender), "@", 2)
	if len(mailboxParts) != 2 || len(senderParts) != 2 || mailboxParts[1] != senderParts[1] {
		return false
	}
	mailboxUser := strings.SplitN(mailboxParts[0], "+", 2)[0]
	senderUser := strings.SplitN(senderParts[0], "+", 2)[0]
	return mailboxUser == senderUser
}

func normalizeAutoresponderSenderPolicy(policy AutoresponderSenderPolicy) (AutoresponderSenderPolicy, error) {
	if len(policy.Allow) > 256 || len(policy.Deny) > 256 || len(policy.ExcludedDomains) > 128 {
		return AutoresponderSenderPolicy{}, ErrInvalidCommand
	}
	allow, err := NormalizeAddresses(policy.Allow)
	if err != nil && len(policy.Allow) != 0 {
		return AutoresponderSenderPolicy{}, err
	}
	deny, err := NormalizeAddresses(policy.Deny)
	if err != nil && len(policy.Deny) != 0 {
		return AutoresponderSenderPolicy{}, err
	}
	for _, address := range allow {
		if containsAutoresponderAddress(deny, address) {
			return AutoresponderSenderPolicy{}, ErrInvalidCommand
		}
	}
	domains := make([]string, 0, len(policy.ExcludedDomains))
	seen := make(map[string]bool, len(policy.ExcludedDomains))
	for _, domain := range policy.ExcludedDomains {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if !validHostname(domain) || seen[domain] {
			if seen[domain] {
				continue
			}
			return AutoresponderSenderPolicy{}, ErrInvalidCommand
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	sortAutoresponderStrings(domains)
	return AutoresponderSenderPolicy{Allow: allow, Deny: deny, ExcludedDomains: domains}, nil
}

func normalizeAutoresponderTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC().Truncate(time.Second)
	return &normalized
}

func sameAutoresponderSettings(left, right AutoresponderSettings) bool {
	if left.Subject != right.Subject || left.Body != right.Body || left.Timezone != right.Timezone || left.RepeatInterval != right.RepeatInterval || !sameAutoresponderTime(left.StartAt, right.StartAt) || !sameAutoresponderTime(left.EndAt, right.EndAt) || len(left.Senders.Allow) != len(right.Senders.Allow) || len(left.Senders.Deny) != len(right.Senders.Deny) || len(left.Senders.ExcludedDomains) != len(right.Senders.ExcludedDomains) {
		return false
	}
	for index := range left.Senders.Allow {
		if left.Senders.Allow[index] != right.Senders.Allow[index] {
			return false
		}
	}
	for index := range left.Senders.Deny {
		if left.Senders.Deny[index] != right.Senders.Deny[index] {
			return false
		}
	}
	for index := range left.Senders.ExcludedDomains {
		if left.Senders.ExcludedDomains[index] != right.Senders.ExcludedDomains[index] {
			return false
		}
	}
	return true
}

func sameAutoresponderTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right) && right.Location() == time.UTC && right.Nanosecond() == 0
}

func hasUnsafeAutoresponderControl(value string) bool {
	for _, character := range value {
		if character == 0x7f || character < 0x20 && character != '\n' && character != '\t' {
			return true
		}
	}
	return false
}

func safeAutoresponderTimezone(value string) bool {
	for _, character := range value {
		if !(character == '/' || character == '_' || character == '-' || character == '+' || character == '.' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z') {
			return false
		}
	}
	return value != "Local" && !strings.HasPrefix(value, "/") && !strings.Contains(value, "..")
}

func containsAutoresponderAddress(values []Address, target Address) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsAutoresponderString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortAutoresponderStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for current := index; current > 0 && values[current] < values[current-1]; current-- {
			values[current], values[current-1] = values[current-1], values[current]
		}
	}
}
