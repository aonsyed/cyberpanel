package mailtelemetry

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Correlation struct {
	TenantID  TenantID
	DomainID  DomainID
	MailboxID MailboxID
	Direction Direction
}

func (correlation Correlation) valid() bool {
	return validID(string(correlation.TenantID)) && (correlation.DomainID == "" || validID(string(correlation.DomainID))) && (correlation.MailboxID == "" || validID(string(correlation.MailboxID))) && correlation.Direction.Valid()
}

type Correlator interface {
	ResolveMailCorrelation(context.Context, CorrelationInput) (Correlation, error)
}

type CorrelationInput struct {
	Source SourceKind
	Addresses []string
	QueueHint string
	MessageHint string
}

type PolicyResolver interface {
	EffectiveMailLogPolicy(context.Context, TenantID, DomainID, MailboxID) (Policy, error)
}

type AddressProtector interface {
	ProtectMailAddress(context.Context, TenantID, string) (string, error)
}

type SourceProtector interface {
	ProtectMailSource(context.Context, TenantID, netip.Addr) (string, error)
}

type Pseudonymizer struct{ key []byte }

func NewPseudonymizer(key []byte) (*Pseudonymizer, error) {
	if len(key) < 32 || len(key) > 128 {
		return nil, ErrInvalid
	}
	return &Pseudonymizer{key: append([]byte(nil), key...)}, nil
}

func (pseudonymizer *Pseudonymizer) Address(tenant TenantID, address string) (AddressIdentity, error) {
	address = canonicalAddress(address)
	if pseudonymizer == nil || len(pseudonymizer.key) < 32 || !validID(string(tenant)) || !validAddress(address) {
		return AddressIdentity{}, ErrInvalid
	}
	mac := hmac.New(sha256.New, pseudonymizer.key)
	mac.Write([]byte("mail-address-v1\x00"))
	mac.Write([]byte(tenant))
	mac.Write([]byte{0})
	mac.Write([]byte(address))
	return AddressIdentity{Kind: IdentityPseudonym, Value: hex.EncodeToString(mac.Sum(nil))}, nil
}

func (pseudonymizer *Pseudonymizer) Source(tenant TenantID, source netip.Addr) (RemoteIdentity, error) {
	if pseudonymizer == nil || len(pseudonymizer.key) < 32 || !validID(string(tenant)) || !source.IsValid() || source.IsUnspecified() || source.IsMulticast() {
		return RemoteIdentity{}, ErrInvalid
	}
	source = source.Unmap()
	mac := hmac.New(sha256.New, pseudonymizer.key)
	mac.Write([]byte("mail-source-v1\x00"))
	mac.Write([]byte(tenant))
	mac.Write([]byte{0})
	mac.Write([]byte(source.String()))
	return RemoteIdentity{Pseudonym: hex.EncodeToString(mac.Sum(nil))}, nil
}

type InputRecord struct {
	Source           SourceKind
	SourceID         SourceID
	SourceGeneration uint64
	Cursor           string
	OccurredAt       time.Time
	ObservedAt       time.Time
	Message          []byte
}

func (record InputRecord) valid() bool {
	return record.Source.Valid() && validID(string(record.SourceID)) && record.SourceGeneration > 0 && record.SourceGeneration <= MaximumRevision && record.Cursor != "" && len(record.Cursor) <= MaximumCursorBytes && !record.OccurredAt.IsZero() && !record.ObservedAt.Before(record.OccurredAt.Add(-time.Minute)) && len(record.Message) > 0 && len(record.Message) <= MaximumRecordBytes
}

type NormalizedRecord struct {
	Event  *Event
	Gap    *ParseGap
	Retain bool
}

type Normalizer struct {
	correlator Correlator
	policies   PolicyResolver
	pseudonyms *Pseudonymizer
	protector  AddressProtector
	sourceProtector SourceProtector
}

func NewNormalizer(correlator Correlator, policies PolicyResolver, pseudonyms *Pseudonymizer, protector AddressProtector, sourceProtector SourceProtector) (*Normalizer, error) {
	if correlator == nil || policies == nil || pseudonyms == nil {
		return nil, ErrInvalid
	}
	return &Normalizer{correlator: correlator, policies: policies, pseudonyms: pseudonyms, protector: protector, sourceProtector: sourceProtector}, nil
}

type parsedRecord struct {
	addresses       []string
	queue           string
	message         string
	category        Category
	result          Result
	diagnostic      string
	durationMicros  uint64
	bytes           uint64
	metadata        []Metadata
	provider        string
	providerReceipt string
	signature       string
	signatureKeyID  string
}

func canonicalAddress(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "<>\"'"))
	return strings.ToLower(value)
}

var addressPattern = regexp.MustCompile(`^[a-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]{1,64}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func validAddress(value string) bool { return len(value) <= 254 && addressPattern.MatchString(value) && !strings.Contains(value, "..") }

var (
	postfixStatus = regexp.MustCompile(`^postfix/(?:smtp|lmtp|local|virtual)\[[0-9]{1,10}\]: ([A-F0-9]{5,32}): to=<([^>]*)>,(?: orig_to=<[^>]*>,)? relay=[^,]{1,255}, delay=([0-9]+(?:\.[0-9]+)?),[^\r\n]{0,1000}[^\r\n]{0,24} dsn=([245]\.[0-9]{1,3}\.[0-9]{1,3}), status=(sent|deferred|bounced|reject(?:ed)?)\b`)
	postfixReject = regexp.MustCompile(`^postfix/smtpd\[[0-9]{1,10}\]: (?:NOQUEUE|([A-F0-9]{5,32})): reject: [^\r\n]{0,1000}[^\r\n]{0,536}; from=<([^>]*)> to=<([^>]*)>(?: proto=[A-Za-z0-9]+)?`)
	postfixQueue  = regexp.MustCompile(`^postfix/qmgr\[[0-9]{1,10}\]: ([A-F0-9]{5,32}): from=<([^>]*)>, size=([0-9]{1,20}), nrcpt=([0-9]{1,8})`)
	dovecotLMTP   = regexp.MustCompile(`^dovecot: lmtp\([^)]{0,128}\): (?:msgid=<([^>]*)>: )?(?:save|saved|delivered)[^\r\n]{0,512}(?:to|user)[ =<]([^> ,]+)`)
	dovecotAuth   = regexp.MustCompile(`^dovecot: auth: .*?(?:user=<([^>]*)>|user=([^ ,]+)).*?(auth failed|authentication failure|passdb: .*? succeeded|login succeeded)\b`)
	dovecotQuota  = regexp.MustCompile(`^dovecot: (?:lmtp|lda).*?(?:user=<([^>]*)>|to[ =<]([^> ,]+)).*?(quota exceeded|over quota)\b`)
	rspamdResult  = regexp.MustCompile(`^rspamd(?:\[[0-9]{1,10}\])?: .*?(?:qid|queue[_ -]?id)[=: ]+<?([A-F0-9]{5,32})>?.*?(?:from[=: ]+<([^>]*)>)?.*?\b(reject|add header|rewrite subject|greylist|no action|spam)\b.*?(?:score[=: ]+(-?[0-9]+(?:\.[0-9]+)?))?`)
	clamResult    = regexp.MustCompile(`^(?:clamd|clamav)(?:\[[0-9]{1,10}\])?: .*?(?:queue[_ -]?id[=: ]+<?([A-F0-9]{5,32})>?.*?)?(FOUND|OK)$`)
	dkimResult    = regexp.MustCompile(`^(?:opendkim|rspamd)(?:\[[0-9]{1,10}\])?: .*?(?:queue[_ -]?id[=: ]+<?([A-F0-9]{5,32})>?.*?)?\b(DKIM-Signature field added|signature ok|verification successful|bad signature|verification failed)\b(?:.*?\bkey[=: ]+([A-Za-z0-9._-]{1,128}))?`)
	policyResult  = regexp.MustCompile(`^policy(?:-server)?(?:\[[0-9]{1,10}\])?: action=(permit|reject|defer|dunno) sender=<([^>]*)> recipient=<([^>]*)>(?: queue_id=([A-F0-9]{5,32}))?`)
	deliveryResult = regexp.MustCompile(`^delivery(?:\[[0-9]{1,10}\])?: provider=([A-Za-z0-9._-]{1,128}) receipt=([A-Za-z0-9._:@-]{1,256}) queue_id=([A-F0-9]{5,32}) recipient=<([^>]*)> result=(delivered|deferred|bounced|rejected)(?: signature=([A-Za-z0-9+/=_-]{1,1000}[A-Za-z0-9+/=_-]{0,24}) key_id=([A-Za-z0-9._:@-]{1,128}))?$`)
	postfixRemote = regexp.MustCompile(`\[([0-9A-Fa-f:.]{2,64})\]`)
	dovecotRemote = regexp.MustCompile(`\brip=([0-9A-Fa-f:.]{2,64})\b`)
	rspamdRemote = regexp.MustCompile(`\bip[:= ]+([0-9A-Fa-f:.]{2,64})\b`)
)

func parseRemote(source SourceKind, message string) (netip.Addr, bool) {
	var matches []string
	switch source {
	case SourcePostfix, SourcePolicy, SourceDelivery:
		matches = postfixRemote.FindStringSubmatch(message)
	case SourceDovecot, SourceAuthentication:
		matches = dovecotRemote.FindStringSubmatch(message)
	case SourceRspamd, SourceClamAV:
		matches = rspamdRemote.FindStringSubmatch(message)
	}
	if len(matches) != 2 { return netip.Addr{}, false }
	address, err := netip.ParseAddr(matches[1])
	if err != nil || address.IsUnspecified() || address.IsMulticast() { return netip.Addr{}, false }
	return address.Unmap(), true
}

func parseLine(source SourceKind, message string) (parsedRecord, bool) {
	switch source {
	case SourcePostfix:
		if matches := postfixStatus.FindStringSubmatch(message); matches != nil {
			duration, durationErr := strconv.ParseFloat(matches[3], 64)
			if durationErr != nil || duration < 0 || duration > (30*24*time.Hour).Seconds() { return parsedRecord{}, false }
			result, category := ResultUnknown, CategoryDelivery
			switch matches[5] {
			case "sent":
				result = ResultDelivered
			case "deferred":
				result, category = ResultDeferred, CategoryDeferral
			case "bounced":
				result, category = ResultBounced, CategoryBounce
			default:
				result, category = ResultRejected, CategoryRejection
			}
			return parsedRecord{addresses: []string{matches[2]}, queue: matches[1], category: category, result: result, diagnostic: matches[4], durationMicros: uint64(duration * 1_000_000)}, true
		}
		if matches := postfixReject.FindStringSubmatch(message); matches != nil {
			return parsedRecord{addresses: []string{matches[2], matches[3]}, queue: matches[1], category: CategoryRejection, result: ResultRejected}, true
		}
		if matches := postfixQueue.FindStringSubmatch(message); matches != nil {
			bytesValue, bytesErr := strconv.ParseUint(matches[3], 10, 64)
			if bytesErr != nil || bytesValue > 1<<50 { return parsedRecord{}, false }
			return parsedRecord{addresses: []string{matches[2]}, queue: matches[1], category: CategoryDelivery, result: ResultAccepted, bytes: bytesValue}, true
		}
	case SourceDovecot, SourceAuthentication:
		if matches := dovecotLMTP.FindStringSubmatch(message); matches != nil {
			return parsedRecord{addresses: []string{matches[2]}, message: matches[1], category: CategoryDelivery, result: ResultDelivered}, true
		}
		if matches := dovecotQuota.FindStringSubmatch(message); matches != nil {
			return parsedRecord{addresses: []string{firstNonEmpty(matches[1], matches[2])}, category: CategoryQuota, result: ResultRejected}, true
		}
		if matches := dovecotAuth.FindStringSubmatch(message); matches != nil {
			result := ResultFailed
			if strings.Contains(matches[3], "succeeded") {
				result = ResultPassed
			}
			return parsedRecord{addresses: []string{firstNonEmpty(matches[1], matches[2])}, category: CategoryAuth, result: result}, true
		}
	case SourceRspamd:
		if matches := rspamdResult.FindStringSubmatch(message); matches != nil {
			result := ResultClean
			if matches[3] == "reject" || matches[3] == "spam" || matches[3] == "add header" || matches[3] == "rewrite subject" {
				result = ResultDetected
			}
			metadata := []Metadata{}
			if matches[4] != "" {
				metadata = append(metadata, Metadata{Key: "spam.score", Value: matches[4], Class: DataSecurity})
			}
			return parsedRecord{addresses: compactAddresses(matches[2]), queue: matches[1], category: CategorySpam, result: result, metadata: metadata}, true
		}
	case SourceClamAV:
		if matches := clamResult.FindStringSubmatch(message); matches != nil {
			result := ResultClean
			if matches[2] == "FOUND" {
				result = ResultDetected
			}
			return parsedRecord{queue: matches[1], category: CategoryMalware, result: result}, true
		}
	case SourceDKIM:
		if matches := dkimResult.FindStringSubmatch(message); matches != nil {
			result := ResultPassed
			if strings.Contains(matches[2], "bad") || strings.Contains(matches[2], "failed") {
				result = ResultFailed
			}
			return parsedRecord{queue: matches[1], category: CategorySigning, result: result, signatureKeyID: matches[3]}, true
		}
	case SourcePolicy:
		if matches := policyResult.FindStringSubmatch(message); matches != nil {
			result := ResultAccepted
			category := CategoryPolicy
			if matches[1] == "reject" {
				result, category = ResultRejected, CategoryRejection
			} else if matches[1] == "defer" {
				result, category = ResultDeferred, CategoryDeferral
			}
			return parsedRecord{addresses: []string{matches[2], matches[3]}, queue: matches[4], category: category, result: result}, true
		}
	case SourceDelivery:
		if matches := deliveryResult.FindStringSubmatch(message); matches != nil {
			result, category := ResultDelivered, CategoryDelivery
			switch matches[5] {
			case "deferred":
				result, category = ResultDeferred, CategoryDeferral
			case "bounced":
				result, category = ResultBounced, CategoryBounce
			case "rejected":
				result, category = ResultRejected, CategoryRejection
			}
			return parsedRecord{addresses: []string{matches[4]}, queue: matches[3], category: category, result: result, provider: matches[1], providerReceipt: matches[2], signature: matches[6], signatureKeyID: matches[7]}, true
		}
	}
	return parsedRecord{}, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func compactAddresses(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func evidenceFor(parsed parsedRecord) EvidenceClass {
	if parsed.providerReceipt != "" {
		return EvidenceProviderReceipt
	}
	if parsed.category == CategoryAuth || parsed.category == CategorySpam || parsed.category == CategoryMalware || parsed.category == CategorySigning {
		return EvidenceSecurity
	}
	return EvidenceOrdinary
}

func (normalizer *Normalizer) Normalize(ctx context.Context, record InputRecord) (NormalizedRecord, error) {
	if normalizer == nil || ctx == nil || !record.valid() {
		return NormalizedRecord{}, ErrInvalid
	}
	recordDigestBytes := sha256.Sum256(record.Message)
	recordDigest := hex.EncodeToString(recordDigestBytes[:])
	parsed, ok := parseLine(record.Source, string(record.Message))
	if !ok {
		gap := ParseGap{ID: "gap-" + digestParts(string(record.SourceID), record.Cursor, recordDigest)[:24], SourceID: record.SourceID, SourceGeneration: record.SourceGeneration, SourceCursor: record.Cursor, Code: GapParse, Count: 1, FirstAt: record.OccurredAt.UTC(), LastAt: record.OccurredAt.UTC(), EvidenceDigest: recordDigest}
		return NormalizedRecord{Gap: &gap}, nil
	}
	addresses := make([]string, 0, len(parsed.addresses))
	for _, address := range parsed.addresses {
		address = canonicalAddress(address)
		if address != "" {
			if !validAddress(address) {
				gap := ParseGap{ID: "gap-" + digestParts(string(record.SourceID), record.Cursor, recordDigest)[:24], SourceID: record.SourceID, SourceGeneration: record.SourceGeneration, SourceCursor: record.Cursor, Code: GapParse, Count: 1, FirstAt: record.OccurredAt.UTC(), LastAt: record.OccurredAt.UTC(), EvidenceDigest: recordDigest}
				return NormalizedRecord{Gap: &gap}, nil
			}
			addresses = append(addresses, address)
		}
	}
	correlation, err := normalizer.correlator.ResolveMailCorrelation(ctx, CorrelationInput{Source: record.Source, Addresses: addresses, QueueHint: parsed.queue, MessageHint: parsed.message})
	if err != nil || !correlation.valid() {
		if err != nil && !errors.Is(err, ErrNotFound) {
			return NormalizedRecord{}, err
		}
		gap := ParseGap{ID: "gap-" + digestParts(string(record.SourceID), record.Cursor, recordDigest)[:24], SourceID: record.SourceID, SourceGeneration: record.SourceGeneration, SourceCursor: record.Cursor, Code: GapCorrelation, Count: 1, FirstAt: record.OccurredAt.UTC(), LastAt: record.OccurredAt.UTC(), EvidenceDigest: recordDigest}
		return NormalizedRecord{Gap: &gap}, nil
	}
	policy, policyErr := normalizer.policies.EffectiveMailLogPolicy(ctx, correlation.TenantID, correlation.DomainID, correlation.MailboxID)
	if policyErr != nil && !errors.Is(policyErr, ErrNotFound) {
		return NormalizedRecord{}, policyErr
	}
	evidence := evidenceFor(parsed)
	mandatory := evidence != EvidenceOrdinary
	if policyErr != nil && !mandatory {
		return NormalizedRecord{Retain: false}, nil
	}
	if policyErr == nil && (policy.Validate() != nil || policy.TenantID != correlation.TenantID) {
		return NormalizedRecord{}, ErrIntegrity
	}
	identity := func(address string) (*AddressIdentity, error) {
		if address == "" {
			return nil, nil
		}
		if policyErr == nil && policy.Redaction.ProtectedAccess {
			if normalizer.protector == nil {
				return nil, ErrProtected
			}
			reference, protectErr := normalizer.protector.ProtectMailAddress(ctx, correlation.TenantID, address)
			if protectErr != nil || !validID(reference) {
				return nil, ErrProtected
			}
			return &AddressIdentity{Kind: IdentityProtectedRef, Value: reference}, nil
		}
		value, hashErr := normalizer.pseudonyms.Address(correlation.TenantID, address)
		return &value, hashErr
	}
	var sender, recipient *AddressIdentity
	envelopeAllowed := policyErr == nil && policy.permits(parsed.category, DataEnvelope)
	if envelopeAllowed && len(addresses) > 0 {
		sender, err = identity(addresses[0])
		if err != nil {
			return NormalizedRecord{}, err
		}
	}
	if envelopeAllowed && len(addresses) > 1 {
		recipient, err = identity(addresses[len(addresses)-1])
		if err != nil {
			return NormalizedRecord{}, err
		}
	} else if envelopeAllowed && len(addresses) == 1 {
		recipient = sender
		sender = nil
	}
	metadata := make([]Metadata, 0, len(parsed.metadata))
	if policyErr == nil && policy.Redaction.IncludeDiagnostics {
		for _, item := range parsed.metadata {
			if policy.permits(parsed.category, item.Class) {
				metadata = append(metadata, item)
			}
		}
	}
	diagnostic := ""
	if policyErr == nil && policy.Redaction.IncludeDiagnostics && policy.permits(parsed.category, DataDiagnostic) { diagnostic = parsed.diagnostic }
	durationMicros, bytesValue := uint64(0), uint64(0)
	if policyErr == nil && policy.permits(parsed.category, DataTiming) { durationMicros = parsed.durationMicros }
	if envelopeAllowed { bytesValue = parsed.bytes }
	providerReceiptDigest, signatureDigest := "", ""
	if parsed.providerReceipt != "" { providerReceiptDigest = digestParts("provider-receipt-v1", string(correlation.TenantID), parsed.providerReceipt) }
	if parsed.signature != "" { signatureDigest = digestParts("provider-signature-v1", parsed.signature) }
	var remoteSource *RemoteIdentity
	if remoteAddress, present := parseRemote(record.Source, string(record.Message)); present {
		remote, remoteErr := normalizer.pseudonyms.Source(correlation.TenantID, remoteAddress)
		if remoteErr != nil { return NormalizedRecord{}, remoteErr }
		if normalizer.sourceProtector != nil {
			reference, protectErr := normalizer.sourceProtector.ProtectMailSource(ctx, correlation.TenantID, remoteAddress)
			if protectErr != nil || !validProtectedSourceRef(reference) { return NormalizedRecord{}, ErrProtected }
			remote.ProtectedRef = reference
		}
		remoteSource = &remote
	}
	event := Event{
		ID: EventID("event-" + digestParts(string(record.SourceID), strconv.FormatUint(record.SourceGeneration, 10), record.Cursor, recordDigest)[:24]),
		TenantID: correlation.TenantID, DomainID: correlation.DomainID, MailboxID: correlation.MailboxID,
		Source: record.Source, SourceID: record.SourceID, SourceGeneration: record.SourceGeneration, SourceCursor: record.Cursor,
		OccurredAt: record.OccurredAt.UTC(), ObservedAt: record.ObservedAt.UTC(), Direction: correlation.Direction,
		Category: parsed.category, Result: parsed.result, Evidence: evidence, Sender: sender, Recipient: recipient, RemoteSource: remoteSource,
		DiagnosticCode: diagnostic, DurationMicros: durationMicros, Bytes: bytesValue, Metadata: metadata,
		Provenance: Provenance{Parser: string(record.Source) + "-strict", ParserVersion: 1, Provider: parsed.provider, ProviderReceiptDigest: providerReceiptDigest, SignatureDigest: signatureDigest, SignatureKeyID: parsed.signatureKeyID, RecordDigest: recordDigest},
	}
	if policyErr == nil {
		event.PolicyID, event.PolicyRevision = policy.ID, policy.Revision
		retention := policy.Retention.Ordinary
		switch evidence {
		case EvidenceProviderReceipt:
			retention = policy.Retention.Provider
		case EvidenceSecurity:
			retention = policy.Retention.SecurityFloor
		case EvidenceAudit:
			retention = policy.Retention.AuditFloor
		case EvidenceIncident:
			retention = 0
		}
		if retention > 0 { event.RetainUntil = event.OccurredAt.Add(retention) }
	}
	if parsed.queue != "" && policyErr == nil && policy.permits(parsed.category, DataQueue) {
		event.QueueIdentity = digestParts("queue-v1", string(correlation.TenantID), parsed.queue)
	}
	if parsed.message != "" && policyErr == nil && policy.permits(parsed.category, DataQueue) {
		event.MessageIdentity = digestParts("message-v1", string(correlation.TenantID), parsed.message)
	}
	if event.Validate() != nil {
		return NormalizedRecord{}, ErrIntegrity
	}
	retain := mandatory || policy.permits(event.Category, DataResult)
	var sourceGap *ParseGap
	if event.RemoteSource == nil && (event.Category == CategoryAuth || event.Category == CategoryRejection) && (event.Direction == DirectionInbound || event.Direction == DirectionUnknown) {
		gap := ParseGap{ID: "gap-"+digestParts("remote-source", string(record.SourceID), record.Cursor, recordDigest)[:24], TenantID: correlation.TenantID, SourceID: record.SourceID, SourceGeneration: record.SourceGeneration, SourceCursor: record.Cursor, Code: GapCorrelation, Count: 1, FirstAt: record.OccurredAt.UTC(), LastAt: record.OccurredAt.UTC(), EvidenceDigest: recordDigest}
		sourceGap = &gap
	}
	return NormalizedRecord{Event: &event, Gap: sourceGap, Retain: retain}, nil
}
