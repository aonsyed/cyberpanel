package maildelivery

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type SMTPTLSMode string

const (
	SMTPSTARTTLS   SMTPTLSMode = "starttls_required"
	SMTPImplicitTLS SMTPTLSMode = "implicit_tls"
)

type SMTPRelayOrigin struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	ServerName string `json:"server_name"`
	HelloName string `json:"hello_name"`
	TLSMode SMTPTLSMode `json:"tls_mode"`
}

func (origin SMTPRelayOrigin) Validate() error {
	if !validHostname(origin.Host) || net.ParseIP(origin.Host) != nil || origin.ServerName != origin.Host || !validHostname(origin.HelloName) {
		return ErrInvalid
	}
	if origin.Port != 25 && origin.Port != 465 && origin.Port != 587 && origin.Port != 2525 {
		return ErrInvalid
	}
	if origin.TLSMode == SMTPImplicitTLS && origin.Port != 465 || origin.TLSMode == SMTPSTARTTLS && origin.Port == 465 {
		return ErrInvalid
	}
	if origin.TLSMode != SMTPImplicitTLS && origin.TLSMode != SMTPSTARTTLS {
		return ErrInvalid
	}
	return nil
}

type SMTPAuthSecret struct {
	Username []byte
	Password []byte
	Cleanup func()
}

func (secret SMTPAuthSecret) Validate() error {
	if len(secret.Username) == 0 || len(secret.Username) > 512 || len(secret.Password) == 0 || len(secret.Password) > 4096 || secret.Cleanup == nil {
		return ErrInvalid
	}
	if len("AUTH PLAIN ")+base64.StdEncoding.EncodedLen(len(secret.Username)+len(secret.Password)+2) > 4096 {
		return ErrInvalid
	}
	for _, character := range secret.Username {
		if character == 0 || character == '\r' || character == '\n' {
			return ErrInvalid
		}
	}
	for _, character := range secret.Password {
		if character == 0 {
			return ErrInvalid
		}
	}
	return nil
}

type SMTPSecretResolver interface {
	ResolveSMTPAuthSecret(context.Context, EncryptedCredentialReference) (SMTPAuthSecret, error)
}

type SMTPDNSResolver interface {
	LookupNetIP(context.Context, string, string) ([]net.IP, error)
}

type SMTPDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type SMTPQueueObserver interface {
	QuerySMTPIdempotency(context.Context, SMTPRelayOrigin, TenantID, string) (QueryResult, error)
}

type SMTPRelay struct {
	origin SMTPRelayOrigin
	credential EncryptedCredentialReference
	secrets SMTPSecretResolver
	resolver SMTPDNSResolver
	dialer SMTPDialer
	observer SMTPQueueObserver
	tlsConfig *tls.Config
	dialTimeout time.Duration
	commandTimeout time.Duration
	maximumResponseBytes int
	maximumMessageBytes int64
	now func() time.Time
}

type SMTPRelayOptions struct {
	Origin SMTPRelayOrigin
	Credential EncryptedCredentialReference
	Secrets SMTPSecretResolver
	Resolver SMTPDNSResolver
	Dialer SMTPDialer
	Observer SMTPQueueObserver
	TLSConfig *tls.Config
	DialTimeout time.Duration
	CommandTimeout time.Duration
	MaximumResponseBytes int
	MaximumMessageBytes int64
	Now func() time.Time
}

func NewSMTPRelay(options SMTPRelayOptions) (*SMTPRelay, error) {
	if options.Origin.Validate() != nil || options.Credential.Validate() != nil || options.Secrets == nil || options.Observer == nil {
		return nil, ErrInvalid
	}
	if options.Resolver == nil {
		options.Resolver = net.DefaultResolver
	}
	if options.Dialer == nil {
		options.Dialer = &net.Dialer{}
	}
	if options.DialTimeout == 0 {
		options.DialTimeout = 10 * time.Second
	}
	if options.CommandTimeout == 0 {
		options.CommandTimeout = 30 * time.Second
	}
	if options.MaximumResponseBytes == 0 {
		options.MaximumResponseBytes = 64 << 10
	}
	if options.MaximumMessageBytes == 0 {
		options.MaximumMessageBytes = MaximumMessageBytes
	}
	if options.DialTimeout < time.Second || options.DialTimeout > time.Minute || options.CommandTimeout < time.Second ||
		options.CommandTimeout > 2*time.Minute || options.MaximumResponseBytes < 1024 || options.MaximumResponseBytes > 1<<20 ||
		options.MaximumMessageBytes <= 0 || options.MaximumMessageBytes > MaximumMessageBytes {
		return nil, ErrInvalid
	}
	configuration := options.TLSConfig
	if configuration == nil {
		configuration = &tls.Config{}
	} else {
		configuration = configuration.Clone()
	}
	if configuration.InsecureSkipVerify || configuration.ServerName != "" && configuration.ServerName != options.Origin.ServerName {
		return nil, ErrInvalid
	}
	configuration.ServerName = options.Origin.ServerName
	if configuration.MinVersion == 0 || configuration.MinVersion < tls.VersionTLS12 {
		configuration.MinVersion = tls.VersionTLS12
	}
	configuration.Renegotiation = tls.RenegotiateNever
	if options.Now == nil {
		options.Now = time.Now
	}
	return &SMTPRelay{origin: options.Origin, credential: options.Credential, secrets: options.Secrets, resolver: options.Resolver,
		dialer: options.Dialer, observer: options.Observer, tlsConfig: configuration, dialTimeout: options.DialTimeout,
		commandTimeout: options.CommandTimeout, maximumResponseBytes: options.MaximumResponseBytes,
		maximumMessageBytes: options.MaximumMessageBytes, now: options.Now}, nil
}

func (relay *SMTPRelay) QueryByIdempotency(ctx context.Context, binding ProviderBinding, idempotencyKey string) (QueryResult, error) {
	if relay == nil || binding.Validate() != nil || binding.Credential != relay.credential || !validID(idempotencyKey) {
		return QueryResult{}, ErrInvalid
	}
	return relay.observer.QuerySMTPIdempotency(ctx, relay.origin, binding.TenantID, idempotencyKey)
}

func (relay *SMTPRelay) Submit(ctx context.Context, request SubmitRequest) (SubmitResult, error) {
	if relay == nil || validateSubmitRequest(request) != nil || request.Envelope.Size+160 > relay.maximumMessageBytes ||
		validateSMTPPath(request.Envelope.MailFrom) != nil {
		return SubmitResult{}, smtpFailure(false)
	}
	for _, recipient := range request.Envelope.Recipients {
		if validateSMTPPath(recipient) != nil {
			return SubmitResult{}, smtpFailure(false)
		}
	}
	connection, session, err := relay.open(ctx)
	if err != nil {
		return SubmitResult{}, smtpFailure(false)
	}
	defer connection.Close()
	secret, err := relay.secrets.ResolveSMTPAuthSecret(ctx, relay.credential)
	if err != nil || secret.Validate() != nil {
		if secret.Cleanup != nil {
			secret.Cleanup()
		}
		clearBytes(secret.Username)
		clearBytes(secret.Password)
		return SubmitResult{}, smtpFailure(false)
	}
	defer secret.Cleanup()
	defer clearBytes(secret.Username)
	defer clearBytes(secret.Password)
	if err = session.authenticate(ctx, secret); err != nil {
		return SubmitResult{}, smtpFailure(false)
	}
	if code, _, commandErr := session.command(ctx, "MAIL FROM:<"+request.Envelope.MailFrom+">"); commandErr != nil || code != 250 {
		return SubmitResult{}, smtpFailure(false)
	}
	for _, recipient := range request.Envelope.Recipients {
		code, _, commandErr := session.command(ctx, "RCPT TO:<"+recipient+">")
		if commandErr != nil || code != 250 && code != 251 {
			return SubmitResult{}, smtpFailure(false)
		}
	}
	code, _, err := session.command(ctx, "DATA")
	if err != nil || code != 354 {
		return SubmitResult{}, smtpFailure(false)
	}
	if err = session.writeMessage(ctx, request); err != nil {
		return SubmitResult{State: SubmissionAmbiguous, Code: "smtp_data_ambiguous", MayHaveSubmitted: true}, smtpFailure(true)
	}
	code, response, err := session.readResponse(ctx)
	if err != nil {
		return SubmitResult{State: SubmissionAmbiguous, Code: "smtp_completion_ambiguous", MayHaveSubmitted: true}, smtpFailure(true)
	}
	if code != 250 {
		return SubmitResult{State: SubmissionFailed, Code: "smtp_rejected"}, smtpFailure(false)
	}
	responseDigest := sha256.Sum256([]byte(strings.Join(response, "\n") + "\x00" + request.Envelope.IdempotencyKey))
	providerMessageID := "smtp_" + hex.EncodeToString(responseDigest[:])
	_, _, _ = session.command(ctx, "QUIT")
	return SubmitResult{State: SubmissionAccepted, ProviderMessageID: providerMessageID, AcceptedAt: relay.now().UTC(), Code: "smtp_accepted"}, nil
}

func (relay *SMTPRelay) open(ctx context.Context) (net.Conn, *smtpSession, error) {
	lookupContext, cancel := context.WithTimeout(ctx, relay.dialTimeout)
	defer cancel()
	addresses, err := relay.resolver.LookupNetIP(lookupContext, "ip", relay.origin.Host)
	if err != nil || len(addresses) == 0 || len(addresses) > 32 {
		return nil, nil, ErrUnavailable
	}
	for _, address := range addresses {
		if !publicRelayIP(address) {
			return nil, nil, ErrDenied
		}
	}
	var connection net.Conn
	for _, address := range addresses {
		dialContext, dialCancel := context.WithTimeout(ctx, relay.dialTimeout)
		connection, err = relay.dialer.DialContext(dialContext, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(int(relay.origin.Port))))
		dialCancel()
		if err == nil {
			break
		}
	}
	if connection == nil {
		return nil, nil, ErrUnavailable
	}
	fail := func() (net.Conn, *smtpSession, error) {
		_ = connection.Close()
		return nil, nil, ErrUnavailable
	}
	if relay.origin.TLSMode == SMTPImplicitTLS {
		tlsConnection := tls.Client(connection, relay.tlsConfig.Clone())
		handshakeContext, handshakeCancel := context.WithTimeout(ctx, relay.commandTimeout)
		err = tlsConnection.HandshakeContext(handshakeContext)
		handshakeCancel()
		if err != nil {
			return fail()
		}
		connection = tlsConnection
	}
	session := newSMTPSession(connection, relay.commandTimeout, relay.maximumResponseBytes)
	if code, _, greetingErr := session.readResponse(ctx); greetingErr != nil || code != 220 {
		return fail()
	}
	code, lines, err := session.command(ctx, "EHLO "+relay.origin.HelloName)
	if err != nil || code != 250 {
		return fail()
	}
	if relay.origin.TLSMode == SMTPSTARTTLS {
		if !smtpExtension(lines, "STARTTLS") {
			return fail()
		}
		if code, _, err = session.command(ctx, "STARTTLS"); err != nil || code != 220 {
			return fail()
		}
		tlsConnection := tls.Client(connection, relay.tlsConfig.Clone())
		handshakeContext, handshakeCancel := context.WithTimeout(ctx, relay.commandTimeout)
		err = tlsConnection.HandshakeContext(handshakeContext)
		handshakeCancel()
		if err != nil {
			return fail()
		}
		connection = tlsConnection
		session = newSMTPSession(connection, relay.commandTimeout, relay.maximumResponseBytes)
		code, _, err = session.command(ctx, "EHLO "+relay.origin.HelloName)
		if err != nil || code != 250 {
			return fail()
		}
	}
	return connection, session, nil
}

type smtpSession struct {
	connection net.Conn
	reader *bufio.Reader
	timeout time.Duration
	maximumResponseBytes int
}

func newSMTPSession(connection net.Conn, timeout time.Duration, maximumResponseBytes int) *smtpSession {
	return &smtpSession{connection: connection, reader: bufio.NewReaderSize(connection, 4097), timeout: timeout, maximumResponseBytes: maximumResponseBytes}
}

func (session *smtpSession) deadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(session.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return deadline
}

func (session *smtpSession) command(ctx context.Context, command string) (int, []string, error) {
	return session.commandBytes(ctx, []byte(command))
}

func (session *smtpSession) commandBytes(ctx context.Context, command []byte) (int, []string, error) {
	if len(command) == 0 || len(command) > 4096 {
		return 0, nil, ErrInvalid
	}
	for _, character := range command {
		if character == 0 || character == '\r' || character == '\n' {
			return 0, nil, ErrInvalid
		}
	}
	if err := session.connection.SetDeadline(session.deadline(ctx)); err != nil {
		return 0, nil, err
	}
	if err := writeSMTPBytes(session.connection, command); err != nil {
		return 0, nil, err
	}
	if err := writeSMTPBytes(session.connection, []byte{'\r', '\n'}); err != nil {
		return 0, nil, err
	}
	return session.readResponse(ctx)
}

func (session *smtpSession) readResponse(ctx context.Context) (int, []string, error) {
	if err := session.connection.SetDeadline(session.deadline(ctx)); err != nil {
		return 0, nil, err
	}
	total := 0
	code := 0
	lines := make([]string, 0, 4)
	for lineNumber := 0; lineNumber < 128; lineNumber++ {
		line, err := session.reader.ReadSlice('\n')
		if err != nil || len(line) < 5 || len(line) > 4096 || line[len(line)-2] != '\r' {
			return 0, nil, ErrUnavailable
		}
		total += len(line)
		if total > session.maximumResponseBytes {
			return 0, nil, ErrUnavailable
		}
		parsed, err := strconv.Atoi(string(line[:3]))
		if err != nil || parsed < 200 || parsed > 599 || line[3] != ' ' && line[3] != '-' {
			return 0, nil, ErrUnavailable
		}
		if code == 0 {
			code = parsed
		} else if parsed != code {
			return 0, nil, ErrUnavailable
		}
		text := string(line[4 : len(line)-2])
		if strings.ContainsRune(text, 0) {
			return 0, nil, ErrUnavailable
		}
		lines = append(lines, text)
		if line[3] == ' ' {
			return code, lines, nil
		}
	}
	return 0, nil, ErrUnavailable
}

func (session *smtpSession) authenticate(ctx context.Context, secret SMTPAuthSecret) error {
	payload := make([]byte, 0, len(secret.Username)+len(secret.Password)+2)
	payload = append(payload, 0)
	payload = append(payload, secret.Username...)
	payload = append(payload, 0)
	payload = append(payload, secret.Password...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(payload)))
	base64.StdEncoding.Encode(encoded, payload)
	clearBytes(payload)
	command := append([]byte("AUTH PLAIN "), encoded...)
	clearBytes(encoded)
	code, _, err := session.commandBytes(ctx, command)
	clearBytes(command)
	if err != nil || code != 235 {
		return ErrDenied
	}
	return nil
}

func writeSMTPBytes(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(content) {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func (session *smtpSession) writeMessage(ctx context.Context, request SubmitRequest) error {
	if err := session.connection.SetDeadline(session.deadline(ctx)); err != nil {
		return err
	}
	output := bufio.NewWriterSize(session.connection, 32<<10)
	header := []byte("X-CyberPanel-Delivery-ID: " + request.Envelope.IdempotencyKey + "\r\n")
	if _, err := output.Write(header); err != nil {
		clearBytes(header)
		return err
	}
	clearBytes(header)
	limited := io.LimitReader(request.Content, request.Envelope.Size+1)
	buffer := make([]byte, 32<<10)
	defer clearBytes(buffer)
	var read int64
	lineStart := true
	previousCR := false
	for {
		count, readErr := limited.Read(buffer)
		if count > 0 {
			read += int64(count)
			if read > request.Envelope.Size {
				return ErrInvalid
			}
			for _, character := range buffer[:count] {
				if previousCR && character != '\n' || character == '\n' && !previousCR {
					return ErrInvalid
				}
				if lineStart && character == '.' {
					if err := output.WriteByte('.'); err != nil {
						return err
					}
				}
				if err := output.WriteByte(character); err != nil {
					return err
				}
				lineStart = character == '\n'
				previousCR = character == '\r'
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if read != request.Envelope.Size || previousCR {
		return ErrInvalid
	}
	if !lineStart {
		if _, err := io.WriteString(output, "\r\n"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(output, ".\r\n"); err != nil {
		return err
	}
	return output.Flush()
}

func smtpExtension(lines []string, name string) bool {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], name) {
			return true
		}
	}
	return false
}

func validateSMTPPath(value string) error {
	if len(value) == 0 || len(value) > 320 || strings.ContainsAny(value, "\x00\r\n<>") {
		return ErrInvalid
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || parsed.Name != "" || strings.Count(value, "@") != 1 {
		return ErrInvalid
	}
	for _, character := range []byte(value) {
		if character < 33 || character > 126 {
			return ErrInvalid
		}
	}
	return nil
}

var nonPublicRelayPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func publicRelayIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicRelayPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

type smtpSubmissionError struct {
	ambiguous bool
}

func (failure smtpSubmissionError) Error() string { return "maildelivery: SMTP relay failed" }
func (failure smtpSubmissionError) MayHaveSubmitted() bool { return failure.ambiguous }
func smtpFailure(ambiguous bool) error { return smtpSubmissionError{ambiguous: ambiguous} }

type PostfixRelaySpec struct {
	Generation uint64 `json:"generation"`
	BindingID BindingID `json:"binding_id"`
	TenantID TenantID `json:"tenant_id"`
	Origin SMTPRelayOrigin `json:"origin"`
	Credential EncryptedCredentialReference `json:"credential"`
	DomainIDs []DomainID `json:"domain_ids"`
	MaximumMessageBytes int64 `json:"maximum_message_bytes"`
	MaximumRecipients uint16 `json:"maximum_recipients"`
	RatePerMinute uint32 `json:"rate_per_minute"`
	Concurrency uint16 `json:"concurrency"`
	CreatedAt time.Time `json:"created_at"`
}

func (spec PostfixRelaySpec) Validate() error {
	if spec.Generation == 0 || !validID(string(spec.BindingID)) || !validID(string(spec.TenantID)) || spec.Origin.Validate() != nil ||
		spec.Credential.Validate() != nil || len(spec.DomainIDs) == 0 || len(spec.DomainIDs) > 1000 || spec.MaximumMessageBytes <= 0 ||
		spec.MaximumMessageBytes > MaximumMessageBytes || spec.MaximumRecipients == 0 || spec.MaximumRecipients > MaximumRecipients ||
		spec.RatePerMinute == 0 || spec.RatePerMinute > 1000000 || spec.Concurrency == 0 || spec.Concurrency > 1000 || spec.CreatedAt.IsZero() {
		return ErrInvalid
	}
	seen := make(map[DomainID]struct{}, len(spec.DomainIDs))
	for _, domainID := range spec.DomainIDs {
		if !validID(string(domainID)) {
			return ErrInvalid
		}
		if _, exists := seen[domainID]; exists {
			return ErrInvalid
		}
		seen[domainID] = struct{}{}
	}
	return nil
}

type PostfixRelayGeneration struct {
	ID string `json:"id"`
	Spec PostfixRelaySpec `json:"spec"`
	ManifestDigest string `json:"manifest_digest"`
	CredentialMapReference string `json:"credential_map_reference"`
	TransportArtifactDigest string `json:"transport_artifact_digest"`
	TLSArtifactDigest string `json:"tls_artifact_digest"`
}

func (generation PostfixRelayGeneration) Validate() error {
	if !validID(generation.ID) || generation.Spec.Validate() != nil || !validDigest(generation.ManifestDigest) ||
		!validID(generation.CredentialMapReference) || !validDigest(generation.TransportArtifactDigest) || !validDigest(generation.TLSArtifactDigest) {
		return ErrInvalid
	}
	return nil
}

type PostfixRelayStageReceipt struct {
	GenerationID string `json:"generation_id"`
	StageDigest string `json:"stage_digest"`
	StagedAt time.Time `json:"staged_at"`
}

type PostfixRelayValidationReceipt struct {
	GenerationID string `json:"generation_id"`
	ValidationDigest string `json:"validation_digest"`
	ValidatedAt time.Time `json:"validated_at"`
}

type PostfixRelayActivationReceipt struct {
	GenerationID string `json:"generation_id"`
	PreviousGenerationID string `json:"previous_generation_id,omitempty"`
	ActivationDigest string `json:"activation_digest"`
	ReloadDigest string `json:"reload_digest"`
	RollbackDigest string `json:"rollback_digest,omitempty"`
	RolledBack bool `json:"rolled_back"`
	Ambiguous bool `json:"ambiguous"`
	ActivatedAt time.Time `json:"activated_at"`
}

type PostfixRelayObservation struct {
	GenerationID string `json:"generation_id"`
	CurrentGenerationID string `json:"current_generation_id,omitempty"`
	Active bool `json:"active"`
	Valid bool `json:"valid"`
	EvidenceDigest string `json:"evidence_digest"`
	ObservedAt time.Time `json:"observed_at"`
}

type PostfixRelayRenderer interface {
	RenderPostfixRelay(context.Context, PostfixRelaySpec) (PostfixRelayGeneration, error)
}

type PostfixRelayStager interface {
	StagePostfixRelay(context.Context, PostfixRelayGeneration) (PostfixRelayStageReceipt, error)
}

type PostfixRelayValidator interface {
	ValidatePostfixRelay(context.Context, PostfixRelayGeneration, PostfixRelayStageReceipt) (PostfixRelayValidationReceipt, error)
}

type PostfixRelayActivator interface {
	ActivatePostfixRelay(context.Context, PostfixRelayGeneration, PostfixRelayStageReceipt, PostfixRelayValidationReceipt, string) (PostfixRelayActivationReceipt, error)
}

type PostfixRelayReconciler interface {
	ObservePostfixRelay(context.Context, PostfixRelayGeneration) (PostfixRelayObservation, error)
}

type PostfixRelayController interface {
	PostfixRelayRenderer
	PostfixRelayStager
	PostfixRelayValidator
	PostfixRelayActivator
	PostfixRelayReconciler
}
