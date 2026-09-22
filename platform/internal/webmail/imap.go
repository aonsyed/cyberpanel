package webmail

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maximumIMAPCommandBytes  = 8 << 10
	maximumIMAPLineBytes     = 32 << 10
	maximumIMAPLiteralBytes  = 64 << 10
	maximumIMAPResponseBytes = 2 << 20
	maximumIMAPResponseLines = 2048
)

type Endpoint struct {
	UnixSocket   string
	TLSAddress   string
	TLSServerName string
	TLSConfig    *tls.Config
	TLSConfigForConnection func() (*tls.Config, error)
	DialTimeout  time.Duration
	CommandTimeout time.Duration
}

func (endpoint Endpoint) valid() bool {
	transportCount := 0
	if endpoint.UnixSocket != "" {
		transportCount++
		if !filepath.IsAbs(endpoint.UnixSocket) || filepath.Clean(endpoint.UnixSocket) != endpoint.UnixSocket || endpoint.UnixSocket == "/" {
			return false
		}
	}
	if endpoint.TLSAddress != "" {
		transportCount++
		host, port, err := net.SplitHostPort(endpoint.TLSAddress)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() || port == "" || endpoint.TLSServerName == "" ||
			endpoint.TLSConfig != nil && endpoint.TLSConfig.InsecureSkipVerify {
			return false
		}
	}
	return transportCount == 1 && endpoint.DialTimeout > 0 && endpoint.DialTimeout <= 30*time.Second &&
		endpoint.CommandTimeout > 0 && endpoint.CommandTimeout <= 30*time.Second
}

type imapClient struct {
	connection net.Conn
	reader     *bufio.Reader
	sequence   uint32
	timeout    time.Duration
	stop       func() bool
}

func dialIMAP(ctx context.Context, endpoint Endpoint, bearer string) (*imapClient, error) {
	if ctx == nil || !endpoint.valid() || len(bearer) < 32 || len(bearer) > 256 || strings.ContainsAny(bearer, "\x00\r\n") {
		return nil, ErrInvalid
	}
	dialer := &net.Dialer{Timeout: endpoint.DialTimeout}
	var connection net.Conn
	var err error
	if endpoint.UnixSocket != "" {
		connection, err = dialer.DialContext(ctx, "unix", endpoint.UnixSocket)
	} else {
		config := endpoint.TLSConfig
		if endpoint.TLSConfigForConnection != nil {
			config, err = endpoint.TLSConfigForConnection()
			if err != nil || config == nil || config.InsecureSkipVerify || config.ServerName == "" {
				return nil, errors.Join(ErrUnavailable, err)
			}
		}
		if config == nil {
			config = &tls.Config{}
		} else {
			config = config.Clone()
		}
		if endpoint.TLSConfigForConnection == nil {
			config.ServerName = endpoint.TLSServerName
		}
		if config.MinVersion < tls.VersionTLS13 {
			config.MinVersion = tls.VersionTLS13
		}
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: config}).DialContext(ctx, "tcp", endpoint.TLSAddress)
	}
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	client := &imapClient{connection: connection, reader: bufio.NewReaderSize(connection, maximumIMAPLineBytes), timeout: endpoint.CommandTimeout}
	client.stop = context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	if err = connection.SetDeadline(time.Now().Add(endpoint.CommandTimeout)); err != nil {
		client.stop()
		connection.Close()
		return nil, errors.Join(ErrUnavailable, err)
	}
	greeting, _, err := client.readResponseLine()
	if err != nil || !strings.HasPrefix(strings.ToUpper(greeting), "* OK") {
		client.stop()
		connection.Close()
		return nil, ErrUnavailable
	}
	capabilities, err := client.command("CAPABILITY")
	if err != nil || !hasCapabilities(capabilities, "IMAP4REV1", "AUTH=OAUTHBEARER", "SASL-IR") {
		client.stop()
		connection.Close()
		return nil, ErrUnavailable
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("n,,\x01auth=Bearer " + bearer + "\x01\x01"))
	if _, err = client.command("AUTHENTICATE OAUTHBEARER " + encoded); err != nil {
		client.stop()
		connection.Close()
		return nil, errors.Join(ErrUnauthorized, err)
	}
	// Dovecot exposes mailbox extensions only after authentication. Native
	// CONTEXT=SEARCH supports positive PARTIAL ranges without advertising the
	// newer PARTIAL capability; SPECIAL-USE RETURN is also accepted natively.
	capabilities, err = client.command("CAPABILITY")
	if err != nil || !hasCapabilities(capabilities, "IMAP4REV1", "ESEARCH", "CONDSTORE", "LIST-EXTENDED", "LIST-STATUS", "QUOTA", "BINARY", "MOVE", "UIDPLUS") ||
		(!hasCapabilities(capabilities, "PARTIAL") && !hasCapabilities(capabilities, "CONTEXT=SEARCH")) {
		client.stop()
		connection.Close()
		return nil, ErrUnavailable
	}
	return client, nil
}

func hasCapabilities(lines []string, required ...string) bool {
	set := make(map[string]bool)
	for _, line := range lines {
		upper := strings.ToUpper(line)
		if !strings.HasPrefix(upper, "* CAPABILITY ") {
			continue
		}
		for _, capability := range strings.Fields(strings.TrimPrefix(upper, "* CAPABILITY ")) {
			set[capability] = true
		}
	}
	for _, capability := range required {
		if !set[capability] {
			return false
		}
	}
	return true
}

func (client *imapClient) close() {
	if client == nil || client.connection == nil {
		return
	}
	if client.stop != nil {
		client.stop()
	}
	_ = client.connection.Close()
}

func (client *imapClient) command(command string) ([]string, error) {
	if client == nil || client.connection == nil || command == "" || len(command) > maximumIMAPCommandBytes || strings.ContainsAny(command, "\x00\r\n") {
		return nil, ErrInvalid
	}
	sequence := atomic.AddUint32(&client.sequence, 1)
	if sequence == 0 {
		return nil, ErrProtocol
	}
	tag := fmt.Sprintf("W%08X", sequence)
	if err := client.connection.SetDeadline(time.Now().Add(client.timeout)); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	if _, err := io.WriteString(client.connection, tag+" "+command+"\r\n"); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	lines := make([]string, 0, 16)
	total := 0
	for count := 0; count < maximumIMAPResponseLines; count++ {
		line, consumed, err := client.readResponseLine()
		total += consumed
		if err != nil {
			return nil, err
		}
		if total > maximumIMAPResponseBytes {
			return nil, ErrPartial
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "* BYE") || strings.HasPrefix(line, "+") {
			return nil, ErrUnavailable
		}
		if strings.HasPrefix(line, tag+" ") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != tag {
				return nil, ErrAmbiguous
			}
			switch strings.ToUpper(fields[1]) {
			case "OK":
				return lines, nil
			case "NO":
				return nil, ErrUnavailable
			default:
				return nil, ErrProtocol
			}
		}
		if len(line) > maximumIMAPLineBytes {
			return nil, ErrPartial
		}
		lines = append(lines, line)
	}
	return nil, ErrPartial
}

type imapLiteralReader struct {
	client    *imapClient
	tag       string
	remaining int64
	finished  bool
	closed    bool
}

func (reader *imapLiteralReader) Read(buffer []byte) (int, error) {
	if reader == nil || reader.client == nil || reader.closed {
		return 0, io.ErrClosedPipe
	}
	if reader.remaining == 0 {
		if err := reader.finish(); err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	read, err := reader.client.reader.Read(buffer)
	reader.remaining -= int64(read)
	if err != nil {
		return read, errors.Join(ErrUnavailable, err)
	}
	return read, nil
}

func (reader *imapLiteralReader) finish() error {
	if reader.finished {
		return nil
	}
	if reader.remaining != 0 {
		return ErrPartial
	}
	for count := 0; count < 16; count++ {
		line, _, err := readPhysicalLine(reader.client.reader)
		if err != nil {
			return errors.Join(ErrUnavailable, err)
		}
		if strings.HasPrefix(line, reader.tag+" ") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != reader.tag {
				return ErrAmbiguous
			}
			if strings.EqualFold(fields[1], "OK") {
				reader.finished = true
				return nil
			}
			return ErrUnavailable
		}
		if count != 0 || line != ")" {
			return ErrAmbiguous
		}
	}
	return ErrPartial
}

func (reader *imapLiteralReader) Close() error {
	if reader == nil || reader.closed {
		return nil
	}
	reader.closed = true
	var result error
	if reader.remaining > 0 {
		_, result = io.CopyN(io.Discard, reader.client.reader, reader.remaining)
		reader.remaining = 0
	}
	if result == nil {
		result = reader.finish()
	}
	reader.client.close()
	return result
}

func (client *imapClient) literalCommand(command string, expectedUID uint32, maximum uint64) (io.ReadCloser, uint64, error) {
	if client == nil || client.connection == nil || command == "" || len(command) > maximumIMAPCommandBytes ||
		strings.ContainsAny(command, "\x00\r\n") || expectedUID == 0 || maximum == 0 || maximum > MaximumAttachmentBytes {
		return nil, 0, ErrInvalid
	}
	sequence := atomic.AddUint32(&client.sequence, 1)
	if sequence == 0 {
		return nil, 0, ErrProtocol
	}
	tag := fmt.Sprintf("W%08X", sequence)
	if err := client.connection.SetDeadline(time.Now().Add(client.timeout)); err != nil {
		return nil, 0, errors.Join(ErrUnavailable, err)
	}
	if _, err := io.WriteString(client.connection, tag+" "+command+"\r\n"); err != nil {
		return nil, 0, errors.Join(ErrUnavailable, err)
	}
	uidMarker := " UID " + strconv.FormatUint(uint64(expectedUID), 10) + " "
	for count := 0; count < 16; count++ {
		line, _, err := readPhysicalLine(client.reader)
		if err != nil {
			return nil, 0, errors.Join(ErrUnavailable, err)
		}
		if strings.HasPrefix(strings.ToUpper(line), "* BYE") || strings.HasPrefix(line, "+") {
			return nil, 0, ErrUnavailable
		}
		if strings.HasPrefix(line, tag+" ") {
			return nil, 0, ErrProtocol
		}
		length, markerStart, ok := literalSuffix(line)
		if !ok {
			return nil, 0, ErrAmbiguous
		}
		if !strings.Contains(line[:markerStart], uidMarker) || length < 0 || uint64(length) > maximum {
			return nil, 0, ErrLimit
		}
		return &imapLiteralReader{client: client, tag: tag, remaining: int64(length)}, uint64(length), nil
	}
	return nil, 0, ErrPartial
}

func (client *imapClient) readResponseLine() (string, int, error) {
	line, consumed, err := readPhysicalLine(client.reader)
	if err != nil {
		return "", consumed, errors.Join(ErrUnavailable, err)
	}
	for {
		literalLength, markerStart, ok := literalSuffix(line)
		if !ok {
			return line, consumed, nil
		}
		if literalLength > maximumIMAPLiteralBytes || consumed+literalLength > maximumIMAPResponseBytes {
			return "", consumed, ErrPartial
		}
		literal := make([]byte, literalLength)
		if _, err = io.ReadFull(client.reader, literal); err != nil {
			return "", consumed, errors.Join(ErrUnavailable, err)
		}
		continuation, continuationBytes, readErr := readPhysicalLine(client.reader)
		consumed += literalLength + continuationBytes
		if readErr != nil {
			return "", consumed, errors.Join(ErrUnavailable, readErr)
		}
		line = line[:markerStart] + imapLiteralQuote(literal) + continuation
		if len(line) > maximumIMAPLineBytes {
			return "", consumed, ErrPartial
		}
	}
}

func readPhysicalLine(reader *bufio.Reader) (string, int, error) {
	buffer := make([]byte, 0, 256)
	consumed := 0
	for {
		part, prefix, err := reader.ReadLine()
		consumed += len(part)
		if err != nil {
			return "", consumed, err
		}
		if len(buffer)+len(part) > maximumIMAPLineBytes {
			return "", consumed, ErrPartial
		}
		buffer = append(buffer, part...)
		if !prefix {
			return string(buffer), consumed + 2, nil
		}
	}
}

func literalSuffix(line string) (int, int, bool) {
	if !strings.HasSuffix(line, "}") {
		return 0, 0, false
	}
	start := strings.LastIndexByte(line, '{')
	if start < 0 || start+2 >= len(line) {
		return 0, 0, false
	}
	raw := strings.TrimSuffix(line[start+1:], "}")
	raw = strings.TrimSuffix(raw, "+")
	length, err := strconv.Atoi(raw)
	if err != nil || length < 0 {
		return 0, 0, false
	}
	return length, start, true
}

func imapLiteralQuote(value []byte) string {
	var output strings.Builder
	output.WriteByte('"')
	for _, character := range value {
		switch character {
		case '\\', '"':
			output.WriteByte('\\')
			output.WriteByte(character)
		case '\r', '\n', 0:
			output.WriteByte(' ')
		default:
			output.WriteByte(character)
		}
	}
	output.WriteByte('"')
	return output.String()
}

func imapQuote(value string) (string, error) {
	if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return "", ErrInvalid
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`, nil
}

func encodeMailbox(name string) (string, error) {
	if !validMailboxName(name) {
		return "", ErrInvalid
	}
	var output strings.Builder
	runes := []rune(name)
	for index := 0; index < len(runes); {
		if runes[index] >= 0x20 && runes[index] <= 0x7e {
			if runes[index] == '&' {
				output.WriteString("&-")
			} else {
				output.WriteRune(runes[index])
			}
			index++
			continue
		}
		end := index
		for end < len(runes) && (runes[end] < 0x20 || runes[end] > 0x7e) {
			end++
		}
		units := utf16.Encode(runes[index:end])
		encoded := make([]byte, len(units)*2)
		for unitIndex, unit := range units {
			encoded[unitIndex*2] = byte(unit >> 8)
			encoded[unitIndex*2+1] = byte(unit)
		}
		output.WriteByte('&')
		output.WriteString(strings.ReplaceAll(strings.TrimRight(base64.StdEncoding.EncodeToString(encoded), "="), "/", ","))
		output.WriteByte('-')
		index = end
	}
	return output.String(), nil
}

func decodeMailbox(encoded string) (string, error) {
	if encoded == "" || !utf8.ValidString(encoded) || strings.ContainsAny(encoded, "\x00\r\n") {
		return "", ErrProtocol
	}
	var output strings.Builder
	for index := 0; index < len(encoded); {
		if encoded[index] != '&' {
			if encoded[index] < 0x20 || encoded[index] > 0x7e {
				return "", ErrProtocol
			}
			output.WriteByte(encoded[index])
			index++
			continue
		}
		end := strings.IndexByte(encoded[index:], '-')
		if end < 0 {
			return "", ErrProtocol
		}
		end += index
		if end == index+1 {
			output.WriteByte('&')
			index = end + 1
			continue
		}
		raw := strings.ReplaceAll(encoded[index+1:end], ",", "/")
		padding := strings.Repeat("=", (4-len(raw)%4)%4)
		decoded, err := base64.StdEncoding.DecodeString(raw + padding)
		if err != nil || len(decoded)%2 != 0 {
			return "", ErrProtocol
		}
		units := make([]uint16, len(decoded)/2)
		for unitIndex := range units {
			units[unitIndex] = uint16(decoded[unitIndex*2])<<8 | uint16(decoded[unitIndex*2+1])
		}
		for unitIndex := 0; unitIndex < len(units); unitIndex++ {
			if units[unitIndex] >= 0xd800 && units[unitIndex] <= 0xdbff {
				if unitIndex+1 >= len(units) || units[unitIndex+1] < 0xdc00 || units[unitIndex+1] > 0xdfff {
					return "", ErrProtocol
				}
				unitIndex++
			} else if units[unitIndex] >= 0xdc00 && units[unitIndex] <= 0xdfff {
				return "", ErrProtocol
			}
		}
		runes := utf16.Decode(units)
		output.WriteString(string(runes))
		index = end + 1
	}
	name := output.String()
	if !validMailboxName(name) {
		return "", ErrProtocol
	}
	canonical, err := encodeMailbox(name)
	if err != nil || canonical != encoded {
		return "", ErrProtocol
	}
	return name, nil
}

type imapValue struct {
	atom string
	list []imapValue
}

func parseIMAPValues(input string) ([]imapValue, error) {
	index := 0
	values, err := parseIMAPList(input, &index, false)
	if err != nil {
		return nil, err
	}
	for index < len(input) && input[index] == ' ' {
		index++
	}
	if index != len(input) {
		return nil, ErrProtocol
	}
	return values, nil
}

func parseIMAPList(input string, index *int, nested bool) ([]imapValue, error) {
	values := make([]imapValue, 0, 8)
	for *index < len(input) {
		for *index < len(input) && input[*index] == ' ' {
			*index++
		}
		if *index >= len(input) {
			break
		}
		if input[*index] == ')' {
			if !nested {
				return nil, ErrProtocol
			}
			*index++
			return values, nil
		}
		if input[*index] == '(' {
			*index++
			children, err := parseIMAPList(input, index, true)
			if err != nil {
				return nil, err
			}
			values = append(values, imapValue{list: children})
			continue
		}
		atom, err := parseIMAPAtom(input, index)
		if err != nil {
			return nil, err
		}
		values = append(values, imapValue{atom: atom})
	}
	if nested {
		return nil, ErrProtocol
	}
	return values, nil
}

func parseIMAPAtom(input string, index *int) (string, error) {
	if input[*index] == '"' {
		*index++
		var output strings.Builder
		for *index < len(input) {
			character := input[*index]
			*index++
			if character == '"' {
				return output.String(), nil
			}
			if character == '\\' {
				if *index >= len(input) {
					return "", ErrProtocol
				}
				character = input[*index]
				*index++
			}
			output.WriteByte(character)
		}
		return "", ErrProtocol
	}
	start := *index
	for *index < len(input) && input[*index] != ' ' && input[*index] != '(' && input[*index] != ')' {
		*index++
	}
	if start == *index {
		return "", ErrProtocol
	}
	atom := input[start:*index]
	if strings.EqualFold(atom, "NIL") {
		return "", nil
	}
	return atom, nil
}
