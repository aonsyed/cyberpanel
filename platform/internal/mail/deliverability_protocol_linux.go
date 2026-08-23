//go:build linux

package mail

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxDeliverabilityProtocolBytes = 32 << 10
const maxDeliverabilityProtocolLines = 64

type LinuxDeliverabilityProtocolProbe struct {
	Now func() time.Time
}

func NewLinuxDeliverabilityProtocolProbe() ProtocolProbe {
	return LinuxDeliverabilityProtocolProbe{Now: time.Now}
}

func (probe LinuxDeliverabilityProtocolProbe) Probe(ctx context.Context, endpoint deliverabilityProtocolEndpoint) (deliverabilityProtocolEvidence, error) {
	evidence := deliverabilityProtocolEvidence{ObservedAt: deliverabilityNow(probe.Now)}
	port, err := deliverabilityProtocolPort(endpoint.Protocol)
	if ctx == nil || err != nil || !deliverabilityPublicAddress(endpoint.Address) || !validHostname(endpoint.ServerName) || endpoint.ServerName != strings.ToLower(strings.TrimSuffix(endpoint.ServerName, ".")) {
		return evidence, ErrInvalidCommand
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(endpoint.Address.Unmap().String(), strconv.Itoa(int(port))))
	if err != nil {
		if ctx.Err() != nil {
			return evidence, ctx.Err()
		}
		return evidence, errors.New("public mail port unavailable")
	}
	defer connection.Close()
	evidence.Reachable = true
	deadline := time.Now().Add(maximumDeliverabilityCheck)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()

	switch endpoint.Protocol {
	case DeliverabilitySMTP:
		greeting, _, protocolErr := probeDeliverabilitySMTP(ctx, connection, false, endpoint.ServerName, &evidence)
		evidence.GreetingName = greeting
		if protocolErr != nil {
			return evidence, normalizedDeliverabilityProtocolError(ctx, protocolErr)
		}
	case DeliverabilitySubmission:
		greeting, capabilities, protocolErr := probeDeliverabilitySMTP(ctx, connection, true, endpoint.ServerName, &evidence)
		evidence.GreetingName = greeting
		evidence.Capabilities = capabilities
		if protocolErr != nil {
			return evidence, normalizedDeliverabilityProtocolError(ctx, protocolErr)
		}
	case DeliverabilitySMTPS:
		tlsConnection, tlsErr := deliverabilityTLSClient(ctx, connection, endpoint.ServerName, &evidence)
		if tlsErr != nil {
			return evidence, normalizedDeliverabilityProtocolError(ctx, tlsErr)
		}
		greeting, capabilities, protocolErr := probeDeliverabilitySMTP(ctx, tlsConnection, false, endpoint.ServerName, &evidence)
		evidence.GreetingName = greeting
		evidence.Capabilities = capabilities
		if protocolErr != nil {
			return evidence, normalizedDeliverabilityProtocolError(ctx, protocolErr)
		}
	case DeliverabilityIMAPS:
		tlsConnection, tlsErr := deliverabilityTLSClient(ctx, connection, endpoint.ServerName, &evidence)
		if tlsErr != nil {
			return evidence, normalizedDeliverabilityProtocolError(ctx, tlsErr)
		}
		reader := newDeliverabilityProtocolReader(tlsConnection)
		line, readErr := reader.line()
		if readErr != nil || !strings.HasPrefix(strings.ToUpper(line), "* OK") {
			return evidence, ErrInvalidReceipt
		}
		if _, writeErr := tlsConnection.Write([]byte("D001 LOGOUT\r\n")); writeErr != nil {
			return evidence, normalizedDeliverabilityProtocolError(ctx, writeErr)
		}
	default:
		return evidence, ErrInvalidCommand
	}
	evidence.ObservedAt = deliverabilityNow(probe.Now)
	return evidence, nil
}

func deliverabilityProtocolPort(protocol DeliverabilityProtocol) (uint16, error) {
	switch protocol {
	case DeliverabilitySMTP:
		return 25, nil
	case DeliverabilitySubmission:
		return 587, nil
	case DeliverabilitySMTPS:
		return 465, nil
	case DeliverabilityIMAPS:
		return 993, nil
	default:
		return 0, ErrInvalidCommand
	}
}

func probeDeliverabilitySMTP(ctx context.Context, connection net.Conn, startTLS bool, serverName string, evidence *deliverabilityProtocolEvidence) (string, []string, error) {
	reader := newDeliverabilityProtocolReader(connection)
	banner, err := readDeliverabilitySMTPResponse(reader, 220)
	if err != nil || len(banner) == 0 {
		return "", nil, ErrInvalidReceipt
	}
	greeting := deliverabilityGreetingName(banner[0])
	if _, err = connection.Write([]byte("EHLO diagnostic.invalid\r\n")); err != nil {
		return greeting, nil, err
	}
	response, err := readDeliverabilitySMTPResponse(reader, 250)
	if err != nil {
		return greeting, nil, err
	}
	capabilities := deliverabilityCapabilities(response)
	if !startTLS {
		_, _ = connection.Write([]byte("QUIT\r\n"))
		return greeting, capabilities, nil
	}
	if !containsDeliverabilityString(capabilities, "STARTTLS") {
		return greeting, capabilities, ErrInvalidReceipt
	}
	if _, err = connection.Write([]byte("STARTTLS\r\n")); err != nil {
		return greeting, capabilities, err
	}
	if _, err = readDeliverabilitySMTPResponse(reader, 220); err != nil {
		return greeting, capabilities, err
	}
	tlsConnection, err := deliverabilityTLSClient(ctx, connection, serverName, evidence)
	if err != nil {
		return greeting, capabilities, err
	}
	tlsReader := newDeliverabilityProtocolReader(tlsConnection)
	if _, err = tlsConnection.Write([]byte("EHLO diagnostic.invalid\r\n")); err != nil {
		return greeting, capabilities, err
	}
	if _, err = readDeliverabilitySMTPResponse(tlsReader, 250); err != nil {
		return greeting, capabilities, err
	}
	_, _ = tlsConnection.Write([]byte("QUIT\r\n"))
	return greeting, capabilities, nil
}

func deliverabilityTLSClient(ctx context.Context, connection net.Conn, serverName string, evidence *deliverabilityProtocolEvidence) (*tls.Conn, error) {
	tlsConnection := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName})
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil, errors.New("mail TLS presentation invalid")
	}
	state := tlsConnection.ConnectionState()
	if !state.HandshakeComplete || state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return nil, ErrInvalidReceipt
	}
	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	evidence.TLSPresented = true
	evidence.TLSVersion = state.Version
	evidence.CertificateDigest = hex.EncodeToString(sum[:])
	evidence.CertificateExpiry = leaf.NotAfter.UTC()
	return tlsConnection, nil
}

type deliverabilityProtocolReader struct {
	reader *bufio.Reader
	bytes  int
	lines  int
}

func newDeliverabilityProtocolReader(connection net.Conn) *deliverabilityProtocolReader {
	return &deliverabilityProtocolReader{reader: bufio.NewReaderSize(connection, 4096)}
}

func (reader *deliverabilityProtocolReader) line() (string, error) {
	if reader.lines >= maxDeliverabilityProtocolLines || reader.bytes >= maxDeliverabilityProtocolBytes {
		return "", ErrInvalidReceipt
	}
	line, err := reader.reader.ReadSlice('\n')
	if err != nil || len(line) > 4096 {
		return "", ErrInvalidReceipt
	}
	reader.lines++
	reader.bytes += len(line)
	if reader.bytes > maxDeliverabilityProtocolBytes || len(line) < 2 || line[len(line)-2] != '\r' {
		return "", ErrInvalidReceipt
	}
	line = line[:len(line)-2]
	if strings.ContainsRune(string(line), '\x00') {
		return "", ErrInvalidReceipt
	}
	return string(line), nil
}

func readDeliverabilitySMTPResponse(reader *deliverabilityProtocolReader, expected int) ([]string, error) {
	lines := []string{}
	for {
		line, err := reader.line()
		if err != nil || len(line) < 4 {
			return nil, ErrInvalidReceipt
		}
		code, parseErr := strconv.Atoi(line[:3])
		if parseErr != nil || code != expected || line[3] != '-' && line[3] != ' ' {
			return nil, ErrInvalidReceipt
		}
		lines = append(lines, strings.TrimSpace(line[4:]))
		if line[3] == ' ' {
			return lines, nil
		}
	}
}

func deliverabilityGreetingName(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	name := strings.ToLower(strings.Trim(strings.TrimSuffix(fields[0], "."), "[]"))
	if !validHostname(name) {
		return ""
	}
	return name
}

func deliverabilityCapabilities(lines []string) []string {
	capabilities := []string{}
	seen := map[string]struct{}{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		value := strings.ToUpper(fields[0])
		if len(value) > 64 {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		capabilities = append(capabilities, value)
		if len(capabilities) >= 32 {
			break
		}
	}
	sort.Strings(capabilities)
	return capabilities
}

func normalizedDeliverabilityProtocolError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, ErrInvalidReceipt) {
		return ErrInvalidReceipt
	}
	return errors.New("mail protocol diagnostic failed")
}
