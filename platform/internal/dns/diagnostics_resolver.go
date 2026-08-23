package dns

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
)

const maxDiagnosticOutput = 64 << 10

type runnerDiagnosticResolver struct {
	runner DiagnosticRunner
	now    func() time.Time
}

func newRunnerDiagnosticResolver(runner DiagnosticRunner, now func() time.Time) DiagnosticResolver {
	return runnerDiagnosticResolver{runner: runner, now: now}
}

func (resolver runnerDiagnosticResolver) Resolve(ctx context.Context, query diagnosticQuery) (diagnosticAnswer, error) {
	answer := diagnosticAnswer{ObservedAt: diagnosticNow(resolver.now)}
	if ctx == nil || resolver.runner == nil || !validDiagnosticQuery(query) {
		return answer, ErrInvalidDNS
	}
	output, err := resolver.runner.Run(ctx, query)
	if err != nil {
		return answer, err
	}
	parsed, err := parseDiagnosticAnswer(output)
	if err != nil {
		return answer, err
	}
	parsed.ObservedAt = diagnosticNow(resolver.now)
	return parsed, nil
}

func validDiagnosticQuery(query diagnosticQuery) bool {
	address := query.Server.Unmap()
	if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || query.Name.String() == "" || query.Name.String() == "@" {
		return false
	}
	switch query.Kind {
	case RR_SOA, RR_NS, RR_A, RR_AAAA, RR_DNSKEY, RR_DS:
		return true
	default:
		return false
	}
}

func parseDiagnosticAnswer(output []byte) (diagnosticAnswer, error) {
	answer := diagnosticAnswer{}
	if len(output) == 0 || len(output) > maxDiagnosticOutput || strings.ContainsRune(string(output), '\x00') {
		return answer, ErrInvalidDNS
	}
	section := ""
	header := false
	for _, rawLine := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, ";; ->>HEADER<<-") {
			status, err := parseDiagnosticHeader(line)
			if err != nil || header {
				return diagnosticAnswer{}, ErrInvalidDNS
			}
			answer.Status = status
			header = true
			continue
		}
		if strings.HasPrefix(line, ";; flags:") {
			flags, err := parseDiagnosticFlags(line)
			if err != nil {
				return diagnosticAnswer{}, ErrInvalidDNS
			}
			answer.Authoritative = flags["aa"]
			answer.Authenticated = flags["ad"]
			continue
		}
		switch line {
		case ";; ANSWER SECTION:":
			section = "answer"
			continue
		case ";; AUTHORITY SECTION:":
			section = "authority"
			continue
		case ";; ADDITIONAL SECTION:":
			section = "additional"
			continue
		}
		if strings.HasPrefix(line, ";;") || strings.HasPrefix(line, ";") || section == "" {
			continue
		}
		record, recognized, err := parseDiagnosticRecord(line)
		if err != nil {
			return diagnosticAnswer{}, err
		}
		if !recognized {
			continue
		}
		if len(answer.Records) >= maxDiagnosticAnswers {
			return diagnosticAnswer{}, ErrDNSDiagnosticOutputLimit
		}
		answer.Records = append(answer.Records, record)
	}
	if !header || answer.Status == "" {
		return diagnosticAnswer{}, ErrInvalidDNS
	}
	return answer, nil
}

func parseDiagnosticHeader(line string) (string, error) {
	const statusMarker = "status:"
	statusIndex := strings.Index(line, statusMarker)
	if statusIndex < 0 {
		return "", ErrInvalidDNS
	}
	statusText := line[statusIndex+len(statusMarker):]
	if comma := strings.IndexByte(statusText, ','); comma >= 0 {
		statusText = statusText[:comma]
	}
	status := strings.ToUpper(strings.TrimSpace(statusText))
	if status == "" || len(status) > 24 {
		return "", ErrInvalidDNS
	}
	for _, character := range status {
		if character < 'A' || character > 'Z' {
			return "", ErrInvalidDNS
		}
	}
	return status, nil
}

func parseDiagnosticFlags(line string) (map[string]bool, error) {
	flagsIndex := strings.Index(line, "flags:")
	if flagsIndex < 0 {
		return nil, ErrInvalidDNS
	}
	flagsText := line[flagsIndex+len("flags:"):]
	if semicolon := strings.IndexByte(flagsText, ';'); semicolon >= 0 {
		flagsText = flagsText[:semicolon]
	}
	flags := map[string]bool{}
	for _, flag := range strings.Fields(flagsText) {
		if len(flag) < 1 || len(flag) > 8 {
			return nil, ErrInvalidDNS
		}
		flags[flag] = true
	}
	return flags, nil
}

func parseDiagnosticRecord(line string) (diagnosticRecord, bool, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return diagnosticRecord{}, false, ErrInvalidDNS
	}
	owner, err := ParseName(fields[0])
	if err != nil || owner.String() == "@" {
		return diagnosticRecord{}, false, ErrInvalidDNS
	}
	if _, err = strconv.ParseUint(fields[1], 10, 32); err != nil || !strings.EqualFold(fields[2], "IN") {
		return diagnosticRecord{}, false, ErrInvalidDNS
	}
	kind := RRKind(strings.ToUpper(fields[3]))
	switch kind {
	case RR_SOA, RR_NS, RR_A, RR_AAAA, RR_DNSKEY, RR_DS:
	default:
		return diagnosticRecord{}, false, nil
	}
	value := strings.Join(fields[4:], " ")
	if kind == RR_SOA {
		value, err = canonicalDiagnosticSOA(value)
	} else {
		value, err = canonicalRData(kind, value)
	}
	if err != nil {
		return diagnosticRecord{}, false, errors.Join(ErrInvalidDNS, err)
	}
	return diagnosticRecord{Owner: owner, Kind: kind, Value: value}, true, nil
}

func canonicalDiagnosticSOA(value string) (string, error) {
	fields := strings.Fields(value)
	if len(fields) != 7 {
		return "", ErrInvalidDNS
	}
	primary, err := ParseName(fields[0])
	if err != nil || primary.String() == "@" {
		return "", ErrInvalidDNS
	}
	hostmaster, err := ParseName(fields[1])
	if err != nil || hostmaster.String() == "@" {
		return "", ErrInvalidDNS
	}
	values := make([]string, 5)
	for index, field := range fields[2:] {
		number, parseErr := strconv.ParseUint(field, 10, 32)
		if parseErr != nil {
			return "", ErrInvalidDNS
		}
		values[index] = strconv.FormatUint(number, 10)
	}
	return strings.Join([]string{primary.FQDN(), hostmaster.FQDN(), values[0], values[1], values[2], values[3], values[4]}, " "), nil
}
