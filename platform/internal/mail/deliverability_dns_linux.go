//go:build linux

package mail

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxDeliverabilityDNSOutput = 32 << 10
const maxDeliverabilityDNSRecords = 64

type LinuxDeliverabilityResolver struct {
	Now func() time.Time
}

func NewLinuxDeliverabilityResolver() Resolver {
	return LinuxDeliverabilityResolver{Now: time.Now}
}

func (resolver LinuxDeliverabilityResolver) Resolve(ctx context.Context, query deliverabilityDNSQuery) (deliverabilityDNSAnswer, error) {
	answer := deliverabilityDNSAnswer{ObservedAt: deliverabilityNow(resolver.Now)}
	if ctx == nil || !validDeliverabilityDNSQuery(query) {
		return answer, ErrInvalidCommand
	}
	arguments := []string{"+time=2", "+tries=1", "+nocmd", "+noquestion", "+nostats", "+noall", "+comments", "+answer", "+recurse", "+nodnssec", "@" + query.Resolver.Unmap().String(), query.Name + ".", string(query.Kind)}
	command := exec.CommandContext(ctx, "/usr/bin/dig", arguments...)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Stdin = nil
	output := &deliverabilityBoundedOutput{limit: maxDeliverabilityDNSOutput}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return answer, ctx.Err()
		}
		if output.overflow {
			return answer, ErrInvalidReceipt
		}
		return answer, errors.New("fixed DNS diagnostic failed")
	}
	if output.overflow {
		return answer, ErrInvalidReceipt
	}
	parsed, err := parseDeliverabilityDNSAnswer(output.buffer.Bytes(), query)
	if err != nil {
		return answer, err
	}
	parsed.ObservedAt = deliverabilityNow(resolver.Now)
	return parsed, nil
}

func validDeliverabilityDNSQuery(query deliverabilityDNSQuery) bool {
	if !deliverabilityPublicAddress(query.Resolver) || !validDeliverabilityDNSName(query.Name) {
		return false
	}
	switch query.Kind {
	case deliverabilityA, deliverabilityAAAA, deliverabilityMX, deliverabilityPTR, deliverabilityTXT:
		return true
	default:
		return false
	}
}

func validDeliverabilityDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character == '-' || character == '_' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z') {
				return false
			}
		}
	}
	return true
}

func parseDeliverabilityDNSAnswer(output []byte, query deliverabilityDNSQuery) (deliverabilityDNSAnswer, error) {
	answer := deliverabilityDNSAnswer{}
	if len(output) == 0 || len(output) > maxDeliverabilityDNSOutput || bytes.IndexByte(output, 0) >= 0 {
		return answer, ErrInvalidReceipt
	}
	header, inAnswer := false, false
	for _, rawLine := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, ";; ->>HEADER<<-") {
			if header {
				return deliverabilityDNSAnswer{}, ErrInvalidReceipt
			}
			status, err := parseDeliverabilityDNSStatus(line)
			if err != nil {
				return deliverabilityDNSAnswer{}, err
			}
			answer.Status = status
			header = true
			continue
		}
		if line == ";; ANSWER SECTION:" {
			inAnswer = true
			continue
		}
		if strings.HasPrefix(line, ";;") || strings.HasPrefix(line, ";") || !inAnswer {
			continue
		}
		value, recognized, err := parseDeliverabilityDNSRecord(line, query)
		if err != nil {
			return deliverabilityDNSAnswer{}, err
		}
		if recognized {
			if len(answer.Values) >= maxDeliverabilityDNSRecords {
				return deliverabilityDNSAnswer{}, ErrInvalidReceipt
			}
			answer.Values = append(answer.Values, value)
		}
	}
	if !header || answer.Status == "" {
		return deliverabilityDNSAnswer{}, ErrInvalidReceipt
	}
	sort.Strings(answer.Values)
	answer.Values = compactDeliverabilityStrings(answer.Values)
	return answer, nil
}

func parseDeliverabilityDNSStatus(line string) (string, error) {
	const marker = "status:"
	index := strings.Index(line, marker)
	if index < 0 {
		return "", ErrInvalidReceipt
	}
	value := line[index+len(marker):]
	if comma := strings.IndexByte(value, ','); comma >= 0 {
		value = value[:comma]
	}
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || len(value) > 24 {
		return "", ErrInvalidReceipt
	}
	for _, character := range value {
		if character < 'A' || character > 'Z' {
			return "", ErrInvalidReceipt
		}
	}
	return value, nil
}

func parseDeliverabilityDNSRecord(line string, query deliverabilityDNSQuery) (string, bool, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return "", false, ErrInvalidReceipt
	}
	owner := strings.ToLower(strings.TrimSuffix(fields[0], "."))
	if owner != query.Name || !strings.EqualFold(fields[2], "IN") {
		return "", false, nil
	}
	if _, err := strconv.ParseUint(fields[1], 10, 32); err != nil {
		return "", false, ErrInvalidReceipt
	}
	kind := deliverabilityDNSKind(strings.ToUpper(fields[3]))
	if kind != query.Kind {
		return "", false, nil
	}
	switch kind {
	case deliverabilityA:
		address, err := netip.ParseAddr(fields[4])
		if err != nil || !address.Is4() || len(fields) != 5 {
			return "", false, ErrInvalidReceipt
		}
		return address.String(), true, nil
	case deliverabilityAAAA:
		address, err := netip.ParseAddr(fields[4])
		if err != nil || !address.Is6() || address.Zone() != "" || len(fields) != 5 {
			return "", false, ErrInvalidReceipt
		}
		return address.String(), true, nil
	case deliverabilityMX:
		if len(fields) != 6 {
			return "", false, ErrInvalidReceipt
		}
		priority, err := strconv.ParseUint(fields[4], 10, 16)
		target := "."
		if fields[5] != "." {
			target = strings.ToLower(strings.TrimSuffix(fields[5], "."))
		}
		if err != nil || target != "." && !validHostname(target) {
			return "", false, ErrInvalidReceipt
		}
		return strconv.FormatUint(priority, 10) + " " + target, true, nil
	case deliverabilityPTR:
		if len(fields) != 5 {
			return "", false, ErrInvalidReceipt
		}
		target := strings.ToLower(strings.TrimSuffix(fields[4], "."))
		if !validHostname(target) {
			return "", false, ErrInvalidReceipt
		}
		return target, true, nil
	case deliverabilityTXT:
		value, err := parseDeliverabilityTXT(strings.Join(fields[4:], " "))
		if err != nil {
			return "", false, err
		}
		return value, true, nil
	default:
		return "", false, nil
	}
}

func parseDeliverabilityTXT(value string) (string, error) {
	var out strings.Builder
	for index := 0; index < len(value); {
		for index < len(value) && (value[index] == ' ' || value[index] == '\t') {
			index++
		}
		if index >= len(value) {
			break
		}
		if value[index] != '"' {
			return "", ErrInvalidReceipt
		}
		index++
		closed := false
		for index < len(value) {
			if value[index] == '"' {
				index++
				closed = true
				break
			}
			if value[index] == '\\' {
				index++
				if index >= len(value) {
					return "", ErrInvalidReceipt
				}
				if index+2 < len(value) && value[index] >= '0' && value[index] <= '9' && value[index+1] >= '0' && value[index+1] <= '9' && value[index+2] >= '0' && value[index+2] <= '9' {
					number, _ := strconv.ParseUint(value[index:index+3], 10, 8)
					out.WriteByte(byte(number))
					index += 3
					continue
				}
			}
			out.WriteByte(value[index])
			index++
		}
		if !closed || out.Len() > 4096 {
			return "", ErrInvalidReceipt
		}
	}
	result := out.String()
	if result == "" || strings.ContainsAny(result, "\x00\r\n") {
		return "", ErrInvalidReceipt
	}
	return result, nil
}

type LinuxDeliverabilityLocalPolicyProbe struct {
	Now func() time.Time
}

func NewLinuxDeliverabilityLocalPolicyProbe() LocalPolicyProbe {
	return LinuxDeliverabilityLocalPolicyProbe{Now: time.Now}
}

func (probe LinuxDeliverabilityLocalPolicyProbe) Probe(ctx context.Context, request DeliverabilityLocalPolicyRequest) (DeliverabilityLocalPolicyEvidence, error) {
	evidence := DeliverabilityLocalPolicyEvidence{ObservedAt: deliverabilityNow(probe.Now)}
	if ctx == nil || !validHostname(request.Hostname) || request.Hostname != strings.ToLower(strings.TrimSuffix(request.Hostname, ".")) {
		return evidence, ErrInvalidCommand
	}
	values := map[string]string{}
	for _, key := range []string{"myhostname", "mynetworks", "smtpd_sasl_auth_enable", "smtpd_relay_restrictions", "smtpd_recipient_restrictions"} {
		value, err := readDeliverabilityPostconf(ctx, key)
		if err != nil {
			return evidence, err
		}
		values[key] = value
	}
	evidence.Hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(values["myhostname"]), "."))
	evidence.SASLEnabled = strings.EqualFold(strings.TrimSpace(values["smtpd_sasl_auth_enable"]), "yes")
	var ok bool
	evidence.RelayRestrictions, ok = parseDeliverabilityRestrictions(values["smtpd_relay_restrictions"])
	if !ok {
		return evidence, nil
	}
	evidence.RecipientRestrictions, ok = parseDeliverabilityRestrictions(values["smtpd_recipient_restrictions"])
	if !ok {
		return evidence, nil
	}
	evidence.TrustedNetworks, ok = parseDeliverabilityNetworks(values["mynetworks"])
	if !ok {
		return evidence, nil
	}
	evidence.Proven = evidence.Hostname == request.Hostname
	restrictions := append(append([]string(nil), evidence.RelayRestrictions...), evidence.RecipientRestrictions...)
	rejectsUnauthenticated := containsDeliverabilityString(restrictions, "reject_unauth_destination") || containsDeliverabilityString(restrictions, "defer_unauth_destination")
	unsafePermit := containsDeliverabilityString(restrictions, "permit")
	unsafeNetwork := false
	for _, network := range evidence.TrustedNetworks {
		if network.Bits() == 0 {
			unsafeNetwork = true
		}
	}
	evidence.Safe = evidence.Proven && evidence.SASLEnabled && rejectsUnauthenticated && !unsafePermit && !unsafeNetwork
	return evidence, nil
}

func readDeliverabilityPostconf(ctx context.Context, key string) (string, error) {
	allowed := map[string]bool{"myhostname": true, "mynetworks": true, "smtpd_sasl_auth_enable": true, "smtpd_relay_restrictions": true, "smtpd_recipient_restrictions": true}
	if ctx == nil || !allowed[key] {
		return "", ErrInvalidCommand
	}
	command := exec.CommandContext(ctx, "/usr/sbin/postconf", "-h", key)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/bin"}
	command.Stdin = nil
	output := &deliverabilityBoundedOutput{limit: 16 << 10}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("fixed Postfix policy query failed")
	}
	if output.overflow {
		return "", ErrInvalidReceipt
	}
	value := strings.TrimSpace(output.buffer.String())
	if len(value) > 8192 || strings.ContainsAny(value, "\x00\r") {
		return "", ErrInvalidReceipt
	}
	return value, nil
}

func parseDeliverabilityRestrictions(value string) ([]string, bool) {
	items := []string{}
	for _, part := range strings.Split(value, ",") {
		part = strings.ToLower(strings.Join(strings.Fields(part), " "))
		if part == "" {
			continue
		}
		if len(part) > 512 || strings.ContainsAny(part, "\x00\r\n") {
			return nil, false
		}
		items = append(items, part)
		if len(items) > 64 {
			return nil, false
		}
	}
	return items, true
}

func parseDeliverabilityNetworks(value string) ([]netip.Prefix, bool) {
	networks := []netip.Prefix{}
	value = strings.ReplaceAll(value, ",", " ")
	for _, field := range strings.Fields(strings.ReplaceAll(strings.ReplaceAll(value, "[", ""), "]", "")) {
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			address, addressErr := netip.ParseAddr(field)
			if addressErr != nil {
				return nil, false
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		networks = append(networks, prefix.Masked())
		if len(networks) > 32 {
			return nil, false
		}
	}
	sort.Slice(networks, func(left, right int) bool { return networks[left].String() < networks[right].String() })
	return networks, true
}

type deliverabilityBoundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (output *deliverabilityBoundedOutput) Write(value []byte) (int, error) {
	written := len(value)
	remaining := output.limit - output.buffer.Len()
	if remaining <= 0 {
		output.overflow = true
		return written, nil
	}
	if len(value) > remaining {
		output.overflow = true
		value = value[:remaining]
	}
	_, _ = output.buffer.Write(value)
	return written, nil
}
