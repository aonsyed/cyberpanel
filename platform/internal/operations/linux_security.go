//go:build linux

package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (executor *LinuxOperationsExecutor) applyFirewall(ctx context.Context, request EffectRequest, effect FirewallPolicyEffect) (linuxEffectResult, error) {
	if replay, done, err := executor.replaySecurityEffect(ctx, request); done || err != nil {
		return replay, err
	}
	policy := effect.Policy
	if policy.Backend != FirewallNFTables {
		return linuxEffectResult{}, ErrInvalidEffect
	}
	if err := validateProtectedManagementProbe(policy.ManagementProbe); err != nil {
		return linuxEffectResult{}, err
	}
	if err := validateManagementReachability(policy); err != nil {
		return linuxEffectResult{}, err
	}
	if err := executor.requireDirectNFTablesOwnership(ctx); err != nil {
		return linuxEffectResult{}, err
	}
	content := renderNFTables(policy)
	candidate, err := executor.stageSecurityGeneration(KindFirewallPolicy, policy.ID, policy.Generation, policy, content, "nft")
	if err != nil {
		return linuxEffectResult{}, err
	}
	previous, same, err := executor.securityGenerationCAS(candidate)
	if err != nil {
		return linuxEffectResult{}, err
	}
	if same {
		return linuxEffectResult{MutationObserved: true}, ErrCompensationFailed
	}
	runtimePresent, err := executor.nftablesRuntimePresent(ctx)
	if err != nil {
		return linuxEffectResult{}, err
	}
	if previous == nil && runtimePresent {
		return linuxEffectResult{}, ErrConflict
	}
	if previous != nil {
		if _, err = executor.verifyNFTGeneration(ctx, *previous, nil); err != nil {
			return linuxEffectResult{}, ErrConflict
		}
	}
	if _, err = executor.probeLocalTCP(ctx, policy.ManagementProbe.Port, policy.ManagementProbe.MinimumSuccesses); err != nil {
		return linuxEffectResult{}, err
	}
	snapshot, err := executor.snapshotFile("/etc/cyberpanel/firewall.nft")
	if err != nil {
		return linuxEffectResult{}, err
	}
	lease, err := executor.armSecurityLease(request, candidate, previous, []operationsFileSnapshot{snapshot}, runtimePresent, nil)
	if err != nil {
		return linuxEffectResult{}, err
	}
	result := linuxEffectResult{Snapshots: []operationsFileSnapshot{snapshot}, MutationObserved: true}
	if !runtimePresent {
		if output, addErr := executor.runner.Run(ctx, "/usr/sbin/nft", "add", "table", "inet", "cyberpanel"); addErr != nil {
			return result, fmt.Errorf("create managed nftables table: %w: %s", addErr, boundedText(output, 2048))
		}
	}
	validateOutput, err := executor.runner.Run(ctx, "/usr/sbin/nft", "--check", "--file", candidate.NativePath)
	if err != nil {
		return result, fmt.Errorf("nftables generation validation: %w: %s", err, boundedText(validateOutput, 2048))
	}
	if _, err = executor.replaceManagedFile("/etc/cyberpanel/firewall.nft", content, 0o600); err != nil {
		return result, err
	}
	applyOutput, err := executor.runner.Run(ctx, "/usr/sbin/nft", "--file", candidate.NativePath)
	if err != nil {
		return result, fmt.Errorf("nftables atomic commit: %w: %s", err, boundedText(applyOutput, 2048))
	}
	observedDigest, err := executor.verifyNFTGeneration(ctx, candidate, &policy)
	if err != nil {
		return result, err
	}
	managementProof, err := executor.probeLocalTCP(ctx, policy.ManagementProbe.Port, policy.ManagementProbe.MinimumSuccesses)
	if err != nil {
		return result, err
	}
	activation := &ActivationEvidence{
		Strategy: ActivationMakeBeforeBreak, CandidateDigest: candidate.PolicyDigest,
		PreviousDigest: snapshotDigest(snapshot), StageReceiptDigest: candidate.NativeDigest,
		ProbeReceiptDigest: digestBytes([]byte(observedDigest + "\x00" + managementProof)),
		CommitReceiptDigest: digestBytes(append(applyOutput, []byte(observedDigest)...)),
	}
	if err = executor.storeGeneration(KindFirewallPolicy, policy.ID, policy.Generation, candidate.PolicyDigest); err != nil {
		return result, err
	}
	if err = executor.confirmSecurityLease(request.EffectID, lease.ConfirmationNonce, activation); err != nil {
		return result, errors.Join(ErrCompensationFailed, err)
	}
	result.Activation = activation
	return result, nil
}

func (executor *LinuxOperationsExecutor) requireDirectNFTablesOwnership(ctx context.Context) error {
	output, err := executor.runner.Run(ctx, "/usr/bin/systemctl", "is-active", "firewalld.service")
	state := strings.TrimSpace(string(output))
	if state == "active" || state == "activating" || state == "reloading" {
		return ErrConflict
	}
	if err != nil && state != "inactive" && state != "failed" && state != "unknown" && state != "deactivating" {
		return err
	}
	return nil
}

func (executor *LinuxOperationsExecutor) nftablesRuntimePresent(ctx context.Context) (bool, error) {
	if _, err := executor.runner.Run(ctx, "/usr/sbin/nft", "list", "table", "inet", "cyberpanel"); err == nil {
		return true, nil
	}
	output, err := executor.runner.Run(ctx, "/usr/sbin/nft", "list", "tables")
	if err != nil {
		return false, err
	}
	return strings.Contains(string(output), "table inet cyberpanel"), nil
}

func (executor *LinuxOperationsExecutor) verifyNFTGeneration(ctx context.Context, generation securityActiveGeneration, policy *FirewallPolicy) (string, error) {
	output, err := executor.runner.Run(ctx, "/usr/sbin/nft", "--handle", "list", "table", "inet", "cyberpanel")
	if err != nil {
		return "", err
	}
	text := string(output)
	marker := "cyberpanel-generation:" + strconv.FormatUint(generation.Generation, 10) + ":" + generation.PolicyDigest
	if !strings.Contains(text, marker) {
		return "", ErrCompensationFailed
	}
	if policy != nil {
		for _, rule := range policy.Rules {
			if strings.Count(text, "cyberpanel:"+rule.ID.String()) != 1 {
				return "", ErrCompensationFailed
			}
		}
	}
	return digestBytes(output), nil
}

func validateProtectedManagementProbe(probe ManagementProbe) error {
	if probe.Port == 0 || probe.MinimumSuccesses == 0 || probe.MinimumSuccesses > 8 || len(probe.SourceCIDRs) == 0 || len(probe.SourceCIDRs) > 32 {
		return ErrInvalidEffect
	}
	for _, prefix := range probe.SourceCIDRs {
		address := prefix.Addr()
		if !validPrefix(prefix) || prefix.Bits() == 0 || address.IsUnspecified() || address.IsMulticast() {
			return ErrInvalidEffect
		}
	}
	return nil
}

func (executor *LinuxOperationsExecutor) probeLocalTCP(ctx context.Context, port uint16, successes uint8) (string, error) {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	var evidence strings.Builder
	for count := uint8(0); count < successes; count++ {
		connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		if err != nil {
			return "", err
		}
		evidence.WriteString(connection.LocalAddr().String())
		evidence.WriteByte('>')
		evidence.WriteString(connection.RemoteAddr().String())
		evidence.WriteByte('\n')
		_ = connection.Close()
	}
	return digestBytes([]byte(evidence.String())), nil
}

func validateManagementReachability(policy FirewallPolicy)error{rules:=append([]FirewallRule(nil),policy.Rules...);sort.Slice(rules,func(i,j int)bool{return rules[i].Priority<rules[j].Priority});for _,management:=range policy.ManagementProbe.SourceCIDRs{decided:=false;for _,rule:=range rules{if rule.Protocol!=ProtocolTCP||(rule.Family==FamilyIPv4)!=management.Addr().Is4()||!portRangesContain(rule.DestinationPorts,policy.ManagementProbe.Port)||!sourcesCover(rule.Sources,management){continue};if rule.Action!=FirewallAccept{return ErrInvalidEffect};decided=true;break};if !decided{return ErrInvalidEffect}};return nil}
func portRangesContain(ranges []PortRange,port uint16)bool{for _,candidate:=range ranges{if candidate.From<=port&&candidate.To>=port{return true}};return false}
func sourcesCover(sources []netip.Prefix,target netip.Prefix)bool{if len(sources)==0{return true};for _,source:=range sources{if source.Bits()<=target.Bits()&&source.Contains(target.Addr()){return true}};return false}

func renderNFTables(policy FirewallPolicy) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("flush table inet cyberpanel\ntable inet cyberpanel {\n")
	policyDigest, _ := activationDigest(policy)
	fmt.Fprintf(&buffer, " comment \"cyberpanel-generation:%d:%s\"\n", policy.Generation, policyDigest)
	renderNFTChain := func(name string, hook string, priority int, defaultAction FirewallAction) {
		basePolicy:=defaultAction;if basePolicy==FirewallReject{basePolicy=FirewallDrop};fmt.Fprintf(&buffer, " chain %s { type filter hook %s priority %d; policy %s;\n", name, hook, priority, basePolicy)
		if name == "input" { buffer.WriteString("  ct state established,related accept\n  iifname \"lo\" accept\n") }
		if name == "input" {
			rules := append([]FirewallRule(nil), policy.Rules...); sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
			for _, rule := range rules { buffer.WriteString(renderNFTRule(rule)) }
		}
		if defaultAction==FirewallReject{buffer.WriteString("  reject\n")};buffer.WriteString(" }\n")
	}
	renderNFTChain("input", "input", 0, policy.DefaultInbound)
	renderNFTChain("forward", "forward", 0, policy.DefaultForward)
	renderNFTChain("output", "output", 0, policy.DefaultOutbound)
	buffer.WriteString("}\n")
	return buffer.Bytes()
}

func renderNFTRule(rule FirewallRule) string {
	var parts []string
	familyExpression:="meta nfproto ipv4";addressExpression:="ip saddr";protocol:=string(rule.Protocol);if rule.Family==FamilyIPv6{familyExpression="meta nfproto ipv6";addressExpression="ip6 saddr"};if rule.Protocol==ProtocolICMP{protocol="meta l4proto icmp";if rule.Family==FamilyIPv6{protocol="meta l4proto ipv6-icmp"}};parts=append(parts,familyExpression)
	if len(rule.Sources) > 0 { values := make([]string, len(rule.Sources)); for index, prefix := range rule.Sources { values[index] = prefix.String() }; parts = append(parts, addressExpression+" { "+strings.Join(values, ", ")+" }") }
	parts = append(parts, protocol)
	if len(rule.DestinationPorts) > 0 { values := make([]string, len(rule.DestinationPorts)); for index, ports := range rule.DestinationPorts { if ports.From == ports.To { values[index] = strconv.Itoa(int(ports.From)) } else { values[index] = fmt.Sprintf("%d-%d", ports.From, ports.To) } }; parts = append(parts, "dport { "+strings.Join(values, ", ")+" }") }
	if rule.RatePerMinute > 0 { parts = append(parts, fmt.Sprintf("limit rate %d/minute", rule.RatePerMinute)) }
	if rule.Log { parts = append(parts, "log prefix \"cyberpanel-fw \"") }
	parts = append(parts, string(rule.Action), "comment \"cyberpanel:"+rule.ID.String()+"\"")
	return "  " + strings.Join(parts, " ") + "\n"
}

func renderFirewalld(policy FirewallPolicy) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<zone target=\"")
	buffer.WriteString(strings.ToUpper(string(policy.DefaultInbound))); buffer.WriteString("\">\n <short>CyberPanel managed</short>\n")
	rules := append([]FirewallRule(nil), policy.Rules...); sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	for _, rule := range rules {
		families := map[AddressFamily]string{FamilyIPv4: "ipv4", FamilyIPv6: "ipv6"}
		sources := rule.Sources; if len(sources) == 0 { if rule.Family == FamilyIPv4 { sources = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} } else { sources = []netip.Prefix{netip.MustParsePrefix("::/0")} } }
		for _, source := range sources { fmt.Fprintf(&buffer, " <rule family=\"%s\" priority=\"%d\"><source address=\"%s\"/>", families[rule.Family], rule.Priority, source.String()); if rule.Protocol != ProtocolICMP { for _, ports := range rule.DestinationPorts { value := strconv.Itoa(int(ports.From)); if ports.To != ports.From { value = fmt.Sprintf("%d-%d", ports.From, ports.To) }; fmt.Fprintf(&buffer, "<port protocol=\"%s\" port=\"%s\"/>", rule.Protocol, value) } }else{protocol:="icmp";if rule.Family==FamilyIPv6{protocol="ipv6-icmp"};fmt.Fprintf(&buffer,"<protocol value=\"%s\"/>",protocol)};if rule.Log{buffer.WriteString("<log prefix=\"cyberpanel-fw\" level=\"info\"");if rule.RatePerMinute>0{fmt.Fprintf(&buffer,"><limit value=\"%d/m\"/></log>",rule.RatePerMinute)}else{buffer.WriteString("/>")}};if rule.RatePerMinute>0{fmt.Fprintf(&buffer,"<%s><limit value=\"%d/m\"/></%s>",rule.Action,rule.RatePerMinute,rule.Action)}else{fmt.Fprintf(&buffer,"<%s/>",rule.Action)};buffer.WriteString("</rule>\n") }
	}
	buffer.WriteString("</zone>\n"); return buffer.Bytes()
}

func renderFirewalldPolicies(policy FirewallPolicy)map[string][]byte{zone:=string(renderFirewalld(policy));zoneStart:=strings.Index(zone,"<zone target=");body:="";if zoneStart>=0{openingEnd:=strings.Index(zone[zoneStart:],">\n");if openingEnd>=0{body=zone[zoneStart+openingEnd+2:];body=strings.TrimSuffix(body,"</zone>\n")}};inbound:=fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<policy target=\"%s\"><ingress-zone name=\"ANY\"/><egress-zone name=\"HOST\"/>\n%s</policy>\n",strings.ToUpper(string(policy.DefaultInbound)),body);result:=map[string][]byte{
	"/etc/firewalld/policies/cyberpanel-inbound.xml":[]byte(inbound),
	"/etc/firewalld/policies/cyberpanel-outbound.xml":[]byte(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<policy target=\"%s\"><ingress-zone name=\"HOST\"/><egress-zone name=\"ANY\"/></policy>\n",strings.ToUpper(string(policy.DefaultOutbound)))),
};for _,zoneName:=range []string{"public","external","dmz","work","home","internal","trusted"}{path:="/etc/firewalld/policies/cyberpanel-forward-"+zoneName+".xml";result[path]=[]byte(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<policy target=\"%s\"><ingress-zone name=\"%s\"/><egress-zone name=\"ANY\"/></policy>\n",strings.ToUpper(string(policy.DefaultForward)),zoneName))};return result}

func (executor *LinuxOperationsExecutor) applySSHPolicy(ctx context.Context, request EffectRequest, effect SSHPolicyEffect) (linuxEffectResult, error) {
	if replay, done, err := executor.replaySecurityEffect(ctx, request); done || err != nil {
		return replay, err
	}
	policy := effect.Policy
	if err := validateProtectedManagementProbe(policy.ManagementProbe); err != nil {
		return linuxEffectResult{}, err
	}
	content, err := renderSSHPolicy(policy)
	if err != nil {
		return linuxEffectResult{}, err
	}
	candidate, err := executor.stageSecurityGeneration(KindSSHPolicy, policy.ID, policy.Generation, policy, content, "conf")
	if err != nil {
		return linuxEffectResult{}, err
	}
	previous, same, err := executor.securityGenerationCAS(candidate)
	if err != nil {
		return linuxEffectResult{}, err
	}
	if same {
		return linuxEffectResult{MutationObserved: true}, ErrCompensationFailed
	}
	effective, err := executor.runner.Run(ctx, "/usr/sbin/sshd", "-T", "-f", "/etc/ssh/sshd_config", "-C", "user=root,host=localhost,addr=127.0.0.1")
	if err != nil {
		return linuxEffectResult{}, fmt.Errorf("observe current sshd policy: %w: %s", err, boundedText(effective, 2048))
	}
	previousPorts := parseSSHDPorts(effective)
	if len(previousPorts) == 0 {
		previousPorts = []uint16{22}
	}
	snapshot, err := executor.snapshotFile("/etc/ssh/sshd_config.d/50-cyberpanel.conf")
	if err != nil {
		return linuxEffectResult{}, err
	}
	lease, err := executor.armSecurityLease(request, candidate, previous, []operationsFileSnapshot{snapshot}, true, previousPorts)
	if err != nil {
		return linuxEffectResult{}, err
	}
	result := linuxEffectResult{Snapshots: []operationsFileSnapshot{snapshot}, MutationObserved: true}
	dualPorts := append([]uint16{policy.Port}, previousPorts...)
	dualContent, err := renderSSHPolicyPorts(policy, dualPorts)
	if err != nil {
		return result, err
	}
	if _, err = executor.replaceManagedFile("/etc/ssh/sshd_config.d/50-cyberpanel.conf", dualContent, 0o600); err != nil {
		return result, err
	}
	validateDual, err := executor.runner.Run(ctx, "/usr/sbin/sshd", "-t", "-f", "/etc/ssh/sshd_config")
	if err != nil {
		return result, fmt.Errorf("validate dual ssh listener: %w: %s", err, boundedText(validateDual, 2048))
	}
	reloadDual, err := executor.reloadSSHD(ctx)
	if err != nil {
		return result, err
	}
	if _, err = executor.probeSSHListener(ctx, policy.Port, policy.ManagementProbe.MinimumSuccesses); err != nil {
		return result, err
	}
	if _, err = executor.replaceManagedFile("/etc/ssh/sshd_config.d/50-cyberpanel.conf", content, 0o600); err != nil {
		return result, err
	}
	validateFinal, err := executor.runner.Run(ctx, "/usr/sbin/sshd", "-t", "-f", "/etc/ssh/sshd_config")
	if err != nil {
		return result, fmt.Errorf("validate final ssh policy: %w: %s", err, boundedText(validateFinal, 2048))
	}
	reloadFinal, err := executor.reloadSSHD(ctx)
	if err != nil {
		return result, err
	}
	effectiveFinal, err := executor.runner.Run(ctx, "/usr/sbin/sshd", "-T", "-f", "/etc/ssh/sshd_config", "-C", "user=root,host=localhost,addr=127.0.0.1")
	if err != nil {
		return result, err
	}
	finalPorts := parseSSHDPorts(effectiveFinal)
	if len(finalPorts) != 1 || finalPorts[0] != policy.Port {
		return result, ErrCompensationFailed
	}
	listenerProof, err := executor.probeSSHListener(ctx, policy.Port, policy.ManagementProbe.MinimumSuccesses)
	if err != nil {
		return result, err
	}
	activation := &ActivationEvidence{
		Strategy: ActivationMakeBeforeBreak, CandidateDigest: candidate.PolicyDigest,
		PreviousDigest: snapshotDigest(snapshot), StageReceiptDigest: candidate.NativeDigest,
		ProbeReceiptDigest: digestBytes(listenerProof),
		CommitReceiptDigest: digestBytes(append(append(append(append(validateDual, reloadDual...), validateFinal...), reloadFinal...), effectiveFinal...)),
	}
	if err = executor.storeGeneration(KindSSHPolicy, policy.ID, policy.Generation, candidate.PolicyDigest); err != nil {
		return result, err
	}
	if err = executor.confirmSecurityLease(request.EffectID, lease.ConfirmationNonce, activation); err != nil {
		return result, errors.Join(ErrCompensationFailed, err)
	}
	result.Activation = activation
	return result, nil
}

func renderSSHPolicy(policy SSHPolicy) ([]byte,error) {
	return renderSSHPolicyPorts(policy, []uint16{policy.Port})
}

func renderSSHPolicyPorts(policy SSHPolicy, ports []uint16) ([]byte,error) {
	var buffer bytes.Buffer
	uniquePorts := map[uint16]struct{}{}
	buffer.WriteString("# CyberPanel immutable SSH policy generation ")
	buffer.WriteString(strconv.FormatUint(policy.Generation, 10))
	buffer.WriteByte('\n')
	for _, port := range ports {
		if port == 0 {
			return nil, ErrInvalidEffect
		}
		if _, exists := uniquePorts[port]; exists {
			continue
		}
		uniquePorts[port] = struct{}{}
		fmt.Fprintf(&buffer, "Port %d\n", port)
	}
	fmt.Fprintf(&buffer, "PermitRootLogin %s\nPasswordAuthentication no\nPermitEmptyPasswords no\nKbdInteractiveAuthentication %s\nPubkeyAuthentication yes\n", yesNo(policy.AllowRoot), yesNo(policy.Authentication == SSHKeysAndMFA))
	if policy.Authentication == SSHKeysAndMFA { buffer.WriteString("AuthenticationMethods publickey,keyboard-interactive:pam\n") } else { buffer.WriteString("AuthenticationMethods publickey\n") }
	fmt.Fprintf(&buffer, "AllowTcpForwarding %s\nAllowAgentForwarding %s\nAllowStreamLocalForwarding %s\nGatewayPorts no\nPermitTunnel no\nX11Forwarding no\nPermitUserEnvironment no\nPermitUserRC no\nStrictModes yes\nLoginGraceTime 30\nClientAliveInterval %d\nClientAliveCountMax 1\nMaxAuthTries %d\nMaxSessions %d\nAuthorizedKeysFile /etc/ssh/authorized_keys/cyberpanel-%%u\n", yesNo(policy.AllowTCPForwarding), yesNo(policy.AllowAgentForwarding), yesNo(policy.AllowTCPForwarding), int(policy.IdleTimeout/time.Second), policy.MaxAuthTries, policy.MaxSessions)
	if len(policy.AllowedGroups) > 0 { groups := make([]string, len(policy.AllowedGroups)); for index, group := range policy.AllowedGroups { name:=group.String();if !managedSSHGroup(name){return nil,ErrInvalidEffect};if _,err:=user.LookupGroup(name);err!=nil{return nil,ErrInvalidEffect};groups[index] = name }; buffer.WriteString("AllowGroups "+strings.Join(groups, " ")+"\n") }
	return buffer.Bytes(),nil
}

func (executor *LinuxOperationsExecutor) probeSSHListener(ctx context.Context, port uint16, successes uint8) ([]byte, error) {
	if successes == 0 || successes > 8 {
		return nil, ErrInvalidEffect
	}
	var evidence []byte
	dialer := net.Dialer{Timeout: 2 * time.Second}
	for count := uint8(0); count < successes; count++ {
		connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		if err != nil {
			return evidence, err
		}
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		banner := make([]byte, 256)
		read, readErr := connection.Read(banner)
		_ = connection.Close()
		if readErr != nil || read == 0 || !strings.HasPrefix(string(banner[:read]), "SSH-2.0-") {
			return evidence, ErrCompensationFailed
		}
		evidence = append(evidence, bytes.TrimSpace(banner[:read])...)
		evidence = append(evidence, '\n')
	}
	listeners, err := executor.runner.Run(ctx, "/usr/bin/ss", "-H", "-lntp", "sport", "=", ":"+strconv.Itoa(int(port)))
	if err != nil || !strings.Contains(string(listeners), "sshd") {
		return evidence, ErrCompensationFailed
	}
	evidence = append(evidence, listeners...)
	return evidence, nil
}

func (executor *LinuxOperationsExecutor) putSSHKey(effect PutSSHKeyEffect) (linuxEffectResult, error) {
	key := effect.Key; path := "/etc/ssh/authorized_keys/cyberpanel-" + key.PrincipalID.String()
	if err:=executor.guardGeneration(KindSSHKey,key.ID,key.Generation,key);err!=nil{return linuxEffectResult{},err}
	if !managedSSHPrincipal(key.PrincipalID.String()){return linuxEffectResult{},ErrInvalidEffect};account,lookupErr:=user.Lookup(key.PrincipalID.String());if lookupErr!=nil{return linuxEffectResult{},ErrInvalidEffect};uid,uidErr:=strconv.ParseUint(account.Uid,10,32);if uidErr!=nil||uid==0{return linuxEffectResult{},ErrInvalidEffect}
	if err:=validateSSHKeyMaterial(key);err!=nil{return linuxEffectResult{},err}
	content := renderSSHKey(key)
	snapshot, err := executor.snapshotFile(path); if err != nil { return linuxEffectResult{}, err }
	existing := snapshot.Content
	marker := " cyberpanel:"+key.ID.String()
	lines := strings.Split(strings.TrimSpace(string(existing)), "\n"); replaced := false
	for index, line := range lines { if strings.HasSuffix(line, marker) { lines[index] = strings.TrimSpace(string(content)); replaced = true } }
	if !replaced { lines = append(lines, strings.TrimSpace(string(content))) }
	clean := make([]string, 0, len(lines)); for _, line := range lines { if strings.TrimSpace(line) != "" { clean = append(clean, line) } }
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil { return linuxEffectResult{}, err }
	if err = atomicOperationsFile(path, []byte(strings.Join(clean, "\n")+"\n"), 0o600); err != nil { return linuxEffectResult{}, err };if err=executor.storeGeneration(KindSSHKey,key.ID,key.Generation,mustActivationDigest(key));err!=nil{return linuxEffectResult{Snapshots:[]operationsFileSnapshot{snapshot},MutationObserved:true},err}
	return linuxEffectResult{Snapshots: []operationsFileSnapshot{snapshot}, MutationObserved: true}, nil
}

func validateSSHKeyMaterial(key SSHKey)error{if strings.ContainsAny(key.PublicBlob," \t"){return ErrInvalidEffect};decoded,err:=base64.StdEncoding.DecodeString(key.PublicBlob);if err!=nil||len(decoded)<8{return ErrInvalidEffect};length:=binary.BigEndian.Uint32(decoded[:4]);if length==0||int(length)>len(decoded)-4||string(decoded[4:4+length])!=key.Algorithm{return ErrInvalidEffect};digest:=sha256.Sum256(decoded);if hex.EncodeToString(digest[:])!=key.FingerprintSHA256{return ErrInvalidEffect};return nil}

func (executor *LinuxOperationsExecutor) deleteSSHKey(effect DeleteSSHKeyEffect) (linuxEffectResult, error) {
	key := effect.Key; path := "/etc/ssh/authorized_keys/cyberpanel-"+key.PrincipalID.String(); snapshot, err := executor.snapshotFile(path); if err != nil { return linuxEffectResult{}, err }
	if err=executor.guardGeneration(KindSSHKey,key.ID,key.Generation,key);err!=nil{return linuxEffectResult{},err}
	if !managedSSHPrincipal(key.PrincipalID.String()){return linuxEffectResult{},ErrInvalidEffect}
	marker := " cyberpanel:"+key.ID.String(); var kept []string
	for _, line := range strings.Split(string(snapshot.Content), "\n") { if line != "" && !strings.HasSuffix(line, marker) { kept = append(kept, line) } }
	if len(kept) == 0 { err = os.Remove(path); if errors.Is(err, os.ErrNotExist) { err = nil } } else { err = atomicOperationsFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600) }
	if err != nil { return linuxEffectResult{}, err }
	if err=executor.storeGeneration(KindSSHKey,key.ID,key.Generation,mustActivationDigest(key));err!=nil{return linuxEffectResult{Snapshots:[]operationsFileSnapshot{snapshot},MutationObserved:true},err}
	return linuxEffectResult{Snapshots: []operationsFileSnapshot{snapshot}, MutationObserved: true}, nil
}

func renderSSHKey(key SSHKey) []byte {
	var restrictions []string
	if len(key.Restrictions.SourceCIDRs) > 0 { values := make([]string, len(key.Restrictions.SourceCIDRs)); for index, prefix := range key.Restrictions.SourceCIDRs { values[index] = prefix.String() }; restrictions = append(restrictions, "from=\""+strings.Join(values, ",")+"\"") }
	if !key.Restrictions.PermitPTY { restrictions = append(restrictions, "no-pty") }
	if !key.Restrictions.PermitPortForwarding { restrictions = append(restrictions, "no-port-forwarding") }
	if !key.Restrictions.PermitAgentForwarding { restrictions = append(restrictions, "no-agent-forwarding") }
	prefix := ""; if len(restrictions) > 0 { prefix = strings.Join(restrictions, ",")+" " }
	return []byte(prefix+key.Algorithm+" "+key.PublicBlob+" cyberpanel:"+key.ID.String()+"\n")
}
func managedSSHPrincipal(value string)bool{return strings.HasPrefix(value,"cp_")&&len(value)<=32}
func managedSSHGroup(value string)bool{return managedSSHPrincipal(value)||value=="cyberpanel-users"}

func (executor *LinuxOperationsExecutor) applyWAF(ctx context.Context, effect WAFPolicyEffect) (linuxEffectResult, error) {
	policy := effect.Policy
	if err := executor.guardGeneration(KindWAFPolicy, policy.ID, policy.Generation, policy); err != nil { return linuxEffectResult{}, err }
	content, err := executor.renderWAF(policy); if err != nil { return linuxEffectResult{}, err }
	candidateDigest, _ := activationDigest(policy); path := "/usr/local/lsws/conf/modsec/cyberpanel.conf"
	snapshot, err := executor.replaceManagedFile(path, content, 0o600); if err != nil { return linuxEffectResult{}, err }
	result := linuxEffectResult{Snapshots: []operationsFileSnapshot{snapshot}, MutationObserved: true}
	validateOutput, err := executor.validateWebConfiguration(ctx); if err != nil { return result, err }
	reloadOutput, err := executor.runner.Run(ctx, "/usr/local/lsws/bin/lswsctrl", "reload"); if err != nil { return result, err }
	probeOutput,err:=executor.runner.Run(ctx,"/usr/bin/systemctl","is-active","lsws.service");if err!=nil||strings.TrimSpace(string(probeOutput))!="active"{return result,errors.New("web engine failed post-WAF activation probe")}
	if err = executor.storeGeneration(KindWAFPolicy, policy.ID, policy.Generation, candidateDigest); err != nil { return result, err }
	result.Activation = &ActivationEvidence{Strategy:ActivationCompileProbeSwap,CandidateDigest:candidateDigest,PreviousDigest:snapshotDigest(snapshot),StageReceiptDigest:digestBytes(validateOutput),ProbeReceiptDigest:digestBytes(probeOutput),CommitReceiptDigest:digestBytes(reloadOutput)}
	return result, nil
}

func (executor *LinuxOperationsExecutor) renderWAF(policy WAFPolicy) ([]byte, error) {
	var buffer bytes.Buffer
	mode := map[WAFMode]string{WAFDisabled: "Off", WAFDetectionOnly: "DetectionOnly", WAFBlocking: "On"}[policy.Mode]
	auditMode:="RelevantOnly";if policy.AuditSamplingBasisPoints==0{auditMode="Off"}else if policy.AuditSamplingBasisPoints==10000{auditMode="On"}
	fmt.Fprintf(&buffer, "# CyberPanel WAF generation %d\n# Audit sampling basis points: %d\nSecRuleEngine %s\nSecRequestBodyLimit %d\nSecAuditEngine %s\n", policy.Generation,policy.AuditSamplingBasisPoints, mode, policy.RequestBodyLimitBytes,auditMode)
	packs := append([]WAFPack(nil), policy.ProviderPacks...); if policy.CRS != nil { packs = append([]WAFPack{*policy.CRS}, packs...) }
	for _, pack := range packs { path, ok := executor.wafPacks[pack.Provider.String()+":"+pack.Name.String()]; if !ok || !allowedWAFPackPath(path) { return nil, ErrInvalidEffect }; digest, err := fileDigest(path, 64<<20); if err != nil || digest != pack.ContentDigest { return nil, ErrInvalidEffect }; fmt.Fprintf(&buffer, "Include %s\n", path) }
	usedRuleIDs:=make(map[uint32]struct{},len(policy.CustomRules)+len(policy.Exclusions))
	for _, rule := range policy.CustomRules { usedRuleIDs[rule.ID]=struct{}{}; if strings.ContainsAny(rule.Pattern, "\r\n\"") { return nil, ErrInvalidEffect }; target := map[WAFTarget]string{WAFTargetURI:"REQUEST_URI", WAFTargetArgs:"ARGS", WAFTargetHeaders:"REQUEST_HEADERS", WAFTargetBody:"REQUEST_BODY"}[rule.Target]; operator := map[WAFOperator]string{WAFOperatorRegex:"@rx", WAFOperatorContains:"@contains", WAFOperatorEquals:"@streq"}[rule.Operator]; actions := make([]string, 0, len(rule.Actions)+3); actions = append(actions, fmt.Sprintf("id:%d", rule.ID), fmt.Sprintf("phase:%d", rule.Phase), fmt.Sprintf("severity:%d", rule.Severity)); for _, action := range rule.Actions { actions = append(actions, string(action)) }; fmt.Fprintf(&buffer, "SecRule %s \"%s %s\" \"%s\"\n", target, operator, rule.Pattern, strings.Join(actions, ",")) }
	for exclusionIndex, exclusion := range policy.Exclusions {
		if !exclusion.ExpiresAt.After(time.Now().UTC()) { return nil,ErrInvalidEffect }
		if exclusion.RequestPathPrefix != "" {
			if strings.ContainsAny(exclusion.RequestPathPrefix,"\"") { return nil,ErrInvalidEffect }
			syntheticID:=uint32(990000000+exclusionIndex);for { if _,exists:=usedRuleIDs[syntheticID];!exists{break};syntheticID++ };usedRuleIDs[syntheticID]=struct{}{}
			actions:=[]string{fmt.Sprintf("id:%d",syntheticID),"phase:1","pass","nolog"}
			for _,ruleID:=range exclusion.RuleIDs { if len(exclusion.ArgumentNames)==0 { actions=append(actions,fmt.Sprintf("ctl:ruleRemoveById=%d",ruleID)) } else { for _,name:=range exclusion.ArgumentNames { actions=append(actions,fmt.Sprintf("ctl:ruleRemoveTargetById=%d;ARGS:%s",ruleID,name)) } } }
			fmt.Fprintf(&buffer,"SecRule REQUEST_URI \"@beginsWith %s\" \"%s\"\n",exclusion.RequestPathPrefix,strings.Join(actions,",")); continue
		}
		for _, ruleID := range exclusion.RuleIDs { if len(exclusion.ArgumentNames) == 0 { fmt.Fprintf(&buffer, "SecRuleRemoveById %d\n", ruleID); continue }; for _, name := range exclusion.ArgumentNames { fmt.Fprintf(&buffer, "SecRuleUpdateTargetById %d !ARGS:%s\n", ruleID, name) } }
	}
	return buffer.Bytes(), nil
}

func (executor *LinuxOperationsExecutor) validateWebConfiguration(ctx context.Context) ([]byte, error) {
	if info, err := os.Stat("/usr/local/lsws/bin/openlitespeed"); err == nil && info.Mode().IsRegular() { output, runErr := executor.runner.Run(ctx, "/usr/local/lsws/bin/openlitespeed", "-t"); return output, runErr }
	return executor.runner.Run(ctx, "/usr/local/lsws/bin/lshttpd", "-t")
}

func (executor *LinuxOperationsExecutor) guardGeneration(kind ResourceKind, id ResourceID, generation uint64, value any) error {
	if generation == 0 { return ErrInvalidEffect }
	digest, _ := activationDigest(value); path := executor.generationPath(kind, id)
	content, err := os.ReadFile(path); if errors.Is(err, os.ErrNotExist) { return nil }; if err != nil { return err }
	var current struct { Generation uint64 `json:"generation"`; Digest string `json:"digest"` }
	if json.Unmarshal(content, &current) != nil || current.Generation > generation || current.Generation == generation && current.Digest != digest { return ErrConflict }
	return nil
}

func (executor *LinuxOperationsExecutor) storeGeneration(kind ResourceKind, id ResourceID, generation uint64, digest string) error {
	content, _ := json.Marshal(struct { Generation uint64 `json:"generation"`; Digest string `json:"digest"` }{generation, digest})
	return atomicOperationsFile(executor.generationPath(kind, id), content, 0o600)
}

func (executor *LinuxOperationsExecutor) requireGeneration(kind ResourceKind,id ResourceID,generation uint64)error{content,err:=os.ReadFile(executor.generationPath(kind,id));if err!=nil{return err};var current struct{Generation uint64 `json:"generation"`;Digest string `json:"digest"`};if json.Unmarshal(content,&current)!=nil||current.Generation!=generation||!validSHA256(current.Digest){return ErrConflict};return nil}

func (executor *LinuxOperationsExecutor) generationPath(kind ResourceKind, id ResourceID) string { return filepath.Join(executor.stateRoot, "generations", string(kind)+"-"+id.String()+".json") }
func activationDigest(value any) (string, error) { content, err := json.Marshal(value); if err != nil { return "", err }; digest := sha256.Sum256(content); return hex.EncodeToString(digest[:]), nil }
func activationEvidence(strategy ActivationStrategy, candidate, previous, stage, commit string) *ActivationEvidence { return &ActivationEvidence{Strategy: strategy, CandidateDigest: candidate, PreviousDigest: previous, StageReceiptDigest: stage, ProbeReceiptDigest: digestBytes([]byte("probe-confirmed:"+candidate)), CommitReceiptDigest: commit} }
func digestBytes(content []byte) string { digest := sha256.Sum256(content); return hex.EncodeToString(digest[:]) }
func snapshotDigest(snapshot operationsFileSnapshot) string { if !snapshot.Existed { return "" }; return digestBytes(snapshot.Content) }
func yesNo(value bool) string { if value { return "yes" }; return "no" }
func boundedText(content []byte, maximum int) string { if len(content) > maximum { content = content[:maximum] }; return strings.TrimSpace(string(content)) }
func probeTCP(ctx context.Context, port uint16, successes uint8) error { dialer := net.Dialer{Timeout: 2*time.Second}; for count := uint8(0); count < successes; count++ { connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))); if err != nil { return err }; _ = connection.Close() }; return nil }
func allowedWAFPackPath(path string) bool { clean := filepath.Clean(path); return strings.HasPrefix(clean, "/usr/share/modsecurity-crs/") || strings.HasPrefix(clean, "/usr/local/lsws/conf/modsec/packs/") }
func fileDigest(path string, maximum int64) (string, error) { info, err := os.Lstat(path); if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum { return "", ErrInvalidEffect }; content, err := os.ReadFile(path); if err != nil { return "", err }; return digestBytes(content), nil }
