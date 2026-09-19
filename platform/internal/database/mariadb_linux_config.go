//go:build linux

package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type generatedFile struct {
	Payload []byte
	Mode    os.FileMode
}

type fixedHostOperation uint8

const (
	hostRestartMariaDB fixedHostOperation = iota + 1
	hostReloadNftables
	hostUpgradeMariaDBUbuntu
	hostUpgradeMariaDBAlma
	hostRunMariaDBUpgrade
)

func (executor *LinuxMariaDBExecutor) writeGeneration(id ResourceID, generation uint64, files map[string]generatedFile) (string, error) {
	if id.IsZero() || generation == 0 || len(files) == 0 || len(files) > 16 {
		return "", ErrInvalidResource
	}
	root := filepath.Join(mariaDBConfigRoot, "generations", id.String(), strconv.FormatUint(generation, 10))
	if err := ensureRootDirectory(root, 0700); err != nil {
		return "", err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		if !safeGeneratedName(name) {
			return "", ErrInvalidResource
		}
		names = append(names, name)
	}
	sort.Strings(names)
	manifest := struct {
		Adapter    string            `json:"adapter"`
		ResourceID ResourceID        `json:"resource_id"`
		Generation uint64            `json:"generation"`
		Digests    map[string]string `json:"digests"`
	}{mariaDBAdapterVersion, id, generation, make(map[string]string, len(names))}
	for _, name := range names {
		file := files[name]
		if len(file.Payload) == 0 || len(file.Payload) > 4<<20 || file.Mode != 0600 && file.Mode != 0644 {
			return "", ErrInvalidResource
		}
		manifest.Digests[name] = digestBytes(file.Payload)
		if err := atomicRootFile(filepath.Join(root, name), file.Payload, file.Mode); err != nil {
			return "", err
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	if err := atomicRootFile(filepath.Join(root, "manifest.json"), append(encoded, '\n'), 0600); err != nil {
		return "", err
	}
	return root, nil
}

func safeGeneratedName(name string) bool {
	if name == "" || len(name) > 96 || strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		return false
	}
	for index := range name {
		character := name[index]
		if !asciiAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func (executor *LinuxMariaDBExecutor) applyNetworkPolicy(ctx context.Context, request EffectRequest, policy NetworkAccessPolicy) (effectApplication, error) {
	instance, err := executor.instance(policy.InstanceID)
	if err != nil {
		return effectApplication{failureCode: "instance_not_found"}, err
	}
	if instance.NetworkPolicyID != policy.ID {
		return effectApplication{failureCode: "precondition_failed"}, ErrUnauthorized
	}
	var previous NetworkAccessPolicy
	previousErr := executor.readResource("policies", policy.ID, &previous)
	if previousErr != nil && !errors.Is(previousErr, ErrNotFound) {
		return effectApplication{failureCode: "state_persistence_failed"}, previousErr
	}
	if previousErr == nil && previous.InstanceID != policy.InstanceID {
		return effectApplication{failureCode: "precondition_failed"}, ErrConflict
	}
	if instance.Placement == PlacementExternal {
		return executor.applyExternalNetworkPolicy(ctx, request, instance, policy, previous, previousErr == nil)
	}
	return executor.applyLocalNetworkPolicy(ctx, request, instance, policy, previous, previousErr == nil)
}

func (executor *LinuxMariaDBExecutor) applyExternalNetworkPolicy(ctx context.Context, request EffectRequest, instance DatabaseInstance, policy NetworkAccessPolicy, previous NetworkAccessPolicy, hasPrevious bool) (effectApplication, error) {
	if instance.External == nil || policy.TLS != instance.External.RequiredTLS || policy.Verification != VerifyIndependentExternal {
		return effectApplication{failureCode: "external_network_unmanaged"}, ErrUnauthorized
	}
	compensationValue := mariaDBCompensation{Kind: EffectApplyNetworkPolicy, InstanceID: instance.ID, TargetID: policy.ID, RemoveState: !hasPrevious}
	if hasPrevious {
		compensationValue.Policy = &previous
	}
	compensation, err := executor.saveCompensation(request, compensationValue)
	if err != nil {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	defer cleanup()
	proof, err := connection.query(ctx, sqlObserveStatus)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	manifest, _ := json.MarshalIndent(policy, "", "  ")
	if _, err := executor.writeGeneration(policy.ID, policy.Generation, map[string]generatedFile{"external-network-policy.json": {Payload: append(manifest, '\n'), Mode: 0600}}); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "network_apply_failed"}, err
	}
	if err := executor.writeResource("policies", policy.ID, policy); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	return effectApplication{proof: append(proof, manifest...), mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) applyLocalNetworkPolicy(ctx context.Context, request EffectRequest, instance DatabaseInstance, policy NetworkAccessPolicy, previous NetworkAccessPolicy, hasPrevious bool) (effectApplication, error) {
	serverConfigPath := executor.serverConfigPath()
	previousServer, serverExists, err := readManagedConfig(serverConfigPath)
	if err != nil {
		return effectApplication{failureCode: "precondition_failed"}, err
	}
	previousFirewall, firewallExists, err := readManagedConfig(mariaDBFirewallConfig)
	if err != nil {
		return effectApplication{failureCode: "precondition_failed"}, err
	}
	compensationValue := mariaDBCompensation{Kind: EffectApplyNetworkPolicy, InstanceID: instance.ID, TargetID: policy.ID, RemoveState: !hasPrevious,
		ServerConfigPresent: serverExists, FirewallConfigPresent: firewallExists}
	if hasPrevious { compensationValue.Policy = &previous }
	if serverExists { compensationValue.ServerConfig = previousServer }
	if firewallExists { compensationValue.FirewallConfig = previousFirewall }
	compensation, err := executor.saveCompensation(request, compensationValue)
	if err != nil {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	proof, err := executor.installLocalConfiguration(ctx, instance, policy, nil, policy.ID, policy.Generation)
	if err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "network_apply_failed"}, err
	}
	if err := executor.writeResource("policies", policy.ID, policy); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	return effectApplication{proof: proof, mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) installLocalConfiguration(ctx context.Context, instance DatabaseInstance, policy NetworkAccessPolicy, tuning *TuningProfile, generationID ResourceID, generation uint64) ([]byte, error) {
	material, err := executor.secrets.LocalServerTLS(ctx, instance.ID, policy.ID, policy.TLS)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(material.CertificateAuthorityPEM, material.CertificatePEM, material.KeyPEM)
	if err := validateServerTLS(material); err != nil {
		return nil, err
	}
	generationRoot := filepath.Join(mariaDBConfigRoot, "generations", generationID.String(), strconv.FormatUint(generation, 10))
	serverConfig := renderServerConfiguration(policy, tuning, filepath.Join(generationRoot, "ca.pem"), filepath.Join(generationRoot, "server-cert.pem"), filepath.Join(generationRoot, "server-key.pem"))
	firewallConfig := renderFirewallConfiguration(policy)
	files := map[string]generatedFile{
		"ca.pem":             {Payload: material.CertificateAuthorityPEM, Mode: 0644},
		"server-cert.pem":    {Payload: material.CertificatePEM, Mode: 0644},
		"server-key.pem":     {Payload: material.KeyPEM, Mode: 0600},
		"server.cnf":         {Payload: serverConfig, Mode: 0644},
		"network-policy.nft": {Payload: firewallConfig, Mode: 0644},
	}
	root, err := executor.writeGeneration(generationID, generation, files)
	if err != nil {
		return nil, err
	}
	if root != generationRoot {
		return nil, ErrInvalidResource
	}
	if err := atomicRootFile(executor.serverConfigPath(), serverConfig, 0644); err != nil {
		return nil, err
	}
	if err := atomicRootFile(mariaDBFirewallConfig, firewallConfig, 0644); err != nil {
		return nil, err
	}
	firewallProof, err := runFixedHost(ctx, hostReloadNftables)
	if err != nil {
		return nil, err
	}
	databaseProof, err := runFixedHost(ctx, hostRestartMariaDB)
	if err != nil {
		return nil, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	status, err := connection.query(ctx, sqlObserveStatus)
	if err != nil {
		return nil, err
	}
	proof := append(append(append([]byte(nil), firewallProof...), databaseProof...), status...)
	return proof, nil
}

func renderServerConfiguration(policy NetworkAccessPolicy, tuning *TuningProfile, caPath, certificatePath, keyPath string) []byte {
	bindAddress := "127.0.0.1"
	for _, networkInterface := range policy.Interfaces {
		if networkInterface == InterfacePrivate || networkInterface == InterfacePublic {
			bindAddress = "0.0.0.0"
		}
	}
	var result strings.Builder
	result.WriteString("# Managed by CyberPanel; manual edits are replaced.\n[mariadbd]\n")
	result.WriteString("bind-address=")
	result.WriteString(bindAddress)
	result.WriteString("\nport=3306\nskip_name_resolve=ON\nrequire_secure_transport=ON\n")
	result.WriteString("ssl_ca=")
	result.WriteString(caPath)
	result.WriteString("\nssl_cert=")
	result.WriteString(certificatePath)
	result.WriteString("\nssl_key=")
	result.WriteString(keyPath)
	result.WriteByte('\n')
	if tuning != nil {
		settings := tuning.Settings
		result.WriteString("innodb_buffer_pool_size=")
		result.WriteString(strconv.FormatUint(settings.BufferPoolBytes, 10))
		result.WriteString("\nmax_connections=")
		result.WriteString(strconv.FormatUint(uint64(settings.MaxConnections), 10))
		result.WriteString("\ntmp_table_size=")
		result.WriteString(strconv.FormatUint(settings.TempTableBytes, 10))
		result.WriteString("\nmax_heap_table_size=")
		result.WriteString(strconv.FormatUint(settings.TempTableBytes, 10))
		result.WriteString("\nslow_query_log=ON\nlong_query_time=")
		result.WriteString(slowQuerySeconds(settings.SlowQueryMillis))
		result.WriteString("\ninnodb_flush_method=")
		if settings.FlushMethod == FlushODirect { result.WriteString("O_DIRECT") } else { result.WriteString("fsync") }
		result.WriteByte('\n')
	}
	return []byte(result.String())
}

func renderFirewallConfiguration(policy NetworkAccessPolicy) []byte {
	ipv4 := make([]string, 0, len(policy.AllowedCIDRs))
	ipv6 := make([]string, 0, len(policy.AllowedCIDRs))
	for _, prefix := range policy.AllowedCIDRs {
		if prefix.Addr().Is4() { ipv4 = append(ipv4, prefix.String()) } else { ipv6 = append(ipv6, prefix.String()) }
	}
	sort.Strings(ipv4)
	sort.Strings(ipv6)
	var result strings.Builder
	result.WriteString("table inet cyberpanel_mariadb {\n  chain input {\n    type filter hook input priority -5; policy accept;\n    iifname \"lo\" tcp dport 3306 accept\n")
	if len(ipv4) > 0 {
		result.WriteString("    ip saddr { ")
		result.WriteString(strings.Join(ipv4, ", "))
		result.WriteString(" } tcp dport 3306 accept\n")
	}
	if len(ipv6) > 0 {
		result.WriteString("    ip6 saddr { ")
		result.WriteString(strings.Join(ipv6, ", "))
		result.WriteString(" } tcp dport 3306 accept\n")
	}
	result.WriteString("    tcp dport 3306 reject with tcp reset\n  }\n}\n")
	return []byte(result.String())
}

func (executor *LinuxMariaDBExecutor) compensateNetworkPolicy(ctx context.Context, compensation mariaDBCompensation) ([]byte, error) {
	instance, err := executor.instance(compensation.InstanceID)
	if err != nil { return nil, err }
	if instance.Placement == PlacementExternal {
		if compensation.RemoveState {
			return []byte("external-network-policy-removed"), executor.removeResource("policies", compensation.TargetID)
		}
		if compensation.Policy == nil { return nil, ErrCompensationFailed }
		return []byte("external-network-policy-restored"), executor.writeResource("policies", compensation.Policy.ID, *compensation.Policy)
	}
	if compensation.ServerConfigPresent {
		if len(compensation.ServerConfig) == 0 { return nil, ErrCompensationFailed }
		if err := atomicRootFile(executor.serverConfigPath(), compensation.ServerConfig, 0644); err != nil { return nil, err }
	} else if err := os.Remove(executor.serverConfigPath()); err != nil && !os.IsNotExist(err) { return nil, err }
	if compensation.FirewallConfigPresent {
		if len(compensation.FirewallConfig) == 0 { return nil, ErrCompensationFailed }
		if err := atomicRootFile(mariaDBFirewallConfig, compensation.FirewallConfig, 0644); err != nil { return nil, err }
	} else if err := os.Remove(mariaDBFirewallConfig); err != nil && !os.IsNotExist(err) { return nil, err }
	firewallProof, err := runFixedHost(ctx, hostReloadNftables)
	if err != nil { return nil, err }
	databaseProof, err := runFixedHost(ctx, hostRestartMariaDB)
	if err != nil { return nil, err }
	if compensation.Policy != nil {
		err = executor.writeResource("policies", compensation.Policy.ID, *compensation.Policy)
	} else if compensation.RemoveState {
		err = executor.removeResource("policies", compensation.TargetID)
	}
	return append(firewallProof, databaseProof...), err
}

func (executor *LinuxMariaDBExecutor) applyTuning(ctx context.Context, request EffectRequest, profile TuningProfile) (effectApplication, error) {
	instance, err := executor.instance(profile.InstanceID)
	if err != nil {
		return effectApplication{failureCode: "instance_not_found"}, err
	}
	if compareVersion(instance.Version, profile.Version) != 0 {
		return effectApplication{failureCode: "precondition_failed"}, ErrConflict
	}
	if instance.Placement == PlacementExternal {
		return executor.applyExternalTuning(ctx, request, instance, profile)
	}
	return executor.applyLocalTuning(ctx, request, instance, profile)
}

func (executor *LinuxMariaDBExecutor) applyLocalTuning(ctx context.Context, request EffectRequest, instance DatabaseInstance, profile TuningProfile) (effectApplication, error) {
	var policy NetworkAccessPolicy
	if err := executor.readResource("policies", instance.NetworkPolicyID, &policy); err != nil {
		return effectApplication{failureCode: "precondition_failed"}, err
	}
	previousServer, serverExists, err := readManagedConfig(executor.serverConfigPath())
	if err != nil || !serverExists {
		return effectApplication{failureCode: "precondition_failed"}, errors.Join(ErrNotFound, err)
	}
	previousFirewall, firewallExists, err := readManagedConfig(mariaDBFirewallConfig)
	if err != nil || !firewallExists {
		return effectApplication{failureCode: "precondition_failed"}, errors.Join(ErrNotFound, err)
	}
	compensationValue := mariaDBCompensation{Kind: EffectApplyTuning, InstanceID: instance.ID, TargetID: profile.ID, ServerConfig: previousServer, FirewallConfig: previousFirewall,
		ServerConfigPresent: true, FirewallConfigPresent: true, RemoveState: true}
	var previous TuningProfile
	if err := executor.readResource("tuning", profile.ID, &previous); err == nil {
		compensationValue.Tuning, compensationValue.RemoveState = &previous, false
	} else if !errors.Is(err, ErrNotFound) {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	compensation, err := executor.saveCompensation(request, compensationValue)
	if err != nil { return effectApplication{failureCode: "state_persistence_failed"}, err }
	proof, err := executor.installLocalConfiguration(ctx, instance, policy, &profile, profile.ID, profile.Generation)
	if err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "tuning_apply_failed"}, err
	}
	if err := executor.writeResource("tuning", profile.ID, profile); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	return effectApplication{proof: proof, mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) applyExternalTuning(ctx context.Context, request EffectRequest, instance DatabaseInstance, profile TuningProfile) (effectApplication, error) {
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil { return effectApplication{failureCode: "connection_failed"}, err }
	defer cleanup()
	observed, err := connection.query(ctx, sqlObserveTuning)
	if err != nil { return effectApplication{failureCode: "connection_failed"}, err }
	previous, err := tuningFromObservation(profile, observed)
	if err != nil || previous.Settings.FlushMethod != profile.Settings.FlushMethod {
		return effectApplication{failureCode: "precondition_failed"}, errors.Join(ErrConflict, err)
	}
	compensation, err := executor.saveCompensation(request, mariaDBCompensation{Kind: EffectApplyTuning, InstanceID: instance.ID, TargetID: profile.ID, Tuning: &previous})
	if err != nil { return effectApplication{failureCode: "state_persistence_failed"}, err }
	proof, err := connection.query(ctx, sqlApplyExternalTuning, profile)
	if err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "tuning_apply_failed"}, err
	}
	manifest, _ := json.MarshalIndent(profile, "", "  ")
	if _, err := executor.writeGeneration(profile.ID, profile.Generation, map[string]generatedFile{"external-tuning.json": {Payload: append(manifest, '\n'), Mode: 0600}}); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	if err := executor.writeResource("tuning", profile.ID, profile); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	return effectApplication{proof: proof, mutated: true, compensation: compensation}, nil
}

func tuningFromObservation(base TuningProfile, observed []byte) (TuningProfile, error) {
	fields := strings.Fields(strings.TrimSpace(string(observed)))
	if len(fields) != 6 { return TuningProfile{}, ErrInvalidResource }
	bufferPool, err := strconv.ParseUint(fields[0], 10, 64); if err != nil { return TuningProfile{}, err }
	connections, err := strconv.ParseUint(fields[1], 10, 32); if err != nil { return TuningProfile{}, err }
	tempTable, err := strconv.ParseUint(fields[2], 10, 64); if err != nil { return TuningProfile{}, err }
	heapTable, err := strconv.ParseUint(fields[3], 10, 64); if err != nil { return TuningProfile{}, err }
	if heapTable < tempTable { tempTable = heapTable }
	slowSeconds, err := strconv.ParseFloat(fields[4], 64); if err != nil || slowSeconds <= 0 { return TuningProfile{}, ErrInvalidResource }
	flush := FlushFsync
	if strings.EqualFold(fields[5], "O_DIRECT") { flush = FlushODirect } else if !strings.EqualFold(fields[5], "fsync") { return TuningProfile{}, ErrInvalidResource }
	base.Settings = TuningSettings{BufferPoolBytes: bufferPool, MaxConnections: uint32(connections), TempTableBytes: tempTable, SlowQueryMillis: uint32(slowSeconds * 1000), FlushMethod: flush}
	return base, nil
}

func (executor *LinuxMariaDBExecutor) compensateTuning(ctx context.Context, compensation mariaDBCompensation) ([]byte, error) {
	instance, err := executor.instance(compensation.InstanceID)
	if err != nil { return nil, err }
	if instance.Placement == PlacementExternal {
		if compensation.Tuning == nil { return nil, ErrCompensationFailed }
		connection, cleanup, err := executor.connection(ctx, instance)
		if err != nil { return nil, err }
		defer cleanup()
		proof, err := connection.query(ctx, sqlApplyExternalTuning, *compensation.Tuning)
		if err == nil { err = executor.writeResource("tuning", compensation.Tuning.ID, *compensation.Tuning) }
		return proof, err
	}
	if len(compensation.ServerConfig) == 0 || len(compensation.FirewallConfig) == 0 { return nil, ErrCompensationFailed }
	if err := atomicRootFile(executor.serverConfigPath(), compensation.ServerConfig, 0644); err != nil { return nil, err }
	if err := atomicRootFile(mariaDBFirewallConfig, compensation.FirewallConfig, 0644); err != nil { return nil, err }
	firewallProof, err := runFixedHost(ctx, hostReloadNftables); if err != nil { return nil, err }
	databaseProof, err := runFixedHost(ctx, hostRestartMariaDB); if err != nil { return nil, err }
	if compensation.Tuning != nil {
		err = executor.writeResource("tuning", compensation.Tuning.ID, *compensation.Tuning)
	} else if compensation.RemoveState {
		err = executor.removeResource("tuning", compensation.TargetID)
	}
	return append(firewallProof, databaseProof...), err
}

func (executor *LinuxMariaDBExecutor) applyUpgrade(ctx context.Context, _ EffectRequest, upgrade DatabaseUpgrade) (effectApplication, error) {
	instance, err := executor.instance(upgrade.InstanceID)
	if err != nil { return effectApplication{failureCode: "instance_not_found"}, err }
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil { return effectApplication{failureCode: "connection_failed"}, err }
	status, err := connection.query(ctx, sqlObserveStatus)
	cleanup()
	if err != nil { return effectApplication{failureCode: "upgrade_preflight_failed"}, err }
	observedVersion, err := parseMariaDBVersion(firstField(status))
	if err != nil { return effectApplication{failureCode: "upgrade_preflight_failed"}, err }
	switch upgrade.Phase {
	case UpgradeRequested, UpgradePreflight, UpgradePrepared:
		if compareVersion(observedVersion, upgrade.From) != 0 { return effectApplication{failureCode: "upgrade_preflight_failed"}, ErrConflict }
	case UpgradeCutover:
		if instance.Placement == PlacementExternal {
			return effectApplication{failureCode: "unsupported_external_upgrade"}, ErrUnauthorized
		}
		if compareVersion(observedVersion, upgrade.From) != 0 { return effectApplication{failureCode: "upgrade_preflight_failed"}, ErrConflict }
		operation := hostUpgradeMariaDBUbuntu
		if executor.distribution == LinuxMariaDBAlma { operation = hostUpgradeMariaDBAlma }
		packageProof, runErr := runFixedHost(ctx, operation)
		if runErr != nil { return effectApplication{mutated: true, failureCode: "upgrade_apply_failed", ambiguous: true}, runErr }
		upgradeProof, runErr := runFixedHost(ctx, hostRunMariaDBUpgrade)
		if runErr != nil { return effectApplication{mutated: true, failureCode: "upgrade_apply_failed", ambiguous: true}, runErr }
		restartProof, runErr := runFixedHost(ctx, hostRestartMariaDB)
		if runErr != nil { return effectApplication{mutated: true, failureCode: "upgrade_apply_failed", ambiguous: true}, runErr }
		status = append(append(packageProof, upgradeProof...), restartProof...)
	case UpgradeVerifying, UpgradeComplete:
		if compareVersion(observedVersion, upgrade.To) != 0 { return effectApplication{failureCode: "upgrade_preflight_failed"}, ErrConflict }
	case UpgradeFailed:
		return effectApplication{failureCode: "upgrade_preflight_failed"}, ErrConflict
	default:
		return effectApplication{failureCode: "upgrade_preflight_failed"}, ErrInvalidResource
	}
	connection, cleanup, err = executor.connection(ctx, instance)
	if err != nil { return effectApplication{mutated: upgrade.Phase == UpgradeCutover, failureCode: "connection_failed", ambiguous: upgrade.Phase == UpgradeCutover}, err }
	defer cleanup()
	verification, err := connection.query(ctx, sqlObserveStatus)
	if err != nil { return effectApplication{mutated: upgrade.Phase == UpgradeCutover, failureCode: "upgrade_apply_failed", ambiguous: upgrade.Phase == UpgradeCutover}, err }
	verifiedVersion, err := parseMariaDBVersion(firstField(verification))
	expected := upgrade.From
	if upgrade.Phase == UpgradeCutover || upgrade.Phase == UpgradeVerifying || upgrade.Phase == UpgradeComplete { expected = upgrade.To }
	if err != nil || compareVersion(verifiedVersion, expected) != 0 { return effectApplication{mutated: upgrade.Phase == UpgradeCutover, failureCode: "upgrade_apply_failed", ambiguous: upgrade.Phase == UpgradeCutover}, ErrConflict }
	if upgrade.Phase == UpgradeCutover || upgrade.Phase == UpgradeVerifying || upgrade.Phase == UpgradeComplete {
		instance.Version = upgrade.To
		if err := executor.writeResource("instances", instance.ID, instance); err != nil { return effectApplication{mutated: true, failureCode: "state_persistence_failed", ambiguous: true}, err }
	}
	if err := executor.writeResource("upgrades", upgrade.ID, upgrade); err != nil { return effectApplication{mutated: upgrade.Phase == UpgradeCutover, failureCode: "state_persistence_failed", ambiguous: upgrade.Phase == UpgradeCutover}, err }
	manifest, _ := json.MarshalIndent(upgrade, "", "  ")
	if _, err := executor.writeGeneration(upgrade.ID, upgrade.Generation, map[string]generatedFile{"upgrade.json": {Payload: append(manifest, '\n'), Mode: 0600}}); err != nil { return effectApplication{mutated: upgrade.Phase == UpgradeCutover, failureCode: "state_persistence_failed", ambiguous: upgrade.Phase == UpgradeCutover}, err }
	return effectApplication{proof: append(status, verification...), mutated: true}, nil
}

func readManagedConfig(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) { return nil, false, nil }
	if err != nil { return nil, false, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Size() > 4<<20 { return nil, false, ErrUnauthorized }
	payload, err := os.ReadFile(path)
	return payload, err == nil, err
}

func runFixedHost(ctx context.Context, operation fixedHostOperation) ([]byte, error) {
	var executable string
	var arguments []string
	switch operation {
	case hostRestartMariaDB:
		executable, arguments = "/usr/bin/systemctl", []string{"restart", mariaDBService}
	case hostReloadNftables:
		executable, arguments = "/usr/bin/systemctl", []string{"reload", "nftables.service"}
	case hostUpgradeMariaDBUbuntu:
		executable, arguments = "/usr/bin/apt-get", []string{"-q", "-y", "--only-upgrade", "install", "mariadb-server", "mariadb-client", "mariadb-backup"}
	case hostUpgradeMariaDBAlma:
		executable, arguments = "/usr/bin/dnf", []string{"-q", "-y", "upgrade", "MariaDB-server", "MariaDB-client", "MariaDB-backup"}
	case hostRunMariaDBUpgrade:
		executable, arguments = "/usr/bin/mariadb-upgrade", []string{"--no-defaults", "--skip-write-binlog", "--protocol=socket", "--socket=" + mariaDBSocket, "--user=root"}
	default:
		return nil, ErrInvalidCommand
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/root", "DEBIAN_FRONTEND=noninteractive"}
	output := &limitedBuffer{remaining: maximumProcessOutput}
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil { return nil, fmt.Errorf("fixed host operation %d failed: %w", operation, err) }
	if output.overflow { return nil, errors.New("fixed host operation output exceeded the limit") }
	return append([]byte(nil), output.buffer.Bytes()...), nil
}

func canonicalPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	result := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(result, func(left, right int) bool { return result[left].String() < result[right].String() })
	return result
}
