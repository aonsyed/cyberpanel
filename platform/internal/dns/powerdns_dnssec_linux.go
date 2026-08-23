//go:build linux

package dns

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

// GenerateAndPublishDNSSEC creates keys only through PowerDNS's fixed
// management utility. Private material remains in the authoritative backend;
// callers receive public DNSKEY/DS material and opaque numeric key handles.
func (host *LinuxPowerDNSHost) GenerateAndPublishDNSSEC(ctx context.Context, zone ZoneSpec, policy DNSSECPolicy, effectID string) (KeyActivationReceipt, error) {
	receipt := KeyActivationReceipt{EffectID: effectID, AppliedAt: time.Now().UTC()}
	if host == nil || ctx == nil || validateDNSSECPolicy(policy) != nil || validatePowerDNSDNSSECZone(zone) != nil || !validPowerDNSEffectID(effectID) {
		return receipt, ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	algorithm, err := powerDNSDNSSECAlgorithm(policy.Algorithm)
	if err != nil {
		return receipt, err
	}
	roles := []string{"csk"}
	if policy.SplitKeys {
		roles = []string{"ksk", "zsk"}
	}
	created := make([]DNSSECKeyDescriptor, 0, len(roles))
	rollback := func() {
		for _, key := range created {
			_, _ = runPowerDNSProcess(context.Background(), host.profile.pdnsUtil, "remove-zone-key", zone.Name.FQDN(), key.PrivateHandle)
		}
		_, _ = runPowerDNSProcess(context.Background(), host.profile.pdnsUtil, "rectify-zone", zone.Name.FQDN())
	}
	for _, role := range roles {
		powerDNSRole := role
		if powerDNSRole == "csk" {
			powerDNSRole = "ksk"
		}
		output, addErr := runPowerDNSProcess(ctx, host.profile.pdnsUtil, "add-zone-key", zone.Name.FQDN(), powerDNSRole, "active", "published", algorithm)
		if addErr != nil {
			rollback()
			return receipt, addErr
		}
		keyID, parseErr := parsePowerDNSKeyID(output)
		if parseErr != nil {
			rollback()
			return receipt, parseErr
		}
		key, exportErr := host.exportPowerDNSKey(ctx, zone, keyID, role, policy.Algorithm)
		if exportErr != nil {
			rollback()
			return receipt, exportErr
		}
		created = append(created, key)
	}
	if _, err = runPowerDNSProcess(ctx, host.profile.pdnsUtil, "rectify-zone", zone.Name.FQDN()); err != nil {
		rollback()
		return receipt, err
	}
	ds := make([]DSRecord, 0, len(created))
	for _, key := range created {
		if key.Role == "zsk" {
			continue
		}
		record, exportErr := host.exportPowerDNSDS(ctx, zone, key.PrivateHandle)
		if exportErr != nil {
			rollback()
			return receipt, exportErr
		}
		ds = append(ds, record)
	}
	if len(ds) == 0 {
		rollback()
		return receipt, ErrInvalidDNS
	}
	receipt.Keys = created
	receipt.DS = canonicalPowerDNSDS(ds)
	receipt.DNSKEYDigest = digestDNSSECPublicKeys(created)
	receipt.AppliedAt = host.now()
	return receipt, nil
}

func (host *LinuxPowerDNSHost) RetireDNSSEC(ctx context.Context, zone ZoneSpec, keys []DNSSECKeyDescriptor, effectID string) error {
	if host == nil || ctx == nil || validatePowerDNSDNSSECZone(zone) != nil || !validPowerDNSEffectID(effectID) || len(keys) == 0 || len(keys) > 8 {
		return ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	for _, key := range keys {
		if !validPowerDNSKeyHandle(key.PrivateHandle) {
			return ErrInvalidDNS
		}
		if _, err := runPowerDNSProcess(ctx, host.profile.pdnsUtil, "remove-zone-key", zone.Name.FQDN(), key.PrivateHandle); err != nil {
			return err
		}
	}
	_, err := runPowerDNSProcess(ctx, host.profile.pdnsUtil, "rectify-zone", zone.Name.FQDN())
	return err
}

func (host *LinuxPowerDNSHost) RemoveDNSSEC(ctx context.Context, zone ZoneSpec, effectID string) error {
	if host == nil || ctx == nil || validatePowerDNSDNSSECZone(zone) != nil || !validPowerDNSEffectID(effectID) {
		return ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	_, err := runPowerDNSProcess(ctx, host.profile.pdnsUtil, "disable-dnssec", zone.Name.FQDN())
	return err
}

// ProveDNSSEC requires both the local authoritative answer and an AD-marked
// recursive DS answer to contain the exact public material expected by the
// coordinator. It never treats local configuration state as registrar proof.
func (host *LinuxPowerDNSHost) ProveDNSSEC(ctx context.Context, zone ZoneSpec, keys []DNSSECKeyDescriptor, ds []DSRecord) (DNSSECProof, error) {
	proof := DNSSECProof{ObservedAt: host.now(), ResolverSet: []string{"authoritative:127.0.0.1", "recursive:system"}}
	if host == nil || ctx == nil || validatePowerDNSDNSSECZone(zone) != nil || len(keys) == 0 || len(keys) > 8 || len(ds) == 0 || len(ds) > 8 {
		return proof, ErrInvalidDNS
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	for _, key := range keys {
		if !validPowerDNSKeyHandle(key.PrivateHandle) || key.PublicDNSKEY == "" {
			return proof, ErrInvalidDNS
		}
	}
	proof.DNSKEYDigest = digestDNSSECPublicKeys(keys)
	proof.DSDigest = digestPowerDNSDS(ds)
	authoritative, err := runPowerDNSProcess(ctx, host.profile.dig, "@127.0.0.1", "+norecurse", "+dnssec", "+noall", "+comments", "+answer", zone.Name.FQDN(), "DNSKEY")
	if err != nil {
		return proof, err
	}
	proof.Authoritative = dnsOutputHasFlag(authoritative, "aa") && dnsOutputContainsKeys(authoritative, keys)
	recursive, err := runPowerDNSProcess(ctx, host.profile.dig, "+dnssec", "+noall", "+comments", "+answer", zone.Name.FQDN(), "DS")
	if err != nil {
		return proof, err
	}
	proof.RecursiveValidated = dnsOutputHasFlag(recursive, "ad") && dnsOutputContainsDS(recursive, ds)
	proof.ObservedAt = host.now()
	return proof, nil
}

func (host *LinuxPowerDNSHost) exportPowerDNSKey(ctx context.Context, zone ZoneSpec, keyID, role string, algorithm DNSSECAlgorithm) (DNSSECKeyDescriptor, error) {
	output, err := runPowerDNSProcess(ctx, host.profile.pdnsUtil, "export-zone-dnskey", zone.Name.FQDN(), keyID)
	if err != nil {
		return DNSSECKeyDescriptor{}, err
	}
	public, tag, err := parsePowerDNSDNSKEY(output)
	if err != nil {
		return DNSSECKeyDescriptor{}, err
	}
	return DNSSECKeyDescriptor{ID: "pdns-key-" + keyID, Role: role, Algorithm: algorithm, KeyTag: tag, PublicDNSKEY: public, PrivateHandle: keyID, CreatedAt: host.now()}, nil
}

func (host *LinuxPowerDNSHost) exportPowerDNSDS(ctx context.Context, zone ZoneSpec, keyID string) (DSRecord, error) {
	output, err := runPowerDNSProcess(ctx, host.profile.pdnsUtil, "export-zone-ds", zone.Name.FQDN(), keyID)
	if err != nil {
		return DSRecord{}, err
	}
	return parsePowerDNSDS(output)
}

func validatePowerDNSDNSSECZone(zone ZoneSpec) error {
	if zone.ID == "" || zone.TenantID == "" || zone.Generation == 0 || !validPowerDNSZoneName(zone.Name) || zone.Mode == ZoneSecondary {
		return ErrInvalidDNS
	}
	return nil
}

func powerDNSDNSSECAlgorithm(algorithm DNSSECAlgorithm) (string, error) {
	switch algorithm {
	case DNSSECECDSAP256SHA256:
		return "ECDSAP256SHA256", nil
	case DNSSECEd25519:
		return "ED25519", nil
	default:
		return "", ErrInvalidDNS
	}
}

func parsePowerDNSKeyID(output []byte) (string, error) {
	fields := strings.Fields(string(output))
	for index := len(fields) - 1; index >= 0; index-- {
		candidate := strings.Trim(fields[index], "()[],:;\"'")
		if validPowerDNSKeyHandle(candidate) {
			return candidate, nil
		}
	}
	return "", ErrInvalidDNS
}

func validPowerDNSKeyHandle(value string) bool {
	if len(value) == 0 || len(value) > 10 || value[0] == '0' {
		return false
	}
	number, err := strconv.ParseUint(value, 10, 32)
	return err == nil && number > 0
}

func parsePowerDNSDNSKEY(output []byte) (string, uint16, error) {
	fields := strings.Fields(string(output))
	for index, field := range fields {
		if strings.EqualFold(field, "DNSKEY") && len(fields) >= index+5 {
			value := strings.Join(fields[index+1:index+5], " ")
			canonical, err := canonicalDNSKEY(value)
			if err != nil {
				return "", 0, err
			}
			tag := dnskeyTag(canonical)
			if tag == 0 {
				return "", 0, ErrInvalidDNS
			}
			return canonical, tag, nil
		}
	}
	return "", 0, ErrInvalidDNS
}

func parsePowerDNSDS(output []byte) (DSRecord, error) {
	fields := strings.Fields(string(output))
	for index, field := range fields {
		if strings.EqualFold(field, "DS") && len(fields) >= index+5 {
			keyTag, firstErr := strconv.ParseUint(fields[index+1], 10, 16)
			algorithm, secondErr := strconv.ParseUint(fields[index+2], 10, 8)
			digestType, thirdErr := strconv.ParseUint(fields[index+3], 10, 8)
			digest := strings.ToUpper(fields[index+4])
			if firstErr != nil || secondErr != nil || thirdErr != nil || len(digest) < 40 || len(digest) > 128 {
				return DSRecord{}, ErrInvalidDNS
			}
			if _, err := hex.DecodeString(digest); err != nil {
				return DSRecord{}, ErrInvalidDNS
			}
			return DSRecord{KeyTag: uint16(keyTag), Algorithm: uint8(algorithm), DigestType: uint8(digestType), Digest: digest}, nil
		}
	}
	return DSRecord{}, ErrInvalidDNS
}

func dnskeyTag(value string) uint16 {
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return 0
	}
	flags, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return 0
	}
	protocol, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		return 0
	}
	algorithm, err := strconv.ParseUint(fields[2], 10, 8)
	if err != nil {
		return 0
	}
	key, err := decodeDNSSECBase64(fields[3])
	if err != nil {
		return 0
	}
	wire := []byte{byte(flags >> 8), byte(flags), byte(protocol), byte(algorithm)}
	wire = append(wire, key...)
	var accumulator uint32
	for index, value := range wire {
		if index&1 == 0 {
			accumulator += uint32(value) << 8
		} else {
			accumulator += uint32(value)
		}
	}
	accumulator += (accumulator >> 16) & 0xffff
	return uint16(accumulator & 0xffff)
}

func decodeDNSSECBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return nil, ErrInvalidDNS
	}
	return decoded, nil
}

func canonicalPowerDNSDS(records []DSRecord) []DSRecord {
	copyOfRecords := append([]DSRecord(nil), records...)
	sort.Slice(copyOfRecords, func(left, right int) bool {
		if copyOfRecords[left].KeyTag != copyOfRecords[right].KeyTag {
			return copyOfRecords[left].KeyTag < copyOfRecords[right].KeyTag
		}
		return copyOfRecords[left].Digest < copyOfRecords[right].Digest
	})
	return copyOfRecords
}

func digestDNSSECPublicKeys(keys []DNSSECKeyDescriptor) string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key.PublicDNSKEY)
	}
	sort.Strings(values)
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func digestPowerDNSDS(records []DSRecord) string {
	hash := sha256.New()
	for _, record := range canonicalPowerDNSDS(records) {
		hash.Write([]byte(strconv.FormatUint(uint64(record.KeyTag), 10)))
		hash.Write([]byte{' '})
		hash.Write([]byte(strconv.FormatUint(uint64(record.Algorithm), 10)))
		hash.Write([]byte{' '})
		hash.Write([]byte(strconv.FormatUint(uint64(record.DigestType), 10)))
		hash.Write([]byte{' '})
		hash.Write([]byte(strings.ToUpper(record.Digest)))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func dnsOutputHasFlag(output []byte, expected string) bool {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, ";;") || !strings.Contains(line, "flags:") {
			continue
		}
		flags := strings.Fields(strings.SplitN(strings.SplitN(line, "flags:", 2)[1], ";", 2)[0])
		for _, flag := range flags {
			if flag == expected {
				return true
			}
		}
	}
	return false
}

func dnsOutputContainsKeys(output []byte, keys []DNSSECKeyDescriptor) bool {
	content := string(output)
	for _, key := range keys {
		if !strings.Contains(content, " DNSKEY "+key.PublicDNSKEY) {
			return false
		}
	}
	return true
}

func dnsOutputContainsDS(output []byte, records []DSRecord) bool {
	content := strings.ToUpper(string(output))
	for _, record := range records {
		value := " DS " + strconv.FormatUint(uint64(record.KeyTag), 10) + " " + strconv.FormatUint(uint64(record.Algorithm), 10) + " " + strconv.FormatUint(uint64(record.DigestType), 10) + " " + strings.ToUpper(record.Digest)
		if !strings.Contains(content, value) {
			return false
		}
	}
	return true
}

func validDNSSECProof(proof DNSSECProof) bool {
	return !proof.ObservedAt.IsZero() && len(proof.ResolverSet) > 0 && len(proof.DNSKEYDigest) == 64 && len(proof.DSDigest) == 64
}
