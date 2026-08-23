//go:build linux

package dns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
)

const (
	PowerDNSConfigurationRoot       = "/var/lib/cyberpanel/powerdns"
	PowerDNSDaemonDatabasePurpose PowerDNSDatabasePurpose = PowerDNSAuthoritativePurpose
	powerDNSConfigurationKey       = "pdns/pdns.conf"
	powerDNSMaximumCredentialBytes = 4096
)

var (
	ErrPowerDNSConfigCredential = errors.New("PowerDNS configuration credential unavailable")
	ErrPowerDNSIntegrity        = errors.New("PowerDNS configuration integrity failure")
	ErrPowerDNSAmbiguous        = errors.New("PowerDNS configuration outcome is ambiguous")
)

// PowerDNSDatabaseBinding is an identity-only description of the dedicated
// MariaDB database used by PowerDNS. Credential material is deliberately not
// part of this value and is resolved only by the privileged host adapter.
type PowerDNSDatabaseBinding struct {
	ID            string                  `json:"id"`
	Purpose       PowerDNSDatabasePurpose `json:"purpose"`
	Host          netip.Addr              `json:"host"`
	Port          uint16                  `json:"port"`
	Database      string                  `json:"database"`
	Username      string                  `json:"username"`
	CredentialRef string                  `json:"credential_ref"`
	Fingerprint   string                  `json:"fingerprint"`
	Backend PowerDNSDatabaseBackend `json:"backend"`
}

type PowerDNSDatabaseBackend string
const(PowerDNSBackendMariaDB PowerDNSDatabaseBackend="mariadb";PowerDNSBackendSQLite PowerDNSDatabaseBackend="sqlite")

func (binding PowerDNSDatabaseBinding) AuthoritativeIdentity() PowerDNSAuthoritativeDatabaseIdentity {
	return PowerDNSAuthoritativeDatabaseIdentity{
		Purpose:       binding.Purpose,
		Fingerprint:   binding.Fingerprint,
		CredentialRef: binding.CredentialRef,
	}
}

func (binding PowerDNSDatabaseBinding) ExpectedFingerprint() string {
	hash := sha256.New()
	for _, value := range []string{"powerdns-database-binding-v2", string(binding.Purpose),string(binding.Backend), binding.Host.Unmap().String(), strconv.FormatUint(uint64(binding.Port), 10), binding.Database, binding.Username} {
		_, _ = hash.Write([]byte(strconv.Itoa(len(value))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// PowerDNSConfigSnapshot is the complete non-secret desired configuration.
// The authoritative service always supports native, primary, and secondary
// zones; zone-specific transfer policy remains in PowerDNS metadata.
type PowerDNSConfigSnapshot struct {
	NodeID             string                  `json:"node_id"`
	Generation         uint64                  `json:"generation"`
	ListenAddresses    []netip.Addr            `json:"listen_addresses"`
	NotifySources      []netip.Addr            `json:"notify_sources,omitempty"` // union of secured secondary-zone primaries
	Port               uint16                  `json:"port"`
	Database           PowerDNSDatabaseBinding `json:"database"`
	ReceiverThreads    uint16                  `json:"receiver_threads"`
	DistributorThreads uint16                  `json:"distributor_threads"`
	RetrievalThreads   uint16                  `json:"retrieval_threads"`
	MaximumTCPClients  uint32                  `json:"maximum_tcp_clients"`
}

func (snapshot PowerDNSConfigSnapshot) AuthoritativeIdentity() PowerDNSAuthoritativeDatabaseIdentity {
	return snapshot.Database.AuthoritativeIdentity()
}

// PowerDNSCredentialResolver is implemented by the privileged secret store.
// Implementations must scope grants to the complete validated binding identity.
type PowerDNSCredentialResolver interface {
	ResolvePowerDNSDatabaseCredential(context.Context, PowerDNSDatabaseBinding) ([]byte, error)
}

type powerDNSConfigGeneration struct {
	ID             string
	Snapshot       PowerDNSConfigSnapshot
	SnapshotDigest string
	StorageDigest  string
	Artifacts      []daemoncfg.Artifact
}

func (snapshot PowerDNSConfigSnapshot) Validate(controlDatabaseFingerprint string) error {
	_, err := snapshot.canonical(controlDatabaseFingerprint)
	return err
}

func (snapshot PowerDNSConfigSnapshot) canonical(controlDatabaseFingerprint string) (PowerDNSConfigSnapshot, error) {
	if !safePowerDNSOpaque(snapshot.NodeID, 128) || snapshot.Generation == 0 || snapshot.Port != 53 {
		return PowerDNSConfigSnapshot{}, ErrInvalidDNS
	}
	if snapshot.ReceiverThreads < 1 || snapshot.ReceiverThreads > 128 ||
		snapshot.DistributorThreads < 1 || snapshot.DistributorThreads > 128 ||
		snapshot.RetrievalThreads < 1 || snapshot.RetrievalThreads > 64 ||
		snapshot.MaximumTCPClients < 64 || snapshot.MaximumTCPClients > 1<<20 {
		return PowerDNSConfigSnapshot{}, ErrInvalidDNS
	}
	database := snapshot.Database
	database.Host = database.Host.Unmap()
	if err := database.validate(controlDatabaseFingerprint); err != nil {
		return PowerDNSConfigSnapshot{}, err
	}
	if len(snapshot.ListenAddresses) == 0 || len(snapshot.ListenAddresses) > 16 || len(snapshot.NotifySources) > 1024 {
		return PowerDNSConfigSnapshot{}, ErrInvalidDNS
	}

	canonical := snapshot
	canonical.Database = database
	canonical.ListenAddresses = make([]netip.Addr, 0, len(snapshot.ListenAddresses))
	seen := make(map[netip.Addr]struct{}, len(snapshot.ListenAddresses))
	for _, address := range snapshot.ListenAddresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" || address.IsMulticast() {
			return PowerDNSConfigSnapshot{}, ErrInvalidDNS
		}
		if _, exists := seen[address]; exists {
			return PowerDNSConfigSnapshot{}, ErrInvalidDNS
		}
		seen[address] = struct{}{}
		canonical.ListenAddresses = append(canonical.ListenAddresses, address)
	}
	sort.Slice(canonical.ListenAddresses, func(i, j int) bool {
		return canonical.ListenAddresses[i].Compare(canonical.ListenAddresses[j]) < 0
	})
	canonical.NotifySources = make([]netip.Addr, 0, len(snapshot.NotifySources))
	notifySeen := make(map[netip.Addr]struct{}, len(snapshot.NotifySources))
	for _, address := range snapshot.NotifySources {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
			return PowerDNSConfigSnapshot{}, ErrInvalidDNS
		}
		if _, exists := notifySeen[address]; exists {
			return PowerDNSConfigSnapshot{}, ErrInvalidDNS
		}
		notifySeen[address] = struct{}{}
		canonical.NotifySources = append(canonical.NotifySources, address)
	}
	sort.Slice(canonical.NotifySources, func(i, j int) bool {
		return canonical.NotifySources[i].Compare(canonical.NotifySources[j]) < 0
	})
	return canonical, nil
}

func (binding PowerDNSDatabaseBinding) validate(controlDatabaseFingerprint string) error {
	if binding.AuthoritativeIdentity().Validate(controlDatabaseFingerprint) != nil ||
		binding.Purpose != PowerDNSDaemonDatabasePurpose ||
		!safePowerDNSOpaque(binding.ID, 128) ||
		(binding.Backend==PowerDNSBackendMariaDB&&(!binding.Host.IsValid()||!binding.Host.IsLoopback()||binding.Host.Zone()!="")) ||
		(binding.Backend!=PowerDNSBackendMariaDB&&binding.Backend!=PowerDNSBackendSQLite)||binding.Backend==PowerDNSBackendMariaDB&&binding.Port==0||binding.Backend==PowerDNSBackendSQLite&&(binding.ID!="local-sqlite"||binding.Port!=0||binding.Host!=netip.IPv4Unspecified()) ||
		!safePowerDNSSQLIdentifier(binding.Database, 64) ||
		!safePowerDNSSQLIdentifier(binding.Username, 64) ||
		!safePowerDNSOpaque(binding.CredentialRef, 256) ||
		!powerDNSSHA256(binding.Fingerprint) || binding.Fingerprint != binding.ExpectedFingerprint() ||
		!powerDNSSHA256(controlDatabaseFingerprint) ||
		binding.Fingerprint == controlDatabaseFingerprint {
		return ErrInvalidDNS
	}

	databaseName := strings.ToLower(binding.Database)
	if binding.Backend==PowerDNSBackendMariaDB&&!strings.HasPrefix(databaseName, "pdns_") && !strings.HasPrefix(databaseName, "powerdns_") {
		return ErrInvalidDNS
	}
	if strings.Contains(databaseName, "control") || strings.Contains(databaseName, "panel") {
		return ErrInvalidDNS
	}
	return nil
}

func renderPowerDNSGeneration(snapshot PowerDNSConfigSnapshot, credential []byte, ownership PowerDNSOwnership, profile powerDNSProfile, controlDatabaseFingerprint string) (powerDNSConfigGeneration, error) {
	canonical, err := snapshot.canonical(controlDatabaseFingerprint)
	if err != nil || ownership.Validate() != nil || canonical.Database.Backend==PowerDNSBackendMariaDB&&!validPowerDNSCredential(credential) || canonical.Database.Backend==PowerDNSBackendSQLite&&len(credential)!=0 {
		return powerDNSConfigGeneration{}, errors.Join(ErrInvalidDNS, err)
	}

	snapshotJSON, err := json.Marshal(canonical)
	if err != nil {
		return powerDNSConfigGeneration{}, err
	}
	snapshotSum := sha256.Sum256(snapshotJSON)
	snapshotDigest := hex.EncodeToString(snapshotSum[:])

	var configuration bytes.Buffer
	configuration.WriteString("# Managed by CyberPanel. Manual changes are replaced.\n")
	if canonical.Database.Backend==PowerDNSBackendSQLite{configuration.WriteString("launch=gsqlite3\ngsqlite3-database=/var/lib/cyberpanel/powerdns/authority.db\ngsqlite3-dnssec=yes\n")}else{configuration.WriteString("launch=gmysql\n");fmt.Fprintf(&configuration,"gmysql-host=%s\n",canonical.Database.Host.String());fmt.Fprintf(&configuration,"gmysql-port=%d\n",canonical.Database.Port);fmt.Fprintf(&configuration,"gmysql-dbname=%s\n",canonical.Database.Database);fmt.Fprintf(&configuration,"gmysql-user=%s\n",canonical.Database.Username);configuration.WriteString("gmysql-password=");configuration.Write(credential);configuration.WriteByte('\n')}
	fmt.Fprintf(&configuration, "local-address=%s\n", joinPowerDNSAddresses(canonical.ListenAddresses))
	fmt.Fprintf(&configuration, "local-port=%d\n", canonical.Port)
	fmt.Fprintf(&configuration, "%s=yes\n", profile.primarySetting)
	fmt.Fprintf(&configuration, "%s=yes\n", profile.secondarySetting)
	configuration.WriteString("daemon=no\n")
	configuration.WriteString("guardian=no\n")
	configuration.WriteString("api=no\n")
	configuration.WriteString("webserver=no\n")
	configuration.WriteString("dnsupdate=no\n")
	configuration.WriteString("default-api-rectify=yes\n")
	configuration.WriteString("disable-axfr=no\n")
	configuration.WriteString("allow-axfr-ips=127.0.0.0/8,::1\n")
	fmt.Fprintf(&configuration, "allow-notify-from=%s\n", joinPowerDNSAddresses(append([]netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}, canonical.NotifySources...)))
	configuration.WriteString("allow-unsigned-notify=no\n")
	configuration.WriteString("allow-unsigned-supermaster=no\n")
	configuration.WriteString("any-to-tcp=yes\n")
	configuration.WriteString("version-string=anonymous\n")
	configuration.WriteString("security-poll-suffix=\n")
	configuration.WriteString("log-dns-queries=no\n")
	configuration.WriteString("loglevel=4\n")
	configuration.WriteString("cache-ttl=20\n")
	configuration.WriteString("query-cache-ttl=20\n")
	configuration.WriteString("negquery-cache-ttl=60\n")
	fmt.Fprintf(&configuration, "receiver-threads=%d\n", canonical.ReceiverThreads)
	fmt.Fprintf(&configuration, "distributor-threads=%d\n", canonical.DistributorThreads)
	fmt.Fprintf(&configuration, "retrieval-threads=%d\n", canonical.RetrievalThreads)
	fmt.Fprintf(&configuration, "max-tcp-connections=%d\n", canonical.MaximumTCPClients)
	configuration.WriteString("reuseport=yes\n")

	content := configuration.Bytes()
	defer clearPowerDNSBytes(content)
	contentSum := sha256.Sum256(content)
	artifacts := []daemoncfg.Artifact{{
		Path:    powerDNSConfigurationKey,
		Mode:    0440,
		GID:     ownership.PDNSGID,
		Content: append([]byte(nil), content...),
		SHA256:  hex.EncodeToString(contentSum[:]),
	}}
	storageDigest, err := daemoncfg.ComputeDigest(artifacts)
	if err != nil {
		clearPowerDNSArtifacts(artifacts)
		return powerDNSConfigGeneration{}, err
	}
	return powerDNSConfigGeneration{
		ID:             "pdns-" + strconv.FormatUint(canonical.Generation, 10) + "-" + snapshotDigest[:12] + "-" + storageDigest[:12],
		Snapshot:       canonical,
		SnapshotDigest: snapshotDigest,
		StorageDigest:  storageDigest,
		Artifacts:      artifacts,
	}, nil
}

func joinPowerDNSAddresses(addresses []netip.Addr) string {
	values := make([]string, len(addresses))
	for index, address := range addresses {
		values[index] = address.String()
	}
	return strings.Join(values, ",")
}

func validPowerDNSCredential(credential []byte) bool {
	if len(credential) < 24 || len(credential) > powerDNSMaximumCredentialBytes {
		return false
	}
	for _, value := range credential {
		if !(value == '_' || value == '-' || value == '.' || value == '~' ||
			value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z') {
			return false
		}
	}
	return true
}

func safePowerDNSSQLIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for index, character := range value {
		if !(character == '_' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z') {
			return false
		}
		if index == 0 && character >= '0' && character <= '9' {
			return false
		}
	}
	return true
}

func safePowerDNSOpaque(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == '.' || character == ':' || character == '/' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z') {
			return false
		}
	}
	return true
}

func powerDNSSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func clearPowerDNSBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func clearPowerDNSArtifacts(artifacts []daemoncfg.Artifact) {
	for index := range artifacts {
		clearPowerDNSBytes(artifacts[index].Content)
	}
}
