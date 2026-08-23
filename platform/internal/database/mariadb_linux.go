//go:build linux

package database

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	mariaDBStateRoot       = "/var/lib/cyberpanel/database"
	mariaDBConfigRoot      = "/etc/cyberpanel/database"
	mariaDBRunRoot         = "/run/cyberpanel/database"
	mariaDBUbuntuConfig    = "/etc/mysql/mariadb.conf.d/90-cyberpanel.cnf"
	mariaDBAlmaConfig      = "/etc/my.cnf.d/90-cyberpanel.cnf"
	mariaDBFirewallConfig  = "/etc/nftables.d/90-cyberpanel-mariadb.nft"
	mariaDBSocket          = "/run/mysqld/mysqld.sock"
	mariaDBService         = "mariadb.service"
	mariaDBAdapterVersion  = "linux-mariadb-v1"
	maximumSecretBytes     = 64 << 10
	maximumProcessOutput   = 1 << 20
)

type LinuxMariaDBDistribution string

const (
	LinuxMariaDBUbuntu LinuxMariaDBDistribution = "ubuntu"
	LinuxMariaDBAlma   LinuxMariaDBDistribution = "alma"
)

// MariaDBAdministrator is returned only by the trusted secret source. Password
// and private-key bytes are wiped by the executor after each use and are never
// placed in argv, environment variables, receipts, or durable adapter state.
type MariaDBAdministrator struct {
	Username             SQLIdentifier
	Password             []byte
	ClientCertificatePEM []byte
	ClientKeyPEM         []byte
}

// MariaDBServerTLS contains one complete local server identity generation.
// CertificateAuthorityPEM may contain a CA bundle; CertificatePEM and KeyPEM
// must form one X.509 key pair.
type MariaDBServerTLS struct {
	CertificateAuthorityPEM []byte
	CertificatePEM          []byte
	KeyPEM                  []byte
}

// LinuxMariaDBSecretSource is the only credential-bearing dependency. Each
// method is purpose-bound: callers cannot ask it for an arbitrary secret.
type LinuxMariaDBSecretSource interface {
	PrincipalPassword(context.Context, SecretRef, ResourceID, string, string) ([]byte, error)
	ExternalAdministrator(context.Context, SecretRef, ResourceID, ResourceID) (MariaDBAdministrator, error)
	PinnedCertificateAuthority(context.Context, SecretRef, ResourceID) ([]byte, error)
	LocalServerTLS(context.Context, ResourceID, ResourceID, TLSMode) (MariaDBServerTLS, error)
}

type MariaDBInstanceStatus struct {
	InstanceID  ResourceID       `json:"instance_id"`
	Placement   Placement        `json:"placement"`
	Version     MariaDBVersion   `json:"version"`
	Reachable   bool             `json:"reachable"`
	TLSVerified bool             `json:"tls_verified"`
	ProofDigest string           `json:"proof_digest"`
	ObservedAt  time.Time        `json:"observed_at"`
}

// LinuxMariaDBExecutor is the concrete root broker for local and managed
// external MariaDB instances. Its public surface is the closed MariaDBExecutor
// effect sum plus a read-only typed status probe.
type LinuxMariaDBExecutor struct {
	secrets      LinuxMariaDBSecretSource
	distribution LinuxMariaDBDistribution
	now          func() time.Time
	mu           sync.Mutex
}

type effectApplication struct {
	proof        []byte
	mutated      bool
	compensation *mariaDBCompensation
	failureCode  string
	ambiguous    bool
}

type mariaDBCompensation struct {
	Token         ResourceID                `json:"token"`
	EffectID      string                    `json:"effect_id"`
	RequestDigest string                    `json:"request_digest"`
	Kind          EffectKind                `json:"kind"`
	InstanceID    ResourceID                `json:"instance_id,omitempty"`
	TargetID      ResourceID                `json:"target_id,omitempty"`
	Database      *Database                 `json:"database,omitempty"`
	Principal     *DatabasePrincipal        `json:"principal,omitempty"`
	GrantSet      *GrantSet                 `json:"grant_set,omitempty"`
	Policy        *NetworkAccessPolicy      `json:"policy,omitempty"`
	Instance      *DatabaseInstance         `json:"instance,omitempty"`
	Session       *DatabaseWorkspaceSession `json:"session,omitempty"`
	Tuning        *TuningProfile            `json:"tuning,omitempty"`
	ServerConfig  []byte                    `json:"server_config,omitempty"`
	FirewallConfig []byte                   `json:"firewall_config,omitempty"`
	ServerConfigPresent bool                `json:"server_config_present,omitempty"`
	FirewallConfigPresent bool              `json:"firewall_config_present,omitempty"`
	RemoveState   bool                      `json:"remove_state,omitempty"`
}

func NewLinuxMariaDBExecutor(secrets LinuxMariaDBSecretSource, distribution LinuxMariaDBDistribution, localInstances []DatabaseInstance) (*LinuxMariaDBExecutor, error) {
	if os.Geteuid() != 0 || secrets == nil || distribution != LinuxMariaDBUbuntu && distribution != LinuxMariaDBAlma {
		return nil, ErrUnauthorized
	}
	executor := &LinuxMariaDBExecutor{secrets: secrets, distribution: distribution, now: time.Now}
	if err := executor.initializeRoots(); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(localInstances))
	for _, instance := range localInstances {
		if instance.Validate() != nil || instance.Placement != PlacementLocal || instance.Metadata.TenantID.String() != "" {
			return nil, ErrInvalidResource
		}
		if _, duplicate := seen[instance.ID.String()]; duplicate {
			return nil, ErrConflict
		}
		seen[instance.ID.String()] = struct{}{}
		var stored DatabaseInstance
		err := executor.readResource("instances", instance.ID, &stored)
		if err == nil {
			if stored.Placement != PlacementLocal || stored.LocalServiceRef != instance.LocalServiceRef {
				return nil, ErrConflict
			}
			continue
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err := executor.writeResource("instances", instance.ID, instance); err != nil {
			return nil, err
		}
	}
	return executor, nil
}

func DetectLinuxMariaDBDistribution()(LinuxMariaDBDistribution,error){payload,err:=os.ReadFile("/etc/os-release");if err!=nil{return "",err};values:=map[string]string{};for _,line:=range strings.Split(string(payload),"\n"){key,value,found:=strings.Cut(line,"=");if found{values[key]=strings.Trim(strings.TrimSpace(value),"\"")}};switch values["ID"]{case "ubuntu":return LinuxMariaDBUbuntu,nil;case "almalinux":return LinuxMariaDBAlma,nil;default:return "",ErrInvalidResource}}

func (executor *LinuxMariaDBExecutor) ObserveOrApply(ctx context.Context, request EffectRequest) (EffectReceipt, error) {
	if executor == nil || executor.secrets == nil || os.Geteuid() != 0 {
		return EffectReceipt{}, ErrUnauthorized
	}
	if err := validateEffectRequest(request); err != nil || validateLinuxEffectScope(request) != nil {
		return EffectReceipt{}, ErrInvalidCommand
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()

	var prior EffectReceipt
	if err := executor.readNamed("effects", request.EffectID, &prior); err == nil {
		if prior.RequestDigest != request.RequestDigest || !effectReceiptMatches(request, prior) {
			return EffectReceipt{}, ErrIdempotency
		}
		return prior, nil
	} else if !errors.Is(err, ErrNotFound) {
		return EffectReceipt{}, err
	}

	application, err := executor.apply(ctx, request)
	receipt := EffectReceipt{EffectID: request.EffectID, RequestDigest: request.RequestDigest}
	if err == nil {
		receipt.Outcome = EffectConfirmed
		receipt.MutationObserved = true
		receipt.ProofDigest = digestBytes(application.proof)
		if application.compensation != nil {
			_ = executor.removeResource("compensations", application.compensation.Token)
		}
	} else if application.ambiguous || application.mutated && application.compensation == nil {
		receipt.Outcome = EffectAmbiguous
		receipt.MutationObserved = application.mutated
		receipt.FailureCode = closedFailureCode(application.failureCode)
	} else {
		receipt.Outcome = EffectRejected
		receipt.MutationObserved = application.mutated
		receipt.FailureCode = closedFailureCode(application.failureCode)
		if application.mutated && application.compensation != nil {
			receipt.CompensationToken = application.compensation.Token
		}
	}
	if writeErr := executor.writeNamed("effects", request.EffectID, receipt); writeErr != nil {
		if err == nil {
			receipt = EffectReceipt{EffectID: request.EffectID, RequestDigest: request.RequestDigest, Outcome: EffectAmbiguous, MutationObserved: true, FailureCode: "receipt_persistence_failed"}
		}
		return receipt, errors.Join(err, writeErr)
	}
	return receipt, err
}

func (executor *LinuxMariaDBExecutor) Compensate(ctx context.Context, request CompensationRequest) (CompensationReceipt, error) {
	receipt := CompensationReceipt{EffectID: request.EffectID, RequestDigest: request.RequestDigest, CompensationToken: request.CompensationToken}
	if executor == nil || executor.secrets == nil || os.Geteuid() != 0 || request.EffectID == "" || request.RequestDigest == "" || request.CompensationToken.IsZero() {
		return receipt, ErrInvalidCommand
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	var compensation mariaDBCompensation
	if err := executor.readResource("compensations", request.CompensationToken, &compensation); err != nil {
		receipt.Outcome = EffectRejected
		return receipt, err
	}
	if compensation.EffectID != request.EffectID || compensation.RequestDigest != request.RequestDigest || compensation.Token != request.CompensationToken {
		receipt.Outcome = EffectRejected
		return receipt, ErrIdempotency
	}
	proof, err := executor.applyCompensation(ctx, compensation)
	if err != nil {
		receipt.Outcome = EffectAmbiguous
		return receipt, err
	}
	receipt.Outcome = EffectConfirmed
	receipt.ProofDigest = digestBytes(proof)
	if err := executor.removeResource("compensations", request.CompensationToken); err != nil {
		receipt.Outcome = EffectAmbiguous
		return receipt, err
	}
	return receipt, nil
}

func (executor *LinuxMariaDBExecutor) Status(ctx context.Context, instanceID ResourceID) (MariaDBInstanceStatus, error) {
	if executor == nil || instanceID.IsZero() || os.Geteuid() != 0 {
		return MariaDBInstanceStatus{}, ErrInvalidCommand
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	instance, err := executor.instance(instanceID)
	if err != nil {
		return MariaDBInstanceStatus{}, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return MariaDBInstanceStatus{}, err
	}
	defer cleanup()
	observed, err := connection.query(ctx, sqlObserveStatus)
	if err != nil {
		return MariaDBInstanceStatus{}, err
	}
	version, err := parseMariaDBVersion(firstField(observed))
	if err != nil {
		return MariaDBInstanceStatus{}, err
	}
	proof := digestBytes(append([]byte(instance.ID.String()+"\x00"), observed...))
	return MariaDBInstanceStatus{InstanceID: instance.ID, Placement: instance.Placement, Version: version, Reachable: true,
		TLSVerified: instance.Placement == PlacementExternal, ProofDigest: proof, ObservedAt: executor.now().UTC()}, nil
}

func (executor *LinuxMariaDBExecutor) apply(ctx context.Context, request EffectRequest) (effectApplication, error) {
	switch request.Kind {
	case EffectCreateDatabase:
		return executor.applyCreateDatabase(ctx, request, request.CreateDatabase.Database)
	case EffectDeleteDatabase:
		return executor.applyDeleteDatabase(ctx, request, *request.DeleteDatabase)
	case EffectCreatePrincipal:
		return executor.applyCreatePrincipal(ctx, request, request.CreatePrincipal.Principal)
	case EffectDeletePrincipal:
		return executor.applyDeletePrincipal(ctx, request, request.DeletePrincipal.Principal)
	case EffectRotatePassword:
		return executor.applyRotatePassword(ctx, request, *request.RotatePassword)
	case EffectReplaceGrants:
		return executor.applyReplaceGrants(ctx, request, request.ReplaceGrants.GrantSet)
	case EffectApplyNetworkPolicy:
		return executor.applyNetworkPolicy(ctx, request, request.ApplyNetworkPolicy.Policy)
	case EffectBindExternalInstance:
		return executor.applyBindExternal(ctx, request, request.BindExternalInstance.Instance)
	case EffectOpenConsoleSession:
		return executor.applyConsoleSession(ctx, request, request.OpenConsoleSession.Session)
	case EffectApplyTuning:
		return executor.applyTuning(ctx, request, request.ApplyTuning.Profile)
	case EffectUpgradeDatabase:
		return executor.applyUpgrade(ctx, request, request.UpgradeDatabase.Upgrade)
	default:
		return effectApplication{failureCode: "unsupported_effect"}, ErrInvalidCommand
	}
}

func validateLinuxEffectScope(request EffectRequest) error {
	if request.Scope.Kind != effectResourceKind(request.Kind) {
		return ErrInvalidCommand
	}
	var metadata Metadata
	switch request.Kind {
	case EffectCreateDatabase:
		metadata = request.CreateDatabase.Database.Metadata
	case EffectDeleteDatabase:
		metadata = request.DeleteDatabase.Database.Metadata
	case EffectCreatePrincipal:
		metadata = request.CreatePrincipal.Principal.Metadata
	case EffectDeletePrincipal:
		metadata = request.DeletePrincipal.Principal.Metadata
	case EffectRotatePassword:
		metadata = request.RotatePassword.Principal.Metadata
	case EffectReplaceGrants:
		metadata = request.ReplaceGrants.GrantSet.Metadata
	case EffectApplyNetworkPolicy:
		metadata = request.ApplyNetworkPolicy.Policy.Metadata
	case EffectBindExternalInstance:
		metadata = request.BindExternalInstance.Instance.Metadata
	case EffectOpenConsoleSession:
		metadata = request.OpenConsoleSession.Session.Metadata
	case EffectApplyTuning:
		metadata = request.ApplyTuning.Profile.Metadata
	case EffectUpgradeDatabase:
		metadata = request.UpgradeDatabase.Upgrade.Metadata
	default:
		return ErrInvalidCommand
	}
	if metadata.ID != request.Scope.ID || metadata.TenantID != request.Scope.TenantID {
		return ErrUnauthorized
	}
	return nil
}

func effectResourceKind(kind EffectKind) ResourceKind {
	switch kind {
	case EffectCreateDatabase, EffectDeleteDatabase:
		return KindDatabase
	case EffectCreatePrincipal, EffectDeletePrincipal, EffectRotatePassword:
		return KindPrincipal
	case EffectReplaceGrants:
		return KindGrantSet
	case EffectApplyNetworkPolicy:
		return KindNetworkPolicy
	case EffectBindExternalInstance:
		return KindDatabaseInstance
	case EffectOpenConsoleSession:
		return KindConsoleSession
	case EffectApplyTuning:
		return KindTuningProfile
	case EffectUpgradeDatabase:
		return KindDatabaseUpgrade
	default:
		return ""
	}
}

func (executor *LinuxMariaDBExecutor) initializeRoots() error {
	for _, path := range []string{mariaDBStateRoot, mariaDBConfigRoot, mariaDBRunRoot} {
		if err := ensureRootDirectory(path, 0700); err != nil {
			return err
		}
	}
	for _, name := range []string{"instances", "databases", "principals", "grants", "policies", "sessions", "tuning", "upgrades", "effects", "compensations"} {
		if err := ensureRootDirectory(filepath.Join(mariaDBStateRoot, name), 0700); err != nil {
			return err
		}
	}
	return ensureRootDirectory(filepath.Join(mariaDBConfigRoot, "generations"), 0700)
}

func ensureRootDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, "/") {
		return ErrInvalidResource
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0077 != 0 {
		return ErrUnauthorized
	}
	return nil
}

func (executor *LinuxMariaDBExecutor) writeResource(kind string, id ResourceID, value any) error {
	if id.IsZero() {
		return ErrInvalidResource
	}
	return executor.writeNamed(kind, id.String()+".json", value)
}

func (executor *LinuxMariaDBExecutor) readResource(kind string, id ResourceID, value any) error {
	if id.IsZero() {
		return ErrInvalidResource
	}
	return executor.readNamed(kind, id.String()+".json", value)
}

func (executor *LinuxMariaDBExecutor) removeResource(kind string, id ResourceID) error {
	if id.IsZero() {
		return ErrInvalidResource
	}
	return executor.removeNamed(kind, id.String()+".json")
}

func (executor *LinuxMariaDBExecutor) writeNamed(kind, name string, value any) error {
	if !safeStateComponent(kind) || !safeStateName(name) {
		return ErrInvalidResource
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return atomicRootFile(filepath.Join(mariaDBStateRoot, kind, name), payload, 0600)
}

func (executor *LinuxMariaDBExecutor) readNamed(kind, name string, value any) error {
	if !safeStateComponent(kind) || !safeStateName(name) {
		return ErrInvalidResource
	}
	path := filepath.Join(mariaDBStateRoot, kind, name)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm() != 0600 || info.Size() > 4<<20 {
		return ErrUnauthorized
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, value); err != nil {
		return ErrInvalidResource
	}
	return nil
}

func (executor *LinuxMariaDBExecutor) removeNamed(kind, name string) error {
	if !safeStateComponent(kind) || !safeStateName(name) {
		return ErrInvalidResource
	}
	err := os.Remove(filepath.Join(mariaDBStateRoot, kind, name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func atomicRootFile(path string, payload []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := verifyRootDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".cyberpanel-mariadb-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chown(0, 0); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func verifyRootDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return ErrUnauthorized
	}
	return nil
}

func safeStateComponent(value string) bool {
	switch value {
	case "instances", "databases", "principals", "grants", "policies", "sessions", "tuning", "upgrades", "effects", "compensations":
		return true
	default:
		return false
	}
}

func safeStateName(value string) bool {
	if value == "" || len(value) > 160 || strings.Contains(value, "..") {
		return false
	}
	for index := range value {
		character := value[index]
		if !asciiAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func (executor *LinuxMariaDBExecutor) instance(id ResourceID) (DatabaseInstance, error) {
	var instance DatabaseInstance
	if err := executor.readResource("instances", id, &instance); err != nil {
		return DatabaseInstance{}, err
	}
	if instance.Validate() != nil || instance.ID != id {
		return DatabaseInstance{}, ErrInvalidResource
	}
	return instance, nil
}

func (executor *LinuxMariaDBExecutor) serverConfigPath() string {
	if executor.distribution == LinuxMariaDBAlma {
		return mariaDBAlmaConfig
	}
	return mariaDBUbuntuConfig
}

func (executor *LinuxMariaDBExecutor) saveCompensation(request EffectRequest, compensation mariaDBCompensation) (*mariaDBCompensation, error) {
	digest := sha256.Sum256([]byte("cyberpanel:mariadb-compensation:v1\x00" + request.EffectID + "\x00" + request.RequestDigest))
	token, err := NewResourceID("comp-" + hex.EncodeToString(digest[:]))
	if err != nil {
		return nil, err
	}
	compensation.Token, compensation.EffectID, compensation.RequestDigest = token, request.EffectID, request.RequestDigest
	if err := executor.writeResource("compensations", token, compensation); err != nil {
		return nil, err
	}
	return &compensation, nil
}

func validateServerTLS(material MariaDBServerTLS) error {
	if len(material.CertificateAuthorityPEM) == 0 || len(material.CertificatePEM) == 0 || len(material.KeyPEM) == 0 ||
		len(material.CertificateAuthorityPEM) > maximumSecretBytes || len(material.CertificatePEM) > maximumSecretBytes || len(material.KeyPEM) > maximumSecretBytes {
		return ErrInvalidResource
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(material.CertificateAuthorityPEM) {
		return ErrInvalidResource
	}
	if _, err := tls.X509KeyPair(material.CertificatePEM, material.KeyPEM); err != nil {
		return ErrInvalidResource
	}
	return nil
}

func validateAdministrator(administrator MariaDBAdministrator, mutual bool) error {
	if administrator.Username.IsZero() || len(administrator.Password) == 0 || len(administrator.Password) > maximumSecretBytes || strings.IndexByte(string(administrator.Password), 0) >= 0 {
		return ErrInvalidResource
	}
	if !mutual && (len(administrator.ClientCertificatePEM) != 0 || len(administrator.ClientKeyPEM) != 0) {
		return ErrInvalidResource
	}
	if mutual {
		if len(administrator.ClientCertificatePEM) == 0 || len(administrator.ClientKeyPEM) == 0 || len(administrator.ClientCertificatePEM) > maximumSecretBytes || len(administrator.ClientKeyPEM) > maximumSecretBytes {
			return ErrInvalidResource
		}
		if _, err := tls.X509KeyPair(administrator.ClientCertificatePEM, administrator.ClientKeyPEM); err != nil {
			return ErrInvalidResource
		}
	}
	return nil
}

func wipeBytes(values ...[]byte) {
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
		runtime.KeepAlive(value)
	}
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func closedFailureCode(value string) string {
	switch value {
	case "precondition_failed", "instance_not_found", "instance_conflict", "credential_unavailable", "tls_material_invalid", "connection_failed",
		"database_conflict", "database_apply_failed", "database_delete_failed", "principal_conflict", "principal_apply_failed", "principal_delete_failed",
		"grant_apply_failed", "network_apply_failed", "external_network_unmanaged", "console_apply_failed", "tuning_apply_failed",
		"upgrade_preflight_failed", "upgrade_apply_failed", "unsupported_external_upgrade", "state_persistence_failed", "receipt_persistence_failed", "unsupported_effect":
		return value
	default:
		return "operation_failed"
	}
}

func parseMariaDBVersion(raw string) (MariaDBVersion, error) {
	raw = strings.TrimSpace(raw)
	if dash := strings.IndexByte(raw, '-'); dash >= 0 {
		raw = raw[:dash]
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return MariaDBVersion{}, ErrInvalidResource
	}
	var version MariaDBVersion
	values := []*uint16{&version.Major, &version.Minor, &version.Patch}
	for index := 0; index < len(parts) && index < len(values); index++ {
		var parsed uint64
		if _, err := fmt.Sscanf(parts[index], "%d", &parsed); err != nil || parsed > 65535 {
			return MariaDBVersion{}, ErrInvalidResource
		}
		*values[index] = uint16(parsed)
	}
	if version.Major == 0 {
		return MariaDBVersion{}, ErrInvalidResource
	}
	return version, nil
}

func firstField(raw []byte) string {
	line := strings.TrimSpace(string(raw))
	if newline := strings.IndexByte(line, '\n'); newline >= 0 {
		line = line[:newline]
	}
	if tab := strings.IndexByte(line, '\t'); tab >= 0 {
		line = line[:tab]
	}
	return line
}
