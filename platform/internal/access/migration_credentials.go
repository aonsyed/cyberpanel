package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
)

type MigrationPrincipalKind string

const (
	MigrationPrincipalSSH  MigrationPrincipalKind = "ssh"
	MigrationPrincipalFTPS MigrationPrincipalKind = "ftps"
)

type MigrationAccessPolicy string

const (
	MigrationPolicyShell         MigrationAccessPolicy = "shell"
	MigrationPolicySFTPReadWrite MigrationAccessPolicy = "sftp_read_write"
	MigrationPolicySFTPReadOnly  MigrationAccessPolicy = "sftp_read_only"
	MigrationPolicyFTPSReadWrite MigrationAccessPolicy = "ftps_read_write"
)

type MigrationCredentialFormat string

const MigrationCredentialUnixCryptHash MigrationCredentialFormat = "unix_crypt_hash_v1"

type MigrationCredentialReference struct {
	Reference string                    `json:"reference"`
	Format    MigrationCredentialFormat `json:"format"`
}

type MigrationAuthorizedKey struct {
	ID        SSHKeyID  `json:"id"`
	Name      string    `json:"name"`
	PublicKey PublicKey `json:"public_key"`
}

type MigrationPrincipal struct {
	EffectID       string                        `json:"effect_id"`
	MigrationID    string                        `json:"migration_id"`
	PrincipalID    PrincipalID                   `json:"principal_id"`
	TenantID       TenantID                      `json:"tenant_id"`
	SiteID         SiteID                        `json:"site_id"`
	Kind           MigrationPrincipalKind        `json:"kind"`
	Policy         MigrationAccessPolicy         `json:"policy"`
	Username       string                        `json:"username"`
	Home           RelativePath                  `json:"home"`
	UID            uint32                        `json:"uid"`
	GID            uint32                        `json:"gid"`
	AuthorizedKeys []MigrationAuthorizedKey      `json:"authorized_keys,omitempty"`
	Credential     *MigrationCredentialReference `json:"credential,omitempty"`
	Enabled        bool                          `json:"enabled"`
}

func (principal MigrationPrincipal) Validate() error {
	if !migrationAccessDigest(principal.EffectID) || !validID(principal.MigrationID) {
		return ErrInvalidID
	}
	if err := requireID("principal", string(principal.PrincipalID)); err != nil {
		return err
	}
	if err := requireID("tenant", string(principal.TenantID)); err != nil {
		return err
	}
	if err := requireID("site", string(principal.SiteID)); err != nil {
		return err
	}
	if err := validateLoginName(principal.Username); err != nil {
		return err
	}
	if parsed, err := ParseRelativePath(principal.Home.String()); err != nil || parsed != principal.Home {
		return ErrInvalidPath
	}
	if principal.UID < 1000 || principal.GID < 1000 {
		return ErrInvalidState
	}
	seen := map[string]struct{}{}
	switch principal.Kind {
	case MigrationPrincipalSSH:
		if principal.Policy != MigrationPolicyShell && principal.Policy != MigrationPolicySFTPReadWrite && principal.Policy != MigrationPolicySFTPReadOnly || principal.Credential != nil || len(principal.AuthorizedKeys) == 0 {
			return ErrInvalidState
		}
		for _, key := range principal.AuthorizedKeys {
			if err := requireID("SSH key", string(key.ID)); err != nil {
				return err
			}
			if strings.TrimSpace(key.Name) == "" || len(key.Name) > 191 || strings.ContainsAny(key.Name, "\r\n\x00") {
				return ErrInvalidState
			}
			parsed, err := ParsePublicKey(key.PublicKey.AuthorizedKey())
			if err != nil || parsed.Fingerprint != key.PublicKey.Fingerprint {
				return ErrIntegrity
			}
			if _, duplicate := seen[parsed.Fingerprint]; duplicate {
				return ErrConflict
			}
			seen[parsed.Fingerprint] = struct{}{}
		}
	case MigrationPrincipalFTPS:
		if principal.Policy != MigrationPolicyFTPSReadWrite || len(principal.AuthorizedKeys) != 0 || principal.Credential == nil || principal.Credential.Format != MigrationCredentialUnixCryptHash || !validID(principal.Credential.Reference) {
			return ErrInvalidState
		}
	default:
		return ErrInvalidState
	}
	return nil
}

type MigrationFenceBinding struct {
	SourceGeneration uint64    `json:"source_generation"`
	Fence            uint64    `json:"fence"`
	Digest           string    `json:"digest"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (binding MigrationFenceBinding) Validate(now time.Time) error {
	if binding.validateRecorded() != nil || !binding.ExpiresAt.After(now) {
		return ErrUnauthorized
	}
	return nil
}

func (binding MigrationFenceBinding) validateRecorded() error {
	if binding.SourceGeneration == 0 || binding.Fence == 0 || !migrationAccessDigest(binding.Digest) || binding.ExpiresAt.IsZero() {
		return ErrUnauthorized
	}
	return nil
}

type MigrationActivationAction string

const (
	MigrationActivationAdmit            MigrationActivationAction = "admit"
	MigrationActivationObserveAdmission MigrationActivationAction = "observe_admission"
	MigrationActivationCommit           MigrationActivationAction = "commit"
)

type MigrationPrincipalBatch struct {
	EffectID    string                    `json:"effect_id"`
	MigrationID string                    `json:"migration_id"`
	PlanDigest  string                    `json:"plan_digest"`
	Fence       MigrationFenceBinding     `json:"fence"`
	Principals  []MigrationPrincipal      `json:"principals"`
	Action      MigrationActivationAction `json:"action"`
	Attempt     uint32                    `json:"attempt"`
}

func (batch MigrationPrincipalBatch) Validate(now time.Time) error {
	if batch.validateRecorded() != nil {
		return ErrInvalidState
	}
	return batch.Fence.Validate(now)
}

func (batch MigrationPrincipalBatch) validateRecorded() error {
	if !migrationAccessDigest(batch.EffectID) || !validID(batch.MigrationID) || !migrationAccessDigest(batch.PlanDigest) || batch.Attempt == 0 || len(batch.Principals) == 0 || len(batch.Principals) > 10000 || batch.Fence.validateRecorded() != nil || batch.EffectID != MigrationAccessEffectID("migration-access-activation-v1", batch.MigrationID, batch.PlanDigest, batch.Fence.Digest) {
		return ErrInvalidState
	}
	if batch.Action != MigrationActivationAdmit && batch.Action != MigrationActivationObserveAdmission && batch.Action != MigrationActivationCommit {
		return ErrInvalidState
	}
	seen := map[PrincipalID]struct{}{}
	usernames := map[string]struct{}{}
	uids := map[uint32]struct{}{}
	tenant, site := batch.Principals[0].TenantID, batch.Principals[0].SiteID
	for _, principal := range batch.Principals {
		if principal.MigrationID != batch.MigrationID || principal.TenantID != tenant || principal.SiteID != site || principal.Validate() != nil {
			return ErrInvalidState
		}
		if _, duplicate := seen[principal.PrincipalID]; duplicate {
			return ErrConflict
		}
		seen[principal.PrincipalID] = struct{}{}
		if _, duplicate := usernames[principal.Username]; duplicate {
			return ErrConflict
		}
		usernames[principal.Username] = struct{}{}
		if _, duplicate := uids[principal.UID]; duplicate {
			return ErrConflict
		}
		uids[principal.UID] = struct{}{}
	}
	return nil
}

type MigrationAccessStatus string

const (
	MigrationAccessApplied     MigrationAccessStatus = "applied"
	MigrationAccessTerminal    MigrationAccessStatus = "terminal"
	MigrationAccessAmbiguous   MigrationAccessStatus = "ambiguous"
	MigrationAccessCompensated MigrationAccessStatus = "compensated"
)

type MigrationAccessObservation struct {
	EffectID       string                `json:"effect_id"`
	PrincipalID    PrincipalID           `json:"principal_id,omitempty"`
	Status         MigrationAccessStatus `json:"status"`
	State          string                `json:"state"`
	EvidenceDigest string                `json:"evidence_digest,omitempty"`
	ErrorCode      string                `json:"error_code,omitempty"`
	ObservedAt     time.Time             `json:"observed_at"`
}

func (observation MigrationAccessObservation) Validate(effectID string) error {
	if observation.EffectID != effectID || observation.ObservedAt.IsZero() {
		return ErrIntegrity
	}
	switch observation.Status {
	case MigrationAccessApplied, MigrationAccessCompensated:
		if !migrationAccessDigest(observation.EvidenceDigest) || observation.ErrorCode != "" {
			return ErrIntegrity
		}
	case MigrationAccessTerminal, MigrationAccessAmbiguous:
		if observation.ErrorCode == "" || len(observation.ErrorCode) > 128 {
			return ErrIntegrity
		}
	default:
		return ErrIntegrity
	}
	return nil
}

type MigrationPrincipalExecutor interface {
	StageMigrationPrincipal(context.Context, MigrationPrincipal, uint32) (MigrationAccessObservation, error)
	ObserveMigrationPrincipal(context.Context, MigrationPrincipal) (MigrationAccessObservation, error)
	ActivateMigrationPrincipals(context.Context, MigrationPrincipalBatch) (MigrationAccessObservation, error)
	CompensateMigrationPrincipal(context.Context, MigrationPrincipal, uint32) (MigrationAccessObservation, error)
}

type unixCryptHashCredential struct {
	Version uint32                    `json:"version"`
	Format  MigrationCredentialFormat `json:"format"`
	Hash    string                    `json:"hash"`
}

func ValidateUnixCryptHash(value []byte) error {
	if len(value) < 20 || len(value) > 255 || bytes.IndexAny(value, "\x00\r\n:") >= 0 {
		return ErrInvalidState
	}
	text := string(value)
	if strings.HasPrefix(text, "$2a$") || strings.HasPrefix(text, "$2b$") || strings.HasPrefix(text, "$2y$") {
		if len(text) == 60 && text[6] == '$' && validCryptAlphabet(text[7:], 53, 53) {
			cost, err := strconv.Atoi(text[4:6])
			if err == nil && cost >= 4 && cost <= 31 {
				return nil
			}
		}
		return ErrInvalidState
	}
	parts := strings.Split(text, "$")
	if len(parts) < 4 || parts[0] != "" {
		return ErrInvalidState
	}
	switch parts[1] {
	case "1":
		if len(parts) == 4 && validCryptAlphabet(parts[2], 1, 8) && validCryptAlphabet(parts[3], 22, 22) {
			return nil
		}
	case "5", "6":
		digestLength := 43
		if parts[1] == "6" {
			digestLength = 86
		}
		saltIndex := 2
		if len(parts) == 5 && strings.HasPrefix(parts[2], "rounds=") {
			rounds, err := strconv.ParseUint(strings.TrimPrefix(parts[2], "rounds="), 10, 32)
			if err != nil || rounds < 1000 || rounds > 999999999 {
				return ErrInvalidState
			}
			saltIndex = 3
		} else if len(parts) != 4 {
			return ErrInvalidState
		}
		if validCryptAlphabet(parts[saltIndex], 1, 16) && validCryptAlphabet(parts[saltIndex+1], digestLength, digestLength) {
			return nil
		}
	case "y":
		if len(parts) == 5 && validCryptAlphabet(parts[2], 1, 32) && validCryptAlphabet(parts[3], 1, 86) && validCryptAlphabet(parts[4], 20, 128) {
			return nil
		}
	}
	return ErrInvalidState
}

func validCryptAlphabet(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := range value {
		character := value[index]
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '/') {
			return false
		}
	}
	return true
}

func EncodeUnixCryptHashCredential(value []byte) ([]byte, error) {
	if err := ValidateUnixCryptHash(value); err != nil {
		return nil, err
	}
	return json.Marshal(unixCryptHashCredential{Version: 1, Format: MigrationCredentialUnixCryptHash, Hash: string(value)})
}

func DecodeUnixCryptHashCredential(value []byte) ([]byte, error) {
	if len(value) == 0 || len(value) > 2048 {
		return nil, ErrInvalidState
	}
	var credential unixCryptHashCredential
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil || decoder.Decode(&struct{}{}) != io.EOF || credential.Version != 1 || credential.Format != MigrationCredentialUnixCryptHash || ValidateUnixCryptHash([]byte(credential.Hash)) != nil {
		return nil, ErrInvalidState
	}
	return []byte(credential.Hash), nil
}

func migrationAccessDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func MigrationAccessEffectID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
