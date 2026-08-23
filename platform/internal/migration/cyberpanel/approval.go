package cyberpanel

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

const sourcePlanSignatureDomain = "cyberpanel-source-plan-v1"

type LocalApprovalPolicy struct {
	SourceInstallationID string
	Keys map[string]ed25519.PublicKey
	MaximumLifetime time.Duration
	AllowedTargets map[string]struct{}
	AllowedSchemaHashes map[string]struct{}
}

type LocalApprovalVerifier struct {
	policy LocalApprovalPolicy
}

func NewLocalApprovalVerifier(policy LocalApprovalPolicy) (*LocalApprovalVerifier, error) {
	if strings.TrimSpace(policy.SourceInstallationID)==""||len(policy.Keys) == 0 || len(policy.AllowedTargets) == 0 || len(policy.AllowedSchemaHashes) == 0 {
		return nil, ErrInvalid
	}
	if policy.MaximumLifetime == 0 {
		policy.MaximumLifetime = 24 * time.Hour
	}
	if policy.MaximumLifetime < time.Minute || policy.MaximumLifetime > 30*24*time.Hour {
		return nil, ErrInvalid
	}
	keys := make(map[string]ed25519.PublicKey, len(policy.Keys))
	for id, key := range policy.Keys {
		if !validKeyID(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	targets := make(map[string]struct{}, len(policy.AllowedTargets))
	for target := range policy.AllowedTargets {
		if strings.TrimSpace(target) == "" {
			return nil, ErrInvalid
		}
		targets[target] = struct{}{}
	}
	hashes := make(map[string]struct{}, len(policy.AllowedSchemaHashes))
	for digest := range policy.AllowedSchemaHashes {
		if !isDigest(digest) {
			return nil, ErrInvalid
		}
		hashes[digest] = struct{}{}
	}
	policy.Keys = keys
	policy.AllowedTargets = targets
	policy.AllowedSchemaHashes = hashes
	return &LocalApprovalVerifier{policy: policy}, nil
}

func (v *LocalApprovalVerifier) VerifyApprovedPlan(ctx context.Context, approved ApprovedPlan, now time.Time) error {
	if v == nil || ctx == nil || now.IsZero() || approved.ApprovedAt.IsZero() || !validKeyID(approved.ApproverKeyID) || len(approved.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := approved.Plan.validate(now.UTC()); err != nil {
		return err
	}
	if approved.Plan.SourceInstallationID!=v.policy.SourceInstallationID{return ErrDenied}
	if approved.ApprovedAt.Before(approved.Plan.NotBefore) || approved.ApprovedAt.After(approved.Plan.ExpiresAt) || approved.Plan.ExpiresAt.Sub(approved.Plan.NotBefore) > v.policy.MaximumLifetime {
		return ErrDenied
	}
	if _, allowed := v.policy.AllowedTargets[approved.Plan.TargetInstallationID]; !allowed {
		return ErrDenied
	}
	if _, allowed := v.policy.AllowedSchemaHashes[approved.Plan.SchemaHash]; !allowed {
		return ErrDenied
	}
	key, trusted := v.policy.Keys[approved.ApproverKeyID]
	if !trusted {
		return ErrDenied
	}
	message, err := approvedPlanMessage(approved)
	if err != nil || !ed25519.Verify(key, message, approved.Signature) {
		return ErrDenied
	}
	return nil
}

func SignApprovedPlan(plan SourcePlan, approvedAt time.Time, keyID string, privateKey ed25519.PrivateKey) (ApprovedPlan, error) {
	if approvedAt.IsZero() || !validKeyID(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return ApprovedPlan{}, ErrInvalid
	}
	if err := plan.validate(approvedAt.UTC()); err != nil {
		return ApprovedPlan{}, err
	}
	approved := ApprovedPlan{Plan: plan, ApprovedAt: approvedAt.UTC(), ApproverKeyID: keyID}
	message, err := approvedPlanMessage(approved)
	if err != nil {
		return ApprovedPlan{}, err
	}
	approved.Signature = ed25519.Sign(privateKey, message)
	return approved, nil
}

func approvedPlanMessage(approved ApprovedPlan) ([]byte, error) {
	approved.Signature = nil
	approved.Plan.SiteSourceIDs = append([]string(nil), approved.Plan.SiteSourceIDs...)
	sortStrings(approved.Plan.SiteSourceIDs)
	raw, err := json.Marshal(approved)
	if err != nil {
		return nil, err
	}
	return append([]byte(sourcePlanSignatureDomain+"\x00"), raw...), nil
}

type FilePlanStore struct {
	root *os.Root
}

func OpenFilePlanStore(rootPath string) (*FilePlanStore, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(rootPath)
	if err != nil || !before.IsDir() || before.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, ErrInvalid
	}
	return &FilePlanStore{root: root}, nil
}

func (s *FilePlanStore) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
}

func (s *FilePlanStore) ApprovedPlan(ctx context.Context, migrationID migration.ID) (ApprovedPlan, error) {
	if s == nil || s.root == nil || ctx == nil || !migrationID.Valid() {
		return ApprovedPlan{}, ErrInvalid
	}
	select {
	case <-ctx.Done():
		return ApprovedPlan{}, ctx.Err()
	default:
	}
	name := migrationID.String() + ".json"
	before, err := s.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return ApprovedPlan{}, migration.ErrNotFound
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 || before.Size() < 2 || before.Size() > 1<<20 {
		return ApprovedPlan{}, ErrInvalid
	}
	file, err := s.root.Open(name)
	if err != nil {
		return ApprovedPlan{}, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o400 {
		return ApprovedPlan{}, ErrInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var value ApprovedPlan
	if err := decoder.Decode(&value); err != nil {
		return ApprovedPlan{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ApprovedPlan{}, ErrInvalid
	}
	final, err := file.Stat()
	if err != nil || !sameFileState(after, final) || !final.Mode().IsRegular() || final.Mode().Perm() != 0o400 {
		return ApprovedPlan{}, ErrChanged
	}
	if value.Plan.MigrationID != migrationID {
		return ApprovedPlan{}, ErrDenied
	}
	return value, nil
}

func approvedPlanDigest(approved ApprovedPlan) (string, error) {
	message, err := approvedPlanMessage(approved)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(message)
	return hex.EncodeToString(sum[:]), nil
}

func isDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validKeyID(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' && character != ':' && character != '.' {
			return false
		}
	}
	return true
}

func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}
