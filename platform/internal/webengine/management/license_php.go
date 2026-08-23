package management

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

const (
	LicenseModeSerial     = "serial"
	LicenseModeLicenseKey = "license_key"
	LicenseModeTrial      = "trial"
)

const (
	LicenseUnknown     webengine.LicenseState = "unknown"
	LicenseGrace       webengine.LicenseState = "grace"
	LicenseExpired     webengine.LicenseState = "expired"
	LicenseRevoked     webengine.LicenseState = "revoked"
	LicenseInvalid     webengine.LicenseState = "invalid"
	LicenseOverLimit   webengine.LicenseState = "over_limit"
	LicenseUnavailable webengine.LicenseState = "unavailable"
)

type LicenseCommand struct {
	CommandID                 string
	License                   LicenseRequest
	ExpectedGeneration, Fence uint64
	CommitAuthorizationDigest string
}

type PHPProfileCommand struct {
	CommandID                 string
	Profile                   PHPProfile
	ExpectedGeneration, Fence uint64
	CommitAuthorizationDigest string
}

// PHPArtifactCatalog resolves only product-approved local artifacts. The
// privileged broker independently resolves and verifies the same signed
// catalog before touching a runtime path.
type PHPArtifactCatalog interface {
	ResolvePHP(context.Context, string, []string) (PHPArtifactPlan, error)
}

type phpRollbackExecutor interface {
	RollbackPHP(context.Context, EffectRequest, PHPArtifactPlan, *PHPProfile) (EffectReceipt, error)
}

type managedEffectRepository interface {
	AdmitManagedEffect(context.Context, Operation) (Operation, bool, error)
	RecordManagedEffect(context.Context, string, string, any) error
	CommitManagedLicense(context.Context, string, Installation, LicenseStatus, uint64) error
	CommitManagedPHP(context.Context, string, Installation, PHPProfile, any, uint64) error
}

func (service *Service) ConfigureLicense(ctx context.Context, command LicenseCommand) (LicenseStatus, error) {
	if service == nil || !service.capabilities.RefreshLicense || ctx == nil {
		return LicenseStatus{}, ErrUnsupported
	}
	repository, ok := service.repository.(managedEffectRepository)
	if !ok {
		return LicenseStatus{}, ErrUnsupported
	}
	current, err := service.repository.Installation(ctx)
	if err != nil {
		return LicenseStatus{}, err
	}
	if current.ID != "node-webengine" || current.Edition != webengine.EditionLiteSpeedEnterprise ||
		current.Generation != command.ExpectedGeneration || current.State != StateActive {
		return current.License, ErrConflict
	}
	if !validLicenseRequest(command.License) || !validEffectToken(command.CommandID) ||
		command.Fence != command.ExpectedGeneration+1 || !validSHA256(command.CommitAuthorizationDigest) {
		return LicenseStatus{}, ErrInvalid
	}
	planDigest := digestJSON(struct {
		Mode       string `json:"mode"`
		SecretRef  string `json:"secret_ref,omitempty"`
		Trial      bool   `json:"trial"`
		Generation uint64 `json:"generation"`
	}{command.License.Mode, command.License.SecretRef, command.License.Trial, command.ExpectedGeneration})
	effect := effectID(command.CommandID, planDigest)
	next := current
	next.Generation++
	next.UpdatedAt = service.clock().UTC()
	operation := Operation{ID: effect, Kind: "license.configure", Status: "accepted", RequestDigest: planDigest,
		ExpectedGeneration: command.ExpectedGeneration, Installation: next, CreatedAt: service.clock().UTC(), UpdatedAt: service.clock().UTC()}
	admitted, _, err := repository.AdmitManagedEffect(ctx, operation)
	if err != nil {
		return LicenseStatus{}, err
	}
	if admitted.Status == "applied" {
		return admitted.Installation.License, nil
	}
	if admitted.Status == "rejected" || admitted.Status == "rolled_back" {
		return admitted.Installation.License, ErrLicense
	}
	request := EffectRequest{EffectID: effect, ExpectedGeneration: command.ExpectedGeneration, Fence: command.Fence,
		PlanDigest: planDigest, CommitAuthorizationDigest: command.CommitAuthorizationDigest,
		LicenseMode: command.License.Mode, SecretRef: command.License.SecretRef}
	status, effectErr := service.executor.ApplyLicense(ctx, request, command.License)
	if effectErr != nil || !validLicenseStatus(status, request, command.License) {
		_ = repository.RecordManagedEffect(context.WithoutCancel(ctx), effect, "ambiguous", status)
		return status, errors.Join(ErrAmbiguous, effectErr)
	}
	next.License = status
	if err = repository.CommitManagedLicense(ctx, effect, next, status, command.ExpectedGeneration); err != nil {
		return status, errors.Join(ErrAmbiguous, err)
	}
	return status, nil
}

func (service *Service) refreshLicense(ctx context.Context, effect string, expected, fence uint64) (LicenseStatus, error) {
	if service == nil || !service.capabilities.RefreshLicense || ctx == nil {
		return LicenseStatus{}, ErrUnsupported
	}
	repository, ok := service.repository.(managedEffectRepository)
	if !ok {
		return LicenseStatus{}, ErrUnsupported
	}
	current, err := service.repository.Installation(ctx)
	if err != nil {
		return LicenseStatus{}, err
	}
	if current.Edition != webengine.EditionLiteSpeedEnterprise || current.Generation != expected ||
		current.State != StateActive || !validEffectToken(effect) || fence != expected+1 || !validStoredLicense(current.License) {
		return current.License, ErrConflict
	}
	planDigest := digestJSON(struct {
		Mode, SecretRef, PriorReceipt string
		Generation                    uint64
	}{current.License.Mode, current.License.SecretRef, current.License.ReceiptDigest, expected})
	next := current
	next.Generation++
	next.UpdatedAt = service.clock().UTC()
	operation := Operation{ID: effect, Kind: "license.refresh", Status: "accepted", RequestDigest: planDigest,
		ExpectedGeneration: expected, Installation: next, CreatedAt: service.clock().UTC(), UpdatedAt: service.clock().UTC()}
	admitted, _, err := repository.AdmitManagedEffect(ctx, operation)
	if err != nil {
		return LicenseStatus{}, err
	}
	if admitted.Status == "applied" {
		return admitted.Installation.License, nil
	}
	request := EffectRequest{EffectID: effect, ExpectedGeneration: expected, Fence: fence, PlanDigest: planDigest,
		LicenseMode: current.License.Mode, SecretRef: current.License.SecretRef, SerialFingerprint: current.License.SerialFingerprint}
	status, effectErr := service.executor.RefreshLicense(ctx, request)
	licenseRequest := LicenseRequest{Mode: current.License.Mode, SecretRef: current.License.SecretRef, Trial: current.License.Mode == LicenseModeTrial}
	if effectErr != nil || !validLicenseStatus(status, request, licenseRequest) {
		_ = repository.RecordManagedEffect(context.WithoutCancel(ctx), effect, "ambiguous", status)
		return status, errors.Join(ErrAmbiguous, effectErr)
	}
	next.License = status
	if err = repository.CommitManagedLicense(ctx, effect, next, status, expected); err != nil {
		return status, errors.Join(ErrAmbiguous, err)
	}
	return status, nil
}

func (service *Service) CreatePHPProfile(ctx context.Context, command PHPProfileCommand) (PHPProfile, error) {
	if service == nil || !service.capabilities.InstallPHP || ctx == nil {
		return PHPProfile{}, ErrUnsupported
	}
	repository, ok := service.repository.(managedEffectRepository)
	if !ok {
		return PHPProfile{}, ErrUnsupported
	}
	catalog, ok := service.catalog.(PHPArtifactCatalog)
	if !ok {
		return PHPProfile{}, ErrUnsupported
	}
	current, err := service.repository.Installation(ctx)
	if err != nil {
		return PHPProfile{}, err
	}
	if current.Generation != command.ExpectedGeneration || current.State != StateActive ||
		!validEffectToken(command.CommandID) || command.Fence != command.ExpectedGeneration+1 ||
		!validSHA256(command.CommitAuthorizationDigest) {
		return PHPProfile{}, ErrConflict
	}
	profile := command.Profile
	extensions := canonicalExtensions(profile.Extensions)
	if len(profile.Extensions) > 0 && len(extensions) == 0 {
		return PHPProfile{}, ErrInvalid
	}
	profile.Extensions = extensions
	profile.Generation = command.ExpectedGeneration + 1
	plan, err := catalog.ResolvePHP(ctx, profile.Version, profile.Extensions)
	if err != nil {
		return PHPProfile{}, err
	}
	profile.BinaryPathID = plan.BinaryPathID
	profile.CatalogDigest = plan.CatalogDigest
	profile.CatalogSequence = plan.CatalogSequence
	profile.BinaryArtifactDigest = digestJSON(plan)
	profile.ConfigDigest = phpProfileConfigDigest(profile)
	if !validPHPProfile(profile, plan) {
		return PHPProfile{}, ErrInvalid
	}
	planDigest := digestJSON(struct {
		Plan    PHPArtifactPlan `json:"plan"`
		Profile PHPProfile      `json:"profile"`
	}{plan, profile})
	effect := effectID(command.CommandID, planDigest)
	next := current
	next.Generation = profile.Generation
	next.UpdatedAt = service.clock().UTC()
	operation := Operation{ID: effect, Kind: "php_profile.create", Status: "accepted", RequestDigest: planDigest,
		ExpectedGeneration: command.ExpectedGeneration, Installation: next, CreatedAt: service.clock().UTC(), UpdatedAt: service.clock().UTC()}
	admitted, _, err := repository.AdmitManagedEffect(ctx, operation)
	if err != nil {
		return PHPProfile{}, err
	}
	if admitted.Status == "applied" {
		return service.repository.PHPProfile(ctx, profile.ID)
	}
	var previous *PHPProfile
	if stored, loadErr := service.repository.PHPProfile(ctx, profile.ID); loadErr == nil {
		previous = &stored
	} else if !errors.Is(loadErr, ErrNotFound) {
		return PHPProfile{}, loadErr
	}
	request := EffectRequest{EffectID: effect, ExpectedGeneration: command.ExpectedGeneration, Fence: command.Fence,
		PlanDigest: planDigest, CommitAuthorizationDigest: command.CommitAuthorizationDigest}
	installReceipt, effectErr := service.executor.InstallPHP(ctx, request, plan)
	if effectErr == nil && validPHPReceipt(installReceipt, request, profile.Generation) {
		installReceipt, effectErr = service.executor.ApplyPHPProfile(ctx, request, profile)
	}
	if effectErr != nil || !validPHPReceipt(installReceipt, request, profile.Generation) {
		status := "ambiguous"
		if rollback, supported := service.executor.(phpRollbackExecutor); supported {
			restored, rollbackErr := rollback.RollbackPHP(context.WithoutCancel(ctx), request, plan, previous)
			if rollbackErr == nil && validPHPRollbackReceipt(restored, request, profile.Generation) {
				status = "rolled_back"
			} else {
				effectErr = errors.Join(effectErr, rollbackErr)
			}
		}
		_ = repository.RecordManagedEffect(context.WithoutCancel(ctx), effect, status, installReceipt)
		if status == "rolled_back" {
			return profile, errors.Join(ErrInvalid, effectErr)
		}
		return profile, errors.Join(ErrAmbiguous, effectErr)
	}
	if err = repository.CommitManagedPHP(ctx, effect, next, profile, installReceipt, command.ExpectedGeneration); err != nil {
		return profile, errors.Join(ErrAmbiguous, err)
	}
	return profile, nil
}

func validLicenseRequest(request LicenseRequest) bool {
	if request.Mode == LicenseModeTrial {
		return request.Trial && request.SecretRef == ""
	}
	return !request.Trial && (request.Mode == LicenseModeSerial || request.Mode == LicenseModeLicenseKey) && validSecretReference(request.SecretRef)
}

func validStoredLicense(status LicenseStatus) bool {
	request := LicenseRequest{Mode: status.Mode, SecretRef: status.SecretRef, Trial: status.Mode == LicenseModeTrial}
	return validLicenseRequest(request) && validSHA256(status.ReceiptDigest) && !status.CheckedAt.IsZero()
}

func validLicenseStatus(status LicenseStatus, request EffectRequest, license LicenseRequest) bool {
	if status.Mode != license.Mode || status.SecretRef != license.SecretRef || status.CheckedAt.IsZero() ||
		status.CheckedAt.After(time.Now().UTC().Add(time.Minute)) || status.ReceiptDigest != licenseReceiptDigest(status, request) {
		return false
	}
	switch status.State {
	case webengine.LicenseActive, webengine.LicenseTrial, LicenseUnknown, LicenseGrace, LicenseExpired,
		LicenseRevoked, LicenseInvalid, LicenseOverLimit, LicenseUnavailable:
	default:
		return false
	}
	if status.State == webengine.LicenseActive && status.Mode == LicenseModeTrial ||
		status.State == webengine.LicenseTrial && status.Mode != LicenseModeTrial ||
		status.SerialFingerprint != "" && !validSHA256(status.SerialFingerprint) {
		return false
	}
	return true
}

func licenseReceiptDigest(status LicenseStatus, request EffectRequest) string {
	copy := status
	copy.ReceiptDigest = ""
	return digestJSON(struct {
		Domain  string
		Request EffectRequest
		Status  LicenseStatus
	}{"cyberpanel:webengine-license-receipt:v1", request, copy})
}

func validPHPProfile(profile PHPProfile, plan PHPArtifactPlan) bool {
	if !validProfileID(profile.ID) || !validPHPVersion(profile.Version) || profile.Version != plan.Version ||
		profile.BinaryPathID != plan.BinaryPathID || profile.CatalogDigest != plan.CatalogDigest || profile.CatalogSequence != plan.CatalogSequence ||
		profile.Generation == 0 || !validSHA256(profile.BinaryArtifactDigest) || profile.BinaryArtifactDigest != digestJSON(plan) ||
		!validSHA256(profile.ConfigDigest) || profile.ConfigDigest != phpProfileConfigDigest(profile) ||
		profile.MemoryLimitBytes < 64<<20 || profile.MemoryLimitBytes > 1<<40 ||
		profile.UploadLimitBytes == 0 || profile.UploadLimitBytes > profile.MemoryLimitBytes ||
		profile.BodyLimitBytes < profile.UploadLimitBytes || profile.BodyLimitBytes > profile.MemoryLimitBytes ||
		profile.RequestTimeout < time.Second || profile.RequestTimeout > time.Hour ||
		profile.MaxConnections == 0 || profile.MaxConnections > 100000 ||
		profile.MaxChildren < profile.MaxConnections || profile.MaxChildren > 100000 || profile.Detached {
		return false
	}
	return equalStrings(profile.Extensions, canonicalExtensions(profile.Extensions))
}

func phpProfileConfigDigest(profile PHPProfile) string {
	copy := profile
	copy.ConfigDigest = ""
	copy.BinaryArtifactDigest = ""
	return digestJSON(struct {
		Domain  string
		Profile PHPProfile
	}{"cyberpanel:webengine-php-profile:v1", copy})
}

func validPHPReceipt(receipt EffectReceipt, request EffectRequest, generation uint64) bool {
	return receipt.Outcome == "confirmed" && receipt.EffectID == request.EffectID && receipt.PlanDigest == request.PlanDigest &&
		receipt.Generation == generation && receipt.Fence == request.Fence && validSHA256(receipt.EvidenceDigest) && !receipt.ObservedAt.IsZero()
}

func validPHPRollbackReceipt(receipt EffectReceipt, request EffectRequest, generation uint64) bool {
	return receipt.Outcome == "rolled_back" && receipt.EffectID == request.EffectID && receipt.PlanDigest == request.PlanDigest &&
		receipt.Generation == generation && receipt.Fence == request.Fence && validSHA256(receipt.EvidenceDigest) && !receipt.ObservedAt.IsZero()
}

func validSecretReference(value string) bool {
	return validProfileID(value) && strings.HasPrefix(value, "lse_")
}

func validProfileID(value string) bool {
	if len(value) < 3 || len(value) > 96 {
		return false
	}
	for index, character := range value {
		if index == 0 && (character < 'a' || character > 'z') {
			return false
		}
		if character != '-' && character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validPHPVersion(value string) bool {
	return value == "8.2" || value == "8.3" || value == "8.4"
}

func canonicalExtensions(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil
		}
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] || !validProfileID(left[index]) {
			return false
		}
	}
	return true
}

func (repository *SQLRepository) AdmitManagedEffect(ctx context.Context, operation Operation) (Operation, bool, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validEffectToken(operation.ID) ||
		!validEffectToken(operation.Kind) || !validSHA256(operation.RequestDigest) || operation.ExpectedGeneration == 0 ||
		operation.Installation.Generation != operation.ExpectedGeneration+1 {
		return Operation{}, false, ErrInvalid
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Operation{}, false, err
	}
	defer tx.Rollback()
	var kind, status, digest string
	var expected uint64
	var installationRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT kind,status,request_digest,expected_generation,installation_json FROM webengine_management_operations WHERE id=?`, operation.ID).
		Scan(&kind, &status, &digest, &expected, &installationRaw)
	if err == nil {
		if kind != operation.Kind || digest != operation.RequestDigest || expected != operation.ExpectedGeneration ||
			json.Unmarshal(installationRaw, &operation.Installation) != nil {
			return Operation{}, false, ErrConflict
		}
		operation.Status = status
		return operation, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Operation{}, false, err
	}
	var generation uint64
	if err = tx.QueryRowContext(ctx, `SELECT generation FROM webengine_installation WHERE singleton_id=1`).Scan(&generation); err != nil {
		return Operation{}, false, err
	}
	if generation != operation.ExpectedGeneration {
		return Operation{}, false, ErrConflict
	}
	installationRaw, err = json.Marshal(operation.Installation)
	if err != nil {
		return Operation{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webengine_management_operations(id,kind,status,request_digest,expected_generation,installation_json,receipt_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		operation.ID, operation.Kind, "accepted", operation.RequestDigest, operation.ExpectedGeneration, installationRaw, []byte(`{}`), operation.CreatedAt, operation.UpdatedAt)
	if err != nil {
		return Operation{}, false, err
	}
	return operation, true, tx.Commit()
}

func (repository *SQLRepository) RecordManagedEffect(ctx context.Context, id, status string, receipt any) error {
	if repository == nil || repository.db == nil || ctx == nil || !validEffectToken(id) || status != "ambiguous" && status != "rolled_back" && status != "rejected" {
		return ErrInvalid
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE webengine_management_operations SET status=?,receipt_json=?,updated_at=? WHERE id=? AND status IN ('accepted','ambiguous')`,
		status, receiptRaw, repository.clock().UTC(), id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	return nil
}

func (repository *SQLRepository) CommitManagedLicense(ctx context.Context, id string, installation Installation, status LicenseStatus, expected uint64) error {
	installation.License = status
	return repository.commitManagedProjection(ctx, id, installation, nil, status, expected)
}

func (repository *SQLRepository) CommitManagedPHP(ctx context.Context, id string, installation Installation, profile PHPProfile, receipt any, expected uint64) error {
	return repository.commitManagedProjection(ctx, id, installation, &profile, receipt, expected)
}

func (repository *SQLRepository) commitManagedProjection(ctx context.Context, id string, installation Installation, profile *PHPProfile, receipt any, expected uint64) error {
	if repository == nil || repository.db == nil || ctx == nil || !validEffectToken(id) || installation.ID != "node-webengine" ||
		installation.Generation != expected+1 || installation.UpdatedAt.IsZero() || profile != nil && profile.Generation != installation.Generation {
		return ErrInvalid
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	installationRaw, err := json.Marshal(installation)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE webengine_installation SET generation=?,state=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`,
		installation.Generation, installation.State, installationRaw, repository.clock().UTC(), expected)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	var tuningRaw []byte
	var tuningGeneration uint64
	if err = tx.QueryRowContext(ctx, `SELECT generation,value_json FROM webengine_global_tuning WHERE singleton_id=1`).Scan(&tuningGeneration, &tuningRaw); err != nil {
		return err
	}
	var tuning GlobalTuning
	if tuningGeneration != expected || json.Unmarshal(tuningRaw, &tuning) != nil {
		return ErrConflict
	}
	tuning.Generation = installation.Generation
	tuningRaw, err = json.Marshal(tuning)
	if err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE webengine_global_tuning SET generation=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`,
		tuning.Generation, tuningRaw, repository.clock().UTC(), expected)
	if err != nil {
		return err
	}
	changed, err = result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	if profile != nil {
		profileRaw, encodeErr := json.Marshal(profile)
		if encodeErr != nil {
			return encodeErr
		}
		result, err = tx.ExecContext(ctx, `INSERT INTO webengine_php_profiles(id,generation,value_json,updated_at) VALUES(?,?,?,?)`,
			profile.ID, profile.Generation, profileRaw, repository.clock().UTC())
		if err != nil {
			return errors.Join(ErrConflict, err)
		}
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE webengine_management_operations SET status='applied',installation_json=?,receipt_json=?,updated_at=? WHERE id=? AND expected_generation=? AND status IN ('accepted','ambiguous')`,
		installationRaw, receiptRaw, repository.clock().UTC(), id, expected)
	if err != nil {
		return err
	}
	changed, err = result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	return tx.Commit()
}
