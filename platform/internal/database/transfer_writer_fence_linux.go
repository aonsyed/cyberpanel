//go:build linux

package database

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type transferFenceAccount struct {
	Principal DatabasePrincipal `json:"principal"`
	GrantSet  GrantSet          `json:"grant_set"`
	Identity  string            `json:"identity"`
	Grants    string            `json:"grants"`
	WasLocked bool              `json:"was_locked"`
}

// A held record is evidence of account admission closure and natural session
// drainage, not native replacement authority. Public replacement stays disabled.
// Grants are captured and never revoked/replaced; ACCOUNT LOCK leaves them intact.
type transferWriterFence struct {
	Restore        *transferReplacementRestorePoint `json:"restore,omitempty"`
	Database       Database                         `json:"database"`
	Token          ResourceID                       `json:"token"`
	NativeIdentity string                           `json:"native_identity"`
	Accounts       []transferFenceAccount           `json:"accounts"`
	State          string                           `json:"state"`
}

func transferFenceJournalLock(database ResourceID) (func(), error) {
	if database.IsZero() {
		return nil, ErrInvalidResource
	}
	root := filepath.Join(mariaDBStateRoot, "transfer-fences")
	if err := ensureRootDirectory(root, 0700); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(root, database.String()+".lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		syscall.Close(fd)
		return nil, ErrConflict
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = syscall.Close(fd) }, nil
}

func observeTransferFenceAccount(ctx context.Context, connection *mariaDBConnection, p DatabasePrincipal) (string, bool, string, error) {
	raw, err := connection.query(ctx, sqlTransferFenceAccount, p)
	if err != nil {
		return "", false, "", err
	}
	fields := strings.Split(strings.TrimSpace(string(raw)), "\t")
	if len(fields) != 2 || !validSHA256(fields[0]) || (fields[1] != "0" && fields[1] != "1") {
		return "", false, "", ErrAmbiguous
	}
	grants, err := connection.query(ctx, sqlTransferFenceGrants, p)
	if err != nil || len(grants) == 0 {
		return "", false, "", ErrAmbiguous
	}
	return fields[0], fields[1] == "1", string(grants), nil
}

// grantIDs identify existing protected registry entries, not tenant-supplied
// account names. Native inventory must prove these are the complete, exclusive
// application accounts for this schema. Timeout leaves an acquiring journal and
// admission closed until explicit release; a retry cannot silently acquire it.
func (executor *LinuxMariaDBExecutor) acquireTransferWriterFence(ctx context.Context, database Database, token ResourceID, grantIDs []ResourceID, drain time.Duration) (transferWriterFence, error) {
	var record transferWriterFence
	if executor == nil || ctx == nil || os.Geteuid() != 0 || database.Validate() != nil || token.IsZero() || len(grantIDs) == 0 || len(grantIDs) > 64 || drain <= 0 || drain > time.Minute {
		return record, ErrUnauthorized
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	admit, err := transferFenceAdmissionLock(true)
	if err != nil {
		return record, err
	}
	defer admit()
	ctx = context.WithValue(ctx, transferFenceMutationAuthority{}, true)
	unlock, err := transferFenceJournalLock(database.ID)
	if err != nil {
		return record, err
	}
	defer unlock()
	if err = executor.readResource("transfer-fences", database.ID, &record); err == nil {
		// Retained restore points are recovery anchors, not reusable lock slots.
		// An explicit retention lifecycle must retire them before another import.
		if record.Database.ID != database.ID || record.State != "released" || record.Token == token || record.Restore != nil {
			return record, ErrConflict
		}
	} else if !errors.Is(err, ErrNotFound) {
		return record, err
	}
	var stored Database
	if err = executor.readResource("databases", database.ID, &stored); err != nil || stored != database {
		return record, ErrUnauthorized
	}
	instance, err := executor.instance(database.InstanceID)
	if err != nil || instance.Placement != PlacementLocal {
		return record, ErrUnauthorized
	}
	ctx, release, err := executor.beginWriterMutation(ctx)
	if err != nil {
		return record, err
	}
	defer release()
	connection, closeConnection, err := executor.connection(ctx, instance)
	if err != nil {
		return record, err
	}
	defer closeConnection()
	observed, err := connection.query(ctx, sqlObserveDatabase, database)
	if err != nil || strings.TrimSpace(string(observed)) == "" {
		return record, ErrNotFound
	}
	record = transferWriterFence{Database: database, Token: token, State: "acquiring"}
	seen := map[string]bool{}
	for _, id := range grantIDs {
		var g GrantSet
		var p DatabasePrincipal
		if err = executor.readResource("grants", id, &g); err != nil || g.Validate() != nil || g.ID != id || g.DatabaseID != database.ID || g.InstanceID != database.InstanceID || g.TenantID != database.TenantID || g.SiteID != database.SiteID {
			return record, ErrUnauthorized
		}
		if err = executor.readResource("principals", g.PrincipalID, &p); err != nil || p.Validate() != nil || p.ID != g.PrincipalID || p.InstanceID != database.InstanceID || p.TenantID != database.TenantID || p.SiteID != database.SiteID || p.HostScope != HostScopeLoopback || seen[p.Name.String()] {
			return record, ErrUnauthorized
		}
		if p.Name.String() == "root" || p.Name.String() == "mysql" || p.Name.String() == "mariadb.sys" {
			return record, ErrUnauthorized
		}
		seen[p.Name.String()] = true
		identity, locked, grants, err := observeTransferFenceAccount(ctx, connection, p)
		if err != nil {
			return record, err
		}
		record.Accounts = append(record.Accounts, transferFenceAccount{p, g, identity, grants, locked})
	}
	identity, err := connection.query(ctx, sqlTransferFenceIdentity)
	if err != nil {
		return record, err
	}
	record.NativeIdentity = strings.TrimSpace(string(identity))
	if !validSHA256(record.NativeIdentity) {
		return record, ErrAmbiguous
	}
	if err = verifyTransferFenceScope(ctx, connection, record); err != nil {
		return record, err
	}
	// Before the first native change: complete original account/grant state.
	if err = executor.writeResource("transfer-fences", database.ID, record); err != nil {
		return record, err
	}
	for _, account := range record.Accounts {
		if _, err = connection.query(ctx, sqlTransferFenceLock, account.Principal); err != nil {
			return record, ErrAmbiguous
		}
	}
	bounded, cancel := context.WithTimeout(ctx, drain)
	defer cancel()
	for {
		drained := true
		for _, account := range record.Accounts {
			identity, locked, grants, err := observeTransferFenceAccount(bounded, connection, account.Principal)
			if err != nil || identity != account.Identity || !locked || grants != account.Grants {
				return record, ErrAmbiguous
			}
			count, err := connection.query(bounded, sqlTransferFenceSessions, account.Principal)
			if err != nil {
				return record, ErrAmbiguous
			}
			if strings.TrimSpace(string(count)) != "0" {
				drained = false
			}
		}
		if drained {
			break
		}
		select {
		case <-bounded.Done():
			return record, bounded.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	if err = verifyTransferFenceScope(ctx, connection, record); err != nil {
		return record, ErrAmbiguous
	}
	record.State = "held"
	if err = executor.writeResource("transfer-fences", database.ID, record); err != nil {
		return record, ErrAmbiguous
	}
	return record, nil
}

func verifyTransferFenceScope(ctx context.Context, connection *mariaDBConnection, record transferWriterFence) error {
	replication, err := connection.query(ctx, sqlTransferFenceReplication)
	if err != nil || strings.TrimSpace(string(replication)) != "" {
		return ErrUnauthorized
	}
	identity, err := connection.query(ctx, sqlTransferFenceIdentity)
	if err != nil || strings.TrimSpace(string(identity)) != record.NativeIdentity {
		return ErrAmbiguous
	}
	count, err := connection.query(ctx, sqlTransferFenceAudit, transferFenceScope{record.Database, record.Accounts})
	if err != nil || strings.TrimSpace(string(count)) != "0" {
		return ErrUnauthorized
	}
	return nil
}

// Release/recovery never drops schemas, changes grants, or promotes imports.
// An acquiring record may represent zero, some or all accounts locked. Replaying
// their exact original lock states is safe; changed credentials/grants fail closed.
func (executor *LinuxMariaDBExecutor) releaseTransferWriterFence(ctx context.Context, databaseID, token ResourceID) error {
	if executor == nil || ctx == nil || os.Geteuid() != 0 || token.IsZero() {
		return ErrUnauthorized
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	admit, err := transferFenceAdmissionLock(true)
	if err != nil {
		return err
	}
	defer admit()
	ctx = context.WithValue(ctx, transferFenceMutationAuthority{}, true)
	unlock, err := transferFenceJournalLock(databaseID)
	if err != nil {
		return err
	}
	defer unlock()
	return executor.releaseTransferWriterFenceLocked(ctx, databaseID, token)
}

func (executor *LinuxMariaDBExecutor) releaseTransferWriterFenceLocked(ctx context.Context, databaseID, token ResourceID) error {
	var record transferWriterFence
	if err := executor.readResource("transfer-fences", databaseID, &record); err != nil {
		return err
	}
	if record.Database.Validate() != nil || record.Database.ID != databaseID || record.Token != token || len(record.Accounts) == 0 || len(record.Accounts) > 64 {
		return ErrUnauthorized
	}
	if record.State != "acquiring" && record.State != "held" && record.State != "releasing" && record.State != "released" {
		return ErrAmbiguous
	}
	if record.Restore != nil && !record.Restore.ImportID.IsZero() {
		var imp isolatedTransferRecord
		if err := executor.readResource("transfer-imports", record.Restore.ImportID, &imp); err == nil {
			if imp.Job.Digest != record.Restore.JobDigest {
				return ErrAmbiguous
			}
			switch imp.State {
			case "creating", "allocated", "loading", "closed", "verified", "promotion-verified", "promoted", "replacement-rolled-back":
			default:
				return ErrAmbiguous
			}
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	instance, err := executor.instance(record.Database.InstanceID)
	if err != nil || instance.Placement != PlacementLocal {
		return ErrUnauthorized
	}
	connection, closeConnection, err := executor.connection(ctx, instance)
	if err != nil {
		return err
	}
	defer closeConnection()
	if err = verifyTransferFenceScope(ctx, connection, record); err != nil {
		return err
	}
	for _, account := range record.Accounts {
		var current DatabasePrincipal
		if err = executor.readResource("principals", account.Principal.ID, &current); err != nil || current != account.Principal {
			return ErrAmbiguous
		}
		var grantsRecord GrantSet
		if err = executor.readResource("grants", account.GrantSet.ID, &grantsRecord); err != nil || !sameWriterValue(grantsRecord, account.GrantSet) {
			return ErrAmbiguous
		}
		identity, locked, grants, err := observeTransferFenceAccount(ctx, connection, account.Principal)
		if err != nil || identity != account.Identity || grants != account.Grants {
			return ErrAmbiguous
		}
		if record.State == "released" && locked != account.WasLocked {
			return ErrAmbiguous
		}
	}
	if record.State == "released" {
		return nil
	}
	record.State = "releasing"
	if err = executor.writeResource("transfer-fences", databaseID, record); err != nil {
		return err
	}
	for _, account := range record.Accounts {
		statement := sqlTransferFenceUnlock
		if account.WasLocked {
			statement = sqlTransferFenceLock
		}
		if _, err = connection.query(ctx, statement, account.Principal); err != nil {
			return ErrAmbiguous
		}
		identity, locked, grants, err := observeTransferFenceAccount(ctx, connection, account.Principal)
		if err != nil || identity != account.Identity || locked != account.WasLocked || grants != account.Grants {
			return ErrAmbiguous
		}
	}
	record.State = "released"
	return executor.writeResource("transfer-fences", databaseID, record)
}
