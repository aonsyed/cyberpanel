package dns

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// PowerDNSDatabasePurpose identifies the only database role accepted by the
// authoritative PowerDNS store. It is deliberately distinct from the control
// database role so a raw control-plane handle cannot be supplied by accident.
type PowerDNSDatabasePurpose string

const PowerDNSAuthoritativePurpose PowerDNSDatabasePurpose = "powerdns_authoritative"

var (
	ErrPowerDNSDatabaseIsolation       = errors.New("PowerDNS authoritative database is not isolated from the control database")
	ErrPowerDNSAuthoritativeCredential = errors.New("PowerDNS authoritative database credential is unavailable")
	ErrPowerDNSDatabaseOpen            = errors.New("PowerDNS authoritative database could not be opened")
)

// PowerDNSAuthoritativeDatabaseIdentity describes the dedicated PowerDNS
// authoritative database without containing its credential. Fingerprint must
// identify the database target, rather than the credential used to reach it.
type PowerDNSAuthoritativeDatabaseIdentity struct {
	Purpose       PowerDNSDatabasePurpose `json:"purpose"`
	Fingerprint   string                  `json:"fingerprint"`
	CredentialRef string                  `json:"credential_ref"`
}

// Validate rejects an identity unless it is explicitly purpose-bound to the
// authoritative PowerDNS database and distinct from the control database.
func (identity PowerDNSAuthoritativeDatabaseIdentity) Validate(controlDatabaseFingerprint string) error {
	if identity.Purpose != PowerDNSAuthoritativePurpose ||
		!validPowerDNSFingerprint(identity.Fingerprint) ||
		!validPowerDNSIdentityValue(identity.CredentialRef, 2048) ||
		!validPowerDNSFingerprint(controlDatabaseFingerprint) {
		return ErrPowerDNSDatabaseIsolation
	}
	if strings.EqualFold(identity.Fingerprint, controlDatabaseFingerprint) {
		return ErrPowerDNSDatabaseIsolation
	}
	return nil
}

// PowerDNSAuthoritativeCredentialResolver returns caller-owned credential
// bytes for the dedicated authoritative database. Implementations must not log
// the material and must return a fresh buffer because the factory wipes it.
type PowerDNSAuthoritativeCredentialResolver interface {
	ResolvePowerDNSAuthoritativeCredential(context.Context, PowerDNSAuthoritativeDatabaseIdentity) ([]byte, error)
}

// PowerDNSAuthoritativeDatabaseOpener consumes the purpose-bound identity and
// credential. It must not retain or expose the credential outside the driver
// connection state.
type PowerDNSAuthoritativeDatabaseOpener interface {
	OpenPowerDNSAuthoritativeDatabase(context.Context, PowerDNSAuthoritativeDatabaseIdentity, []byte) (PowerDNSOpenedDatabase, error)
}

type PowerDNSOpenedDatabase struct {
	Database *sql.DB
	ObservedFingerprint string
}

type PowerDNSConnectorResolver interface {
	ResolvePowerDNSConnector(context.Context, PowerDNSAuthoritativeDatabaseIdentity, []byte) (driver.Connector, string, error)
}

type SQLPowerDNSDatabaseOpener struct {
	Connectors PowerDNSConnectorResolver
	MaximumOpenConnections int
	MaximumIdleConnections int
	ConnectionMaximumLifetime time.Duration
}

func (opener SQLPowerDNSDatabaseOpener) OpenPowerDNSAuthoritativeDatabase(ctx context.Context, identity PowerDNSAuthoritativeDatabaseIdentity, credential []byte) (PowerDNSOpenedDatabase, error) {
	if ctx == nil || opener.Connectors == nil || len(credential) == 0 || identity.Purpose != PowerDNSAuthoritativePurpose {
		return PowerDNSOpenedDatabase{}, ErrPowerDNSDatabaseOpen
	}
	connector, observedFingerprint, err := opener.Connectors.ResolvePowerDNSConnector(ctx, identity, credential)
	if err != nil || connector == nil || observedFingerprint != identity.Fingerprint {
		if err == nil && observedFingerprint != identity.Fingerprint {
			return PowerDNSOpenedDatabase{}, ErrPowerDNSDatabaseIsolation
		}
		return PowerDNSOpenedDatabase{}, ErrPowerDNSDatabaseOpen
	}
	database := sql.OpenDB(connector)
	maximumOpen := opener.MaximumOpenConnections
	if maximumOpen < 1 {
		maximumOpen = 32
	}
	if maximumOpen > 256 {
		maximumOpen = 256
	}
	maximumIdle := opener.MaximumIdleConnections
	if maximumIdle < 0 {
		maximumIdle = 0
	}
	if maximumIdle == 0 || maximumIdle > maximumOpen {
		maximumIdle = maximumOpen / 4
	}
	lifetime := opener.ConnectionMaximumLifetime
	if lifetime <= 0 || lifetime > 24*time.Hour {
		lifetime = 30 * time.Minute
	}
	database.SetMaxOpenConns(maximumOpen)
	database.SetMaxIdleConns(maximumIdle)
	database.SetConnMaxLifetime(lifetime)
	database.SetConnMaxIdleTime(5 * time.Minute)
	if err = database.PingContext(ctx); err != nil {
		_ = database.Close()
		return PowerDNSOpenedDatabase{}, ErrPowerDNSDatabaseOpen
	}
	return PowerDNSOpenedDatabase{Database: database, ObservedFingerprint: observedFingerprint}, nil
}

// PowerDNSAuthoritativeDatabase is an opaque, validated handle. Its sql.DB is
// intentionally not exposed, preventing consumers from substituting a raw
// control database after construction.
type PowerDNSAuthoritativeDatabase struct {
	database                   *sql.DB
	identity                   PowerDNSAuthoritativeDatabaseIdentity
	controlDatabaseFingerprint string
}

func newPowerDNSAuthoritativeDatabase(database *sql.DB, identity PowerDNSAuthoritativeDatabaseIdentity, controlDatabaseFingerprint string) (PowerDNSAuthoritativeDatabase, error) {
	if database == nil {
		return PowerDNSAuthoritativeDatabase{}, ErrPowerDNSDatabaseOpen
	}
	if err := identity.Validate(controlDatabaseFingerprint); err != nil {
		return PowerDNSAuthoritativeDatabase{}, err
	}
	return PowerDNSAuthoritativeDatabase{
		database:                   database,
		identity:                   identity,
		controlDatabaseFingerprint: controlDatabaseFingerprint,
	}, nil
}

// Identity returns only the non-secret identity attached to the handle.
func (database PowerDNSAuthoritativeDatabase) Identity() PowerDNSAuthoritativeDatabaseIdentity {
	return database.identity
}

// Close releases the dedicated database handle.
func (database PowerDNSAuthoritativeDatabase) Close() error {
	if database.database == nil {
		return nil
	}
	return database.database.Close()
}

func (database PowerDNSAuthoritativeDatabase) valid() bool {
	return database.database != nil && database.identity.Validate(database.controlDatabaseFingerprint) == nil
}

// PowerDNSAuthoritativeDatabaseFactory resolves the database credential and
// opens a validated, purpose-bound authoritative handle.
type PowerDNSAuthoritativeDatabaseFactory struct {
	ControlDatabaseFingerprint string
	Credentials                PowerDNSAuthoritativeCredentialResolver
	Opener                     PowerDNSAuthoritativeDatabaseOpener
}

func (factory PowerDNSAuthoritativeDatabaseFactory) Open(ctx context.Context, identity PowerDNSAuthoritativeDatabaseIdentity) (PowerDNSAuthoritativeDatabase, error) {
	database, err := factory.open(ctx, identity)
	if err != nil {
		return PowerDNSAuthoritativeDatabase{}, err
	}
	if _, err = database.VerifySchema(ctx); err != nil {
		_ = database.Close()
		return PowerDNSAuthoritativeDatabase{}, err
	}
	return database, nil
}

func (factory PowerDNSAuthoritativeDatabaseFactory) Bootstrap(ctx context.Context, identity PowerDNSAuthoritativeDatabaseIdentity) (PowerDNSSchemaReceipt, error) {
	database, err := factory.open(ctx, identity)
	if err != nil {
		return PowerDNSSchemaReceipt{}, err
	}
	defer database.Close()
	receipt, err := database.Bootstrap(ctx)
	if err != nil {
		return receipt, err
	}
	return receipt, nil
}

func (factory PowerDNSAuthoritativeDatabaseFactory) open(ctx context.Context, identity PowerDNSAuthoritativeDatabaseIdentity) (PowerDNSAuthoritativeDatabase, error) {
	if ctx == nil {
		return PowerDNSAuthoritativeDatabase{}, ErrPowerDNSDatabaseOpen
	}
	if err := identity.Validate(factory.ControlDatabaseFingerprint); err != nil {
		return PowerDNSAuthoritativeDatabase{}, err
	}
	if factory.Credentials == nil {
		return PowerDNSAuthoritativeDatabase{}, ErrPowerDNSAuthoritativeCredential
	}
	if factory.Opener == nil {
		return PowerDNSAuthoritativeDatabase{}, ErrPowerDNSDatabaseOpen
	}

	credential, err := factory.Credentials.ResolvePowerDNSAuthoritativeCredential(ctx, identity)
	if err != nil || len(credential) == 0 || len(credential) > 1<<20 {
		wipePowerDNSSecret(credential)
		return PowerDNSAuthoritativeDatabase{}, ErrPowerDNSAuthoritativeCredential
	}
	defer wipePowerDNSSecret(credential)

	opened, err := factory.Opener.OpenPowerDNSAuthoritativeDatabase(ctx, identity, credential)
	if err != nil || opened.Database == nil || opened.ObservedFingerprint != identity.Fingerprint {
		if opened.Database != nil {
			_ = opened.Database.Close()
		}
		if err == nil && opened.ObservedFingerprint != identity.Fingerprint {
			return PowerDNSAuthoritativeDatabase{}, ErrPowerDNSDatabaseIsolation
		}
		return PowerDNSAuthoritativeDatabase{}, ErrPowerDNSDatabaseOpen
	}

	database, err := newPowerDNSAuthoritativeDatabase(opened.Database, identity, factory.ControlDatabaseFingerprint)
	if err != nil {
		_ = opened.Database.Close()
		return PowerDNSAuthoritativeDatabase{}, err
	}
	return database, nil
}

func validPowerDNSIdentityValue(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validPowerDNSFingerprint(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func wipePowerDNSSecret(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}

var _ PowerDNSAuthoritativeDatabaseOpener = SQLPowerDNSDatabaseOpener{}
