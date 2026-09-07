//go:build linux

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// Operator ceremony (installed binary, local root only):
// cyberpanel migration-key create --key-id migration_2026
// cyberpanel migration-key show --key-id migration_2026
// cyberpanel migration-key rotate --from-key-id migration_2026 --key-id migration_2027
// Rotation creates a distinct key and retains the old key for in-flight work.
// No private-key argument, private-key file, or private-key output is accepted.
func runMigrationKeyCLI(arguments []string, output io.Writer) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || output == nil || len(arguments) == 0 { return errors.New("migration-key requires the local root operator and create, show, or rotate") }
	action := arguments[0]
	if action != "create" && action != "show" && action != "rotate" { return migration.ErrInvalid }
	flags := flag.NewFlagSet("cyberpanel migration-key", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyID := flags.String("key-id", "", "public key identifier")
	fromKeyID := flags.String("from-key-id", "", "existing key identifier retained during rotation")
	if flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 { return migration.ErrInvalid }
	if _, err := secrets.NewID(*keyID); err != nil { return migration.ErrInvalid }
	if action == "rotate" {
		if _, err := secrets.NewID(*fromKeyID); err != nil || *fromKeyID == *keyID { return migration.ErrInvalid }
	} else if *fromKeyID != "" { return migration.ErrInvalid }
	// Pin enrollment to the executable the service actually runs. A copied,
	// locally rebuilt, or caller-selected binary cannot provision a different
	// material consumer under the same command name.
	release, err := webEngineExecutableDigest("/usr/lib/cyberpanel/bin/cyberpanel")
	if err != nil { return err }
	current, err := certificates.CurrentExecutableDigest()
	if err != nil || current != release { return errors.New("run migration-key using the installed panel-core binary") }
	installation, err := migrationKeyInstallation()
	if err != nil { return err }
	material, err := secrets.NewLocalMaterialClient()
	if err != nil { return err }
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if action == "rotate" {
		previous, err := migrationKeyMaterial(ctx, material, installation, *fromKeyID)
		wipeBytes(previous)
		if err != nil { return errors.Join(errors.New("rotation requires an existing readable source key; old keys are retained"), err) }
	}
	private, err := migrationKeyMaterial(ctx, material, installation, *keyID)
	if errors.Is(err, secrets.ErrNotFound) && action != "show" {
		management, clientErr := secrets.NewLocalManagementClient()
		if clientErr != nil { return clientErr }
		private = make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, private); err != nil { wipeBytes(private); return err }
		id := migrationTargetSealingKeyID(installation, *keyID)
		_, putErr := management.PutExact(ctx, secrets.PutRequest{ID: id, OwnerTenantID: secrets.ID("installation"), Purpose: secrets.PurposeFederation,
			Audience: secrets.AudienceBinding{AdapterID: "cyberpanel.migration", AdapterVersion: "1", Account: "migration-sealing",
				Origin: "local://panel-core/migration", ResourceKind: "migration_sealing_key", ResourceID: id, ResourceGeneration: 1,
				Operations: []secrets.Operation{secrets.OperationDecrypt}, ConsumerReleaseDigest: release}, Plaintext: private})
		wipeBytes(private)
		// Recover an uncertain reply or concurrent create by reading only the
		// same protected record. Never retry with another key or overwrite it.
		private, err = migrationKeyMaterial(ctx, material, installation, *keyID)
		if err != nil { wipeBytes(private); return errors.Join(putErr, err) }
	} else if err != nil { wipeBytes(private); return err }
	defer wipeBytes(private)
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil { return migration.ErrInvalid }
	public := hex.EncodeToString(key.PublicKey().Bytes())
	// This is the entire public output contract. It can be copied into source
	// configuration without exposing broker references or private key bytes.
	return json.NewEncoder(output).Encode(struct {
		Schema string `json:"schema"`
		TargetInstallationID string `json:"target_installation_id"`
		TargetSealingKeyID string `json:"target_sealing_key_id"`
		TargetSealingPublicKey string `json:"target_sealing_public_key"`
		RetainedPreviousKeyID string `json:"retained_previous_key_id,omitempty"`
	}{"cyberpanel.migration-target-key/v1", installation, *keyID, public, *fromKeyID})
}

func migrationKeyMaterial(ctx context.Context, client *secrets.MaterialClient, installation, keyID string) ([]byte, error) {
	id := migrationTargetSealingKeyID(installation, keyID)
	response, err := client.Read(ctx, secrets.MaterialRequest{SecretID: id, OwnerTenantID: secrets.ID("installation"), Purpose: secrets.PurposeFederation,
		Operation: secrets.OperationDecrypt, AdapterID: "cyberpanel.migration", AdapterVersion: "1", ResourceID: id})
	if err != nil { wipeBytes(response.Material); return nil, err }
	if response.SecretVersion != 1 || len(response.Material) != 32 { wipeBytes(response.Material); return nil, migration.ErrConflict }
	return response.Material, nil
}

func migrationKeyInstallation() (string, error) {
	const path = "/etc/cyberpanel/migration/trust.json"
	before, err := os.Lstat(path)
	if err != nil { return "", err }
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || before.Mode().Perm()&0o022 != 0 { return "", migration.ErrBlocked }
	raw, err := readCoreFile(path, 1<<20, false)
	if err != nil { return "", err }
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) { return "", migration.ErrConflict }
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || stat.Ctim != afterStat.Ctim { return "", migration.ErrConflict }
	var document struct { TargetInstallationID string `json:"target_installation_id"` }
	if json.Unmarshal(raw, &document) != nil || document.TargetInstallationID == "" || len(document.TargetInstallationID) > 191 { return "", migration.ErrInvalid }
	if _, err := migrationTargetSecretVerifier(); err != nil { return "", err }
	final, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, final) { return "", migration.ErrConflict }
	finalStat, ok := final.Sys().(*syscall.Stat_t)
	if !ok || stat.Ctim != finalStat.Ctim || before.Size() != final.Size() || !before.ModTime().Equal(final.ModTime()) { return "", migration.ErrConflict }
	return document.TargetInstallationID, nil
}
