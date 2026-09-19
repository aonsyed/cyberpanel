//go:build linux

package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
)

const MailBrokerMigrationPublication MailBrokerOperation = "migration_publication"

type mailPublicationJournal struct {
	Version             uint8     `json:"version"`
	ImportID            string    `json:"import_id"`
	BindingDigest       string    `json:"binding_digest"`
	ConfigurationDigest string    `json:"configuration_digest"`
	StorageDigest       string    `json:"storage_digest"`
	GenerationID        string    `json:"generation_id"`
	PreviousGeneration  string    `json:"previous_generation,omitempty"`
	ValidationDigest    string    `json:"validation_digest"`
	SourceFenceDigest   string    `json:"source_fence_digest,omitempty"`
	MaildirDigest       string    `json:"maildir_digest,omitempty"`
	ActivationDigest    string    `json:"activation_digest,omitempty"`
	ServiceDigest       string    `json:"service_digest,omitempty"`
	State               string    `json:"state"`
	PostfixWasActive    bool      `json:"postfix_was_active"`
	DovecotWasActive    bool      `json:"dovecot_was_active"`
	RolledBack          bool      `json:"rolled_back,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func (request MailPublicationRequest) Validate() error {
	if request.Operation != "stage" && request.Operation != "activate" && request.Operation != "observe" && request.Operation != "cancel" {
		return ErrInvalidCommand
	}
	if request.Operation == "activate" {
		if !validMailEvidenceDigest(request.SourceFenceDigest) {
			return ErrInvalidCommand
		}
	} else if request.SourceFenceDigest != "" {
		return ErrInvalidCommand
	}
	return validateMigrationPublication(request.Bundle, request.Generation)
}

func (receipt MailPublicationReceipt) valid(request MailPublicationRequest) bool {
	if receipt.ImportID != request.Bundle.ID || receipt.ConfigurationDigest != request.Generation.Digest || !validMailEvidenceDigest(receipt.StorageDigest) || !validMailGenerationID(receipt.GenerationID) || !validMailEvidenceDigest(receipt.ValidationDigest) || !validMailEvidenceDigest(receipt.EvidenceDigest) || receipt.ObservedAt.IsZero() {
		return false
	}
	if receipt.PreviousGeneration != "" && !validMailGenerationID(receipt.PreviousGeneration) {
		return false
	}
	for _, digest := range []string{receipt.ActivationDigest, receipt.MaildirDigest, receipt.ServiceDigest} {
		if digest != "" && !validMailEvidenceDigest(digest) {
			return false
		}
	}
	switch receipt.State {
	case "dark":
		return !receipt.ServicesStopped
	case "active":
		return !receipt.ServicesStopped && receipt.ActivationDigest != "" && receipt.MaildirDigest != "" && receipt.ServiceDigest != ""
	case "stopped":
		return receipt.ServicesStopped
	case "canceled":
		return !receipt.ServicesStopped
	default:
		return false
	}
}

func validateMigrationPublication(bundle MigrationBundle, generation ConfigGeneration) error {
	if !validOpaque(bundle.ID) || !bundle.Domain.Domain.StaticRoutes || bundle.Domain.Domain.Tenant == "" || len(bundle.Maildirs) != len(bundle.Domain.Mailboxes) || len(bundle.Maildirs) > 10000 {
		return ErrInvalidCommand
	}
	canonical, err := (ConfigRenderer{}).Render(generation.Snapshot)
	if err != nil || !equalMailGenerations(canonical, generation) {
		return errors.Join(ErrInvalidCommand, err)
	}
	wanted, err := json.Marshal(bundle.Domain)
	if err != nil || len(wanted) > 1<<20 {
		return ErrInvalidCommand
	}
	matched := 0
	for _, projection := range generation.Snapshot.Domains {
		raw, marshalErr := json.Marshal(projection)
		if marshalErr == nil && bytes.Equal(raw, wanted) {
			matched++
		}
	}
	if matched != 1 {
		return ErrConflict
	}
	mailboxes := make(map[MailboxID]Mailbox, len(bundle.Domain.Mailboxes))
	for _, mailbox := range bundle.Domain.Mailboxes {
		if mailbox.ID == "" || mailbox.Domain != bundle.Domain.Domain.ID || mailbox.SiteID == "" || !mailbox.Enabled || mailbox.CredentialRef == "" {
			return ErrInvalidCommand
		}
		mailboxes[mailbox.ID] = mailbox
	}
	seen := make(map[MailboxID]bool, len(bundle.Maildirs))
	for _, request := range bundle.Maildirs {
		if request.Operation != "observe" || len(request.Archive) != 0 || request.Validate() != nil || request.ImportID != bundle.ID || request.TenantID != bundle.Domain.Domain.Tenant || request.DomainID != bundle.Domain.Domain.ID || request.Domain != bundle.Domain.Domain.Name || seen[request.MailboxID] {
			return ErrInvalidCommand
		}
		mailbox, ok := mailboxes[request.MailboxID]
		if !ok || mailbox.Local != request.Local || mailbox.SiteID != request.SiteID {
			return ErrConflict
		}
		seen[request.MailboxID] = true
	}
	for _, alias := range bundle.Domain.Aliases {
		if alias.Capability != "" || alias.PipeRef != "" {
			return ErrInvalidCommand
		}
	}
	return nil
}

func (client *MailDaemonClient) PublishMigration(ctx context.Context, request MailPublicationRequest) (MailPublicationReceipt, error) {
	response, err := client.request(ctx, MailBrokerRequest{Operation: MailBrokerMigrationPublication, Publication: &request})
	if response.Publication == nil {
		return MailPublicationReceipt{}, errors.Join(ErrInvalidReceipt, err)
	}
	return *response.Publication, err
}

func (host *LinuxMailHost) StageMigrationPublication(ctx context.Context, bundle MigrationBundle, generation ConfigGeneration) (MailPublicationReceipt, error) {
	if ctx == nil || validateMigrationPublication(bundle, generation) != nil {
		return MailPublicationReceipt{}, ErrInvalidCommand
	}
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	return host.stageMigrationPublicationLocked(ctx, bundle, generation)
}

func (host *LinuxMailHost) stageMigrationPublicationLocked(ctx context.Context, bundle MigrationBundle, generation ConfigGeneration) (MailPublicationReceipt, error) {
	journal, found, err := host.loadMailPublication(bundle, generation)
	if err != nil {
		return MailPublicationReceipt{}, err
	}
	if found {
		return host.observeMailPublicationLocked(ctx, bundle, generation, journal)
	}
	if err = host.requireMigrationDomainAbsent(bundle.Domain.Domain.Name); err != nil {
		return MailPublicationReceipt{}, err
	}
	mailEvidence := make([]string, 0, len(bundle.Maildirs))
	for _, request := range bundle.Maildirs {
		observed, observeErr := host.inspectMigrationMaildir(ctx, request, false)
		if observeErr != nil {
			return MailPublicationReceipt{}, observeErr
		}
		mailEvidence = append(mailEvidence, observed.EvidenceDigest)
	}
	sort.Strings(mailEvidence)
	storageDigest, generationID, previous, validation, err := host.stageMigrationCandidateLocked(ctx, generation)
	if err != nil {
		return MailPublicationReceipt{}, err
	}
	journal = mailPublicationJournal{Version: 1, ImportID: bundle.ID, BindingDigest: mailPublicationBinding(bundle, generation), ConfigurationDigest: generation.Digest, StorageDigest: storageDigest, GenerationID: generationID, PreviousGeneration: previous, ValidationDigest: validation, MaildirDigest: digestMailEvidence(mailEvidence...), State: "prepared", UpdatedAt: host.now()}
	if err = host.saveMailPublication(journal); err != nil {
		return MailPublicationReceipt{}, err
	}
	return mailPublicationReceipt(journal, "dark", false), nil
}

func (host *LinuxMailHost) ActivateMigrationPublication(ctx context.Context, bundle MigrationBundle, generation ConfigGeneration, sourceFenceDigest string) (MailPublicationReceipt, error) {
	if ctx == nil || !validMailEvidenceDigest(sourceFenceDigest) || validateMigrationPublication(bundle, generation) != nil {
		return MailPublicationReceipt{}, ErrInvalidCommand
	}
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	journal, found, err := host.loadMailPublication(bundle, generation)
	if err != nil || !found {
		return MailPublicationReceipt{}, errors.Join(ErrNotFound, err)
	}
	if journal.State == "active" {
		return host.observeMailPublicationLocked(ctx, bundle, generation, journal)
	}
	if journal.State == "canceled" {
		return mailPublicationReceipt(journal, "canceled", false), ErrConflict
	}
	if journal.State != "prepared" && journal.State != "maintenance" && journal.State != "maildirs" && journal.State != "published" && journal.State != "stopped" {
		return MailPublicationReceipt{}, ErrAmbiguous
	}
	journal.SourceFenceDigest = sourceFenceDigest
	journal.RolledBack = false
	if journal.State == "prepared" {
		postfix, postfixErr := host.controlService(ctx, ServicePostfix, ServiceProbe)
		dovecot, dovecotErr := host.controlService(ctx, ServiceDovecot, ServiceProbe)
		if postfixErr != nil || dovecotErr != nil || !postfix.Active || !dovecot.Active {
			return MailPublicationReceipt{}, errors.Join(ErrBlocked, postfixErr, dovecotErr)
		}
		journal.PostfixWasActive, journal.DovecotWasActive = true, true
		for _, request := range bundle.Maildirs {
			if _, err = host.inspectMigrationMaildir(ctx, request, false); err != nil {
				return MailPublicationReceipt{}, err
			}
		}
		if validation, validateErr := host.validateMigrationGeneration(ctx, journal.GenerationID); validateErr != nil || validation != journal.ValidationDigest {
			return MailPublicationReceipt{}, errors.Join(ErrConflict, validateErr)
		}
		journal.State = "maintenance"
		journal.UpdatedAt = host.now()
		if err = host.saveMailPublication(journal); err != nil {
			return MailPublicationReceipt{}, err
		}
		if _, err = host.controlService(ctx, ServicePostfix, ServiceStop); err == nil {
			_, err = host.controlService(ctx, ServiceDovecot, ServiceStop)
		}
		if err != nil {
			return host.rollbackMailPublication(ctx, bundle, generation, journal, err)
		}
	} else {
		// A replay owns a durable maintenance marker. Stop both processes before
		// inspecting any possibly-partial filesystem publication.
		_, postfixErr := host.controlService(ctx, ServicePostfix, ServiceStop)
		_, dovecotErr := host.controlService(ctx, ServiceDovecot, ServiceStop)
		if postfixErr != nil || dovecotErr != nil {
			journal.State = "stopped"
			journal.UpdatedAt = host.now()
			_ = host.saveMailPublication(journal)
			return mailPublicationReceipt(journal, "stopped", true), errors.Join(ErrAmbiguous, postfixErr, dovecotErr)
		}
	}
	maildirDigest, publishErr := host.publishMigrationMaildirs(ctx, bundle)
	if publishErr != nil {
		return host.rollbackMailPublication(ctx, bundle, generation, journal, publishErr)
	}
	journal.MaildirDigest = maildirDigest
	journal.State = "maildirs"
	journal.UpdatedAt = host.now()
	if err = host.saveMailPublication(journal); err != nil {
		return host.stopAmbiguousMailPublication(ctx, journal, err)
	}
	current, err := host.Store.Current()
	if err != nil {
		return host.stopAmbiguousMailPublication(ctx, journal, err)
	}
	if current != journal.GenerationID {
		if current != journal.PreviousGeneration {
			return host.stopAmbiguousMailPublication(ctx, journal, ErrConflict)
		}
		previous, activateErr := host.Store.Activate(ctx, journal.GenerationID)
		if activateErr != nil || previous != journal.PreviousGeneration {
			return host.rollbackMailPublication(ctx, bundle, generation, journal, errors.Join(activateErr, ErrConflict))
		}
		journal.ActivationDigest = digestMailEvidence(journal.GenerationID, previous)
	} else if journal.ActivationDigest == "" {
		journal.ActivationDigest = digestMailEvidence("reconciled", journal.GenerationID, journal.PreviousGeneration)
	}
	journal.State = "published"
	journal.UpdatedAt = host.now()
	if err = host.saveMailPublication(journal); err != nil {
		return host.stopAmbiguousMailPublication(ctx, journal, err)
	}
	if validation, validateErr := host.validateMigrationGeneration(ctx, journal.GenerationID); validateErr != nil || validation != journal.ValidationDigest {
		return host.rollbackMailPublication(ctx, bundle, generation, journal, errors.Join(ErrConflict, validateErr))
	}
	// Any start attempt can expose a partial publication. From this point on,
	// failures are stopped and reconciled; they are never guessed backward.
	dovecot, dovecotErr := host.controlService(ctx, ServiceDovecot, ServiceStart)
	postfix, postfixErr := MailServiceReceipt{}, error(nil)
	if dovecotErr == nil {
		postfix, postfixErr = host.controlService(ctx, ServicePostfix, ServiceStart)
	}
	journal.ServiceDigest = digestMailEvidence(dovecot.EvidenceDigest, postfix.EvidenceDigest, errorText(dovecotErr), errorText(postfixErr))
	if dovecotErr != nil || postfixErr != nil || !dovecot.Active || !postfix.Active {
		return host.stopAmbiguousMailPublication(ctx, journal, errors.Join(dovecotErr, postfixErr, ErrAmbiguous))
	}
	journal.State = "active"
	journal.UpdatedAt = host.now()
	if err = host.saveMailPublication(journal); err != nil {
		return host.stopAmbiguousMailPublication(ctx, journal, err)
	}
	return host.observeMailPublicationLocked(ctx, bundle, generation, journal)
}

func (host *LinuxMailHost) ObserveMigrationPublication(ctx context.Context, bundle MigrationBundle, generation ConfigGeneration) (MailPublicationReceipt, error) {
	if ctx == nil || validateMigrationPublication(bundle, generation) != nil {
		return MailPublicationReceipt{}, ErrInvalidCommand
	}
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	journal, found, err := host.loadMailPublication(bundle, generation)
	if err != nil || !found {
		return MailPublicationReceipt{}, errors.Join(ErrNotFound, err)
	}
	return host.observeMailPublicationLocked(ctx, bundle, generation, journal)
}

func (host *LinuxMailHost) CancelMigrationPublication(ctx context.Context, bundle MigrationBundle, generation ConfigGeneration) (MailPublicationReceipt, error) {
	if ctx == nil || validateMigrationPublication(bundle, generation) != nil {
		return MailPublicationReceipt{}, ErrInvalidCommand
	}
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	journal, found, err := host.loadMailPublication(bundle, generation)
	if err != nil || !found {
		return MailPublicationReceipt{}, errors.Join(ErrNotFound, err)
	}
	if journal.State == "canceled" {
		return mailPublicationReceipt(journal, "canceled", false), nil
	}
	if journal.State != "prepared" {
		return MailPublicationReceipt{}, ErrAmbiguous
	}
	if err = host.requireMigrationDomainAbsent(bundle.Domain.Domain.Name); err != nil {
		return MailPublicationReceipt{}, err
	}
	for _, request := range bundle.Maildirs {
		if _, err = host.inspectMigrationMaildir(ctx, request, false); err != nil {
			return MailPublicationReceipt{}, err
		}
	}
	journal.State = "canceled"
	journal.UpdatedAt = host.now()
	if err = host.saveMailPublication(journal); err != nil {
		return MailPublicationReceipt{}, err
	}
	return mailPublicationReceipt(journal, "canceled", false), nil
}

func (host *LinuxMailHost) observeMailPublicationLocked(ctx context.Context, bundle MigrationBundle, generation ConfigGeneration, journal mailPublicationJournal) (MailPublicationReceipt, error) {
	if journal.State == "canceled" {
		return mailPublicationReceipt(journal, "canceled", false), nil
	}
	if journal.State == "prepared" {
		if err := host.requireMigrationDomainAbsent(bundle.Domain.Domain.Name); err != nil {
			return MailPublicationReceipt{}, err
		}
		for _, request := range bundle.Maildirs {
			if _, err := host.inspectMigrationMaildir(ctx, request, false); err != nil {
				return MailPublicationReceipt{}, err
			}
		}
		return mailPublicationReceipt(journal, "dark", false), nil
	}
	if journal.State != "active" {
		_, _ = host.controlService(ctx, ServicePostfix, ServiceStop)
		_, _ = host.controlService(ctx, ServiceDovecot, ServiceStop)
		return mailPublicationReceipt(journal, "stopped", true), ErrAmbiguous
	}
	current, err := host.Store.Current()
	if err != nil || current != journal.GenerationID {
		return mailPublicationReceipt(journal, "stopped", true), errors.Join(ErrAmbiguous, err)
	}
	proofs := make([]string, 0, len(bundle.Maildirs))
	for _, request := range bundle.Maildirs {
		observed, observeErr := host.inspectMigrationMaildir(ctx, request, true)
		if observeErr != nil {
			return mailPublicationReceipt(journal, "stopped", true), errors.Join(ErrAmbiguous, observeErr)
		}
		proofs = append(proofs, observed.EvidenceDigest)
	}
	sort.Strings(proofs)
	if digestMailEvidence(proofs...) != journal.MaildirDigest {
		return mailPublicationReceipt(journal, "stopped", true), ErrConflict
	}
	postfix, postfixErr := host.controlService(ctx, ServicePostfix, ServiceProbe)
	dovecot, dovecotErr := host.controlService(ctx, ServiceDovecot, ServiceProbe)
	if postfixErr != nil || dovecotErr != nil || !postfix.Active || !dovecot.Active {
		return mailPublicationReceipt(journal, "stopped", true), errors.Join(ErrAmbiguous, postfixErr, dovecotErr)
	}
	return mailPublicationReceipt(journal, "active", false), nil
}

func (host *LinuxMailHost) stageMigrationCandidateLocked(ctx context.Context, generation ConfigGeneration) (string, string, string, string, error) {
	artifacts, err := host.storeArtifacts(ctx, generation)
	if err != nil {
		return "", "", "", "", err
	}
	defer wipeMailArtifacts(artifacts)
	storageDigest, err := daemoncfg.ComputeDigest(artifacts)
	if err != nil {
		return "", "", "", "", err
	}
	generationID := generation.ID + "-" + storageDigest[:16]
	if _, err = host.Store.Stage(ctx, generationID, storageDigest, artifacts); err != nil {
		return "", "", "", "", err
	}
	previous, err := host.Store.Current()
	if err != nil {
		return "", "", "", "", err
	}
	validation, err := host.validateMigrationGeneration(ctx, generationID)
	return storageDigest, generationID, previous, validation, err
}

func (host *LinuxMailHost) validateMigrationGeneration(ctx context.Context, id string) (string, error) {
	root := filepath.Join(MailConfigurationRoot, "generations", id)
	commands := [][]string{{host.profile.postfix, "-c", filepath.Join(root, "postfix"), "check"}, {host.profile.doveconf, "-c", filepath.Join(root, "dovecot/dovecot.conf"), "-n"}}
	evidence := []string{id}
	for _, command := range commands {
		output, err := runMailProcess(ctx, command[0], command[1:]...)
		evidence = append(evidence, command[0], string(output), errorText(err))
		if err != nil {
			return digestMailEvidence(evidence...), err
		}
	}
	return digestMailEvidence(evidence...), nil
}

func (host *LinuxMailHost) rollbackMailPublication(ctx context.Context, bundle MigrationBundle, generation ConfigGeneration, journal mailPublicationJournal, cause error) (MailPublicationReceipt, error) {
	current, currentErr := host.Store.Current()
	var rollbackErr error
	if currentErr == nil && current == journal.GenerationID {
		rollbackErr = host.Store.Rollback(ctx, journal.PreviousGeneration)
	} else if currentErr != nil || current != journal.PreviousGeneration {
		rollbackErr = errors.Join(currentErr, ErrConflict)
	}
	rollbackErr = errors.Join(rollbackErr, host.rollbackMigrationMaildirs(ctx, bundle))
	if rollbackErr == nil && journal.DovecotWasActive {
		_, rollbackErr = host.controlService(ctx, ServiceDovecot, ServiceStart)
	}
	if rollbackErr == nil && journal.PostfixWasActive {
		_, rollbackErr = host.controlService(ctx, ServicePostfix, ServiceStart)
	}
	if rollbackErr != nil {
		return host.stopAmbiguousMailPublication(ctx, journal, errors.Join(cause, rollbackErr))
	}
	journal.State = "prepared"
	journal.SourceFenceDigest = ""
	journal.ActivationDigest = ""
	journal.RolledBack = true
	journal.UpdatedAt = host.now()
	if err := host.saveMailPublication(journal); err != nil {
		return host.stopAmbiguousMailPublication(ctx, journal, errors.Join(cause, err))
	}
	return mailPublicationReceipt(journal, "dark", false), cause
}

func (host *LinuxMailHost) stopAmbiguousMailPublication(ctx context.Context, journal mailPublicationJournal, cause error) (MailPublicationReceipt, error) {
	postfix, postfixErr := host.controlService(ctx, ServicePostfix, ServiceStop)
	dovecot, dovecotErr := host.controlService(ctx, ServiceDovecot, ServiceStop)
	journal.ServiceDigest = digestMailEvidence(journal.ServiceDigest, postfix.EvidenceDigest, dovecot.EvidenceDigest, errorText(postfixErr), errorText(dovecotErr))
	journal.State = "stopped"
	journal.UpdatedAt = host.now()
	saveErr := host.saveMailPublication(journal)
	return mailPublicationReceipt(journal, "stopped", true), errors.Join(ErrAmbiguous, cause, postfixErr, dovecotErr, saveErr)
}

func mailPublicationBinding(bundle MigrationBundle, generation ConfigGeneration) string {
	raw, _ := json.Marshal(struct {
		Bundle     MigrationBundle `json:"bundle"`
		Generation string          `json:"generation"`
	}{bundle, generation.Digest})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func mailPublicationReceipt(journal mailPublicationJournal, state string, stopped bool) MailPublicationReceipt {
	receipt := MailPublicationReceipt{ImportID: journal.ImportID, ConfigurationDigest: journal.ConfigurationDigest, StorageDigest: journal.StorageDigest, GenerationID: journal.GenerationID, PreviousGeneration: journal.PreviousGeneration, ValidationDigest: journal.ValidationDigest, ActivationDigest: journal.ActivationDigest, MaildirDigest: journal.MaildirDigest, ServiceDigest: journal.ServiceDigest, State: state, RolledBack: journal.RolledBack, ServicesStopped: stopped, ObservedAt: journal.UpdatedAt}
	receipt.EvidenceDigest = digestMailEvidence(receipt.ImportID, receipt.ConfigurationDigest, receipt.StorageDigest, receipt.GenerationID, receipt.PreviousGeneration, receipt.ValidationDigest, receipt.ActivationDigest, receipt.MaildirDigest, receipt.ServiceDigest, receipt.State, fmt.Sprint(receipt.RolledBack), fmt.Sprint(receipt.ServicesStopped), receipt.ObservedAt.UTC().Format(time.RFC3339Nano))
	return receipt
}

func (host *LinuxMailHost) loadMailPublication(bundle MigrationBundle, generation ConfigGeneration) (mailPublicationJournal, bool, error) {
	var journal mailPublicationJournal
	directory, err := openMailPublicationDirectory(bundle.ID, false)
	if errors.Is(err, syscall.ENOENT) {
		return journal, false, nil
	}
	if err != nil {
		return journal, false, err
	}
	defer syscall.Close(directory)
	raw, err := readMailImportFile(directory, "publication.json", 1<<20)
	if err != nil {
		return journal, false, err
	}
	if json.Unmarshal(raw, &journal) != nil || journal.Version != 1 || journal.ImportID != bundle.ID || journal.BindingDigest != mailPublicationBinding(bundle, generation) || journal.ConfigurationDigest != generation.Digest || !validMailEvidenceDigest(journal.StorageDigest) || !validMailGenerationID(journal.GenerationID) || !validMailEvidenceDigest(journal.ValidationDigest) || journal.UpdatedAt.IsZero() {
		return journal, false, ErrConflict
	}
	return journal, true, nil
}

func (host *LinuxMailHost) saveMailPublication(journal mailPublicationJournal) error {
	directory, err := openMailPublicationDirectory(journal.ImportID, true)
	if err != nil {
		return err
	}
	defer syscall.Close(directory)
	raw, err := json.Marshal(journal)
	if err != nil || len(raw) > 1<<20 {
		return ErrInvalidCommand
	}
	return replaceMailImportFile(directory, "publication.json", raw)
}

func openMailPublicationDirectory(importID string, create bool) (int, error) {
	root, err := openMailProductRoot()
	if err != nil {
		return -1, err
	}
	defer syscall.Close(root)
	imports, err := mailDirectory(root, "mail-imports", create)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(imports)
	return mailDirectory(imports, digestMailEvidence("publication", importID), create)
}

func replaceMailImportFile(root int, name string, content []byte) error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".journal-" + hex.EncodeToString(random[:])
	fd, err := mailOpenAt(root, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600, false)
	if err != nil {
		return err
	}
	defer syscall.Unlinkat(root, temporary)
	file := os.NewFile(uintptr(fd), "mail-publication")
	if _, err = file.Write(content); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = syscall.Renameat(root, temporary, root, name); err != nil {
		return err
	}
	return syscall.Fsync(root)
}

func (host *LinuxMailHost) requireMigrationDomainAbsent(domain string) error {
	root, err := openMailProductRoot()
	if err != nil {
		return err
	}
	defer syscall.Close(root)
	fd, err := mailOpenAt(root, "mailboxes/"+domain, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
	if err == nil {
		syscall.Close(fd)
		return ErrConflict
	}
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

func (host *LinuxMailHost) inspectMigrationMaildir(ctx context.Context, request MaildirImportRequest, live bool) (MaildirImportReceipt, error) {
	request.Operation = "observe"
	request.Archive = nil
	if request.Validate() != nil {
		return MaildirImportReceipt{}, ErrInvalidCommand
	}
	identity, err := host.mailboxIdentity(request.TenantID, request.SiteID)
	if err != nil {
		return MaildirImportReceipt{}, err
	}
	root, err := openMailProductRoot()
	if err != nil {
		return MaildirImportReceipt{}, err
	}
	defer syscall.Close(root)
	imports, err := mailDirectory(root, "mail-imports", false)
	if err != nil {
		return MaildirImportReceipt{}, err
	}
	defer syscall.Close(imports)
	directory, err := mailDirectory(imports, digestMailEvidence(request.TenantID, string(request.DomainID), string(request.MailboxID), request.ImportID), false)
	if err != nil {
		return MaildirImportReceipt{}, err
	}
	defer syscall.Close(directory)
	binding := request
	binding.Operation = "stage"
	encoded, _ := json.Marshal(binding)
	actual, err := readMailImportFile(directory, "binding.json", 16<<10)
	if err != nil || !bytes.Equal(actual, encoded) {
		return MaildirImportReceipt{}, errors.Join(ErrConflict, err)
	}
	manifestRaw, err := readMailImportFile(directory, "manifest.json", 1<<20)
	if err != nil {
		return MaildirImportReceipt{}, err
	}
	var manifest maildirManifest
	if json.Unmarshal(manifestRaw, &manifest) != nil || manifest.UID != identity.UID || manifest.GID != identity.GID || len(manifest.Entries) > 1024 {
		return MaildirImportReceipt{}, ErrConflict
	}
	dataRoot := directory
	if live {
		dataRoot, err = mailOpenAt(root, "mailboxes/"+request.Domain+"/"+request.Local, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		if err != nil {
			return MaildirImportReceipt{}, err
		}
		defer syscall.Close(dataRoot)
	}
	var total uint64
	for _, entry := range manifest.Entries {
		if err = ctx.Err(); err != nil {
			return MaildirImportReceipt{}, err
		}
		var content []byte
		if live {
			content, err = readOwnedMailFile(dataRoot, entry.Path, maximumMaildirImportBytes, identity.UID, identity.GID)
		} else {
			content, err = readMailImportFile(dataRoot, entry.Path, maximumMaildirImportBytes)
		}
		if err != nil {
			return MaildirImportReceipt{}, err
		}
		sum := sha256.Sum256(content)
		size := uint64(len(content))
		wipeMailBytes(content)
		if size != entry.Size || hex.EncodeToString(sum[:]) != entry.Digest {
			return MaildirImportReceipt{}, ErrConflict
		}
		total += size
	}
	if total != manifest.Bytes {
		return MaildirImportReceipt{}, ErrConflict
	}
	sum := sha256.Sum256(manifestRaw)
	return MaildirImportReceipt{ImportID: request.ImportID, ArchiveDigest: request.ArchiveDigest, EvidenceDigest: hex.EncodeToString(sum[:]), State: "dark", Bytes: total, Objects: uint64(len(manifest.Entries)), ObservedAt: host.now()}, nil
}

func readOwnedMailFile(root int, name string, maximum int64, uid, gid uint32) ([]byte, error) {
	fd, err := mailOpenAt(root, name, syscall.O_RDONLY, 0, false)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "mailbox")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uid || stat.Gid != gid || stat.Nlink != 1 || info.Size() > maximum {
		return nil, ErrUnauthorized
	}
	content := make([]byte, info.Size())
	if _, err = file.ReadAt(content, 0); err != nil && len(content) != 0 {
		wipeMailBytes(content)
		return nil, err
	}
	return content, nil
}

func (host *LinuxMailHost) publishMigrationMaildirs(ctx context.Context, bundle MigrationBundle) (string, error) {
	root, err := openMailProductRoot()
	if err != nil {
		return "", err
	}
	defer syscall.Close(root)
	mailboxes, err := ensureMailDirectory(root, "mailboxes", 0, 0, 0755)
	if err != nil {
		return "", err
	}
	defer syscall.Close(mailboxes)
	domain, err := ensureMailMigrationDomain(mailboxes, bundle.Domain.Domain.Name, bundle.ID)
	if err != nil {
		return "", err
	}
	defer syscall.Close(domain)
	proofs := make([]string, 0, len(bundle.Maildirs))
	for _, request := range bundle.Maildirs {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		identity, identityErr := host.mailboxIdentity(request.TenantID, request.SiteID)
		if identityErr != nil {
			return "", identityErr
		}
		local, localErr := ensureMailDirectory(domain, request.Local, identity.UID, identity.GID, 0700)
		if localErr != nil {
			return "", localErr
		}
		live, liveErr := mailOpenAt(local, "Maildir", syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		if liveErr == nil {
			syscall.Close(live)
			syscall.Close(local)
			observed, observeErr := host.inspectMigrationMaildir(ctx, request, true)
			if observeErr != nil {
				return "", observeErr
			}
			proofs = append(proofs, observed.EvidenceDigest)
			continue
		}
		if !errors.Is(liveErr, syscall.ENOENT) {
			syscall.Close(local)
			return "", liveErr
		}
		imports, openErr := mailDirectory(root, "mail-imports", false)
		if openErr != nil {
			syscall.Close(local)
			return "", openErr
		}
		staged, openErr := mailDirectory(imports, digestMailEvidence(request.TenantID, string(request.DomainID), string(request.MailboxID), request.ImportID), false)
		syscall.Close(imports)
		if openErr != nil {
			syscall.Close(local)
			return "", openErr
		}
		if err = chownMaildirAt(staged, identity.UID, identity.GID); err == nil {
			err = syscall.Renameat(staged, "Maildir", local, "Maildir")
		}
		syncErr := syscall.Fsync(staged)
		syscall.Close(staged)
		err = errors.Join(err, syncErr, syscall.Fsync(local))
		syscall.Close(local)
		if err != nil {
			return "", err
		}
		observed, observeErr := host.inspectMigrationMaildir(ctx, request, true)
		if observeErr != nil {
			return "", observeErr
		}
		proofs = append(proofs, observed.EvidenceDigest)
	}
	sort.Strings(proofs)
	return digestMailEvidence(proofs...), syscall.Fsync(domain)
}

func (host *LinuxMailHost) rollbackMigrationMaildirs(ctx context.Context, bundle MigrationBundle) error {
	root, err := openMailProductRoot()
	if err != nil {
		return err
	}
	defer syscall.Close(root)
	mailboxes, err := mailOpenAt(root, "mailboxes", syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.Close(mailboxes)
	domain, err := mailOpenAt(mailboxes, bundle.Domain.Domain.Name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.Close(domain)
	owner, err := readMailImportFile(domain, ".migration-owner", 256)
	if err != nil || string(owner) != bundle.ID+"\n" {
		return errors.Join(ErrConflict, err)
	}
	for index := len(bundle.Maildirs) - 1; index >= 0; index-- {
		request := bundle.Maildirs[index]
		if err = ctx.Err(); err != nil {
			return err
		}
		local, openErr := mailOpenAt(domain, request.Local, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		if errors.Is(openErr, syscall.ENOENT) {
			continue
		}
		if openErr != nil {
			return openErr
		}
		imports, importErr := mailDirectory(root, "mail-imports", false)
		if importErr != nil {
			syscall.Close(local)
			return importErr
		}
		staged, importErr := mailDirectory(imports, digestMailEvidence(request.TenantID, string(request.DomainID), string(request.MailboxID), request.ImportID), false)
		syscall.Close(imports)
		if importErr != nil {
			syscall.Close(local)
			return importErr
		}
		live, liveErr := mailOpenAt(local, "Maildir", syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		if liveErr == nil {
			syscall.Close(live)
			dark, darkErr := mailOpenAt(staged, "Maildir", syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
			if darkErr == nil {
				syscall.Close(dark)
				syscall.Close(local)
				syscall.Close(staged)
				return ErrConflict
			}
			if !errors.Is(darkErr, syscall.ENOENT) {
				syscall.Close(local)
				syscall.Close(staged)
				return darkErr
			}
			if err = syscall.Renameat(local, "Maildir", staged, "Maildir"); err == nil {
				err = chownMaildirAt(staged, 0, 0)
			}
		}
		if err == nil {
			err = errors.Join(syscall.Fsync(local), syscall.Fsync(staged))
		}
		syscall.Close(local)
		syscall.Close(staged)
		if err != nil {
			return err
		}
		if removeErr := mailUnlinkAt(domain, request.Local, 0x200); removeErr != nil && !errors.Is(removeErr, syscall.ENOENT) {
			return removeErr
		}
	}
	if err = syscall.Unlinkat(domain, ".migration-owner"); err != nil && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	if err = mailUnlinkAt(mailboxes, bundle.Domain.Domain.Name, 0x200); err != nil && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	return syscall.Fsync(mailboxes)
}

func ensureMailMigrationDomain(mailboxes int, name, importID string) (int, error) {
	directory, err := mailOpenAt(mailboxes, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
	created := false
	if errors.Is(err, syscall.ENOENT) {
		if err = syscall.Mkdirat(mailboxes, name, 0711); err != nil {
			return -1, err
		}
		if err = syscall.Fsync(mailboxes); err != nil {
			return -1, err
		}
		directory, err = mailOpenAt(mailboxes, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		created = true
	}
	if err != nil {
		return -1, err
	}
	var stat syscall.Stat_t
	if syscall.Fstat(directory, &stat) != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0777 != 0711 {
		syscall.Close(directory)
		return -1, ErrUnauthorized
	}
	marker := []byte(importID + "\n")
	if created {
		err = writeMailImportFile(directory, ".migration-owner", marker)
	} else {
		var actual []byte
		actual, err = readMailImportFile(directory, ".migration-owner", 256)
		if err == nil && !bytes.Equal(actual, marker) {
			err = ErrConflict
		}
	}
	if err != nil {
		syscall.Close(directory)
		return -1, err
	}
	return directory, nil
}

func ensureMailDirectory(parent int, name string, uid, gid uint32, mode uint32) (int, error) {
	directory, err := mailOpenAt(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
	if errors.Is(err, syscall.ENOENT) {
		if err = syscall.Mkdirat(parent, name, mode); err != nil {
			return -1, err
		}
		directory, err = mailOpenAt(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		if err == nil {
			err = errors.Join(syscall.Fchown(directory, int(uid), int(gid)), syscall.Fchmod(directory, mode), syscall.Fsync(parent))
		}
	}
	if err != nil {
		return -1, err
	}
	var stat syscall.Stat_t
	if syscall.Fstat(directory, &stat) != nil || stat.Uid != uid || stat.Gid != gid || stat.Mode&0777 != mode {
		syscall.Close(directory)
		return -1, ErrUnauthorized
	}
	return directory, nil
}

func chownMaildirAt(parent int, uid, gid uint32) error {
	for _, directory := range []string{"Maildir", "Maildir/cur", "Maildir/new", "Maildir/tmp"} {
		fd, err := mailOpenAt(parent, directory, syscall.O_RDONLY|syscall.O_DIRECTORY, 0, false)
		if err != nil {
			return err
		}
		err = errors.Join(syscall.Fchown(fd, int(uid), int(gid)), syscall.Fchmod(fd, 0700))
		syscall.Close(fd)
		if err != nil {
			return err
		}
	}
	manifestRaw, err := readMailImportFile(parent, "manifest.json", 1<<20)
	if err != nil {
		return err
	}
	var manifest maildirManifest
	if json.Unmarshal(manifestRaw, &manifest) != nil {
		return ErrConflict
	}
	for _, entry := range manifest.Entries {
		if path.Clean(entry.Path) != entry.Path || !strings.HasPrefix(entry.Path, "Maildir/") {
			return ErrConflict
		}
		fd, openErr := mailOpenAt(parent, entry.Path, syscall.O_RDONLY, 0, false)
		if openErr != nil {
			return openErr
		}
		openErr = errors.Join(syscall.Fchown(fd, int(uid), int(gid)), syscall.Fchmod(fd, 0600))
		syscall.Close(fd)
		if openErr != nil {
			return openErr
		}
	}
	return nil
}

func mailUnlinkAt(directory int, name string, flags uintptr) error {
	value, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(directory), uintptr(unsafe.Pointer(value)), flags)
	if errno != 0 {
		return errno
	}
	return nil
}
