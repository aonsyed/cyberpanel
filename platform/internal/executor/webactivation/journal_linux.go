//go:build linux

package webactivation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
)

const (
	DefaultJournalRoot = "/var/lib/cyberpanel/webengine-activation"
	journalFile = "receipts.json"
	journalTemporary = ".receipts.tmp"
	maximumJournalBytes = 8 << 20
	maximumJournalEntries = 2048
)

type journalRecord struct {
	EffectID string `json:"effect_id"`
	ExpectedDigest string `json:"expected_digest"`
	RequestDigest string `json:"request_digest"`
	State string `json:"state"`
	Receipt activation.Receipt `json:"receipt"`
	ErrorCode string `json:"error_code,omitempty"`
	StartedAt time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type journalState struct {
	Version uint16 `json:"version"`
	Records map[string]journalRecord `json:"records"`
}

type Journal struct {
	root *os.Root
	state journalState
	mu sync.Mutex
}

func NewJournal(rootPath string) (*Journal, error) {
	if rootPath != DefaultJournalRoot { return nil, errors.New("unregistered web-engine activation journal root") }
	if err := ensureJournalRoot(rootPath); err != nil { return nil, err }
	root, err := os.OpenRoot(rootPath)
	if err != nil { return nil, err }
	journal := &Journal{root: root, state: journalState{Version: ProtocolVersion, Records: make(map[string]journalRecord)}}
	if err = journal.load(); err != nil { root.Close(); return nil, err }
	return journal, nil
}

func (journal *Journal) Close() error {
	if journal == nil || journal.root == nil { return nil }
	err := journal.root.Close()
	journal.root = nil
	return err
}

func (journal *Journal) Begin(request Request, now time.Time) (journalRecord, bool, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.root == nil { return journalRecord{}, false, errors.New("activation journal is closed") }
	requestDigest := request.Digest()
	if existing, found := journal.state.Records[request.EffectID]; found {
		if existing.RequestDigest != requestDigest { return journalRecord{}, true, ErrInvalidRequest }
		return existing, true, nil
	}
	previousRecords := cloneRecords(journal.state.Records)
	journal.prune()
	if len(journal.state.Records) >= maximumJournalEntries { return journalRecord{}, false, errors.New("activation receipt journal is full") }
	record := journalRecord{EffectID: request.EffectID, ExpectedDigest: request.ExpectedDigest, RequestDigest: requestDigest, State: "pending", StartedAt: now.UTC()}
	journal.state.Records[request.EffectID] = record
	if err := journal.persist(); err != nil { journal.state.Records = previousRecords; return journalRecord{}, false, err }
	return record, false, nil
}

func (journal *Journal) Complete(request Request, response Response) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, found := journal.state.Records[request.EffectID]
	if !found || record.RequestDigest != request.Digest() { return ErrInvalidRequest }
	if record.State == "completed" {
		if record.Receipt != response.Receipt || record.ErrorCode != response.ErrorCode || !record.CompletedAt.Equal(response.CompletedAt) { return ErrInvalidResponse }
		return nil
	}
	record.State = "completed"
	record.Receipt = response.Receipt
	record.ErrorCode = response.ErrorCode
	record.CompletedAt = response.CompletedAt.UTC()
	journal.state.Records[request.EffectID] = record
	if err := journal.persist(); err != nil { journal.state.Records[request.EffectID] = journalRecord{EffectID: request.EffectID, ExpectedDigest: request.ExpectedDigest, RequestDigest: request.Digest(), State: "pending", StartedAt: record.StartedAt}; return err }
	return nil
}

func cloneRecords(records map[string]journalRecord) map[string]journalRecord {
	cloned := make(map[string]journalRecord, len(records))
	for key, record := range records { cloned[key] = record }
	return cloned
}

func (journal *Journal) prune() {
	if len(journal.state.Records) < maximumJournalEntries { return }
	completed := make([]journalRecord, 0, len(journal.state.Records))
	for _, record := range journal.state.Records {
		if record.State == "completed" { completed = append(completed, record) }
	}
	sort.Slice(completed, func(left, right int) bool { return completed[left].CompletedAt.Before(completed[right].CompletedAt) })
	remove := len(journal.state.Records) - maximumJournalEntries + 1
	for index := 0; index < remove && index < len(completed); index++ { delete(journal.state.Records, completed[index].EffectID) }
}

func (journal *Journal) load() error {
	info, err := journal.root.Lstat(journalTemporary)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 { return errors.New("unsafe activation journal crash residue") }
		if err = journal.root.Remove(journalTemporary); err != nil { return err }
	} else if !errors.Is(err, fs.ErrNotExist) { return err }
	info, err = journal.root.Lstat(journalFile)
	if errors.Is(err, fs.ErrNotExist) { return nil }
	if err != nil { return err }
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maximumJournalBytes { return errors.New("unsafe activation receipt journal") }
	file, err := journal.root.Open(journalFile)
	if err != nil { return err }
	content, readErr := io.ReadAll(io.LimitReader(file, maximumJournalBytes+1))
	closeErr := file.Close()
	if readErr != nil { return readErr }
	if closeErr != nil { return closeErr }
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var state journalState
	if err = decoder.Decode(&state); err != nil || decoder.Decode(&struct{}{}) != io.EOF { return errors.New("invalid activation receipt journal") }
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, content) || state.Version != ProtocolVersion || state.Records == nil || len(state.Records) > maximumJournalEntries { return errors.New("invalid activation receipt journal") }
	for effectID, record := range state.Records {
		if effectID != record.EffectID || effectID != effectIdentity(record.ExpectedDigest) || !validDigest(record.ExpectedDigest) || !validDigest(record.RequestDigest) || record.StartedAt.IsZero() || (record.State != "pending" && record.State != "completed") { return errors.New("invalid activation journal record") }
		if record.State == "completed" {
			if record.CompletedAt.IsZero() || !validErrorCode(record.ErrorCode) || !validReceipt(record.Receipt, record.ExpectedDigest) || (record.Receipt.Status == activation.Applied && record.ErrorCode != "") || (record.Receipt.Status != activation.Applied && record.ErrorCode == "") { return errors.New("invalid completed activation journal record") }
		} else if !record.CompletedAt.IsZero() || record.ErrorCode != "" || record.Receipt != (activation.Receipt{}) { return errors.New("invalid pending activation journal record") }
	}
	journal.state = state
	return nil
}

func (journal *Journal) persist() error {
	encoded, err := json.Marshal(journal.state)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumJournalBytes { return errors.New("activation receipt journal exceeds policy") }
	if _, err = journal.root.Lstat(journalTemporary); err == nil { return errors.New("activation journal temporary file already exists") } else if !errors.Is(err, fs.ErrNotExist) { return err }
	file, err := journal.root.OpenFile(journalTemporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil { return err }
	written, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil { _ = journal.root.Remove(journalTemporary); return writeErr }
	if written != len(encoded) { _ = journal.root.Remove(journalTemporary); return io.ErrShortWrite }
	if syncErr != nil { _ = journal.root.Remove(journalTemporary); return syncErr }
	if closeErr != nil { _ = journal.root.Remove(journalTemporary); return closeErr }
	if err = journal.root.Rename(journalTemporary, journalFile); err != nil { _ = journal.root.Remove(journalTemporary); return err }
	directory, err := journal.root.Open(".")
	if err != nil { return err }
	err = directory.Sync()
	closeErr = directory.Close()
	if err != nil { return err }
	return closeErr
}

func ensureJournalRoot(rootPath string) error {
	parent := filepath.Dir(rootPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 { return errors.New("activation journal parent is unsafe") }
	if err = os.Mkdir(rootPath, 0o700); err != nil && !errors.Is(err, os.ErrExist) { return err }
	info, err := os.Lstat(rootPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 { return errors.New("activation journal root is unsafe") }
	real, err := filepath.EvalSymlinks(rootPath)
	if err != nil || real != rootPath { return errors.New("activation journal root contains a symlink") }
	return nil
}
