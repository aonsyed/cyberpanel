package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type IdempotencyReceipt struct {
	KeyDigest string `json:"key_digest"`
	RequestDigest string `json:"request_digest"`
	State string `json:"state"`
	Response CoreResponse `json:"response,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type IdempotencyLedger interface {
	Acquire(context.Context, string, string) (IdempotencyReceipt, bool, error)
	Complete(context.Context, string, string, CoreResponse) error
	Retryable(context.Context, string, string) error
}

type DirectoryIdempotencyLedger struct {
	root string
	clock func() time.Time
	staleAfter time.Duration
	mutex sync.Mutex
}

func NewDirectoryIdempotencyLedger(root string) (*DirectoryIdempotencyLedger, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root { return nil, invalid("idempotency directory") }
	if err := secureStateDirectory(root, 0700); err != nil { return nil, err }
	return &DirectoryIdempotencyLedger{root: root, clock: time.Now, staleAfter: 30*time.Minute}, nil
}

func (ledger *DirectoryIdempotencyLedger) path(key string) (string, string) {
	sum := sha256.Sum256([]byte(key)); digest := hex.EncodeToString(sum[:])
	return filepath.Join(ledger.root, digest[:2], digest+".json"), digest
}

func (ledger *DirectoryIdempotencyLedger) Acquire(ctx context.Context, key, requestDigest string) (IdempotencyReceipt, bool, error) {
	if err := ctx.Err(); err != nil { return IdempotencyReceipt{}, false, err }
	if ledger == nil || requestDigest == "" { return IdempotencyReceipt{}, false, invalid("idempotency acquisition") }
	ledger.mutex.Lock(); defer ledger.mutex.Unlock()
	path, keyDigest := ledger.path(key)
	now := ledger.clock().UTC()
	receipt, err := readIdempotencyReceipt(path)
	if err == nil {
		if receipt.KeyDigest != keyDigest || receipt.RequestDigest != requestDigest { return IdempotencyReceipt{}, false, ErrIdempotencyConflict }
		if receipt.State == "complete" { if receipt.Response.ProtocolVersion!=InternalProtocolVersion||receipt.Response.Status<200||receipt.Response.Status>299||receipt.Response.Envelope==nil||receipt.Response.Problem!=nil{return IdempotencyReceipt{},false,ErrUnavailable};return receipt, true, nil }
		if receipt.State == "running" && now.Sub(receipt.UpdatedAt) < ledger.staleAfter { return IdempotencyReceipt{}, false, ErrUnavailable }
	} else if !errors.Is(err, os.ErrNotExist) { return IdempotencyReceipt{}, false, err }
	if err = secureStateDirectory(filepath.Dir(path), 0700); err != nil { return IdempotencyReceipt{}, false, err }
	receipt = IdempotencyReceipt{KeyDigest: keyDigest, RequestDigest: requestDigest, State: "running", CreatedAt: now, UpdatedAt: now}
	if err = writeStateFile(path, receipt, 0600); err != nil { return IdempotencyReceipt{}, false, err }
	return receipt, false, nil
}

func (ledger *DirectoryIdempotencyLedger) Complete(ctx context.Context, key, requestDigest string, response CoreResponse) error {
	if err := ctx.Err(); err != nil { return err }
	ledger.mutex.Lock(); defer ledger.mutex.Unlock()
	path, keyDigest := ledger.path(key)
	receipt, err := readIdempotencyReceipt(path); if err != nil { return err }
	if receipt.KeyDigest != keyDigest || receipt.RequestDigest != requestDigest { return ErrIdempotencyConflict }
	if response.ProtocolVersion!=InternalProtocolVersion||response.Envelope==nil||response.Problem!=nil{return invalid("idempotency response")}
	receipt.State, receipt.Response, receipt.UpdatedAt = "complete", response, ledger.clock().UTC()
	return writeStateFile(path, receipt, 0600)
}

func (ledger *DirectoryIdempotencyLedger) Retryable(ctx context.Context, key, requestDigest string) error {
	if err := ctx.Err(); err != nil { return err }
	ledger.mutex.Lock(); defer ledger.mutex.Unlock()
	path, keyDigest := ledger.path(key)
	receipt, err := readIdempotencyReceipt(path); if err != nil { return err }
	if receipt.KeyDigest != keyDigest || receipt.RequestDigest != requestDigest { return ErrIdempotencyConflict }
	receipt.State, receipt.UpdatedAt = "retryable", ledger.clock().UTC()
	return writeStateFile(path, receipt, 0600)
}

func readIdempotencyReceipt(path string) (IdempotencyReceipt, error) {
	var receipt IdempotencyReceipt
	content, err := readProtectedFile(path, 1<<24); if err != nil { return receipt, err }
	if err = decodeStrict(content, &receipt); err != nil { return receipt, fmt.Errorf("invalid idempotency receipt: %w", err) }
	return receipt, nil
}

func secureStateDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path { return invalid("state directory") }
	if err := os.MkdirAll(path, mode); err != nil { return err }
	info, err := os.Lstat(path); if err != nil { return err }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 { return fmt.Errorf("unsafe state directory permissions: %s", path) }
	return nil
}

func writeStateFile(path string, value any, mode os.FileMode) error {
	content, err := json.Marshal(value); if err != nil { return err }
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".panel-state-"); if err != nil { return err }
	temporaryPath := temporary.Name(); committed := false
	defer func() { temporary.Close(); if !committed { _ = os.Remove(temporaryPath) } }()
	if err = temporary.Chmod(mode); err != nil { return err }
	if _, err = temporary.Write(content); err != nil { return err }
	if err = temporary.Sync(); err != nil { return err }
	if err = temporary.Close(); err != nil { return err }
	if err = os.Rename(temporaryPath, path); err != nil { return err }
	committed = true
	dir, err := os.Open(directory); if err != nil { return err }; defer dir.Close()
	return dir.Sync()
}

func readProtectedFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 { return nil, ErrInvalidRequest }
	info, err := os.Lstat(path); if err != nil { return nil, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > maximum { return nil, ErrInvalidRequest }
	file,err:=os.Open(path);if err!=nil{return nil,err};defer file.Close();opened,err:=file.Stat();if err!=nil||!os.SameFile(info,opened){return nil,ErrInvalidRequest};content,err:=io.ReadAll(io.LimitReader(file,maximum+1));if err!=nil||int64(len(content))>maximum{return nil,ErrInvalidRequest};return content,nil
}
