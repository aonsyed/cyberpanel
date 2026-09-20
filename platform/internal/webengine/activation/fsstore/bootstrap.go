package fsstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
)

type bootstrapRecord struct {
	Candidate string `json:"candidate"`
	Original  string `json:"original"`
}

func (s *Store) bootstrapState(ctx context.Context, candidate activation.Receipt) ([]byte, []byte, error) {
	if ctx == nil || s == nil || s.root == nil {
		return nil, nil, errors.New("bootstrap context and store required")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// A broken existing receipt is not permission to initialize a new node.
	if _, err := s.root.Lstat(path.Join(stateDir, "current")); !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, errors.New("managed current state already exists or is unreadable")
	}
	sealed, master, err := s.resolve(candidate, false)
	if err != nil || sealed.Snapshot != 1 {
		return nil, nil, errors.New("bootstrap requires sealed snapshot one")
	}
	live, err := s.readManagedFile(s.master, maxArtifactBytes)
	return master, live, err
}

func (s *Store) PrepareBootstrap(ctx context.Context, candidate activation.Receipt) error {
	master, live, err := s.bootstrapState(ctx, candidate)
	if err != nil {
		return err
	}
	marker := path.Join(stateDir, "bootstrap.json")
	backup := path.Join(stateDir, "bootstrap-master")
	raw, err := s.readManagedFile(marker, maxStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		if err = s.writeExact(backup, live); err != nil {
			return err
		}
		sum := sha256.Sum256(live)
		raw, err = json.Marshal(bootstrapRecord{candidate.Digest, hex.EncodeToString(sum[:])})
		if err != nil {
			return err
		}
		return s.writeExact(marker, raw)
	}
	if err != nil {
		return err
	}
	original, err := s.bootstrapOriginal(raw, candidate)
	if err != nil {
		return err
	}
	if !bytes.Equal(live, original) && !bytes.Equal(live, master) {
		return errors.New("bootstrap live master changed outside activation")
	}
	return nil
}

func (s *Store) bootstrapOriginal(raw []byte, candidate activation.Receipt) ([]byte, error) {
	var record bootstrapRecord
	if parseCanonicalJSON(raw, &record) != nil || record.Candidate != candidate.Digest || !validDigest(record.Original) {
		return nil, errors.New("bootstrap checkpoint conflicts")
	}
	original, err := s.readManagedFile(path.Join(stateDir, "bootstrap-master"), maxArtifactBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(original)
	if hex.EncodeToString(sum[:]) != record.Original {
		return nil, errors.New("bootstrap backup integrity failure")
	}
	return original, nil
}

func (s *Store) RestoreBootstrap(ctx context.Context, candidate activation.Receipt) error {
	master, live, err := s.bootstrapState(ctx, candidate)
	if err != nil {
		return err
	}
	raw, err := s.readManagedFile(path.Join(stateDir, "bootstrap.json"), maxStateBytes)
	if err != nil {
		return err
	}
	original, err := s.bootstrapOriginal(raw, candidate)
	if err != nil {
		return err
	}
	if !bytes.Equal(live, original) && !bytes.Equal(live, master) {
		return errors.New("refusing to overwrite unrelated master")
	}
	return s.replace(s.master, original)
}
