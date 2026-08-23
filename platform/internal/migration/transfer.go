package migration

import (
	"context"
	"errors"
	"io"
	"time"
)

const sourceReadWindow = uint64(4 << 20)

type ChunkProgressSink interface {
	RecordChunkProgress(context.Context, ID, string, uint64, uint64, string) error
}

// ChunkStager copies only manifest-addressed objects. A source cannot use this
// channel as a path oracle because reads are expressed solely by signed chunk
// digest and bounded byte ranges.
type ChunkStager struct {
	store           *ChunkStore
	progress        ChunkProgressSink
	references      ChunkReferenceStore
	quarantineDelay time.Duration
	clock           func() time.Time
}

func NewChunkStager(store *ChunkStore, progress ChunkProgressSink) (*ChunkStager, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &ChunkStager{store: store, progress: progress, quarantineDelay: DefaultChunkQuarantineDelay, clock: time.Now}, nil
}

func (s *ChunkStager) WithReferenceStore(references ChunkReferenceStore) *ChunkStager {
	if s != nil {
		s.references = references
	}
	return s
}

func (s *ChunkStager) Stage(ctx context.Context, migrationID ID, manifest Manifest, source SourceReader) error {
	if s == nil || s.store == nil || ctx == nil || !migrationID.Valid() || source == nil || manifest.Validate() != nil || manifest.MigrationID != migrationID {
		return ErrInvalid
	}
	for _, descriptor := range canonicalChunks(manifest.Chunks) {
		reference := ChunkReference{}
		if s.references != nil {
			var err error
			reference, err = s.references.AcquireChunkReference(ctx, migrationID, descriptor)
			if err != nil {
				return err
			}
			if reference.MigrationID != migrationID || reference.Digest != descriptor.Digest || reference.Size != descriptor.Size || reference.ObjectEpoch == 0 || !runtimeScopeText(reference.TenantID, 128) {
				return ErrAmbiguous
			}
		}
		present, err := s.store.Has(ctx, descriptor)
		if err != nil {
			if s.references != nil {
				return errors.Join(ErrAmbiguous, err)
			}
			return err
		}
		if present {
			if s.references != nil && !reference.Materialized {
				if err := s.references.ConfirmChunkReference(ctx, migrationID, descriptor); err != nil {
					return err
				}
			}
			if s.progress != nil {
				if err := s.progress.RecordChunkProgress(ctx, migrationID, descriptor.Digest, descriptor.Size, descriptor.Size, "verified"); err != nil {
					return err
				}
			}
			continue
		}
		if s.references != nil && reference.Materialized {
			return errors.Join(ErrAmbiguous, ErrNotFound)
		}
		reader := &remoteChunkReader{ctx: ctx, source: source, digest: descriptor.Digest, size: descriptor.Size}
		if err := s.store.Put(ctx, descriptor, reader); err != nil {
			if s.progress != nil {
				_ = s.progress.RecordChunkProgress(ctx, migrationID, descriptor.Digest, reader.offset, descriptor.Size, "failed")
			}
			return err
		}
		if s.references != nil {
			if err := s.references.ConfirmChunkReference(ctx, migrationID, descriptor); err != nil {
				return err
			}
		}
		if s.progress != nil {
			if err := s.progress.RecordChunkProgress(ctx, migrationID, descriptor.Digest, descriptor.Size, descriptor.Size, "verified"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ChunkStager) Release(ctx context.Context, migrationID ID, reason ChunkReleaseReason) error {
	if s == nil || s.store == nil || ctx == nil || !migrationID.Valid() || !validChunkReleaseReason(reason) || s.quarantineDelay <= 0 || s.quarantineDelay > maximumChunkQuarantineDelay {
		return ErrInvalid
	}
	if s.references == nil {
		return nil
	}
	_, err := s.references.ReleaseChunkReferences(ctx, migrationID, reason, s.quarantineDelay)
	return err
}

type remoteChunkReader struct {
	ctx    context.Context
	source SourceReader
	digest string
	size   uint64
	offset uint64
	pending []byte
}

func (r *remoteChunkReader) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if len(r.pending) != 0 {
		count := copy(destination, r.pending)
		r.pending = r.pending[count:]
		return count, nil
	}
	if r.offset >= r.size {
		return 0, io.EOF
	}
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
	}
	window := r.size - r.offset
	if window > sourceReadWindow {
		window = sourceReadWindow
	}
	chunk, err := r.source.OpenChunk(r.ctx, r.digest, r.offset, window)
	if err != nil {
		return 0, err
	}
	if uint64(len(chunk)) != window {
		return 0, errors.Join(ErrInvalid, io.ErrUnexpectedEOF)
	}
	r.offset += window
	count := copy(destination, chunk)
	if count < len(chunk) {
		r.pending = append(r.pending[:0], chunk[count:]...)
	}
	return count, nil
}
