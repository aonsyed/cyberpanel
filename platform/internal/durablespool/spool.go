package durablespool

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	indexSchema        = "cyberpanel.durable-spool.index.v1"
	recordSchema       = "cyberpanel.durable-spool.record.v1"
	indexLeaf          = "index.manifest.json"
	maximumManifestBytes = 16 << 10
)

type diskIndex struct {
	Schema       string `json:"schema"`
	HighSequence uint64 `json:"high_sequence"`
}

type diskRecord struct {
	Schema      string `json:"schema"`
	Record      Record `json:"record"`
	PayloadLeaf string `json:"payload_leaf"`
}

func digestPayload(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func recordID(sequence uint64, class RecordClass, digest string) RecordID {
	hash := sha256.New()
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], sequence)
	hash.Write(encoded[:])
	hash.Write([]byte{0})
	hash.Write([]byte(class))
	hash.Write([]byte{0})
	hash.Write([]byte(digest))
	return RecordID("ds_" + hex.EncodeToString(hash.Sum(nil))[:48])
}

func recordLeaves(sequence uint64) (string, string) {
	stem := fmt.Sprintf("record-%020d", sequence)
	return stem + ".manifest.json", stem + ".payload"
}

func parseRecordLeaf(leaf, suffix string) (uint64, bool) {
	if !strings.HasPrefix(leaf, "record-") || !strings.HasSuffix(leaf, suffix) {
		return 0, false
	}
	number := strings.TrimSuffix(strings.TrimPrefix(leaf, "record-"), suffix)
	if len(number) != 20 {
		return 0, false
	}
	sequence, err := strconv.ParseUint(number, 10, 64)
	if err != nil || sequence == 0 {
		return 0, false
	}
	manifestLeaf, payloadLeaf := recordLeaves(sequence)
	return sequence, leaf == manifestLeaf || leaf == payloadLeaf
}

func encodeCanonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumManifestBytes {
		if err != nil {
			return nil, err
		}
		return nil, ErrLimit
	}
	return append(encoded, '\n'), nil
}

func decodeCanonical(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maximumManifestBytes {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func validRecord(record Record) bool {
	if !record.ID.valid() || record.Sequence == 0 || !record.Class.valid() || record.Priority != priorityFor(record.Class) || record.PayloadSize == 0 || !validDigest(record.SHA256) || record.CreatedAt.IsZero() || record.AvailableAt.IsZero() || record.AvailableAt.Before(record.CreatedAt) || (record.Disposable && record.Class != ClassOrdinaryEvent) || record.Attempts > 0 && record.Fence == 0 {
		return false
	}
	if record.RetryReason != "" && (len(record.RetryReason) > MaximumReasonBytes || !opaqueValuePattern.MatchString(record.RetryReason)) {
		return false
	}
	switch record.State {
	case StateQueued:
		return record.LeaseOwner == "" && record.LeaseUntil.IsZero()
	case StateLeased:
		return record.Fence > 0 && record.LeaseOwner != "" && len(record.LeaseOwner) <= MaximumOwnerBytes && opaqueValuePattern.MatchString(record.LeaseOwner) && !record.LeaseUntil.IsZero()
	default:
		return false
	}
}

func validDiskRecord(manifest diskRecord) bool {
	if manifest.Schema != recordSchema || !validRecord(manifest.Record) {
		return false
	}
	manifestLeaf, payloadLeaf := recordLeaves(manifest.Record.Sequence)
	_ = manifestLeaf
	return manifest.PayloadLeaf == payloadLeaf && manifest.Record.ID == recordID(manifest.Record.Sequence, manifest.Record.Class, manifest.Record.SHA256)
}

func stableRecords(records map[RecordID]*diskRecord) []*diskRecord {
	values := make([]*diskRecord, 0, len(records))
	for _, record := range records {
		values = append(values, record)
	}
	sort.Slice(values, func(left, right int) bool {
		if values[left].Record.Priority != values[right].Record.Priority {
			return values[left].Record.Priority > values[right].Record.Priority
		}
		return values[left].Record.Sequence < values[right].Record.Sequence
	})
	return values
}

func usageFor(records map[RecordID]*diskRecord) (Usage, error) {
	var usage Usage
	for _, manifest := range records {
		value := manifest.Record
		classUsage := usage.For(value.Class)
		bytes, ok := add(classUsage.PayloadBytes, value.PayloadSize)
		if !ok || classUsage.Records == ^uint64(0) {
			return Usage{}, ErrIntegrity
		}
		classUsage.PayloadBytes, classUsage.Records = bytes, classUsage.Records+1
		switch value.Class {
		case ClassTerminalReceipt:
			usage.TerminalReceipt = classUsage
		case ClassAuditCheckpoint:
			usage.AuditCheckpoint = classUsage
		case ClassSecurityCheckpoint:
			usage.SecurityCheckpoint = classUsage
		case ClassOrdinaryEvent:
			usage.OrdinaryEvent = classUsage
		default:
			return Usage{}, ErrIntegrity
		}
		usage.TotalPayloadBytes, ok = add(usage.TotalPayloadBytes, value.PayloadSize)
		if !ok || usage.TotalRecords == ^uint64(0) {
			return Usage{}, ErrIntegrity
		}
		usage.TotalRecords++
		if value.Class == ClassOrdinaryEvent && value.Disposable && value.State == StateQueued {
			usage.EvictablePayloadBytes, ok = add(usage.EvictablePayloadBytes, value.PayloadSize)
			if !ok || usage.EvictableRecords == ^uint64(0) {
				return Usage{}, ErrIntegrity
			}
			usage.EvictableRecords++
		}
	}
	return usage, nil
}

func normalizeAvailable(now, available time.Time) (time.Time, error) {
	now = now.UTC()
	if available.IsZero() {
		return now, nil
	}
	available = available.UTC()
	if available.Before(now) {
		return now, nil
	}
	if available.After(now.Add(365 * 24 * time.Hour)) {
		return time.Time{}, ErrInvalid
	}
	return available, nil
}
