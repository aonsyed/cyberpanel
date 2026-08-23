package capacity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	MaximumUsageExportRows = 10000
	maximumUsageExportBytes = 16 << 20
)

type UsageDimension string

const (
	UsagePlan     UsageDimension = "plan"
	UsageStorage  UsageDimension = "storage"
	UsageTraffic  UsageDimension = "traffic"
	UsageCPU      UsageDimension = "cpu"
	UsageMail     UsageDimension = "mail"
	UsageBackup   UsageDimension = "backup"
	UsageProvider UsageDimension = "provider"
	UsageCampaign UsageDimension = "campaign"
)

func (dimension UsageDimension) Valid() bool {
	switch dimension {
	case UsagePlan, UsageStorage, UsageTraffic, UsageCPU, UsageMail, UsageBackup, UsageProvider, UsageCampaign:
		return true
	default:
		return false
	}
}

type UsageRow struct {
	TenantID      string         `json:"tenant_id"`
	Dimension     UsageDimension `json:"dimension"`
	ResourceKind  string         `json:"resource_kind"`
	ResourceID    string         `json:"resource_id"`
	Metric        MetricName     `json:"metric"`
	Unit          Unit           `json:"unit"`
	IntervalStart time.Time      `json:"interval_start"`
	IntervalEnd   time.Time      `json:"interval_end"`
	Quantity      int64          `json:"quantity"`
	Scale         uint8          `json:"scale"`
	SourceDigest  string         `json:"source_digest"`
}

func (row UsageRow) validate(periodStart, periodEnd time.Time) error {
	if !capacityIDPattern.MatchString(row.TenantID) || !row.Dimension.Valid() || !metricNamePattern.MatchString(row.ResourceKind) || !capacityIDPattern.MatchString(row.ResourceID) || !metricNamePattern.MatchString(string(row.Metric)) || !row.Unit.Valid() || row.IntervalStart.IsZero() || !row.IntervalEnd.After(row.IntervalStart) || row.IntervalStart.Before(periodStart) || row.IntervalEnd.After(periodEnd) || row.Quantity < 0 || row.Scale > 9 || !validUsageDigest(row.SourceDigest) {
		return ErrInvalid
	}
	return nil
}

func (row UsageRow) canonical() UsageRow {
	row.IntervalStart, row.IntervalEnd = row.IntervalStart.UTC(), row.IntervalEnd.UTC()
	if row.Quantity == 0 {
		row.Scale = 0
	}
	for row.Scale > 0 && row.Quantity%10 == 0 {
		row.Quantity /= 10
		row.Scale--
	}
	return row
}

type SignatureAlgorithm string

const (
	SignatureEd25519       SignatureAlgorithm = "ed25519"
	SignatureECDSAP256SHA256 SignatureAlgorithm = "ecdsa_p256_sha256"
)

func (algorithm SignatureAlgorithm) Valid() bool {
	return algorithm == SignatureEd25519 || algorithm == SignatureECDSAP256SHA256
}

type Signer interface {
	KeyID() string
	Algorithm() SignatureAlgorithm
	Sign(context.Context, []byte) ([]byte, error)
}

type UsageExportRequest struct {
	ExportID    string     `json:"export_id"`
	PeriodStart time.Time  `json:"period_start"`
	PeriodEnd   time.Time  `json:"period_end"`
	GeneratedAt time.Time  `json:"generated_at"`
	Rows        []UsageRow `json:"rows"`
}

type UsageExport struct {
	SchemaVersion uint32             `json:"schema_version"`
	ExportID      string             `json:"export_id"`
	PeriodStart   time.Time          `json:"period_start"`
	PeriodEnd     time.Time          `json:"period_end"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Rows          []UsageRow         `json:"rows"`
	Digest        string             `json:"digest"`
	KeyID         string             `json:"key_id"`
	Algorithm     SignatureAlgorithm `json:"algorithm"`
	Signature     string             `json:"signature"`
}

type usageExportPayload struct {
	SchemaVersion uint32     `json:"schema_version"`
	ExportID      string     `json:"export_id"`
	PeriodStart   time.Time  `json:"period_start"`
	PeriodEnd     time.Time  `json:"period_end"`
	GeneratedAt   time.Time  `json:"generated_at"`
	Rows          []UsageRow `json:"rows"`
}

func BuildUsageExport(ctx context.Context, request UsageExportRequest, signer Signer) (UsageExport, error) {
	if ctx == nil || signer == nil || !capacityIDPattern.MatchString(request.ExportID) || request.PeriodStart.IsZero() || !request.PeriodEnd.After(request.PeriodStart) || request.PeriodEnd.Sub(request.PeriodStart) > 10*365*24*time.Hour || request.GeneratedAt.Before(request.PeriodEnd) || request.GeneratedAt.After(request.PeriodEnd.Add(30*24*time.Hour)) || len(request.Rows) == 0 || len(request.Rows) > MaximumUsageExportRows || !capacityIDPattern.MatchString(signer.KeyID()) || !signer.Algorithm().Valid() {
		return UsageExport{}, ErrInvalid
	}
	request.PeriodStart, request.PeriodEnd, request.GeneratedAt = request.PeriodStart.UTC(), request.PeriodEnd.UTC(), request.GeneratedAt.UTC()
	rows := append([]UsageRow(nil), request.Rows...)
	for index := range rows {
		rows[index] = rows[index].canonical()
		if rows[index].validate(request.PeriodStart, request.PeriodEnd) != nil {
			return UsageExport{}, ErrInvalid
		}
	}
	sort.Slice(rows, func(left, right int) bool { return usageRowSortKey(rows[left]) < usageRowSortKey(rows[right]) })
	for index := 1; index < len(rows); index++ {
		if usageRowIdentity(rows[index-1]) == usageRowIdentity(rows[index]) {
			return UsageExport{}, ErrConflict
		}
	}
	payload := usageExportPayload{SchemaVersion:1,ExportID:request.ExportID,PeriodStart:request.PeriodStart,PeriodEnd:request.PeriodEnd,GeneratedAt:request.GeneratedAt,Rows:rows}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) == 0 || len(raw) > maximumUsageExportBytes {
		return UsageExport{}, ErrLimit
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	message := append([]byte("capacity.usage_export.v1\x00"), sum[:]...)
	signature, err := signer.Sign(ctx, message)
	if err != nil {
		return UsageExport{}, err
	}
	if len(signature) == 0 || len(signature) > 8192 {
		return UsageExport{}, ErrIntegrity
	}
	return UsageExport{SchemaVersion:1,ExportID:request.ExportID,PeriodStart:request.PeriodStart,PeriodEnd:request.PeriodEnd,GeneratedAt:request.GeneratedAt,Rows:rows,Digest:digest,KeyID:signer.KeyID(),Algorithm:signer.Algorithm(),Signature:base64.RawStdEncoding.EncodeToString(signature)}, nil
}

func (export UsageExport) VerifyDigest() error {
	if export.SchemaVersion != 1 || !capacityIDPattern.MatchString(export.ExportID) || export.PeriodStart.IsZero() || !export.PeriodEnd.After(export.PeriodStart) || export.PeriodEnd.Sub(export.PeriodStart) > 10*365*24*time.Hour || export.GeneratedAt.Before(export.PeriodEnd) || export.GeneratedAt.After(export.PeriodEnd.Add(30*24*time.Hour)) || !export.Algorithm.Valid() || !capacityIDPattern.MatchString(export.KeyID) || !validUsageDigest(export.Digest) || len(export.Rows) == 0 || len(export.Rows) > MaximumUsageExportRows || len(export.Signature) == 0 || len(export.Signature) > 12000 {
		return ErrInvalid
	}
	for index, row := range export.Rows {
		if row != row.canonical() || row.validate(export.PeriodStart, export.PeriodEnd) != nil || index > 0 && usageRowSortKey(export.Rows[index-1]) >= usageRowSortKey(row) {
			return ErrIntegrity
		}
	}
	payload := usageExportPayload{SchemaVersion:export.SchemaVersion,ExportID:export.ExportID,PeriodStart:export.PeriodStart.UTC(),PeriodEnd:export.PeriodEnd.UTC(),GeneratedAt:export.GeneratedAt.UTC(),Rows:export.Rows}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) == 0 || len(raw) > maximumUsageExportBytes {
		return ErrIntegrity
	}
	sum := sha256.Sum256(raw)
	if export.Digest != hex.EncodeToString(sum[:]) {
		return ErrIntegrity
	}
	if signature, decodeErr := base64.RawStdEncoding.DecodeString(export.Signature); decodeErr != nil || len(signature) == 0 || len(signature) > 8192 {
		return ErrIntegrity
	}
	return nil
}

func usageRowIdentity(row UsageRow) string {
	return strings.Join([]string{row.TenantID,string(row.Dimension),row.ResourceKind,row.ResourceID,string(row.Metric),string(row.Unit),row.IntervalStart.UTC().Format(time.RFC3339Nano),row.IntervalEnd.UTC().Format(time.RFC3339Nano)}, "\x00")
}

func usageRowSortKey(row UsageRow) string {
	return usageRowIdentity(row) + "\x00" + row.SourceDigest + "\x00" + formatUsageQuantity(row.Quantity, row.Scale)
}

func formatUsageQuantity(quantity int64, scale uint8) string {
	if scale == 0 {
		return decimalInt64(quantity)
	}
	divisor := int64(math.Pow10(int(scale)))
	whole, fraction := quantity/divisor, quantity%divisor
	value := decimalInt64(whole) + "."
	digits := decimalInt64(fraction)
	for len(digits) < int(scale) {
		digits = "0" + digits
	}
	return value + digits
}

func decimalInt64(value int64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[position:])
}

func validUsageDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
