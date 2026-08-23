package capacity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sort"
	"time"
)

const Schema = `
CREATE TABLE IF NOT EXISTS capacity_series (
 tenant_id TEXT NOT NULL, resource_kind TEXT NOT NULL, resource_id TEXT NOT NULL,
 metric TEXT NOT NULL, unit TEXT NOT NULL, raw_interval_ns INTEGER NOT NULL,
 last_raw_ns INTEGER NOT NULL, created_at_ns INTEGER NOT NULL,
 PRIMARY KEY (tenant_id, resource_kind, resource_id, metric)
);
CREATE INDEX IF NOT EXISTS capacity_series_tenant ON capacity_series(tenant_id, resource_kind, resource_id, metric);
CREATE TABLE IF NOT EXISTS capacity_samples (
 tenant_id TEXT NOT NULL, resource_kind TEXT NOT NULL, resource_id TEXT NOT NULL,
 metric TEXT NOT NULL, unit TEXT NOT NULL, tier TEXT NOT NULL,
 observed_ns INTEGER NOT NULL, interval_ns INTEGER NOT NULL,
 minimum REAL NOT NULL, maximum REAL NOT NULL, value_sum REAL NOT NULL,
 sample_count INTEGER NOT NULL, p95 REAL NOT NULL, missing_count INTEGER NOT NULL,
 missing_reason TEXT NOT NULL,
 PRIMARY KEY (tenant_id, resource_kind, resource_id, metric, tier, observed_ns),
 CHECK (tier IN ('raw','hour','day')),
 CHECK (interval_ns > 0 AND sample_count >= 0 AND missing_count >= 0 AND sample_count + missing_count > 0)
);
CREATE INDEX IF NOT EXISTS capacity_samples_query ON capacity_samples(tenant_id, resource_kind, resource_id, metric, tier, observed_ns);
CREATE INDEX IF NOT EXISTS capacity_samples_compact ON capacity_samples(tier, observed_ns, tenant_id, resource_kind, resource_id, metric);
`

type SQLiteRepository struct {
	DB                     *sql.DB
	MaximumBatch           uint16
	MaximumSeriesPerTenant uint32
}

func (repository SQLiteRepository) Initialize(ctx context.Context) error {
	if repository.DB == nil || ctx == nil {
		return ErrInvalid
	}
	_, err := repository.DB.ExecContext(ctx, Schema)
	return err
}

func (repository SQLiteRepository) limits() (int, uint32) {
	batch := int(repository.MaximumBatch)
	if batch == 0 {
		batch = 500
	}
	series := repository.MaximumSeriesPerTenant
	if series == 0 {
		series = 10000
	}
	return batch, series
}

func (repository SQLiteRepository) Ingest(ctx context.Context, samples []MetricSample) error {
	maximumBatch, maximumSeries := repository.limits()
	if repository.DB == nil || ctx == nil || len(samples) == 0 || len(samples) > maximumBatch || maximumBatch > 1000 || maximumSeries > 100000 {
		return ErrInvalid
	}
	canonical := append([]MetricSample(nil), samples...)
	for index := range canonical {
		canonical[index].ObservedAt = canonical[index].ObservedAt.UTC()
		if canonical[index].Validate() != nil || canonical[index].ObservedAt.UnixNano() <= 0 || canonical[index].ObservedAt.UnixNano()%canonical[index].SampleInterval.Nanoseconds() != 0 {
			return ErrInvalid
		}
	}
	sort.Slice(canonical, func(left, right int) bool {
		leftKey, rightKey := sampleSeriesKey(canonical[left]), sampleSeriesKey(canonical[right])
		if leftKey != rightKey {
			return leftKey < rightKey
		}
		return canonical[left].ObservedAt.Before(canonical[right].ObservedAt)
	})
	deduplicated := canonical[:0]
	for _, sample := range canonical {
		if len(deduplicated) > 0 && sampleSeriesKey(deduplicated[len(deduplicated)-1]) == sampleSeriesKey(sample) && deduplicated[len(deduplicated)-1].ObservedAt.Equal(sample.ObservedAt) {
			if !sameMetricSample(deduplicated[len(deduplicated)-1], sample) {
				return ErrConflict
			}
			continue
		}
		deduplicated = append(deduplicated, sample)
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, sample := range deduplicated {
		if err = repository.ingestOne(ctx, tx, sample, maximumSeries); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (repository SQLiteRepository) ingestOne(ctx context.Context, tx *sql.Tx, sample MetricSample, maximumSeries uint32) error {
	var unit string
	var interval, last int64
	err := tx.QueryRowContext(ctx, `SELECT unit,raw_interval_ns,last_raw_ns FROM capacity_series WHERE tenant_id=? AND resource_kind=? AND resource_id=? AND metric=?`, sample.Scope.TenantID, sample.Scope.ResourceKind, sample.Scope.ResourceID, sample.Metric).Scan(&unit, &interval, &last)
	observed := sample.ObservedAt.UnixNano()
	if errors.Is(err, sql.ErrNoRows) {
		var count uint32
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM capacity_series WHERE tenant_id=?`, sample.Scope.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= maximumSeries {
			return ErrCardinality
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO capacity_series(tenant_id,resource_kind,resource_id,metric,unit,raw_interval_ns,last_raw_ns,created_at_ns) VALUES(?,?,?,?,?,?,?,?)`, sample.Scope.TenantID, sample.Scope.ResourceKind, sample.Scope.ResourceID, sample.Metric, sample.Unit, sample.SampleInterval.Nanoseconds(), observed, time.Now().UTC().UnixNano())
		if err != nil {
			return err
		}
		return insertRawSample(ctx, tx, sample)
	}
	if err != nil {
		return err
	}
	if Unit(unit) != sample.Unit || interval != sample.SampleInterval.Nanoseconds() {
		return ErrConflict
	}
	if observed <= last {
		var value float64
		var count, missing uint64
		var reason string
		err = tx.QueryRowContext(ctx, `SELECT value_sum,sample_count,missing_count,missing_reason FROM capacity_samples WHERE tenant_id=? AND resource_kind=? AND resource_id=? AND metric=? AND tier=? AND observed_ns=?`, sample.Scope.TenantID, sample.Scope.ResourceKind, sample.Scope.ResourceID, sample.Metric, TierRaw, observed).Scan(&value, &count, &missing, &reason)
		if err == nil && value == sample.Value && count == boolCount(!sample.Missing) && missing == boolCount(sample.Missing) && MissingReason(reason) == sample.MissingReason {
			return nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return ErrStaleSample
	}
	if observed-last < interval {
		return ErrStaleSample
	}
	if err = insertRawSample(ctx, tx, sample); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE capacity_series SET last_raw_ns=? WHERE tenant_id=? AND resource_kind=? AND resource_id=? AND metric=? AND last_raw_ns=?`, observed, sample.Scope.TenantID, sample.Scope.ResourceKind, sample.Scope.ResourceID, sample.Metric, last)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	return nil
}

func insertRawSample(ctx context.Context, tx *sql.Tx, sample MetricSample) error {
	minimum, maximum, sum, p95, count, missing, reason := sample.Value, sample.Value, sample.Value, sample.Value, uint64(1), uint64(0), ""
	if sample.Missing {
		minimum, maximum, sum, p95, count, missing, reason = 0, 0, 0, 0, 0, 1, string(sample.MissingReason)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO capacity_samples(tenant_id,resource_kind,resource_id,metric,unit,tier,observed_ns,interval_ns,minimum,maximum,value_sum,sample_count,p95,missing_count,missing_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, sample.Scope.TenantID, sample.Scope.ResourceKind, sample.Scope.ResourceID, sample.Metric, sample.Unit, TierRaw, sample.ObservedAt.UnixNano(), sample.SampleInterval.Nanoseconds(), minimum, maximum, sum, count, p95, missing, reason)
	return err
}

func (repository SQLiteRepository) QueryPoints(ctx context.Context, query PointQuery) (PointPage, error) {
	if repository.DB == nil || ctx == nil || query.Validate() != nil {
		return PointPage{}, ErrInvalid
	}
	query.From, query.Until = query.From.UTC(), query.Until.UTC()
	var unit string
	var rawInterval int64
	err := repository.DB.QueryRowContext(ctx, `SELECT unit,raw_interval_ns FROM capacity_series WHERE tenant_id=? AND resource_kind=? AND resource_id=? AND metric=?`, query.Scope.TenantID, query.Scope.ResourceKind, query.Scope.ResourceID, query.Metric).Scan(&unit, &rawInterval)
	if errors.Is(err, sql.ErrNoRows) {
		return PointPage{}, ErrNotFound
	}
	if err != nil {
		return PointPage{}, err
	}
	after := int64(0)
	if query.Cursor != "" {
		after, err = decodePointCursor(query)
		if err != nil {
			return PointPage{}, err
		}
	}
	rows, err := repository.DB.QueryContext(ctx, `SELECT observed_ns,interval_ns,minimum,maximum,value_sum,sample_count,p95,missing_count,missing_reason FROM capacity_samples WHERE tenant_id=? AND resource_kind=? AND resource_id=? AND metric=? AND tier=? AND observed_ns>=? AND observed_ns<? AND (?=0 OR observed_ns>?) ORDER BY observed_ns LIMIT ?`, query.Scope.TenantID, query.Scope.ResourceKind, query.Scope.ResourceID, query.Metric, query.Tier, query.From.UnixNano(), query.Until.UnixNano(), after, after, int(query.Limit)+1)
	if err != nil {
		return PointPage{}, err
	}
	defer rows.Close()
	points := make([]MetricPoint, 0, int(query.Limit)+1)
	for rows.Next() {
		point := MetricPoint{Scope:query.Scope,Metric:query.Metric,Unit:Unit(unit),Tier:query.Tier}
		var observed, interval int64
		var reason string
		if err = rows.Scan(&observed, &interval, &point.Minimum, &point.Maximum, &point.Sum, &point.Count, &point.P95, &point.MissingCount, &reason); err != nil {
			return PointPage{}, err
		}
		point.ObservedAt, point.SampleInterval, point.MissingReason = time.Unix(0, observed).UTC(), time.Duration(interval), MissingReason(reason)
		if point.validate() != nil {
			return PointPage{}, ErrIntegrity
		}
		points = append(points, point)
	}
	if err = rows.Err(); err != nil {
		return PointPage{}, err
	}
	next := ""
	if len(points) > int(query.Limit) {
		points = points[:query.Limit]
		next, err = encodePointCursor(query, points[len(points)-1].ObservedAt.UnixNano())
		if err != nil {
			return PointPage{}, err
		}
	}
	return PointPage{Points:points,NextCursor:next,RawSampleInterval:time.Duration(rawInterval),Unit:Unit(unit)}, nil
}

type pointCursor struct {
	Version uint8  `json:"version"`
	Query   string `json:"query"`
	AfterNS int64  `json:"after_ns"`
}

func pointQueryDigest(query PointQuery) (string, error) {
	value := struct {
		Scope MetricScope `json:"scope"`
		Metric MetricName `json:"metric"`
		Tier Tier `json:"tier"`
		From int64 `json:"from_ns"`
		Until int64 `json:"until_ns"`
	}{query.Scope,query.Metric,query.Tier,query.From.UTC().UnixNano(),query.Until.UTC().UnixNano()}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func encodePointCursor(query PointQuery, after int64) (string, error) {
	digest, err := pointQueryDigest(query)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(pointCursor{Version:1,Query:digest,AfterNS:after})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodePointCursor(query PointQuery) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(query.Cursor)
	if err != nil || len(raw) == 0 || len(raw) > 512 {
		return 0, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cursor pointCursor
	if decoder.Decode(&cursor) != nil || decoder.Decode(&struct{}{}) != io.EOF || cursor.Version != 1 || cursor.AfterNS < query.From.UTC().UnixNano() || cursor.AfterNS >= query.Until.UTC().UnixNano() {
		return 0, ErrInvalid
	}
	digest, err := pointQueryDigest(query)
	if err != nil || cursor.Query != digest {
		return 0, ErrInvalid
	}
	return cursor.AfterNS, nil
}

func (repository SQLiteRepository) Compact(ctx context.Context, policy RetentionPolicy, now time.Time) (CompactionResult, error) {
	if repository.DB == nil || ctx == nil || policy.Validate() != nil || now.IsZero() {
		return CompactionResult{}, ErrInvalid
	}
	now = now.UTC()
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil {
		return CompactionResult{}, err
	}
	defer tx.Rollback()
	remaining := int(policy.MaximumCompactionRows)
	result := CompactionResult{}
	rawRead, hourWritten, rawDeleted, more, err := compactMetricTier(ctx, tx, TierRaw, TierHour, policy.Hour.Resolution, now.Add(-policy.Raw.RetainFor).Truncate(policy.Hour.Resolution), remaining)
	if err != nil {
		return CompactionResult{}, err
	}
	result.RawRowsRead, result.HourRowsWritten, result.RowsDeleted = uint32(rawRead), uint32(hourWritten), uint32(rawDeleted)
	result.More = more
	remaining -= rawRead
	if remaining > 0 {
		hourRead, dayWritten, hourDeleted, hourMore, compactErr := compactMetricTier(ctx, tx, TierHour, TierDay, policy.Day.Resolution, now.Add(-policy.Hour.RetainFor).Truncate(policy.Day.Resolution), remaining)
		if compactErr != nil {
			return CompactionResult{}, compactErr
		}
		result.HourRowsRead, result.DayRowsWritten = uint32(hourRead), uint32(dayWritten)
		result.RowsDeleted += uint32(hourDeleted)
		result.More = result.More || hourMore
		remaining -= hourRead
	}
	if remaining > 0 {
		deleteLimit := remaining
		deleted, deleteErr := deleteExpiredDays(ctx, tx, now.Add(-policy.Day.RetainFor).Truncate(policy.Day.Resolution), deleteLimit)
		if deleteErr != nil {
			return CompactionResult{}, deleteErr
		}
		result.RowsDeleted += uint32(deleted)
		remaining -= deleted
		if deleted == deleteLimit {
			result.More = true
		}
	} else {
		result.More = true
	}
	if err = tx.Commit(); err != nil {
		return CompactionResult{}, err
	}
	return result, nil
}

type compactRow struct {
	Point MetricPoint
	ObservedNS int64
	BucketNS int64
}

func compactMetricTier(ctx context.Context, tx *sql.Tx, source, target Tier, resolution time.Duration, cutoff time.Time, maximum int) (int, int, int, bool, error) {
	if maximum <= 0 {
		return 0, 0, 0, true, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT tenant_id,resource_kind,resource_id,metric,unit,observed_ns,interval_ns,minimum,maximum,value_sum,sample_count,p95,missing_count,missing_reason FROM capacity_samples WHERE tier=? AND observed_ns<? ORDER BY tenant_id,resource_kind,resource_id,metric,observed_ns LIMIT ?`, source, cutoff.UnixNano(), maximum+1)
	if err != nil {
		return 0, 0, 0, false, err
	}
	items := make([]compactRow, 0, maximum+1)
	for rows.Next() {
		var item compactRow
		var reason string
		item.Point.Tier = source
		if err = rows.Scan(&item.Point.Scope.TenantID, &item.Point.Scope.ResourceKind, &item.Point.Scope.ResourceID, &item.Point.Metric, &item.Point.Unit, &item.ObservedNS, &item.Point.SampleInterval, &item.Point.Minimum, &item.Point.Maximum, &item.Point.Sum, &item.Point.Count, &item.Point.P95, &item.Point.MissingCount, &reason); err != nil {
			rows.Close()
			return 0, 0, 0, false, err
		}
		item.Point.ObservedAt, item.Point.MissingReason = time.Unix(0, item.ObservedNS).UTC(), MissingReason(reason)
		item.BucketNS = item.Point.ObservedAt.Truncate(resolution).UnixNano()
		if item.Point.validate() != nil {
			rows.Close()
			return 0, 0, 0, false, ErrIntegrity
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, 0, 0, false, err
	}
	more := len(items) > maximum
	if more {
		trailing := compactGroupKey(items[len(items)-1])
		for len(items) > 0 && compactGroupKey(items[len(items)-1]) == trailing {
			items = items[:len(items)-1]
		}
		if len(items) == 0 {
			return 0, 0, 0, true, ErrLimit
		}
	}
	read, written, deleted := 0, 0, 0
	for start := 0; start < len(items); {
		end := start + 1
		for end < len(items) && compactGroupKey(items[end]) == compactGroupKey(items[start]) {
			end++
		}
		group := items[start:end]
		aggregated, aggregateErr := aggregateCompactGroup(group, target, resolution)
		if aggregateErr != nil {
			return read, written, deleted, more, aggregateErr
		}
		if err = mergeCompactedPoint(ctx, tx, aggregated); err != nil {
			return read, written, deleted, more, err
		}
		deleteResult, deleteErr := tx.ExecContext(ctx, `DELETE FROM capacity_samples WHERE tenant_id=? AND resource_kind=? AND resource_id=? AND metric=? AND tier=? AND observed_ns>=? AND observed_ns<?`, aggregated.Scope.TenantID, aggregated.Scope.ResourceKind, aggregated.Scope.ResourceID, aggregated.Metric, source, aggregated.ObservedAt.UnixNano(), aggregated.ObservedAt.Add(resolution).UnixNano())
		if deleteErr != nil {
			return read, written, deleted, more, deleteErr
		}
		removed, deleteErr := deleteResult.RowsAffected()
		if deleteErr != nil || removed != int64(len(group)) {
			return read, written, deleted, more, ErrIntegrity
		}
		read += len(group)
		written++
		deleted += len(group)
		start = end
	}
	return read, written, deleted, more, nil
}

func aggregateCompactGroup(rows []compactRow, target Tier, resolution time.Duration) (MetricPoint, error) {
	if len(rows) == 0 {
		return MetricPoint{}, ErrInvalid
	}
	result := MetricPoint{Scope:rows[0].Point.Scope,Metric:rows[0].Point.Metric,Unit:rows[0].Point.Unit,Tier:target,SampleInterval:resolution,ObservedAt:time.Unix(0,rows[0].BucketNS).UTC()}
	weighted := make([]weightedMetricValue, 0, len(rows))
	for _, row := range rows {
		point := row.Point
		if point.Scope != result.Scope || point.Metric != result.Metric || point.Unit != result.Unit || row.BucketNS != result.ObservedAt.UnixNano() {
			return MetricPoint{}, ErrIntegrity
		}
		if point.Count > 0 {
			if result.Count == 0 {
				result.Minimum, result.Maximum = point.Minimum, point.Maximum
			} else {
				result.Minimum = math.Min(result.Minimum, point.Minimum)
				result.Maximum = math.Max(result.Maximum, point.Maximum)
			}
			result.Sum += point.Sum
			result.Count += point.Count
			weighted = append(weighted, weightedMetricValue{Value:point.P95,Weight:point.Count})
		}
		result.MissingCount += point.MissingCount
		result.MissingReason = combineMissingReason(result.MissingReason, point.MissingReason)
	}
	result.P95 = weightedP95(weighted)
	if result.validate() != nil {
		return MetricPoint{}, ErrIntegrity
	}
	return result, nil
}

func mergeCompactedPoint(ctx context.Context, tx *sql.Tx, point MetricPoint) error {
	existing, err := loadMetricPoint(ctx, tx, point)
	if err == nil {
		if existing.validate() != nil {
			return ErrIntegrity
		}
		combined, combineErr := aggregateCompactGroup([]compactRow{{Point:existing,BucketNS:point.ObservedAt.UnixNano()},{Point:point,BucketNS:point.ObservedAt.UnixNano()}}, point.Tier, point.SampleInterval)
		if combineErr != nil {
			return combineErr
		}
		point = combined
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO capacity_samples(tenant_id,resource_kind,resource_id,metric,unit,tier,observed_ns,interval_ns,minimum,maximum,value_sum,sample_count,p95,missing_count,missing_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,resource_kind,resource_id,metric,tier,observed_ns) DO UPDATE SET interval_ns=excluded.interval_ns,minimum=excluded.minimum,maximum=excluded.maximum,value_sum=excluded.value_sum,sample_count=excluded.sample_count,p95=excluded.p95,missing_count=excluded.missing_count,missing_reason=excluded.missing_reason`, point.Scope.TenantID, point.Scope.ResourceKind, point.Scope.ResourceID, point.Metric, point.Unit, point.Tier, point.ObservedAt.UnixNano(), point.SampleInterval.Nanoseconds(), point.Minimum, point.Maximum, point.Sum, point.Count, point.P95, point.MissingCount, point.MissingReason)
	return err
}

func loadMetricPoint(ctx context.Context, tx *sql.Tx, key MetricPoint) (MetricPoint, error) {
	point := MetricPoint{Scope:key.Scope,Metric:key.Metric,Unit:key.Unit,Tier:key.Tier,ObservedAt:key.ObservedAt}
	var interval int64
	var reason string
	err := tx.QueryRowContext(ctx, `SELECT interval_ns,minimum,maximum,value_sum,sample_count,p95,missing_count,missing_reason FROM capacity_samples WHERE tenant_id=? AND resource_kind=? AND resource_id=? AND metric=? AND tier=? AND observed_ns=?`, key.Scope.TenantID, key.Scope.ResourceKind, key.Scope.ResourceID, key.Metric, key.Tier, key.ObservedAt.UnixNano()).Scan(&interval, &point.Minimum, &point.Maximum, &point.Sum, &point.Count, &point.P95, &point.MissingCount, &reason)
	point.SampleInterval, point.MissingReason = time.Duration(interval), MissingReason(reason)
	return point, err
}

func deleteExpiredDays(ctx context.Context, tx *sql.Tx, cutoff time.Time, maximum int) (int, error) {
	result, err := tx.ExecContext(ctx, `DELETE FROM capacity_samples WHERE rowid IN (SELECT rowid FROM capacity_samples WHERE tier=? AND observed_ns<? ORDER BY observed_ns LIMIT ?)`, TierDay, cutoff.UnixNano(), maximum)
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	return int(deleted), err
}

type weightedMetricValue struct {
	Value float64
	Weight uint64
}

func weightedP95(values []weightedMetricValue) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(left, right int) bool { return values[left].Value < values[right].Value })
	var total uint64
	for _, value := range values {
		total += value.Weight
	}
	target := uint64(math.Ceil(float64(total) * .95))
	var current uint64
	for _, value := range values {
		current += value.Weight
		if current >= target {
			return value.Value
		}
	}
	return values[len(values)-1].Value
}

func combineMissingReason(left, right MissingReason) MissingReason {
	if right == "" {
		return left
	}
	if left == "" || left == right {
		return right
	}
	return MissingMixed
}

func compactGroupKey(row compactRow) string {
	return row.Point.Scope.TenantID + "\x00" + row.Point.Scope.ResourceKind + "\x00" + row.Point.Scope.ResourceID + "\x00" + string(row.Point.Metric) + "\x00" + string(row.Point.Unit) + "\x00" + string(row.Point.Tier) + "\x00" + time.Unix(0, row.BucketNS).UTC().Format(time.RFC3339Nano)
}

func sampleSeriesKey(sample MetricSample) string {
	return sample.Scope.TenantID + "\x00" + sample.Scope.ResourceKind + "\x00" + sample.Scope.ResourceID + "\x00" + string(sample.Metric)
}

func sameMetricSample(left, right MetricSample) bool {
	return left.Scope == right.Scope && left.Metric == right.Metric && left.Unit == right.Unit && left.SampleInterval == right.SampleInterval && left.ObservedAt.Equal(right.ObservedAt) && left.Value == right.Value && left.Missing == right.Missing && left.MissingReason == right.MissingReason
}

func boolCount(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
