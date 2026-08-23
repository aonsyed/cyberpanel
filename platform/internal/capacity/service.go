package capacity

import (
	"context"
	"math"
	"time"
)

type Aggregation string

const (
	AggregationMinimum Aggregation = "min"
	AggregationMaximum Aggregation = "max"
	AggregationMean    Aggregation = "mean"
	AggregationSum     Aggregation = "sum"
	AggregationCount   Aggregation = "count"
	AggregationP95     Aggregation = "p95"
)

func (aggregation Aggregation) Valid() bool {
	switch aggregation {
	case AggregationMinimum, AggregationMaximum, AggregationMean, AggregationSum, AggregationCount, AggregationP95:
		return true
	default:
		return false
	}
}

type PointStore interface {
	QueryPoints(context.Context, PointQuery) (PointPage, error)
}

type Service struct {
	Store PointStore
}

type QueryRequest struct {
	Scope               MetricScope  `json:"scope"`
	Metric              MetricName   `json:"metric"`
	SourceTier          Tier         `json:"source_tier"`
	From                time.Time    `json:"from"`
	Until               time.Time    `json:"until"`
	Interval            time.Duration `json:"interval"`
	Aggregation         Aggregation  `json:"aggregation"`
	MaximumSourcePoints uint32       `json:"maximum_source_points"`
}

func (request QueryRequest) validate() error {
	if request.Scope.Validate() != nil || !metricNamePattern.MatchString(string(request.Metric)) || !request.SourceTier.Valid() || !request.Aggregation.Valid() || request.From.IsZero() || request.From.Before(time.Unix(0, 0)) || !request.Until.After(request.From) || request.Interval < time.Second || request.Interval > 365*24*time.Hour || request.Until.Sub(request.From)%request.Interval != 0 || request.From.UTC().UnixNano()%request.Interval.Nanoseconds() != 0 || request.Until.Sub(request.From)/request.Interval > 2000 {
		return ErrInvalid
	}
	if request.MaximumSourcePoints > 50000 {
		return ErrInvalid
	}
	return nil
}

type GapReason string

const (
	GapNoSamples      GapReason = "no_samples"
	GapPartialCoverage GapReason = "partial_coverage"
	GapSourceMarked   GapReason = "source_marked_missing"
)

type MissingDataMarker struct {
	From                 time.Time `json:"from"`
	Until                time.Time `json:"until"`
	Reason               GapReason `json:"reason"`
	ExpectedSamples      uint64    `json:"expected_samples"`
	ObservedSamples      uint64    `json:"observed_samples"`
	SourceMissingSamples uint64    `json:"source_missing_samples"`
}

type AggregatePoint struct {
	From                 time.Time `json:"from"`
	Until                time.Time `json:"until"`
	Value                float64   `json:"value"`
	Available            bool      `json:"available"`
	Complete             bool      `json:"complete"`
	Approximate          bool      `json:"approximate"`
	SampleCount          uint64    `json:"sample_count"`
	ExpectedSamples      uint64    `json:"expected_samples"`
	SourceMissingSamples uint64    `json:"source_missing_samples"`
	MissingRatio         float64   `json:"missing_ratio"`
}

type MetricSeries struct {
	Scope             MetricScope        `json:"scope"`
	Metric            MetricName         `json:"metric"`
	Unit              Unit               `json:"unit"`
	SourceTier        Tier               `json:"source_tier"`
	RawSampleInterval time.Duration      `json:"raw_sample_interval"`
	Interval          time.Duration      `json:"interval"`
	Aggregation       Aggregation        `json:"aggregation"`
	From              time.Time          `json:"from"`
	Until             time.Time          `json:"until"`
	Points            []AggregatePoint   `json:"points"`
	Missing           []MissingDataMarker `json:"missing"`
	Approximate       bool               `json:"approximate"`
}

func (service Service) Query(ctx context.Context, request QueryRequest) (MetricSeries, error) {
	if service.Store == nil || ctx == nil || request.validate() != nil {
		return MetricSeries{}, ErrInvalid
	}
	request.From, request.Until = request.From.UTC(), request.Until.UTC()
	maximum := request.MaximumSourcePoints
	if maximum == 0 {
		maximum = 10000
	}
	query := PointQuery{Scope:request.Scope,Metric:request.Metric,Tier:request.SourceTier,From:request.From,Until:request.Until,Limit:1000}
	points := make([]MetricPoint, 0)
	var rawInterval time.Duration
	var unit Unit
	for {
		page, err := service.Store.QueryPoints(ctx, query)
		if err != nil {
			return MetricSeries{}, err
		}
		if rawInterval == 0 {
			rawInterval, unit = page.RawSampleInterval, page.Unit
		} else if page.RawSampleInterval != rawInterval || page.Unit != unit {
			return MetricSeries{}, ErrIntegrity
		}
		if uint64(len(points))+uint64(len(page.Points)) > uint64(maximum) {
			return MetricSeries{}, ErrLimit
		}
		points = append(points, page.Points...)
		if page.NextCursor == "" {
			break
		}
		query.Cursor = page.NextCursor
	}
	if rawInterval < time.Second || rawInterval > 24*time.Hour || request.Interval%rawInterval != 0 {
		return MetricSeries{}, ErrInvalid
	}
	sourceInterval := rawInterval
	if request.SourceTier == TierHour {
		sourceInterval = time.Hour
	} else if request.SourceTier == TierDay {
		sourceInterval = 24 * time.Hour
	}
	if request.Interval < sourceInterval || request.Interval%sourceInterval != 0 || request.From.UnixNano()%sourceInterval.Nanoseconds() != 0 {
		return MetricSeries{}, ErrInvalid
	}
	for index, point := range points {
		if point.Scope != request.Scope || point.Metric != request.Metric || point.Unit != unit || point.Tier != request.SourceTier || point.SampleInterval != sourceInterval || point.ObservedAt.Before(request.From) || !point.ObservedAt.Before(request.Until) || point.ObservedAt.UnixNano()%sourceInterval.Nanoseconds() != 0 || index > 0 && !point.ObservedAt.After(points[index-1].ObservedAt) {
			return MetricSeries{}, ErrIntegrity
		}
	}
	series := MetricSeries{Scope:request.Scope,Metric:request.Metric,Unit:unit,SourceTier:request.SourceTier,RawSampleInterval:rawInterval,Interval:request.Interval,Aggregation:request.Aggregation,From:request.From,Until:request.Until}
	pointIndex := 0
	for start := request.From; start.Before(request.Until); start = start.Add(request.Interval) {
		end := start.Add(request.Interval)
		bucketStart := pointIndex
		for pointIndex < len(points) && points[pointIndex].ObservedAt.Before(end) {
			pointIndex++
		}
		aggregate, marker, err := aggregateInterval(points[bucketStart:pointIndex], start, end, rawInterval, request.Aggregation, request.SourceTier)
		if err != nil {
			return MetricSeries{}, err
		}
		series.Points = append(series.Points, aggregate)
		if marker != nil {
			series.Missing = append(series.Missing, *marker)
		}
		series.Approximate = series.Approximate || aggregate.Approximate
	}
	return series, nil
}

func aggregateInterval(points []MetricPoint, from, until time.Time, rawInterval time.Duration, aggregation Aggregation, tier Tier) (AggregatePoint, *MissingDataMarker, error) {
	expected := uint64(until.Sub(from) / rawInterval)
	if expected == 0 {
		return AggregatePoint{}, nil, ErrInvalid
	}
	result := AggregatePoint{From:from,Until:until,ExpectedSamples:expected,Approximate:aggregation == AggregationP95 && tier != TierRaw}
	weighted := make([]weightedMetricValue, 0, len(points))
	var minimum, maximum, sum float64
	var count, sourceMissing uint64
	for _, point := range points {
		if point.validate() != nil || point.ObservedAt.Before(from) || !point.ObservedAt.Before(until) || count > expected || sourceMissing > expected-count || point.Count > expected-count-sourceMissing {
			return AggregatePoint{}, nil, ErrIntegrity
		}
		remaining := expected - count - sourceMissing - point.Count
		if point.MissingCount > remaining {
			return AggregatePoint{}, nil, ErrIntegrity
		}
		if point.Count > 0 {
			if count == 0 {
				minimum, maximum = point.Minimum, point.Maximum
			} else {
				minimum, maximum = math.Min(minimum, point.Minimum), math.Max(maximum, point.Maximum)
			}
			sum += point.Sum
			weighted = append(weighted, weightedMetricValue{Value:point.P95,Weight:point.Count})
			count += point.Count
		}
		sourceMissing += point.MissingCount
	}
	result.SampleCount, result.SourceMissingSamples = count, sourceMissing
	result.MissingRatio = float64(expected-count) / float64(expected)
	result.Available, result.Complete = count > 0, count == expected
	if result.Available {
		switch aggregation {
		case AggregationMinimum:
			result.Value = minimum
		case AggregationMaximum:
			result.Value = maximum
		case AggregationMean:
			result.Value = sum / float64(count)
		case AggregationSum:
			result.Value = sum
		case AggregationCount:
			result.Value = float64(count)
		case AggregationP95:
			result.Value = weightedP95(weighted)
		default:
			return AggregatePoint{}, nil, ErrInvalid
		}
		if math.IsNaN(result.Value) || math.IsInf(result.Value, 0) {
			return AggregatePoint{}, nil, ErrIntegrity
		}
	}
	if result.Complete {
		return result, nil, nil
	}
	reason := GapPartialCoverage
	if count == 0 && sourceMissing == 0 {
		reason = GapNoSamples
	} else if count == 0 && sourceMissing > 0 {
		reason = GapSourceMarked
	}
	marker := &MissingDataMarker{From:from,Until:until,Reason:reason,ExpectedSamples:expected,ObservedSamples:count,SourceMissingSamples:sourceMissing}
	return result, marker, nil
}

type ForecastRequest struct {
	Query           QueryRequest `json:"query"`
	Horizon         time.Duration `json:"horizon"`
	MinimumSamples  uint16       `json:"minimum_samples"`
	MinimumCoverage float64      `json:"minimum_coverage"`
	CapacityLimit   *float64     `json:"capacity_limit,omitempty"`
}

type ForecastEvidence struct {
	Key   string  `json:"key"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

type CapacityRecommendation struct {
	Code     string             `json:"code"`
	Evidence []ForecastEvidence `json:"evidence"`
}

type CapacityForecast struct {
	Scope              MetricScope             `json:"scope"`
	Metric             MetricName              `json:"metric"`
	Unit               Unit                    `json:"unit"`
	ObservationFrom    time.Time               `json:"observation_from"`
	ObservationUntil   time.Time               `json:"observation_until"`
	Horizon            time.Duration           `json:"horizon"`
	ForecastAt         time.Time               `json:"forecast_at"`
	SlopePerSecond     float64                 `json:"slope_per_second"`
	ForecastValue      float64                 `json:"forecast_value"`
	Lower95            float64                 `json:"lower_95"`
	Upper95            float64                 `json:"upper_95"`
	Confidence         float64                 `json:"confidence"`
	Uncertainty        float64                 `json:"uncertainty"`
	MissingRatio       float64                 `json:"missing_ratio"`
	Samples            uint32                  `json:"samples"`
	Recommendation     CapacityRecommendation  `json:"recommendation"`
}

func (service Service) Forecast(ctx context.Context, request ForecastRequest) (CapacityForecast, error) {
	minimumSamples := request.MinimumSamples
	if minimumSamples == 0 {
		minimumSamples = 24
	}
	minimumCoverage := request.MinimumCoverage
	if minimumCoverage == 0 {
		minimumCoverage = .8
	}
	if minimumSamples < 24 || minimumSamples > 2000 || minimumCoverage < .8 || minimumCoverage > 1 || request.Horizon < request.Query.Interval || request.Horizon > 365*24*time.Hour || request.CapacityLimit != nil && (*request.CapacityLimit <= 0 || math.IsNaN(*request.CapacityLimit) || math.IsInf(*request.CapacityLimit, 0)) {
		return CapacityForecast{}, ErrInvalid
	}
	request.Query.Aggregation = AggregationMean
	series, err := service.Query(ctx, request.Query)
	if err != nil {
		return CapacityForecast{}, err
	}
	xs, ys := make([]float64, 0, len(series.Points)), make([]float64, 0, len(series.Points))
	var expected, observed uint64
	for _, point := range series.Points {
		expected += point.ExpectedSamples
		observed += point.SampleCount
		if point.Available {
			xs = append(xs, point.Until.Sub(series.From).Seconds())
			ys = append(ys, point.Value)
		}
	}
	coverage := float64(observed) / float64(expected)
	missingRatio := 1 - coverage
	if len(xs) < int(minimumSamples) || coverage < minimumCoverage {
		return CapacityForecast{}, ErrInsufficientEvidence
	}
	meanX, meanY := meanFloat64(xs), meanFloat64(ys)
	var sxx, sxy float64
	for index := range xs {
		dx := xs[index] - meanX
		sxx += dx * dx
		sxy += dx * (ys[index] - meanY)
	}
	if sxx <= 0 || math.IsInf(sxx, 0) {
		return CapacityForecast{}, ErrInsufficientEvidence
	}
	slope := sxy / sxx
	intercept := meanY - slope*meanX
	forecastX := series.Until.Sub(series.From).Seconds() + request.Horizon.Seconds()
	forecastValue := intercept + slope*forecastX
	var residualSum, totalSum float64
	for index := range xs {
		residual := ys[index] - (intercept + slope*xs[index])
		residualSum += residual * residual
		difference := ys[index] - meanY
		totalSum += difference * difference
	}
	rSquared := 1.0
	if totalSum > 0 {
		rSquared = math.Max(0, math.Min(1, 1-residualSum/totalSum))
	}
	residualDeviation := 0.0
	if len(xs) > 2 {
		residualDeviation = math.Sqrt(residualSum / float64(len(xs)-2))
	}
	uncertainty := 1.96 * residualDeviation * math.Sqrt(1+1/float64(len(xs))+(forecastX-meanX)*(forecastX-meanX)/sxx)
	confidence := math.Max(0, math.Min(1, rSquared*coverage))
	if math.IsNaN(slope) || math.IsInf(slope, 0) || math.IsNaN(forecastValue) || math.IsInf(forecastValue, 0) || math.IsNaN(uncertainty) || math.IsInf(uncertainty, 0) {
		return CapacityForecast{}, ErrIntegrity
	}
	forecast := CapacityForecast{Scope:series.Scope,Metric:series.Metric,Unit:series.Unit,ObservationFrom:series.From,ObservationUntil:series.Until,Horizon:request.Horizon,ForecastAt:series.Until.Add(request.Horizon),SlopePerSecond:slope,ForecastValue:forecastValue,Lower95:forecastValue-uncertainty,Upper95:forecastValue+uncertainty,Confidence:confidence,Uncertainty:uncertainty,MissingRatio:missingRatio,Samples:uint32(len(xs))}
	forecast.Recommendation = capacityRecommendation(forecast, request.CapacityLimit, coverage)
	return forecast, nil
}

func capacityRecommendation(forecast CapacityForecast, limit *float64, coverage float64) CapacityRecommendation {
	code := "evidence_stable"
	if limit != nil && forecast.Upper95 >= *limit {
		code = "review_capacity_before_horizon"
	} else if forecast.SlopePerSecond > 0 && forecast.Confidence >= .5 {
		code = "monitor_growth"
	}
	evidence := []ForecastEvidence{
		{Key:"sample_count",Value:float64(forecast.Samples),Unit:"intervals"},
		{Key:"coverage",Value:coverage,Unit:"ratio"},
		{Key:"missing_ratio",Value:forecast.MissingRatio,Unit:"ratio"},
		{Key:"slope_per_second",Value:forecast.SlopePerSecond,Unit:string(forecast.Unit)+"/second"},
		{Key:"forecast_upper_95",Value:forecast.Upper95,Unit:string(forecast.Unit)},
	}
	if limit != nil {
		evidence = append(evidence, ForecastEvidence{Key:"capacity_limit",Value:*limit,Unit:string(forecast.Unit)})
	}
	return CapacityRecommendation{Code:code,Evidence:evidence}
}

func meanFloat64(values []float64) float64 {
	var sum float64
	for _, value := range values {
		sum += value
	}
	return sum / float64(len(values))
}
