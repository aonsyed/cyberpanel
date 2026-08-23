package maintenance

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var zonePattern = regexp.MustCompile(`^(UTC|[A-Za-z][A-Za-z0-9_+.-]*(/[A-Za-z0-9_+.-]+)+)$`)

type span struct {
	startsAt time.Time
	endsAt   time.Time
}

type schedulePosition struct {
	previous *span
	current  *span
	next     *span
}

type civilDate struct {
	year  int
	month time.Month
	day   int
}

func normalizedLocation(name string) (*time.Location, error) {
	if len(name) == 0 || len(name) > 128 || !zonePattern.MatchString(name) || strings.Contains(name, "..") || name == "Local" {
		return nil, ErrInvalid
	}
	location, err := time.LoadLocation(name)
	if err != nil || location.String() != name {
		return nil, ErrInvalid
	}
	return location, nil
}

func validateSchedule(schedule Schedule, maximum time.Duration) error {
	switch schedule.Kind {
	case ScheduleAbsolute:
		if !validTimestamp(schedule.StartAt) || !validTimestamp(schedule.EndAt) || !schedule.EndAt.After(schedule.StartAt) || schedule.EndAt.Sub(schedule.StartAt) > maximum || !zeroRecurrence(schedule.Recurrence) {
			return ErrInvalid
		}
	case ScheduleWeekly:
		if !schedule.StartAt.IsZero() || !schedule.EndAt.IsZero() {
			return ErrInvalid
		}
		recurrence := schedule.Recurrence
		if len(recurrence.Weekdays) == 0 || len(recurrence.Weekdays) > 7 || recurrence.LocalStartMinute >= 24*60 || recurrence.Duration < time.Minute || recurrence.Duration > maximum || recurrence.Duration >= 7*24*time.Hour {
			return ErrInvalid
		}
		for index, weekday := range recurrence.Weekdays {
			if !weekday.Valid() || index > 0 && recurrence.Weekdays[index-1] >= weekday {
				return ErrInvalid
			}
		}
		from, err := parseCivilDate(recurrence.EffectiveFrom)
		if err != nil {
			return err
		}
		if recurrence.EffectiveUntil != "" {
			until, err := parseCivilDate(recurrence.EffectiveUntil)
			if err != nil || compareCivil(until, from) < 0 {
				return ErrInvalid
			}
		}
		if recurrence.Fold != FoldEarlier && recurrence.Fold != FoldLater && recurrence.Fold != FoldReject || recurrence.Gap != GapSkip && recurrence.Gap != GapNextValid && recurrence.Gap != GapReject {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func scheduleDuration(schedule Schedule) time.Duration {
	if schedule.Kind == ScheduleAbsolute {
		return schedule.EndAt.Sub(schedule.StartAt)
	}
	return schedule.Recurrence.Duration
}

func zeroRecurrence(recurrence Recurrence) bool {
	return len(recurrence.Weekdays) == 0 && recurrence.LocalStartMinute == 0 && recurrence.Duration == 0 &&
		recurrence.EffectiveFrom == "" && recurrence.EffectiveUntil == "" && recurrence.Fold == "" && recurrence.Gap == ""
}

func resolveSchedule(window Window, at time.Time) (schedulePosition, error) {
	if err := window.Validate(); err != nil || !validTimestamp(at) {
		if err != nil {
			return schedulePosition{}, err
		}
		return schedulePosition{}, ErrInvalid
	}
	if window.Schedule.Kind == ScheduleAbsolute {
		candidate := span{startsAt: window.Schedule.StartAt, endsAt: window.Schedule.EndAt}
		return positionFromSpans([]span{candidate}, at), nil
	}
	location, err := normalizedLocation(window.TimeZone)
	if err != nil {
		return schedulePosition{}, err
	}
	recurrence := window.Schedule.Recurrence
	localAt := at.In(location)
	anchor := civilDate{year: localAt.Year(), month: localAt.Month(), day: localAt.Day()}
	anchors := []civilDate{anchor}
	from, _ := parseCivilDate(recurrence.EffectiveFrom)
	if compareCivil(from, addCivilDays(anchor, 15)) > 0 {
		anchors = append(anchors, from)
	}
	if recurrence.EffectiveUntil != "" {
		until, _ := parseCivilDate(recurrence.EffectiveUntil)
		if compareCivil(until, addCivilDays(anchor, -8)) < 0 {
			anchors = append(anchors, until)
		}
	}
	dateSet := make(map[string]civilDate, len(anchors)*24)
	for _, item := range anchors {
		for offset := -8; offset <= 15; offset++ {
			date := addCivilDays(item, offset)
			dateSet[formatCivilDate(date)] = date
		}
	}
	spans := make([]span, 0, len(dateSet))
	for _, date := range dateSet {
		if !recurrenceIncludesDate(recurrence, date) {
			continue
		}
		start, exists, err := resolveLocalMinute(location, date, recurrence.LocalStartMinute, recurrence.Fold, recurrence.Gap)
		if err != nil {
			return schedulePosition{}, err
		}
		if !exists {
			continue
		}
		end := start.Add(recurrence.Duration)
		if !validTimestamp(start) || !validTimestamp(end) {
			return schedulePosition{}, ErrInvalid
		}
		spans = append(spans, span{startsAt: start, endsAt: end})
	}
	sort.Slice(spans, func(left, right int) bool { return spans[left].startsAt.Before(spans[right].startsAt) })
	spans = deduplicateSpans(spans)
	return positionFromSpans(spans, at), nil
}

func positionFromSpans(spans []span, at time.Time) schedulePosition {
	var position schedulePosition
	for index := range spans {
		candidate := spans[index]
		if !at.Before(candidate.startsAt) && at.Before(candidate.endsAt) {
			copy := candidate
			position.current = &copy
			continue
		}
		if !candidate.endsAt.After(at) {
			if position.previous == nil || candidate.startsAt.After(position.previous.startsAt) {
				copy := candidate
				position.previous = &copy
			}
			continue
		}
		if candidate.startsAt.After(at) && (position.next == nil || candidate.startsAt.Before(position.next.startsAt)) {
			copy := candidate
			position.next = &copy
		}
	}
	return position
}

func resolveLocalMinute(location *time.Location, date civilDate, minute uint16, fold FoldPolicy, gap GapPolicy) (time.Time, bool, error) {
	hour := int(minute) / 60
	minuteOfHour := int(minute) % 60
	wall := time.Date(date.year, date.month, date.day, hour, minuteOfHour, 0, 0, time.UTC)
	offsets := nearbyOffsets(location, wall)
	candidates := matchingWallTimes(location, wall, offsets)
	if len(candidates) == 1 {
		return candidates[0], true, nil
	}
	if len(candidates) > 1 {
		switch fold {
		case FoldEarlier:
			return candidates[0], true, nil
		case FoldLater:
			return candidates[len(candidates)-1], true, nil
		default:
			return time.Time{}, false, ErrClockPolicy
		}
	}
	switch gap {
	case GapSkip:
		return time.Time{}, false, nil
	case GapReject:
		return time.Time{}, false, ErrClockPolicy
	case GapNextValid:
		for offset := 1; offset <= 26*60; offset++ {
			shifted := wall.Add(time.Duration(offset) * time.Minute)
			candidates = matchingWallTimes(location, shifted, offsets)
			if len(candidates) == 0 {
				continue
			}
			if len(candidates) > 1 && fold == FoldReject {
				return time.Time{}, false, ErrClockPolicy
			}
			if fold == FoldLater {
				return candidates[len(candidates)-1], true, nil
			}
			return candidates[0], true, nil
		}
		return time.Time{}, false, ErrClockPolicy
	default:
		return time.Time{}, false, ErrInvalid
	}
}

func nearbyOffsets(location *time.Location, wall time.Time) []int {
	set := make(map[int]struct{})
	for hours := -48; hours <= 48; hours++ {
		_, offset := wall.Add(time.Duration(hours) * time.Hour).In(location).Zone()
		set[offset] = struct{}{}
	}
	offsets := make([]int, 0, len(set))
	for offset := range set {
		offsets = append(offsets, offset)
	}
	sort.Ints(offsets)
	return offsets
}

func matchingWallTimes(location *time.Location, wall time.Time, offsets []int) []time.Time {
	candidates := make([]time.Time, 0, 2)
	for _, offset := range offsets {
		candidate := wall.Add(-time.Duration(offset) * time.Second)
		local := candidate.In(location)
		if local.Year() == wall.Year() && local.Month() == wall.Month() && local.Day() == wall.Day() && local.Hour() == wall.Hour() && local.Minute() == wall.Minute() {
			candidates = append(candidates, candidate.UTC())
		}
	}
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].Before(candidates[right]) })
	return candidates
}

func recurrenceIncludesDate(recurrence Recurrence, date civilDate) bool {
	formatted := formatCivilDate(date)
	if formatted < recurrence.EffectiveFrom || recurrence.EffectiveUntil != "" && formatted > recurrence.EffectiveUntil {
		return false
	}
	weekday := isoWeekday(time.Date(date.year, date.month, date.day, 0, 0, 0, 0, time.UTC).Weekday())
	index := sort.Search(len(recurrence.Weekdays), func(index int) bool { return recurrence.Weekdays[index] >= weekday })
	return index < len(recurrence.Weekdays) && recurrence.Weekdays[index] == weekday
}

func isoWeekday(weekday time.Weekday) Weekday {
	if weekday == time.Sunday {
		return Sunday
	}
	return Weekday(weekday)
}

func parseCivilDate(value string) (civilDate, error) {
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil || parsed.Format("2006-01-02") != value || !validTimestamp(parsed.UTC()) {
		return civilDate{}, ErrInvalid
	}
	return civilDate{year: parsed.Year(), month: parsed.Month(), day: parsed.Day()}, nil
}

func formatCivilDate(date civilDate) string {
	return time.Date(date.year, date.month, date.day, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
}

func addCivilDays(date civilDate, days int) civilDate {
	value := time.Date(date.year, date.month, date.day+days, 0, 0, 0, 0, time.UTC)
	return civilDate{year: value.Year(), month: value.Month(), day: value.Day()}
}

func compareCivil(left, right civilDate) int {
	leftText, rightText := formatCivilDate(left), formatCivilDate(right)
	return strings.Compare(leftText, rightText)
}

func deduplicateSpans(spans []span) []span {
	if len(spans) < 2 {
		return spans
	}
	result := spans[:1]
	for _, candidate := range spans[1:] {
		last := result[len(result)-1]
		if candidate.startsAt.Equal(last.startsAt) && candidate.endsAt.Equal(last.endsAt) {
			continue
		}
		result = append(result, candidate)
	}
	return result
}

func buildOccurrence(window Window, candidate span) (Occurrence, error) {
	occurrence := Occurrence{ID: occurrenceID(window.ID, window.Generation, candidate.startsAt, candidate.endsAt), WindowID: window.ID, WindowGeneration: window.Generation,
		Scope: window.Scope, StartsAt: candidate.startsAt.UTC(), EndsAt: candidate.endsAt.UTC()}
	raw, err := json.Marshal(occurrence)
	if err != nil {
		return Occurrence{}, err
	}
	occurrence.Digest = digestBytes(raw)
	return occurrence, occurrence.Validate()
}

func verifyOccurrence(occurrence Occurrence) error {
	if occurrence.ID != occurrenceID(occurrence.WindowID, occurrence.WindowGeneration, occurrence.StartsAt, occurrence.EndsAt) {
		return ErrIntegrity
	}
	digest := occurrence.Digest
	occurrence.Digest = ""
	raw, err := json.Marshal(occurrence)
	if err != nil || digestBytes(raw) != digest {
		return ErrIntegrity
	}
	occurrence.Digest = digest
	if occurrence.Validate() != nil {
		return ErrIntegrity
	}
	return nil
}

func occurrenceID(windowID string, generation uint64, startsAt, endsAt time.Time) string {
	input := strings.Join([]string{windowID, strconv.FormatUint(generation, 10),
		strconv.FormatInt(startsAt.UnixNano(), 10), strconv.FormatInt(endsAt.UnixNano(), 10)}, "\x00")
	digest := digestBytes([]byte(input))
	return "mwocc_" + digest[:48]
}
