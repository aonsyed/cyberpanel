package scheduler

import (
	"strconv"
	"strings"
	"time"
)

const maximumCronSearchMinutes = 8 * 366 * 24 * 60

var supportedMacros = map[string]string{
	"@hourly":  "0 * * * *",
	"@daily":   "0 0 * * *",
	"@weekly":  "0 0 * * 0",
	"@monthly": "0 0 1 * *",
	"@yearly":  "0 0 1 1 *",
}

type cronField struct {
	minimum    int
	maximum    int
	values     []bool
	restricted bool
}

type cronExpression struct {
	minute     cronField
	hour       cronField
	dayOfMonth cronField
	month      cronField
	dayOfWeek  cronField
}

func NormalizeExpression(value string) (string, error) {
	if expanded, ok := supportedMacros[value]; ok { _, err := parseCron(expanded); return value, err }
	fields := strings.Fields(value); if len(fields) != 5 { return "", ErrInvalid }
	bounds := [][2]int{{0,59},{0,23},{1,31},{1,12},{0,7}}
	normalized := make([]string, 5)
	for index, field := range fields {
		parsed, err := parseCronField(field, bounds[index][0], bounds[index][1], index == 4); if err != nil { return "", err }
		normalized[index] = renderCronField(parsed, index == 4)
	}
	result := strings.Join(normalized, " ")
	if _, err := parseCron(result); err != nil { return "", err }
	return result, nil
}

func NextLogicalTime(expression, timezone string, after time.Time) (time.Time, error) {
	if after.IsZero() { return time.Time{}, ErrInvalid }
	location, err := time.LoadLocation(timezone); if err != nil || timezone == "Local" { return time.Time{}, ErrInvalid }
	parsed, err := parseCron(expression); if err != nil { return time.Time{}, err }
	candidate := after.UTC().Truncate(time.Minute).Add(time.Minute)
	for scanned := 0; scanned < maximumCronSearchMinutes; scanned++ {
		if parsed.matches(candidate.In(location)) { return candidate.UTC(), nil }
		candidate = candidate.Add(time.Minute)
	}
	return time.Time{}, ErrInvalid
}

func parseCron(value string) (cronExpression, error) {
	if expanded, ok := supportedMacros[value]; ok { value = expanded }
	fields := strings.Fields(value); if len(fields) != 5 { return cronExpression{}, ErrInvalid }
	minute, err := parseCronField(fields[0],0,59,false); if err != nil { return cronExpression{},err }
	hour, err := parseCronField(fields[1],0,23,false); if err != nil { return cronExpression{},err }
	dayOfMonth, err := parseCronField(fields[2],1,31,false); if err != nil { return cronExpression{},err }
	month, err := parseCronField(fields[3],1,12,false); if err != nil { return cronExpression{},err }
	dayOfWeek, err := parseCronField(fields[4],0,7,true); if err != nil { return cronExpression{},err }
	return cronExpression{minute:minute,hour:hour,dayOfMonth:dayOfMonth,month:month,dayOfWeek:dayOfWeek},nil
}

func parseCronField(value string, minimum, maximum int, sundayAlias bool) (cronField, error) {
	field := cronField{minimum:minimum,maximum:maximum,values:make([]bool,maximum+1),restricted:value!="*"}
	if value == "" { return cronField{}, ErrInvalid }
	for _, component := range strings.Split(value, ",") {
		if component == "" { return cronField{}, ErrInvalid }
		base, stepText, hasStep := strings.Cut(component, "/"); step := 1
		if hasStep { parsed, err := parseCronNumber(stepText,1,maximum-minimum+1); if err != nil { return cronField{},err }; step = parsed }
		start, end := minimum, maximum
		if base != "*" {
			left, right, ranged := strings.Cut(base, "-")
			parsed, err := parseCronNumber(left,minimum,maximum); if err != nil { return cronField{},err }; start, end = parsed, parsed
			if ranged { parsedEnd, parseErr := parseCronNumber(right,minimum,maximum); if parseErr != nil || parsedEnd < start { return cronField{},ErrInvalid }; end = parsedEnd }
			if hasStep && !ranged { return cronField{}, ErrInvalid }
		}
		for current := start; current <= end; current += step { normalized := current; if sundayAlias && current == 7 { normalized = 0 }; field.values[normalized] = true }
	}
	for value := minimum; value <= maximum; value++ { normalized := value; if sundayAlias && value == 7 { normalized = 0 }; if field.values[normalized] { continue }; return field,nil }
	field.restricted = false
	return field,nil
}

func parseCronNumber(value string, minimum, maximum int) (int, error) {
	if value == "" || len(value) > 2 && maximum < 100 { return 0, ErrInvalid }
	if len(value) > 1 && value[0] == '0' { return 0, ErrInvalid }
	parsed, err := strconv.Atoi(value); if err != nil || parsed < minimum || parsed > maximum { return 0, ErrInvalid }
	return parsed,nil
}

func renderCronField(field cronField, sundayAlias bool) string {
	if !field.restricted { return "*" }
	values := make([]string,0,field.maximum-field.minimum+1)
	upper := field.maximum; if sundayAlias { upper = 6 }
	for value := field.minimum; value <= upper; value++ { if field.values[value] { values=append(values,strconv.Itoa(value)) } }
	return strings.Join(values,",")
}

func (expression cronExpression) matches(value time.Time) bool {
	if !expression.minute.values[value.Minute()] || !expression.hour.values[value.Hour()] || !expression.month.values[int(value.Month())] { return false }
	dayMatches := expression.dayOfMonth.values[value.Day()]
	weekMatches := expression.dayOfWeek.values[int(value.Weekday())]
	if expression.dayOfMonth.restricted && expression.dayOfWeek.restricted { return dayMatches || weekMatches }
	if expression.dayOfMonth.restricted { return dayMatches }
	if expression.dayOfWeek.restricted { return weekMatches }
	return true
}
