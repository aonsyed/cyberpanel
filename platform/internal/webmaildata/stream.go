package webmaildata

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

type InterchangeFormat string

const (
	FormatCSV   InterchangeFormat = "csv"
	FormatVCard InterchangeFormat = "vcard"
)

type StreamLimits struct {
	MaximumBytes       int64
	MaximumRows        int
	MaximumFields      int
	MaximumFieldBytes  int
	MaximumPreviewRows int
	MaximumErrorSamples int
}

func DefaultStreamLimits() StreamLimits {
	return StreamLimits{MaximumBytes: 64 << 20, MaximumRows: 100_000, MaximumFields: 128, MaximumFieldBytes: 64 << 10, MaximumPreviewRows: 25, MaximumErrorSamples: 50}
}

func (limits StreamLimits) Valid() bool {
	return limits.MaximumBytes > 0 && limits.MaximumBytes <= MaximumBackupBytes && limits.MaximumRows > 0 && limits.MaximumRows <= MaximumBackupObjects && limits.MaximumFields > 0 && limits.MaximumFields <= 256 && limits.MaximumFieldBytes > 0 && limits.MaximumFieldBytes <= 1<<20 && limits.MaximumPreviewRows >= 0 && limits.MaximumPreviewRows <= 100 && limits.MaximumErrorSamples >= 0 && limits.MaximumErrorSamples <= 200
}

type ImportRequest struct {
	Scope           Scope
	Format          InterchangeFormat
	Reader          io.Reader
	Mapping         map[string]string
	Limits          StreamLimits
	PreviewOnly     bool
	DuplicatePolicy DuplicatePolicy
	ImportedAt      time.Time
}

type ImportErrorSample struct {
	Row  int    `json:"row"`
	Code string `json:"code"`
}

type ImportResult struct {
	RowsSeen    int                 `json:"rows_seen"`
	Valid       int                 `json:"valid"`
	Committed   int                 `json:"committed"`
	Skipped     int                 `json:"skipped"`
	Failed      int                 `json:"failed"`
	BytesRead   int64               `json:"bytes_read"`
	Mapping     map[string]string   `json:"mapping"`
	Preview     []Contact           `json:"preview,omitempty"`
	ErrorSamples []ImportErrorSample `json:"error_samples,omitempty"`
}

type ContactSink func(context.Context, Contact, DuplicatePolicy) (bool, error)

func StreamImportContacts(ctx context.Context, request ImportRequest, sink ContactSink) (ImportResult, error) {
	if ctx == nil || !request.Scope.Valid() || request.Reader == nil || !request.Limits.Valid() || request.ImportedAt.IsZero() ||
		request.DuplicatePolicy != DuplicateReject && request.DuplicatePolicy != DuplicateSkip && request.DuplicatePolicy != DuplicateMerge || !request.PreviewOnly && sink == nil {
		return ImportResult{}, ErrInvalid
	}
	reader := &boundedReader{reader: request.Reader, remaining: request.Limits.MaximumBytes + 1}
	result := ImportResult{Mapping: map[string]string{}}
	var err error
	switch request.Format {
	case FormatCSV:
		err = streamCSV(ctx, request, reader, sink, &result)
	case FormatVCard:
		err = streamVCard(ctx, request, reader, sink, &result)
	default:
		return ImportResult{}, ErrInvalid
	}
	result.BytesRead = reader.read
	if reader.read > request.Limits.MaximumBytes { return result, ErrLimit }
	return result, err
}

func streamCSV(ctx context.Context, request ImportRequest, source io.Reader, sink ContactSink, result *ImportResult) error {
	reader := csv.NewReader(source)
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	header, err := reader.Read()
	if err != nil { return ErrInvalid }
	if len(header) == 0 || len(header) > request.Limits.MaximumFields { return ErrLimit }
	indexes := map[string]int{}
	for index, field := range header {
		field = strings.ToLower(cleanText(strings.TrimPrefix(field, "\ufeff"), request.Limits.MaximumFieldBytes))
		if field == "" || indexes[field] != 0 || index > 0 && field == strings.ToLower(cleanText(header[0], request.Limits.MaximumFieldBytes)) { return ErrInvalid }
		indexes[field] = index + 1
	}
	mapping, err := resolveMapping(indexes, request.Mapping)
	if err != nil { return err }
	result.Mapping = mapping
	for rowNumber := 2; ; rowNumber++ {
		if err = ctx.Err(); err != nil { return err }
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) { return nil }
		result.RowsSeen++
		if result.RowsSeen > request.Limits.MaximumRows { return ErrLimit }
		if readErr != nil || len(record) > request.Limits.MaximumFields {
			recordImportError(result, request.Limits, rowNumber, "malformed_row")
			continue
		}
		tooLarge := false
		for _, field := range record { if len(field) > request.Limits.MaximumFieldBytes { tooLarge = true; break } }
		if tooLarge { recordImportError(result, request.Limits, rowNumber, "field_limit"); continue }
		contact, buildErr := csvContact(request, mapping, indexes, record, rowNumber)
		if buildErr != nil { recordImportError(result, request.Limits, rowNumber, "invalid_contact"); continue }
		if err = acceptImportedContact(ctx, request, sink, contact, result); err != nil { return err }
	}
}

func resolveMapping(indexes map[string]int, requested map[string]string) (map[string]string, error) {
	allowed := map[string]bool{"display_name": true, "given_name": true, "family_name": true, "organization": true, "notes": true}
	result := map[string]string{}
	if len(requested) == 0 {
		for header := range indexes {
			if allowed[header] || strings.HasPrefix(header, "email") || strings.HasPrefix(header, "phone") || strings.HasPrefix(header, "metadata.") { result[header] = header }
		}
	} else {
		for field, header := range requested {
			field = strings.ToLower(strings.TrimSpace(field)); header = strings.ToLower(strings.TrimSpace(header))
			if !(allowed[field] || strings.HasPrefix(field, "email") || strings.HasPrefix(field, "phone") || strings.HasPrefix(field, "metadata.")) || indexes[header] == 0 { return nil, ErrInvalid }
			result[field] = header
		}
	}
	if result["display_name"] == "" && result["given_name"] == "" && result["family_name"] == "" { return nil, ErrInvalid }
	return result, nil
}

func csvContact(request ImportRequest, mapping map[string]string, indexes map[string]int, record []string, row int) (Contact, error) {
	get := func(field string) string {
		header := mapping[field]
		index := indexes[header]
		if index < 1 || index > len(record) { return "" }
		return sanitizeImportedContent(record[index-1])
	}
	contact := Contact{Scope: request.Scope, ID: importedContactID(request.Scope, row), DisplayName: get("display_name"), GivenName: get("given_name"), FamilyName: get("family_name"), Organization: get("organization"), Notes: get("notes"), Lifecycle: LifecycleActive, Revision: 1, CreatedAt: request.ImportedAt, UpdatedAt: request.ImportedAt, Provenance: Provenance{Kind: ProvenanceCSV, ImportedAt: timePointer(request.ImportedAt)}}
	if contact.DisplayName == "" { contact.DisplayName = strings.TrimSpace(contact.GivenName + " " + contact.FamilyName) }
	keys := make([]string, 0, len(mapping))
	for key := range mapping { keys = append(keys, key) }
	sort.Strings(keys)
	for _, key := range keys {
		field := get(key)
		if field == "" { continue }
		switch {
		case strings.HasPrefix(key, "email"):
			contact.Addresses = append(contact.Addresses, LabeledAddress{Label: key, Address: field, Primary: len(contact.Addresses) == 0})
		case strings.HasPrefix(key, "phone"):
			contact.Phones = append(contact.Phones, LabeledPhone{Label: key, Number: field, Primary: len(contact.Phones) == 0})
		case strings.HasPrefix(key, "metadata."):
			contact.Metadata = append(contact.Metadata, MetadataField{Key: strings.TrimPrefix(key, "metadata."), Value: field})
		}
	}
	return NormalizeContact(contact)
}

func streamVCard(ctx context.Context, request ImportRequest, source io.Reader, sink ContactSink, result *ImportResult) error {
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 4096), request.Limits.MaximumFieldBytes)
	fields := map[string][]string{}
	inCard := false
	invalidCard := false
	fieldCount := 0
	row := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil { return err }
		line := scanner.Text()
		if strings.EqualFold(line, "BEGIN:VCARD") { if inCard { return ErrInvalid }; inCard = true; invalidCard = false; fieldCount = 0; fields = map[string][]string{}; continue }
		if strings.EqualFold(line, "END:VCARD") {
			if !inCard { return ErrInvalid }
			inCard = false; row++; result.RowsSeen++
			if result.RowsSeen > request.Limits.MaximumRows { return ErrLimit }
			if invalidCard { recordImportError(result, request.Limits, row, "unsupported_content"); continue }
			contact, err := vCardContact(request, fields, row)
			if err != nil { recordImportError(result, request.Limits, row, "invalid_vcard"); continue }
			if err = acceptImportedContact(ctx, request, sink, contact, result); err != nil { return err }
			continue
		}
		if !inCard { continue }
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") { invalidCard = true; continue }
		name, raw, found := strings.Cut(line, ":")
		if !found { continue }
		if strings.Contains(strings.ToUpper(name), "ENCODING=") { invalidCard = true; continue }
		name = strings.ToUpper(strings.SplitN(name, ";", 2)[0])
		fieldCount++; if fieldCount > request.Limits.MaximumFields { return ErrLimit }
		fields[name] = append(fields[name], sanitizeImportedContent(unescapeVCard(raw)))
	}
	if err := scanner.Err(); err != nil { if strings.Contains(strings.ToLower(err.Error()), "token too long") { return ErrLimit }; return err }
	if inCard { return ErrInvalid }
	return nil
}

func vCardContact(request ImportRequest, fields map[string][]string, row int) (Contact, error) {
	first := func(key string) string { if len(fields[key]) == 0 { return "" }; return fields[key][0] }
	name := first("FN")
	parts := strings.Split(first("N"), ";")
	contact := Contact{Scope: request.Scope, ID: importedContactID(request.Scope, row), DisplayName: name, Lifecycle: LifecycleActive, Revision: 1, CreatedAt: request.ImportedAt, UpdatedAt: request.ImportedAt, Provenance: Provenance{Kind: ProvenanceVCard, ImportedAt: timePointer(request.ImportedAt)}, Organization: first("ORG"), Notes: first("NOTE")}
	if len(parts) > 0 { contact.FamilyName = parts[0] }
	if len(parts) > 1 { contact.GivenName = parts[1] }
	if contact.DisplayName == "" { contact.DisplayName = strings.TrimSpace(contact.GivenName + " " + contact.FamilyName) }
	for index, address := range fields["EMAIL"] { contact.Addresses = append(contact.Addresses, LabeledAddress{Label: "email", Address: address, Primary: index == 0}) }
	for index, phone := range fields["TEL"] { contact.Phones = append(contact.Phones, LabeledPhone{Label: "phone", Number: phone, Primary: index == 0}) }
	return NormalizeContact(contact)
}

func acceptImportedContact(ctx context.Context, request ImportRequest, sink ContactSink, contact Contact, result *ImportResult) error {
	result.Valid++
	if len(result.Preview) < request.Limits.MaximumPreviewRows { result.Preview = append(result.Preview, contact) }
	if request.PreviewOnly { return nil }
	committed, err := sink(ctx, contact, request.DuplicatePolicy)
	if errors.Is(err, ErrDuplicate) && request.DuplicatePolicy == DuplicateSkip { result.Skipped++; return nil }
	if err != nil { return err }
	if committed { result.Committed++ } else { result.Skipped++ }
	return nil
}

type ContactPager interface { ListContacts(context.Context, ContactQuery) (ContactPage, error) }

func StreamExportContacts(ctx context.Context, source ContactPager, scope Scope, format InterchangeFormat, writer io.Writer, limits StreamLimits) (int, int64, error) {
	if ctx == nil || source == nil || !scope.Valid() || writer == nil || !limits.Valid() { return 0, 0, ErrInvalid }
	bounded := &boundedWriter{writer: writer, maximum: limits.MaximumBytes}
	count := 0
	cursor := ""
	var csvWriter *csv.Writer
	if format == FormatCSV { csvWriter = csv.NewWriter(bounded); if err := csvWriter.Write([]string{"display_name", "given_name", "family_name", "organization", "email", "phone", "notes"}); err != nil { return 0, bounded.written, err } } else if format != FormatVCard { return 0, 0, ErrInvalid }
	for {
		page, err := source.ListContacts(ctx, ContactQuery{Scope: scope, Cursor: cursor, Limit: MaximumPageSize})
		if err != nil { return count, bounded.written, err }
		for _, contact := range page.Contacts {
			if count == limits.MaximumRows { return count, bounded.written, ErrLimit }
			if format == FormatCSV {
				email, phone := "", ""
				if len(contact.Addresses) > 0 { email = contact.Addresses[0].Normalized }
				if len(contact.Phones) > 0 { phone = contact.Phones[0].Normalized }
				err = csvWriter.Write([]string{spreadsheetSafe(contact.DisplayName), spreadsheetSafe(contact.GivenName), spreadsheetSafe(contact.FamilyName), spreadsheetSafe(contact.Organization), spreadsheetSafe(email), spreadsheetSafe(phone), spreadsheetSafe(contact.Notes)})
			} else { _, err = io.WriteString(bounded, renderVCard(contact)) }
			if err != nil { return count, bounded.written, err }
			count++
		}
		if page.NextCursor == "" { break }
		cursor = page.NextCursor
	}
	if csvWriter != nil { csvWriter.Flush(); if err := csvWriter.Error(); err != nil { return count, bounded.written, err } }
	return count, bounded.written, nil
}

func renderVCard(contact Contact) string {
	var value strings.Builder
	value.WriteString("BEGIN:VCARD\r\nVERSION:4.0\r\n")
	value.WriteString("FN:" + escapeVCard(contact.DisplayName) + "\r\n")
	value.WriteString("N:" + escapeVCard(contact.FamilyName) + ";" + escapeVCard(contact.GivenName) + ";;;\r\n")
	if contact.Organization != "" { value.WriteString("ORG:" + escapeVCard(contact.Organization) + "\r\n") }
	for _, address := range contact.Addresses { value.WriteString("EMAIL:" + escapeVCard(address.Normalized) + "\r\n") }
	for _, phone := range contact.Phones { value.WriteString("TEL:" + escapeVCard(phone.Normalized) + "\r\n") }
	if contact.Notes != "" { value.WriteString("NOTE:" + escapeVCard(contact.Notes) + "\r\n") }
	value.WriteString("END:VCARD\r\n")
	return value.String()
}

func recordImportError(result *ImportResult, limits StreamLimits, row int, code string) {
	result.Failed++
	if len(result.ErrorSamples) < limits.MaximumErrorSamples { result.ErrorSamples = append(result.ErrorSamples, ImportErrorSample{Row: row, Code: code}) }
}

func importedContactID(scope Scope, row int) string {
	sum := sha256.Sum256([]byte(scope.TenantID + "\x00" + scope.UserID + "\x00" + scope.MailboxID + "\x00" + strconv.Itoa(row)))
	return "import-" + hex.EncodeToString(sum[:12])
}

func sanitizeImportedContent(value string) string {
	value = strings.TrimPrefix(value, "\ufeff")
	return strings.Map(func(char rune) rune { if char == 0 || char < 0x20 && char != '\n' && char != '\t' { return -1 }; return char }, value)
}

func spreadsheetSafe(value string) string {
	value = sanitizeImportedContent(value)
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) { return "'" + value }
	return value
}

func escapeVCard(value string) string { return strings.NewReplacer("\\", "\\\\", "\n", "\\n", ";", "\\;", ",", "\\,").Replace(sanitizeImportedContent(value)) }
func unescapeVCard(value string) string { return strings.NewReplacer("\\n", "\n", "\\N", "\n", "\\;", ";", "\\,", ",", "\\\\", "\\").Replace(value) }
func timePointer(value time.Time) *time.Time { normalized := value.UTC().Truncate(time.Second); return &normalized }

type boundedReader struct { reader io.Reader; remaining int64; read int64 }
func (reader *boundedReader) Read(buffer []byte) (int, error) {
	if reader.remaining <= 0 { return 0, ErrLimit }
	if int64(len(buffer)) > reader.remaining { buffer = buffer[:reader.remaining] }
	count, err := reader.reader.Read(buffer); reader.read += int64(count); reader.remaining -= int64(count)
	return count, err
}

type boundedWriter struct { writer io.Writer; maximum int64; written int64 }
func (writer *boundedWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > writer.maximum-writer.written { return 0, ErrLimit }
	count, err := writer.writer.Write(value); writer.written += int64(count)
	return count, err
}
