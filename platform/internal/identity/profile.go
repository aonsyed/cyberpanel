package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"
)

var profileLocales = map[string]string{
	"ar-sa": "ar-SA", "de-de": "de-DE", "en-au": "en-AU", "en-ca": "en-CA", "en-gb": "en-GB", "en-us": "en-US",
	"es-es": "es-ES", "es-mx": "es-MX", "fr-ca": "fr-CA", "fr-fr": "fr-FR", "hi-in": "hi-IN", "id-id": "id-ID",
	"it-it": "it-IT", "ja-jp": "ja-JP", "ko-kr": "ko-KR", "nl-nl": "nl-NL", "pl-pl": "pl-PL", "pt-br": "pt-BR",
	"pt-pt": "pt-PT", "ru-ru": "ru-RU", "tr-tr": "tr-TR", "uk-ua": "uk-UA", "ur-pk": "ur-PK", "vi-vn": "vi-VN",
	"zh-cn": "zh-CN", "zh-hk": "zh-HK", "zh-tw": "zh-TW",
}

func canonicalProfileLocale(value string) (string, bool) {
	canonical, ok := profileLocales[strings.ToLower(strings.TrimSpace(value))]
	return canonical, ok
}

func validProfileTimezone(value string) bool {
	if value != strings.TrimSpace(value) || len(value) < 1 || len(value) > 64 || strings.ContainsAny(value, "\x00\\") || strings.Contains(value, "..") { return false }
	if value != "UTC" && !strings.Contains(value, "/") { return false }
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." { return false }
		for _, character := range segment {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_+-", character) { continue }
			return false
		}
	}
	_, err := time.LoadLocation(value)
	return err == nil
}

func validNotificationChannels(values []NotificationChannel) bool {
	for index, value := range values {
		if value != NotificationChannelEmail && value != NotificationChannelInApp { return false }
		if index > 0 && values[index-1] >= value { return false }
	}
	return true
}

func validNotificationCategories(values []NotificationCategory) bool {
	for index, value := range values {
		switch value { case NotificationCategoryAccount, NotificationCategoryBilling, NotificationCategoryOperations, NotificationCategoryProduct, NotificationCategorySecurity: default: return false }
		if index > 0 && values[index-1] >= value { return false }
	}
	return true
}

func normalizeProfileDisplayName(value string) string { return strings.Join(strings.Fields(value), " ") }
func validProfileDisplayName(value string) bool {
	if value != normalizeProfileDisplayName(value) || len(value) < 1 || len(value) > 128 { return false }
	for _, character := range value { if unicode.IsControl(character) { return false } }
	return true
}

func initialProfilePreferences(principal Principal) ProfilePreferences {
	displayName := normalizeProfileDisplayName(principal.DisplayName)
	if !validProfileDisplayName(displayName) { displayName = principal.Username }
	locale, ok := canonicalProfileLocale(principal.Locale)
	if !ok { locale = "en-US" }
	appearance := principal.Theme
	if appearance != ThemeSystem && appearance != ThemeLight && appearance != ThemeDark { appearance = ThemeSystem }
	return ProfilePreferences{PrincipalID: principal.ID, DisplayName: displayName, Locale: locale, Timezone: "UTC", Appearance: appearance, DateFormat: ProfileDateLocaleDefault, TimeFormat: ProfileTimeLocaleDefault, NotificationChannels: []NotificationChannel{NotificationChannelEmail, NotificationChannelInApp}, NotificationCategories: []NotificationCategory{NotificationCategoryAccount, NotificationCategorySecurity}, NotificationMinimumSeverity: NotificationSeverityWarning, ReducedMotion: ReducedMotionSystem, Revision: 1, CreatedAt: principal.CreatedAt, UpdatedAt: principal.UpdatedAt, UpdatedByID: principal.ID}
}

func resetProfilePreferences(principal Principal) ProfilePreferences {
	value := initialProfilePreferences(principal)
	value.DisplayName = principal.Username
	value.Locale = "en-US"
	value.Appearance = ThemeSystem
	return value
}

const profilePreferencesSelect = `SELECT principal_id,display_name,locale,timezone,appearance,date_format,time_format,notification_channels_json,notification_categories_json,notification_minimum_severity,reduced_motion,revision,created_at,updated_at,updated_by_id FROM identity_profile_preferences`

type profilePreferencesScanner interface { Scan(...any) error }

func scanProfilePreferences(row profilePreferencesScanner) (ProfilePreferences, error) {
	var value ProfilePreferences
	var appearance, dateFormat, timeFormat, severity, reducedMotion string
	var channels, categories []byte
	err := row.Scan(&value.PrincipalID, &value.DisplayName, &value.Locale, &value.Timezone, &appearance, &dateFormat, &timeFormat, &channels, &categories, &severity, &reducedMotion, &value.Revision, &value.CreatedAt, &value.UpdatedAt, &value.UpdatedByID)
	if errors.Is(err, sql.ErrNoRows) { return ProfilePreferences{}, ErrNotFound }
	if err != nil { return ProfilePreferences{}, err }
	if err = json.Unmarshal(channels, &value.NotificationChannels); err != nil { return ProfilePreferences{}, err }
	if err = json.Unmarshal(categories, &value.NotificationCategories); err != nil { return ProfilePreferences{}, err }
	value.Appearance = Theme(appearance)
	value.DateFormat = ProfileDateFormat(dateFormat)
	value.TimeFormat = ProfileTimeFormat(timeFormat)
	value.NotificationMinimumSeverity = NotificationSeverity(severity)
	value.ReducedMotion = ReducedMotionPreference(reducedMotion)
	return value, value.Validate()
}

func profilePreferenceJSON(value ProfilePreferences) ([]byte, []byte, error) {
	channels, err := json.Marshal(value.NotificationChannels)
	if err != nil { return nil, nil, err }
	categories, err := json.Marshal(value.NotificationCategories)
	return channels, categories, err
}

func (s *Store) ProfilePreferences(ctx context.Context, principalID ID) (ProfilePreferences, error) {
	if s == nil || s.db == nil || ctx == nil || !principalID.Valid() { return ProfilePreferences{}, ErrInvalid }
	principal, err := s.Principal(ctx, principalID)
	if err != nil { return ProfilePreferences{}, err }
	if principal.Kind != PrincipalHuman || principal.State == PrincipalDeleted { return ProfilePreferences{}, ErrNotFound }
	initial := initialProfilePreferences(principal)
	if err = initial.Validate(); err != nil { return ProfilePreferences{}, err }
	channels, categories, err := profilePreferenceJSON(initial)
	if err != nil { return ProfilePreferences{}, err }
	_, err = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO identity_profile_preferences(principal_id,display_name,locale,timezone,appearance,date_format,time_format,notification_channels_json,notification_categories_json,notification_minimum_severity,reduced_motion,revision,created_at,updated_at,updated_by_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, initial.PrincipalID, initial.DisplayName, initial.Locale, initial.Timezone, initial.Appearance, initial.DateFormat, initial.TimeFormat, channels, categories, initial.NotificationMinimumSeverity, initial.ReducedMotion, initial.Revision, initial.CreatedAt, initial.UpdatedAt, initial.UpdatedByID)
	if err != nil { return ProfilePreferences{}, err }
	return scanProfilePreferences(s.db.QueryRowContext(ctx, profilePreferencesSelect+` WHERE principal_id=?`, principalID))
}

func knownProfileField(field ProfileField) bool {
	switch field {
	case ProfileFieldDisplayName, ProfileFieldLocale, ProfileFieldTimezone, ProfileFieldAppearance, ProfileFieldDateFormat, ProfileFieldTimeFormat, ProfileFieldNotificationChannels, ProfileFieldNotificationCategories, ProfileFieldNotificationSeverity, ProfileFieldReducedMotion:
		return true
	}
	return false
}

func profileFieldSets(patch ProfilePreferencesPatch, allowed map[ProfileField]bool) ([]ProfileField, map[ProfileField]bool, error) {
	if len(patch.FieldMask) < 1 || len(patch.FieldMask) > 10 || len(patch.ResetFields) > len(patch.FieldMask) { return nil, nil, ErrInvalid }
	if len(patch.Values.DisplayName) > 128 || len(patch.Values.Locale) > 35 || len(patch.Values.Timezone) > 64 || len(patch.Values.Appearance) > 32 || len(patch.Values.DateFormat) > 32 || len(patch.Values.TimeFormat) > 32 || len(patch.Values.NotificationChannels) > 2 || len(patch.Values.NotificationCategories) > 5 || len(patch.Values.NotificationMinimumSeverity) > 32 || len(patch.Values.ReducedMotion) > 32 { return nil, nil, ErrInvalid }
	masked := make(map[ProfileField]bool, len(patch.FieldMask))
	fields := append([]ProfileField(nil), patch.FieldMask...)
	for _, field := range fields {
		if !knownProfileField(field) || !allowed[field] || masked[field] { return nil, nil, ErrInvalid }
		masked[field] = true
	}
	reset := make(map[ProfileField]bool, len(patch.ResetFields))
	for _, field := range patch.ResetFields {
		if !masked[field] || reset[field] { return nil, nil, ErrInvalid }
		reset[field] = true
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i] < fields[j] })
	return fields, reset, nil
}

func canonicalChannels(values []NotificationChannel) ([]NotificationChannel, bool) {
	result := append(make([]NotificationChannel, 0, len(values)), values...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, len(result) <= 2 && validNotificationChannels(result)
}

func canonicalCategories(values []NotificationCategory) ([]NotificationCategory, bool) {
	result := append(make([]NotificationCategory, 0, len(values)), values...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, len(result) <= 5 && validNotificationCategories(result)
}

func sameChannels(left, right []NotificationChannel) bool {
	if len(left) != len(right) { return false }
	for index := range left { if left[index] != right[index] { return false } }
	return true
}

func sameCategories(left, right []NotificationCategory) bool {
	if len(left) != len(right) { return false }
	for index := range left { if left[index] != right[index] { return false } }
	return true
}

func applyProfilePatch(current, defaults ProfilePreferences, patch ProfilePreferencesPatch, fields []ProfileField, reset map[ProfileField]bool) (ProfilePreferences, []ProfileField, error) {
	next := current
	for _, field := range fields {
		values := patch.Values
		if reset[field] { values = defaults }
		switch field {
		case ProfileFieldDisplayName:
			if len(values.DisplayName) > 128 || strings.ContainsAny(values.DisplayName, "\x00\r\n\t") { return ProfilePreferences{}, nil, ErrInvalid }
			next.DisplayName = normalizeProfileDisplayName(values.DisplayName)
		case ProfileFieldLocale:
			if len(values.Locale) > 35 { return ProfilePreferences{}, nil, ErrInvalid }
			locale, ok := canonicalProfileLocale(values.Locale); if !ok { return ProfilePreferences{}, nil, ErrInvalid }; next.Locale = locale
		case ProfileFieldTimezone:
			if len(values.Timezone) > 64 { return ProfilePreferences{}, nil, ErrInvalid }
			next.Timezone = strings.TrimSpace(values.Timezone); if !validProfileTimezone(next.Timezone) { return ProfilePreferences{}, nil, ErrInvalid }
		case ProfileFieldAppearance:
			next.Appearance = values.Appearance
		case ProfileFieldDateFormat:
			next.DateFormat = values.DateFormat
		case ProfileFieldTimeFormat:
			next.TimeFormat = values.TimeFormat
		case ProfileFieldNotificationChannels:
			if len(values.NotificationChannels) > 2 { return ProfilePreferences{}, nil, ErrInvalid }
			channels, ok := canonicalChannels(values.NotificationChannels); if !ok { return ProfilePreferences{}, nil, ErrInvalid }; next.NotificationChannels = channels
		case ProfileFieldNotificationCategories:
			if len(values.NotificationCategories) > 5 { return ProfilePreferences{}, nil, ErrInvalid }
			categories, ok := canonicalCategories(values.NotificationCategories); if !ok { return ProfilePreferences{}, nil, ErrInvalid }; next.NotificationCategories = categories
		case ProfileFieldNotificationSeverity:
			next.NotificationMinimumSeverity = values.NotificationMinimumSeverity
		case ProfileFieldReducedMotion:
			next.ReducedMotion = values.ReducedMotion
		}
	}
	if err := next.Validate(); err != nil { return ProfilePreferences{}, nil, err }
	changed := make([]ProfileField, 0, len(fields))
	for _, field := range fields {
		switch field {
		case ProfileFieldDisplayName: if current.DisplayName != next.DisplayName { changed = append(changed, field) }
		case ProfileFieldLocale: if current.Locale != next.Locale { changed = append(changed, field) }
		case ProfileFieldTimezone: if current.Timezone != next.Timezone { changed = append(changed, field) }
		case ProfileFieldAppearance: if current.Appearance != next.Appearance { changed = append(changed, field) }
		case ProfileFieldDateFormat: if current.DateFormat != next.DateFormat { changed = append(changed, field) }
		case ProfileFieldTimeFormat: if current.TimeFormat != next.TimeFormat { changed = append(changed, field) }
		case ProfileFieldNotificationChannels: if !sameChannels(current.NotificationChannels, next.NotificationChannels) { changed = append(changed, field) }
		case ProfileFieldNotificationCategories: if !sameCategories(current.NotificationCategories, next.NotificationCategories) { changed = append(changed, field) }
		case ProfileFieldNotificationSeverity: if current.NotificationMinimumSeverity != next.NotificationMinimumSeverity { changed = append(changed, field) }
		case ProfileFieldReducedMotion: if current.ReducedMotion != next.ReducedMotion { changed = append(changed, field) }
		}
	}
	if len(changed) == 0 { return ProfilePreferences{}, nil, ErrConflict }
	return next, changed, nil
}

func profileFieldDigest(value ProfilePreferences, field ProfileField) string {
	var raw any
	switch field {
	case ProfileFieldDisplayName: raw = value.DisplayName
	case ProfileFieldLocale: raw = value.Locale
	case ProfileFieldTimezone: raw = value.Timezone
	case ProfileFieldAppearance: raw = value.Appearance
	case ProfileFieldDateFormat: raw = value.DateFormat
	case ProfileFieldTimeFormat: raw = value.TimeFormat
	case ProfileFieldNotificationChannels: raw = value.NotificationChannels
	case ProfileFieldNotificationCategories: raw = value.NotificationCategories
	case ProfileFieldNotificationSeverity: raw = value.NotificationMinimumSeverity
	case ProfileFieldReducedMotion: raw = value.ReducedMotion
	}
	encoded, _ := json.Marshal(raw)
	return digest(encoded)
}

func (s *Service) profileUpdateAudit(ctx context.Context, actor, tenant, target ID, action, outcome string, value ProfilePreferences, fields []ProfileField) {
	if s == nil || ctx == nil { return }
	names := make([]string, len(fields)); material := make([]string, len(fields))
	for index, field := range fields { names[index] = string(field); material[index] = string(field)+"="+profileFieldDigest(value, field) }
	s.record(ctx, actor, tenant, action+"."+strings.Join(names, "+"), "profile_preferences", target, outcome, target.String()+"\x00"+strings.Join(material, "\x00")+"\x00"+s.clock().UTC().Format(time.RFC3339Nano))
}

var allProfileFields = map[ProfileField]bool{ProfileFieldDisplayName:true, ProfileFieldLocale:true, ProfileFieldTimezone:true, ProfileFieldAppearance:true, ProfileFieldDateFormat:true, ProfileFieldTimeFormat:true, ProfileFieldNotificationChannels:true, ProfileFieldNotificationCategories:true, ProfileFieldNotificationSeverity:true, ProfileFieldReducedMotion:true}
var adminProfileFields = map[ProfileField]bool{ProfileFieldDisplayName:true, ProfileFieldLocale:true, ProfileFieldTimezone:true}

func (s *Service) CurrentProfilePreferences(ctx context.Context, actor ActorContext) (ProfilePreferences, error) {
	if s == nil || s.store == nil || actor.SessionID == "" { return ProfilePreferences{}, ErrInvalid }
	if err := s.validateActor(ctx, actor, AssurancePassword); err != nil { return ProfilePreferences{}, err }
	return s.store.ProfilePreferences(ctx, actor.PrincipalID)
}

func (s *Service) UpdateCurrentProfilePreferences(ctx context.Context, actor ActorContext, expected uint64, patch ProfilePreferencesPatch) (ProfilePreferences, error) {
	if s == nil || s.store == nil || actor.SessionID == "" { return ProfilePreferences{}, ErrInvalid }
	if err := s.validateActor(ctx, actor, AssurancePassword); err != nil { return ProfilePreferences{}, err }
	return s.updateProfilePreferences(ctx, actor, actor.PrincipalID, "", expected, patch, allProfileFields, "profile.self.update")
}

func (s *Service) authorizeAdminProfile(ctx context.Context, actor ActorContext, tenantID, targetID ID, minimum AssuranceLevel) (Principal, error) {
	if !tenantID.Valid() || !targetID.Valid() || actor.PrincipalID == targetID { return Principal{}, ErrInvalid }
	if _, err := s.AuthorizeActor(ctx, actor, "principal:manage", Scope{Kind:ScopeTenant, TenantID:tenantID}, minimum); err != nil { return Principal{}, err }
	tenant, err := s.store.Tenant(ctx, tenantID)
	if err != nil || tenant.State != TenantActive { return Principal{}, ErrForbidden }
	target, err := s.store.Principal(ctx, targetID)
	if err != nil || target.Kind != PrincipalHuman || target.State != PrincipalActive { return Principal{}, ErrNotFound }
	memberships, err := s.store.Memberships(ctx, targetID)
	if err != nil { return Principal{}, err }
	for _, membership := range memberships { if membership.TenantID == tenantID && membership.State == MembershipActive { return target, nil } }
	return Principal{}, ErrNotFound
}

func adminProfilePreferences(value ProfilePreferences) AdminProfilePreferences { return AdminProfilePreferences{PrincipalID:value.PrincipalID, DisplayName:value.DisplayName, Locale:value.Locale, Timezone:value.Timezone, Revision:value.Revision, UpdatedAt:value.UpdatedAt} }

func (s *Service) ProfilePreferencesForAdmin(ctx context.Context, actor ActorContext, tenantID, targetID ID) (AdminProfilePreferences, error) {
	if s == nil || s.store == nil { return AdminProfilePreferences{}, ErrInvalid }
	if _, err := s.authorizeAdminProfile(ctx, actor, tenantID, targetID, AssurancePassword); err != nil { return AdminProfilePreferences{}, err }
	value, err := s.store.ProfilePreferences(ctx, targetID)
	return adminProfilePreferences(value), err
}

func (s *Service) UpdateProfilePreferencesForAdmin(ctx context.Context, actor ActorContext, tenantID, targetID ID, expected uint64, patch ProfilePreferencesPatch) (AdminProfilePreferences, error) {
	if s == nil || s.store == nil || actor.SessionID == "" { return AdminProfilePreferences{}, ErrInvalid }
	if _, err := s.authorizeAdminProfile(ctx, actor, tenantID, targetID, AssuranceMFA); err != nil { return AdminProfilePreferences{}, err }
	value, err := s.updateProfilePreferences(ctx, actor, targetID, tenantID, expected, patch, adminProfileFields, "profile.admin.update")
	return adminProfilePreferences(value), err
}

func (s *Service) updateProfilePreferences(ctx context.Context, actor ActorContext, targetID, adminTenantID ID, expected uint64, patch ProfilePreferencesPatch, allowed map[ProfileField]bool, action string) (ProfilePreferences, error) {
	fields, reset, err := profileFieldSets(patch, allowed)
	if err != nil || expected == 0 { return ProfilePreferences{}, ErrInvalid }
	principal, err := s.store.Principal(ctx, targetID)
	if err != nil || principal.Kind != PrincipalHuman || principal.State != PrincipalActive { return ProfilePreferences{}, ErrNotFound }
	if _, err = s.store.ProfilePreferences(ctx, targetID); err != nil { return ProfilePreferences{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil { return ProfilePreferences{}, err }
	defer tx.Rollback()
	var principalKind, principalState string
	if err = tx.QueryRowContext(ctx, `SELECT kind,state FROM identity_principals WHERE id=?`, targetID).Scan(&principalKind, &principalState); errors.Is(err, sql.ErrNoRows) { return ProfilePreferences{}, ErrNotFound }
	if err != nil { return ProfilePreferences{}, err }
	if PrincipalKind(principalKind) != PrincipalHuman || PrincipalState(principalState) != PrincipalActive { return ProfilePreferences{}, ErrForbidden }
	if adminTenantID != "" {
		var activeMemberships uint64
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_memberships m JOIN identity_tenants t ON t.id=m.tenant_id WHERE m.principal_id=? AND m.tenant_id=? AND m.state=? AND t.state=?`, targetID, adminTenantID, MembershipActive, TenantActive).Scan(&activeMemberships); err != nil { return ProfilePreferences{}, err }
		if activeMemberships == 0 { return ProfilePreferences{}, ErrForbidden }
	}
	current, err := scanProfilePreferences(tx.QueryRowContext(ctx, profilePreferencesSelect+` WHERE principal_id=?`, targetID))
	if err != nil { return ProfilePreferences{}, err }
	if current.Revision != expected { s.profileUpdateAudit(ctx, actor.PrincipalID, adminTenantID, targetID, action, "rejected", patch.Values, fields); return ProfilePreferences{}, ErrStaleGeneration }
	next, changed, err := applyProfilePatch(current, resetProfilePreferences(principal), patch, fields, reset)
	if err != nil { s.profileUpdateAudit(ctx, actor.PrincipalID, adminTenantID, targetID, action, "rejected", patch.Values, fields); return ProfilePreferences{}, err }
	now := s.clock().UTC(); if !now.After(current.UpdatedAt) { now = current.UpdatedAt.Add(time.Nanosecond) }
	next.Revision = current.Revision + 1; next.CreatedAt = current.CreatedAt; next.UpdatedAt = now; next.UpdatedByID = actor.PrincipalID
	if err = next.Validate(); err != nil { return ProfilePreferences{}, err }
	channels, categories, err := profilePreferenceJSON(next); if err != nil { return ProfilePreferences{}, err }
	result, err := tx.ExecContext(ctx, `UPDATE identity_profile_preferences SET display_name=?,locale=?,timezone=?,appearance=?,date_format=?,time_format=?,notification_channels_json=?,notification_categories_json=?,notification_minimum_severity=?,reduced_motion=?,revision=?,updated_at=?,updated_by_id=? WHERE principal_id=? AND revision=?`, next.DisplayName, next.Locale, next.Timezone, next.Appearance, next.DateFormat, next.TimeFormat, channels, categories, next.NotificationMinimumSeverity, next.ReducedMotion, next.Revision, next.UpdatedAt, next.UpdatedByID, next.PrincipalID, current.Revision)
	if err != nil { return ProfilePreferences{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return ProfilePreferences{}, ErrStaleGeneration }
	syncPrincipal := false
	for _, field := range changed { if field == ProfileFieldDisplayName || field == ProfileFieldLocale || field == ProfileFieldAppearance { syncPrincipal = true } }
	if syncPrincipal {
		result, err = tx.ExecContext(ctx, `UPDATE identity_principals SET display_name=?,locale=?,theme=?,generation=generation+1,updated_at=? WHERE id=? AND kind=? AND state=?`, next.DisplayName, next.Locale, next.Appearance, now, targetID, PrincipalHuman, PrincipalActive)
		if err != nil { return ProfilePreferences{}, err }
		if rows, _ := result.RowsAffected(); rows != 1 { return ProfilePreferences{}, ErrConflict }
	}
	if err = tx.Commit(); err != nil { return ProfilePreferences{}, err }
	s.profileUpdateAudit(ctx, actor.PrincipalID, adminTenantID, targetID, action, "applied", next, changed)
	return next, nil
}
