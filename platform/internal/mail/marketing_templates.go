package mail

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maximumCampaignTemplateBytes = 8 << 20

// CreateTemplate starts a versioned template as a draft. Every later edit is
// inserted as a new generation so an approved campaign always references an
// immutable body rather than whichever text happens to be current.
func (s MarketingStore) CreateTemplate(ctx context.Context, tenant string, value CampaignTemplate) (CampaignTemplate, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || value.Generation != 0 && value.Generation != 1 {
		return CampaignTemplate{}, ErrInvalidCommand
	}
	value.Generation = 1
	value.State = "draft"
	value.UpdatedAt = time.Now().UTC()
	if err := validateCampaignTemplate(value); err != nil {
		return CampaignTemplate{}, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return CampaignTemplate{}, err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO marketing_templates_v2(id,tenant_id,generation,state,template_json,updated_at) VALUES(?,?,?,?,?,?)`, value.ID, tenant, value.Generation, value.State, raw, value.UpdatedAt)
	return value, err
}

// ReviseTemplate creates a new draft generation. Approved generations remain
// addressable through their id.generation reference and are never overwritten.
func (s MarketingStore) ReviseTemplate(ctx context.Context, tenant string, value CampaignTemplate, expected uint64) (CampaignTemplate, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || expected == 0 {
		return CampaignTemplate{}, ErrInvalidCommand
	}
	prior, found, err := s.LatestTemplate(ctx, tenant, value.ID)
	if err != nil {
		return CampaignTemplate{}, err
	}
	if !found {
		return CampaignTemplate{}, ErrNotFound
	}
	if prior.Generation != expected || prior.State == "archived" {
		return CampaignTemplate{}, ErrConflict
	}
	value.Generation = expected + 1
	value.State = "draft"
	value.UpdatedAt = time.Now().UTC()
	if err = validateCampaignTemplate(value); err != nil {
		return CampaignTemplate{}, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return CampaignTemplate{}, err
	}
	result, err := s.DB.ExecContext(ctx, `INSERT INTO marketing_templates_v2(id,tenant_id,generation,state,template_json,updated_at) SELECT ?,?,?,?,?,? WHERE (SELECT MAX(generation) FROM marketing_templates_v2 WHERE tenant_id=? AND id=?)=?`, value.ID, tenant, value.Generation, value.State, raw, value.UpdatedAt, tenant, value.ID, expected)
	if err != nil {
		return CampaignTemplate{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return CampaignTemplate{}, err
	}
	if affected != 1 {
		return CampaignTemplate{}, ErrConflict
	}
	return value, nil
}

func (s MarketingStore) SetTemplateState(ctx context.Context, tenant string, id CampaignTemplateID, expected uint64, target string) (CampaignTemplate, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(id)) || expected == 0 || target != "approved" && target != "archived" {
		return CampaignTemplate{}, ErrInvalidCommand
	}
	prior, found, err := s.LatestTemplate(ctx, tenant, id)
	if err != nil {
		return CampaignTemplate{}, err
	}
	if !found {
		return CampaignTemplate{}, ErrNotFound
	}
	if prior.Generation != expected || target == "approved" && prior.State != "draft" || target == "archived" && prior.State == "archived" {
		return CampaignTemplate{}, ErrConflict
	}
	next := prior
	next.Generation++
	next.State = target
	next.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(next)
	if err != nil {
		return CampaignTemplate{}, err
	}
	result, err := s.DB.ExecContext(ctx, `INSERT INTO marketing_templates_v2(id,tenant_id,generation,state,template_json,updated_at) SELECT ?,?,?,?,?,? WHERE (SELECT MAX(generation) FROM marketing_templates_v2 WHERE tenant_id=? AND id=?)=?`, next.ID, tenant, next.Generation, next.State, raw, next.UpdatedAt, tenant, next.ID, expected)
	if err != nil {
		return CampaignTemplate{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return CampaignTemplate{}, err
	}
	if affected != 1 {
		return CampaignTemplate{}, ErrConflict
	}
	return next, nil
}

func (s MarketingStore) LatestTemplate(ctx context.Context, tenant string, id CampaignTemplateID) (CampaignTemplate, bool, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(id)) {
		return CampaignTemplate{}, false, ErrInvalidCommand
	}
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT template_json FROM marketing_templates_v2 WHERE tenant_id=? AND id=? ORDER BY generation DESC LIMIT 1`, tenant, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return CampaignTemplate{}, false, nil
	}
	if err != nil {
		return CampaignTemplate{}, false, err
	}
	var value CampaignTemplate
	if err = strictJSON(raw, &value); err != nil || value.ID != id {
		return CampaignTemplate{}, false, errors.Join(ErrInvalidReceipt, err)
	}
	return value, true, nil
}

func (s MarketingStore) TemplateVersion(ctx context.Context, tenant, reference string) (CampaignTemplate, bool, error) {
	id, generation, err := parseCampaignTemplateReference(reference)
	if err != nil || s.DB == nil || ctx == nil || !validOpaque(tenant) {
		return CampaignTemplate{}, false, ErrInvalidCommand
	}
	var raw []byte
	err = s.DB.QueryRowContext(ctx, `SELECT template_json FROM marketing_templates_v2 WHERE tenant_id=? AND id=? AND generation=?`, tenant, id, generation).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return CampaignTemplate{}, false, nil
	}
	if err != nil {
		return CampaignTemplate{}, false, err
	}
	var value CampaignTemplate
	if err = strictJSON(raw, &value); err != nil || value.ID != id || value.Generation != generation {
		return CampaignTemplate{}, false, errors.Join(ErrInvalidReceipt, err)
	}
	return value, true, nil
}

// ApprovedTemplateVersion resolves the immutable generation named by a
// campaign while also honoring the template's current lifecycle. Archiving a
// template is therefore an immediate stop signal even for campaigns that were
// composed against an older approved generation.
func (s MarketingStore) ApprovedTemplateVersion(ctx context.Context, tenant, reference string) (CampaignTemplate, bool, error) {
	value, found, err := s.TemplateVersion(ctx, tenant, reference)
	if err != nil || !found {
		return value, found, err
	}
	latest, latestFound, err := s.LatestTemplate(ctx, tenant, value.ID)
	if err != nil {
		return CampaignTemplate{}, false, err
	}
	if !latestFound {
		return CampaignTemplate{}, false, ErrInvalidReceipt
	}
	if value.State != "approved" || latest.State == "archived" {
		return CampaignTemplate{}, true, ErrConflict
	}
	return value, true, nil
}

func (s MarketingStore) Templates(ctx context.Context, tenant string, limit int, cursor string) ([]CampaignTemplate, string, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) {
		return nil, "", ErrInvalidCommand
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	after, err := decodeCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT current.id,current.template_json FROM marketing_templates_v2 AS current JOIN (SELECT id,MAX(generation) AS generation FROM marketing_templates_v2 WHERE tenant_id=? GROUP BY id) AS latest ON latest.id=current.id AND latest.generation=current.generation WHERE current.tenant_id=? AND current.id>? ORDER BY current.id LIMIT ?`, tenant, tenant, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]CampaignTemplate, 0, limit+1)
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, "", err
		}
		var item CampaignTemplate
		if err = strictJSON(raw, &item); err != nil || string(item.ID) != id {
			return nil, "", errors.Join(ErrInvalidReceipt, err)
		}
		items = append(items, item)
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > limit {
		next = base64.RawURLEncoding.EncodeToString([]byte(ids[limit-1]))
		items = items[:limit]
	}
	return items, next, nil
}

func CampaignTemplateReference(value CampaignTemplate) string {
	return string(value.ID) + "." + strconv.FormatUint(value.Generation, 10)
}

func parseCampaignTemplateReference(reference string) (CampaignTemplateID, uint64, error) {
	index := strings.LastIndexByte(reference, '.')
	if index <= 0 || index == len(reference)-1 {
		return "", 0, ErrInvalidCommand
	}
	id := CampaignTemplateID(reference[:index])
	generation, err := strconv.ParseUint(reference[index+1:], 10, 64)
	if err != nil || generation == 0 || !validOpaque(string(id)) || !validOpaque(reference) {
		return "", 0, ErrInvalidCommand
	}
	return id, generation, nil
}

type CampaignTemplateVariables struct {
	ContactID      ContactID
	Address        Address
	UnsubscribeURL string
}

func RenderCampaignTemplate(value CampaignTemplate, variables CampaignTemplateVariables) (string, string, error) {
	if value.State != "approved" || validateCampaignTemplate(value) != nil || !validOpaque(string(variables.ContactID)) || ValidateAddress(variables.Address) != nil || !validHTTPSURL(variables.UnsubscribeURL) {
		return "", "", ErrInvalidCommand
	}
	replacements := map[string]string{
		"contact_id":      string(variables.ContactID),
		"email":           string(variables.Address),
		"unsubscribe_url": variables.UnsubscribeURL,
	}
	text, err := substituteCampaignVariables(value.Text, replacements)
	if err != nil {
		return "", "", err
	}
	htmlBody := "<pre>" + html.EscapeString(text) + "</pre>"
	return text, htmlBody, nil
}

func validateCampaignTemplate(value CampaignTemplate) error {
	if !validOpaque(string(value.ID)) || strings.TrimSpace(value.Name) == "" || len(value.Name) > 256 || strings.ContainsAny(value.Name, "\x00\r\n") || value.Text == "" || len(value.Text) > maximumCampaignTemplateBytes || strings.ContainsRune(value.Text, '\x00') || value.Generation == 0 || value.UpdatedAt.IsZero() {
		return ErrInvalidCommand
	}
	switch value.State {
	case "draft", "approved", "archived":
	default:
		return ErrInvalidCommand
	}
	_, err := substituteCampaignVariables(value.Text, map[string]string{"contact_id":"contact", "email":"recipient@example.invalid", "unsubscribe_url":"https://example.invalid/unsubscribe"})
	return err
}

func substituteCampaignVariables(source string, values map[string]string) (string, error) {
	var output strings.Builder
	output.Grow(len(source))
	for len(source) > 0 {
		start := strings.Index(source, "{{")
		if start < 0 {
			if strings.Contains(source, "}}") {
				return "", ErrInvalidCommand
			}
			output.WriteString(source)
			break
		}
		output.WriteString(source[:start])
		source = source[start+2:]
		end := strings.Index(source, "}}")
		if end < 0 {
			return "", ErrInvalidCommand
		}
		name := strings.TrimSpace(source[:end])
		value, ok := values[name]
		if !ok || name == "" {
			return "", ErrInvalidCommand
		}
		output.WriteString(value)
		source = source[end+2:]
	}
	if output.Len() > maximumCampaignTemplateBytes {
		return "", fmt.Errorf("%w: rendered campaign body too large", ErrInvalidCommand)
	}
	return output.String(), nil
}

func validHTTPSURL(value string) bool {
	if len(value) < 12 || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n\t ") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.User == nil && parsed.Hostname() != "" && parsed.Fragment == ""
}
