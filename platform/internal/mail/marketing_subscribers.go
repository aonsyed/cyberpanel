package mail

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const maximumSubscriberTags = 64

func (s MarketingStore) CreateSubscriber(ctx context.Context, tenant string, value Subscriber) (Subscriber, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || value.Generation != 0 && value.Generation != 1 {
		return Subscriber{}, ErrInvalidCommand
	}
	if !validSubscriberTagsInput(value.Tags) {
		return Subscriber{}, ErrInvalidCommand
	}
	value.Address = canonicalMarketingAddress(value.Address)
	value.Tags = normalizeSubscriberTags(value.Tags)
	value.State = SubscriberActive
	value.Verification = VerificationUnverified
	value.VerificationRef = ""
	value.Generation = 1
	value.CreatedAt = time.Now().UTC()
	value.UpdatedAt = value.CreatedAt
	if err := validateSubscriber(value); err != nil {
		return Subscriber{}, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return Subscriber{}, err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO marketing_subscribers_v2(id,tenant_id,address,generation,state,subscriber_json,updated_at) VALUES(?,?,?,?,?,?,?)`, value.ID, tenant, value.Address, value.Generation, value.State, raw, value.UpdatedAt)
	return value, err
}

func (s MarketingStore) ReviseSubscriber(ctx context.Context, tenant string, value Subscriber, expected uint64) (Subscriber, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || expected == 0 || !validOpaque(string(value.ID)) {
		return Subscriber{}, ErrInvalidCommand
	}
	prior, found, err := s.Subscriber(ctx, tenant, value.ID)
	if err != nil {
		return Subscriber{}, err
	}
	if !found {
		return Subscriber{}, ErrNotFound
	}
	if prior.Generation != expected || prior.State != SubscriberActive {
		return Subscriber{}, ErrConflict
	}
	if !validSubscriberTagsInput(value.Tags) {
		return Subscriber{}, ErrInvalidCommand
	}
	value.Address = canonicalMarketingAddress(value.Address)
	value.Tags = normalizeSubscriberTags(value.Tags)
	value.State = prior.State
	value.Verification = prior.Verification
	value.VerificationRef = prior.VerificationRef
	if value.Address != prior.Address {
		value.Verification = VerificationUnverified
		value.VerificationRef = ""
	}
	value.Generation = expected + 1
	value.CreatedAt = prior.CreatedAt
	value.UpdatedAt = time.Now().UTC()
	if err = validateSubscriber(value); err != nil {
		return Subscriber{}, err
	}
	return s.replaceSubscriber(ctx, tenant, value, expected)
}

func (s MarketingStore) SetSubscriberState(ctx context.Context, tenant string, id ContactID, expected uint64, target SubscriberState) (Subscriber, error) {
	if target != SubscriberActive && target != SubscriberArchived {
		return Subscriber{}, ErrInvalidCommand
	}
	value, found, err := s.Subscriber(ctx, tenant, id)
	if err != nil {
		return Subscriber{}, err
	}
	if !found {
		return Subscriber{}, ErrNotFound
	}
	if value.Generation != expected || value.State == target {
		return Subscriber{}, ErrConflict
	}
	value.State = target
	value.Generation++
	value.UpdatedAt = time.Now().UTC()
	return s.replaceSubscriber(ctx, tenant, value, expected)
}

func (s MarketingStore) RecordSubscriberVerification(ctx context.Context, tenant string, id ContactID, expected uint64, state VerificationState, evidenceRef string) (Subscriber, error) {
	if state != VerificationVerified && state != VerificationInvalid && state != VerificationRisky && state != VerificationUnknown || !validOpaque(evidenceRef) {
		return Subscriber{}, ErrInvalidCommand
	}
	value, found, err := s.Subscriber(ctx, tenant, id)
	if err != nil {
		return Subscriber{}, err
	}
	if !found {
		return Subscriber{}, ErrNotFound
	}
	if value.Generation != expected || value.State != SubscriberActive {
		return Subscriber{}, ErrConflict
	}
	value.Verification = state
	value.VerificationRef = evidenceRef
	value.Generation++
	value.UpdatedAt = time.Now().UTC()
	return s.replaceSubscriber(ctx, tenant, value, expected)
}

func (s MarketingStore) Subscriber(ctx context.Context, tenant string, id ContactID) (Subscriber, bool, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(id)) {
		return Subscriber{}, false, ErrInvalidCommand
	}
	return s.loadSubscriber(ctx, `SELECT subscriber_json FROM marketing_subscribers_v2 WHERE tenant_id=? AND id=?`, tenant, id)
}

func (s MarketingStore) SubscriberByAddress(ctx context.Context, tenant string, address Address) (Subscriber, bool, error) {
	address = canonicalMarketingAddress(address)
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || ValidateAddress(address) != nil {
		return Subscriber{}, false, ErrInvalidCommand
	}
	return s.loadSubscriber(ctx, `SELECT subscriber_json FROM marketing_subscribers_v2 WHERE tenant_id=? AND address=?`, tenant, address)
}

func (s MarketingStore) Subscribers(ctx context.Context, tenant string, state SubscriberState, limit int, cursor string) ([]Subscriber, string, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || state != "" && state != SubscriberActive && state != SubscriberArchived {
		return nil, "", ErrInvalidCommand
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	after, err := decodeCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	query := `SELECT id,subscriber_json FROM marketing_subscribers_v2 WHERE tenant_id=? AND id>?`
	arguments := []any{tenant, after}
	if state != "" {
		query += ` AND state=?`
		arguments = append(arguments, state)
	}
	query += ` ORDER BY id LIMIT ?`
	arguments = append(arguments, limit+1)
	rows, err := s.DB.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]Subscriber, 0, limit+1)
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, "", err
		}
		var item Subscriber
		if err = strictJSON(raw, &item); err != nil || string(item.ID) != id || validateSubscriber(item) != nil {
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

func (s MarketingStore) DeleteSubscriberGeneration(ctx context.Context, tenant string, id ContactID, expected uint64) error {
	value, found, err := s.Subscriber(ctx, tenant, id)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	if expected == 0 || value.Generation != expected || value.State != SubscriberArchived {
		return ErrConflict
	}
	result, err := s.DB.ExecContext(ctx, `DELETE FROM marketing_subscribers_v2 WHERE tenant_id=? AND id=? AND generation=? AND state=?`, tenant, id, expected, SubscriberArchived)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrConflict
	}
	return nil
}

func (s MarketingStore) replaceSubscriber(ctx context.Context, tenant string, value Subscriber, expected uint64) (Subscriber, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return Subscriber{}, err
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE marketing_subscribers_v2 SET address=?,generation=?,state=?,subscriber_json=?,updated_at=? WHERE tenant_id=? AND id=? AND generation=?`, value.Address, value.Generation, value.State, raw, value.UpdatedAt, tenant, value.ID, expected)
	if err != nil {
		return Subscriber{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Subscriber{}, err
	}
	if affected != 1 {
		return Subscriber{}, ErrConflict
	}
	return value, nil
}

func (s MarketingStore) loadSubscriber(ctx context.Context, query string, arguments ...any) (Subscriber, bool, error) {
	var raw []byte
	err := s.DB.QueryRowContext(ctx, query, arguments...).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Subscriber{}, false, nil
	}
	if err != nil {
		return Subscriber{}, false, err
	}
	var value Subscriber
	if err = strictJSON(raw, &value); err != nil || validateSubscriber(value) != nil {
		return Subscriber{}, false, errors.Join(ErrInvalidReceipt, err)
	}
	return value, true, nil
}

func (s MarketingStore) validateListSubscribers(ctx context.Context, tenant string, ids []ContactID) error {
	for start := 0; start < len(ids); start += 200 {
		end := start + 200
		if end > len(ids) {
			end = len(ids)
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", end-start), ",")
		arguments := make([]any, 0, end-start+2)
		arguments = append(arguments, tenant, SubscriberActive)
		for _, id := range ids[start:end] {
			arguments = append(arguments, id)
		}
		query := fmt.Sprintf(`SELECT COUNT(*) FROM marketing_subscribers_v2 WHERE tenant_id=? AND state=? AND id IN (%s)`, placeholders)
		var count int
		if err := s.DB.QueryRowContext(ctx, query, arguments...).Scan(&count); err != nil {
			return err
		}
		if count != end-start {
			return ErrConflict
		}
	}
	return nil
}

func (s MarketingStore) validateConsentSubscriberBinding(ctx context.Context, event ConsentEvent) error {
	subscriber, found, err := s.Subscriber(ctx, event.TenantID, event.ContactID)
	if err != nil {
		return err
	}
	if event.State == Consented {
		if !found {
			return ErrNotFound
		}
		if subscriber.State != SubscriberActive || subscriber.Address != event.Address {
			return ErrConflict
		}
		return nil
	}
	if found && subscriber.Address != event.Address {
		return ErrConflict
	}
	return nil
}

func validateSubscriber(value Subscriber) error {
	if !validOpaque(string(value.ID)) || ValidateAddress(value.Address) != nil || value.Address != canonicalMarketingAddress(value.Address) || len(value.Name) > 256 || strings.ContainsAny(value.Name, "\x00\r\n") || len(value.Tags) > maximumSubscriberTags || value.Generation == 0 || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return ErrInvalidCommand
	}
	if value.State != SubscriberActive && value.State != SubscriberArchived {
		return ErrInvalidCommand
	}
	switch value.Verification {
	case VerificationUnverified:
		if value.VerificationRef != "" {
			return ErrInvalidCommand
		}
	case VerificationVerified, VerificationInvalid, VerificationRisky, VerificationUnknown:
		if !validOpaque(value.VerificationRef) {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	if normalized := normalizeSubscriberTags(value.Tags); len(normalized) != len(value.Tags) {
		return ErrInvalidCommand
	} else {
		for index := range normalized {
			if normalized[index] != value.Tags[index] {
				return ErrInvalidCommand
			}
		}
	}
	return nil
}

func normalizeSubscriberTags(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if !validOpaque(value) {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func validSubscriberTagsInput(values []string) bool {
	if len(values) > maximumSubscriberTags {
		return false
	}
	for _, value := range values {
		if !validOpaque(strings.ToLower(strings.TrimSpace(value))) {
			return false
		}
	}
	return true
}

func canonicalMarketingAddress(value Address) Address {
	return Address(strings.ToLower(strings.TrimSpace(string(value))))
}
