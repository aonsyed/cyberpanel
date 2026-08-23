// Package preview owns short-lived, host-bound site preview sessions.
package preview

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/sqlrepo"
)

var (
	ErrInvalid          = errors.New("preview session is invalid")
	ErrNotFound         = errors.New("preview session not found")
	ErrConflict         = errors.New("preview session conflicts with current site state")
	ErrExpired          = errors.New("preview session expired")
	ErrBudgetExhausted  = errors.New("preview request budget exhausted")
	ErrRecoveryRequired = errors.New("preview session requires recovery")
)

type State string

const (
	StatePreparing        State = "preparing"
	StateActive           State = "active"
	StateExhausted        State = "exhausted"
	StateExpired          State = "expired"
	StateRevoked          State = "revoked"
	StateRecoveryRequired State = "recovery_required"
)

const (
	DefaultRequestBudget uint32 = 128
	MaximumRequestBudget uint32 = 4096
)

// Session deliberately stores no bearer token separate from Hostname. The
// randomly generated, exact preview hostname is the opaque capability. Panel
// cookies are host-only on a separately configured registrable domain and
// therefore cannot reach this host.
type Session struct {
	ID                 string    `json:"id"`
	CommandID          string    `json:"command_id"`
	RequestDigest      string    `json:"request_digest"`
	TenantID           string    `json:"tenant_id"`
	SiteID             string    `json:"site_id"`
	ViewerPrincipalID  string    `json:"viewer_principal_id"`
	ViewerCredentialID string    `json:"viewer_credential_id"`
	AuthzEpoch         uint64    `json:"authz_epoch"`
	Hostname           string    `json:"hostname"`
	SourceGeneration   uint64    `json:"source_generation"`
	BindingGeneration  uint64    `json:"binding_generation,omitempty"`
	RequestBudget      uint32    `json:"request_budget"`
	ConsumedRequests   uint32    `json:"consumed_requests"`
	State              State     `json:"state"`
	Failure            string    `json:"failure,omitempty"`
	ExpiresAt          time.Time `json:"expires_at"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func (session Session) Validate(previewDomain string) error {
	if !safeIdentifier(session.ID, 128) || !safeIdentifier(session.CommandID, 256) || !validDigest(session.RequestDigest) || !safeIdentifier(session.ViewerPrincipalID, 128) || !safeIdentifier(session.ViewerCredentialID, 128) || session.AuthzEpoch == 0 || session.SourceGeneration == 0 || session.RequestBudget == 0 || session.RequestBudget > MaximumRequestBudget || session.ConsumedRequests > session.RequestBudget || session.ExpiresAt.IsZero() || session.CreatedAt.IsZero() || session.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	if _, err := site.NewTenantID(session.TenantID); err != nil { return ErrInvalid }
	if _, err := site.NewSiteID(session.SiteID); err != nil { return ErrInvalid }
	hostname, err := site.ParseHostname(session.Hostname)
	if err != nil || hostname.String() != session.Hostname || !strings.HasSuffix(session.Hostname, "."+previewDomain) { return ErrInvalid }
	switch session.State {
	case StatePreparing:
		if session.BindingGeneration != 0 { return ErrInvalid }
	case StateActive, StateExhausted, StateExpired, StateRevoked, StateRecoveryRequired:
		if session.BindingGeneration <= session.SourceGeneration { return ErrInvalid }
	default:
		return ErrInvalid
	}
	if len(session.Failure) > 2048 || strings.IndexByte(session.Failure, 0) >= 0 { return ErrInvalid }
	return nil
}

const Schema = `
CREATE TABLE IF NOT EXISTS hosting_preview_sessions (
 id TEXT PRIMARY KEY,
 command_id TEXT NOT NULL UNIQUE,
 request_digest TEXT NOT NULL,
 tenant_id TEXT NOT NULL,
 site_id TEXT NOT NULL,
 viewer_principal_id TEXT NOT NULL,
 viewer_credential_id TEXT NOT NULL,
 authz_epoch BIGINT NOT NULL,
 hostname TEXT NOT NULL UNIQUE,
 source_generation BIGINT NOT NULL,
 binding_generation BIGINT NOT NULL,
 request_budget BIGINT NOT NULL,
 consumed_requests BIGINT NOT NULL,
 state TEXT NOT NULL,
 failure TEXT NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 created_at TIMESTAMP NOT NULL,
 updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS hosting_preview_expiry ON hosting_preview_sessions(state, expires_at);
CREATE INDEX IF NOT EXISTS hosting_preview_site ON hosting_preview_sessions(tenant_id, site_id, state);
`

type Repository struct {
	db      *sql.DB
	domain  string
	clock   func() time.Time
}

func NewRepository(db *sql.DB, previewDomain string) (*Repository, error) {
	if db == nil || !validRegistrableDomain(previewDomain) { return nil, ErrInvalid }
	return &Repository{db: db, domain: strings.ToLower(previewDomain), clock: time.Now}, nil
}

func (repository *Repository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil { return ErrInvalid }
	_, err := repository.db.ExecContext(ctx, Schema)
	return err
}

func (repository *Repository) ByCommand(ctx context.Context, commandID string) (Session, error) {
	if repository == nil || !safeIdentifier(commandID, 256) { return Session{}, ErrInvalid }
	return repository.query(ctx, `SELECT `+sessionColumns+` FROM hosting_preview_sessions WHERE command_id=?`, commandID)
}

func (repository *Repository) ByHostname(ctx context.Context, hostname string) (Session, error) {
	if repository == nil { return Session{}, ErrInvalid }
	return repository.query(ctx, `SELECT `+sessionColumns+` FROM hosting_preview_sessions WHERE hostname=?`, strings.ToLower(hostname))
}

func (repository *Repository) Admit(ctx context.Context, proposed Session) (Session, bool, error) {
	if repository == nil || proposed.Validate(repository.domain) != nil || proposed.State != StatePreparing { return Session{}, false, ErrInvalid }
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return Session{}, false, err }
	defer tx.Rollback()
	existing, err := querySession(tx.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM hosting_preview_sessions WHERE command_id=?`, proposed.CommandID), repository.domain)
	if err == nil {
		if existing.RequestDigest != proposed.RequestDigest { return Session{}, false, ErrConflict }
		return existing, false, tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) { return Session{}, false, err }
	_, err = tx.ExecContext(ctx, `INSERT INTO hosting_preview_sessions (`+sessionColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, sessionValues(proposed)...)
	if err != nil { return Session{}, false, err }
	if err = tx.Commit(); err != nil { return Session{}, false, err }
	return proposed, true, nil
}

func (repository *Repository) Activate(ctx context.Context, id string, bindingGeneration uint64) (Session, error) {
	if repository == nil || !safeIdentifier(id, 128) || bindingGeneration == 0 { return Session{}, ErrInvalid }
	now := repository.clock().UTC()
	result, err := repository.db.ExecContext(ctx, `UPDATE hosting_preview_sessions SET binding_generation=?,state=?,updated_at=? WHERE id=? AND state=? AND binding_generation=0 AND source_generation<?`, bindingGeneration, StateActive, now, id, StatePreparing, bindingGeneration)
	if err != nil { return Session{}, err }
	changed, err := result.RowsAffected()
	if err != nil { return Session{}, err }
	if changed != 1 {
		session, loadErr := repository.query(ctx, `SELECT `+sessionColumns+` FROM hosting_preview_sessions WHERE id=?`, id)
		if loadErr == nil && session.BindingGeneration == bindingGeneration && session.State == StateActive { return session, nil }
		if loadErr != nil { return Session{}, loadErr }
		return Session{}, ErrConflict
	}
	return repository.query(ctx, `SELECT `+sessionColumns+` FROM hosting_preview_sessions WHERE id=?`, id)
}

// Consume is the transaction boundary used by the untrusted preview gateway.
// It verifies the exact site generation in the same control-database
// transaction that spends one request, so a stale hostname cannot cross into a
// newly changed site generation.
func (repository *Repository) Consume(ctx context.Context, hostname string, now time.Time) (Session, error) {
	if repository == nil || now.IsZero() { return Session{}, ErrInvalid }
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return Session{}, err }
	defer tx.Rollback()
	session, err := querySession(tx.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM hosting_preview_sessions WHERE hostname=?`, strings.ToLower(hostname)), repository.domain)
	if err != nil { return Session{}, err }
	if session.State != StateActive { if session.State == StateExhausted { return Session{}, ErrBudgetExhausted }; return Session{}, ErrExpired }
	if !now.UTC().Before(session.ExpiresAt) {
		_, _ = tx.ExecContext(ctx, `UPDATE hosting_preview_sessions SET state=?,updated_at=? WHERE id=? AND state=?`, StateExpired, now.UTC(), session.ID, StateActive)
		_ = tx.Commit()
		return Session{}, ErrExpired
	}
	var generation uint64
	if err = tx.QueryRowContext(ctx, `SELECT generation FROM hosting_sites WHERE tenant_id=? AND site_id=?`, session.TenantID, session.SiteID).Scan(&generation); err != nil || generation != session.BindingGeneration {
		_, _ = tx.ExecContext(ctx, `UPDATE hosting_preview_sessions SET state=?,failure=?,updated_at=? WHERE id=? AND state=?`, StateRecoveryRequired, "site generation changed", now.UTC(), session.ID, StateActive)
		_ = tx.Commit()
		return Session{}, ErrConflict
	}
	next := session.ConsumedRequests + 1
	nextState := StateActive
	if next >= session.RequestBudget { nextState = StateExhausted }
	result, err := tx.ExecContext(ctx, `UPDATE hosting_preview_sessions SET consumed_requests=?,state=?,updated_at=? WHERE id=? AND state=? AND consumed_requests=?`, next, nextState, now.UTC(), session.ID, StateActive, session.ConsumedRequests)
	if err != nil { return Session{}, err }
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 { if err == nil { err = ErrConflict }; return Session{}, err }
	session.ConsumedRequests, session.State, session.UpdatedAt = next, nextState, now.UTC()
	if err = tx.Commit(); err != nil { return Session{}, err }
	return session, nil
}

func (repository *Repository) ExpirationCandidates(ctx context.Context, now time.Time, limit int) ([]Session, error) {
	if repository == nil || now.IsZero() || limit < 1 || limit > 500 { return nil, ErrInvalid }
	rows, err := repository.db.QueryContext(ctx, `SELECT `+sessionColumns+` FROM hosting_preview_sessions WHERE (state IN (?,?) OR (state=? AND expires_at<=?)) ORDER BY expires_at,id LIMIT ?`, StateExhausted, StateRecoveryRequired, StateActive, now.UTC(), limit)
	if err != nil { return nil, err }
	defer rows.Close()
	values := make([]Session, 0, limit)
	for rows.Next() {
		value, scanErr := scanSession(rows, repository.domain)
		if scanErr != nil { return nil, scanErr }
		values = append(values, value)
	}
	return values, rows.Err()
}

func (repository *Repository) Close(ctx context.Context, id string, state State, failure string) error {
	if repository == nil || !safeIdentifier(id, 128) || state != StateExpired && state != StateRevoked && state != StateRecoveryRequired || len(failure) > 2048 || strings.IndexByte(failure, 0) >= 0 { return ErrInvalid }
	result, err := repository.db.ExecContext(ctx, `UPDATE hosting_preview_sessions SET state=?,failure=?,updated_at=? WHERE id=? AND state NOT IN (?,?)`, state, failure, repository.clock().UTC(), id, StateExpired, StateRevoked)
	if err != nil { return err }
	changed, err := result.RowsAffected()
	if err != nil { return err }
	if changed == 0 {
		existing, loadErr := repository.query(ctx, `SELECT `+sessionColumns+` FROM hosting_preview_sessions WHERE id=?`, id)
		if loadErr != nil { return loadErr }
		if existing.State == state || existing.State == StateExpired || existing.State == StateRevoked { return nil }
		return ErrConflict
	}
	return nil
}

func (repository *Repository) query(ctx context.Context, statement string, args ...any) (Session, error) {
	return querySession(repository.db.QueryRowContext(ctx, statement, args...), repository.domain)
}

const sessionColumns = `id,command_id,request_digest,tenant_id,site_id,viewer_principal_id,viewer_credential_id,authz_epoch,hostname,source_generation,binding_generation,request_budget,consumed_requests,state,failure,expires_at,created_at,updated_at`

func sessionValues(value Session) []any {
	return []any{value.ID,value.CommandID,value.RequestDigest,value.TenantID,value.SiteID,value.ViewerPrincipalID,value.ViewerCredentialID,value.AuthzEpoch,value.Hostname,value.SourceGeneration,value.BindingGeneration,value.RequestBudget,value.ConsumedRequests,value.State,value.Failure,value.ExpiresAt,value.CreatedAt,value.UpdatedAt}
}

type rowScanner interface { Scan(...any) error }

func querySession(row rowScanner, domain string) (Session, error) { return scanSession(row, domain) }

func scanSession(row rowScanner, domain string) (Session, error) {
	var value Session
	err := row.Scan(&value.ID,&value.CommandID,&value.RequestDigest,&value.TenantID,&value.SiteID,&value.ViewerPrincipalID,&value.ViewerCredentialID,&value.AuthzEpoch,&value.Hostname,&value.SourceGeneration,&value.BindingGeneration,&value.RequestBudget,&value.ConsumedRequests,&value.State,&value.Failure,&value.ExpiresAt,&value.CreatedAt,&value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) { return Session{}, ErrNotFound }
	if err != nil { return Session{}, err }
	if value.Validate(domain) != nil { return Session{}, ErrRecoveryRequired }
	return value, nil
}

type RandomSource interface { Read([]byte) (int, error) }

type IssueRequest struct {
	CommandID          string
	TenantID           site.TenantID
	SiteID             site.SiteID
	ExpectedGeneration uint64
	ViewerPrincipalID  string
	ViewerCredentialID string
	AuthzEpoch         uint64
	TTL                time.Duration
	RequestBudget      uint32
}

type Resolution struct {
	SessionID         string    `json:"session_id"`
	PreviewHostname   string    `json:"preview_hostname"`
	TargetHostname    string    `json:"target_hostname"`
	TenantID          string    `json:"tenant_id"`
	SiteID            string    `json:"site_id"`
	SiteGeneration    uint64    `json:"site_generation"`
	ConsumedRequests  uint32    `json:"consumed_requests"`
	RemainingRequests uint32    `json:"remaining_requests"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type Service struct {
	Store                 *Repository
	Sites                 *sqlrepo.Repository
	Commands              hostingservice.Service
	PanelRegistrableDomain string
	PreviewDomain         string
	Random                RandomSource
	Now                   func() time.Time
}

func NewService(store *Repository, sites *sqlrepo.Repository, commands hostingservice.Service, panelDomain, previewDomain string) (*Service, error) {
	panelDomain, previewDomain = strings.ToLower(panelDomain), strings.ToLower(previewDomain)
	if store == nil || sites == nil || !validRegistrableDomain(panelDomain) || !validRegistrableDomain(previewDomain) || panelDomain == previewDomain || strings.HasSuffix(panelDomain, "."+previewDomain) || strings.HasSuffix(previewDomain, "."+panelDomain) || store.domain != previewDomain {
		return nil, ErrInvalid
	}
	return &Service{Store:store,Sites:sites,Commands:commands,PanelRegistrableDomain:panelDomain,PreviewDomain:previewDomain,Random:rand.Reader,Now:time.Now},nil
}

func (service *Service) now() time.Time { if service.Now != nil { return service.Now().UTC() }; return time.Now().UTC() }

func (service *Service) Issue(ctx context.Context, request IssueRequest) (Session, error) {
	if service == nil || service.Store == nil || service.Sites == nil || service.Random == nil || !safeIdentifier(request.CommandID, 256) || request.TenantID.String() == "" || request.SiteID.String() == "" || request.ExpectedGeneration == 0 || !safeIdentifier(request.ViewerPrincipalID,128) || !safeIdentifier(request.ViewerCredentialID,128) || request.AuthzEpoch == 0 || request.TTL < time.Minute || request.TTL > time.Hour {
		return Session{}, ErrInvalid
	}
	if request.RequestBudget == 0 { request.RequestBudget = DefaultRequestBudget }
	if request.RequestBudget > MaximumRequestBudget { return Session{}, ErrInvalid }
	digest := issueDigest(request)
	if existing, err := service.Store.ByCommand(ctx, request.CommandID); err == nil {
		if existing.RequestDigest != digest { return Session{}, ErrConflict }
		return service.resume(ctx, existing)
	} else if !errors.Is(err, ErrNotFound) { return Session{}, err }
	aggregate, err := service.Sites.Load(ctx, request.TenantID, request.SiteID)
	if err != nil { return Session{}, err }
	if aggregate.Generation() != request.ExpectedGeneration || aggregate.Lifecycle() != site.LifecycleActive { return Session{}, ErrConflict }
	token := make([]byte, 24)
	if _, err = io.ReadFull(service.Random, token); err != nil { return Session{}, err }
	hostname := "p-" + hex.EncodeToString(token) + "." + service.PreviewDomain
	for index := range token { token[index] = 0 }
	if _, err = site.ParseHostname(hostname); err != nil { return Session{}, ErrInvalid }
	now := service.now()
	identifier := sha256.Sum256([]byte("cyberpanel:preview-session:v1\x00"+request.CommandID+"\x00"+hostname))
	proposed := Session{ID:"preview-"+hex.EncodeToString(identifier[:])[:48],CommandID:request.CommandID,RequestDigest:digest,TenantID:request.TenantID.String(),SiteID:request.SiteID.String(),ViewerPrincipalID:request.ViewerPrincipalID,ViewerCredentialID:request.ViewerCredentialID,AuthzEpoch:request.AuthzEpoch,Hostname:hostname,SourceGeneration:request.ExpectedGeneration,RequestBudget:request.RequestBudget,State:StatePreparing,ExpiresAt:now.Add(request.TTL),CreatedAt:now,UpdatedAt:now}
	admitted, _, err := service.Store.Admit(ctx, proposed)
	if err != nil { return Session{}, err }
	return service.resume(ctx, admitted)
}

// Resolve spends one request and returns only the fixed local proxy target.
// The caller never supplies an upstream address, port, scheme, or Host value.
func (service *Service) Resolve(ctx context.Context, hostname string) (Resolution, error) {
	if service == nil || service.Store == nil || service.Sites == nil { return Resolution{}, ErrInvalid }
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	parsed, err := site.ParseHostname(hostname)
	if err != nil || !strings.HasSuffix(parsed.String(), "."+service.PreviewDomain) { return Resolution{}, ErrNotFound }
	session, err := service.Store.Consume(ctx, parsed.String(), service.now())
	if err != nil { return Resolution{}, err }
	tenant, err := site.NewTenantID(session.TenantID)
	if err != nil { return Resolution{}, ErrRecoveryRequired }
	siteID, err := site.NewSiteID(session.SiteID)
	if err != nil { return Resolution{}, ErrRecoveryRequired }
	aggregate, err := service.Sites.Load(ctx, tenant, siteID)
	if err != nil || aggregate.Generation() != session.BindingGeneration || aggregate.Lifecycle() != site.LifecycleActive { return Resolution{}, ErrConflict }
	target := ""
	for _, binding := range aggregate.Bindings() { if binding.Kind == site.BindingPrimary { target = binding.Hostname.String(); break } }
	if target == "" || target == session.Hostname { return Resolution{}, ErrRecoveryRequired }
	return Resolution{SessionID:session.ID,PreviewHostname:session.Hostname,TargetHostname:target,TenantID:session.TenantID,SiteID:session.SiteID,SiteGeneration:session.BindingGeneration,ConsumedRequests:session.ConsumedRequests,RemainingRequests:session.RequestBudget-session.ConsumedRequests,ExpiresAt:session.ExpiresAt},nil
}

func (service *Service) resume(ctx context.Context, session Session) (Session, error) {
	if session.State == StateActive && service.now().Before(session.ExpiresAt) { return session, nil }
	if session.State != StatePreparing { if session.State == StateRecoveryRequired { return Session{}, ErrRecoveryRequired }; return Session{}, ErrExpired }
	hostname, err := site.ParseHostname(session.Hostname)
	if err != nil { return Session{}, ErrInvalid }
	tenant, _ := site.NewTenantID(session.TenantID)
	siteID, _ := site.NewSiteID(session.SiteID)
	receipt, err := service.Commands.Handle(ctx, hostingservice.AttachDomainBinding{CommandID:session.CommandID+"-binding",Actor:hostingservice.Actor{TenantID:tenant},TenantID:tenant,SiteID:siteID,ExpectedGeneration:session.SourceGeneration,Binding:site.DomainBinding{Hostname:hostname,Kind:site.BindingPreview}})
	if err != nil { return Session{}, err }
	if receipt.Status != hostingservice.OperationApplied || receipt.Request.Projection.Generation <= session.SourceGeneration { return Session{}, ErrRecoveryRequired }
	active, err := service.Store.Activate(ctx, session.ID, receipt.Request.Projection.Generation)
	if err != nil { return Session{}, errors.Join(ErrRecoveryRequired, err) }
	return active, nil
}

// Reap withdraws expired or spent preview hostnames through the same durable
// node-wide activation path used to attach them.
func (service *Service) Reap(ctx context.Context, limit int) (int, error) {
	if service == nil || limit < 1 || limit > 500 { return 0, ErrInvalid }
	candidates, err := service.Store.ExpirationCandidates(ctx, service.now(), limit)
	if err != nil { return 0, err }
	closed := 0
	for _, session := range candidates {
		tenant, tenantErr := site.NewTenantID(session.TenantID)
		siteID, siteErr := site.NewSiteID(session.SiteID)
		hostname, hostnameErr := site.ParseHostname(session.Hostname)
		if tenantErr != nil || siteErr != nil || hostnameErr != nil { _ = service.Store.Close(ctx,session.ID,StateRecoveryRequired,"invalid stored preview scope"); continue }
		aggregate, loadErr := service.Sites.Load(ctx, tenant, siteID)
		if errors.Is(loadErr, hostingservice.ErrNotFound) { if service.Store.Close(ctx,session.ID,StateExpired,"")==nil { closed++ }; continue }
		if loadErr != nil { continue }
		bindingFound := false
		for _, binding := range aggregate.Bindings() { if binding.Hostname == hostname { bindingFound = binding.Kind == site.BindingPreview; if !bindingFound { _=service.Store.Close(ctx,session.ID,StateRecoveryRequired,"preview hostname ownership changed") }; break } }
		if !bindingFound {
			current, _ := service.Store.ByCommand(ctx, session.CommandID)
			if current.State != StateRecoveryRequired && service.Store.Close(ctx,session.ID,StateExpired,"")==nil { closed++ }
			continue
		}
		commandID := fmt.Sprintf("%s-expire-%d", session.ID, aggregate.Generation())
		_, detachErr := service.Commands.Handle(ctx, hostingservice.DetachDomainBinding{CommandID:commandID,Actor:hostingservice.Actor{TenantID:tenant},TenantID:tenant,SiteID:siteID,ExpectedGeneration:aggregate.Generation(),Hostname:hostname})
		if detachErr != nil { continue }
		if service.Store.Close(ctx,session.ID,StateExpired,"")==nil { closed++ }
	}
	return closed, nil
}

func (service *Service) RunJanitor(ctx context.Context, interval time.Duration) {
	if service == nil { return }
	if interval < 5*time.Second { interval = 30*time.Second }
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-ticker.C: _, _ = service.Reap(ctx, 128)
		}
	}
}

func issueDigest(request IssueRequest) string {
	raw, _ := json.Marshal(struct{Version uint8 `json:"version"`;CommandID,TenantID,SiteID,ViewerPrincipalID,ViewerCredentialID string;ExpectedGeneration,AuthzEpoch uint64;TTLNanoseconds int64;RequestBudget uint32}{1,request.CommandID,request.TenantID.String(),request.SiteID.String(),request.ViewerPrincipalID,request.ViewerCredentialID,request.ExpectedGeneration,request.AuthzEpoch,int64(request.TTL),request.RequestBudget})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validRegistrableDomain(value string) bool { parsed, err := site.ParseHostname(strings.ToLower(value)); return err == nil && parsed.String() == strings.ToLower(value) }
func validDigest(value string) bool { if len(value)!=64{return false};_,err:=hex.DecodeString(value);return err==nil }
func safeIdentifier(value string, maximum int) bool { if value==""||len(value)>maximum||strings.TrimSpace(value)!=value{return false};for index:=range value{character:=value[index];if !((character>='a'&&character<='z')||(character>='A'&&character<='Z')||(character>='0'&&character<='9')||character=='-'||character=='_'||character=='.'||character==':'){return false}};return true }
