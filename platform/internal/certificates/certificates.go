// Package certificates defines durable ACME issuance and immutable deployment.
package certificates

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type AccountID string; type PolicyID string; type OrderID string; type ChallengeID string; type CertificateID string; type DeploymentID string
type ChallengeKind string
const ( HTTP01 ChallengeKind = "http-01"; DNS01 ChallengeKind = "dns-01" )
type Account struct { ID AccountID `json:"id"`; Directory string `json:"directory"`; KeyRef string `json:"key_ref"`; Contact []string `json:"contact"` }
type Policy struct { ID PolicyID `json:"id"`; Account AccountID `json:"account"`; Names []string `json:"names"`; Wildcard bool `json:"wildcard"`; Preferred ChallengeKind `json:"challenge"`; RenewBefore time.Duration `json:"renew_before"` }
type Order struct { ID OrderID `json:"id"`; Policy PolicyID `json:"policy"`; Key string `json:"key"`; State string `json:"state"`; CreatedAt time.Time `json:"created_at"` }
type Challenge struct { ID ChallengeID `json:"id"`; Order OrderID `json:"order"`; Kind ChallengeKind `json:"kind"`; Name string `json:"name"`; Token string `json:"token"`; URL string `json:"url,omitempty"`; KeyAuthorization string `json:"key_authorization,omitempty"`; DNSValue string `json:"dns_value,omitempty"`; TenantID string `json:"tenant_id,omitempty"`; State string `json:"state"` }
type Generation struct { ID CertificateID `json:"id"`; Order OrderID `json:"order"`; PEM []byte `json:"pem"`; Chain []byte `json:"chain"`; PrivateKeyRef string `json:"private_key_ref"`; NotBefore time.Time `json:"not_before"`; NotAfter time.Time `json:"not_after"` }
type Deployment struct { ID DeploymentID `json:"id"`; Consumer string `json:"consumer"`; Generation CertificateID `json:"generation"`; ImmutablePath string `json:"immutable_path"`; DeployedAt time.Time `json:"deployed_at"` }
type HTTP01Presenter interface { PresentHTTP01(context.Context, Challenge) error; RemoveHTTP01(context.Context, Challenge) error }
type DNS01Presenter interface { PresentDNS01(context.Context, Challenge) error; RemoveDNS01(context.Context, Challenge) error }
type ACME interface { EnsureAccount(context.Context, Account) error; CreateOrder(context.Context, Account, Policy, Order) ([]Challenge, error); Finalize(context.Context, OrderID) (Generation, error) }

const Schema = `CREATE TABLE IF NOT EXISTS certificate_orders (id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, order_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS certificate_challenges (id TEXT PRIMARY KEY, order_id TEXT NOT NULL, challenge_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS certificate_generations (id TEXT PRIMARY KEY, generation_json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS certificate_deployments (id TEXT PRIMARY KEY, consumer TEXT NOT NULL, generation_id TEXT NOT NULL, deployment_json TEXT NOT NULL, UNIQUE(consumer, generation_id));`
type Repository struct { DB *sql.DB }
func (r Repository) Bootstrap(ctx context.Context) error { if r.DB == nil { return errors.New("certificate db required") }; _, err := r.DB.ExecContext(ctx, Schema); return err }
func (r Repository) Begin(ctx context.Context, acme ACME, account Account, policy Policy, order Order) ([]Challenge, error) {
	if r.DB == nil || acme == nil || order.ID == "" || order.Key == "" || policy.ID != order.Policy { return nil, errors.New("invalid acme order") }
	var raw []byte; err := r.DB.QueryRowContext(ctx, `SELECT order_json FROM certificate_orders WHERE idempotency_key = ?`, order.Key).Scan(&raw); if err == nil { var existing Order; if json.Unmarshal(raw, &existing) != nil { return nil, errors.New("invalid stored order") }; rows, err := r.DB.QueryContext(ctx, `SELECT challenge_json FROM certificate_challenges WHERE order_id = ?`, existing.ID); if err != nil { return nil, err }; defer rows.Close(); var challenges []Challenge; for rows.Next() { var b []byte; var c Challenge; if err := rows.Scan(&b); err != nil || json.Unmarshal(b, &c) != nil { return nil, errors.New("invalid stored challenge") }; challenges = append(challenges, c) }; return challenges, rows.Err() }; if !errors.Is(err, sql.ErrNoRows) { return nil, err }
	if err := acme.EnsureAccount(ctx, account); err != nil { return nil, err }; challenges, err := acme.CreateOrder(ctx, account, policy, order); if err != nil { return nil, err }
	tx, err := r.DB.BeginTx(ctx, nil); if err != nil { return nil, err }; defer tx.Rollback(); b, _ := json.Marshal(order); if _, err = tx.ExecContext(ctx, `INSERT INTO certificate_orders (id, idempotency_key, order_json) VALUES (?, ?, ?)`, order.ID, order.Key, b); err != nil { return nil, err }; for _, challenge := range challenges { b, _ = json.Marshal(challenge); if _, err = tx.ExecContext(ctx, `INSERT INTO certificate_challenges (id, order_id, challenge_json) VALUES (?, ?, ?)`, challenge.ID, order.ID, b); err != nil { return nil, err } }; return challenges, tx.Commit()
}
func (r Repository) StoreGeneration(ctx context.Context, generation Generation) error { b, err := json.Marshal(generation); if err != nil { return err }; _, err = r.DB.ExecContext(ctx, `INSERT INTO certificate_generations (id, generation_json) VALUES (?, ?)`, generation.ID, b); return err }
func (r Repository) Deploy(ctx context.Context, deployment Deployment) error { if r.DB == nil || deployment.ImmutablePath == "" { return errors.New("invalid immutable deployment") }; b, err := json.Marshal(deployment); if err != nil { return err }; _, err = r.DB.ExecContext(ctx, `INSERT INTO certificate_deployments (id, consumer, generation_id, deployment_json) VALUES (?, ?, ?, ?)`, deployment.ID, deployment.Consumer, deployment.Generation, b); return err }
func (r Repository) CurrentDeployment(ctx context.Context, consumer string) (Deployment, error) {
	if r.DB == nil || ctx == nil || consumer == "" { return Deployment{}, ErrInvalidCertificate }
	var raw []byte
	err := r.DB.QueryRowContext(ctx, `SELECT deployment_json FROM certificate_deployments WHERE consumer=? ORDER BY rowid DESC LIMIT 1`, consumer).Scan(&raw)
	if err != nil { return Deployment{}, err }
	var deployment Deployment
	if json.Unmarshal(raw, &deployment) != nil || deployment.Consumer != consumer || deployment.ID == "" || deployment.Generation == "" || deployment.ImmutablePath == "" { return Deployment{}, ErrInvalidCertificate }
	return deployment, nil
}
func (r Repository) ConsumersBoundTo(ctx context.Context, generation CertificateID, limit int) ([]string, bool, error) {
	if r.DB == nil || ctx == nil || generation == "" { return nil, false, ErrInvalidCertificate }
	if limit < 1 || limit > 128 { limit = 32 }
	rows, err := r.DB.QueryContext(ctx, `SELECT current.consumer FROM certificate_deployments AS current WHERE current.generation_id=? AND current.rowid=(SELECT MAX(latest.rowid) FROM certificate_deployments AS latest WHERE latest.consumer=current.consumer) ORDER BY current.consumer LIMIT ?`, generation, limit+1)
	if err != nil { return nil, false, err }
	defer rows.Close()
	consumers := make([]string, 0, limit+1)
	for rows.Next() { var consumer string; if err=rows.Scan(&consumer);err!=nil{return nil,false,err};if consumer==""{return nil,false,ErrInvalidCertificate};consumers=append(consumers,consumer) }
	if err=rows.Err();err!=nil{return nil,false,err}
	more := len(consumers) > limit
	if more { consumers = consumers[:limit] }
	return consumers, more, nil
}
func PresentChallenge(ctx context.Context, challenge Challenge, http HTTP01Presenter, dns DNS01Presenter) error {
	switch challenge.Kind { case HTTP01: if http == nil { return errors.New("http-01 presenter required") }; return http.PresentHTTP01(ctx, challenge); case DNS01: if dns == nil { return errors.New("dns-01 presenter required") }; return dns.PresentDNS01(ctx, challenge); default: return errors.New("unsupported acme challenge") }
}
func RemoveChallenge(ctx context.Context, challenge Challenge, http HTTP01Presenter, dns DNS01Presenter) error {
	switch challenge.Kind { case HTTP01: if http == nil { return errors.New("http-01 presenter required") }; return http.RemoveHTTP01(ctx, challenge); case DNS01: if dns == nil { return errors.New("dns-01 presenter required") }; return dns.RemoveDNS01(ctx, challenge); default: return errors.New("unsupported acme challenge") }
}
func RenewalDue(g Generation, policy Policy, now time.Time) bool { return !g.NotAfter.After(now.Add(policy.RenewBefore)) }
