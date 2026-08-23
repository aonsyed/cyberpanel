package certificates

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

type RenewalState string

const (
	RenewalPending  RenewalState = "pending"
	RenewalRunning  RenewalState = "running"
	RenewalDegraded RenewalState = "degraded"
	RenewalComplete RenewalState = "complete"
	RenewalStale    RenewalState = "stale"

	maximumRenewalAttempts = uint32(12)
	maximumRenewalBatch = uint32(32)
	renewalLease = 30 * time.Minute
)

type Renewal struct {
	ID                   string
	TenantID             string
	PolicyID             PolicyID
	PolicyGeneration     uint64
	CurrentCertificateID CertificateID
	ReplacementID        CertificateID
	State                RenewalState
	Attempt              uint32
	NextAttemptAt        time.Time
	Error                string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type RenewalCoordinator struct {
	Store       IssuanceStore
	Deployments Repository
	Issuance    *IssuanceCoordinator
	Deployment  *DeploymentCoordinator
	Now         func() time.Time
}

type renewalCandidate struct {
	issuance Issuance
	policy   CertificatePolicy
	material CertificateMaterial
}

const renewalSchema = `CREATE TABLE IF NOT EXISTS certificate_renewals_v2(
id TEXT PRIMARY KEY,
tenant_id TEXT NOT NULL,
policy_id TEXT NOT NULL,
policy_generation INTEGER NOT NULL,
current_certificate_id TEXT NOT NULL,
replacement_certificate_id TEXT NOT NULL,
state TEXT NOT NULL,
attempt INTEGER NOT NULL,
next_attempt_at TIMESTAMP NOT NULL,
error TEXT NOT NULL,
claim_token TEXT NOT NULL,
created_at TIMESTAMP NOT NULL,
updated_at TIMESTAMP NOT NULL,
UNIQUE(tenant_id,policy_id,policy_generation,current_certificate_id));
CREATE INDEX IF NOT EXISTS certificate_renewals_due_v2 ON certificate_renewals_v2(state,next_attempt_at,updated_at);`

func (c *RenewalCoordinator) Bootstrap(ctx context.Context) error {
	if err := c.validate(ctx); err != nil { return err }
	_, err := c.Store.DB.ExecContext(ctx, renewalSchema)
	return err
}

func (c *RenewalCoordinator) RunQueue(ctx context.Context, interval time.Duration, maximumPerRound uint32) {
	if c.validate(ctx) != nil { return }
	if interval < time.Minute { interval = 15 * time.Minute }
	if maximumPerRound == 0 { maximumPerRound = 4 }
	if maximumPerRound > maximumRenewalBatch { maximumPerRound = maximumRenewalBatch }
	_, _ = c.RunOnce(ctx, maximumPerRound)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-ticker.C: _, _ = c.RunOnce(ctx, maximumPerRound)
		}
	}
}

func (c *RenewalCoordinator) RunOnce(ctx context.Context, maximum uint32) (uint32, error) {
	if err := c.validate(ctx); err != nil { return 0, err }
	if maximum == 0 { maximum = 4 }
	if maximum > maximumRenewalBatch { maximum = maximumRenewalBatch }
	candidates, err := c.due(ctx, maximum)
	if err != nil { return 0, err }
	var failures []error
	for index, candidate := range candidates {
		operationContext, cancel := context.WithTimeout(ctx, 30*time.Minute)
		err = c.renew(operationContext, candidate)
		cancel()
		if err != nil { failures = append(failures, fmt.Errorf("renew certificate %s: %w", candidate.material.ID, err)) }
		if ctx.Err() != nil { return uint32(index + 1), errors.Join(ctx.Err(), errors.Join(failures...)) }
	}
	return uint32(len(candidates)), errors.Join(failures...)
}

func (c *RenewalCoordinator) validate(ctx context.Context) error {
	if c == nil || ctx == nil || c.Store.DB == nil || c.Deployments.DB == nil || c.Issuance == nil || c.Deployment == nil || c.Issuance.Store.DB != c.Store.DB || c.Deployment.Store.DB != c.Deployments.DB { return errors.New("certificate renewal dependencies required") }
	return nil
}

func (c *RenewalCoordinator) due(ctx context.Context, limit uint32) ([]renewalCandidate, error) {
	now := c.now()
	rows, err := c.Store.DB.QueryContext(ctx, `SELECT issuance.issuance_json,policy.policy_json,material.material_json
FROM certificate_issuances_v2 AS issuance
JOIN certificate_policies_v2 AS policy ON policy.id=issuance.policy_id AND policy.tenant_id=issuance.tenant_id
JOIN certificate_material_v2 AS material ON material.issuance_id=issuance.id AND material.tenant_id=issuance.tenant_id
LEFT JOIN certificate_renewals_v2 AS renewal ON renewal.tenant_id=issuance.tenant_id AND renewal.policy_id=issuance.policy_id AND renewal.policy_generation=policy.generation AND renewal.current_certificate_id=material.id
WHERE issuance.phase IN ('issued','active')
AND unixepoch(json_extract(material.material_json,'$.not_after'))<=unixepoch(?)+CAST(json_extract(policy.policy_json,'$.renew_before') AS INTEGER)/1000000000
AND ((renewal.id IS NULL AND EXISTS(SELECT 1 FROM certificate_deployments AS bound WHERE bound.generation_id=material.id AND bound.rowid=(SELECT MAX(latest.rowid) FROM certificate_deployments AS latest WHERE latest.consumer=bound.consumer)))
OR (renewal.state IN ('pending','degraded') AND renewal.next_attempt_at<=?)
OR (renewal.state='running' AND renewal.updated_at<=?)
OR (renewal.state='complete' AND EXISTS(SELECT 1 FROM certificate_deployments AS rebound WHERE rebound.generation_id=material.id AND rebound.rowid=(SELECT MAX(latest_rebound.rowid) FROM certificate_deployments AS latest_rebound WHERE latest_rebound.consumer=rebound.consumer))))
ORDER BY unixepoch(json_extract(material.material_json,'$.not_after')),issuance.tenant_id,issuance.policy_id,issuance.id LIMIT ?`, now, now, now.Add(-renewalLease), limit)
	if err != nil { return nil, err }
	defer rows.Close()
	items := make([]renewalCandidate, 0, limit)
	for rows.Next() {
		var issuanceRaw, policyRaw, materialRaw []byte
		if err=rows.Scan(&issuanceRaw,&policyRaw,&materialRaw);err!=nil{return nil,err}
		var candidate renewalCandidate
		if json.Unmarshal(issuanceRaw,&candidate.issuance)!=nil || json.Unmarshal(policyRaw,&candidate.policy)!=nil || json.Unmarshal(materialRaw,&candidate.material)!=nil { return nil, ErrInvalidCertificate }
		if validatePolicy(candidate.policy)!=nil || candidate.issuance.TenantID!=candidate.policy.TenantID || candidate.issuance.PolicyID!=candidate.policy.ID || candidate.material.ID=="" || candidate.material.ID!=candidate.issuance.Certificate.ID || candidate.material.IssuanceID!=candidate.issuance.ID || candidate.material.NotAfter.IsZero() || candidate.material.NotAfter.After(now.Add(candidate.policy.RenewBefore)) { return nil, ErrInvalidCertificate }
		items = append(items, candidate)
	}
	if err=rows.Err();err!=nil{return nil,err}
	return items, nil
}

func (c *RenewalCoordinator) renew(ctx context.Context, candidate renewalCandidate) error {
	renewal, err := c.admit(ctx, candidate)
	if err != nil { return err }
	bound, _, err := c.Deployments.ConsumersBoundTo(ctx, candidate.material.ID, int(maximumRenewalBatch))
	if err != nil { return err }
	renewal, token, claimed, err := c.claim(ctx, renewal, len(bound) > 0)
	if err != nil || !claimed { return err }
	policy, err := c.Store.Policy(ctx, candidate.policy.TenantID, candidate.policy.ID)
	if err != nil { return c.degrade(ctx, renewal, token, candidate.material.NotAfter, err) }
	if policy.Generation != candidate.policy.Generation { return c.stale(ctx, renewal, token, ErrCertificateConflict) }
	material, err := c.Store.Material(ctx, candidate.policy.TenantID, candidate.material.ID)
	if err != nil { return c.degrade(ctx, renewal, token, candidate.material.NotAfter, err) }
	if material.ID!=candidate.material.ID || material.IssuanceID!=candidate.issuance.ID { return c.stale(ctx, renewal, token, ErrCertificateConflict) }
	issued, err := c.Issuance.Issue(ctx, policy.TenantID, policy.ID, renewalEffectID("issuance", renewal.ID), renewalEffectID("idempotency", renewal.ID))
	if err != nil { return c.degrade(ctx, renewal, token, material.NotAfter, err) }
	if issued.PolicyGeneration!=policy.Generation || issued.PolicyID!=policy.ID || issued.TenantID!=policy.TenantID || issued.Certificate.ID=="" || (issued.Phase!=IssuanceIssued && issued.Phase!=IssuanceActive) { return c.stale(ctx, renewal, token, ErrCertificateConflict) }
	currentPolicy, err := c.Store.Policy(ctx, policy.TenantID, policy.ID)
	if err != nil { return c.degrade(ctx, renewal, token, material.NotAfter, err) }
	if currentPolicy.Generation != policy.Generation { return c.stale(ctx, renewal, token, ErrCertificateConflict) }
	consumers, more, err := c.Deployments.ConsumersBoundTo(ctx, material.ID, int(maximumRenewalBatch))
	if err != nil { return c.degrade(ctx, renewal, token, material.NotAfter, err) }
	var deploymentFailures []error
	for _, consumer := range consumers {
		currentPolicy, err = c.Store.Policy(ctx, policy.TenantID, policy.ID)
		if err != nil || currentPolicy.Generation != policy.Generation {
			if err == nil { err = ErrCertificateConflict }
			return c.stale(ctx, renewal, token, err)
		}
		current, currentErr := c.Deployments.CurrentDeployment(ctx, consumer)
		if currentErr != nil { deploymentFailures=append(deploymentFailures,currentErr);continue }
		if current.Generation != material.ID { continue }
		effectID := renewalEffectID("deploy", renewal.ID, consumer, string(issued.Certificate.ID))
		if _, deployErr := c.Deployment.Deploy(ctx, consumer, issued.Certificate, effectID); deployErr != nil { deploymentFailures=append(deploymentFailures,fmt.Errorf("deploy %s: %w",consumer,deployErr)) }
	}
	remaining, remainsMore, remainingErr := c.Deployments.ConsumersBoundTo(ctx, material.ID, int(maximumRenewalBatch))
	if remainingErr != nil { deploymentFailures=append(deploymentFailures,remainingErr) }
	if more || remainsMore || len(remaining)>0 { deploymentFailures=append(deploymentFailures,errors.New("certificate renewal consumers remain bound to prior generation")) }
	if len(deploymentFailures)>0 { return c.degrade(ctx, renewal, token, material.NotAfter, errors.Join(deploymentFailures...)) }
	issued.Phase=IssuanceActive;issued.Error="";issued.UpdatedAt=c.now()
	if err=c.Store.Save(ctx,issued);err!=nil{return c.degrade(ctx,renewal,token,material.NotAfter,err)}
	return c.complete(ctx, renewal, token, issued.Certificate.ID)
}

func (c *RenewalCoordinator) admit(ctx context.Context, candidate renewalCandidate) (Renewal, error) {
	now := c.now()
	value := Renewal{ID:renewalEffectID("renewal",candidate.policy.TenantID,string(candidate.policy.ID),strconv.FormatUint(candidate.policy.Generation,10),string(candidate.material.ID)),TenantID:candidate.policy.TenantID,PolicyID:candidate.policy.ID,PolicyGeneration:candidate.policy.Generation,CurrentCertificateID:candidate.material.ID,State:RenewalPending,NextAttemptAt:now,CreatedAt:now,UpdatedAt:now}
	_, err := c.Store.DB.ExecContext(ctx, `INSERT INTO certificate_renewals_v2(id,tenant_id,policy_id,policy_generation,current_certificate_id,replacement_certificate_id,state,attempt,next_attempt_at,error,claim_token,created_at,updated_at) VALUES(?,?,?,?,?,'','pending',0,?,'','',?,?) ON CONFLICT(id) DO NOTHING`, value.ID,value.TenantID,value.PolicyID,value.PolicyGeneration,value.CurrentCertificateID,now,now,now)
	if err != nil { return Renewal{}, err }
	stored, _, err := c.load(ctx, value.ID)
	if err != nil { return Renewal{}, err }
	if stored.TenantID!=value.TenantID || stored.PolicyID!=value.PolicyID || stored.PolicyGeneration!=value.PolicyGeneration || stored.CurrentCertificateID!=value.CurrentCertificateID { return Renewal{}, ErrCertificateConflict }
	return stored, nil
}

func (c *RenewalCoordinator) claim(ctx context.Context, renewal Renewal, rebound bool) (Renewal, string, bool, error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil { return Renewal{}, "", false, err }
	token := hex.EncodeToString(tokenBytes)
	now := c.now()
	reboundValue := 0
	if rebound { reboundValue = 1 }
	result, err := c.Store.DB.ExecContext(ctx, `UPDATE certificate_renewals_v2 SET state='running',attempt=CASE WHEN attempt<? THEN attempt+1 ELSE attempt END,error='',claim_token=?,updated_at=? WHERE id=? AND ((state IN ('pending','degraded') AND next_attempt_at<=?) OR (state='running' AND updated_at<=?) OR (state='complete' AND ?=1))`, maximumRenewalAttempts,token,now,renewal.ID,now,now.Add(-renewalLease),reboundValue)
	if err != nil { return Renewal{}, "", false, err }
	affected, err := result.RowsAffected()
	if err != nil { return Renewal{}, "", false, err }
	if affected == 0 { return renewal, "", false, nil }
	claimed, claimToken, err := c.load(ctx, renewal.ID)
	if err != nil { return Renewal{}, "", false, err }
	if claimToken != token || claimed.State != RenewalRunning { return Renewal{}, "", false, ErrCertificateConflict }
	return claimed, token, true, nil
}

func (c *RenewalCoordinator) load(ctx context.Context, id string) (Renewal, string, error) {
	var value Renewal
	var policyID, currentID, replacementID, state, claimToken string
	var attempt uint64
	err := c.Store.DB.QueryRowContext(ctx, `SELECT id,tenant_id,policy_id,policy_generation,current_certificate_id,replacement_certificate_id,state,attempt,next_attempt_at,error,claim_token,created_at,updated_at FROM certificate_renewals_v2 WHERE id=?`, id).Scan(&value.ID,&value.TenantID,&policyID,&value.PolicyGeneration,&currentID,&replacementID,&state,&attempt,&value.NextAttemptAt,&value.Error,&claimToken,&value.CreatedAt,&value.UpdatedAt)
	if err != nil { return Renewal{}, "", err }
	if attempt>uint64(maximumRenewalAttempts) || value.ID=="" || value.TenantID=="" { return Renewal{}, "", ErrInvalidCertificate }
	value.PolicyID=PolicyID(policyID);value.CurrentCertificateID=CertificateID(currentID);value.ReplacementID=CertificateID(replacementID);value.State=RenewalState(state);value.Attempt=uint32(attempt)
	return value, claimToken, nil
}

func (c *RenewalCoordinator) complete(ctx context.Context, renewal Renewal, token string, replacement CertificateID) error {
	now := c.now()
	result, err := c.Store.DB.ExecContext(ctx, `UPDATE certificate_renewals_v2 SET replacement_certificate_id=?,state='complete',next_attempt_at=?,error='',claim_token='',updated_at=? WHERE id=? AND state='running' AND claim_token=?`, replacement,now,now,renewal.ID,token)
	return renewalCASResult(result, err)
}

func (c *RenewalCoordinator) stale(ctx context.Context, renewal Renewal, token string, cause error) error {
	now := c.now()
	result, err := c.Store.DB.ExecContext(ctx, `UPDATE certificate_renewals_v2 SET state='stale',next_attempt_at=?,error=?,claim_token='',updated_at=? WHERE id=? AND state='running' AND claim_token=?`, now,boundedRenewalError(cause),now,renewal.ID,token)
	if stateErr:=renewalCASResult(result,err);stateErr!=nil{return errors.Join(cause,stateErr)}
	return cause
}

func (c *RenewalCoordinator) degrade(ctx context.Context, renewal Renewal, token string, expires time.Time, cause error) error {
	now := c.now()
	next := now.Add(renewalBackoff(renewal.ID, renewal.Attempt, now, expires))
	result, err := c.Store.DB.ExecContext(ctx, `UPDATE certificate_renewals_v2 SET state='degraded',next_attempt_at=?,error=?,claim_token='',updated_at=? WHERE id=? AND state='running' AND claim_token=?`, next,boundedRenewalError(cause),now,renewal.ID,token)
	if stateErr:=renewalCASResult(result,err);stateErr!=nil{return errors.Join(cause,stateErr)}
	return cause
}

func renewalCASResult(result sql.Result, err error) error {
	if err != nil { return err }
	affected, err := result.RowsAffected()
	if err != nil { return err }
	if affected != 1 { return ErrCertificateConflict }
	return nil
}

func (c *RenewalCoordinator) now() time.Time {
	if c.Now != nil { return c.Now().UTC() }
	return time.Now().UTC()
}

func renewalEffectID(kind string, values ...string) string {
	hash := sha256.New()
	hash.Write([]byte("certificate-renewal-v1\x00" + kind))
	for _, value := range values { hash.Write([]byte{0});hash.Write([]byte(value)) }
	return kind + "_" + hex.EncodeToString(hash.Sum(nil))[:48]
}

func renewalBackoff(id string, attempt uint32, now, expires time.Time) time.Duration {
	if attempt < 1 { attempt = 1 }
	shift := attempt - 1
	if shift > 6 { shift = 6 }
	base := 15 * time.Minute * time.Duration(uint64(1)<<shift)
	if base > 12*time.Hour { base = 12*time.Hour }
	sum := sha256.Sum256([]byte(id + "\x00" + strconv.FormatUint(uint64(attempt),10)))
	jitter := time.Duration(binary.BigEndian.Uint64(sum[:8]) % uint64(base/4+1))
	delay := base + jitter
	remaining := expires.Sub(now)
	if remaining > 0 && delay > remaining/4 { delay = remaining/4 }
	if delay < time.Minute { delay = time.Minute }
	return delay
}

func boundedRenewalError(err error) string {
	if err == nil { return "" }
	value := err.Error()
	if len(value) > 2048 { value = value[:2048] }
	return value
}
