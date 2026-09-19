//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/controlplane"
	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

const haFederationConfigPath = "/etc/cyberpanel/ha/federated-dispatch.json"
const haFederationApprovalPath = "/etc/cyberpanel/ha/federated-approvals.json"

// All authority is provisioned out of band. There is deliberately no approval
// generator, enrollment mutation, environment override, or caller-selected URL.
type haFederationConfig struct {
	Endpoint string `json:"endpoint"`
	ServerSPKISHA256 string `json:"server_spki_sha256"`
	CAPath string `json:"ca_path"`
	ClientCertificatePath string `json:"client_certificate_path"`
	ClientKeyPath string `json:"client_key_path"`
	TenantID string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	PeerID federation.ID `json:"peer_id"`
	NodeGrants map[federation.ID]federation.ID `json:"node_grants"`
}

type haFederationApproval struct {
	TenantID string `json:"tenant_id"`
	NodeID federation.ID `json:"node_id"`
	GrantID federation.ID `json:"grant_id"`
	Purpose string `json:"purpose"`
	Approval federation.Approval `json:"approval"`
}

type haFederatedSender struct {
	db *sql.DB
	client *http.Client
	config haFederationConfig
	sessionID string
	now func() time.Time
}

func newHAFederatedSender(ctx context.Context, db *sql.DB, now func() time.Time) (ha.FederatedHAIntentSender, error) {
	raw, err := readHAFederationProtectedFile(haFederationConfigPath, false)
	if errors.Is(err, os.ErrNotExist) { return nil, nil }
	if err != nil { return nil, err }
	if ctx == nil || db == nil { return nil, ha.ErrInvalid }
	var config haFederationConfig
	if err = decodeHAFederationJSON(raw, &config); err != nil { return nil, err }
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" || endpoint.String() != config.Endpoint {
		return nil, ha.ErrInvalid
	}
	pin, err := hex.DecodeString(config.ServerSPKISHA256)
	if err != nil || len(pin) != sha256.Size || config.TenantID != "system" || config.PrincipalID == "" || !config.PeerID.Valid() || len(config.NodeGrants) == 0 || len(config.NodeGrants) > 128 { return nil, ha.ErrForbidden }
	for node, grant := range config.NodeGrants { if !node.Valid() || !grant.Valid() { return nil, ha.ErrInvalid } }
	ca, err := readHAFederationProtectedFile(config.CAPath, false)
	if err != nil { return nil, err }
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) { return nil, ha.ErrInvalid }
	certificate, err := readHAFederationProtectedFile(config.ClientCertificatePath, false)
	if err != nil { return nil, err }
	key, err := readHAFederationProtectedFile(config.ClientKeyPath, true)
	if err != nil { return nil, err }
	defer wipeBytes(key)
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil { return nil, err }
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: endpoint.Hostname(), Certificates: []tls.Certificate{pair}, VerifyConnection: func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 { return ha.ErrForbidden }
		digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(digest[:], pin) != 1 { return ha.ErrForbidden }
		return nil
	}}
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, DialContext: (&net.Dialer{Timeout: 5*time.Second, KeepAlive: -1}).DialContext, TLSHandshakeTimeout: 5*time.Second, ResponseHeaderTimeout: 10*time.Second, ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 32<<10, MaxConnsPerHost: 4, DisableKeepAlives: true, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 15*time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if now == nil { now = time.Now }
	// An insert is committed before any POST. A crash or lost POST response is
	// recovered by authenticated GET lookup, never by another mutation request.
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ha_federated_dispatch_v1 (
	 dispatch_key TEXT PRIMARY KEY, request_digest TEXT NOT NULL,
	 bound_intent BLOB, claimed_at TIMESTAMP NOT NULL
	)`)
	if err != nil { return nil, err }
	return &haFederatedSender{db: db, client: client, config: config, sessionID: "mtls:"+haSenderDigest(pair.Certificate[0]), now: now}, nil
}

func (sender *haFederatedSender) BindAndSend(ctx context.Context, draft federation.Intent) (federation.Intent, federation.Receipt, error) {
	if sender == nil || ctx == nil { return federation.Intent{}, federation.Receipt{}, ha.ErrInvalid }
	grantID, ok := sender.config.NodeGrants[draft.NodeID]
	if !ok || draft.TenantID != sender.config.TenantID { return federation.Intent{}, federation.Receipt{}, ha.ErrForbidden }
	plan, err := ha.FederatedHAApprovalPlanDigest(draft, sender.config.TenantID, grantID)
	if err != nil { return federation.Intent{}, federation.Receipt{}, err }
	key := haSenderDigest([]byte(sender.config.Endpoint+"\x00"+sender.config.TenantID+"\x00"+draft.NodeID.String()+"\x00"+draft.IdempotencyKey))
	// Replay checks precede approval expiry checks: observing an already submitted
	// effect must remain possible after approval expiry, without new authority.
	if bound, found, loadErr := sender.loadClaim(ctx, key, plan); found || loadErr != nil {
		if found && errors.Is(loadErr, ha.ErrReconciliationRequired) { return sender.recoverClaim(ctx, draft, grantID, key, plan) }
		if loadErr != nil { return bound, federation.Receipt{}, loadErr }
		if err = sender.validateBound(draft, bound, grantID, plan, false); err != nil { return bound, federation.Receipt{}, err }
		receipt, observeErr := sender.Observe(ctx, bound)
		return bound, receipt, observeErr
	}
	approval, err := sender.approvalFor(draft, grantID, plan)
	if err != nil { return federation.Intent{}, federation.Receipt{}, err }
	var grant controlplane.MutationGrantRecord
	if err = sender.request(ctx, http.MethodGet, "/v1/grants/"+grantID.String(), nil, &grant); err != nil { return federation.Intent{}, federation.Receipt{}, err }
	if err = sender.validateGrant(draft, grantID, grant); err != nil { return federation.Intent{}, federation.Receipt{}, err }
	payload := struct {
		NodeID federation.ID `json:"node_id"`
		GrantID federation.ID `json:"grant_id"`
		CommandType string `json:"command_type"`
		SchemaHash string `json:"schema_hash"`
		Payload json.RawMessage `json:"payload"`
		TenantID string `json:"tenant_id"`
		ResourceKind string `json:"resource_kind"`
		ResourceID string `json:"resource_id"`
		ExpectedGeneration uint64 `json:"expected_generation"`
		IdempotencyKey string `json:"idempotency_key"`
		Risk federation.Risk `json:"risk"`
		Approval *federation.Approval `json:"approval"`
	}{draft.NodeID, grantID, draft.CommandType, draft.SchemaHash, draft.Payload, draft.TenantID, draft.ResourceKind, draft.ResourceID, draft.ExpectedGeneration, draft.IdempotencyKey, draft.Risk, &approval}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > 1<<20 { return federation.Intent{}, federation.Receipt{}, ha.ErrInvalid }
	result, err := sender.db.ExecContext(ctx, `INSERT OR IGNORE INTO ha_federated_dispatch_v1(dispatch_key,request_digest,claimed_at) VALUES(?,?,?)`, key, plan, sender.now().UTC())
	if err != nil { return federation.Intent{}, federation.Receipt{}, err }
	count, err := result.RowsAffected()
	if err != nil || count != 1 { return federation.Intent{}, federation.Receipt{}, errors.Join(ha.ErrReconciliationRequired, err) }
	var bound federation.Intent
	if err = sender.request(ctx, http.MethodPost, "/v1/intents", raw, &bound); err != nil { return sender.recoverClaim(ctx, draft, grantID, key, plan) }
	if err = sender.validateBound(draft, bound, grantID, plan, true); err != nil { return federation.Intent{}, federation.Receipt{}, errors.Join(ha.ErrReconciliationRequired, err) }
	expectedApproval, _ := json.Marshal(approval)
	var actualApproval []byte
	if len(bound.Approvals) == 1 { actualApproval, _ = json.Marshal(bound.Approvals[0]) }
	if !bytes.Equal(expectedApproval, actualApproval) || bound.AuthorityEpoch != grant.AuthorityEpoch { return federation.Intent{}, federation.Receipt{}, ha.ErrForbidden }
	encoded, err := json.Marshal(bound)
	if err != nil { return bound, federation.Receipt{}, ha.ErrReconciliationRequired }
	// Persist a received ID even when the caller is canceled immediately after
	// the response; this cannot submit any additional network mutation.
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	result, err = sender.db.ExecContext(saveCtx, `UPDATE ha_federated_dispatch_v1 SET bound_intent=? WHERE dispatch_key=? AND request_digest=? AND bound_intent IS NULL`, encoded, key, plan)
	if err != nil { return bound, federation.Receipt{}, errors.Join(ha.ErrReconciliationRequired, err) }
	count, err = result.RowsAffected()
	if err != nil || count != 1 { return bound, federation.Receipt{}, ha.ErrReconciliationRequired }
	receipt, err := sender.Observe(ctx, bound)
	return bound, receipt, err
}

func (sender *haFederatedSender) loadClaim(ctx context.Context, key, plan string) (federation.Intent, bool, error) {
	var digest string
	var raw []byte
	err := sender.db.QueryRowContext(ctx, `SELECT request_digest,bound_intent FROM ha_federated_dispatch_v1 WHERE dispatch_key=?`, key).Scan(&digest, &raw)
	if errors.Is(err, sql.ErrNoRows) { return federation.Intent{}, false, nil }
	if err != nil { return federation.Intent{}, false, err }
	if digest != plan { return federation.Intent{}, true, ha.ErrForbidden }
	if len(raw) == 0 { return federation.Intent{}, true, ha.ErrReconciliationRequired }
	var bound federation.Intent
	if err = decodeHAFederationJSON(raw, &bound); err != nil { return bound, true, err }
	return bound, true, nil
}

func (sender *haFederatedSender) recoverClaim(ctx context.Context, draft federation.Intent, grant federation.ID, key, plan string) (federation.Intent, federation.Receipt, error) {
	query := url.Values{"tenant_id": {sender.config.TenantID}, "node_id": {draft.NodeID.String()}, "grant_id": {grant.String()}, "idempotency_key": {draft.IdempotencyKey}, "request_digest": {plan}}
	var bound federation.Intent
	if err := sender.request(ctx, http.MethodGet, "/v1/intents/lookup?"+query.Encode(), nil, &bound); err != nil { return bound, federation.Receipt{}, errors.Join(ha.ErrReconciliationRequired, err) }
	if err := sender.validateBound(draft, bound, grant, plan, false); err != nil { return federation.Intent{}, federation.Receipt{}, err }
	encoded, err := json.Marshal(bound)
	if err != nil { return federation.Intent{}, federation.Receipt{}, ha.ErrReconciliationRequired }
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	result, err := sender.db.ExecContext(saveCtx, `UPDATE ha_federated_dispatch_v1 SET bound_intent=? WHERE dispatch_key=? AND request_digest=? AND bound_intent IS NULL`, encoded, key, plan)
	if err != nil { return bound, federation.Receipt{}, errors.Join(ha.ErrReconciliationRequired, err) }
	count, err := result.RowsAffected()
	if err != nil { return bound, federation.Receipt{}, ha.ErrReconciliationRequired }
	if count != 1 {
		// Concurrent observation may have saved the same result. Conflicting
		// intent IDs/signatures must not be silently adopted.
		stored, found, loadErr := sender.loadClaim(saveCtx, key, plan)
		if loadErr != nil || !found || !bytes.Equal(stored.SigStructure(), bound.SigStructure()) || !bytes.Equal(stored.Signature, bound.Signature) { return federation.Intent{}, federation.Receipt{}, ha.ErrReconciliationRequired }
	}
	receipt, err := sender.Observe(ctx, bound)
	return bound, receipt, err
}

func (sender *haFederatedSender) approvalFor(draft federation.Intent, grant federation.ID, plan string) (federation.Approval, error) {
	raw, err := readHAFederationProtectedFile(haFederationApprovalPath, false)
	if err != nil { return federation.Approval{}, errors.Join(ha.ErrForbidden, err) }
	var approvals []haFederationApproval
	if decodeHAFederationJSON(raw, &approvals) != nil || len(approvals) > 256 { return federation.Approval{}, ha.ErrForbidden }
	var match *federation.Approval
	for index := range approvals {
		entry := &approvals[index]
		if entry.TenantID != draft.TenantID || entry.NodeID != draft.NodeID || entry.GrantID != grant || entry.Purpose != draft.CommandType || entry.Approval.PlanDigest != plan { continue }
		approval := &entry.Approval
		if match != nil || approval.PolicyVersion != ha.FederatedHAApprovalPolicyVersion || approval.AuthorizationID == "" || approval.SigningKeyID == "" || len(approval.Signature) != ed25519.SignatureSize || !sender.now().Before(approval.ExpiresAt) || !haSenderValidDigest(approval.DisplayDigest) { return federation.Approval{}, ha.ErrForbidden }
		match = approval
	}
	if match == nil { return federation.Approval{}, ha.ErrForbidden }
	// Opaque independently signed approval is forwarded byte-for-byte. The
	// enrolled node's existing AuthorityVerifier owns signature verification.
	return *match, nil
}

func (sender *haFederatedSender) validateGrant(draft federation.Intent, id federation.ID, record controlplane.MutationGrantRecord) error {
	grant := record.Grant
	now := sender.now().UTC()
	if record.ID != id || record.NodeID != draft.NodeID || record.OwnerTenantID.String() != draft.TenantID || record.PeerID != sender.config.PeerID || record.State != "active" || !now.Before(record.ExpiresAt) || grant == nil || grant.Validate(now) != nil || grant.ID != id || grant.NodeID != draft.NodeID || grant.PeerID != sender.config.PeerID || grant.AuthorityEpoch != record.AuthorityEpoch || grant.MaximumRisk != federation.RiskCritical { return ha.ErrForbidden }
	for _, selector := range grant.Selectors {
		if selector.TenantID != draft.TenantID || selector.Kind != draft.ResourceKind || selector.ResourceID != draft.ResourceID || selector.LabelSelector != "" { continue }
		for _, operation := range selector.Operations { if operation == draft.CommandType { return nil } }
	}
	return ha.ErrForbidden
}

func (sender *haFederatedSender) validateBound(draft, bound federation.Intent, grant federation.ID, plan string, fresh bool) error {
	if bound.NodeID != draft.NodeID || bound.GrantID != grant || bound.PeerID != sender.config.PeerID || bound.TenantID != draft.TenantID || bound.ProtocolVersion != draft.ProtocolVersion || bound.CommandType != draft.CommandType || bound.SchemaHash != draft.SchemaHash || bound.PayloadDigest != draft.PayloadDigest || !bytes.Equal(bound.Payload, draft.Payload) || bound.ResourceKind != draft.ResourceKind || bound.ResourceID != draft.ResourceID || bound.ExpectedGeneration != draft.ExpectedGeneration || bound.IdempotencyKey != draft.IdempotencyKey || bound.Risk != draft.Risk || bound.ActorAssertion.Subject != sender.config.PrincipalID || bound.ActorAssertion.Audience != bound.NodeID.String() || bound.ActorAssertion.AuthorizationEpoch == 0 || len(bound.Approvals) != 1 || bound.Approvals[0].PlanDigest != plan || bound.Approvals[0].PolicyVersion != ha.FederatedHAApprovalPolicyVersion { return ha.ErrForbidden }
	if fresh && !haSenderAuthenticationMethod(bound.ActorAssertion.AuthenticationMethods, "phishing_resistant") && !haSenderAuthenticationMethod(bound.ActorAssertion.AuthenticationMethods, "hardware_bound") { return ha.ErrForbidden }
	now := sender.now().UTC()
	if !fresh { now = bound.IssuedAt }
	if bound.Validate(now) != nil { return ha.ErrForbidden }
	return nil
}

func haSenderAuthenticationMethod(methods []string,want string)bool{for _,method:=range methods{if method==want{return true}};return false}

func (sender *haFederatedSender) Observe(ctx context.Context, bound federation.Intent) (federation.Receipt, error) {
	if sender == nil || ctx == nil || !bound.ID.Valid() || bound.TenantID != sender.config.TenantID || bound.PeerID != sender.config.PeerID || sender.config.NodeGrants[bound.NodeID] != bound.GrantID { return federation.Receipt{}, ha.ErrForbidden }
	var record controlplane.IntentRecord
	if err := sender.request(ctx, http.MethodGet, "/v1/intents/"+bound.ID.String(), nil, &record); err != nil { return federation.Receipt{}, err }
	if record.OwnerTenantID.String() != sender.config.TenantID || !bytes.Equal(record.Intent.SigStructure(), bound.SigStructure()) || !bytes.Equal(record.Intent.Signature, bound.Signature) || record.Receipt == nil { return federation.Receipt{}, ha.ErrReconciliationRequired }
	receipt := *record.Receipt
	if receipt.IntentID != bound.ID || receipt.NodeID != bound.NodeID || receipt.EffectID != bound.EffectID || receipt.IdempotencyKey != bound.IdempotencyKey { return federation.Receipt{}, ha.ErrForbidden }
	if err := sender.verifyEvidence(receipt, record.ReceiptEvidence); err != nil { return federation.Receipt{}, err }
	return receipt, nil
}

func (sender *haFederatedSender) VerifyNodeReceipt(ctx context.Context, node federation.ID, keyID string, message, signature []byte) error {
	if sender == nil || ctx == nil || !node.Valid() || len(message) > 4<<20 { return ha.ErrInvalid }
	var envelope struct { Domain string `json:"domain"`; Value federation.Receipt `json:"value"` }
	if decodeHAFederationJSON(message, &envelope) != nil || envelope.Domain != "cyberpanel-federation-receipt-v1" || !envelope.Value.IntentID.Valid() || envelope.Value.NodeID != node || envelope.Value.SignatureKeyID != keyID { return ha.ErrForbidden }
	var record controlplane.IntentRecord
	if err := sender.request(ctx, http.MethodGet, "/v1/intents/"+envelope.Value.IntentID.String(), nil, &record); err != nil { return err }
	if record.OwnerTenantID.String() != sender.config.TenantID || record.Receipt == nil || record.Intent.NodeID != node || record.Intent.PeerID != sender.config.PeerID || sender.config.NodeGrants[node] != record.Intent.GrantID || !bytes.Equal(record.Receipt.SigStructure(), message) || !bytes.Equal(record.Receipt.Signature, signature) { return ha.ErrForbidden }
	return sender.verifyEvidence(*record.Receipt, record.ReceiptEvidence)
}

func (sender *haFederatedSender) verifyEvidence(receipt federation.Receipt, evidence *controlplane.NodeReceiptEvidenceRecord) error {
	now := sender.now().UTC()
	if evidence == nil || evidence.NodeID != receipt.NodeID || evidence.KeyID != receipt.SignatureKeyID || evidence.State != "current" && evidence.State != "historical" || len(evidence.PublicKey) != ed25519.PublicKeySize || evidence.NotBefore.IsZero() || !evidence.ExpiresAt.After(evidence.NotBefore) || receipt.UpdatedAt.Before(evidence.NotBefore) || !receipt.UpdatedAt.Before(evidence.ExpiresAt) || receipt.UpdatedAt.After(now.Add(time.Minute)) || !now.Before(evidence.ExpiresAt) || !ed25519.Verify(ed25519.PublicKey(evidence.PublicKey), receipt.SigStructure(), receipt.Signature) { return ha.ErrForbidden }
	return nil
}

func (sender *haFederatedSender) request(ctx context.Context, method, path string, body []byte, target any) error {
	if method != http.MethodGet && method != http.MethodPost || method == http.MethodPost && path != "/v1/intents" { return ha.ErrForbidden }
	request, err := http.NewRequestWithContext(ctx, method, sender.config.Endpoint+path, bytes.NewReader(body))
	if err != nil { return err }
	request.GetBody = nil // no transparent replay of a mutation body
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPost { request.Header.Set("Content-Type", "application/json") }
	response, err := sender.client.Do(request)
	if err != nil { return errors.Join(ha.ErrReconciliationRequired, err) }
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusForbidden { return ha.ErrForbidden }
	if response.StatusCode != http.StatusOK { return ha.ErrReconciliationRequired }
	raw, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 { return ha.ErrInvalid }
	var envelope struct { Version uint32 `json:"version"`; Data json.RawMessage `json:"data"` }
	if decodeHAFederationJSON(raw, &envelope) != nil || envelope.Version != 1 || len(envelope.Data) == 0 || bytes.Equal(envelope.Data, []byte("null")) { return ha.ErrInvalid }
	return decodeHAFederationJSON(envelope.Data, target)
}

func readHAFederationProtectedFile(path string, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasPrefix(path, "/etc/cyberpanel/") { return nil, ha.ErrForbidden }
	// Check every parent to prevent a writable directory or symlink from
	// redirecting an otherwise protected endpoint, trust root or credential.
	for parent := filepath.Dir(path); parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil { return nil, err }
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || haApprovalFileUID(info) != 0 { return nil, ha.ErrForbidden }
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil { return nil, err }
	defer file.Close()
	info, err := file.Stat()
	if err != nil { return nil, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || secret && info.Mode().Perm()&0007 != 0 || info.Size() <= 0 || info.Size() > 1<<20 { return nil, ha.ErrForbidden }
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 { return nil, ha.ErrInvalid }
	return raw, nil
}

func decodeHAFederationJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF { return ha.ErrInvalid }
	return nil
}

func haSenderDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func haSenderValidDigest(value string) bool { decoded, err := hex.DecodeString(value); return err == nil && len(decoded) == sha256.Size }

var _ ha.FederatedHAIntentSender = (*haFederatedSender)(nil)
