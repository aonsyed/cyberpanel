package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const (
	operatorMaximumBodyBytes     = int64(1 << 20)
	operatorMaximumResponseBytes = 4 << 20
)

type OperatorAPI struct {
	service   *Service
	store     *Store
	authority *OperatorAuthority
	audit     *OperatorAudit
	issuer    *EnrollmentIssuer
}

func NewOperatorAPI(service *Service, store *Store, authority *OperatorAuthority, audit *OperatorAudit) (*OperatorAPI, error) {
	if service == nil || store == nil || authority == nil || audit == nil || service.store != store || authority.store != store || audit.store != store {
		return nil, ErrInvalid
	}
	return &OperatorAPI{service: service, store: store, authority: authority, audit: audit}, nil
}

func (api *OperatorAPI) Handler() http.Handler { return http.HandlerFunc(api.serveHTTP) }

// WithEnrollmentIssuer is configured before the operator listener starts.
func (api *OperatorAPI) WithEnrollmentIssuer(issuer *EnrollmentIssuer) error {
	if api == nil || issuer == nil || issuer.ca == nil || issuer.peer != api.service.peerID {
		return ErrInvalid
	}
	api.issuer = issuer
	return nil
}

func (api *OperatorAPI) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.RawPath != "" || request.URL.Path == "" || strings.Contains(request.URL.Path, "//") {
		writeOperatorError(writer, http.StatusBadRequest, "invalid_path")
		return
	}
	operator, err := api.operator(request)
	if err != nil {
		writeOperatorError(writer, http.StatusForbidden, "client_grant_rejected")
		return
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 2 || segments[0] != "v1" {
		writeOperatorError(writer, http.StatusNotFound, "operation_not_found")
		return
	}
	switch {
	case len(segments) == 2 && segments[1] == "nodes" && request.Method == http.MethodGet:
		api.listNodes(writer, request, operator)
	case len(segments) == 3 && segments[1] == "nodes" && request.Method == http.MethodGet:
		api.inspectNode(writer, request, operator, segments[2])
	case len(segments) == 4 && segments[1] == "nodes" && segments[3] == "revoke" && request.Method == http.MethodPost:
		api.revokeNode(writer, request, operator, segments[2])
	case len(segments) == 4 && segments[1] == "nodes" && segments[3] == "detach" && request.Method == http.MethodPost:
		api.detachNode(writer, request, operator, segments[2])
	case len(segments) == 5 && segments[1] == "nodes" && segments[3] == "certificate" && segments[4] == "rotate" && request.Method == http.MethodPost:
		api.rotateNodeCertificate(writer, request, operator, segments[2])
	case len(segments) == 2 && segments[1] == "intents" && request.Method == http.MethodPost:
		api.createIntent(writer, request, operator)
	case len(segments) == 3 && segments[1] == "intents" && segments[2] == "lookup" && request.Method == http.MethodGet:
		api.lookupHAIntent(writer, request, operator)
	case len(segments) == 3 && segments[1] == "intents" && request.Method == http.MethodGet:
		api.inspectIntent(writer, request, operator, segments[2])
	case len(segments) == 3 && segments[1] == "grants" && request.Method == http.MethodGet:
		api.inspectGrant(writer, request, operator, segments[2])
	case len(segments) == 3 && segments[1] == "sagas" && request.Method == http.MethodGet:
		api.inspectSaga(writer, request, operator, segments[2])
	case len(segments) == 4 && segments[1] == "sagas" && segments[3] == "advance" && request.Method == http.MethodPost:
		api.advanceSaga(writer, request, operator, segments[2])
	default:
		writeOperatorError(writer, http.StatusNotFound, "operation_not_found")
	}
}

func (api *OperatorAPI) operator(request *http.Request) (Operator, error) {
	if api == nil || api.authority == nil || request == nil || request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) == 0 || len(request.TLS.VerifiedChains) == 0 {
		return Operator{}, ErrForbidden
	}
	leaf := request.TLS.PeerCertificates[0]
	if leaf == nil || leaf.IsCA {
		return Operator{}, ErrForbidden
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	return api.authority.OperatorForFingerprint(request.Context(), hex.EncodeToString(fingerprint[:]))
}

func (api *OperatorAPI) listNodes(writer http.ResponseWriter, request *http.Request, operator Operator) {
	if !emptyOperatorBody(request) || !validNodeListQuery(request) || api.authority.authorizePermission(request.Context(), operator, "node.list") != nil {
		api.reject(writer, request, operator, "node.list", "fleet", operator.TenantID, ErrForbidden)
		return
	}
	limit := uint32(20)
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || parsed == 0 || parsed > 100 {
			api.reject(writer, request, operator, "node.list", "fleet", operator.TenantID, ErrInvalid)
			return
		}
		limit = uint32(parsed)
	}
	after := request.URL.Query().Get("after")
	if !api.admit(writer, request, operator, "node.list", "fleet", operator.TenantID) {
		return
	}
	nodes, err := api.store.NodesForTenant(request.Context(), operator.TenantID, after, limit)
	api.complete(writer, request, operator, "node.list", "fleet", operator.TenantID, nodes, err)
}

func (api *OperatorAPI) inspectNode(writer http.ResponseWriter, request *http.Request, operator Operator, rawID string) {
	id, err := federation.NewID(rawID)
	if err != nil || !emptyOperatorBody(request) || api.authority.authorizePermission(request.Context(), operator, "node.inspect") != nil {
		api.reject(writer, request, operator, "node.inspect", "node", rawID, ErrForbidden)
		return
	}
	if !api.admit(writer, request, operator, "node.inspect", "node", rawID) {
		return
	}
	node, err := api.store.Node(request.Context(), id)
	if err == nil && node.OwnerTenantID.String() != operator.TenantID {
		err = ErrForbidden
	}
	var generation uint64
	if err == nil {
		generation, err = api.store.NodeLifecycleGeneration(request.Context(), node.ID)
	}
	api.complete(writer, request, operator, "node.inspect", "node", rawID, struct {
		Node
		Generation uint64 `json:"generation"`
	}{node, generation}, err)
}

func (api *OperatorAPI) rotateNodeCertificate(writer http.ResponseWriter, request *http.Request, operator Operator, rawID string) {
	const permission = "node.certificate.rotate"
	id, idErr := federation.NewID(rawID)
	tenant, tenantErr := federation.NewID(operator.TenantID)
	var payload struct {
		ExpectedGeneration uint64 `json:"expected_generation"`
		ExpectedAuthorityEpoch uint64 `json:"expected_authority_epoch"`
		IdempotencyKey string `json:"idempotency_key"`
		SigningPublicKey []byte `json:"signing_public_key"`
		PreviousCertificateFingerprint string `json:"previous_certificate_fingerprint_sha256"`
	}
	decodeErr := decodeOperatorJSON(request, &payload)
	rotation := NodeCertificateRotationRequest{NodeID: id, TenantID: tenant, ExpectedGeneration: payload.ExpectedGeneration, ExpectedAuthorityEpoch: payload.ExpectedAuthorityEpoch, IdempotencyKey: payload.IdempotencyKey, SigningPublicKey: payload.SigningPublicKey}
	rotation.PreviousCertificateFingerprint = payload.PreviousCertificateFingerprint
	if idErr != nil || tenantErr != nil || decodeErr != nil || rotation.validate() != nil {
		api.reject(writer, request, operator, permission, "node", rawID, ErrInvalid)
		return
	}
	if api.issuer == nil || api.authorizeNodeLifecycle(request.Context(), operator, permission, id) != nil {
		api.reject(writer, request, operator, permission, "node", rawID, ErrForbidden)
		return
	}
	if !api.admit(writer, request, operator, permission, "node", rawID) {
		return
	}
	reservation, err := api.store.ReserveNodeCertificateRotation(request.Context(), rotation)
	var result NodeCertificateRotationResult
	if err == nil && reservation.Result != nil {
		result = *reservation.Result
	} else if err == nil {
		var issued IssuedEnrollmentCertificate
		issued, err = api.issuer.Issue(id, rotation.SigningPublicKey, reservation.RequestDigest, reservation.IssuedAt)
		if err == nil {
			result = NodeCertificateRotationResult{NodeID: id, Generation: reservation.ResultGeneration, AuthorityEpoch: rotation.ExpectedAuthorityEpoch, EvidenceKeyID: "fedcert_"+issued.Fingerprint[:48], CertificateFingerprint: issued.Fingerprint, NodeCertificate: issued.PEM, CertificateExpiresAt: issued.ExpiresAt}
			result.PeerID = api.issuer.peer
			result.IdempotencyKey = rotation.IdempotencyKey
			result.RequestDigest = reservation.RequestDigest
			result.PreviousCertificateFingerprint = rotation.PreviousCertificateFingerprint
			result.SigningPublicKey = append([]byte(nil), rotation.SigningPublicKey...)
			result.Signature = ed25519.Sign(api.issuer.privateKey, result.SigStructure())
			if err = api.authorizeNodeLifecycle(request.Context(), operator, permission, id); err == nil {
				result, err = api.store.CompleteNodeCertificateRotation(request.Context(), rotation, reservation, issued, result)
			}
		}
	}
	api.complete(writer, request, operator, permission, "node", rawID, result, err)
}

func (api *OperatorAPI) detachNode(writer http.ResponseWriter, request *http.Request, operator Operator, rawID string) {
	const permission = "node.detach"
	id, idErr := federation.NewID(rawID)
	tenant, tenantErr := federation.NewID(operator.TenantID)
	var payload struct {
		ExpectedGeneration uint64 `json:"expected_generation"`
		ExpectedAuthorityEpoch uint64 `json:"expected_authority_epoch"`
		IdempotencyKey string `json:"idempotency_key"`
		Reason string `json:"reason"`
	}
	decodeErr := decodeOperatorJSON(request, &payload)
	detach := NodeDetachRequest{NodeID: id, TenantID: tenant, ExpectedGeneration: payload.ExpectedGeneration, ExpectedAuthorityEpoch: payload.ExpectedAuthorityEpoch, IdempotencyKey: payload.IdempotencyKey, Reason: payload.Reason}
	if idErr != nil || tenantErr != nil || decodeErr != nil || detach.validate() != nil {
		api.reject(writer, request, operator, permission, "node", rawID, ErrInvalid)
		return
	}
	if api.authorizeNodeLifecycle(request.Context(), operator, permission, id) != nil {
		api.reject(writer, request, operator, permission, "node", rawID, ErrForbidden)
		return
	}
	if !api.admit(writer, request, operator, permission, "node", rawID) {
		return
	}
	revocation := federation.Revocation{PeerID: api.service.peerID, NodeID: id, NewAuthorityEpoch: detach.ExpectedAuthorityEpoch+1, Reason: detach.Reason, IssuedAt: api.service.clock().UTC()}
	var result NodeDetachResult
	key, err := api.service.signer.RevocationKeyID(request.Context())
	if err == nil {
		revocation.SigningKeyID = key
		revocation.Signature, err = api.service.signer.SignRevocation(request.Context(), key, revocationStructure(revocation))
	}
	if err == nil {
		if err = api.authorizeNodeLifecycle(request.Context(), operator, permission, id); err == nil {
			result, err = api.store.DetachNode(request.Context(), detach, revocation)
		}
	}
	api.complete(writer, request, operator, permission, "node", rawID, result, err)
}

func (api *OperatorAPI) authorizeNodeLifecycle(ctx context.Context, operator Operator, permission string, nodeID federation.ID) error {
	if err := api.authority.authorizePermission(ctx, operator, permission); err != nil {
		return err
	}
	node, err := api.store.Node(ctx, nodeID)
	if err != nil || node.OwnerTenantID.String() != operator.TenantID {
		return ErrForbidden
	}
	return nil
}

func (api *OperatorAPI) createIntent(writer http.ResponseWriter, request *http.Request, operator Operator) {
	var payload struct {
		NodeID             federation.ID        `json:"node_id"`
		GrantID            federation.ID        `json:"grant_id"`
		CommandType        string               `json:"command_type"`
		SchemaHash         string               `json:"schema_hash"`
		Payload            json.RawMessage      `json:"payload"`
		TenantID           string               `json:"tenant_id"`
		ResourceKind       string               `json:"resource_kind"`
		ResourceID         string               `json:"resource_id"`
		ExpectedGeneration uint64               `json:"expected_generation"`
		IdempotencyKey     string               `json:"idempotency_key"`
		Risk               federation.Risk      `json:"risk"`
		Approval           *federation.Approval `json:"approval,omitempty"`
	}
	if err := decodeOperatorJSON(request, &payload); err != nil || payload.TenantID != operator.TenantID {
		api.reject(writer, request, operator, "node.intent.create", "node", payload.NodeID.String(), ErrInvalid)
		return
	}
	if !api.admit(writer, request, operator, "node.intent.create", "node", payload.NodeID.String()) {
		return
	}
	intent, err := api.service.CreateIntent(request.Context(), operator, IntentRequest{NodeID: payload.NodeID, GrantID: payload.GrantID, CommandType: payload.CommandType, SchemaHash: payload.SchemaHash, Payload: payload.Payload, TenantID: payload.TenantID, ResourceKind: payload.ResourceKind, ResourceID: payload.ResourceID, ExpectedGeneration: payload.ExpectedGeneration, IdempotencyKey: payload.IdempotencyKey, Risk: payload.Risk, Approval: payload.Approval})
	api.complete(writer, request, operator, "node.intent.create", "intent", intent.ID.String(), intent, err)
}

func (api *OperatorAPI) inspectIntent(writer http.ResponseWriter, request *http.Request, operator Operator, rawID string) {
	id, err := federation.NewID(rawID)
	if err != nil || !emptyOperatorBody(request) || api.authority.authorizePermission(request.Context(), operator, "intent.inspect") != nil {
		api.reject(writer, request, operator, "intent.inspect", "intent", rawID, ErrForbidden)
		return
	}
	if !api.admit(writer, request, operator, "intent.inspect", "intent", rawID) {
		return
	}
	record, err := api.store.InspectIntent(request.Context(), id)
	if err == nil && record.OwnerTenantID.String() != operator.TenantID {
		err = ErrForbidden
	}
	api.complete(writer, request, operator, "intent.inspect", "intent", rawID, record, err)
}

func (api *OperatorAPI) inspectGrant(writer http.ResponseWriter, request *http.Request, operator Operator, rawID string) {
	id, err := federation.NewID(rawID)
	if err != nil || !emptyOperatorBody(request) || api.authority.authorizePermission(request.Context(), operator, "grant.inspect") != nil {
		api.reject(writer, request, operator, "grant.inspect", "grant", rawID, ErrForbidden)
		return
	}
	if !api.admit(writer, request, operator, "grant.inspect", "grant", rawID) {
		return
	}
	record, err := api.store.InspectMutationGrant(request.Context(), id)
	if err == nil && record.OwnerTenantID.String() != operator.TenantID {
		err = ErrForbidden
	}
	api.complete(writer, request, operator, "grant.inspect", "grant", rawID, record, err)
}

func (api *OperatorAPI) revokeNode(writer http.ResponseWriter, request *http.Request, operator Operator, rawID string) {
	id, idErr := federation.NewID(rawID)
	var payload struct{ Reason string `json:"reason"` }
	decodeErr := decodeOperatorJSON(request, &payload)
	if idErr != nil || decodeErr != nil || payload.Reason == "" || len(payload.Reason) > 512 || strings.ContainsAny(payload.Reason, "\x00\r\n") {
		api.reject(writer, request, operator, "node.revoke", "node", rawID, ErrInvalid)
		return
	}
	if !api.admit(writer, request, operator, "node.revoke", "node", rawID) {
		return
	}
	revocation, err := api.service.RevokeNode(request.Context(), operator, id, payload.Reason)
	api.complete(writer, request, operator, "node.revoke", "node", rawID, revocation, err)
}

func (api *OperatorAPI) inspectSaga(writer http.ResponseWriter, request *http.Request, operator Operator, rawID string) {
	id, err := federation.NewID(rawID)
	if err != nil || !emptyOperatorBody(request) || api.authority.authorizePermission(request.Context(), operator, "saga.inspect") != nil {
		api.reject(writer, request, operator, "saga.inspect", "saga", rawID, ErrForbidden)
		return
	}
	if !api.admit(writer, request, operator, "saga.inspect", "saga", rawID) {
		return
	}
	saga, err := api.store.Saga(request.Context(), id)
	if err == nil && saga.OwnerTenantID.String() != operator.TenantID {
		err = ErrForbidden
	}
	api.complete(writer, request, operator, "saga.inspect", "saga", rawID, saga, err)
}

func (api *OperatorAPI) advanceSaga(writer http.ResponseWriter, request *http.Request, operator Operator, rawID string) {
	id, err := federation.NewID(rawID)
	if err != nil || !emptyOperatorBody(request) {
		api.reject(writer, request, operator, "saga.advance", "saga", rawID, ErrInvalid)
		return
	}
	if !api.admit(writer, request, operator, "saga.advance", "saga", rawID) {
		return
	}
	saga, err := api.service.AdvanceSaga(request.Context(), id, operator)
	api.complete(writer, request, operator, "saga.advance", "saga", rawID, saga, err)
}

func (api *OperatorAPI) admit(writer http.ResponseWriter, request *http.Request, operator Operator, action, targetKind, targetID string) bool {
	if err := api.audit.Append(request.Context(), operator, action, targetKind, targetID, "attempt", "operator request admitted"); err != nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "audit_unavailable")
		return false
	}
	return true
}

func (api *OperatorAPI) reject(writer http.ResponseWriter, request *http.Request, operator Operator, action, targetKind, targetID string, cause error) {
	if err := api.audit.Append(request.Context(), operator, action, targetKind, targetID, "rejected", operatorErrorCode(cause)); err != nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	writeOperatorFailure(writer, cause)
}

func (api *OperatorAPI) complete(writer http.ResponseWriter, request *http.Request, operator Operator, action, targetKind, targetID string, value any, operationErr error) {
	outcome := "success"
	if operationErr != nil {
		outcome = "rejected"
	}
	if err := api.audit.Append(request.Context(), operator, action, targetKind, targetID, outcome, operatorErrorCode(operationErr)); err != nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	if operationErr != nil {
		writeOperatorFailure(writer, operationErr)
		return
	}
	writeOperatorJSON(writer, http.StatusOK, value)
}

func decodeOperatorJSON(request *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || request.ContentLength > operatorMaximumBodyBytes || len(request.TransferEncoding) != 0 {
		return ErrInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, operatorMaximumBodyBytes+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func emptyOperatorBody(request *http.Request) bool {
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		return false
	}
	var one [1]byte
	count, err := request.Body.Read(one[:])
	return count == 0 && errors.Is(err, io.EOF)
}

func validNodeListQuery(request *http.Request) bool {
	for key, values := range request.URL.Query() {
		if key != "limit" && key != "after" || len(values) != 1 {
			return false
		}
	}
	return true
}

func writeOperatorJSON(writer http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(struct {
		Version uint32 `json:"version"`
		Data    any    `json:"data"`
	}{1, value})
	if err != nil || len(encoded) > operatorMaximumResponseBytes {
		writeOperatorError(writer, http.StatusInternalServerError, "response_unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func writeOperatorFailure(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		writeOperatorError(writer, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrForbidden):
		writeOperatorError(writer, http.StatusForbidden, "forbidden")
	case errors.Is(err, ErrNotFound):
		writeOperatorError(writer, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrConflict), errors.Is(err, ErrStale):
		writeOperatorError(writer, http.StatusConflict, "conflict")
	case errors.Is(err, context.DeadlineExceeded):
		writeOperatorError(writer, http.StatusGatewayTimeout, "deadline_exceeded")
	default:
		writeOperatorError(writer, http.StatusInternalServerError, "internal_error")
	}
}

func writeOperatorError(writer http.ResponseWriter, status int, code string) {
	writeOperatorJSON(writer, status, struct{ Code string `json:"code"` }{code})
}

func operatorErrorCode(err error) string {
	if err == nil {
		return "none"
	}
	switch {
	case errors.Is(err, ErrInvalid): return "invalid"
	case errors.Is(err, ErrForbidden): return "forbidden"
	case errors.Is(err, ErrNotFound): return "not_found"
	case errors.Is(err, ErrConflict): return "conflict"
	case errors.Is(err, ErrStale): return "stale"
	default: return "internal"
	}
}

type OperatorServer struct {
	API                *OperatorAPI
	TLSConfig          *tls.Config
	MaximumConnections uint32
	ShutdownTimeout    time.Duration
}

func NewOperatorServer(api *OperatorAPI, tlsConfig *tls.Config, maximumConnections uint32, shutdownTimeout time.Duration) (*OperatorServer, error) {
	if api == nil || tlsConfig == nil || tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil || maximumConnections == 0 || maximumConnections > 4096 || shutdownTimeout < time.Second || shutdownTimeout > 2*time.Minute {
		return nil, ErrInvalid
	}
	return &OperatorServer{API: api, TLSConfig: tlsConfig.Clone(), MaximumConnections: maximumConnections, ShutdownTimeout: shutdownTimeout}, nil
}

func (server *OperatorServer) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || ctx == nil || listener == nil {
		return ErrInvalid
	}
	bounded := &operatorBoundedListener{Listener: listener, semaphore: make(chan struct{}, server.MaximumConnections)}
	httpServer := &http.Server{Handler: server.API.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: server.TLSConfig.Clone()}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- httpServer.Serve(tls.NewListener(bounded, server.TLSConfig.Clone())) }()
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), server.ShutdownTimeout)
		defer cancel()
		shutdownErr := httpServer.Shutdown(shutdownContext)
		if shutdownErr != nil {
			_ = httpServer.Close()
		}
		serveErr := <-serveErrors
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			return errors.Join(shutdownErr, serveErr)
		}
		return shutdownErr
	}
}

type operatorBoundedListener struct {
	net.Listener
	semaphore chan struct{}
}

func (listener *operatorBoundedListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case listener.semaphore <- struct{}{}:
			return &operatorBoundedConnection{Conn: connection, release: func() { <-listener.semaphore }}, nil
		default:
			_ = connection.Close()
		}
	}
}

type operatorBoundedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *operatorBoundedConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}
