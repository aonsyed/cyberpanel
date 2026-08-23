package apiserver

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/preview"
)

type NonceStore interface { Mark(string, time.Time) error }

type Core struct {
	Registry *Registry
	Authenticator Authenticator
	Verifier RequestVerifier
	Nonces NonceStore
	Idempotency IdempotencyLedger
	Clock func() time.Time
	MaximumConcurrent uint32
	Preview *preview.Service
	semaphore chan struct{}
}

func NewCore(registry *Registry, authenticator Authenticator, verifier RequestVerifier, nonces NonceStore, idempotency IdempotencyLedger) (*Core, error) {
	if registry == nil || authenticator == nil || verifier == nil || nonces == nil || idempotency == nil { return nil, invalid("core dependencies") }
	return &Core{Registry: registry, Authenticator: authenticator, Verifier: verifier, Nonces: nonces, Idempotency: idempotency, Clock: time.Now, MaximumConcurrent: 256}, nil
}

func (core *Core) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/invoke", core.invoke)
	mux.HandleFunc("GET /internal/v1/health", core.health)
	mux.HandleFunc("GET /internal/v1/catalog", core.catalog)
	mux.HandleFunc("POST /internal/v1/preview/consume", core.consumePreview)
	maximum := core.MaximumConcurrent; if maximum == 0 { maximum = 256 }; if maximum > 4096 { maximum = 4096 }
	core.semaphore = make(chan struct{}, maximum)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		select {
		case core.semaphore <- struct{}{}:
			defer func(){ <-core.semaphore }(); mux.ServeHTTP(writer, request)
		default:
			writeProblem(writer, classifyError(ErrUnavailable, request.Header.Get("X-Request-ID")), DefaultMaximumResponseBytes)
		}
	})
}

type previewConsumeRequest struct { Hostname string `json:"hostname"` }

func (core *Core) consumePreview(writer http.ResponseWriter, request *http.Request) {
	if core.Preview == nil { writeProblem(writer,classifyError(ErrOperationUnavailable,""),1<<20);return }
	var payload previewConsumeRequest
	if err := readJSON(request, 4096, &payload); err != nil { writeProblem(writer,classifyError(err,""),1<<20);return }
	if len(payload.Hostname) < 3 || len(payload.Hostname) > 253 || strings.TrimSpace(payload.Hostname) != payload.Hostname { writeProblem(writer,classifyError(ErrInvalidRequest,""),1<<20);return }
	resolution, err := core.Preview.Resolve(request.Context(), payload.Hostname)
	if err != nil { writeProblem(writer,classifyError(mapDomainError(err),""),1<<20);return }
	_ = writeJSON(writer,http.StatusOK,resolution,1<<20)
}

func (core *Core) health(writer http.ResponseWriter, request *http.Request) {
	_ = writeJSON(writer, http.StatusOK, map[string]any{"status":"ready", "protocol_version":InternalProtocolVersion, "operations":len(core.Registry.DescribeBound()), "time":core.now()}, 1<<20)
}

func (core *Core)catalog(writer http.ResponseWriter,request *http.Request){_ = writeJSON(writer,http.StatusOK,CoreCatalog{ProtocolVersion:InternalProtocolVersion,APIVersion:APIVersion,Operations:core.Registry.DescribeBound()},DefaultMaximumResponseBytes)}

func (core *Core) invoke(writer http.ResponseWriter, httpRequest *http.Request) {
	var request CoreRequest
	if err := readJSON(httpRequest, AbsoluteMaximumBodyBytes+65536, &request); err != nil { core.writeInternalProblem(writer, classifyError(err, "")); return }
	now := core.now()
	if err := request.Validate(now); err != nil { core.writeInternalProblem(writer, classifyError(err, request.Request.RequestID)); return }
	if err := core.Verifier.Verify(request); err != nil { core.writeInternalProblem(writer, classifyError(ErrUnauthenticated, request.Request.RequestID)); return }
	if err := core.Nonces.Mark(request.Nonce, request.SentAt); err != nil { core.writeInternalProblem(writer, classifyError(ErrUnauthenticated, request.Request.RequestID)); return }
	registered,exists:=core.Registry.Lookup(request.Request.Operation);if !exists||registered.Handler==nil{core.writeInternalProblem(writer,classifyError(ErrOperationUnavailable,request.Request.RequestID));return}
	operation, payload, canonical, err := core.Registry.Canonicalize(request.Request)
	if err != nil { core.writeInternalProblem(writer, classifyError(err, request.Request.RequestID)); return }
	request.Request = canonical
	if operation.Mutating {
		if !idempotencyPattern.MatchString(request.IdempotencyKey) { core.writeInternalProblem(writer, classifyError(invalid("idempotency_key"), request.Request.RequestID)); return }
	} else if request.IdempotencyKey != "" { core.writeInternalProblem(writer, classifyError(invalid("idempotency_key on read operation"), request.Request.RequestID)); return }
	var actor Actor
	if operation.Auth == AuthRequired {
		if request.Auth == nil { core.writeInternalProblem(writer, classifyError(ErrUnauthenticated, request.Request.RequestID)); return }
		actor, err = core.Authenticator.Authenticate(httpRequest.Context(), *request.Auth, request.Meta)
		if err != nil { core.writeInternalProblem(writer, classifyError(err, request.Request.RequestID)); return }
		scope, scopeErr := operation.ResolveScope(request.Request, payload); if scopeErr != nil { core.writeInternalProblem(writer, classifyError(scopeErr, request.Request.RequestID)); return }
		if !operation.SelfService { if err = core.Authenticator.Authorize(httpRequest.Context(), actor, operation.Permission, scope, operation.Assurance); err != nil { core.writeInternalProblem(writer, classifyError(err, request.Request.RequestID)); return } }
	} else if request.Auth != nil { core.writeInternalProblem(writer, classifyError(invalid("credentials on anonymous operation"), request.Request.RequestID)); return }
	invocation := Invocation{Actor: actor, Request: request.Request, IdempotencyKey: request.IdempotencyKey, Meta: request.Meta}
	var ledgerKey, requestDigest string
	if operation.Mutating {
		ledgerKey = actor.PrincipalID.String()+"\x00"+operation.Name+"\x00"+request.IdempotencyKey
		requestDigest, err = digestRequest(actor.PrincipalID, operation.Name, request.IdempotencyKey, request.Request)
		if err != nil { core.writeInternalProblem(writer, classifyError(ErrInvalidRequest, request.Request.RequestID)); return }
		receipt, cached, acquireErr := core.Idempotency.Acquire(httpRequest.Context(), ledgerKey, requestDigest)
		if acquireErr != nil { core.writeInternalProblem(writer, classifyError(acquireErr, request.Request.RequestID)); return }
		if cached { core.writeInternal(writer, receipt.Response); return }
	}
	result, err := operation.Handler(httpRequest.Context(), invocation, payload)
	if err != nil {
		if operation.Mutating { _ = core.Idempotency.Retryable(context.WithoutCancel(httpRequest.Context()), ledgerKey, requestDigest) }
		core.writeInternalProblem(writer, classifyError(err, request.Request.RequestID)); return
	}
	raw, err := rawResult(result.Value); if err != nil || int64(len(raw)) > effectiveResponseLimit(operation) {
		if operation.Mutating { _ = core.Idempotency.Retryable(context.WithoutCancel(httpRequest.Context()), ledgerKey, requestDigest) }
		core.writeInternalProblem(writer, classifyError(ErrResponseTooLarge, request.Request.RequestID)); return
	}
	envelope := ResponseEnvelope{APIVersion: APIVersion, RequestID: request.Request.RequestID, Operation: operation.Name, Result: raw, Generation: result.Generation, CompletedAt: now}
	status := statusOrDefault(result.Status, operation.Mutating)
	response := CoreResponse{ProtocolVersion:InternalProtocolVersion, Status:status, Envelope:&envelope, Headers:safeResponseHeaders(result.Headers), Session:result.Session, ClearSession:result.ClearSession}
	if result.Session!=nil&&result.ClearSession { core.writeInternalProblem(writer, classifyError(ErrInvalidRequest, request.Request.RequestID)); return }
	if result.Session != nil && result.Session.Validate() != nil { core.writeInternalProblem(writer, classifyError(ErrInvalidRequest, request.Request.RequestID)); return }
	if operation.Mutating {
		if err = core.Idempotency.Complete(context.WithoutCancel(httpRequest.Context()), ledgerKey, requestDigest, response); err != nil { core.writeInternalProblem(writer, classifyError(ErrUnavailable, request.Request.RequestID)); return }
	}
	core.writeInternal(writer, response)
}

func (core *Core) writeInternalProblem(writer http.ResponseWriter, problem Problem) { core.writeInternal(writer, CoreResponse{ProtocolVersion:InternalProtocolVersion, Status:problem.Status, Problem:&problem}) }
func (core *Core) writeInternal(writer http.ResponseWriter, response CoreResponse) { _ = writeJSON(writer, http.StatusOK, response, DefaultMaximumResponseBytes+65536) }
func (core *Core) now() time.Time { if core.Clock == nil { return time.Now().UTC() }; return core.Clock().UTC() }

func safeResponseHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 { return nil }
	safe := make(map[string]string)
	for key, value := range headers {
		switch http.CanonicalHeaderKey(key) {
		case "Location", "Etag", "Retry-After":
			if value != "" && len(value) <= 2048 && !strings.ContainsAny(value, "\r\n") { safe[http.CanonicalHeaderKey(key)] = value }
		}
	}
	return safe
}

type PeerAuthorizer interface { Authorize(net.Conn) error }
type authorizedListener struct { net.Listener; authorizer PeerAuthorizer }
func (listener authorizedListener) Accept() (net.Conn, error) { for { connection, err := listener.Listener.Accept(); if err != nil { return nil, err }; if err = listener.authorizer.Authorize(connection); err == nil { return connection, nil }; _ = connection.Close() } }

func ServeCore(server *http.Server, listener net.Listener, peer PeerAuthorizer) error {
	if server == nil || listener == nil || peer == nil { return invalid("core server") }
	return server.Serve(authorizedListener{Listener:listener, authorizer:peer})
}

func parseRetryAfter(value string) uint32 { parsed, _ := strconv.ParseUint(value,10,32); return uint32(parsed) }
