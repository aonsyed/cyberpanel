package apiserver

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrInvalidRequest = errors.New("api: invalid request")
	ErrUnauthenticated = errors.New("api: unauthenticated")
	ErrForbidden = errors.New("api: forbidden")
	ErrNotFound = errors.New("api: resource not found")
	ErrConflict = errors.New("api: conflict")
	ErrIdempotencyConflict = errors.New("api: idempotency key reused with different request")
	ErrAssuranceRequired = errors.New("api: additional authentication assurance required")
	ErrRateLimited = errors.New("api: rate limited")
	ErrUnavailable = errors.New("api: temporarily unavailable")
	ErrOperationUnavailable = errors.New("api: operation is not available on this node")
	ErrResponseTooLarge = errors.New("api: response exceeds configured bound")
	ErrUntrustedPeer = errors.New("api: untrusted local peer")
	ErrInvalidSignature = errors.New("api: invalid internal request signature")
	ErrReplay = errors.New("api: replayed internal request")
)

type Problem struct {
	Type string `json:"type"`
	Title string `json:"title"`
	Status int `json:"status"`
	Code string `json:"code"`
	Detail string `json:"detail,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	RetryAfterSeconds uint32 `json:"retry_after_seconds,omitempty"`
}

func (problem Problem) Error() string {
	if problem.Detail != "" { return problem.Code + ": " + problem.Detail }
	return problem.Code
}

func classifyError(err error, requestID string) Problem {
	problem := Problem{Type: "https://cyberpanel.dev/problems/internal", Title: "Internal error", Status: http.StatusInternalServerError, Code: "internal_error", RequestID: requestID}
	switch {
	case errors.Is(err, ErrInvalidRequest):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/invalid-request", "Invalid request", http.StatusBadRequest, "invalid_request"
	case errors.Is(err, ErrUnauthenticated):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/unauthenticated", "Authentication required", http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, ErrForbidden):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/forbidden", "Forbidden", http.StatusForbidden, "forbidden"
	case errors.Is(err, ErrAssuranceRequired):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/assurance-required", "Additional authentication required", http.StatusForbidden, "assurance_required"
	case errors.Is(err, ErrNotFound):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/not-found", "Not found", http.StatusNotFound, "not_found"
	case errors.Is(err, ErrIdempotencyConflict):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/idempotency-conflict", "Idempotency conflict", http.StatusUnprocessableEntity, "idempotency_conflict"
	case errors.Is(err, ErrConflict):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/conflict", "Conflict", http.StatusConflict, "conflict"
	case errors.Is(err, ErrRateLimited):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/rate-limited", "Too many requests", http.StatusTooManyRequests, "rate_limited"
	case errors.Is(err, ErrUnavailable):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/unavailable", "Temporarily unavailable", http.StatusServiceUnavailable, "unavailable"
	case errors.Is(err, ErrOperationUnavailable):
		problem.Type, problem.Title, problem.Status, problem.Code = "https://cyberpanel.dev/problems/operation-unavailable", "Operation unavailable", http.StatusNotImplemented, "operation_unavailable"
	}
	var prerequisite *containerApplicationPrerequisiteError
	if errors.As(err, &prerequisite) { problem.Detail = prerequisite.detail }
	return problem
}

func invalid(field string) error { return fmt.Errorf("%w: %s", ErrInvalidRequest, field) }
