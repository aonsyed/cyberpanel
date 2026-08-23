package apiserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type HostFilesystemIssuePayload struct {
	Reason             string                        `json:"reason"`
	Roots              []access.HostFilesystemRootID `json:"roots"`
	AbsoluteTTLSeconds uint32                        `json:"absolute_ttl_seconds,omitempty"`
	IdleTTLSeconds     uint32                        `json:"idle_ttl_seconds,omitempty"`
	ByteLimit          int64                         `json:"byte_limit,omitempty"`
}

type HostFilesystemListPayload struct {
	SessionID access.HostFilesystemSessionID `json:"session_id"`
	Root      access.HostFilesystemRootID    `json:"root"`
	Directory access.HostFilesystemPath      `json:"directory"`
	Limit     uint16                         `json:"limit,omitempty"`
	Cursor    string                         `json:"cursor,omitempty"`
}

type HostFilesystemStatPayload struct {
	SessionID access.HostFilesystemSessionID `json:"session_id"`
	Root      access.HostFilesystemRootID    `json:"root"`
	Path      access.HostFilesystemPath      `json:"path"`
}

type HostFilesystemReadPayload struct {
	SessionID access.HostFilesystemSessionID `json:"session_id"`
	Root      access.HostFilesystemRootID    `json:"root"`
	Path      access.HostFilesystemPath      `json:"path"`
	Offset    int64                          `json:"offset,omitempty"`
	Length    int64                          `json:"length"`
}

type HostFilesystemEdgeService interface {
	IssueHostFilesystemSession(context.Context, access.HostFilesystemAuthorization, access.HostFilesystemIssueRequest) (access.HostFilesystemSession, error)
	ListHostFilesystem(context.Context, access.HostFilesystemAuthorization, access.HostFilesystemSessionID, access.HostFilesystemRootID, access.HostFilesystemPath, access.HostFilesystemPageRequest) (access.HostFilesystemPage, error)
	StatHostFilesystem(context.Context, access.HostFilesystemAuthorization, access.HostFilesystemSessionID, access.HostFilesystemRootID, access.HostFilesystemPath) (access.HostFilesystemEntry, error)
	ReadHostFilesystem(context.Context, access.HostFilesystemAuthorization, access.HostFilesystemSessionID, access.HostFilesystemRootID, access.HostFilesystemPath, int64, int64) (access.HostFilesystemRead, error)
}

func hostFilesystemScope(request RequestEnvelope, _ any) (identity.Scope, error) {
	if request.TenantID != "" || request.ResourceID != "" || request.ExpectedGeneration != 0 {
		return identity.Scope{}, invalid("host filesystem installation scope")
	}
	return installationScope(request, nil)
}

func validateHostFilesystemReason(reason string) bool {
	reason = strings.TrimSpace(reason)
	if len(reason) < 12 || len(reason) > 512 || !utf8.ValidString(reason) || strings.IndexByte(reason, 0) >= 0 {
		return false
	}
	for _, character := range reason {
		if character < 0x20 && character != '\t' {
			return false
		}
	}
	return true
}

func validateHostFilesystemIssue(value any) error {
	payload := value.(*HostFilesystemIssuePayload)
	if !validateHostFilesystemReason(payload.Reason) || len(payload.Roots) == 0 || len(payload.Roots) > 32 || payload.AbsoluteTTLSeconds > uint32(access.MaximumHostFilesystemAbsoluteTTL/time.Second) || payload.IdleTTLSeconds > uint32(access.MaximumHostFilesystemIdleTTL/time.Second) || payload.ByteLimit < 0 || payload.ByteLimit > access.MaximumHostFilesystemByteLimit {
		return invalid("host filesystem session")
	}
	seen := make(map[access.HostFilesystemRootID]struct{}, len(payload.Roots))
	for _, root := range payload.Roots {
		if root.Validate() != nil {
			return invalid("host filesystem root")
		}
		if _, exists := seen[root]; exists {
			return invalid("duplicate host filesystem root")
		}
		seen[root] = struct{}{}
	}
	if payload.AbsoluteTTLSeconds != 0 && payload.IdleTTLSeconds > payload.AbsoluteTTLSeconds {
		return invalid("host filesystem expiry")
	}
	return nil
}

func validateHostFilesystemList(value any) error {
	payload := value.(*HostFilesystemListPayload)
	if payload.SessionID.Validate() != nil || payload.Root.Validate() != nil || payload.Limit > access.MaximumHostFilesystemPageSize || len(payload.Cursor) > 255 || strings.Contains(payload.Cursor, "/") {
		return invalid("host filesystem list")
	}
	return nil
}

func validateHostFilesystemStat(value any) error {
	payload := value.(*HostFilesystemStatPayload)
	if payload.SessionID.Validate() != nil || payload.Root.Validate() != nil {
		return invalid("host filesystem stat")
	}
	return nil
}

func validateHostFilesystemRead(value any) error {
	payload := value.(*HostFilesystemReadPayload)
	if payload.SessionID.Validate() != nil || payload.Root.Validate() != nil || payload.Path.IsRoot() || payload.Offset < 0 || payload.Length <= 0 || payload.Length > access.MaximumHostFilesystemReadBytes {
		return invalid("host filesystem read")
	}
	return nil
}

func registerHostFilesystemContracts(registry *Registry) error {
	permission := identity.MustPermission("access:host_filesystem")
	definitions := []Operation{
		{Name: "access.host_filesystem.issue", Permission: permission, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true, NewPayload: func() any { return &HostFilesystemIssuePayload{} }, ValidatePayload: validateHostFilesystemIssue, ResolveScope: hostFilesystemScope},
		{Name: "access.host_filesystem.list", Permission: permission, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: false, MaximumResponseBytes: 1 << 20, NewPayload: func() any { return &HostFilesystemListPayload{} }, ValidatePayload: validateHostFilesystemList, ResolveScope: hostFilesystemScope},
		{Name: "access.host_filesystem.stat", Permission: permission, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: false, NewPayload: func() any { return &HostFilesystemStatPayload{} }, ValidatePayload: validateHostFilesystemStat, ResolveScope: hostFilesystemScope},
		{Name: "access.host_filesystem.read", Permission: permission, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: false, MaximumResponseBytes: 2 << 20, NewPayload: func() any { return &HostFilesystemReadPayload{} }, ValidatePayload: validateHostFilesystemRead, ResolveScope: hostFilesystemScope},
	}
	for _, definition := range definitions {
		if err := register(registry, definition); err != nil {
			return err
		}
	}
	return nil
}

func hostFilesystemAuthorization(invocation Invocation) access.HostFilesystemAuthorization {
	now := time.Now().UTC()
	return access.HostFilesystemAuthorization{
		PrincipalID: access.PrincipalID(invocation.Actor.PrincipalID.String()),
		SessionID: invocation.Actor.SessionID.String(), CredentialID: invocation.Actor.CredentialID.String(),
		AuthzEpoch: invocation.Actor.AuthzEpoch, Assurance: uint8(invocation.Actor.Assurance),
		SourceIP: invocation.Meta.ClientIP, MFAVerifiedAt: now,
		LocalConsole: invocation.Meta.ClientIP.IsLoopback(),
	}
}

func mapHostFilesystemError(err error) error {
	if errors.Is(err, access.ErrLimitExceeded) {
		return ErrInvalidRequest
	}
	return mapDomainError(err)
}

func reauthorizeHostFilesystem(ctx context.Context, service *identity.Service, invocation Invocation) error {
	if service == nil {
		return ErrUnavailable
	}
	_, err := service.AuthorizeActor(ctx, invocation.Actor.IdentityContext(), identity.MustPermission("access:host_filesystem"), identity.Scope{Kind: identity.ScopeInstallation}, identity.AssuranceMFA)
	return mapIdentityError(err)
}

func bindHostFilesystemContracts(registry *Registry, services DomainServices) error {
	edge, available := services.AccessEdge.(HostFilesystemEdgeService)
	if !available || edge == nil || services.Identity == nil {
		return nil
	}
	if err := registry.Bind("access.host_filesystem.issue", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		if err := reauthorizeHostFilesystem(ctx, services.Identity, invocation); err != nil {
			return OperationResult{}, err
		}
		payload := value.(*HostFilesystemIssuePayload)
		request := access.HostFilesystemIssueRequest{
			ID: access.HostFilesystemSessionID(effectID(invocation)), Reason: payload.Reason,
			Roots: append([]access.HostFilesystemRootID(nil), payload.Roots...),
			AbsoluteTTL: time.Duration(payload.AbsoluteTTLSeconds) * time.Second,
			IdleTTL: time.Duration(payload.IdleTTLSeconds) * time.Second, ByteLimit: payload.ByteLimit,
		}
		session, err := edge.IssueHostFilesystemSession(ctx, hostFilesystemAuthorization(invocation), request)
		if err != nil {
			return OperationResult{}, mapHostFilesystemError(err)
		}
		return OperationResult{Status: http.StatusCreated, Value: session}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("access.host_filesystem.list", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		if err := reauthorizeHostFilesystem(ctx, services.Identity, invocation); err != nil {
			return OperationResult{}, err
		}
		payload := value.(*HostFilesystemListPayload)
		page, err := edge.ListHostFilesystem(ctx, hostFilesystemAuthorization(invocation), payload.SessionID, payload.Root, payload.Directory, access.HostFilesystemPageRequest{Limit: payload.Limit, Cursor: payload.Cursor})
		if err != nil {
			return OperationResult{}, mapHostFilesystemError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: page}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("access.host_filesystem.stat", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		if err := reauthorizeHostFilesystem(ctx, services.Identity, invocation); err != nil {
			return OperationResult{}, err
		}
		payload := value.(*HostFilesystemStatPayload)
		entry, err := edge.StatHostFilesystem(ctx, hostFilesystemAuthorization(invocation), payload.SessionID, payload.Root, payload.Path)
		if err != nil {
			return OperationResult{}, mapHostFilesystemError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: entry}, nil
	}); err != nil {
		return err
	}
	return registry.Bind("access.host_filesystem.read", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		if err := reauthorizeHostFilesystem(ctx, services.Identity, invocation); err != nil {
			return OperationResult{}, err
		}
		payload := value.(*HostFilesystemReadPayload)
		result, err := edge.ReadHostFilesystem(ctx, hostFilesystemAuthorization(invocation), payload.SessionID, payload.Root, payload.Path, payload.Offset, payload.Length)
		if err != nil {
			return OperationResult{}, mapHostFilesystemError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: result}, nil
	})
}
