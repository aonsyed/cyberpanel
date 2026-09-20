package apiserver

import (
	"context"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"net/http"
	"time"
)

type DatabasePrincipalOption struct {
	Label string `json:"label"`
	Value string `json:"value"`
}
type DatabaseConsoleIssuePayload struct {
	PrincipalID string `json:"principal_id"`
}
type DatabaseConsoleProjection struct {
	ID         string    `json:"id"`
	SiteID     string    `json:"site_id"`
	Generation uint64    `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type DatabaseConsoleEdgeService interface {
	IssueDatabaseConsole(context.Context, EdgeCall, DatabaseConsoleIssuePayload) (DatabaseConsoleProjection, error)
}

func validateDatabaseConsoleIssue(value any) error {
	if _, err := database.NewResourceID(value.(*DatabaseConsoleIssuePayload).PrincipalID); err != nil {
		return invalid("database principal")
	}
	return nil
}
func bindManagedDatabaseConsole(registry *Registry, services DomainServices) error {
	edge, ok := services.DatabaseEdge.(DatabaseConsoleEdgeService)
	if !ok {
		return nil
	}
	return registry.Bind("database.console.issue", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		result, err := edge.IssueDatabaseConsole(ctx, edgeCall(inv), *value.(*DatabaseConsoleIssuePayload))
		if err != nil {
			return OperationResult{}, mapDomainError(err)
		}
		return OperationResult{Status: http.StatusCreated, Value: result, Generation: result.Generation}, nil
	})
}
