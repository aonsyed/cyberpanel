package catalog

import (
	"context"
	"database/sql"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

// SiteScheme uses only the finalized, owned routing input. Missing TLS is a
// valid HTTP configuration; missing/stale authority is never an HTTP fallback.
func (catalog *SQLCatalog) SiteScheme(ctx context.Context, scope service.CommandScope, hostname string, expectedGeneration uint64) (string, error) {
	if catalog == nil || catalog.db == nil || expectedGeneration == 0 {
		return "", ErrChangeClosed
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	input, err := loadTLSSite(ctx, tx, scope)
	if err != nil {
		return "", err
	}
	if !tlsHostnameOwned(input, hostname) || input.Projection.Lifecycle != site.LifecycleActive || input.Projection.Generation != expectedGeneration {
		return "", ErrChangeClosed
	}
	configuration, generation, err := loadConfiguration(ctx, tx)
	if err != nil {
		return "", err
	}
	var digest string
	if err := tx.QueryRowContext(ctx, `SELECT applied_digest FROM webengine_node_config WHERE singleton_id=1`).Scan(&digest); err != nil || generation == 0 || !validDigest(digest) {
		return "", ErrChangeClosed
	}
	scheme, port, mode := "http", uint16(80), webengine.TLSModeClear
	if len(input.TLS) > 0 {
		if len(input.TLS) != 1 || input.TLS[0].OwnerScope != scope || input.TLS[0].Generation == 0 || input.TLS[0].PolicyRef == "" || input.TLS[0].MaterialKey == "" {
			return "", ErrChangeClosed
		}
		scheme, port, mode = "https", 443, webengine.TLSModeTLS
	}
	for _, listener := range configuration.Engine.Listeners {
		if listener.Port == port && listener.TLSMode == mode {
			return scheme, tx.Commit()
		}
	}
	return "", ErrChangeClosed
}
