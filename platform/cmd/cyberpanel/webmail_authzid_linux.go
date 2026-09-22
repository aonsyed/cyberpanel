//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	securewebmail "github.com/aonsyed/cyberpanel/platform/internal/webmail"
)

// AuthzID supplies the native SASL username from the already-authorized,
// consumed grant. It does not consume the Dovecot bridge token; only the real
// introspection request may do that. No caller-supplied address is accepted.
func (handler webmailTokenInfo) AuthzID(ctx context.Context, token string) (string, error) {
	if ctx == nil || handler.database == nil || len(token) < 32 || len(token) > 256 {
		return "", securewebmail.ErrUnauthorized
	}
	digest := sha256.Sum256([]byte(token))
	var tenant, mailbox string
	var epoch uint64
	now := time.Now().UTC()
	err := handler.database.QueryRowContext(ctx, `SELECT d.tenant_id,d.mailbox_id,d.authz_epoch FROM webmail_dovecot_tokens_v1 d JOIN webmail_grants_v1 g ON g.token_digest=d.token_digest AND g.tenant_id=d.tenant_id AND g.mailbox_id=d.mailbox_id AND g.authz_epoch=d.authz_epoch AND g.consumed_at=d.consumed_at WHERE d.token_digest=? AND d.expires_at>? AND d.consumed_at>0 AND g.expires_at>? AND g.revoked_at IS NULL`, hex.EncodeToString(digest[:]), now.UnixNano(), now.UnixNano()).Scan(&tenant, &mailbox, &epoch)
	if err != nil {
		return "", securewebmail.ErrUnauthorized
	}
	account, err := handler.directory.AuthorizeMailbox(ctx, securewebmail.Principal{UserID: "dovecot", SessionID: "authzid"}, tenant, mailbox)
	if err != nil || account.AuthorizationEpoch != epoch {
		return "", securewebmail.ErrUnauthorized
	}
	return account.AddressLabel, nil
}
