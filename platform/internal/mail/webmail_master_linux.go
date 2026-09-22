//go:build linux

package mail

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
)

// Only the verifier crosses into the native daemon's existing immutable,
// root-owned, Dovecot-readable generation. The 384-bit random master password
// remains in the root-only secret tree; no daemon receives its plaintext.
func webmailMasterPassdbArtifact(secret []byte, gid uint32) daemoncfg.Artifact {
	verifier := sha256.Sum256(secret)
	content := []byte(webmailMasterUser + ":{SHA256}" + base64.StdEncoding.EncodeToString(verifier[:]) + "\n")
	digest := sha256.Sum256(content)
	return daemoncfg.Artifact{Path: "dovecot/webmail-master", Mode: 0440, GID: gid, Content: content, SHA256: hex.EncodeToString(digest[:])}
}
