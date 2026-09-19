package apps

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

func applicationSecretID(prefix, value string) secrets.ID {
	sum := sha256.Sum256([]byte(prefix + "\x00" + value))
	identifier, _ := secrets.NewID(prefix + "_" + hex.EncodeToString(sum[:])[:48])
	return identifier
}
func ApplicationTenantOwnerID(tenantID string) secrets.ID {
	if identifier, err := secrets.NewID(tenantID); err == nil {
		return identifier
	}
	return applicationSecretID("apptenant", tenantID)
}
func ApplicationAudienceID(resource string) secrets.ID {
	if identifier, err := secrets.NewID(resource); err == nil {
		return identifier
	}
	return applicationSecretID("appresource", resource)
}
func ApplicationManagedSecretID(purpose string, installation InstallationID) secrets.ID {
	return applicationSecretID("appsecret", purpose+"\x00"+string(installation))
}
