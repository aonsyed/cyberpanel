//go:build linux

package apiserver

import (
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"os"
)

func privateGatewayCredential(file *os.File) bool {
	return file.Name() == "/run/credentials/panel-gateway.service/gateway-signer" && secrets.PrivateSystemdCredential(file)
}
