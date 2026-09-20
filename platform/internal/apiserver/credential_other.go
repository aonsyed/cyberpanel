//go:build !linux

package apiserver

import "os"

func privateGatewayCredential(*os.File) bool { return false }
