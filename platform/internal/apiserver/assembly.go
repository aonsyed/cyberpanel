package apiserver

import (
	"path/filepath"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type CoreAssemblyConfig struct{StateRoot string;TrustPath string}

func AssembleCore(config CoreAssemblyConfig,identityService *identity.Service,domains DomainServices)(*Core,error){if identityService==nil{return nil,invalid("identity service")};if err:=secureStateDirectory(config.StateRoot,0700);err!=nil{return nil,err};registry,err:=NewDomainRegistry();if err!=nil{return nil,err};domains.Identity=identityService;if err=domains.Bind(registry);err!=nil{return nil,err};trust,err:=NewFileTrustStore(config.TrustPath);if err!=nil{return nil,err};nonces,err:=NewDirectoryNonceStore(filepath.Join(config.StateRoot,"nonces"));if err!=nil{return nil,err};idempotency,err:=NewDirectoryIdempotencyLedger(filepath.Join(config.StateRoot,"idempotency"));if err!=nil{return nil,err};core,err:=NewCore(registry,IdentityAuthenticator{Service:identityService},trust,nonces,idempotency);if err!=nil{return nil,err};core.Preview=domains.HostingPreviews;return core,nil}
