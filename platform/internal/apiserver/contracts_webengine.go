package apiserver

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	management "github.com/aonsyed/cyberpanel/platform/internal/webengine/management"
)

type WebEngineInstallPayload struct{OS string `json:"os"`;OSVersion string `json:"os_version"`;Architecture string `json:"architecture"`;Version string `json:"version"`;Edition webengine.Edition `json:"edition"`;Channel management.Channel `json:"channel"`;License management.LicenseRequest `json:"license"`;CommitAuthorizationDigest string `json:"commit_authorization_digest"`}
type WebEngineConvertPayload struct{OS string `json:"os"`;OSVersion string `json:"os_version"`;Architecture string `json:"architecture"`;Version string `json:"version"`;Target webengine.Edition `json:"target"`;Channel management.Channel `json:"channel"`;License management.LicenseRequest `json:"license"`;SnapshotGeneration uint64 `json:"snapshot_generation"`;CommitAuthorizationDigest string `json:"commit_authorization_digest"`;RollbackWindow time.Duration `json:"rollback_window"`}
type WebEngineLicenseRefreshPayload struct{}
type WebEnginePHPInstallPayload struct{Profile management.PHPProfile `json:"profile"`;Plan management.PHPArtifactPlan `json:"plan"`;CommitAuthorizationDigest string `json:"commit_authorization_digest"`}
type WebEngineTunePayload struct{Tuning management.GlobalTuning `json:"tuning"`;CommitAuthorizationDigest string `json:"commit_authorization_digest"`}

func registerWebEngineContracts(registry *Registry)error{
	operations:=[]Operation{
		{Name:"webengine.install",Permission:identity.MustPermission("webengine:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebEngineInstallPayload{}},ValidatePayload:func(value any)error{return validateWebTarget(value.(*WebEngineInstallPayload).OS,value.(*WebEngineInstallPayload).OSVersion,value.(*WebEngineInstallPayload).Architecture,value.(*WebEngineInstallPayload).Version)},ResolveScope:installationScope},
		{Name:"webengine.convert",Permission:identity.MustPermission("webengine:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebEngineConvertPayload{}},ValidatePayload:func(value any)error{return validateWebTarget(value.(*WebEngineConvertPayload).OS,value.(*WebEngineConvertPayload).OSVersion,value.(*WebEngineConvertPayload).Architecture,value.(*WebEngineConvertPayload).Version)},ResolveScope:installationScope},
		{Name:"webengine.license.refresh",Permission:identity.MustPermission("webengine:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebEngineLicenseRefreshPayload{}},ResolveScope:installationScope},
		{Name:"webengine.php.install",Permission:identity.MustPermission("webengine:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebEnginePHPInstallPayload{}},ResolveScope:installationScope},
		{Name:"webengine.tuning.apply",Permission:identity.MustPermission("webengine:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WebEngineTunePayload{}},ValidatePayload:validateWebEngineTune,ResolveScope:installationScope},
	}
	for _,operation:=range operations{if err:=register(registry,operation);err!=nil{return err}}
	return nil
}

func validateWebTarget(osName,osVersion,architecture,version string)error{if osName!="ubuntu"&&osName!="almalinux"{return invalid("web engine OS")};if architecture!="amd64"&&architecture!="arm64"{return invalid("web engine architecture")};for _,value:=range []string{osVersion,version}{if value==""||len(value)>128||strings.ContainsAny(value,"\x00\r\n\t /\\;|&$`'"){return invalid("web engine version")}};return nil}

func validateWebEngineTune(value any)error{payload:=value.(*WebEngineTunePayload);candidate:=payload.Tuning;candidate.Generation=1;if _,err:=management.DesiredTuning(candidate);err!=nil||len(payload.CommitAuthorizationDigest)!=64||strings.Trim(payload.CommitAuthorizationDigest,"0123456789abcdef")!=""{return invalid("web engine tuning")};return nil}

func bindWebEngine(registry *Registry,services DomainServices)error{
	if services.WebEngine==nil{return nil}
	capabilities:=services.WebEngine.Capabilities()
	if capabilities.Install{if err:=registry.Bind("webengine.install",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){p:=value.(*WebEngineInstallPayload);installation,err:=services.WebEngine.Install(ctx,management.InstallCommand{CommandID:commandID(inv),OS:p.OS,OSVersion:p.OSVersion,Architecture:p.Architecture,Version:p.Version,Edition:p.Edition,Channel:p.Channel,License:p.License,ExpectedGeneration:inv.Request.ExpectedGeneration,Fence:inv.Request.ExpectedGeneration+1,CommitAuthorizationDigest:p.CommitAuthorizationDigest});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:installation,Generation:installation.Generation},nil});err!=nil{return err}}
	if capabilities.Convert{if err:=registry.Bind("webengine.convert",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){p:=value.(*WebEngineConvertPayload);installation,err:=services.WebEngine.Convert(ctx,management.ConvertCommand{CommandID:commandID(inv),OS:p.OS,OSVersion:p.OSVersion,Architecture:p.Architecture,Version:p.Version,Target:p.Target,Channel:p.Channel,License:p.License,ExpectedGeneration:inv.Request.ExpectedGeneration,SnapshotGeneration:p.SnapshotGeneration,Fence:inv.Request.ExpectedGeneration+1,CommitAuthorizationDigest:p.CommitAuthorizationDigest,RollbackWindow:p.RollbackWindow});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:installation,Generation:installation.Generation},nil});err!=nil{return err}}
	if capabilities.RefreshLicense{if err:=registry.Bind("webengine.license.refresh",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){license,err:=services.WebEngine.RefreshLicense(ctx,effectID(inv),inv.Request.ExpectedGeneration,inv.Request.ExpectedGeneration+1);if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:license,Generation:inv.Request.ExpectedGeneration+1},nil});err!=nil{return err}}
	if capabilities.InstallPHP{if err:=registry.Bind("webengine.php.install",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){p:=value.(*WebEnginePHPInstallPayload);p.Profile.Generation=inv.Request.ExpectedGeneration+1;profile,err:=services.WebEngine.InstallPHP(ctx,effectID(inv),p.Profile,p.Plan,inv.Request.ExpectedGeneration,inv.Request.ExpectedGeneration+1,p.CommitAuthorizationDigest);if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:profile,Generation:profile.Generation},nil});err!=nil{return err}}
	if capabilities.Tune{return registry.Bind("webengine.tuning.apply",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){p:=value.(*WebEngineTunePayload);p.Tuning.Generation=inv.Request.ExpectedGeneration+1;tuning,err:=services.WebEngine.Tune(ctx,effectID(inv),p.Tuning,inv.Request.ExpectedGeneration,inv.Request.ExpectedGeneration+1,p.CommitAuthorizationDigest);if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:tuning,Generation:tuning.Generation},nil})}
	return nil
}
