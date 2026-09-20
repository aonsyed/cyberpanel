//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/noderelease"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/management"
)

type webEngineEdge struct {
	service *management.Service
	edition webengine.Edition
}

func newWebEngineEdge(service *management.Service, edition webengine.Edition) (*webEngineEdge, error) {
	if service == nil || edition != webengine.EditionOpenLiteSpeed && edition != webengine.EditionLiteSpeedEnterprise {
		return nil, management.ErrInvalid
	}
	return &webEngineEdge{service: service, edition: edition}, nil
}

func (edge *webEngineEdge) WebEngineCapabilities() apiserver.WebEngineEdgeCapabilities {
	if edge == nil || edge.service == nil {
		return apiserver.WebEngineEdgeCapabilities{}
	}
	capabilities := edge.service.Capabilities()
	return apiserver.WebEngineEdgeCapabilities{List: capabilities.Inspect, License: capabilities.RefreshLicense && edge.edition == webengine.EditionLiteSpeedEnterprise, Tuning: capabilities.Tune, Upgrade: capabilities.Upgrade, Remove: capabilities.Remove, PHPProfile: capabilities.InstallPHP}
}

func (edge *webEngineEdge) ListInstallations(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.WebEngineProjection], error) {
	if edge == nil || edge.service == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" || call.ExpectedGeneration != 0 {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{}, management.ErrInvalid
	}
	installation, err := edge.service.Installation(ctx)
	if errors.Is(err, management.ErrNotFound) {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{Items: []apiserver.WebEngineProjection{}}, nil
	}
	if err != nil {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{}, err
	}
	if installation.State == management.StateAbsent { return apiserver.EdgePage[apiserver.WebEngineProjection]{Items: []apiserver.WebEngineProjection{}}, nil }
	tuning, err := edge.service.CurrentTuning(ctx)
	if err != nil {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{}, err
	}
	if tuning.Generation != installation.Generation {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{}, management.ErrConflict
	}
	if page.Cursor != "" && page.Cursor >= installation.ID {
		return apiserver.EdgePage[apiserver.WebEngineProjection]{Items: []apiserver.WebEngineProjection{}, Total: 1}, nil
	}
	return apiserver.EdgePage[apiserver.WebEngineProjection]{Items: []apiserver.WebEngineProjection{webEngineProjection(installation, tuning)}, Total: 1}, nil
}

func (edge *webEngineEdge) ConfigureTuning(ctx context.Context, call apiserver.EdgeCall, payload apiserver.WebEngineTuningPayload) (apiserver.EdgeMutation[apiserver.WebEngineProjection], error) {
	if edge == nil || edge.service == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "node-webengine" ||
		call.ExpectedGeneration == 0 || call.CommandID == "" || call.PrincipalID == "" || call.CredentialID == "" || call.AuthzEpoch == 0 {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrInvalid
	}
	installation, err := edge.service.Installation(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	if installation.ID != call.ResourceID || installation.Edition != edge.edition || installation.Generation != call.ExpectedGeneration {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrConflict
	}
	tuning, err := edge.service.CurrentTuning(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	if tuning.Generation != call.ExpectedGeneration {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrConflict
	}
	if payload.WorkerProcesses != 0 {
		if edge.edition == webengine.EditionLiteSpeedEnterprise && uint32(payload.WorkerProcesses) != tuning.WorkerProcesses {
			return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrLicense
		}
		tuning.WorkerProcesses = uint32(payload.WorkerProcesses)
	}
	if payload.MaxConnections != 0 {
		tuning.MaxConnections = payload.MaxConnections
		tuning.MaxTLSConnections = payload.MaxConnections
	}
	if payload.KeepAliveSeconds != 0 {
		tuning.KeepAliveTimeout = durationSeconds(payload.KeepAliveSeconds)
	}
	tuning.Generation++
	effectID := webEngineEffectID(call.CommandID, "tuning", call.ResourceID)
	_, err = edge.service.Tune(ctx, effectID, tuning, call.ExpectedGeneration, call.ExpectedGeneration+1, webEngineAuthorizationDigest(call))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	installation, err = edge.service.Installation(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	tuning, err = edge.service.CurrentTuning(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	projection := webEngineProjection(installation, tuning)
	return apiserver.EdgeMutation[apiserver.WebEngineProjection]{
		OperationID: effectID, State: string(installation.State), Generation: installation.Generation, Resource: projection,
	}, nil
}

func (edge *webEngineEdge) ConfigureLicense(ctx context.Context, call apiserver.EdgeCall, payload apiserver.WebEngineLicensePayload, secret []byte) (apiserver.EdgeMutation[apiserver.WebEngineProjection], error) {
	defer wipeBytes(secret)
	if edge==nil||edge.service==nil||ctx==nil||call.TenantID!=""||call.ResourceID!="node-webengine"||call.ExpectedGeneration==0||call.CommandID==""||call.PrincipalID==""||call.CredentialID==""||call.AuthzEpoch==0||payload.Edition!=string(webengine.EditionLiteSpeedEnterprise)||edge.edition!=webengine.EditionLiteSpeedEnterprise||len(secret)==0||len(secret)>1<<20{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},management.ErrInvalid}
	current,err:=edge.service.Installation(ctx);if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err};if current.ID!=call.ResourceID||current.Edition!=edge.edition||current.Generation!=call.ExpectedGeneration||current.State!=management.StateActive{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},management.ErrConflict}
	releaseDigest,err:=webEngineExecutableDigest("/usr/local/libexec/cyberpanel/panel-execd");if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err};secretID,err:=secrets.NewID("lse_"+webEngineDigest(call.CommandID,call.IdempotencyKey,call.ResourceID)[:48]);if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},management.ErrInvalid};owner,_:=secrets.NewID("installation");resource,_:=secrets.NewID("node-webengine")
	secretClient,err:=secrets.NewLocalManagementClient();if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err};_,err=secretClient.Put(ctx,secrets.PutRequest{ID:secretID,OwnerTenantID:owner,Purpose:secrets.PurposeAuthentication,Audience:secrets.AudienceBinding{AdapterID:management.LinuxLicenseSecretAdapterID,AdapterVersion:management.LinuxLicenseSecretAdapterVersion,Account:"installation",Origin:"local://panel-execd",ResourceKind:"webengine",ResourceID:resource,ResourceGeneration:call.ExpectedGeneration+1,Operations:[]secrets.Operation{secrets.OperationAuthenticate},ConsumerReleaseDigest:releaseDigest},Plaintext:append([]byte(nil),secret...)});if err!=nil&&!errors.Is(err,secrets.ErrConflict){return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err}
	status,err:=edge.service.ConfigureLicense(ctx,management.LicenseCommand{CommandID:call.CommandID,License:management.LicenseRequest{Mode:management.LicenseModeSerial,SecretRef:secretID.String()},ExpectedGeneration:call.ExpectedGeneration,Fence:call.ExpectedGeneration+1,CommitAuthorizationDigest:webEngineAuthorizationDigest(call)});if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err};installation,err:=edge.service.Installation(ctx);if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err};tuning,err:=edge.service.CurrentTuning(ctx);if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err};if installation.Generation!=call.ExpectedGeneration+1||installation.License.ReceiptDigest!=status.ReceiptDigest||tuning.Generation!=call.ExpectedGeneration{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},management.ErrAmbiguous};projection:=webEngineProjection(installation,tuning);return apiserver.EdgeMutation[apiserver.WebEngineProjection]{OperationID:webEngineEffectID(call.CommandID,"license",call.ResourceID),State:string(status.State),Generation:installation.Generation,Resource:projection},nil
}

func (edge *webEngineEdge) Upgrade(ctx context.Context, call apiserver.EdgeCall, payload apiserver.WebEngineUpgradePayload) (apiserver.EdgeMutation[apiserver.WebEngineProjection], error) {
	if edge==nil||edge.service==nil||ctx==nil||call.TenantID!=""||call.ResourceID!="node-webengine"||call.ExpectedGeneration==0||call.CommandID==""||call.PrincipalID==""||call.CredentialID==""||call.AuthzEpoch==0{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},management.ErrInvalid}
	current,err:=edge.service.Installation(ctx);if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err};if current.ID!=call.ResourceID||current.Edition!=edge.edition||current.Generation!=call.ExpectedGeneration||current.State!=management.StateActive{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},management.ErrConflict}
	channel:=current.Channel;if payload.Channel!=""{channel=management.Channel(payload.Channel)}
	installation,err:=edge.service.Upgrade(ctx,management.UpgradeCommand{CommandID:call.CommandID,Version:payload.Version,Channel:channel,ExpectedGeneration:call.ExpectedGeneration,Fence:call.ExpectedGeneration+1,CommitAuthorizationDigest:webEngineAuthorizationDigest(call)});if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err}
	tuning,err:=edge.service.CurrentTuning(ctx);if err!=nil{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},err};if tuning.Generation!=installation.Generation{return apiserver.EdgeMutation[apiserver.WebEngineProjection]{},management.ErrConflict}
	return apiserver.EdgeMutation[apiserver.WebEngineProjection]{OperationID:webEngineEffectID(call.CommandID,"upgrade",payload.Version),State:string(installation.State),Generation:installation.Generation,Resource:webEngineProjection(installation,tuning)},nil
}

func (edge *webEngineEdge) Remove(ctx context.Context, call apiserver.EdgeCall, payload apiserver.WebEngineRemovePayload) (apiserver.EdgeMutation[apiserver.WebEngineProjection], error) {
	if edge == nil || edge.service == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "node-webengine" ||
		call.ExpectedGeneration == 0 || call.CommandID == "" || call.PrincipalID == "" || call.CredentialID == "" || call.AuthzEpoch == 0 ||
		call.Assurance < identity.AssurancePhishingResistant || payload.Confirmation != apiserver.WebEngineRemoveConfirmation {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrInvalid
	}
	current, err := edge.service.Installation(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	if current.ID != call.ResourceID || current.Edition != edge.edition || current.Generation != call.ExpectedGeneration || current.State != management.StateActive {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrConflict
	}
	installation, err := edge.service.Remove(ctx, management.RemoveCommand{
		CommandID: call.CommandID, ExpectedGeneration: call.ExpectedGeneration, Fence: call.ExpectedGeneration + 1,
		CommitAuthorizationDigest: webEngineAuthorizationDigest(call),
	})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	tuning, err := edge.service.CurrentTuning(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, err
	}
	if tuning.Generation != installation.Generation || installation.State != management.StateAbsent {
		return apiserver.EdgeMutation[apiserver.WebEngineProjection]{}, management.ErrConflict
	}
	return apiserver.EdgeMutation[apiserver.WebEngineProjection]{
		OperationID: call.CommandID, State: string(installation.State), Generation: installation.Generation,
		Resource: webEngineProjection(installation, tuning),
	}, nil
}

func (edge *webEngineEdge) CreatePHPProfile(ctx context.Context, call apiserver.EdgeCall, payload apiserver.WebEnginePHPProfilePayload) (apiserver.EdgeMutation[apiserver.WebEnginePHPProfileProjection], error) {
	if edge==nil||edge.service==nil||ctx==nil||call.TenantID!=""||call.ResourceID!="node-webengine"||call.ExpectedGeneration==0||call.CommandID==""||call.PrincipalID==""||call.CredentialID==""||call.AuthzEpoch==0{return apiserver.EdgeMutation[apiserver.WebEnginePHPProfileProjection]{},management.ErrInvalid};current,err:=edge.service.Installation(ctx);if err!=nil{return apiserver.EdgeMutation[apiserver.WebEnginePHPProfileProjection]{},err};if current.ID!=call.ResourceID||current.Edition!=edge.edition||current.Generation!=call.ExpectedGeneration||current.State!=management.StateActive{return apiserver.EdgeMutation[apiserver.WebEnginePHPProfileProjection]{},management.ErrConflict}
	memory:=payload.MemoryBytes;if memory==0{memory=256<<20};upload:=memory/4;if upload>64<<20{upload=64<<20};profile,err:=edge.service.CreatePHPProfile(ctx,management.PHPProfileCommand{CommandID:call.CommandID,Profile:management.PHPProfile{ID:payload.Name,Version:payload.Version,Extensions:append([]string(nil),payload.Extensions...),MemoryLimitBytes:memory,UploadLimitBytes:upload,BodyLimitBytes:upload,RequestTimeout:300*time.Second,MaxConnections:8,MaxChildren:8},ExpectedGeneration:call.ExpectedGeneration,Fence:call.ExpectedGeneration+1,CommitAuthorizationDigest:webEngineAuthorizationDigest(call)});if err!=nil{return apiserver.EdgeMutation[apiserver.WebEnginePHPProfileProjection]{},err};projection:=apiserver.WebEnginePHPProfileProjection{ID:profile.ID,Name:profile.ID,Version:profile.Version,Extensions:append([]string(nil),profile.Extensions...),MemoryBytes:profile.MemoryLimitBytes,State:"active",Generation:profile.Generation};return apiserver.EdgeMutation[apiserver.WebEnginePHPProfileProjection]{OperationID:webEngineEffectID(call.CommandID,"php",profile.ID),State:"active",Generation:profile.Generation,Resource:projection},nil
}

func webEngineExecutableDigest(path string) (string, error) {
	if path == "/usr/local/libexec/cyberpanel/panel-execd" {
		resolved, err := noderelease.ResolveExecutorPath(path)
		if err != nil { return "", err }
		path = resolved
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return "", management.ErrInvalid
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 { return "", management.ErrInvalid }
	file, err := os.Open(path)
	if err != nil { return "", err }
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) { return "", management.ErrInvalid }
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, (1<<30)+1))
	if err != nil { return "", err }
	if n == 0 || n > 1<<30 { return "", management.ErrInvalid }
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func webEngineProjection(installation management.Installation, tuning management.GlobalTuning) apiserver.WebEngineProjection {
	licenseState := string(installation.License.State)
	if installation.Edition == webengine.EditionOpenLiteSpeed {
		licenseState = "not_applicable"
	} else if licenseState == "" {
		licenseState = "unknown"
	}
	version := installation.Version
	if version == "" {
		version = "unknown"
	}
	health := "unknown"
	if installation.State == management.StateDegraded {
		health = "degraded"
	} else if installation.State == management.StateActive && webEngineValidDigest(installation.ActiveConfigDigest) {
		health = "healthy"
	}
	return apiserver.WebEngineProjection{
		ID: installation.ID, Edition: string(installation.Edition), Version: version, Channel: string(installation.Channel),
		License: licenseState, LicenseState: licenseState, Workers: tuning.WorkerProcesses, Connections: tuning.MaxConnections,
		Health: health, Generation: installation.Generation, UpdatedAt: installation.UpdatedAt,
	}
}

func webEngineValidDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func webEngineEffectID(values ...string) string {
	return "web-" + webEngineDigest(values...)[:48]
}

func webEngineDigest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func webEngineAuthorizationDigest(call apiserver.EdgeCall) string {
	return webEngineDigest(call.PrincipalID, call.SessionID, call.CredentialID, call.CommandID,
		strconv.FormatUint(uint64(call.Assurance), 10), strconv.FormatUint(call.AuthzEpoch, 10),
		call.ResourceID, strconv.FormatUint(call.ExpectedGeneration, 10), call.IdempotencyKey)
}

func durationSeconds(value uint32) time.Duration {
	return time.Duration(value) * time.Second
}

var _ apiserver.WebEngineEdgeService = (*webEngineEdge)(nil)
var _ apiserver.WebEngineEdgeCapabilityProvider = (*webEngineEdge)(nil)
