//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanelbackup"
)

// This is selection data for the existing authenticated migration.create flow,
// not an authority token. No API call is made by the converter executable.
type createHandoff struct {
	Operation string `json:"operation"`
	TenantID string `json:"tenant_id"`
	SuggestedIdempotencyKey string `json:"suggested_idempotency_key"`
	Payload struct {
		Source string `json:"source"`
		SourceEndpoint string `json:"source_endpoint"`
	} `json:"payload"`
}

func writeConversionResult(request cyberpanelbackup.ConvertRequest,response cyberpanelbackup.ConvertResponse)error {
	// Both paths are emitted by the fixed-root converter. A resume may select
	// already-admitted evidence; it must not select some other filesystem path.
	intake:="file://"+cyberpanelbackup.DefaultIntakePath+"/"+response.MigrationID.String()
	quarantine:="file://"+cyberpanelbackup.DefaultQuarantinePath+"/"+response.ManifestRoot+"/bundle"
	if !response.Succeeded||(response.BundleEndpoint!=intake&&response.BundleEndpoint!=quarantine){return errors.New("invalid converter handoff")}
	handoff:=createHandoff{Operation:"migration.create",TenantID:request.TenantID}
	handoff.Payload.Source="cyberpanel_backup";handoff.Payload.SourceEndpoint=response.BundleEndpoint
	// An endpoint change after admission is a different API payload. It gets a
	// different suggested key; unchanged selection data retains its retry key.
	digest:=sha256.Sum256([]byte(request.TenantID+"\x00"+response.EvidenceDigest+"\x00"+response.BundleEndpoint))
	handoff.SuggestedIdempotencyKey="backup-create-"+hex.EncodeToString(digest[:16])
	return json.NewEncoder(os.Stdout).Encode(struct {
		cyberpanelbackup.ConvertResponse
		MigrationCreate createHandoff `json:"migration_create"`
	}{ConvertResponse:response,MigrationCreate:handoff})
}

// The disposable service accepts no path flags. An operator submits the typed
// request on stdin with `cyberpanel-backup-convert convert` as root.
func main() {
	log.SetFlags(0)
	ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
	defer cancel()
	if len(os.Args)==2&&os.Args[1]=="convert" {
		if os.Geteuid()!=0{log.Fatal("local root administrator required")}
		raw,err:=io.ReadAll(io.LimitReader(os.Stdin,(16<<10)+1));if err!=nil||len(raw)>16<<10{log.Fatal("invalid conversion request")}
		decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();var request cyberpanelbackup.ConvertRequest
		if err=decoder.Decode(&request);err!=nil{log.Fatal("invalid conversion request")};if err=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){log.Fatal("invalid conversion request")}
		response,err:=cyberpanelbackup.ConvertLocal(ctx,request);if err!=nil{log.Fatal("conversion incomplete; inspect local receipt and retry the same request ID")}
		if err=writeConversionResult(request,response);err!=nil{log.Fatal("write conversion response failed")};return
	}
	if len(os.Args)!=1{log.Fatal("usage: cyberpanel-backup-convert [convert]")}
	if os.Geteuid()==0{log.Fatal("converter service must run unprivileged")}
	config,err:=cyberpanelbackup.LoadConverterConfig(cyberpanelbackup.DefaultConverterConfigPath);if err!=nil{log.Fatal("invalid converter provisioning")}
	signing,sealing,err:=cyberpanelbackup.LoadProvisionedConverterKeys();if err!=nil{log.Fatal("converter credentials unavailable")}
	converter,err:=cyberpanelbackup.NewConverter(config,signing,sealing)
	for index:=range signing{signing[index]=0};for index:=range sealing{sealing[index]=0}
	if err!=nil{log.Fatal("converter initialization rejected")};defer converter.Close()
	if err=converter.Serve(ctx);err!=nil&&!errors.Is(err,context.Canceled){log.Fatal("converter stopped")}
}
