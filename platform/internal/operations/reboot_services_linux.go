//go:build linux

package operations

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Reboot health is a live observation, never a replay of the effect journal.
func (executor *LinuxOperationsExecutor) observeRebootServices(ctx context.Context, request EffectRequest) (EffectReceipt, error) {
	probeContext,cancel:=context.WithTimeout(ctx,2*time.Minute);defer cancel()
	receipt:=EffectReceipt{EffectID:request.EffectID,RequestDigest:request.RequestDigest}
	result,err:=executor.qualifyRebootServices(probeContext,request)
	receipt.CompletedAt=executor.clock.Now().UTC()
	if err!=nil {
		receipt.Outcome=EffectAmbiguous;receipt.FailureCode="reboot_services_unproven"
		return receipt,errors.Join(ErrCompensationFailed,err)
	}
	receipt.Outcome=EffectConfirmed;receipt.Result=result.Result;receipt.ProofDigest=effectProof(request,result)
	return receipt,nil
}

func (executor *LinuxOperationsExecutor) qualifyRebootServices(ctx context.Context, request EffectRequest) (linuxEffectResult,error) {
	effect:=request.ServiceDiagnose
	if validateRebootServiceQualification(request)!=nil || executor.clock.Now().UTC().Before(effect.Since) || executor.clock.Now().UTC().Sub(effect.Since)>2*time.Minute { return linuxEffectResult{},ErrInvalidEffect }
	boot,err:=os.ReadFile("/proc/sys/kernel/random/boot_id");if err!=nil{return linuxEffectResult{},err}
	if strings.TrimSpace(string(boot))!=effect.Reboot.BootID{return linuxEffectResult{},ErrInvalidEffect}
	diagnostics:=&ServiceDiagnostics{Service:ServicePanel,ActiveState:"active",SubState:"running",BootID:effect.Reboot.BootID}
	control:=[]struct{name,unit string}{
		{"panel_core",operationsServiceUnits[ServicePanel]},
		{"panel_auth","panel-authd.service"},
		{"panel_secrets","panel-secretd.service"},
		{"panel_executor","panel-execd.service"},
		{"panel_gateway","panel-gateway.service"},
		{"panel_provider","panel-providerd.service"},
	}
	for _,target:=range control {
		evidence,probeErr:=executor.probeRebootUnit(ctx,target.unit,nil)
		if probeErr!=nil{return linuxEffectResult{},fmt.Errorf("required service %s: %w",target.name,probeErr)}
		diagnostics.Checks=append(diagnostics.Checks,DiagnosticCheck{Code:"reboot:"+target.name,Outcome:CheckPass,EvidenceDigest:evidence})
	}
	for _,binding:=range effect.Reboot.Required {
		if executor.clock.Now().UTC().Sub(binding.ObservedAt)>2*time.Minute{return linuxEffectResult{},ErrInvalidEffect}
		candidates:=operationsServiceUnitCandidates[binding.Service]
		if len(candidates)==0 {
			unit:=operationsServiceUnits[binding.Service]
			switch binding.Service{case ServiceName("rspamd"):unit="rspamd.service";case ServiceName("clamav"):candidates=[]string{"clamav-daemon.service","clamd@scan.service"}}
			if len(candidates)==0{if unit==""{return linuxEffectResult{},ErrInvalidEffect};candidates=[]string{unit}}
		}
		var evidence string
		var probeErr error=ErrNotFound
		for _,unit:=range candidates {
			evidence,probeErr=executor.probeRebootUnit(ctx,unit,&binding)
			if !errors.Is(probeErr,ErrNotFound){break}
		}
		if probeErr!=nil{return linuxEffectResult{},fmt.Errorf("configured service %s: %w",binding.Service,probeErr)}
		diagnostics.Checks=append(diagnostics.Checks,DiagnosticCheck{Code:"reboot:"+string(binding.Service),Outcome:CheckPass,EvidenceDigest:evidence})
	}
	diagnostics.ObservedAt=executor.clock.Now().UTC()
	if validateRebootServiceDiagnostics(request,*diagnostics)!=nil{return linuxEffectResult{},ErrInvalidEffect}
	return linuxEffectResult{Result:EffectResult{Diagnostics:diagnostics}},nil
}

// Unit paths and property names are fixed; process identifiers come from this
// live systemd response, not from caller-selected filesystem paths.
func (executor *LinuxOperationsExecutor) probeRebootUnit(ctx context.Context, unit string, binding *RebootServiceBinding) (string,error) {
	runner,ok:=executor.runner.(BoundedFixedCommandRunner);if !ok{return "",ErrInvalidEffect}
	probeContext,cancel:=context.WithTimeout(ctx,5*time.Second);defer cancel()
	output,truncated,err:=runner.RunBounded(probeContext,"/usr/bin/systemctl",16<<10,"show",unit,"--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,MainPID,InvocationID,ControlGroup,NeedDaemonReload,Job","--no-pager")
	if err!=nil{return "",err};if truncated{return "",ErrInvalidEffect}
	values:=parseKeyValues(output)
	if values["LoadState"]=="not-found"{return "",ErrNotFound}
	if _,present:=values["Job"];!present{return "",ErrInvalidEffect}
	if values["LoadState"]!="loaded" || values["ActiveState"]!="active" || values["SubState"]!="running" || values["Result"]!="success" || values["ExecMainStatus"]!="0" || values["NeedDaemonReload"]!="no" || values["Job"]!=""&&values["Job"]!="0" { return "",ErrInvalidEffect }
	pid,err:=strconv.ParseUint(values["MainPID"],10,32);if err!=nil||pid==0||len(values["InvocationID"])!=32{return "",ErrInvalidEffect}
	if binding!=nil && (uint32(pid)!=binding.MainPID || values["InvocationID"]!=binding.InvocationID){return "",ErrConflict}
	group:=values["ControlGroup"];if !strings.HasPrefix(group,"/")||group=="/"{return "",ErrInvalidEffect}
	// Verify that the observed process still exists and belongs to this unit.
	file,err:=os.Open("/proc/"+strconv.FormatUint(pid,10)+"/cgroup");if err!=nil{return "",err}
	raw,readErr:=io.ReadAll(io.LimitReader(file,(16<<10)+1));closeErr:=file.Close()
	if readErr!=nil||closeErr!=nil||len(raw)>16<<10{return "",ErrInvalidEffect}
	owned:=false
	for _,line:=range strings.Split(string(raw),"\n") {
		parts:=strings.SplitN(line,":",3)
		if len(parts)==3 && (parts[0]=="0" || parts[1]=="name=systemd") && (parts[2]==group || strings.HasPrefix(parts[2],group+"/")){owned=true}
	}
	if !owned{return "",ErrInvalidEffect}
	registryProof:="";if binding!=nil{registryProof=binding.HealthEvidenceDigest}
	return digestBytes([]byte(string(output)+"\x00"+string(raw)+"\x00"+registryProof)),nil
}
