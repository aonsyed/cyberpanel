//go:build linux

package operations

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var operationsServiceUnits = map[ServiceName]string{
	ServiceWebEnterprise: "lsws.service", ServiceWebOpenLiteSpeed: "lsws.service", ServiceMariaDB: "mariadb.service",
	ServicePostfix: "postfix.service", ServiceDovecot: "dovecot.service", ServicePowerDNS: "pdns.service",
	ServicePureFTPd: "pure-ftpd.service", ServiceRedis: "redis-server.service", ServiceElasticsearch: "elasticsearch.service",
	ServicePanel: "cyberpanel.service",
}
var operationsServiceUnitCandidates=map[ServiceName][]string{ServicePureFTPd:{"pure-ftpd.service","pure-ftpd-mysql.service"},ServiceRedis:{"redis-server.service","redis.service"},ServicePowerDNS:{"pdns.service","pdns_server.service"}}
func (executor *LinuxOperationsExecutor)serviceUnit(ctx context.Context,service ServiceName)(string,error){canonical,ok:=operationsServiceUnits[service];if !ok{return "",ErrInvalidEffect};candidates:=operationsServiceUnitCandidates[service];if len(candidates)==0{candidates=[]string{canonical}};for _,candidate:=range candidates{output,err:=executor.runner.Run(ctx,"/usr/bin/systemctl","show",candidate,"--property=LoadState","--value");if err==nil&&strings.TrimSpace(string(output))=="loaded"{return candidate,nil}};return "",ErrNotFound}

func (executor *LinuxOperationsExecutor) applyResourceProfile(ctx context.Context, effect ResourceProfileEffect) (linuxEffectResult, error) {
	profile := effect.Profile
	if err := executor.guardGeneration(KindResourceProfile, profile.ID, profile.Generation, profile); err != nil { return linuxEffectResult{}, err }
	volume, ok := executor.volumes[profile.Quota.VolumeRef.String()]; if !ok || !allowedVolume(volume.MountPath) { return linuxEffectResult{}, ErrInvalidEffect }
	path := "/etc/cyberpanel/resource-profiles/"+profile.ID.String()+".json"; content, _ := json.Marshal(profile)
	snapshot, err := executor.replaceManagedFile(path, content, 0o600); if err != nil { return linuxEffectResult{}, err }
	result := linuxEffectResult{Snapshots: []operationsFileSnapshot{snapshot}, MutationObserved: true}
	unit := "cyberpanel-"+profile.Cgroup.Binding.ScopeID.String()+".slice"
	properties := []string{
		"CPUQuotaPerSecUSec="+strconv.FormatUint(profile.Cgroup.CPUQuotaMicros*1000000/profile.Cgroup.CPUPeriodMicros, 10)+"us",
		"MemoryHigh="+strconv.FormatUint(profile.Cgroup.MemoryHighBytes, 10), "MemoryMax="+strconv.FormatUint(profile.Cgroup.MemoryMaxBytes, 10),
		"MemorySwapMax="+strconv.FormatUint(profile.Cgroup.SwapMaxBytes, 10), "TasksMax="+strconv.FormatUint(profile.Cgroup.TasksMax, 10),
	}
	if profile.Cgroup.IOReadBytesPerSecond>0||profile.Cgroup.IOWriteBytesPerSecond>0 { deviceOutput,deviceErr:=executor.runner.Run(ctx,"/usr/bin/findmnt","--noheadings","--output","SOURCE","--target",volume.MountPath);if deviceErr!=nil{return result,deviceErr};device:=strings.TrimSpace(string(deviceOutput));if !validBlockDevice(device){return result,ErrInvalidEffect};if profile.Cgroup.IOReadBytesPerSecond>0{properties=append(properties,"IOReadBandwidthMax="+device+" "+strconv.FormatUint(profile.Cgroup.IOReadBytesPerSecond,10))};if profile.Cgroup.IOWriteBytesPerSecond>0{properties=append(properties,"IOWriteBandwidthMax="+device+" "+strconv.FormatUint(profile.Cgroup.IOWriteBytesPerSecond,10))} }
	arguments := append([]string{"set-property", "--runtime", unit}, properties...)
	if output, runErr := executor.runner.Run(ctx, "/usr/bin/systemctl", arguments...); runErr != nil { return result, fmt.Errorf("cgroup v2 profile: %w: %s", runErr, boundedText(output, 2048)) }
	if err = executor.applyProjectQuota(ctx, volume, profile.Quota); err != nil { return result, err }
	if err = executor.storeGeneration(KindResourceProfile, profile.ID, profile.Generation, mustActivationDigest(profile)); err != nil { return result, err }
	return result, nil
}

func (executor *LinuxOperationsExecutor) applyProjectQuota(ctx context.Context, volume OperationsVolume, quota ProjectQuota) error {
	backend,err:=executor.quotaBackend(ctx,volume);if err!=nil{return err}
	switch backend {
	case "project":
		command := fmt.Sprintf("limit -p bsoft=%d bhard=%d isoft=%d ihard=%d %d", quota.SpaceSoftBytes, quota.SpaceHardBytes, quota.InodeSoft, quota.InodeHard, quota.ProjectID)
		output, err := executor.runner.Run(ctx, "/usr/sbin/xfs_quota", "-x", "-c", command, volume.MountPath); if err != nil { return fmt.Errorf("project quota: %w: %s", err, boundedText(output, 2048)) }
	case "ext4-project":
		output, err := executor.runner.Run(ctx, "/usr/sbin/setquota", "-P", strconv.FormatUint(uint64(quota.ProjectID), 10), strconv.FormatUint(quota.SpaceSoftBytes/1024, 10), strconv.FormatUint(quota.SpaceHardBytes/1024, 10), strconv.FormatUint(quota.InodeSoft, 10), strconv.FormatUint(quota.InodeHard, 10), volume.MountPath); if err != nil { return fmt.Errorf("project quota: %w: %s", err, boundedText(output, 2048)) }
	default:
		return ErrInvalidEffect
	}
	return nil
}

func (executor *LinuxOperationsExecutor)quotaBackend(ctx context.Context,volume OperationsVolume)(string,error){if volume.QuotaBackend!="auto"{return volume.QuotaBackend,nil};output,err:=executor.runner.Run(ctx,"/usr/bin/findmnt","--noheadings","--output","FSTYPE","--target",volume.MountPath);if err!=nil{return "",err};switch strings.TrimSpace(string(output)){case "xfs":return "project",nil;case "ext4":return "ext4-project",nil;default:return "",ErrInvalidEffect}}

func allowedVolume(path string) bool { return path == "/home" || path == "/var/lib/cyberpanel" }
func validBlockDevice(value string)bool{if !strings.HasPrefix(value,"/dev/")||len(value)>128{return false};for _,character:=range strings.TrimPrefix(value,"/dev/"){if !(character>='a'&&character<='z'||character>='A'&&character<='Z'||character>='0'&&character<='9'||character=='-'||character=='_'||character=='/'||character=='.'){return false}};return !strings.Contains(value,"..")}

func (executor *LinuxOperationsExecutor) resetTransfer(effect TransferResetEffect) (linuxEffectResult, error) {
	account := effect.Account; path := filepath.Join(executor.stateRoot, "runtime", "transfer-"+account.ID.String()+".json")
	if err:=executor.guardGeneration(KindTransferAccount,account.ID,account.Generation,account);err!=nil{return linuxEffectResult{},err}
	content, _ := json.Marshal(account); snapshot, err := executor.replaceManagedFile(path, content, 0o600); if err != nil { return linuxEffectResult{}, err }
	if err=executor.storeGeneration(KindTransferAccount,account.ID,account.Generation,mustActivationDigest(account));err!=nil{return linuxEffectResult{Snapshots:[]operationsFileSnapshot{snapshot},MutationObserved:true},err}
	return linuxEffectResult{Snapshots: []operationsFileSnapshot{snapshot}, MutationObserved: true}, nil
}

func (executor *LinuxOperationsExecutor) sampleTransfer(effect TransferSampleEffect) (linuxEffectResult, error) {
	path := filepath.Join(executor.stateRoot, "runtime", "transfer-"+effect.Account.ID.String()+".json")
	content, err := os.ReadFile(path); if errors.Is(err, os.ErrNotExist) { return linuxEffectResult{}, ErrNotFound }; if err != nil { return linuxEffectResult{}, err }
	var stored TransferAccount; if json.Unmarshal(content, &stored) != nil || stored.ID != effect.Account.ID || stored.CounterEpoch != effect.Account.CounterEpoch || effect.Account.IngressBytes<stored.IngressBytes || effect.Account.EgressBytes<stored.EgressBytes || effect.Account.LastSampleAt.Before(stored.LastSampleAt) { return linuxEffectResult{}, ErrInvalidEffect }
	if err=executor.guardGeneration(KindTransferAccount,effect.Account.ID,effect.Account.Generation,effect.Account);err!=nil{return linuxEffectResult{},err}
	updated,_:=json.Marshal(effect.Account);if err=atomicOperationsFile(path,updated,0o600);err!=nil{return linuxEffectResult{},err}
	if err=executor.storeGeneration(KindTransferAccount,effect.Account.ID,effect.Account.Generation,mustActivationDigest(effect.Account));err!=nil{return linuxEffectResult{},err}
	return linuxEffectResult{}, nil
}

func (executor *LinuxOperationsExecutor) applyServicePolicy(ctx context.Context, effect ServicePolicyEffect) (linuxEffectResult, error) {
	policy := effect.Policy; unit, unitErr := executor.serviceUnit(ctx,policy.Service); if unitErr!=nil{return linuxEffectResult{},unitErr}
	if err := executor.guardGeneration(KindServicePolicy, policy.ID, policy.Generation, policy); err != nil { return linuxEffectResult{}, err }
	content, _ := json.Marshal(policy); path := "/etc/cyberpanel/service-policies/"+string(policy.Service)+".json"; snapshot, err := executor.replaceManagedFile(path, content, 0o600); if err != nil { return linuxEffectResult{}, err }
	result := linuxEffectResult{Snapshots: []operationsFileSnapshot{snapshot}, MutationObserved: true}
	bootAction := "disable"; if policy.EnabledAtBoot { bootAction = "enable" }
	if output, runErr := executor.runner.Run(ctx, "/usr/bin/systemctl", bootAction, unit); runErr != nil { return result, fmt.Errorf("service boot policy: %w: %s", runErr, boundedText(output, 2048)) }
	action := "stop"; if policy.Desired == ServiceRunning { action = "start" }
	if output, runErr := executor.runner.Run(ctx, "/usr/bin/systemctl", action, unit); runErr != nil { return result, fmt.Errorf("service desired state: %w: %s", runErr, boundedText(output, 2048)) }
	if err = executor.probeService(ctx, policy.Service, policy.HealthProbe, policy.Desired); err != nil { return result, err }
	if err = executor.storeGeneration(KindServicePolicy, policy.ID, policy.Generation, mustActivationDigest(policy)); err != nil { return result, err }
	return result, nil
}

func (executor *LinuxOperationsExecutor) controlService(ctx context.Context, effect ServiceControlEffect) (linuxEffectResult, error) {
	unit, unitErr := executor.serviceUnit(ctx,effect.Service); if unitErr!=nil{return linuxEffectResult{},unitErr}
	if err:=executor.requireGeneration(KindServicePolicy,serviceResourceID(effect.Service),effect.PolicyGeneration);err!=nil{return linuxEffectResult{},err}
	action := string(effect.Action); if action != "start" && action != "stop" && action != "restart" && action != "reload" { return linuxEffectResult{}, ErrInvalidEffect }
	output, err := executor.runner.Run(ctx, "/usr/bin/systemctl", action, unit); if err != nil { return linuxEffectResult{MutationObserved: true}, fmt.Errorf("service control: %w: %s", err, boundedText(output, 2048)) }
	return linuxEffectResult{MutationObserved: true}, nil
}

func (executor *LinuxOperationsExecutor) diagnoseService(ctx context.Context, effect ServiceDiagnoseEffect) (linuxEffectResult, error) {
	unit, unitErr := executor.serviceUnit(ctx,effect.Service); if unitErr!=nil{return linuxEffectResult{},unitErr}
	if effect.Depth != DiagnosticSummary && effect.Depth != DiagnosticDependency && effect.Depth != DiagnosticDeep { return linuxEffectResult{}, ErrInvalidEffect }
	output, err := executor.runner.Run(ctx, "/usr/bin/systemctl", "show", unit, "--property=ActiveState,SubState,NRestarts,Result", "--no-pager"); if err != nil { return linuxEffectResult{}, err }
	values := parseKeyValues(output); diagnostics := &ServiceDiagnostics{Service: effect.Service, ActiveState: values["ActiveState"], SubState: values["SubState"]}
	restarts, _ := strconv.ParseUint(values["NRestarts"], 10, 32); diagnostics.RestartCount = uint32(restarts)
	stateOutcome := CheckFail; if diagnostics.ActiveState == "active" { stateOutcome = CheckPass } else if diagnostics.ActiveState == "activating" { stateOutcome = CheckWarn }
	diagnostics.Checks = append(diagnostics.Checks, DiagnosticCheck{Code: "systemd_state", Outcome: stateOutcome, EvidenceDigest: digestBytes(output)})
	if effect.Depth == DiagnosticDependency || effect.Depth == DiagnosticDeep { dependencyOutput, dependencyErr := executor.runner.Run(ctx,"/usr/bin/systemctl","list-dependencies","--failed","--no-pager",unit);outcome:=CheckPass;if dependencyErr!=nil||bytes.Contains(dependencyOutput,[]byte("●")){outcome=CheckFail};diagnostics.Checks=append(diagnostics.Checks,DiagnosticCheck{Code:"failed_dependencies",Outcome:outcome,EvidenceDigest:digestBytes(dependencyOutput)}) }
	if effect.Depth == DiagnosticDeep { journalOutput,journalErr:=executor.runner.Run(ctx,"/usr/bin/journalctl","--unit="+unit,"--since="+effect.Since.UTC().Format(time.RFC3339Nano),"--priority=err","--lines=128","--no-pager");outcome:=CheckPass;if journalErr!=nil{outcome=CheckWarn}else if len(bytes.TrimSpace(journalOutput))>0{outcome=CheckFail};diagnostics.Checks=append(diagnostics.Checks,DiagnosticCheck{Code:"recent_errors",Outcome:outcome,EvidenceDigest:digestBytes(journalOutput)}) }
	if stateOutcome != CheckPass { diagnostics.SuggestedRepairs = []RepairStrategy{RepairResetFailed, RepairDependencyOrder} }
	return linuxEffectResult{Result: EffectResult{Diagnostics: diagnostics}}, nil
}

func (executor *LinuxOperationsExecutor) repairService(ctx context.Context, effect ServiceRepairEffect) (linuxEffectResult, error) {
	unit, unitErr := executor.serviceUnit(ctx,effect.Service); if unitErr!=nil{return linuxEffectResult{},unitErr}
	if err := executor.verifyDiagnosticProof(effect.DiagnosticProofDigest,effect.Service); err != nil { return linuxEffectResult{}, err }
	var sequences [][]string
	switch effect.Strategy {
	case RepairReconcileConfig: sequences = [][]string{{"daemon-reload"}, {"reload-or-restart", unit}}
	case RepairResetFailed: sequences = [][]string{{"reset-failed", unit}, {"restart", unit}}
	case RepairDependencyOrder: sequences = [][]string{{"start", unit}}
	case RepairReinstallManagedFiles: return executor.reinstallServicePackage(ctx, effect.Service)
	default: return linuxEffectResult{}, ErrInvalidEffect
	}
	for _, arguments := range sequences { if output, err := executor.runner.Run(ctx, "/usr/bin/systemctl", arguments...); err != nil { return linuxEffectResult{MutationObserved: true}, fmt.Errorf("service repair: %w: %s", err, boundedText(output, 2048)) } }
	return linuxEffectResult{MutationObserved: true}, nil
}

func (executor *LinuxOperationsExecutor) reinstallServicePackage(ctx context.Context, service ServiceName) (linuxEffectResult, error) {
	packageIDs := map[ServiceName]string{ServiceWebOpenLiteSpeed:"openlitespeed",ServiceWebEnterprise:"litespeed", ServiceMariaDB:"mariadb-server", ServicePostfix:"postfix", ServiceDovecot:"dovecot", ServicePowerDNS:"powerdns",ServicePureFTPd:"pureftpd", ServiceRedis:"redis", ServiceElasticsearch:"elasticsearch"}
	id, ok := packageIDs[service]; if !ok { return linuxEffectResult{}, ErrInvalidEffect }; item, ok := executor.packages[id]; if !ok { return linuxEffectResult{}, ErrInvalidEffect }
	if item.APTName != "" { output, err := executor.runner.Run(ctx, "/usr/bin/apt-get", "--yes", "--reinstall", "install", item.APTName); if err == nil { return linuxEffectResult{MutationObserved:true}, nil } else if len(output) > 0 { _ = output } }
	output, err := executor.runner.Run(ctx, "/usr/bin/dnf", "--assumeyes", "reinstall", item.DNFName); if err != nil { return linuxEffectResult{MutationObserved:true}, fmt.Errorf("managed package reinstall: %w: %s", err, boundedText(output, 2048)) }
	return linuxEffectResult{MutationObserved:true}, nil
}

func (executor *LinuxOperationsExecutor) probeService(ctx context.Context, service ServiceName, probe ServiceHealthProbe, desired ServiceDesiredState) error {
	unit,err:=executor.serviceUnit(ctx,service);if err!=nil{return err}
	if desired == ServiceStopped { output, err := executor.runner.Run(ctx, "/usr/bin/systemctl", "is-active", unit); if err == nil && strings.TrimSpace(string(output)) != "inactive" { return errors.New("service remained active") }; return nil }
	if probe.Kind == ProbeSystemd { output, err := executor.runner.Run(ctx, "/usr/bin/systemctl", "is-active", unit); if err != nil || strings.TrimSpace(string(output)) != "active" { return errors.New("service is not active") }; return nil }
	switch probe.Kind {
	case ProbeTCP: return probeTCP(ctx,probe.Port,1)
	case ProbeHTTP,ProbeElasticsearch: return probeHTTPProtocol(ctx,probe.Port)
	case ProbeMariaDB: return probeMariaDBProtocol(ctx,probe.Port)
	case ProbeRedis: return probeRedisProtocol(ctx,probe.Port)
	default:return ErrInvalidEffect
	}
}

func probeHTTPProtocol(ctx context.Context,port uint16)error{transport:=&http.Transport{Proxy:nil,DialContext:(&net.Dialer{Timeout:2*time.Second}).DialContext,DisableKeepAlives:true};defer transport.CloseIdleConnections();client:=http.Client{Transport:transport,Timeout:3*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}};request,err:=http.NewRequestWithContext(ctx,http.MethodGet,"http://127.0.0.1:"+strconv.Itoa(int(port))+"/",nil);if err!=nil{return err};response,err:=client.Do(request);if err!=nil{return err};defer response.Body.Close();_,err=io.CopyN(io.Discard,response.Body,4096);if errors.Is(err,io.EOF){err=nil};if response.StatusCode<100||response.StatusCode>599{return ErrInvalidEffect};return err}
func probeMariaDBProtocol(ctx context.Context,port uint16)error{connection,err:=(&net.Dialer{Timeout:2*time.Second}).DialContext(ctx,"tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(int(port))));if err!=nil{return err};defer connection.Close();_ = connection.SetDeadline(time.Now().Add(2*time.Second));header:=make([]byte,5);if _,err=io.ReadFull(connection,header);err!=nil{return err};if header[3]!=0||header[4]!=10{return errors.New("invalid MariaDB handshake")};return nil}
func probeRedisProtocol(ctx context.Context,port uint16)error{connection,err:=(&net.Dialer{Timeout:2*time.Second}).DialContext(ctx,"tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(int(port))));if err!=nil{return err};defer connection.Close();_ = connection.SetDeadline(time.Now().Add(2*time.Second));if _,err=connection.Write([]byte("*1\r\n$4\r\nPING\r\n"));err!=nil{return err};response:=make([]byte,64);count,err:=connection.Read(response);if err!=nil{return err};if !bytes.HasPrefix(response[:count],[]byte("+PONG"))&&!bytes.HasPrefix(response[:count],[]byte("-NOAUTH")){return errors.New("invalid Redis protocol response")};return nil}

func (executor *LinuxOperationsExecutor) queryMetrics(ctx context.Context, effect MetricsQueryEffect) (linuxEffectResult, error) {
	if effect.Limit == 0 || effect.Limit > 10000 || effect.End.Before(effect.Start) || effect.End.Sub(effect.Start) > 31*24*time.Hour { return linuxEffectResult{}, ErrInvalidEffect }
	at := executor.clock.Now().UTC(); if at.Before(effect.Start) { at = effect.Start }; if at.After(effect.End) { at = effect.End }
	points := make([]MetricPoint, 0, len(effect.Names)); seen := make(map[MetricName]struct{})
	for _, name := range effect.Names { if len(points) >= int(effect.Limit) { break }; if _, exists := seen[name]; exists { continue }; seen[name] = struct{}{}; value, unit, err := executor.metricValue(ctx, effect.Scope, name); if err != nil { continue }; points = append(points, MetricPoint{Name:name, At:at, Value:value, Unit:unit}) }
	return linuxEffectResult{Result: EffectResult{Metrics:&MetricsBatch{Scope:effect.Scope, Points:points, Truncated:len(points)<len(effect.Names)}}}, nil
}

func (executor *LinuxOperationsExecutor) metricValue(ctx context.Context, scope EnforcementScope, name MetricName) (float64, MetricUnit, error) {
	if scope.Kind != ScopeNode {
		cgroup, err := executor.cgroupForScope(scope); if err != nil { return 0,"",err }
		switch name {
		case MetricCPUUsage:
			content, err := os.ReadFile(filepath.Join(cgroup,"cpu.stat")); if err != nil { return 0,UnitRatio,err }; values:=parseKeyValuesSpace(content);usage:=values["usage_usec"];uptimeContent,err:=os.ReadFile("/proc/uptime");if err!=nil{return 0,UnitRatio,err};uptime,_:=strconv.ParseFloat(strings.Fields(string(uptimeContent))[0],64);if uptime<=0{return 0,UnitRatio,ErrInvalidEffect};ratio:=float64(usage)/(uptime*1_000_000*float64(runtime.NumCPU()));if ratio>1{ratio=1};return ratio,UnitRatio,nil
		case MetricMemoryUsage:
			content,err:=os.ReadFile(filepath.Join(cgroup,"memory.current"));if err!=nil{return 0,UnitBytes,err};value,err:=strconv.ParseUint(strings.TrimSpace(string(content)),10,64);return float64(value),UnitBytes,err
		case MetricIOBytes:
			content,err:=os.ReadFile(filepath.Join(cgroup,"io.stat"));if err!=nil{return 0,UnitBytes,err};var total uint64;for _,field:=range strings.Fields(string(content)){if strings.HasPrefix(field,"rbytes=")||strings.HasPrefix(field,"wbytes="){value,_:=strconv.ParseUint(strings.SplitN(field,"=",2)[1],10,64);total+=value}};return float64(total),UnitBytes,nil
		case MetricPHPWorkers:
			content,err:=os.ReadFile(filepath.Join(cgroup,"cgroup.procs"));if err!=nil{return 0,UnitCount,err};count:=0;for _,pid:=range strings.Fields(string(content)){comm,readErr:=os.ReadFile(filepath.Join("/proc",pid,"comm"));if readErr==nil&&strings.Contains(string(comm),"lsphp"){count++}};return float64(count),UnitCount,nil
		case MetricNetworkBytes:
			return 0,UnitBytes,errors.New("network accounting requires the transfer ledger")
		}
	}
	switch name {
	case MetricCPUUsage:
		content, err := os.ReadFile("/proc/loadavg"); if err != nil { return 0, UnitRatio, err }; fields := strings.Fields(string(content)); value, err := strconv.ParseFloat(fields[0], 64); return value/float64(runtime.NumCPU()), UnitRatio, err
	case MetricMemoryUsage:
		values, err := readMeminfo(); if err != nil { return 0, UnitBytes, err }; return float64((values["MemTotal"]-values["MemAvailable"])*1024), UnitBytes, nil
	case MetricDiskUsage, MetricInodeUsage:
		var stat syscall.Statfs_t; if err := syscall.Statfs("/home", &stat); err != nil { return 0, UnitBytes, err }; if name == MetricDiskUsage { return float64((stat.Blocks-stat.Bfree)*uint64(stat.Bsize)), UnitBytes, nil }; return float64(stat.Files-stat.Ffree), UnitCount, nil
	case MetricNetworkBytes:
		content, err := os.ReadFile("/proc/net/dev"); if err != nil { return 0, UnitBytes, err }; var total float64; for _, line := range strings.Split(string(content), "\n") { fields := strings.Fields(strings.ReplaceAll(line, ":", " ")); if len(fields) >= 10 && fields[0] != "lo" { receive, _ := strconv.ParseFloat(fields[1],64); transmit, _ := strconv.ParseFloat(fields[9],64); total += receive+transmit } }; return total, UnitBytes, nil
	case MetricIOBytes:
		content, err := os.ReadFile("/proc/diskstats"); if err != nil { return 0, UnitBytes, err }; var sectors uint64; for _, line := range strings.Split(string(content), "\n") { fields := strings.Fields(line); if len(fields) >= 10 { read, _ := strconv.ParseUint(fields[5],10,64); written, _ := strconv.ParseUint(fields[9],10,64); sectors += read+written } }; return float64(sectors*512), UnitBytes, nil
	case MetricPHPWorkers: return float64(countProcessesContaining("lsphp")), UnitCount, nil
	case MetricServiceHealth: return 1, UnitCount, nil
	default: return 0, "", ErrInvalidEffect
	}
}

func readMeminfo() (map[string]uint64, error) { content, err := os.ReadFile("/proc/meminfo"); if err != nil { return nil, err }; values := map[string]uint64{}; for _, line := range strings.Split(string(content), "\n") { fields := strings.Fields(line); if len(fields) >= 2 { value, parseErr := strconv.ParseUint(fields[1],10,64); if parseErr == nil { values[strings.TrimSuffix(fields[0],":")] = value } } }; return values,nil }
func countProcessesContaining(needle string) int { entries, _ := os.ReadDir("/proc"); count := 0; for _, entry := range entries { if _, err := strconv.Atoi(entry.Name()); err != nil { continue }; content, err := os.ReadFile(filepath.Join("/proc",entry.Name(),"comm")); if err == nil && strings.Contains(string(content),needle) { count++ } }; return count }

func (executor *LinuxOperationsExecutor) queryLogs(ctx context.Context, effect LogQueryEffect) (linuxEffectResult, error) {
	if effect.Limit == 0 || effect.Limit > 5000 || effect.End.Before(effect.Start) || effect.End.Sub(effect.Start) > 31*24*time.Hour { return linuxEffectResult{}, ErrInvalidEffect }
	arguments := []string{"--output=json", "--no-pager", "--since="+effect.Start.UTC().Format(time.RFC3339Nano), "--until="+effect.End.UTC().Format(time.RFC3339Nano), "--lines="+strconv.FormatUint(uint64(effect.Limit),10)}
	if effect.Cursor!="" { arguments=append(arguments,"--after-cursor="+effect.Cursor) }
	arguments = append(arguments, journalSelector(effect.Source, effect.Service)...)
	if effect.TenantID != "" { arguments = append(arguments, "CYBERPANEL_TENANT_ID="+effect.TenantID) }
	if effect.SiteID != "" { arguments = append(arguments, "CYBERPANEL_SITE_ID="+effect.SiteID) }
	output, err := executor.runner.Run(ctx, "/usr/bin/journalctl", arguments...); if err != nil { return linuxEffectResult{}, err }
	entries := parseJournalEntries(output, effect); next:="";if len(entries)>0{next=entries[len(entries)-1].Cursor};return linuxEffectResult{Result:EffectResult{Logs:&LogBatch{Entries:entries,NextCursor:next, Truncated:uint32(len(entries))==effect.Limit}}},nil
}

func journalSelector(source LogSource, service ServiceName) []string {
	switch source {
	case LogPanel: return []string{"--unit=cyberpanel.service"}
	case LogMariaDB: return []string{"--unit=mariadb.service"}
	case LogMail: return []string{"--unit=postfix.service", "--unit=dovecot.service"}
	case LogSSH: return []string{"--unit=sshd.service", "--unit=ssh.service"}
	case LogFirewall: return []string{"--identifier=kernel", "--grep=cyberpanel-fw"}
	case LogServiceJournal: if candidates:=operationsServiceUnitCandidates[service];len(candidates)>0{result:=make([]string,len(candidates));for index,unit:=range candidates{result[index]="--unit="+unit};return result}else if unit, ok := operationsServiceUnits[service]; ok { return []string{"--unit="+unit} }
	case LogWebAccess, LogWebError: return []string{"--unit=lsws.service"}
	case LogPHP: return []string{"--identifier=lsphp"}
	case LogWAF: return []string{"--identifier=modsecurity"}
	}
	return []string{"--identifier=cyberpanel-none"}
}

func parseJournalEntries(output []byte, effect LogQueryEffect) []LogEntry {
	entries := make([]LogEntry,0); scanner := bufio.NewScanner(bytes.NewReader(output)); scanner.Buffer(make([]byte,4096),1<<20)
	for scanner.Scan() { var value map[string]any; if json.Unmarshal(scanner.Bytes(),&value)!=nil { continue }; timestamp,_:=strconv.ParseInt(textValue(value["__REALTIME_TIMESTAMP"]),10,64); at:=time.UnixMicro(timestamp).UTC(); severity64,_:=strconv.ParseUint(textValue(value["PRIORITY"]),10,8); severity:=uint8(severity64); if at.Before(effect.Start)||at.After(effect.End)||severity<effect.MinimumSeverity { continue }; cursor:=textValue(value["__CURSOR"]); message:=textValue(value["MESSAGE"]); if cursor==""||len(cursor)>512||len(message)>65536 { continue }; code:=textValue(value["SYSLOG_IDENTIFIER"]); if code=="" { code="journal" }; if len(code)>128 { code=code[:128] }; entries=append(entries,LogEntry{Cursor:cursor,At:at,Source:effect.Source,Severity:severity,EventCode:code,Message:message}); if len(entries)>=int(effect.Limit){break} }
	return entries
}

func textValue(value any) string { switch typed:=value.(type){case string:return typed;case float64:return strconv.FormatInt(int64(typed),10);default:return ""} }

func (executor *LinuxOperationsExecutor) querySSHLogins(ctx context.Context, effect SSHLoginQueryEffect) (linuxEffectResult,error){
	if effect.Limit==0||effect.Limit>5000||effect.End.Before(effect.Start){return linuxEffectResult{},ErrInvalidEffect}; query:=LogQueryEffect{Source:LogSSH,Start:effect.Start,End:effect.End,Limit:effect.Limit}; logs,err:=executor.queryLogs(ctx,query);if err!=nil{return linuxEffectResult{},err};records:=make([]SSHLoginRecord,0)
	for _,entry:=range logs.Result.Logs.Entries{record,ok:=parseSSHLogin(entry);if !ok{continue};if effect.SourceCIDR!=nil&&!effect.SourceCIDR.Contains(record.Source){continue};records=append(records,record)};return linuxEffectResult{Result:EffectResult{SSHLogins:&SSHLoginBatch{Records:records,Truncated:uint32(len(records))==effect.Limit}}},nil
}

func parseSSHLogin(entry LogEntry)(SSHLoginRecord,bool){ fields:=strings.Fields(entry.Message); outcome:=SSHLoginOutcome(""); marker:=""; if strings.Contains(entry.Message,"Accepted publickey"){outcome=SSHLoginAccepted;marker="from"}else if strings.Contains(entry.Message,"Failed publickey")||strings.Contains(entry.Message,"Invalid user"){outcome=SSHLoginRejected;marker="from"}else{return SSHLoginRecord{},false}; var address netip.Addr;var principal string;for index,value:=range fields{if value==marker&&index+1<len(fields){address,_=netip.ParseAddr(strings.Trim(fields[index+1],"[]"))};if value=="for"&&index+1<len(fields){principal=fields[index+1]}};if !address.IsValid(){return SSHLoginRecord{},false};principalID,_:=NewResourceID(normalizeOpaque(principal));return SSHLoginRecord{At:entry.At,PrincipalID:principalID,Source:address,Authentication:SSHKeysOnly,Outcome:outcome,ReasonCode:"sshd"},true }

func (executor *LinuxOperationsExecutor) querySSHSessions(ctx context.Context,effect SSHSessionQueryEffect)(linuxEffectResult,error){
	if effect.Limit==0||effect.Limit>4096{return linuxEffectResult{},ErrInvalidEffect};output,err:=executor.runner.Run(ctx,"/usr/bin/loginctl","list-sessions","--no-legend","--no-pager");if err!=nil{return linuxEffectResult{},err};sessions:=make([]SSHSession,0)
	for _,line:=range strings.Split(string(output),"\n"){fields:=strings.Fields(line);if len(fields)<3||len(sessions)>=int(effect.Limit){continue};if _,err:=strconv.ParseUint(fields[0],10,32);err!=nil{continue};details,detailErr:=executor.runner.Run(ctx,"/usr/bin/loginctl","show-session",fields[0],"--property=Name,RemoteHost,TimestampUSec,IdleSinceHintUSec,State","--no-pager");if detailErr!=nil{continue};values:=parseKeyValues(details);source,parseErr:=netip.ParseAddr(values["RemoteHost"]);if parseErr!=nil{continue};id,_:=NewResourceID("session-"+fields[0]);principal,_:=NewResourceID(normalizeOpaque(values["Name"]));started:=parseSystemdTimestamp(values["TimestampUSec"]);last:=parseSystemdTimestamp(values["IdleSinceHintUSec"]);if last.Before(started){last=started};sessions=append(sessions,SSHSession{ID:id,PrincipalID:principal,Source:source,StartedAt:started,LastActivityAt:last,Processes:[]ProcessIdentity{}})};return linuxEffectResult{Result:EffectResult{SSHSessions:&SSHSessionBatch{Sessions:sessions,Truncated:len(sessions)>=int(effect.Limit)}}},nil
}

func parseSystemdTimestamp(raw string)time.Time{raw=strings.TrimSpace(raw);if microseconds,err:=strconv.ParseInt(raw,10,64);err==nil&&microseconds>0{return time.UnixMicro(microseconds).UTC()};return time.Now().UTC()}

func (executor *LinuxOperationsExecutor) investigateProcess(ctx context.Context,effect ProcessInvestigateEffect)(linuxEffectResult,error){report,err:=executor.processReport(ctx,effect.Process,effect.IncludeFileDescriptors,effect.IncludeNetworkSockets);if err!=nil{return linuxEffectResult{},err};return linuxEffectResult{Result:EffectResult{Process:&report}},nil}

func (executor *LinuxOperationsExecutor) processReport(ctx context.Context,identity ProcessIdentity,includeFDs,includeSockets bool)(ProcessReport,error){
	if err:=verifyProcessIdentity(identity);err!=nil{return ProcessReport{},err};pid:=strconv.FormatUint(uint64(identity.PID),10);status,err:=os.ReadFile(filepath.Join("/proc",pid,"status"));if err!=nil{return ProcessReport{},err};values:=parseProcStatus(status);report:=ProcessReport{Identity:identity,SystemUserID:uint32(values["Uid"]),SystemGroupID:uint32(values["Gid"]),ResidentBytes:values["VmRSS"]*1024}
	if executable,linkErr:=os.Readlink(filepath.Join("/proc",pid,"exe"));linkErr==nil&&strings.HasPrefix(executable,"/"){if digest,digestErr:=fileDigest(executable,1<<30);digestErr==nil{report.ExecutableDigest=digest}}
	if includeFDs{if entries,readErr:=os.ReadDir(filepath.Join("/proc",pid,"fd"));readErr==nil{report.OpenFileDescriptorCount=uint32(len(entries))}}
	if cgroup,readErr:=os.ReadFile(filepath.Join("/proc",pid,"cgroup"));readErr==nil{for _,line:=range strings.Split(string(cgroup),"\n"){parts:=strings.SplitN(line,":",3);if len(parts)==3&&parts[1]==""{id,_:=NewResourceID(normalizeOpaque(filepath.Base(parts[2])));report.CgroupScope=id}}}
	if includeSockets{output,_:=executor.runner.Run(ctx,"/usr/bin/ss","--no-header","--numeric","--processes","--tcp","--udp");report.Sockets=parseProcessSockets(output,identity.PID)}
	return report,nil
}

func verifyProcessIdentity(identity ProcessIdentity)error{boot,err:=os.ReadFile("/proc/sys/kernel/random/boot_id");if err!=nil{return err};if normalizeOpaque(strings.TrimSpace(string(boot)))!=identity.BootID.String(){return ErrConflict};stat,err:=os.ReadFile(filepath.Join("/proc",strconv.FormatUint(uint64(identity.PID),10),"stat"));if err!=nil{return err};closing:=bytes.LastIndexByte(stat,')');if closing<0||closing+2>=len(stat){return ErrInvalidEffect};fields:=strings.Fields(string(stat[closing+2:]));if len(fields)<=19{return ErrInvalidEffect};start,err:=strconv.ParseUint(fields[19],10,64);if err!=nil||start!=identity.StartTimeTicks{return ErrConflict};return nil}

func parseProcStatus(content []byte)map[string]uint64{values:=map[string]uint64{};for _,line:=range strings.Split(string(content),"\n"){fields:=strings.Fields(line);if len(fields)<2{continue};key:=strings.TrimSuffix(fields[0],":");if key=="Uid"||key=="Gid"||key=="VmRSS"{value,_:=strconv.ParseUint(fields[1],10,64);values[key]=value}};return values}
func parseProcessSockets(output []byte,pid uint32)[]ProcessSocket{needle:="pid="+strconv.FormatUint(uint64(pid),10)+",";result:=make([]ProcessSocket,0);for _,line:=range strings.Split(string(output),"\n"){if !strings.Contains(line,needle){continue};fields:=strings.Fields(line);if len(fields)<5{continue};protocol:=SocketTCP;if strings.HasPrefix(fields[0],"udp"){protocol=SocketUDP};local,_:=netip.ParseAddrPort(normalizeAddrPort(fields[len(fields)-3]));remote,_:=netip.ParseAddrPort(normalizeAddrPort(fields[len(fields)-2]));if local.IsValid(){result=append(result,ProcessSocket{Protocol:protocol,LocalAddress:local,RemoteAddress:remote,State:fields[1]})};if len(result)>=4096{break}};return result}
func normalizeAddrPort(value string)string{value=strings.TrimSpace(value);if strings.HasPrefix(value,"*:"){value="0.0.0.0"+value[1:]};return value}

const syscallPIDFDOpen=434
const syscallPIDFDSendSignal=424

func (executor *LinuxOperationsExecutor) terminateProcess(ctx context.Context,effect ProcessTerminateEffect)(linuxEffectResult,error){
	if err:=verifyProcessIdentity(effect.Process);err!=nil{return linuxEffectResult{},err};if err:=executor.verifyProcessProof(effect.InvestigationProofDigest,effect.Process);err!=nil{return linuxEffectResult{},err};signal:=syscall.SIGTERM;switch effect.Signal{case SignalTerminate:signal=syscall.SIGTERM;case SignalKill:signal=syscall.SIGKILL;case SignalHangup:signal=syscall.SIGHUP;default:return linuxEffectResult{},ErrInvalidEffect}
	pidfd,_,errno:=syscall.Syscall(syscallPIDFDOpen,uintptr(effect.Process.PID),0,0);if errno!=0{return linuxEffectResult{},errno};defer syscall.Close(int(pidfd));_,_,errno=syscall.Syscall6(syscallPIDFDSendSignal,pidfd,uintptr(signal),0,0,0,0);if errno!=0{return linuxEffectResult{MutationObserved:true},errno};select{case<-ctx.Done():return linuxEffectResult{MutationObserved:true},ctx.Err();case<-time.After(50*time.Millisecond):};return linuxEffectResult{MutationObserved:true},nil
}

func (executor *LinuxOperationsExecutor) storeProcessProof(proof string,identity ProcessIdentity)error{content,_:=json.Marshal(identity);return atomicOperationsFile(filepath.Join(executor.stateRoot,"runtime","process-proof-"+proof+".json"),content,0o600)}
func (executor *LinuxOperationsExecutor) verifyProcessProof(proof string,identity ProcessIdentity)error{if !validSHA256(proof){return ErrInvalidEffect};content,err:=os.ReadFile(filepath.Join(executor.stateRoot,"runtime","process-proof-"+proof+".json"));if err!=nil{return err};var stored ProcessIdentity;if json.Unmarshal(content,&stored)!=nil||stored!=identity{return ErrConflict};return nil}
func (executor *LinuxOperationsExecutor) storeDiagnosticProof(proof string,service ServiceName)error{return atomicOperationsFile(filepath.Join(executor.stateRoot,"runtime","diagnostic-proof-"+proof+".json"),[]byte(service),0o600)}
func (executor *LinuxOperationsExecutor) verifyDiagnosticProof(proof string,service ServiceName)error{if !validSHA256(proof){return ErrInvalidEffect};content,err:=os.ReadFile(filepath.Join(executor.stateRoot,"runtime","diagnostic-proof-"+proof+".json"));if err!=nil{return err};if string(content)!=string(service){return ErrConflict};return nil}

func (executor *LinuxOperationsExecutor) applyPackageTransaction(ctx context.Context,effect PackageTransactionEffect)(linuxEffectResult,error){
	transaction:=effect.Transaction;if err:=executor.guardGeneration(KindPackageTransaction,transaction.ID,transaction.Generation,transaction);err!=nil{return linuxEffectResult{},err};changes:=make([]PackageChange,0,len(transaction.Selections));if transaction.RefreshMetadata{binary,args:=packageRefresh(transaction.Manager);if output,err:=executor.runner.Run(ctx,binary,args...);err!=nil{return linuxEffectResult{},fmt.Errorf("package metadata refresh: %w: %s",err,boundedText(output,2048))}}
	for _,selection:=range transaction.Selections{catalog,ok:=executor.packages[selection.Name.String()];if !ok||!validPackageArchitecture(selection.Architecture.String())||!validPackageVersion(selection.FromVersion)||!validPackageVersion(selection.ToVersion)||transaction.SecurityOnly&&transaction.Manager==PackageAPT&&selection.ToVersion==""{return linuxEffectResult{},ErrInvalidEffect};if err:=executor.verifyInstalledVersion(ctx,transaction.Manager,selection,catalog);err!=nil{return linuxEffectResult{},err};binary,args,packageName,err:=packageCommand(transaction.Manager,selection,catalog);if err!=nil{return linuxEffectResult{},err};if transaction.SecurityOnly&&transaction.Manager==PackageDNF{args=append([]string{"--security"},args...)};output,runErr:=executor.runner.Run(ctx,binary,args...);if runErr!=nil{return linuxEffectResult{MutationObserved:true},fmt.Errorf("package transaction: %w: %s",runErr,boundedText(output,2048))};changes=append(changes,PackageChange{Name:selection.Name,Architecture:selection.Architecture,FromVersion:selection.FromVersion,ToVersion:selection.ToVersion,Action:selection.Action});_ = packageName}
	rebootRequired:=false;if _,err:=os.Stat("/var/run/reboot-required");err==nil{rebootRequired=true};result:=&PackageTransactionResult{Changes:changes,RebootRequired:rebootRequired,RecoveryValidated:false};if err:=executor.storeGeneration(KindPackageTransaction,transaction.ID,transaction.Generation,mustActivationDigest(transaction));err!=nil{return linuxEffectResult{MutationObserved:true},err};return linuxEffectResult{MutationObserved:true,Result:EffectResult{Packages:result}},nil
}

func packageRefresh(manager PackageManager)(string,[]string){if manager==PackageAPT{return "/usr/bin/apt-get",[]string{"update"}};return "/usr/bin/dnf",[]string{"--assumeyes","makecache"}}
func packageCommand(manager PackageManager,selection PackageSelection,catalog OperationsPackage)(string,[]string,string,error){name:=catalog.APTName;architecture:=selection.Architecture.String();if manager==PackageDNF{name=catalog.DNFName;architecture=mapArchitectureDNF(architecture)}else{architecture=mapArchitectureAPT(architecture)};if name==""||architecture==""{return "",nil,"",ErrInvalidEffect};spec:=name;if manager==PackageAPT&&architecture!="all"{spec+=":"+architecture}else if manager==PackageDNF&&architecture!="noarch"{spec+="."+architecture};removeSpec:=spec;if selection.ToVersion!=""{if manager==PackageAPT{spec+="="+selection.ToVersion}else{spec+="-"+selection.ToVersion}};if manager==PackageAPT{switch selection.Action{case PackageInstall:return "/usr/bin/apt-get",[]string{"--yes","install",spec},name,nil;case PackageRemove:return "/usr/bin/apt-get",[]string{"--yes","remove",removeSpec},name,nil;case PackageUpgrade:return "/usr/bin/apt-get",[]string{"--yes","--only-upgrade","install",spec},name,nil}}else{switch selection.Action{case PackageInstall:return "/usr/bin/dnf",[]string{"--assumeyes","install",spec},name,nil;case PackageRemove:return "/usr/bin/dnf",[]string{"--assumeyes","remove",removeSpec},name,nil;case PackageUpgrade:return "/usr/bin/dnf",[]string{"--assumeyes","upgrade",spec},name,nil}};return "",nil,"",ErrInvalidEffect}
func mapArchitectureAPT(value string)string{switch value{case "amd64","arm64","all":return value;case "x86_64":return "amd64";case "aarch64":return "arm64";case "noarch":return "all"};return ""}
func mapArchitectureDNF(value string)string{switch value{case "x86_64","aarch64","noarch":return value;case "amd64":return "x86_64";case "arm64":return "aarch64";case "all":return "noarch"};return ""}
func (executor *LinuxOperationsExecutor)verifyInstalledVersion(ctx context.Context,manager PackageManager,selection PackageSelection,catalog OperationsPackage)error{if selection.FromVersion==""||selection.Action==PackageInstall{return nil};if manager==PackageAPT{architecture:=mapArchitectureAPT(selection.Architecture.String());name:=catalog.APTName;if architecture!="all"{name+=":"+architecture};output,err:=executor.runner.Run(ctx,"/usr/bin/dpkg-query","--show","--showformat=${Version}",name);if err!=nil{return ErrConflict};if strings.TrimSpace(string(output))!=selection.FromVersion{return ErrConflict};return nil};name:=catalog.DNFName+"."+mapArchitectureDNF(selection.Architecture.String());output,err:=executor.runner.Run(ctx,"/usr/bin/rpm","--query","--queryformat=%{VERSION}-%{RELEASE}",name);if err!=nil{return ErrConflict};if strings.TrimSpace(string(output))!=selection.FromVersion{return ErrConflict};return nil}
func validPackageArchitecture(value string)bool{switch value{case "all","noarch","amd64","arm64","x86_64","aarch64":return true};return false}
func validPackageVersion(value string)bool{if value==""{return true};if len(value)>128||value[0]=='-'{return false};for _,character:=range value{if !(character>='a'&&character<='z'||character>='A'&&character<='Z'||character>='0'&&character<='9'||strings.ContainsRune(".+:~_-",character)){return false}};return true}

func (executor *LinuxOperationsExecutor) applyManagedService(ctx context.Context,effect ManagedServiceEffect)(linuxEffectResult,error){service:=effect.Service;if err:=executor.guardGeneration(KindManagedService,service.ID,service.Generation,service);err!=nil{return linuxEffectResult{},err};var path,unit string;var content []byte;var err error;switch service.KindName{case ManagedRedis:path="/etc/redis/cyberpanel-"+service.ID.String()+".conf";unit="redis-server@cyberpanel-"+service.ID.String()+".service";content,err=executor.renderRedis(ctx,service);case ManagedElasticsearch:path="/etc/elasticsearch/cyberpanel-"+service.ID.String()+".yml";unit="elasticsearch@cyberpanel-"+service.ID.String()+".service";content,err=executor.renderElasticsearch(ctx,service);default:return linuxEffectResult{},ErrInvalidEffect};if err!=nil{return linuxEffectResult{},err};snapshot,err:=executor.replaceManagedFile(path,content,0o600);if err!=nil{return linuxEffectResult{},err};snapshots:=[]operationsFileSnapshot{snapshot};if service.KindName==ManagedElasticsearch{heapPath:="/etc/elasticsearch/jvm.options.d/cyberpanel-"+service.ID.String()+".options";heapMiB:=service.Elasticsearch.HeapBytes/(1<<20);heap:=[]byte(fmt.Sprintf("-Xms%dm\n-Xmx%dm\n",heapMiB,heapMiB));heapSnapshot,heapErr:=executor.replaceManagedFile(heapPath,heap,0o600);if heapErr!=nil{return linuxEffectResult{Snapshots:snapshots,MutationObserved:true},heapErr};snapshots=append(snapshots,heapSnapshot);if storageErr:=executor.applyManagedStorage(ctx,service);storageErr!=nil{return linuxEffectResult{Snapshots:snapshots,MutationObserved:true},storageErr}};result:=linuxEffectResult{Snapshots:snapshots,MutationObserved:true};memoryMax:=uint64(0);if service.Redis!=nil{memoryMax=service.Redis.MemoryMaxBytes+service.Redis.MemoryMaxBytes/4}else{memoryMax=service.Elasticsearch.HeapBytes*2};if output,propertyErr:=executor.runner.Run(ctx,"/usr/bin/systemctl","set-property","--runtime",unit,"MemoryMax="+strconv.FormatUint(memoryMax,10));propertyErr!=nil{return result,fmt.Errorf("managed service memory limit: %w: %s",propertyErr,boundedText(output,2048))};action:="stop";if service.Desired==ServiceRunning{action="restart"};if output,runErr:=executor.runner.Run(ctx,"/usr/bin/systemctl",action,unit);runErr!=nil{return result,fmt.Errorf("managed service: %w: %s",runErr,boundedText(output,2048))};if err=executor.storeGeneration(KindManagedService,service.ID,service.Generation,mustActivationDigest(service));err!=nil{return result,err};return result,nil}

func (executor *LinuxOperationsExecutor)applyManagedStorage(ctx context.Context,service ManagedService)error{if service.Elasticsearch==nil{return ErrInvalidEffect};path:="/var/lib/cyberpanel/services/elasticsearch-"+service.ID.String();if err:=os.MkdirAll(path,0o700);err!=nil{return err};digest:=sha256.Sum256([]byte("cyberpanel:managed-storage:v1\x00"+service.ID.String()));projectID:=binary.BigEndian.Uint32(digest[:4])&0x3fffffff;if projectID<10000{projectID+=10000};volume,ok:=executor.volumes["cyberpanel"];if !ok{return ErrInvalidEffect};backend,err:=executor.quotaBackend(ctx,volume);if err!=nil{return err};if backend=="project"{assign:=fmt.Sprintf("project -s -p %s %d",path,projectID);if output,runErr:=executor.runner.Run(ctx,"/usr/sbin/xfs_quota","-x","-c",assign,volume.MountPath);runErr!=nil{return fmt.Errorf("managed storage project: %w: %s",runErr,boundedText(output,2048))};limit:=fmt.Sprintf("limit -p bsoft=%d bhard=%d %d",service.Elasticsearch.StorageBytes-service.Elasticsearch.StorageBytes/20,service.Elasticsearch.StorageBytes,projectID);if output,runErr:=executor.runner.Run(ctx,"/usr/sbin/xfs_quota","-x","-c",limit,volume.MountPath);runErr!=nil{return fmt.Errorf("managed storage quota: %w: %s",runErr,boundedText(output,2048))};return nil};if backend=="ext4-project"{if output,runErr:=executor.runner.Run(ctx,"/usr/bin/chattr","-p",strconv.FormatUint(uint64(projectID),10),"+P",path);runErr!=nil{return fmt.Errorf("managed storage project: %w: %s",runErr,boundedText(output,2048))};quota:=ProjectQuota{ProjectID:projectID,SpaceSoftBytes:service.Elasticsearch.StorageBytes-service.Elasticsearch.StorageBytes/20,SpaceHardBytes:service.Elasticsearch.StorageBytes,InodeSoft:1<<20,InodeHard:1<<20};return executor.applyProjectQuota(ctx,OperationsVolume{MountPath:volume.MountPath,QuotaBackend:"ext4-project"},quota)};return ErrInvalidEffect}

func (executor *LinuxOperationsExecutor) renderRedis(ctx context.Context,service ManagedService)([]byte,error){settings:=service.Redis;if settings==nil||executor.secrets==nil{return nil,ErrInvalidEffect};material,err:=executor.secrets.ManagedCredential(ctx,settings.CredentialSecretRef,service);if err!=nil{return nil,err};defer wipeOperationsBytes(material);secret:=strings.TrimSpace(string(material));if strings.ContainsAny(secret," \t\r\n\x00\""){return nil,ErrInvalidEffect};var buffer bytes.Buffer;fmt.Fprintf(&buffer,"# CyberPanel generation %d\nbind 127.0.0.1 ::1\nprotected-mode yes\nport 0\nunixsocket /run/redis/cyberpanel-%s.sock\nunixsocketperm 0660\nmaxmemory %d\nmaxclients %d\nmaxmemory-policy %s\nrequirepass %s\n",service.Generation,service.ID.String(),settings.MemoryMaxBytes,settings.MaxClients,settings.EvictionPolicy,secret);switch settings.Persistence{case RedisRDB:buffer.WriteString("save 900 1\nappendonly no\n");case RedisAOF:buffer.WriteString("save \"\"\nappendonly yes\n");case RedisRDBAOF:buffer.WriteString("save 900 1\nappendonly yes\n")};if settings.TLS{buffer.WriteString("tls-port 0\n# TLS is terminated by the managed local broker.\n")};return buffer.Bytes(),nil}
func (executor *LinuxOperationsExecutor) renderElasticsearch(ctx context.Context,service ManagedService)([]byte,error){settings:=service.Elasticsearch;if settings==nil||executor.secrets==nil{return nil,ErrInvalidEffect};material,err:=executor.secrets.ManagedCredential(ctx,settings.CredentialSecretRef,service);if err!=nil{return nil,err};wipeOperationsBytes(material);var buffer bytes.Buffer;fmt.Fprintf(&buffer,"# CyberPanel generation %d\ncluster.name: cyberpanel-%s\nnode.name: cyberpanel-%s\nnetwork.host: 127.0.0.1\ndiscovery.type: single-node\ncluster.max_shards_per_node: %d\nxpack.security.enabled: true\nxpack.security.http.ssl.enabled: %t\npath.data: /var/lib/cyberpanel/services/elasticsearch-%s\npath.repo: [/var/lib/cyberpanel/snapshots/%s]\n",service.Generation,service.ID.String(),service.ID.String(),settings.MaxShards,settings.TLS,service.ID.String(),settings.SnapshotRepositoryRef.String());return buffer.Bytes(),nil}

func parseKeyValues(content []byte)map[string]string{values:=map[string]string{};for _,line:=range strings.Split(string(content),"\n"){key,value,ok:=strings.Cut(line,"=");if ok{values[key]=value}};return values}
func parseKeyValuesSpace(content []byte)map[string]uint64{values:=map[string]uint64{};for _,line:=range strings.Split(string(content),"\n"){fields:=strings.Fields(line);if len(fields)==2{value,_:=strconv.ParseUint(fields[1],10,64);values[fields[0]]=value}};return values}
func (executor *LinuxOperationsExecutor)cgroupForScope(scope EnforcementScope)(string,error){entries,err:=os.ReadDir("/etc/cyberpanel/resource-profiles");if err!=nil{return "",err};for _,entry:=range entries{if entry.IsDir()||!strings.HasSuffix(entry.Name(),".json"){continue};content,readErr:=os.ReadFile(filepath.Join("/etc/cyberpanel/resource-profiles",entry.Name()));if readErr!=nil{continue};var profile ResourceProfile;if json.Unmarshal(content,&profile)==nil&&profile.Scope==scope{return filepath.Join("/sys/fs/cgroup","cyberpanel-"+profile.Cgroup.Binding.ScopeID.String()+".slice"),nil}};return "",ErrNotFound}
func normalizeOpaque(value string)string{value=strings.TrimSpace(value);var buffer strings.Builder;for _,character:=range value{if character>='a'&&character<='z'||character>='A'&&character<='Z'||character>='0'&&character<='9'||character=='-'||character=='_'||character=='.'{buffer.WriteRune(character)}else{buffer.WriteByte('-')}};result:=strings.Trim(buffer.String(),"-_.");if result==""{result="unknown"};if len(result)>128{result=result[:128]};return result}
func mustActivationDigest(value any)string{digest,_:=activationDigest(value);return digest}

func (executor *LinuxOperationsExecutor) rollbackExternal(ctx context.Context, request EffectRequest, snapshots []operationsFileSnapshot) error {
	switch request.Kind {
	case EffectFirewallPolicy:
		if request.FirewallPolicy.Policy.Backend == FirewallNFTables { return executor.rollbackSecurityLease(ctx, request.EffectID) }
		_, err := executor.runner.Run(ctx, "/usr/bin/firewall-cmd", "--reload"); return err
	case EffectSSHPolicy:
		return executor.rollbackSecurityLease(ctx, request.EffectID)
	case EffectWAFPolicy:
		if _, err := executor.validateWebConfiguration(ctx); err != nil { return err }; _, err := executor.runner.Run(ctx, "/usr/local/lsws/bin/lswsctrl", "reload"); return err
	case EffectResourceProfile:
		profile, ok := previousResourceProfile(snapshots); if !ok { return errors.New("resource profile has no rollback generation") }
		unit := "cyberpanel-"+profile.Cgroup.Binding.ScopeID.String()+".slice"; limits:=profile.Cgroup
		arguments:=[]string{"set-property","--runtime",unit,"CPUQuotaPerSecUSec="+strconv.FormatUint(limits.CPUQuotaMicros*1000000/limits.CPUPeriodMicros,10)+"us","MemoryHigh="+strconv.FormatUint(limits.MemoryHighBytes,10),"MemoryMax="+strconv.FormatUint(limits.MemoryMaxBytes,10),"MemorySwapMax="+strconv.FormatUint(limits.SwapMaxBytes,10),"TasksMax="+strconv.FormatUint(limits.TasksMax,10)}
		volume,ok:=executor.volumes[profile.Quota.VolumeRef.String()];if !ok{return ErrInvalidEffect};if limits.IOReadBytesPerSecond>0||limits.IOWriteBytesPerSecond>0{deviceOutput,deviceErr:=executor.runner.Run(ctx,"/usr/bin/findmnt","--noheadings","--output","SOURCE","--target",volume.MountPath);if deviceErr!=nil{return deviceErr};device:=strings.TrimSpace(string(deviceOutput));if !validBlockDevice(device){return ErrInvalidEffect};if limits.IOReadBytesPerSecond>0{arguments=append(arguments,"IOReadBandwidthMax="+device+" "+strconv.FormatUint(limits.IOReadBytesPerSecond,10))};if limits.IOWriteBytesPerSecond>0{arguments=append(arguments,"IOWriteBandwidthMax="+device+" "+strconv.FormatUint(limits.IOWriteBytesPerSecond,10))}};if _,err:=executor.runner.Run(ctx,"/usr/bin/systemctl",arguments...);err!=nil{return err};return executor.applyProjectQuota(ctx,volume,profile.Quota)
	case EffectServicePolicy:
		policy, ok := previousServicePolicy(snapshots); if !ok { return errors.New("service policy has no rollback generation") }; unit,unitErr:=executor.serviceUnit(ctx,policy.Service);if unitErr!=nil{return unitErr}; action:="stop";if policy.Desired==ServiceRunning{action="start"};_,err:=executor.runner.Run(ctx,"/usr/bin/systemctl",action,unit);return err
	case EffectManagedService:
		unit:="";service:=request.ManagedService.Service;if service.KindName==ManagedRedis{unit="redis-server@cyberpanel-"+service.ID.String()+".service"}else if service.KindName==ManagedElasticsearch{return errors.New("Elasticsearch storage quota rollback requires recovery")};if unit==""{return ErrInvalidEffect};_,err:=executor.runner.Run(ctx,"/usr/bin/systemctl","restart",unit);return err
	case EffectPutSSHKey, EffectDeleteSSHKey, EffectTransferReset:
		return nil
	case EffectTransferSample, EffectServiceDiagnose, EffectMetricsQuery, EffectLogQuery, EffectSSHLoginQuery, EffectSSHSessionQuery, EffectProcessInvestigate:
		return nil
	default:
		return errors.New("host effect cannot be automatically compensated")
	}
}

func previousResourceProfile(snapshots []operationsFileSnapshot)(ResourceProfile,bool){for _,snapshot:=range snapshots{if snapshot.Existed&&strings.Contains(snapshot.Path,"/resource-profiles/"){var value ResourceProfile;if json.Unmarshal(snapshot.Content,&value)==nil&&value.Validate()==nil{return value,true}}};return ResourceProfile{},false}
func previousServicePolicy(snapshots []operationsFileSnapshot)(ServicePolicy,bool){for _,snapshot:=range snapshots{if snapshot.Existed&&strings.Contains(snapshot.Path,"/service-policies/"){var value ServicePolicy;if json.Unmarshal(snapshot.Content,&value)==nil&&value.Validate()==nil{return value,true}}};return ServicePolicy{},false}
func snapshotWasAbsent(snapshots []operationsFileSnapshot,path string)bool{for _,snapshot:=range snapshots{if snapshot.Path==path{return !snapshot.Existed}};return true}
