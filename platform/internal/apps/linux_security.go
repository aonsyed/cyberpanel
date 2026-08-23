//go:build linux

package apps

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const linuxSecurityRulesVersion = "cyberpanel-local-2026.08.1"
const linuxSecurityEngineVersion = "archive-stream-v1"

type linuxSecuritySignature struct{ID,Reason string;Severity FindingSeverity;Needle []byte}

var linuxSecuritySignatures=[]linuxSecuritySignature{
	{"eicar-test-file","EICAR anti-malware test signature detected",SeverityCritical,[]byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")},
	{"php-eval-base64","Obfuscated PHP eval/base64 execution chain detected",SeverityCritical,[]byte("eval(base64_decode(")},
	{"php-assert-base64","Obfuscated PHP assert/base64 execution chain detected",SeverityHigh,[]byte("assert(base64_decode(")},
	{"php-gzinflate-base64","Obfuscated PHP compressed payload execution chain detected",SeverityHigh,[]byte("gzinflate(base64_decode(")},
}

func(runtime *LinuxApplicationRuntime)ID()string{return "cyberpanel-local"}
func(runtime *LinuxApplicationRuntime)Kind()ScannerKind{return ScannerLocal}

func(runtime *LinuxApplicationRuntime)Scan(ctx context.Context,request ScanRequest,_ *DataEgressConsent)(ScanResult,error){
	if runtime==nil||ctx==nil||request.Scope.Validate()!=nil||request.InstallationID==""||request.RunID==""||request.Snapshot.ID==""||request.Snapshot.InstallationID!=request.InstallationID||request.Snapshot.Purpose!=SnapshotScan||request.Snapshot.ManifestDigest==""||request.Budget.Validate()!=nil{return ScanResult{},ErrInvalid}
	if _,err:=runtime.resolve(ctx,request.Scope);err!=nil{return ScanResult{},err};snapshot,err:=loadLinuxApplicationSnapshot(request.Snapshot.ID);if err!=nil{return ScanResult{},err};if snapshot.ManifestDigest!=request.Snapshot.ManifestDigest||snapshot.InstallationID!=request.InstallationID{return ScanResult{},ErrIntegrity}
	if snapshot.Size>request.Budget.MaximumBytes{return ScanResult{},ErrPolicyDenied};archivePath:=filepath.Join(linuxApplicationSnapshotRoot,string(snapshot.ID),"snapshot.tar.gz");file,err:=os.Open(archivePath);if err!=nil{return ScanResult{},err};defer file.Close();zip,err:=gzip.NewReader(file);if err!=nil{return ScanResult{},ErrIntegrity};defer zip.Close();reader:=tar.NewReader(zip)
	allowed:=map[string]bool{};for _,path:=range request.CustomPaths{if path.IsRoot(){return ScanResult{},ErrInvalid};allowed[path.String()]=true};now:=time.Now().UTC();findings:=[]Finding{};var filesScanned,bytesScanned uint64
	for { if err=ctx.Err();err!=nil{return ScanResult{},err};header,nextErr:=reader.Next();if errors.Is(nextErr,io.EOF){break};if nextErr!=nil{return ScanResult{},ErrIntegrity};name:=strings.TrimPrefix(header.Name,"./");path,parseErr:=ParseRelativePath(name);if parseErr!=nil||path.IsRoot(){if header.FileInfo().IsDir(){continue};return ScanResult{},ErrIntegrity};switch header.Typeflag{case tar.TypeDir:continue;case tar.TypeReg,tar.TypeRegA:default:continue};if header.Size<0{return ScanResult{},ErrIntegrity};if len(allowed)>0&&!allowed[path.String()]{continue};size:=uint64(header.Size);if filesScanned==request.Budget.MaximumFiles||size>request.Budget.MaximumExpandedBytes-bytesScanned{return ScanResult{},ErrPolicyDenied};filesScanned++;bytesScanned+=size
		hash:=sha256.New();matched:=map[int]bool{};tail:=[]byte{};remaining:=header.Size;buffer:=make([]byte,64<<10);for remaining>0{count:=int64(len(buffer));if remaining<count{count=remaining};read,readErr:=io.ReadFull(reader,buffer[:count]);if readErr!=nil{return ScanResult{},ErrIntegrity};chunk:=buffer[:read];_,_=hash.Write(chunk);window:=append(append([]byte(nil),tail...),bytes.ToLower(chunk)...);for index,signature:=range linuxSecuritySignatures{if bytes.Contains(window,bytes.ToLower(signature.Needle)){matched[index]=true}};maximum:=0;for _,signature:=range linuxSecuritySignatures{if len(signature.Needle)>maximum{maximum=len(signature.Needle)}};if len(window)>=maximum-1{tail=append(tail[:0],window[len(window)-(maximum-1):]...)}else{tail=append(tail[:0],window...)};remaining-=int64(read)}
		contentDigest:=hex.EncodeToString(hash.Sum(nil));indexes:=make([]int,0,len(matched));for index:=range matched{indexes=append(indexes,index)};sort.Ints(indexes);for _,index:=range indexes{signature:=linuxSecuritySignatures[index];evidence:=securityDigest(string(snapshot.ID),path.String(),signature.ID,contentDigest,snapshot.ManifestDigest);identifier:=FindingID("finding-"+securityDigest(string(request.InstallationID),path.String(),signature.ID)[:48]);findings=append(findings,Finding{ID:identifier,ScanRunID:request.RunID,TenantID:request.Scope.TenantID,SiteID:request.Scope.SiteID,InstallationID:request.InstallationID,Path:path,Resource:"application-file",ContentDigest:contentDigest,SignatureID:signature.ID,Reason:signature.Reason,Severity:signature.Severity,Confidence:1,EvidenceRef:"snapshot:"+string(snapshot.ID)+":"+path.String(),EvidenceDigest:evidence,Scanner:runtime.ID(),ScannerVersion:linuxSecurityRulesVersion,State:FindingOpen,FirstSeenAt:now,LastSeenAt:now,Generation:1});if len(findings)>10000{return ScanResult{},ErrPolicyDenied}}
	}
	result:=ScanResult{RunID:request.RunID,Findings:findings,FilesScanned:filesScanned,BytesScanned:bytesScanned,CompletedAt:now};encoded,_:=json.Marshal(struct{Run ScanRunID `json:"run"`;Snapshot string `json:"snapshot"`;Files uint64 `json:"files"`;Bytes uint64 `json:"bytes"`;Findings []Finding `json:"findings"`}{request.RunID,snapshot.ManifestDigest,filesScanned,bytesScanned,findings});result.ResultDigest=linuxApplicationDigest(encoded);return result,nil
}

func securityDigest(values ...string)string{hash:=sha256.New();for _,value:=range values{_,_=hash.Write([]byte(value));_,_=hash.Write([]byte{0})};return hex.EncodeToString(hash.Sum(nil))}

type linuxRemediationManifest struct{Plan RemediationPlan `json:"plan"`;Moved []string `json:"moved"`;CreatedAt time.Time `json:"created_at"`}

func(runtime *LinuxApplicationRuntime)ApplyRemediation(ctx context.Context,execution RemediationExecution)(ExecutionReceipt,error){
	if runtime==nil||ctx==nil||execution.Plan.Validate()!=nil||execution.Plan.Action!=RemediationQuarantine||execution.Plan.InstallationID!=execution.InstallationID||execution.Plan.TenantID!=execution.Scope.TenantID||execution.Plan.SiteID!=execution.Scope.SiteID{return ExecutionReceipt{},ErrUnsupported};scope,err:=runtime.resolve(ctx,execution.Scope);if err!=nil{return ExecutionReceipt{},err};generationRoot:=filepath.Join(linuxApplicationSitesRoot,scope.binding.SiteKey,"roots","g"+strconv.FormatUint(scope.binding.Generation,10));quarantine:=filepath.Join(generationRoot,"security-quarantine",string(execution.Plan.ID));if !strings.HasPrefix(quarantine,generationRoot+string(os.PathSeparator)){return ExecutionReceipt{},ErrPolicyDenied};manifestPath:=filepath.Join(quarantine,"manifest.json");if _,statErr:=os.Lstat(manifestPath);statErr==nil{return receiptForApplication("security_remediation_apply",execution.Scope,execution.InstallationID,execution,execution.Plan.ApprovalDigest,"",execution.SnapshotID,false),nil}else if !errors.Is(statErr,os.ErrNotExist){return ExecutionReceipt{},statErr};if err=os.MkdirAll(quarantine,0700);err!=nil{return ExecutionReceipt{},err}
	paths:=make([]string,0,len(execution.Plan.ExpectedDigests));for path:=range execution.Plan.ExpectedDigests{paths=append(paths,path)};sort.Strings(paths);moved:=[]string{};rollback:=func(){for index:=len(moved)-1;index>=0;index--{source:=filepath.Join(quarantine,filepath.FromSlash(moved[index]));target:=filepath.Join(scope.root,filepath.FromSlash(moved[index]));if _,targetErr:=os.Lstat(target);errors.Is(targetErr,os.ErrNotExist){_ = os.MkdirAll(filepath.Dir(target),0750);_ = os.Rename(source,target)}}}
	for _,name:=range paths{path,parseErr:=ParseRelativePath(name);if parseErr!=nil||path.IsRoot(){rollback();return ExecutionReceipt{},ErrInvalid};source,secureErr:=secureLinuxApplicationRegular(scope.root,path);if secureErr!=nil{rollback();return ExecutionReceipt{},secureErr};info,statErr:=os.Lstat(source);if statErr!=nil||!info.Mode().IsRegular(){rollback();if statErr!=nil{return ExecutionReceipt{},statErr};return ExecutionReceipt{},ErrPolicyDenied};digest,digestErr:=digestLinuxApplicationFile(source,uint64(info.Size()));if digestErr!=nil||digest!=execution.Plan.ExpectedDigests[name]{rollback();if digestErr!=nil{return ExecutionReceipt{},digestErr};return ExecutionReceipt{},ErrConflict};target:=filepath.Join(quarantine,filepath.FromSlash(name));if err=os.MkdirAll(filepath.Dir(target),0700);err!=nil{rollback();return ExecutionReceipt{},err};if err=os.Rename(source,target);err!=nil{rollback();return ExecutionReceipt{},err};moved=append(moved,name);movedInfo,statErr:=os.Lstat(target);if statErr!=nil||!movedInfo.Mode().IsRegular(){rollback();return ExecutionReceipt{},ErrIntegrity};movedDigest,digestErr:=digestLinuxApplicationFile(target,uint64(movedInfo.Size()));if digestErr!=nil||movedDigest!=digest{rollback();return ExecutionReceipt{},ErrIntegrity}}
	manifest:=linuxRemediationManifest{execution.Plan,moved,time.Now().UTC()};encoded,err:=json.Marshal(manifest);if err!=nil{rollback();return ExecutionReceipt{},err};if err=os.WriteFile(manifestPath,encoded,0600);err!=nil{rollback();return ExecutionReceipt{},err};return receiptForApplication("security_remediation_apply",execution.Scope,execution.InstallationID,execution,manifest,"",execution.SnapshotID,false),nil
}

func(runtime *LinuxApplicationRuntime)RollbackRemediation(ctx context.Context,execution RemediationExecution)(ExecutionReceipt,error){
	if runtime==nil||ctx==nil||execution.Plan.ID==""{return ExecutionReceipt{},ErrInvalid};scope,err:=runtime.resolve(ctx,execution.Scope);if err!=nil{return ExecutionReceipt{},err};generationRoot:=filepath.Join(linuxApplicationSitesRoot,scope.binding.SiteKey,"roots","g"+strconv.FormatUint(scope.binding.Generation,10));quarantine:=filepath.Join(generationRoot,"security-quarantine",string(execution.Plan.ID));encoded,err:=os.ReadFile(filepath.Join(quarantine,"manifest.json"));if err!=nil{return ExecutionReceipt{},err};var manifest linuxRemediationManifest;if json.Unmarshal(encoded,&manifest)!=nil||manifest.Plan.ID!=execution.Plan.ID||manifest.Plan.ApprovalDigest!=execution.Plan.ApprovalDigest{return ExecutionReceipt{},ErrIntegrity};for index:=len(manifest.Moved)-1;index>=0;index--{name:=manifest.Moved[index];path,parseErr:=ParseRelativePath(name);if parseErr!=nil||path.IsRoot(){return ExecutionReceipt{},ErrIntegrity};source:=filepath.Join(quarantine,filepath.FromSlash(name));target:=filepath.Join(scope.root,filepath.FromSlash(name));if _,targetErr:=os.Lstat(target);targetErr==nil{return ExecutionReceipt{},ErrConflict}else if !errors.Is(targetErr,os.ErrNotExist){return ExecutionReceipt{},targetErr};if err=os.MkdirAll(filepath.Dir(target),0750);err!=nil{return ExecutionReceipt{},err};if err=os.Rename(source,target);err!=nil{return ExecutionReceipt{},err}};if err=os.RemoveAll(quarantine);err!=nil{return ExecutionReceipt{},err};return receiptForApplication("security_remediation_rollback",execution.Scope,execution.InstallationID,execution,"rolled_back","",execution.SnapshotID,false),nil
}

func secureLinuxApplicationRegular(root string,path RelativePath)(string,error){current:=root;segments:=strings.Split(path.String(),"/");for index,segment:=range segments{current=filepath.Join(current,segment);info,err:=os.Lstat(current);if err!=nil{return "",err};if info.Mode()&os.ModeSymlink!=0{return "",ErrPolicyDenied};if index<len(segments)-1&&!info.IsDir(){return "",ErrPolicyDenied}};clean:=filepath.Clean(current);if !strings.HasPrefix(clean,root+string(os.PathSeparator)){return "",fmt.Errorf("%w: remediation path",ErrPolicyDenied)};return clean,nil}
