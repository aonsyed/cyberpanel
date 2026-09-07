//go:build linux

package database

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type migrationRestoreState struct {
	Request MigrationRestoreRequest `json:"request"`
	Receipt MigrationRestoreReceipt `json:"receipt"`
}

// RestoreMigrationDatabase shares the root broker's durable resource authority
// and its mutex. A durable ambiguous marker precedes execution; it is never
// automatically replayed, even after daemon restart or a lost response.
func (executor *LinuxMariaDBExecutor) RestoreMigrationDatabase(ctx context.Context, request MigrationRestoreRequest) (MigrationRestoreReceipt,error) {
	if executor==nil || os.Geteuid()!=0 || request.validate()!=nil { return MigrationRestoreReceipt{},ErrUnauthorized }
	executor.mu.Lock(); defer executor.mu.Unlock()
	if request.Action=="discard" { return executor.discardMigrationRestore(request) }
	var target Database
	var principal DatabasePrincipal
	var grants GrantSet
	if err:=executor.readResource("databases",request.DatabaseID,&target); err!=nil { return MigrationRestoreReceipt{},err }
	if err:=executor.readResource("principals",request.PrincipalID,&principal); err!=nil { return MigrationRestoreReceipt{},err }
	if err:=executor.readResource("grants",request.GrantSetID,&grants); err!=nil { return MigrationRestoreReceipt{},err }
	if target.Generation!=1 || principal.Generation!=1 || grants.Generation!=1 { return MigrationRestoreReceipt{},ErrConflict }
	if target.Validate()!=nil || principal.Validate()!=nil || grants.Validate()!=nil || !strings.HasPrefix(target.ID.String(),"migdb-") || !strings.HasPrefix(principal.ID.String(),"migp-") || target.TenantID!=request.TenantID || target.SiteID!=request.SiteID || principal.TenantID!=target.TenantID || principal.SiteID!=target.SiteID || principal.InstanceID!=target.InstanceID || principal.HostScope!=HostScopeLoopback || principal.Disabled || grants.DatabaseID!=target.ID || grants.PrincipalID!=principal.ID || grants.InstanceID!=target.InstanceID || grants.TenantID!=target.TenantID || grants.SiteID!=target.SiteID { return MigrationRestoreReceipt{},ErrUnauthorized }
	instance,err:=executor.instance(target.InstanceID)
	if err!=nil || instance.Placement!=PlacementLocal { return MigrationRestoreReceipt{},ErrUnauthorized }
	root:=filepath.Join(mariaDBStateRoot,"migration-restores")
	if err=ensureRootDirectory(root,0700); err!=nil { return MigrationRestoreReceipt{},err }
	path:=filepath.Join(root,target.ID.String()+".sql")
	identity:=request; identity.Action="begin"; identity.Offset=0; identity.Data=nil
	var state migrationRestoreState
	err=executor.readResource("migration-restores",target.ID,&state)
	if errors.Is(err,ErrNotFound) {
		if request.Action!="begin" { return MigrationRestoreReceipt{},ErrNotFound }
		state=migrationRestoreState{Request:identity,Receipt:MigrationRestoreReceipt{ID:request.ID,InputDigest:request.InputDigest,State:"uploading",ObservedAt:executor.now().UTC()}}
		if err=executor.writeResource("migration-restores",target.ID,state); err!=nil { return MigrationRestoreReceipt{},err }
	} else if err!=nil { return MigrationRestoreReceipt{},err }
	left,_:=json.Marshal(identity); right,_:=json.Marshal(state.Request)
	if !bytes.Equal(left,right) { return MigrationRestoreReceipt{},ErrConflict }
	if state.Receipt.State=="ambiguous" || state.Receipt.State=="discarded" { return state.Receipt,nil }
	if state.Receipt.State=="applied" {
		proof,probeErr:=executor.probeMigrationRestore(ctx,target,principal)
		if probeErr!=nil { return MigrationRestoreReceipt{},probeErr }
		state.Receipt.ProofDigest=digestBytes(append([]byte(state.Receipt.Process.Digest),proof...))
		state.Receipt.ObservedAt=executor.now().UTC()
		return state.Receipt,nil
	}
	file,err:=os.OpenFile(path,os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW,0600)
	if err!=nil { return MigrationRestoreReceipt{},err }; defer file.Close()
	info,err:=file.Stat(); if err!=nil || !info.Mode().IsRegular() || info.Mode().Perm()!=0600 || info.Size()<0 || uint64(info.Size())>request.DumpBytes { return MigrationRestoreReceipt{},ErrInvalidResource }
	owner,ok:=info.Sys().(*syscall.Stat_t); if !ok || owner.Uid!=0 { return MigrationRestoreReceipt{},ErrUnauthorized }
	state.Receipt.Bytes=uint64(info.Size())
	if request.Action=="chunk" {
		if request.Offset<state.Receipt.Bytes {
			prior:=make([]byte,len(request.Data)); n,readErr:=file.ReadAt(prior,int64(request.Offset))
			if readErr!=nil || n!=len(prior) || !bytes.Equal(prior,request.Data) { return MigrationRestoreReceipt{},ErrConflict }
		} else {
			if request.Offset!=state.Receipt.Bytes { return MigrationRestoreReceipt{},ErrConflict }
			n,writeErr:=file.WriteAt(request.Data,int64(request.Offset)); if writeErr!=nil { return MigrationRestoreReceipt{},writeErr }; if n!=len(request.Data) { return MigrationRestoreReceipt{},io.ErrShortWrite }
			if err=file.Sync(); err!=nil { return MigrationRestoreReceipt{},err }; state.Receipt.Bytes+=uint64(n)
		}
	}
	state.Receipt.ObservedAt=executor.now().UTC()
	if request.Action!="apply" { return state.Receipt,nil }
	if state.Receipt.Bytes!=request.DumpBytes { return MigrationRestoreReceipt{},ErrConflict }
	hash:=sha256.New(); count,err:=io.Copy(hash,file)
	if err!=nil || uint64(count)!=request.DumpBytes || hex.EncodeToString(hash.Sum(nil))!=request.DumpDigest { return MigrationRestoreReceipt{},ErrTransferInvalid }
	// Validate the entire input before MariaDB sees the first statement.
	stream,err:=migrationSQLStream(file,request.SourceName,target)
	if err!=nil { return MigrationRestoreReceipt{},err }
	if _,err=io.Copy(io.Discard,stream); err!=nil { return MigrationRestoreReceipt{},err }
	stream,err=migrationSQLStream(file,request.SourceName,target)
	if err!=nil { return MigrationRestoreReceipt{},err }
	config,err:=executor.migrationTransferConfig(ctx,target,principal)
	if err!=nil { return MigrationRestoreReceipt{},err }; defer releaseTransferConfig(config)
	if err=validateTransferClientConfig(config,TransferJob{Direction:TransferImport},target.Name); err!=nil { return MigrationRestoreReceipt{},err }
	state.Receipt.State="ambiguous"
	if err=executor.writeResource("migration-restores",target.ID,state); err!=nil { return MigrationRestoreReceipt{},err }
	output,stderr:=newTransferLimitedBuffer(MaximumTransferStderrBytes),newTransferLimitedBuffer(MaximumTransferStderrBytes)
	command:=exec.CommandContext(ctx,mariaDBClientBinary,migrationClientArguments(config.Path,target.Name)...)
	command.Env=transferEnvironment(); command.Stdin=stream; command.Stdout=output; command.Stderr=stderr
	runErr:=command.Run()
	if runErr!=nil || stream.Error()!=nil { return state.Receipt,nil }
	proof,err:=executor.probeMigrationRestore(ctx,target,principal)
	if err!=nil { return state.Receipt,nil }
	process:=SealTransferProcessReceipt(TransferProcessReceipt{ExitCode:0,BytesProcessed:request.DumpBytes,InputVerified:true,StderrDigest:stderr.Digest(),StderrBytes:stderr.Size(),StderrTruncated:stderr.Truncated(),CompletedAt:executor.now().UTC()})
	state.Receipt.State="applied"; state.Receipt.Process=&process
	state.Receipt.ProofDigest=digestBytes(append([]byte(process.Digest),proof...)); state.Receipt.ObservedAt=executor.now().UTC()
	if err=executor.writeResource("migration-restores",target.ID,state); err!=nil { return MigrationRestoreReceipt{},err }
	// The verified migration chunk remains the recovery source. The privileged
	// duplicate is no longer needed after the durable receipt exists.
	if err=os.Remove(path); err!=nil && !errors.Is(err,os.ErrNotExist) { return MigrationRestoreReceipt{},err }
	return state.Receipt,nil
}

func (executor *LinuxMariaDBExecutor) discardMigrationRestore(request MigrationRestoreRequest)(MigrationRestoreReceipt,error) {
	var state migrationRestoreState
	if err:=executor.readResource("migration-restores",request.DatabaseID,&state); err!=nil { return MigrationRestoreReceipt{},err }
	identity:=request; identity.Action="begin"; identity.Offset=0; identity.Data=nil
	left,_:=json.Marshal(identity); right,_:=json.Marshal(state.Request)
	if !bytes.Equal(left,right) { return MigrationRestoreReceipt{},ErrUnauthorized }
	// Persist the terminal fence before unlinking. A lost response can only
	// repeat this exact cleanup, never return the target to the apply path.
	state.Receipt.State="discarded"; state.Receipt.Process=nil; state.Receipt.ProofDigest=""; state.Receipt.ObservedAt=executor.now().UTC()
	if err:=executor.writeResource("migration-restores",request.DatabaseID,state); err!=nil { return MigrationRestoreReceipt{},err }
	path:=filepath.Join(mariaDBStateRoot,"migration-restores",request.DatabaseID.String()+".sql")
	if err:=os.Remove(path); err!=nil && !errors.Is(err,os.ErrNotExist) { return MigrationRestoreReceipt{},err }
	return state.Receipt,nil
}

// Only the exact canonical preamble may carry a source database name. It is
// consumed, not executed; all remaining statements use the scoped parser.
func migrationSQLStream(file *os.File,source SQLIdentifier,target Database)(*constrainedTransferSQLReader,error) {
	if _,err:=file.Seek(0,io.SeekStart); err!=nil { return nil,err }
	reader:=bufio.NewReaderSize(file,64<<10)
	header,err:=reader.ReadString('\n'); if err!=nil { return nil,err }
	switch header {
	case transferSQLMagic:
	case "-- CyberPanel canonical logical dump v1\n":
		expected:=[]string{"SET FOREIGN_KEY_CHECKS=0;\n","SET UNIQUE_CHECKS=0;\n","CREATE DATABASE IF NOT EXISTS `"+source.String()+"` CHARACTER SET "+target.Charset.String()+" COLLATE "+target.Collation.String()+";\n","USE `"+source.String()+"`;\n"}
		for _,line:=range expected { actual,readErr:=reader.ReadString('\n'); if readErr!=nil || actual!=line { return nil,ErrTransferUnsafeSQL } }
		reader=bufio.NewReaderSize(io.MultiReader(strings.NewReader("SET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\n"),reader),64<<10)
	default: return nil,ErrTransferUnsafeSQL
	}
	return newConstrainedTransferSQLReader(reader,nil),nil
}

func migrationClientArguments(path string,name SQLIdentifier) []string {
	return []string{"--defaults-extra-file="+path,"--protocol=socket","--socket="+mariaDBSocket,"--skip-auto-rehash","--binary-mode=1","--batch","--skip-column-names","--database="+name.String()}
}

func (executor *LinuxMariaDBExecutor) migrationTransferConfig(ctx context.Context,target Database,principal DatabasePrincipal)(TransferClientConfigDescriptor,error) {
	if err:=ensureRootDirectory(strings.TrimSuffix(transferConfigDirectory,"/"),0700); err!=nil { return TransferClientConfigDescriptor{},err }
	password,err:=executor.secrets.PrincipalPassword(ctx,principal.CredentialSecretRef,principal.ID,target.TenantID.String(),target.SiteID.String())
	if err!=nil { return TransferClientConfigDescriptor{},err }; defer wipeBytes(password)
	value,err:=optionFileValue(password); if err!=nil { return TransferClientConfigDescriptor{},err }
	file,err:=os.CreateTemp(transferConfigDirectory,"migration-*.cnf"); if err!=nil { return TransferClientConfigDescriptor{},err }
	path:=file.Name(); release:=func()error{return os.Remove(path)}
	payload:=[]byte("[client]\nuser="+principal.Name.String()+"\npassword=\""+value+"\"\nlocal-infile=0\n")
	_,err=file.Write(payload); wipeBytes(payload); if err==nil { err=file.Sync() }; closeErr:=file.Close(); if err==nil { err=closeErr }
	if err!=nil { _=release(); return TransferClientConfigDescriptor{},err }
	return TransferClientConfigDescriptor{Path:path,Token:principal.ID,Database:target.Name,Direction:TransferImport,Release:release},nil
}

func (executor *LinuxMariaDBExecutor) probeMigrationRestore(ctx context.Context,target Database,principal DatabasePrincipal)([]byte,error) {
	config,err:=executor.migrationTransferConfig(ctx,target,principal); if err!=nil { return nil,err }; defer releaseTransferConfig(config)
	command:=exec.CommandContext(ctx,mariaDBClientBinary,migrationClientArguments(config.Path,target.Name)...)
	command.Env=transferEnvironment()
	command.Stdin=strings.NewReader("SELECT 1;\nSELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME;\n")
	var output bytes.Buffer
	command.Stdout=newTransferBoundedWriter(&output,4<<20,nil); command.Stderr=newTransferLimitedBuffer(MaximumTransferStderrBytes)
	if err=command.Run(); err!=nil { return nil,err }
	if !strings.HasPrefix(output.String(),"1\n") { return nil,ErrInvalidReceipt }
	return output.Bytes(),nil
}

var _ MigrationRestoreExecutor=(*LinuxMariaDBExecutor)(nil)
