//go:build linux

package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

type replicationSQLInput struct{
	Binding ha.StaticReplicationBinding
	Credential MariaDBReplicationCredential
	Checkpoint ha.ReplicationCheckpoint
	StopExisting bool
}

func replicationPeer(binding ha.StaticReplicationBinding)(netip.Addr,error){
	address,err:=netip.ParseAddrPort(binding.PeerAddress)
	if err!=nil||address.Port()!=3306||!address.Addr().IsPrivate()||address.Addr().Is4In6()||address.String()!=binding.PeerAddress||binding.TLSCAPath!="/etc/cyberpanel/ha/replication-ca.pem"||!validSHA256(binding.PeerSPKI){return netip.Addr{},ErrUnauthorized}
	for _,text:=range binding.PeerCIDRs{prefix,parseErr:=netip.ParsePrefix(text);if parseErr==nil&&prefix==prefix.Masked()&&prefix.Addr().IsPrivate()&&prefix.Contains(address.Addr()){return address.Addr(),nil}}
	return netip.Addr{},ErrUnauthorized
}

func buildReplicationStatement(kind mariaDBStatement,values ...any)(string,error){
	if kind==sqlObserveReplication{if len(values)!=0{return "",ErrInvalidCommand};return "SELECT @@server_id AS cp_server_id,@@read_only AS cp_read_only,@@gtid_binlog_pos AS cp_binlog_pos,@@gtid_slave_pos AS cp_slave_pos,@@gtid_current_pos AS cp_current_pos,@@gtid_strict_mode AS cp_strict_mode;\nSHOW SLAVE STATUS;\n",nil}
	value,ok:=oneValue[replicationSQLInput](values);if !ok||value.Credential.Validate()!=nil{return "",ErrInvalidCommand}
	ip,err:=replicationPeer(value.Binding);if err!=nil{return "",err}
	user,host:=value.Credential.Username.String(),ip.String();account:="'"+user+"'@'"+host+"'"
	switch kind{
	case sqlObserveReplicationPrincipal:
		return "SELECT 'ACCOUNT',plugin,ssl_type,authentication_string FROM mysql.user WHERE User='"+user+"' AND Host='"+host+"';\nSELECT 'PRIV',PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(CHAR(39),'"+user+"',CHAR(39),'@',CHAR(39),'"+host+"',CHAR(39)) ORDER BY PRIVILEGE_TYPE;\nSELECT 'EXTRA',(SELECT COUNT(*) FROM mysql.db WHERE User='"+user+"' AND Host='"+host+"')+(SELECT COUNT(*) FROM mysql.tables_priv WHERE User='"+user+"' AND Host='"+host+"')+(SELECT COUNT(*) FROM mysql.columns_priv WHERE User='"+user+"' AND Host='"+host+"')+(SELECT COUNT(*) FROM mysql.procs_priv WHERE User='"+user+"' AND Host='"+host+"');\n",nil
	case sqlCreateReplicationPrincipal:
		return "CREATE USER "+account+" IDENTIFIED VIA mysql_native_password USING '"+nativePasswordHash(value.Credential.Password)+"' REQUIRE SSL;\nGRANT REPLICATION SLAVE ON *.* TO "+account+";\n",nil
	case sqlConfigureReplication:
		if value.Binding.LocalRole!="target"{return "",ErrUnauthorized}
		// Password alphabet is fixed by the credential schema. No SQL quoting
		// escape mode or caller-provided command is involved.
		stop:="";if value.StopExisting{stop="STOP SLAVE;\n"}
		return stop+"CHANGE MASTER TO MASTER_HOST='"+host+"',MASTER_PORT=3306,MASTER_USER='"+user+"',MASTER_PASSWORD='"+string(value.Credential.Password)+"',MASTER_USE_GTID=slave_pos,MASTER_SSL=1,MASTER_SSL_CA='/etc/cyberpanel/ha/replication-ca.pem',MASTER_SSL_VERIFY_SERVER_CERT=1;\nSTART SLAVE;\n",nil
	case sqlWaitReplication:
		if _,_,_,err:=singleDomainGTID(value.Checkpoint.Position);err!=nil{return "",err}
		return "SELECT MASTER_GTID_WAIT('"+value.Checkpoint.Position+"',20);\n",nil
	default:return "",ErrInvalidCommand
	}
}

type replicationPrincipalJournal struct{ChannelID ha.ChannelID;Epoch uint64;PeerAddress string;Username string;CredentialDigest string;State string}

func(executor *LinuxMariaDBExecutor)ensureReplicationPrincipal(ctx context.Context,connection *mariaDBConnection,binding ha.StaticReplicationBinding,credential MariaDBReplicationCredential)error{
	if binding.LocalRole!="source"{return ErrUnauthorized}
	input:=replicationSQLInput{Binding:binding,Credential:credential}
	output,err:=connection.query(ctx,sqlObserveReplicationPrincipal,input);if err!=nil{return err};defer wipeBytes(output)
	name:="ha-repl-user-"+digestBytes([]byte(binding.ChannelID))[:32]+".json"
	want:=replicationPrincipalJournal{ChannelID:binding.ChannelID,Epoch:credential.AuthorityEpoch,PeerAddress:binding.PeerAddress,Username:credential.Username.String(),CredentialDigest:digestBytes(credential.Password),State:"prepared"}
	var existing replicationPrincipalJournal
	loadErr:=executor.readNamed("effects",name,&existing)
	if loadErr==nil{actual:=existing;actual.State="prepared";left,_:=json.Marshal(actual);right,_:=json.Marshal(want);if !bytes.Equal(left,right){return ErrIdempotency}}else if !errors.Is(loadErr,ErrNotFound){return loadErr}
	accountExists:=strings.HasPrefix(string(output),"ACCOUNT\t")
	if accountExists{
		if errors.Is(loadErr,ErrNotFound)||!replicationPrincipalMatches(output,credential){return ErrUnauthorized}
		want.State="applied";return executor.writeNamed("effects",name,want)
	}
	if loadErr==nil&&existing.State=="applied"{return ErrAmbiguous}
	if err=executor.writeNamed("effects",name,want);err!=nil{return err}
	if _,err=connection.query(ctx,sqlCreateReplicationPrincipal,input);err!=nil{return ErrAmbiguous}
	observed,err:=connection.query(ctx,sqlObserveReplicationPrincipal,input);if err!=nil{return ErrAmbiguous};defer wipeBytes(observed)
	if !replicationPrincipalMatches(observed,credential){return ErrAmbiguous}
	want.State="applied";return executor.writeNamed("effects",name,want)
}

func replicationPrincipalMatches(output []byte,credential MariaDBReplicationCredential)bool{
	account,privilege,extra:=false,false,false
	for _,line:=range strings.Split(strings.TrimSpace(string(output)),"\n"){
		switch line{
		case "ACCOUNT\tmysql_native_password\tANY\t"+nativePasswordHash(credential.Password):if account{return false};account=true
		case "PRIV\tREPLICATION SLAVE\tNO":if privilege{return false};privilege=true
		case "PRIV\tUSAGE\tNO":
		case "EXTRA\t0":if extra{return false};extra=true
		default:return false
		}
	}
	return account&&privilege&&extra
}

// MariaDB negotiates TLS after its greeting, not on the first TCP byte. This
// fixed SSLRequest does no authentication and validates the admitted IP, CA
// chain and certificate SPKI before configuring the replica's network client.
func verifyReplicationPeerTLS(ctx context.Context,binding ha.StaticReplicationBinding)error{
	ip,err:=replicationPeer(binding);if err!=nil{return err}
	info,err:=os.Lstat(binding.TLSCAPath);if err!=nil{return err};owner,ok:=info.Sys().(*syscall.Stat_t)
	if !ok||owner.Uid!=0||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0022!=0||info.Size()<=0||info.Size()>1<<20{return ErrUnauthorized}
	ca,err:=os.ReadFile(binding.TLSCAPath);if err!=nil{return err};pool:=x509.NewCertPool();if !pool.AppendCertsFromPEM(ca){return ErrUnauthorized}
	bounded,cancel:=context.WithTimeout(ctx,8*time.Second);defer cancel()
	connection,err:=(&net.Dialer{}).DialContext(bounded,"tcp",binding.PeerAddress);if err!=nil{return err};defer connection.Close()
	deadline,_:=bounded.Deadline();_=connection.SetDeadline(deadline)
	var header [4]byte;if _,err=io.ReadFull(connection,header[:]);err!=nil{return err}
	length:=int(header[0])|int(header[1])<<8|int(header[2])<<16;if length<32||length>64<<10||header[3]!=0{return ErrInvalidResource}
	greeting:=make([]byte,length);if _,err=io.ReadFull(connection,greeting);err!=nil{return err};if greeting[0]!=10{return ErrInvalidResource}
	request:=make([]byte,36);request[0]=32;request[3]=1;binary.LittleEndian.PutUint32(request[4:8],1|4|0x200|0x800|0x2000|0x8000);binary.LittleEndian.PutUint32(request[8:12],1<<20);request[12]=33
	if err=writeDatabaseBrokerBytes(connection,request);err!=nil{return err}
	tlsConnection:=tls.Client(connection,&tls.Config{MinVersion:tls.VersionTLS12,RootCAs:pool,ServerName:ip.String(),VerifyConnection:func(state tls.ConnectionState)error{if len(state.PeerCertificates)==0{return ErrUnauthorized};digest:=sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo);if hex.EncodeToString(digest[:])!=binding.PeerSPKI{return ErrUnauthorized};return nil}})
	return tlsConnection.HandshakeContext(bounded)
}

type replicaObservation struct{ServerID uint64;Binlog,Slave,Current string;Fields map[string]string;Proof string}

func observeReplica(ctx context.Context,connection *mariaDBConnection)(replicaObservation,error){
	output,err:=connection.query(ctx,sqlObserveReplication);if err!=nil{return replicaObservation{},err}
	lines:=strings.Split(strings.TrimSpace(string(output)),"\n");if len(lines)<1{return replicaObservation{},ErrInvalidResource}
	result:=replicaObservation{Fields:map[string]string{},Proof:digestBytes(output)}
	rows:=0
	for _,line:=range lines{trimmed:=strings.TrimSpace(line);if strings.HasPrefix(trimmed,"***"){rows++;if rows>2{return replicaObservation{},ErrUnauthorized};continue};key,value,ok:=strings.Cut(trimmed,":");if !ok{return replicaObservation{},ErrInvalidResource};if _,duplicate:=result.Fields[key];duplicate{return replicaObservation{},ErrInvalidResource};result.Fields[key]=strings.TrimSpace(value)}
	if rows==0||result.Fields["cp_read_only"]!="1"||result.Fields["cp_strict_mode"]!="1"{return replicaObservation{},ErrUnauthorized}
	serverID,err:=strconv.ParseUint(result.Fields["cp_server_id"],10,32);if err!=nil||serverID==0{return replicaObservation{},ErrInvalidResource}
	result.ServerID=serverID;result.Binlog=result.Fields["cp_binlog_pos"];result.Slave=result.Fields["cp_slave_pos"];result.Current=result.Fields["cp_current_pos"]
	for _,key:=range []string{"cp_server_id","cp_read_only","cp_binlog_pos","cp_slave_pos","cp_current_pos","cp_strict_mode"}{delete(result.Fields,key)}
	return result,nil
}

func replicaCompatible(observed replicaObservation,checkpoint ha.ReplicationCheckpoint)bool{
	domain,origin,frontier,err:=singleDomainGTID(checkpoint.Position);if err!=nil||observed.ServerID==origin{return false}
	// Initial physical/logical seeding and domain selection are explicit
	// prerequisites. Never manufacture gtid_slave_pos or reset local history.
	if observed.Slave==""||observed.Current==""{return false}
	for _,position:=range []string{observed.Slave,observed.Current,observed.Binlog}{if position==""{continue};d,o,s,parseErr:=singleDomainGTID(position);if parseErr!=nil||d!=domain||o!=origin||s>frontier{return false}}
	_,_,slave,_:=singleDomainGTID(observed.Slave);_,_,current,_:=singleDomainGTID(observed.Current)
	return slave==current
}

type localReplicaJournal struct{Channel ha.ReplicationChannel;Checkpoint ha.ReplicationCheckpoint;Epoch uint64;DeploymentDigest string;FenceToken uint64;State string;Receipt ha.ReplicationReceipt}

func(executor *LinuxMariaDBExecutor)replicationFence()(localMariaDBHAReceipt,error){
	var fence localMariaDBHAReceipt
	if err:=executor.readNamed("effects","ha-fence-cursor.json",&fence);err!=nil{return fence,err}
	if fence.ClusterID!="mariadb-local"||fence.NodeID!="local"||fence.FencingToken==0||!fence.ReadOnly||!validSHA256(fence.ProofDigest)||fence.AppliedAt.IsZero()||(fence.Action!=MariaDBHAFreeze&&fence.Action!=MariaDBHADemote){return fence,ha.ErrFenceRequired}
	return fence,nil
}

func(executor *LinuxMariaDBExecutor)CatchUpReplica(ctx context.Context,channel ha.ReplicationChannel,checkpoint ha.ReplicationCheckpoint)(ha.ReplicationReceipt,error){
	if executor==nil||ctx==nil||!validMariaDBReplicationChannel(channel){return ha.ReplicationReceipt{},ErrInvalidCommand}
	executor.mu.Lock();defer executor.mu.Unlock()
	binding,node,epoch,err:=executor.replicationBinding(ctx,channel.ID);if err!=nil||!bindingMatchesChannel(binding,node,channel,"target"){return ha.ReplicationReceipt{},ErrUnauthorized}
	ctx=context.WithValue(ctx,sqlMaintenanceCapability{},true)
	credential,err:=executor.replicationCredential(ctx,binding,channel,epoch);if err!=nil{return ha.ReplicationReceipt{},err};defer credential.Wipe()
	if !verifyReplicationCheckpoint(checkpoint,channel,credential)||checkpoint.CreatedAt.After(executor.now().Add(time.Minute)){return ha.ReplicationReceipt{},ha.ErrCheckpointStale}
	fence,err:=executor.replicationFence();if err!=nil{return ha.ReplicationReceipt{},err}
	instanceID,_:=NewResourceID("mariadb-local");instance,err:=executor.instance(instanceID);if err!=nil||instance.Placement!=PlacementLocal{return ha.ReplicationReceipt{},ErrUnauthorized}
	connection,cleanup,err:=executor.connection(ctx,instance);if err!=nil{return ha.ReplicationReceipt{},err};defer cleanup()
	before,err:=observeReplica(ctx,connection);if err!=nil||!replicaCompatible(before,checkpoint){return ha.ReplicationReceipt{},ha.ErrSplitBrainRisk}
	name:="ha-replica-"+digestBytes([]byte(channel.ID))[:32]+".json"
	journal:=localReplicaJournal{Channel:channel,Checkpoint:checkpoint,Epoch:epoch,DeploymentDigest:binding.DeploymentDigest,FenceToken:fence.FencingToken,State:"applying"}
	var previous localReplicaJournal
	loadErr:=executor.readNamed("effects",name,&previous)
	if loadErr==nil{
		if previous.Epoch!=epoch||previous.DeploymentDigest!=binding.DeploymentDigest||previous.FenceToken!=fence.FencingToken{return ha.ReplicationReceipt{},ErrUnauthorized}
		oldChannel,_:=json.Marshal(previous.Channel);newChannel,_:=json.Marshal(channel);if !bytes.Equal(oldChannel,newChannel){return ha.ReplicationReceipt{},ErrIdempotency}
		if previous.Checkpoint.ID==checkpoint.ID{oldCheckpoint,_:=json.Marshal(previous.Checkpoint);newCheckpoint,_:=json.Marshal(checkpoint);if !bytes.Equal(oldCheckpoint,newCheckpoint){return ha.ReplicationReceipt{},ErrIdempotency}}
		if previous.Checkpoint.WriteFrontier>checkpoint.WriteFrontier{return ha.ReplicationReceipt{},ha.ErrCheckpointStale}
		if previous.State=="applying"&&previous.Checkpoint.ID!=checkpoint.ID{return ha.ReplicationReceipt{},ErrAmbiguous}
	}else if !errors.Is(loadErr,ErrNotFound){return ha.ReplicationReceipt{},loadErr}
	if len(before.Fields)>0&&!replicaEndpointMatches(before,binding,credential){return ha.ReplicationReceipt{},ErrUnauthorized}
	if err=verifyReplicationPeerTLS(ctx,binding);err!=nil{return ha.ReplicationReceipt{},err}
	input:=replicationSQLInput{Binding:binding,Credential:credential,Checkpoint:checkpoint,StopExisting:len(before.Fields)>0}
	if loadErr!=nil{
		if err=executor.writeNamed("effects",name,journal);err!=nil{return ha.ReplicationReceipt{},err}
		if err=executor.VerifyReplicationAuthority(ctx,binding,node,epoch);err!=nil{return ha.ReplicationReceipt{},ErrUnauthorized}
		if _,err=connection.query(ctx,sqlConfigureReplication,input);err!=nil{return ha.ReplicationReceipt{},ErrAmbiguous}
	}else if len(before.Fields)==0{return ha.ReplicationReceipt{},ErrAmbiguous}
	if loadErr==nil&&previous.State!="applied"&&previous.State!="applying"{return ha.ReplicationReceipt{},ErrInvalidReceipt}
	waitOutput,waitErr:=connection.query(ctx,sqlWaitReplication,input);if waitErr!=nil||strings.TrimSpace(string(waitOutput))!="0"{return ha.ReplicationReceipt{},ErrAmbiguous}
	after,err:=observeReplica(ctx,connection);if err!=nil||!replicaCaughtUp(after,binding,credential,channel,checkpoint){return ha.ReplicationReceipt{},ErrAmbiguous}
	if err=executor.VerifyReplicationAuthority(ctx,binding,node,epoch);err!=nil{return ha.ReplicationReceipt{},ErrUnauthorized}
	proof,_:=json.Marshal(struct{Channel ha.ChannelID;Checkpoint ha.CheckpointID;Epoch,Fence uint64;Observation string}{channel.ID,checkpoint.ID,epoch,fence.FencingToken,after.Proof})
	receipt:=ha.ReplicationReceipt{ChannelID:channel.ID,SourceNodeID:channel.SourceNodeID,TargetNodeID:channel.TargetNodeID,SourceGeneration:checkpoint.SourceGeneration,WriteFrontier:checkpoint.WriteFrontier,Position:checkpoint.Position,ManifestDigest:checkpoint.ManifestDigest,TargetReceipt:string(proof),VerifiedAt:executor.now().UTC()}
	journal.State="applied";journal.Receipt=receipt
	if err=executor.writeNamed("effects",name,journal);err!=nil{return ha.ReplicationReceipt{},ErrAmbiguous}
	return receipt,nil
}

func replicaEndpointMatches(value replicaObservation,binding ha.StaticReplicationBinding,credential MariaDBReplicationCredential)bool{
	ip,err:=replicationPeer(binding);if err!=nil{return false}
	fields:=value.Fields
	return fields["Master_Host"]==ip.String()&&fields["Master_Port"]=="3306"&&fields["Master_User"]==credential.Username.String()&&fields["Using_Gtid"]=="Slave_Pos"&&fields["Master_SSL_Allowed"]=="Yes"&&fields["Master_SSL_Verify_Server_Cert"]=="Yes"&&fields["Master_SSL_CA_File"]==binding.TLSCAPath
}

func replicaCaughtUp(value replicaObservation,binding ha.StaticReplicationBinding,credential MariaDBReplicationCredential,channel ha.ReplicationChannel,checkpoint ha.ReplicationCheckpoint)bool{
	if !replicaCompatible(value,checkpoint)||!replicaEndpointMatches(value,binding,credential)||value.Slave!=checkpoint.Position||value.Current!=checkpoint.Position||value.Fields["Slave_IO_Running"]!="Yes"||value.Fields["Slave_SQL_Running"]!="Yes"||value.Fields["Last_IO_Errno"]!="0"||value.Fields["Last_SQL_Errno"]!="0"||value.Fields["Gtid_IO_Pos"]!=checkpoint.Position{return false}
	_,origin,_,_:=singleDomainGTID(checkpoint.Position);if value.Fields["Master_Server_Id"]!=strconv.FormatUint(origin,10){return false}
	lag,err:=strconv.ParseUint(value.Fields["Seconds_Behind_Master"],10,32);return err==nil&&time.Duration(lag)*time.Second<=channel.RPO
}

func(executor *LinuxMariaDBExecutor)RejoinDatabaseMember(ctx context.Context,cluster ha.DatabaseCluster,node ha.NodeID,checkpoint ha.ReplicationCheckpoint)(string,error){
	if executor==nil||!validLocalHACluster(cluster)||checkpoint.Validate()!=nil||cluster.WriterNodeID==node{return "",ha.ErrFenceRequired}
	binding,local,_,err:=executor.replicationBinding(ctx,checkpoint.ChannelID);if err!=nil||binding.LocalRole!="target"||node!=local{return "",ErrUnauthorized}
	fenced:=false;for _,member:=range cluster.Members{if member.NodeID==node&&member.State==ha.DBFenced&&member.ReadOnly{fenced=true}};if !fenced{return "",ha.ErrFenceRequired}
	var journal localReplicaJournal
	executor.mu.Lock();err=executor.readNamed("effects","ha-replica-"+digestBytes([]byte(checkpoint.ChannelID))[:32]+".json",&journal);executor.mu.Unlock()
	if err!=nil||journal.Channel.GroupID!=cluster.GroupID||journal.Channel.TargetNodeID!=local{return "",ha.ErrCheckpointStale}
	receipt,err:=executor.CatchUpReplica(ctx,journal.Channel,checkpoint);if err!=nil{return "",err}
	// Rejoin admits a read-only replica only. Promotion remains a distinct
	// fenced writer-lease operation; no RESET or data replacement exists here.
	encoded,err:=json.Marshal(receipt);return string(encoded),err
}
