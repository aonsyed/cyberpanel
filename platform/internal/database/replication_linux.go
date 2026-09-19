//go:build linux

package database

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

type localGTIDCheckpoint struct {
	Channel              ha.ReplicationChannel `json:"channel"`
	CredentialGeneration uint64                `json:"credential_generation"`
	Checkpoint           ha.ReplicationCheckpoint `json:"checkpoint"`
}

func localGTIDCheckpointIdentity(channel ha.ReplicationChannel,generation,credentialGeneration uint64)([]byte,string,error){
	encoded,err:=json.Marshal(struct{Channel ha.ReplicationChannel;Generation,CredentialGeneration uint64}{channel,generation,credentialGeneration})
	if err!=nil{return nil,"",err}
	journalIdentity,err:=json.Marshal(struct{Channel ha.ReplicationChannel;Generation uint64}{channel,generation})
	if err!=nil{return nil,"",err}
	return encoded,"ha-checkpoint-"+digestBytes(journalIdentity)[:40]+".json",nil
}

func(executor *LinuxMariaDBExecutor)replicationBinding(ctx context.Context,channelID ha.ChannelID)(ha.StaticReplicationBinding,ha.NodeID,uint64,error){
	if executor.VerifyReplicationAuthority==nil{return ha.StaticReplicationBinding{},"",0,ErrUnauthorized}
	binding,node,epoch,err:=ha.ReadStaticReplicationBinding(channelID);if err!=nil{return binding,node,epoch,err}
	requested,ok:=ctx.Value(replicationEpochContextKey{}).(uint64);if !ok||requested!=epoch{return binding,node,epoch,ErrUnauthorized}
	if err=executor.VerifyReplicationAuthority(ctx,binding,node,epoch);err!=nil{return binding,node,epoch,ErrUnauthorized}
	return binding,node,epoch,nil
}

func(executor *LinuxMariaDBExecutor)replicationCredential(ctx context.Context,binding ha.StaticReplicationBinding,channel ha.ReplicationChannel,epoch uint64)(MariaDBReplicationCredential,error){
	source,ok:=executor.secrets.(interface{MariaDBReplicationCredential(context.Context,ha.StaticReplicationBinding)(MariaDBReplicationCredential,error)});if !ok{return MariaDBReplicationCredential{},ErrUnauthorized}
	value,err:=source.MariaDBReplicationCredential(ctx,binding);if err!=nil{return value,err}
	if value.Validate()!=nil||value.ChannelID!=channel.ID||value.SourceNodeID!=channel.SourceNodeID||value.TargetNodeID!=channel.TargetNodeID||value.AuthorityEpoch!=epoch{value.Wipe();return MariaDBReplicationCredential{},ErrUnauthorized}
	return value,nil
}

func bindingMatchesChannel(binding ha.StaticReplicationBinding,node ha.NodeID,channel ha.ReplicationChannel,role string)bool{
	if !validMariaDBReplicationChannel(channel)||binding.ChannelID!=channel.ID||binding.ChannelGeneration!=channel.Generation||binding.LocalRole!=role||binding.PurposeKeyRef!=channel.PurposeKeyRef||binding.EncryptionProfile!=channel.EncryptionProfile{return false}
	if role=="source"{return node==channel.SourceNodeID&&binding.PeerNodeID==channel.TargetNodeID};return role=="target"&&node==channel.TargetNodeID&&binding.PeerNodeID==channel.SourceNodeID
}

// Checkpoints attest an actual stable, read-only local binlog position. They
// never claim that a network replica has received bytes or applied transactions.
func(executor *LinuxMariaDBExecutor)CreateDatabaseCheckpoint(ctx context.Context,channel ha.ReplicationChannel,generation uint64)(ha.ReplicationCheckpoint,error){
	if executor==nil||ctx==nil||!validMariaDBReplicationChannel(channel)||generation==0{return ha.ReplicationCheckpoint{},ErrInvalidCommand}
	executor.mu.Lock();defer executor.mu.Unlock()
	binding,node,epoch,err:=executor.replicationBinding(ctx,channel.ID);if err!=nil||!bindingMatchesChannel(binding,node,channel,"source"){return ha.ReplicationCheckpoint{},ErrUnauthorized}
	ctx=context.WithValue(ctx,sqlMaintenanceCapability{},true)
	credential,err:=executor.replicationCredential(ctx,binding,channel,epoch);if err!=nil{return ha.ReplicationCheckpoint{},err};defer credential.Wipe()
	encoded,name,err:=localGTIDCheckpointIdentity(channel,generation,credential.CredentialGeneration);if err!=nil{return ha.ReplicationCheckpoint{},err}
	identity:=digestBytes(encoded)
	var prior localGTIDCheckpoint
	replay:=false
	if err=executor.readNamed("effects",name,&prior);err==nil{
		left,_:=json.Marshal(prior.Channel);right,_:=json.Marshal(channel)
		if string(left)!=string(right)||prior.Checkpoint.SourceGeneration!=generation{return ha.ReplicationCheckpoint{},ErrIdempotency}
		if prior.CredentialGeneration==credential.CredentialGeneration{if !verifyReplicationCheckpoint(prior.Checkpoint,channel,credential){return ha.ReplicationCheckpoint{},ErrIdempotency};replay=true}else if prior.CredentialGeneration==0||prior.CredentialGeneration>=credential.CredentialGeneration||credential.CredentialGeneration-prior.CredentialGeneration>1{return ha.ReplicationCheckpoint{},ErrIdempotency}
	}else if !errors.Is(err,ErrNotFound){return ha.ReplicationCheckpoint{},err}
	instanceID,_:=NewResourceID("mariadb-local");instance,err:=executor.instance(instanceID);if err!=nil||instance.Placement!=PlacementLocal{return ha.ReplicationCheckpoint{},ErrUnauthorized}
	connection,cleanup,err:=executor.connection(ctx,instance);if err!=nil{return ha.ReplicationCheckpoint{},err};defer cleanup()
	preflight,err:=connection.query(ctx,sqlStableGTIDCheckpoint);if err!=nil{return ha.ReplicationCheckpoint{},err}
	preLines:=strings.Split(strings.TrimSpace(string(preflight)),"\n");if len(preLines)!=2||preLines[0]!=preLines[1]{return ha.ReplicationCheckpoint{},ErrAmbiguous}
	preFields:=strings.Split(preLines[0],"\t");if len(preFields)!=6||preFields[2]!="1"||preFields[4]!="1"||preFields[5]!="1"{return ha.ReplicationCheckpoint{},ErrUnauthorized}
	topology,err:=observeReplica(ctx,connection);if err!=nil{return ha.ReplicationCheckpoint{},err}
	if len(topology.Fields)!=0{return ha.ReplicationCheckpoint{},ha.ErrUnsupported}
	if err=executor.ensureReplicationPrincipal(ctx,connection,binding,credential);err!=nil{return ha.ReplicationCheckpoint{},err}
	if replay{
		if preFields[3]!=prior.Checkpoint.Position{return ha.ReplicationCheckpoint{},ha.ErrCheckpointStale}
		if err=executor.VerifyReplicationAuthority(ctx,binding,node,epoch);err!=nil{return ha.ReplicationCheckpoint{},ErrUnauthorized}
		return prior.Checkpoint,nil
	}
	output,err:=connection.query(ctx,sqlStableGTIDCheckpoint);if err!=nil{return ha.ReplicationCheckpoint{},err}
	lines:=strings.Split(strings.TrimSpace(string(output)),"\n")
	if len(lines)!=2||lines[0]!=lines[1]{return ha.ReplicationCheckpoint{},ErrAmbiguous}
	fields:=strings.Split(lines[0],"\t")
	if len(fields)!=6||fields[2]!="1"||fields[4]!="1"||fields[5]!="1"{return ha.ReplicationCheckpoint{},ErrUnauthorized}
	serverID,err:=strconv.ParseUint(fields[0],10,32);if err!=nil||serverID==0{return ha.ReplicationCheckpoint{},ErrInvalidResource}
	_,origin,sequence,err:=singleDomainGTID(fields[3]);if err!=nil||origin!=serverID||sequence==0{return ha.ReplicationCheckpoint{},ErrInvalidResource}
	now:=executor.now().UTC()
	manifest:=digestBytes(append(append([]byte(nil),encoded...),output...))
	checkpoint:=ha.ReplicationCheckpoint{ID:ha.CheckpointID("mdbcp-"+identity[:40]),ChannelID:channel.ID,SourceGeneration:generation,WriteFrontier:sequence,Position:fields[3],ManifestDigest:manifest,Consistency:"mariadb-gtid-read-only-v1",Verified:true,CreatedAt:now,VerifiedAt:now}
	checkpoint.StableViewRef=replicationCheckpointMAC(checkpoint,channel,credential)
	if checkpoint.Validate()!=nil{return ha.ReplicationCheckpoint{},ErrInvalidReceipt}
	if err=executor.VerifyReplicationAuthority(ctx,binding,node,epoch);err!=nil{return ha.ReplicationCheckpoint{},ErrUnauthorized}
	if err=executor.writeNamed("effects",name,localGTIDCheckpoint{Channel:channel,CredentialGeneration:credential.CredentialGeneration,Checkpoint:checkpoint});err!=nil{return ha.ReplicationCheckpoint{},err}
	return checkpoint,nil
}

func replicationCheckpointMAC(checkpoint ha.ReplicationCheckpoint,channel ha.ReplicationChannel,credential MariaDBReplicationCredential)string{
	checkpoint.StableViewRef=""
	unsigned,_:=json.Marshal(struct{Domain string;Channel ha.ReplicationChannel;Epoch,CredentialGeneration uint64;Checkpoint ha.ReplicationCheckpoint}{"cyberpanel-mariadb-checkpoint-v1",channel,credential.AuthorityEpoch,credential.CredentialGeneration,checkpoint})
	mac:=hmac.New(sha256.New,credential.CheckpointKey);_,_=mac.Write(unsigned);return "mariadb-gtid-hmac:"+hex.EncodeToString(mac.Sum(nil))
}

func verifyReplicationCheckpoint(checkpoint ha.ReplicationCheckpoint,channel ha.ReplicationChannel,credential MariaDBReplicationCredential)bool{
	_,_,sequence,err:=singleDomainGTID(checkpoint.Position)
	return err==nil&&checkpoint.Validate()==nil&&checkpoint.ChannelID==channel.ID&&sequence==checkpoint.WriteFrontier&&checkpoint.Consistency=="mariadb-gtid-read-only-v1"&&hmac.Equal([]byte(checkpoint.StableViewRef),[]byte(replicationCheckpointMAC(checkpoint,channel,credential)))
}

// Initially support one GTID domain and one origin only. A maximum over a GTID
// set is not a proof that another domain/server has no divergent transactions.
func singleDomainGTID(value string)(uint64,uint64,uint64,error){
	parts:=strings.Split(value,"-");if len(parts)!=3{return 0,0,0,ErrInvalidResource}
	values:=[3]uint64{}
	for index,part:=range parts{parsed,err:=strconv.ParseUint(part,10,64);if err!=nil||strconv.FormatUint(parsed,10)!=part{return 0,0,0,ErrInvalidResource};values[index]=parsed}
	if values[0]>1<<32-1||values[1]==0||values[1]>1<<32-1{return 0,0,0,ErrInvalidResource}
	return values[0],values[1],values[2],nil
}
