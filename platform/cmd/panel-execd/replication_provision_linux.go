//go:build linux

package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// Only the channel identifier is argv. Credentials must arrive on stdin from
// the operator, never in arguments, environment variables or a config file.
func provisionMariaDBReplication(channelText string)error{
	if os.Geteuid()!=0{return database.ErrUnauthorized}
	ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second);defer cancel()
	binding,node,epoch,err:=ha.ReadStaticReplicationBinding(ha.ChannelID(channelText));if err!=nil{return err}
	recovery,err:=apiserver.NewRecoveryClient("/run/cyberpanel-core/recovery.sock");if err!=nil{return err}
	if err=recovery.VerifyStaticHAReplication(ctx,binding,node,epoch);err!=nil{return err}
	raw,err:=io.ReadAll(io.LimitReader(os.Stdin,8193));if err!=nil{return err};defer func(){for index:=range raw{raw[index]=0}}()
	credential,err:=database.DecodeMariaDBReplicationCredential(raw);if err!=nil{return err};defer credential.Wipe()
	if credential.ChannelID!=binding.ChannelID||credential.AuthorityEpoch!=epoch{return database.ErrUnauthorized}
	if binding.LocalRole=="source"{if credential.SourceNodeID!=node||credential.TargetNodeID!=binding.PeerNodeID{return database.ErrUnauthorized}}else if binding.LocalRole=="target"{if credential.TargetNodeID!=node||credential.SourceNodeID!=binding.PeerNodeID{return database.ErrUnauthorized}}else{return database.ErrUnauthorized}
	material,err:=json.Marshal(credential);if err!=nil{return err};defer func(){for index:=range material{material[index]=0}}()
	client,err:=secrets.NewLocalManagementClient();if err!=nil{return err}
	release,err:=apps.LinuxApplicationExecutorDigest();if err!=nil{return err}
	owner,_:=secrets.NewID("installation")
	metadata,err:=client.PutExact(ctx,secrets.PutRequest{ID:database.DatabaseSecretRecordID(binding.PurposeKeyRef),OwnerTenantID:owner,Purpose:secrets.PurposeDatabase,Audience:secrets.AudienceBinding{AdapterID:database.MariaDBSecretAdapterID,AdapterVersion:database.MariaDBSecretAdapterVersion,Account:"local-mariadb",Origin:"local://panel-execd/mariadb",ResourceKind:"database_replication_channel",ResourceID:database.DatabaseAudienceID("replication-"+string(binding.ChannelID)),ResourceGeneration:binding.ChannelGeneration,Operations:[]secrets.Operation{secrets.OperationAuthenticate},ConsumerReleaseDigest:release},Plaintext:material})
	if err!=nil{return err}
	return json.NewEncoder(os.Stdout).Encode(struct{SecretID secrets.ID `json:"secret_id"`;Version uint64 `json:"version"`;BindingDigest string `json:"binding_digest"`}{metadata.ID,metadata.Version,metadata.BindingDigest})
}
