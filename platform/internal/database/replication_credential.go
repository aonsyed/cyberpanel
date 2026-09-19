package database

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

// Identical channel material is provisioned out-of-band on the two authorized
// nodes. Endpoints, plugins, file paths and SQL are never credential inputs.
const MariaDBReplicationCredentialSchemaVersion uint32 = 1

type MariaDBReplicationCredential struct {
	SchemaVersion        uint32        `json:"schema_version"`
	ChannelID            ha.ChannelID  `json:"channel_id"`
	SourceNodeID         ha.NodeID     `json:"source_node_id"`
	TargetNodeID         ha.NodeID     `json:"target_node_id"`
	AuthorityEpoch       uint64        `json:"authority_epoch"`
	CredentialGeneration uint64        `json:"credential_generation"`
	Username             SQLIdentifier `json:"username"`
	Password             []byte        `json:"password"`
	CheckpointKey        []byte        `json:"checkpoint_key"`
}

func(value MariaDBReplicationCredential)Validate()error{
	if value.SchemaVersion!=MariaDBReplicationCredentialSchemaVersion||value.ChannelID==""||value.SourceNodeID==""||value.TargetNodeID==""||value.SourceNodeID==value.TargetNodeID||value.AuthorityEpoch==0||value.CredentialGeneration==0||value.CredentialGeneration>uint64(1<<63-1)||value.Username.String()!=MariaDBReplicationUsernameForGeneration(value.ChannelID,value.CredentialGeneration)||len(value.Password)<32||len(value.Password)>128||len(value.CheckpointKey)!=32{return ErrInvalidResource}
	for _,character:=range value.Password{if !(asciiAlphaNumeric(character)||character=='_'||character=='-'){return ErrInvalidResource}}
	return nil
}

// MariaDBReplicationUsername retains the deterministic generation-one name.
// Rotations always use MariaDBReplicationUsernameForGeneration so source and
// target credentials can overlap without mutating an account in place.
func MariaDBReplicationUsername(channel ha.ChannelID)string{return MariaDBReplicationUsernameForGeneration(channel,1)}
func MariaDBReplicationUsernameForGeneration(channel ha.ChannelID,generation uint64)string{return "cprepl_"+replicationCredentialUsernameDigest(channel,generation)[:20]}

func replicationCredentialUsernameDigest(channel ha.ChannelID,generation uint64)string{
	payload,_:=json.Marshal(struct{Domain string `json:"domain"`;Channel ha.ChannelID `json:"channel"`;Generation uint64 `json:"generation"`}{"cyberpanel-mariadb-replication-credential-v1",channel,generation})
	return transferDigest(payload)
}

func(value *MariaDBReplicationCredential)Wipe(){for index:=range value.Password{value.Password[index]=0};for index:=range value.CheckpointKey{value.CheckpointKey[index]=0}}

func DecodeMariaDBReplicationCredential(raw []byte)(MariaDBReplicationCredential,error){
	var value MariaDBReplicationCredential
	if len(raw)==0||len(raw)>8192{return value,ErrInvalidResource}
	decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields()
	if err:=decoder.Decode(&value);err!=nil{value.Wipe();return MariaDBReplicationCredential{},ErrInvalidResource}
	if decoder.Decode(&struct{}{})!=io.EOF||value.Validate()!=nil{value.Wipe();return MariaDBReplicationCredential{},ErrInvalidResource}
	return value,nil
}
