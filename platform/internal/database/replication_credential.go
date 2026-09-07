package database

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

// Identical channel material is provisioned out-of-band on the two authorized
// nodes. Endpoints, plugins, file paths and SQL are never credential inputs.
type MariaDBReplicationCredential struct {
	ChannelID ha.ChannelID `json:"channel_id"`
	SourceNodeID ha.NodeID `json:"source_node_id"`
	TargetNodeID ha.NodeID `json:"target_node_id"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	Username SQLIdentifier `json:"username"`
	Password []byte `json:"password"`
	CheckpointKey []byte `json:"checkpoint_key"`
}

func(value MariaDBReplicationCredential)Validate()error{
	if value.ChannelID==""||value.SourceNodeID==""||value.TargetNodeID==""||value.SourceNodeID==value.TargetNodeID||value.AuthorityEpoch==0||value.Username.String()!=MariaDBReplicationUsername(value.ChannelID)||len(value.Password)<32||len(value.Password)>128||len(value.CheckpointKey)!=32{return ErrInvalidResource}
	for _,character:=range value.Password{if !(asciiAlphaNumeric(character)||character=='_'||character=='-'){return ErrInvalidResource}}
	return nil
}

func MariaDBReplicationUsername(channel ha.ChannelID)string{return "cprepl_"+transferDigest([]byte(channel))[:20]}

func(value *MariaDBReplicationCredential)Wipe(){for index:=range value.Password{value.Password[index]=0};for index:=range value.CheckpointKey{value.CheckpointKey[index]=0}}

func DecodeMariaDBReplicationCredential(raw []byte)(MariaDBReplicationCredential,error){
	var value MariaDBReplicationCredential
	if len(raw)==0||len(raw)>8192{return value,ErrInvalidResource}
	decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields()
	if err:=decoder.Decode(&value);err!=nil{value.Wipe();return MariaDBReplicationCredential{},ErrInvalidResource}
	if decoder.Decode(&struct{}{})!=io.EOF||value.Validate()!=nil{value.Wipe();return MariaDBReplicationCredential{},ErrInvalidResource}
	return value,nil
}
