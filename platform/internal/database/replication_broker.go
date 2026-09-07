package database

import "github.com/aonsyed/cyberpanel/platform/internal/ha"

type replicationEpochContextKey struct{}

func validMariaDBReplicationChannel(channel ha.ReplicationChannel) bool {
	return channel.Validate()==nil && channel.Kind==ha.DataDatabase && channel.ResourceID=="mariadb-local" && channel.Mode==ha.ChannelAsynchronous && len(channel.Exclusions)==0
}

func validateMariaDBReplicationRequest(request MariaDBHARequest)error{
	if request.Permit!=nil||request.Lease!=nil||request.FencingToken!=0||request.AuthorityEpoch==0{return ErrInvalidCommand}
	if request.Action==MariaDBHARejoin {
		if request.Channel!=nil||request.SourceGeneration!=0||request.Cluster.Validate()!=nil||request.Cluster.ID!="mariadb-local"||request.Cluster.Topology!=ha.DatabasePrimaryReplica||request.NodeID==""||request.Checkpoint==nil||request.Checkpoint.Validate()!=nil{return ErrInvalidCommand};return nil
	}
	if request.Cluster.ID!=""||request.Cluster.GroupID!=""||len(request.Cluster.Members)!=0||request.Cluster.Topology!=""||request.Cluster.Generation!=0||request.NodeID!=""||request.Channel==nil||!validMariaDBReplicationChannel(*request.Channel){return ErrInvalidCommand}
	switch request.Action{
	case MariaDBHACheckpoint:
		if request.Checkpoint!=nil||request.SourceGeneration==0{return ErrInvalidCommand}
	case MariaDBHACatchUp:
		if request.SourceGeneration!=0||request.Checkpoint==nil||request.Checkpoint.Validate()!=nil||request.Checkpoint.ChannelID!=request.Channel.ID{return ErrInvalidCommand}
	default:return ErrInvalidCommand
	}
	return nil
}

func validateMariaDBReplicationResult(request MariaDBHARequest,result MariaDBHAResult)error{
	if result.Cluster!=nil||result.Permit!=nil||result.Frontier!=0{return ErrInvalidReceipt}
	switch request.Action{
	case MariaDBHACheckpoint:
		if request.Channel==nil||result.Checkpoint==nil||result.Replication!=nil||result.Receipt!=""||result.Checkpoint.Validate()!=nil||result.Checkpoint.ChannelID!=request.Channel.ID||result.Checkpoint.SourceGeneration!=request.SourceGeneration{return ErrInvalidReceipt}
	case MariaDBHACatchUp:
		if request.Channel==nil||request.Checkpoint==nil||result.Checkpoint!=nil||result.Replication==nil||result.Receipt!=""{return ErrInvalidReceipt}
		actual,expected,channel:=*result.Replication,*request.Checkpoint,*request.Channel
		if actual.ChannelID!=channel.ID||actual.SourceNodeID!=channel.SourceNodeID||actual.TargetNodeID!=channel.TargetNodeID||actual.SourceGeneration!=expected.SourceGeneration||actual.Position!=expected.Position||actual.WriteFrontier!=expected.WriteFrontier||actual.ManifestDigest!=expected.ManifestDigest||actual.TargetReceipt==""||actual.VerifiedAt.IsZero(){return ErrInvalidReceipt}
	case MariaDBHARejoin:
		if result.Checkpoint!=nil||result.Replication!=nil||result.Receipt==""{return ErrInvalidReceipt}
	default:return ErrInvalidReceipt
	}
	return nil
}
