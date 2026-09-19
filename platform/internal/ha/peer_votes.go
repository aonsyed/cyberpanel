package ha

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"time"
)

// PeerControl is independent of optional central federation. Only public voter
// identity and bounded endpoints travel in the signed deployment.
type PeerControl struct {
	TopologyEpoch uint64 `json:"topology_epoch"`
	CASHA256 string `json:"ca_sha256"`
	TopologyDigest string `json:"topology_digest"`
	Voters []PeerVoter `json:"voters"`
}
type PeerVoter struct {
	NodeID NodeID `json:"node_id"`
	Endpoint string `json:"endpoint"`
	SPKISHA256 string `json:"spki_sha256"`
	VoteKeyID string `json:"vote_key_id"`
	VotePublicKey []byte `json:"vote_public_key"`
}

func (control PeerControl) Validate(group NodeGroup, nodes []NodeMember) error {
	if control.TopologyEpoch == 0 || !validDigest(control.CASHA256) || !validDigest(control.TopologyDigest) || len(control.Voters) < 3 || len(control.Voters) > 7 || len(control.Voters)%2 != 1 || int(group.MinimumManagers) != len(control.Voters) { return ErrNoQuorum }
	members := map[NodeID]bool{}
	for _, node := range nodes { for _, role := range node.Roles { if role == RoleManager { members[node.ID] = true } } }
	ids, pins, keys, endpoints := map[NodeID]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, voter := range control.Voters {
		if !members[voter.NodeID] || ids[voter.NodeID] || !validDigest(voter.SPKISHA256) || pins[voter.SPKISHA256] || !validID(voter.VoteKeyID) || len(voter.VotePublicKey) != ed25519.PublicKeySize || keys[string(voter.VotePublicKey)] || endpoints[voter.Endpoint] { return ErrNoQuorum }
		u, err := url.Parse(voter.Endpoint)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != voter.Endpoint { return ErrForbidden }
		address, err := netip.ParseAddrPort(u.Host)
		if err != nil || address.String() != u.Host || address.Port() != 9445 || !address.Addr().IsPrivate() || address.Addr().Is4In6() { return ErrForbidden }
		ids[voter.NodeID], pins[voter.SPKISHA256], keys[string(voter.VotePublicKey)], endpoints[voter.Endpoint] = true, true, true, true
	}
	return nil
}

func PeerMembershipDigest(group NodeGroupID, control PeerControl) string {
	control.Voters = append([]PeerVoter(nil),control.Voters...)
	sort.Slice(control.Voters,func(i,j int)bool{return control.Voters[i].NodeID<control.Voters[j].NodeID})
	raw, _ := json.Marshal(struct { Domain string; Group NodeGroupID; Control PeerControl }{"cyberpanel-ha-peer-membership-v1",group,control})
	return federatedHADigest(raw)
}

// Normalize only the admitted owning-node alias, making the static topology
// digest identical across peers without changing their local executor mapping.
func PeerStaticTopologyDigest(bundle StaticDeployment) string {
	nodes:=append([]NodeMember(nil),bundle.Nodes...)
	sort.Slice(nodes,func(i,j int)bool{return nodes[i].ID<nodes[j].ID})
	cluster:=bundle.Cluster;cluster.Members=append([]DatabaseMember(nil),cluster.Members...)
	for index:=range cluster.Members{if cluster.Members[index].NodeID=="local"{cluster.Members[index].NodeID=NodeID(bundle.Trust.NodeID)}}
	sort.Slice(cluster.Members,func(i,j int)bool{return cluster.Members[i].NodeID<cluster.Members[j].NodeID})
	raw,_:=json.Marshal(struct{Domain string;Group NodeGroup;Nodes []NodeMember;Cluster DatabaseCluster}{"cyberpanel-ha-peer-static-topology-v1",bundle.Group,nodes,cluster})
	return federatedHADigest(raw)
}

// Prepare votes are promises only. They never authorize a writer lease. A
// separate post-fence transfer certificate must prove old-writer enforcement.
type PeerVoteProposal struct {
	ID string `json:"id"`
	Coordinator NodeID `json:"coordinator"`
	GroupID NodeGroupID `json:"group_id"`
	ResourceID string `json:"resource_id"`
	PromotionID PromotionID `json:"promotion_id"`
	PromotionGeneration uint64 `json:"promotion_generation"`
	PlanDigest string `json:"plan_digest"`
	Candidate NodeID `json:"candidate"`
	PreviousWriter NodeID `json:"previous_writer"`
	PreviousLeaseID WriterLeaseID `json:"previous_lease_id"`
	PreviousFencingEpoch uint64 `json:"previous_fencing_epoch"`
	FencingEpoch uint64 `json:"fencing_epoch"`
	TopologyEpoch uint64 `json:"topology_epoch"`
	MembershipDigest string `json:"membership_digest"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (proposal PeerVoteProposal) Digest() string { raw,_:=json.Marshal(proposal);return federatedHADigest(raw) }
func (proposal PeerVoteProposal) Validate(now time.Time) error {
	if !validID(proposal.ID) || !validID(string(proposal.Coordinator)) || !validID(string(proposal.GroupID)) || proposal.ResourceID != LocalMariaDBResourceID || !validID(string(proposal.PromotionID)) || proposal.PromotionGeneration == 0 || !validDigest(proposal.PlanDigest) || !validID(string(proposal.Candidate)) || !validID(string(proposal.PreviousWriter)) || proposal.Candidate == proposal.PreviousWriter || !validID(string(proposal.PreviousLeaseID)) || proposal.PreviousFencingEpoch == 0 || proposal.FencingEpoch <= proposal.PreviousFencingEpoch || proposal.FencingEpoch-proposal.PreviousFencingEpoch != 1 || proposal.TopologyEpoch == 0 || !validDigest(proposal.MembershipDigest) || proposal.IssuedAt.IsZero() || proposal.IssuedAt.After(now.Add(5*time.Second)) || !now.Before(proposal.ExpiresAt) || !proposal.ExpiresAt.After(proposal.IssuedAt) || proposal.ExpiresAt.Sub(proposal.IssuedAt) > 2*time.Minute { return ErrNoQuorum }
	if proposal.AuthorityEpoch==0{return ErrNoQuorum}
	return nil
}

type PeerPromotionVote struct {
	VoterID NodeID `json:"voter_id"`
	SigningKeyID string `json:"signing_key_id"`
	ProposalDigest string `json:"proposal_digest"`
	MembershipDigest string `json:"membership_digest"`
	TopologyEpoch uint64 `json:"topology_epoch"`
	FencingEpoch uint64 `json:"fencing_epoch"`
	ObservationDigest string `json:"observation_digest"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature []byte `json:"signature"`
}
func (vote PeerPromotionVote) SigStructure() []byte { vote.Signature=nil;raw,_:=json.Marshal(struct {Domain string `json:"domain"`;Vote PeerPromotionVote `json:"vote"`}{"cyberpanel-ha-prepare-vote-v1",vote});return raw }
type PeerVoteProof struct { Proposal PeerVoteProposal `json:"proposal"`; Votes []PeerPromotionVote `json:"votes"` }
type PeerVoteProjection struct {
	ProposalID string `json:"proposal_id"`
	ProofDigest string `json:"proof_digest"`
	MembershipDigest string `json:"membership_digest"`
	TopologyEpoch uint64 `json:"topology_epoch"`
	FencingEpoch uint64 `json:"fencing_epoch"`
	Voters []NodeID `json:"voters"`
	Required int `json:"required"`
	ExpiresAt time.Time `json:"expires_at"`
	State string `json:"state"`
}

type PeerVoteTopology struct { NodeID NodeID; GroupID NodeGroupID; AuthorityEpoch uint64; DeploymentEpoch uint64; DeploymentDigest string; Control PeerControl }
type PeerVoteTransport interface { RequestVote(context.Context,PeerVoter,PeerVoteProposal)(PeerPromotionVote,error) }
type PeerVoteService struct {
	DB *sql.DB
	Topology func(context.Context)(PeerVoteTopology,error)
	Observe func(context.Context,PeerVoteProposal)(string,error)
	Sign func(context.Context,[]byte)([]byte,error)
	Transport PeerVoteTransport
	Now func()time.Time
}
func (service *PeerVoteService) now()time.Time { if service.Now!=nil{return service.Now().UTC()};return time.Now().UTC() }
func (service *PeerVoteService) Bootstrap(ctx context.Context)error {
	if service==nil||service.DB==nil||service.Topology==nil||service.Observe==nil||service.Sign==nil||service.Transport==nil{return ErrInvalid}
	_,err:=service.DB.ExecContext(ctx,`CREATE TABLE IF NOT EXISTS ha_peer_vote_proposals_v1(id TEXT PRIMARY KEY,promotion_id TEXT NOT NULL,promotion_generation INTEGER NOT NULL,membership_digest TEXT NOT NULL,proposal_json BLOB NOT NULL,proof_json BLOB,UNIQUE(promotion_id,promotion_generation,membership_digest));
CREATE TABLE IF NOT EXISTS ha_peer_promotion_votes_v1(resource_id TEXT NOT NULL,topology_epoch INTEGER NOT NULL,fencing_epoch INTEGER NOT NULL,proposal_digest TEXT NOT NULL,vote_json BLOB NOT NULL,expires_at TIMESTAMP NOT NULL,PRIMARY KEY(resource_id,topology_epoch,fencing_epoch));`)
	return err
}

func verifyPeerVote(topology PeerVoteTopology, proposal PeerVoteProposal, vote PeerPromotionVote, now time.Time)error {
	if proposal.AuthorityEpoch!=topology.AuthorityEpoch{return ErrNoQuorum}
	if proposal.Validate(now)!=nil||proposal.GroupID!=topology.GroupID||proposal.TopologyEpoch!=topology.Control.TopologyEpoch||proposal.MembershipDigest!=PeerMembershipDigest(topology.GroupID,topology.Control)||vote.ProposalDigest!=proposal.Digest()||vote.MembershipDigest!=proposal.MembershipDigest||vote.TopologyEpoch!=proposal.TopologyEpoch||vote.FencingEpoch!=proposal.FencingEpoch||!validDigest(vote.ObservationDigest)||vote.ObservedAt.Before(proposal.IssuedAt.Add(-5*time.Second))||vote.ObservedAt.After(now.Add(5*time.Second))||!vote.ExpiresAt.Equal(proposal.ExpiresAt){return ErrNoQuorum}
	for _,voter:=range topology.Control.Voters{if voter.NodeID==vote.VoterID&&voter.VoteKeyID==vote.SigningKeyID&&ed25519.Verify(ed25519.PublicKey(voter.VotePublicKey),vote.SigStructure(),vote.Signature){return nil}}
	return ErrNoQuorum
}

func (service *PeerVoteService) Cast(ctx context.Context, caller NodeID, proposal PeerVoteProposal)(PeerPromotionVote,error){
	if service==nil||ctx==nil{return PeerPromotionVote{},ErrInvalid}
	topology,err:=service.Topology(ctx);if err!=nil{return PeerPromotionVote{},err}
	if proposal.AuthorityEpoch!=topology.AuthorityEpoch{return PeerPromotionVote{},ErrNoQuorum}
	if proposal.Validate(service.now())!=nil||caller!=proposal.Coordinator||proposal.GroupID!=topology.GroupID||proposal.TopologyEpoch!=topology.Control.TopologyEpoch||proposal.MembershipDigest!=PeerMembershipDigest(topology.GroupID,topology.Control){return PeerPromotionVote{},ErrNoQuorum}
	var local PeerVoter
	callerAllowed,candidateAllowed,previousAllowed:=false,false,false
	for _,voter:=range topology.Control.Voters{if voter.NodeID==topology.NodeID{local=voter};if voter.NodeID==caller{callerAllowed=true};if voter.NodeID==proposal.Candidate{candidateAllowed=true};if voter.NodeID==proposal.PreviousWriter{previousAllowed=true}}
	if local.NodeID==""||!callerAllowed||!candidateAllowed||!previousAllowed{return PeerPromotionVote{},ErrNoQuorum}
	// Observe the local executor and local durable fence/lease state, never a
	// caller's boolean health/quorum assertion, before making a durable promise.
	observation,err:=service.Observe(ctx,proposal);if err!=nil||!validDigest(observation){return PeerPromotionVote{},errors.Join(ErrNoQuorum,err)}
	tx,err:=service.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return PeerPromotionVote{},err};defer tx.Rollback()
	var existing []byte
	var digest string
	err=tx.QueryRowContext(ctx,`SELECT proposal_digest,vote_json FROM ha_peer_promotion_votes_v1 WHERE resource_id=? AND topology_epoch=? AND fencing_epoch=?`,proposal.ResourceID,proposal.TopologyEpoch,proposal.FencingEpoch).Scan(&digest,&existing)
	if err==nil{var vote PeerPromotionVote;if digest!=proposal.Digest()||json.Unmarshal(existing,&vote)!=nil||verifyPeerVote(topology,proposal,vote,service.now())!=nil{return PeerPromotionVote{},ErrConflict};return vote,tx.Commit()}
	if !errors.Is(err,sql.ErrNoRows){return PeerPromotionVote{},err}
	var highestEpoch,highestFence uint64
	var expires time.Time
	err=tx.QueryRowContext(ctx,`SELECT topology_epoch,fencing_epoch,expires_at FROM ha_peer_promotion_votes_v1 WHERE resource_id=? ORDER BY topology_epoch DESC,fencing_epoch DESC LIMIT 1`,proposal.ResourceID).Scan(&highestEpoch,&highestFence,&expires)
	if err==nil&&(proposal.TopologyEpoch<highestEpoch||proposal.FencingEpoch<=highestFence||service.now().Before(expires)){return PeerPromotionVote{},ErrConflict};if err!=nil&&!errors.Is(err,sql.ErrNoRows){return PeerPromotionVote{},err}
	vote:=PeerPromotionVote{VoterID:local.NodeID,SigningKeyID:local.VoteKeyID,ProposalDigest:proposal.Digest(),MembershipDigest:proposal.MembershipDigest,TopologyEpoch:proposal.TopologyEpoch,FencingEpoch:proposal.FencingEpoch,ObservationDigest:observation,ObservedAt:service.now(),ExpiresAt:proposal.ExpiresAt}
	vote.Signature,err=service.Sign(ctx,vote.SigStructure());if err!=nil||verifyPeerVote(topology,proposal,vote,service.now())!=nil{return PeerPromotionVote{},ErrNoQuorum}
	_,err=tx.ExecContext(ctx,`INSERT INTO ha_peer_promotion_votes_v1(resource_id,topology_epoch,fencing_epoch,proposal_digest,vote_json,expires_at) VALUES(?,?,?,?,?,?)`,proposal.ResourceID,proposal.TopologyEpoch,proposal.FencingEpoch,proposal.Digest(),mustPeerVoteJSON(vote),vote.ExpiresAt);if err!=nil{return PeerPromotionVote{},err}
	if err=tx.Commit();err!=nil{return PeerPromotionVote{},err};return vote,nil
}

func (service *PeerVoteService) Collect(ctx context.Context,promotionID PromotionID)(PeerVoteProjection,error){
	if service==nil||ctx==nil||!validID(string(promotionID)){return PeerVoteProjection{},ErrInvalid}
	topology,err:=service.Topology(ctx);if err!=nil{return PeerVoteProjection{},err}
	store:=SQLRepository{DB:service.DB}
	promotion,err:=store.LoadPromotion(ctx,promotionID);if err!=nil{return PeerVoteProjection{},err}
	if promotion.GroupID!=topology.GroupID||promotion.State!=PromotionPlanned||promotion.Automatic||promotion.PotentialDataLoss{return PeerVoteProjection{},ErrUnsafePromotion}
	plan,err:=PromotionPlanDigest(promotion);if err!=nil{return PeerVoteProjection{},err}
	lease,err:=store.LoadLease(ctx,promotion.LeaseID);if err!=nil||lease.GroupID!=promotion.GroupID||lease.ResourceID!=promotion.ResourceID||lease.HolderNodeID!=promotion.PreviousWriter||lease.FencingToken==0||lease.FencingToken==^uint64(0){return PeerVoteProjection{},ErrLeaseLost}
	if lease.AuthorityEpoch!=topology.AuthorityEpoch{return PeerVoteProjection{},ErrLeaseLost}
	membership:=PeerMembershipDigest(topology.GroupID,topology.Control)
	var raw []byte
	err=service.DB.QueryRowContext(ctx,`SELECT proposal_json FROM ha_peer_vote_proposals_v1 WHERE promotion_id=? AND promotion_generation=? AND membership_digest=?`,promotion.ID,promotion.Generation,membership).Scan(&raw)
	var proposal PeerVoteProposal
	if err==nil{if json.Unmarshal(raw,&proposal)!=nil||proposal.PlanDigest!=plan{return PeerVoteProjection{},ErrConflict}}else if errors.Is(err,sql.ErrNoRows){
		now:=service.now()
		proposal=PeerVoteProposal{ID:"ha_vote_"+federatedHADigest([]byte(string(promotion.ID)+"\x00"+plan+"\x00"+membership))[:48],Coordinator:topology.NodeID,GroupID:promotion.GroupID,ResourceID:promotion.ResourceID,PromotionID:promotion.ID,PromotionGeneration:promotion.Generation,PlanDigest:plan,Candidate:promotion.Candidate,PreviousWriter:promotion.PreviousWriter,PreviousLeaseID:lease.ID,PreviousFencingEpoch:lease.FencingToken,FencingEpoch:lease.FencingToken+1,TopologyEpoch:topology.Control.TopologyEpoch,MembershipDigest:membership,IssuedAt:now,ExpiresAt:now.Add(2*time.Minute)}
		proposal.AuthorityEpoch=topology.AuthorityEpoch
		_,err=service.DB.ExecContext(ctx,`INSERT INTO ha_peer_vote_proposals_v1(id,promotion_id,promotion_generation,membership_digest,proposal_json) VALUES(?,?,?,?,?)`,proposal.ID,promotion.ID,promotion.Generation,membership,mustPeerVoteJSON(proposal));if err!=nil{return PeerVoteProjection{},err}
	}else{return PeerVoteProjection{},err}
	if proposal.Validate(service.now())!=nil{return PeerVoteProjection{},ErrNoQuorum}
	proof:=PeerVoteProof{Proposal:proposal}
	var storedProof []byte
	if err=service.DB.QueryRowContext(ctx,`SELECT proof_json FROM ha_peer_vote_proposals_v1 WHERE id=?`,proposal.ID).Scan(&storedProof);err!=nil{return PeerVoteProjection{},err}
	if len(storedProof)!=0 {
		if json.Unmarshal(storedProof,&proof)!=nil{return PeerVoteProjection{},ErrConflict}
		return projectPeerVoteProof(topology,proposal,proof,storedProof,service.now())
	}
	for _,voter:=range topology.Control.Voters{
		var vote PeerPromotionVote
		if voter.NodeID==topology.NodeID{vote,err=service.Cast(ctx,topology.NodeID,proposal)}else{vote,err=service.Transport.RequestVote(ctx,voter,proposal)}
		if err==nil&&verifyPeerVote(topology,proposal,vote,service.now())==nil&&vote.VoterID==voter.NodeID{proof.Votes=append(proof.Votes,vote)}
	}
	if len(proof.Votes)<len(topology.Control.Voters)/2+1{return PeerVoteProjection{},ErrNoQuorum}
	sort.Slice(proof.Votes,func(i,j int)bool{return proof.Votes[i].VoterID<proof.Votes[j].VoterID})
	encoded:=mustPeerVoteJSON(proof)
	// Persist the actual signed evidence, not merely a count or digest.
	result,err:=service.DB.ExecContext(ctx,`UPDATE ha_peer_vote_proposals_v1 SET proof_json=? WHERE id=? AND proof_json IS NULL`,encoded,proposal.ID);if err!=nil{return PeerVoteProjection{},err}
	count,err:=result.RowsAffected();if err!=nil{return PeerVoteProjection{},err}
	if count==0{if err=service.DB.QueryRowContext(ctx,`SELECT proof_json FROM ha_peer_vote_proposals_v1 WHERE id=?`,proposal.ID).Scan(&encoded);err!=nil||json.Unmarshal(encoded,&proof)!=nil{return PeerVoteProjection{},ErrConflict}}
	return projectPeerVoteProof(topology,proposal,proof,encoded,service.now())
}

func projectPeerVoteProof(topology PeerVoteTopology,proposal PeerVoteProposal,proof PeerVoteProof,encoded []byte,now time.Time)(PeerVoteProjection,error){
	seen:=map[NodeID]bool{};ids:=[]NodeID{}
	for _,vote:=range proof.Votes{if seen[vote.VoterID]||verifyPeerVote(topology,proposal,vote,now)!=nil{return PeerVoteProjection{},ErrNoQuorum};seen[vote.VoterID]=true;ids=append(ids,vote.VoterID)}
	if proof.Proposal.Digest()!=proposal.Digest()||len(ids)<len(topology.Control.Voters)/2+1{return PeerVoteProjection{},ErrNoQuorum}
	return PeerVoteProjection{ProposalID:proposal.ID,ProofDigest:federatedHADigest(encoded),MembershipDigest:proposal.MembershipDigest,TopologyEpoch:proposal.TopologyEpoch,FencingEpoch:proposal.FencingEpoch,Voters:ids,Required:len(topology.Control.Voters)/2+1,ExpiresAt:proposal.ExpiresAt,State:"prepared_not_authorized_for_lease"},nil
}

func mustPeerVoteJSON(value any)[]byte{raw,_:=json.Marshal(value);return raw}

type PromotionQuorumAuthority interface { PromotionQuorum(context.Context,Promotion)(QuorumObservation,error) }
type LeaseTransferVerifier interface { VerifyLeaseTransfer(context.Context,WriterLease,QuorumObservation)error }

// No prepare proof can cross this boundary. The follow-up transfer protocol
// must prove old-writer enforcement with an exact post-fence certificate.
func (*PeerVoteService) PromotionQuorum(context.Context,Promotion)(QuorumObservation,error){return QuorumObservation{},ErrNoQuorum}
