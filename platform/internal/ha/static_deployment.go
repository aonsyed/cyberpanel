package ha

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const StaticDeploymentKeyPath = "/etc/cyberpanel/trust/ha-deployment.pub"
const StaticDeploymentIngressPath = "/etc/cyberpanel/ha/federated-ingress.json"

type FederatedIngressTrust struct {
	TenantID string `json:"tenant_id"`
	NodeID federation.ID `json:"node_id"`
	PeerID federation.ID `json:"peer_id"`
	GroupID NodeGroupID `json:"group_id"`
	GrantKeys map[string][]byte `json:"grant_keys"`
	ApprovalKeys map[string][]byte `json:"approval_keys"`
	GrantIDs []federation.ID `json:"grant_ids"`
}

// StaticDeployment deliberately cannot carry leases, promotions, quorum votes,
// health evidence, traffic activations or fence receipts. Nodes are offline and
// the database topology is unobserved until node-owned runtime observation.
type StaticDeployment struct {
	Version uint32 `json:"version"`
	ID federation.ID `json:"id"`
	DeploymentEpoch uint64 `json:"deployment_epoch"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	SigningKeyID string `json:"signing_key_id"`
	Trust FederatedIngressTrust `json:"trust"`
	Group NodeGroup `json:"group"`
	Nodes []NodeMember `json:"nodes"`
	Cluster DatabaseCluster `json:"cluster"`
	Grants []federation.MutationGrant `json:"grants"`
	ReplicationBindings []StaticReplicationBinding `json:"replication_bindings,omitempty"`
	PeerControl *PeerControl `json:"peer_control,omitempty"`
	Signature []byte `json:"signature"`
}

type StaticReplicationBinding struct {
	ChannelID ChannelID `json:"channel_id"`
	ChannelGeneration uint64 `json:"channel_generation"`
	LocalRole string `json:"local_role"`
	PeerNodeID NodeID `json:"peer_node_id"`
	PeerAddress string `json:"peer_address"`
	PeerCIDRs []string `json:"peer_cidrs"`
	PeerSPKI string `json:"peer_spki"`
	TLSCAPath string `json:"tls_ca_path"`
	PurposeKeyRef string `json:"purpose_key_ref"`
	EncryptionProfile string `json:"encryption_profile"`
	DeploymentDigest string `json:"-"`
	DeploymentEpoch uint64 `json:"-"`
}

type StaticReplicationAuthorityRequest struct {
	Binding StaticReplicationBinding `json:"binding"`
	NodeID NodeID `json:"node_id"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	DeploymentDigest string `json:"deployment_digest"`
	DeploymentEpoch uint64 `json:"deployment_epoch"`
}

type StaticDeploymentFile struct { Deployment StaticDeployment `json:"deployment"` }
type StaticDeploymentReceipt struct {
	ID federation.ID `json:"id"`
	NodeID federation.ID `json:"node_id"`
	DeploymentEpoch uint64 `json:"deployment_epoch"`
	Digest string `json:"digest"`
	State string `json:"state"`
	RestartRequired bool `json:"restart_required"`
}

func StaticDeploymentSignaturePayload(bundle StaticDeployment) ([]byte, error) {
	bundle.Signature = nil
	return json.Marshal(struct { Domain string `json:"domain"`; Bundle StaticDeployment `json:"bundle"` }{"cyberpanel-ha-static-deployment-v1", bundle})
}

func StaticDeploymentDigest(bundle StaticDeployment) (string, error) {
	raw, err := json.Marshal(bundle)
	if err != nil { return "", err }
	return federatedHADigest(raw), nil
}

func VerifyStaticDeployment(bundle StaticDeployment, now time.Time) error {
	key, err := ReadStaticDeploymentFile(StaticDeploymentKeyPath, ed25519.PublicKeySize)
	if err != nil || len(key) != ed25519.PublicKeySize { return ErrForbidden }
	raw, err := StaticDeploymentSignaturePayload(bundle)
	if err != nil || len(raw) > 1<<20 || !ed25519.Verify(ed25519.PublicKey(key), raw, bundle.Signature) { return ErrForbidden }
	t := bundle.Trust
	standalone := bundle.PeerControl != nil && t.PeerID == ""
	if bundle.Version != 1 || !bundle.ID.Valid() || bundle.DeploymentEpoch == 0 || bundle.AuthorityEpoch == 0 || !federation.ID(bundle.SigningKeyID).Valid() || bundle.IssuedAt.IsZero() || bundle.IssuedAt.After(now) || !now.Before(bundle.ExpiresAt) || !bundle.ExpiresAt.After(bundle.IssuedAt) || bundle.ExpiresAt.Sub(bundle.IssuedAt) > 365*24*time.Hour || t.TenantID != "system" || !t.NodeID.Valid() || !standalone && !t.PeerID.Valid() || t.GroupID != bundle.Group.ID { return ErrForbidden }
	if bundle.Group.Validate() != nil || bundle.Group.Generation != 1 || bundle.Group.AutomaticFailover || bundle.Group.State != "forming" || len(bundle.Nodes) < 2 || len(bundle.Nodes) > 128 || bundle.Cluster.Validate() != nil || bundle.Cluster.ID != ID(LocalMariaDBResourceID) || bundle.Cluster.GroupID != bundle.Group.ID || bundle.Cluster.Topology != DatabasePrimaryReplica || bundle.Cluster.Generation != 1 || bundle.Cluster.State != "unobserved" || bundle.Cluster.WriterNodeID != "" || bundle.Cluster.WriterLeaseID != "" || bundle.Cluster.PrimaryComponentDigest != "" { return ErrForbidden }
	nodes := map[NodeID]bool{}
	for _, node := range bundle.Nodes {
		if node.Validate() != nil || node.Generation != 1 || node.GroupID != bundle.Group.ID || node.State != NodeOffline || nodes[node.ID] || t.NodeID != "local" && node.ID == "local" { return ErrForbidden }
		nodes[node.ID] = true
	}
	if !nodes[NodeID(t.NodeID)] { return ErrForbidden }
	members := map[NodeID]bool{}
	for _, member := range bundle.Cluster.Members {
		// Only the enrolled owning node is represented by the executor alias.
		identity := member.NodeID
		if identity == "local" { identity = NodeID(t.NodeID) }
		if !nodes[identity] || members[identity] || t.NodeID != "local" && member.NodeID == NodeID(t.NodeID) || member.State != DBJoining || member.ClusterStatus != "Unknown" || !member.ReadOnly || member.PublicListener || member.GTID != "" || member.Sequence != 0 { return ErrForbidden }
		members[identity] = true
	}
	if !members[NodeID(t.NodeID)] || len(members) != len(nodes) || int(bundle.Cluster.DesiredVotingMembers) != len(members) { return ErrForbidden }
	if !standalone && (len(t.GrantKeys) == 0 || len(t.ApprovalKeys) == 0 || len(t.GrantIDs) == 0) || len(t.GrantKeys) > 16 || len(t.ApprovalKeys) > 16 || len(t.GrantIDs) > 128 || len(bundle.Grants) != len(t.GrantIDs) || standalone && len(bundle.Grants) != 0 { return ErrForbidden }
	if bundle.PeerControl != nil {
		if bundle.PeerControl.Validate(bundle.Group,bundle.Nodes) != nil || bundle.PeerControl.TopologyDigest != PeerStaticTopologyDigest(bundle) { return ErrNoQuorum }
		local := false
		for _, voter := range bundle.PeerControl.Voters { if voter.NodeID == NodeID(t.NodeID) { local = true } }
		if !local { return ErrNoQuorum }
	}
	for _, keys := range []map[string][]byte{t.GrantKeys, t.ApprovalKeys} { for id, key := range keys { if !federation.ID(id).Valid() || len(key) != ed25519.PublicKeySize { return ErrForbidden } } }
	ids := map[federation.ID]bool{}
	for _, id := range t.GrantIDs { if !id.Valid() || ids[id] { return ErrForbidden }; ids[id] = true }
	seen := map[federation.ID]bool{}
	for _, grant := range bundle.Grants {
		if !ids[grant.ID] || seen[grant.ID] || grant.Validate(now) != nil || grant.NodeID != t.NodeID || grant.PeerID != t.PeerID || grant.AuthorityEpoch != bundle.AuthorityEpoch || grant.IssuedAt.After(now) || grant.MaximumRisk != federation.RiskCritical { return ErrForbidden }
		message, err := FederatedHAGrantSignaturePayload(grant)
		key := t.GrantKeys[grant.SignatureKeyID]
		if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key), message, grant.Signature) { return ErrForbidden }
		for _, selector := range grant.Selectors {
			if selector.Kind != "ha" || selector.TenantID != t.TenantID || selector.ResourceID != LocalMariaDBResourceID || selector.LabelSelector != "" || len(selector.Operations) == 0 { return ErrForbidden }
			for _, command := range selector.Operations {
				allowed := false
				for _, capability := range FederatedHACommandCapabilities() { if capability.CommandType == command { allowed = true } }
				if !allowed { return ErrForbidden }
			}
		}
		seen[grant.ID] = true
	}
	if len(bundle.ReplicationBindings) > 128 { return ErrForbidden }
	channels := map[ChannelID]bool{}
	for _, binding := range bundle.ReplicationBindings {
		if !validID(string(binding.ChannelID)) || channels[binding.ChannelID] || binding.ChannelGeneration == 0 || binding.LocalRole != "source" && binding.LocalRole != "target" || !nodes[binding.PeerNodeID] || binding.PeerNodeID == NodeID(t.NodeID) || !validDigest(binding.PeerSPKI) || binding.TLSCAPath != "/etc/cyberpanel/ha/replication-ca.pem" || binding.PurposeKeyRef == "" || len(binding.PurposeKeyRef) > 256 || strings.ContainsAny(binding.PurposeKeyRef,"\x00\r\n\t ") || binding.EncryptionProfile == "" || len(binding.EncryptionProfile) > 128 || strings.ContainsAny(binding.EncryptionProfile,"\x00\r\n\t ") { return ErrForbidden }
		endpoint, err := netip.ParseAddrPort(binding.PeerAddress)
		if err != nil || endpoint.String() != binding.PeerAddress || endpoint.Port() != 3306 || !endpoint.Addr().IsPrivate() || endpoint.Addr().Is4In6() || len(binding.PeerCIDRs) == 0 || len(binding.PeerCIDRs) > 16 { return ErrForbidden }
		contains := false
		for _, rawPrefix := range binding.PeerCIDRs {
			prefix, err := netip.ParsePrefix(rawPrefix)
			if err != nil || prefix.Masked() != prefix || prefix.String() != rawPrefix { return ErrForbidden }
			private := false
			for _, privateRange := range []string{"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","fc00::/7"} { block := netip.MustParsePrefix(privateRange); if block.Addr().BitLen() == prefix.Addr().BitLen() && block.Contains(prefix.Addr()) && prefix.Bits() >= block.Bits() { private = true } }
			if !private { return ErrForbidden }; if prefix.Contains(endpoint.Addr()) { contains = true }
		}
		if !contains { return ErrForbidden }
		ca, err := ReadStaticDeploymentFile(binding.TLSCAPath,1<<20)
		if err != nil || !x509.NewCertPool().AppendCertsFromPEM(ca) { return ErrForbidden }
		channels[binding.ChannelID] = true
	}
	return nil
}

func ReadStaticReplicationBinding(channel ChannelID) (StaticReplicationBinding,NodeID,uint64,error) {
	if !validID(string(channel)) { return StaticReplicationBinding{},"",0,ErrInvalid }
	file, err := readSignedStaticDeployment()
	if err != nil { return StaticReplicationBinding{},"",0,err }
	digest, err := StaticDeploymentDigest(file.Deployment)
	if err != nil { return StaticReplicationBinding{},"",0,err }
	for _, binding := range file.Deployment.ReplicationBindings {
		if binding.ChannelID == channel {
			binding.DeploymentDigest, binding.DeploymentEpoch = digest, file.Deployment.DeploymentEpoch
			return binding,NodeID(file.Deployment.Trust.NodeID),file.Deployment.AuthorityEpoch,nil
		}
	}
	return StaticReplicationBinding{},"",0,ErrForbidden
}

func readSignedStaticDeployment() (StaticDeploymentFile,error) {
	var file StaticDeploymentFile
	raw, err := ReadStaticDeploymentFile(StaticDeploymentIngressPath,1<<20)
	if err != nil { return file,err }
	decoder := json.NewDecoder(bytes.NewReader(raw)); decoder.DisallowUnknownFields()
	if decoder.Decode(&file) != nil || decoder.Decode(&struct{}{}) != io.EOF || VerifyStaticDeployment(file.Deployment,time.Now().UTC()) != nil { return file,ErrForbidden }
	return file,nil
}

// VerifyReplicationAuthority proves only live deployment identity/epoch. The
// caller must separately verify current channel generation and dynamic fence
// or checkpoint evidence; a static bundle never supplies those proofs.
func (service *StaticDeploymentService) VerifyReplicationAuthority(ctx context.Context, request StaticReplicationAuthorityRequest) error {
	if service == nil || service.DB == nil || ctx == nil { return ErrInvalid }
	file, err := readSignedStaticDeployment()
	if err != nil { return err }
	trust, err := AdmittedStaticDeploymentTrust(ctx,service.DB,file.Deployment)
	if err != nil { return err }
	digest, err := StaticDeploymentDigest(file.Deployment)
	if err != nil || request.DeploymentDigest != digest || request.DeploymentEpoch != file.Deployment.DeploymentEpoch || request.AuthorityEpoch != file.Deployment.AuthorityEpoch || request.NodeID != NodeID(trust.NodeID) { return ErrForbidden }
	for _, binding := range file.Deployment.ReplicationBindings {
		left, _ := json.Marshal(binding); right, _ := json.Marshal(request.Binding)
		if bytes.Equal(left,right) { return nil }
	}
	return ErrForbidden
}

const staticDeploymentSchema = `CREATE TABLE IF NOT EXISTS ha_static_deployments_v1 (
 node_id TEXT PRIMARY KEY, bundle_id TEXT NOT NULL UNIQUE, deployment_epoch INTEGER NOT NULL,
 authority_epoch INTEGER NOT NULL, bundle_digest TEXT NOT NULL, topology_digest TEXT NOT NULL,
 admitted_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS ha_static_deployment_grants_v1 (
 node_id TEXT NOT NULL, grant_id TEXT NOT NULL, deployment_epoch INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','staged','revoked')),
 PRIMARY KEY(node_id,grant_id)
);`

type StaticDeploymentService struct { DB *sql.DB }

func (service *StaticDeploymentService) Admit(ctx context.Context, bundle StaticDeployment) (StaticDeploymentReceipt, error) {
	var receipt StaticDeploymentReceipt
	if service == nil || service.DB == nil || ctx == nil { return receipt, ErrInvalid }
	if err := VerifyStaticDeployment(bundle, time.Now().UTC()); err != nil { return receipt, err }
	digest, err := StaticDeploymentDigest(bundle)
	if err != nil { return receipt, err }
	topology, err := json.Marshal(struct { Group NodeGroup; Nodes []NodeMember; Cluster DatabaseCluster }{bundle.Group, bundle.Nodes, bundle.Cluster})
	if err != nil { return receipt, err }
	topologyDigest := federatedHADigest(topology)
	if _, err = service.DB.ExecContext(ctx, staticDeploymentSchema); err != nil { return receipt, err }
	if _, err = service.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ha_peer_topology_admissions_v1(group_id TEXT PRIMARY KEY,topology_epoch INTEGER NOT NULL,membership_digest TEXT NOT NULL)`); err != nil { return receipt, err }
	tx, err := service.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return receipt, err }
	defer tx.Rollback()
	var node, peer federation.ID
	var epoch uint64
	if bundle.PeerControl != nil && bundle.Trust.PeerID == "" {
		node,epoch = bundle.Trust.NodeID,bundle.AuthorityEpoch
	} else {
		if err = tx.QueryRowContext(ctx, `SELECT node_id,authority_epoch,active_peer_id FROM federation_state WHERE singleton_id=1`).Scan(&node, &epoch, &peer); err != nil { return receipt, err }
		if node != bundle.Trust.NodeID || peer != bundle.Trust.PeerID || epoch != bundle.AuthorityEpoch { return receipt, ErrForbidden }
		var peerState string
		if err = tx.QueryRowContext(ctx, `SELECT state FROM federation_peers WHERE id=?`, peer).Scan(&peerState); err != nil || peerState != "active" { return receipt, ErrForbidden }
	}
	if bundle.PeerControl != nil {
		membership := PeerMembershipDigest(bundle.Group.ID,*bundle.PeerControl)
		var existing string
		err = tx.QueryRowContext(ctx,`SELECT membership_digest FROM ha_peer_topology_admissions_v1 WHERE group_id=?`,bundle.Group.ID).Scan(&existing)
		if err == nil && existing != membership { return receipt,ErrConflict }
		if err != nil && !errors.Is(err,sql.ErrNoRows) { return receipt,err }
		if errors.Is(err,sql.ErrNoRows) { if _,err=tx.ExecContext(ctx,`INSERT INTO ha_peer_topology_admissions_v1(group_id,topology_epoch,membership_digest) VALUES(?,?,?)`,bundle.Group.ID,bundle.PeerControl.TopologyEpoch,membership);err!=nil{return receipt,err} }
		// Membership changes require a future joint-quorum reconfiguration,
		// never an unilateral replacement by a new static deployment epoch.
	}
	var previousID, previousDigest, previousTopology string
	var previousEpoch uint64
	err = tx.QueryRowContext(ctx, `SELECT bundle_id,deployment_epoch,bundle_digest,topology_digest FROM ha_static_deployments_v1 WHERE node_id=?`, node).Scan(&previousID, &previousEpoch, &previousDigest, &previousTopology)
	first := errors.Is(err, sql.ErrNoRows)
	if err != nil && !first { return receipt, err }
	receipt = StaticDeploymentReceipt{ID: bundle.ID, NodeID: node, DeploymentEpoch: bundle.DeploymentEpoch, Digest: digest, State: "admitted", RestartRequired: true}
	if !first && bundle.DeploymentEpoch == previousEpoch {
		if previousID != bundle.ID.String() || previousDigest != digest { return StaticDeploymentReceipt{}, ErrConflict }
		return receipt, tx.Commit()
	}
	if first && bundle.DeploymentEpoch != 1 || !first && (bundle.DeploymentEpoch <= previousEpoch || bundle.ID.String() == previousID || previousTopology != topologyDigest) { return StaticDeploymentReceipt{}, ErrConflict }
	if first {
		groupRaw, _ := json.Marshal(bundle.Group)
		if err = insertStaticJSON(ctx, tx, `SELECT group_json FROM ha_node_groups WHERE id=?`, []any{bundle.Group.ID}, groupRaw, `INSERT INTO ha_node_groups(id,generation,group_json,updated_at) VALUES(?,?,?,?)`, bundle.Group.ID, bundle.Group.Generation, groupRaw, bundle.Group.UpdatedAt); err != nil { return StaticDeploymentReceipt{}, err }
		for _, member := range bundle.Nodes {
			raw, _ := json.Marshal(member)
			if err = insertStaticJSON(ctx, tx, `SELECT node_json FROM ha_nodes WHERE id=?`, []any{member.ID}, raw, `INSERT INTO ha_nodes(id,group_id,workload_identity,state,generation,node_json,updated_at) VALUES(?,?,?,?,?,?,?)`, member.ID, member.GroupID, member.WorkloadIdentity, member.State, member.Generation, raw, member.UpdatedAt); err != nil { return StaticDeploymentReceipt{}, err }
		}
		clusterRaw, _ := json.Marshal(bundle.Cluster)
		if err = insertStaticJSON(ctx, tx, `SELECT cluster_json FROM ha_database_clusters WHERE id=?`, []any{bundle.Cluster.ID}, clusterRaw, `INSERT INTO ha_database_clusters(id,group_id,topology,state,generation,cluster_json,updated_at) VALUES(?,?,?,?,?,?,?)`, bundle.Cluster.ID, bundle.Cluster.GroupID, bundle.Cluster.Topology, bundle.Cluster.State, bundle.Cluster.Generation, clusterRaw, bundle.Cluster.UpdatedAt); err != nil { return StaticDeploymentReceipt{}, err }
	}
	if peer.Valid() {
		if _, err = tx.ExecContext(ctx, `UPDATE federation_grants SET state='staged',updated_at=? WHERE id IN (SELECT grant_id FROM ha_static_deployment_grants_v1 WHERE node_id=? AND state='active') AND state='active'`, time.Now().UTC(), node); err != nil { return StaticDeploymentReceipt{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE ha_static_deployment_grants_v1 SET state='staged' WHERE node_id=? AND state='active'`, node); err != nil { return StaticDeploymentReceipt{}, err }
	}
	bindings := make(map[string]federation.FederatedPrincipalBinding)
	for _, grant := range bundle.Grants {
		for _, binding := range grant.PrincipalBindings {
			identity := binding.PeerID.String()+"\x00"+binding.Issuer+"\x00"+binding.Subject
			if prior, exists := bindings[identity]; exists {
				priorRaw, priorErr := json.Marshal(prior); bindingRaw, bindingErr := json.Marshal(binding)
				if priorErr != nil || bindingErr != nil || !sameStaticJSON(priorRaw,bindingRaw) { return StaticDeploymentReceipt{}, ErrConflict }
				continue
			}
			bindings[identity] = binding
		}
	}
	if peer.Valid() {
		if _, err = tx.ExecContext(ctx, `UPDATE federation_principal_bindings SET state='staged',updated_at=? WHERE peer_id=? AND state='active'`, time.Now().UTC(), peer); err != nil { return StaticDeploymentReceipt{}, err }
		for _, binding := range bindings {
			raw, marshalErr := json.Marshal(binding); if marshalErr != nil { return StaticDeploymentReceipt{}, marshalErr }
			result, execErr := tx.ExecContext(ctx, `INSERT INTO federation_principal_bindings(id,peer_id,issuer,subject,authorization_epoch,state,binding_json,expires_at,updated_at) VALUES(?,?,?,?,?,'active',?,?,?) ON CONFLICT(peer_id,issuer,subject) DO UPDATE SET id=excluded.id,authorization_epoch=excluded.authorization_epoch,state='active',binding_json=excluded.binding_json,expires_at=excluded.expires_at,updated_at=excluded.updated_at WHERE federation_principal_bindings.authorization_epoch<=excluded.authorization_epoch`, binding.ID,binding.PeerID,binding.Issuer,binding.Subject,binding.AuthorizationEpoch,raw,binding.ExpiresAt,time.Now().UTC())
			if execErr != nil { return StaticDeploymentReceipt{}, execErr }; if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 { return StaticDeploymentReceipt{}, ErrConflict }
		}
		if _, err = tx.ExecContext(ctx, `UPDATE federation_principal_bindings SET state='revoked',updated_at=? WHERE peer_id=? AND state='staged'`, time.Now().UTC(), peer); err != nil { return StaticDeploymentReceipt{}, err }
	}
	for _, grant := range bundle.Grants {
		raw, _ := json.Marshal(grant)
		var stored []byte
		var state string
		loadErr := tx.QueryRowContext(ctx, `SELECT grant_json,state FROM federation_grants WHERE id=?`, grant.ID).Scan(&stored, &state)
		if loadErr == nil {
			if state != "active" && state != "staged" || !sameStaticJSON(stored, raw) { return StaticDeploymentReceipt{}, ErrConflict }
			result, updateErr := tx.ExecContext(ctx, `UPDATE federation_grants SET state='active',updated_at=? WHERE id=? AND state IN ('active','staged')`, time.Now().UTC(), grant.ID)
			if updateErr != nil { return StaticDeploymentReceipt{}, updateErr }
			if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 { return StaticDeploymentReceipt{}, ErrConflict }
		} else {
			if !errors.Is(loadErr, sql.ErrNoRows) { return StaticDeploymentReceipt{}, loadErr }
			if _, err = tx.ExecContext(ctx, `INSERT INTO federation_grants(id,peer_id,authority_epoch,state,grant_json,expires_at,updated_at) VALUES(?,?,?,?,?,?,?)`, grant.ID, grant.PeerID, grant.AuthorityEpoch, "active", raw, grant.ExpiresAt, time.Now().UTC()); err != nil { return StaticDeploymentReceipt{}, err }
		}
		mappingResult, mappingErr := tx.ExecContext(ctx, `INSERT INTO ha_static_deployment_grants_v1(node_id,grant_id,deployment_epoch,state) VALUES(?,?,?,'active') ON CONFLICT(node_id,grant_id) DO UPDATE SET deployment_epoch=excluded.deployment_epoch,state='active' WHERE ha_static_deployment_grants_v1.state IN ('active','staged')`, node,grant.ID,bundle.DeploymentEpoch)
		if mappingErr != nil { return StaticDeploymentReceipt{}, mappingErr }
		if affected, rowsErr := mappingResult.RowsAffected(); rowsErr != nil || affected != 1 { return StaticDeploymentReceipt{}, ErrConflict }
	}
	if peer.Valid() {
		if _, err = tx.ExecContext(ctx, `UPDATE federation_grants SET state='revoked',updated_at=? WHERE id IN (SELECT grant_id FROM ha_static_deployment_grants_v1 WHERE node_id=? AND state='staged') AND state='staged'`, time.Now().UTC(), node); err != nil { return StaticDeploymentReceipt{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE ha_static_deployment_grants_v1 SET state='revoked' WHERE node_id=? AND state='staged'`, node); err != nil { return StaticDeploymentReceipt{}, err }
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ha_static_deployments_v1(node_id,bundle_id,deployment_epoch,authority_epoch,bundle_digest,topology_digest,admitted_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET bundle_id=excluded.bundle_id,deployment_epoch=excluded.deployment_epoch,authority_epoch=excluded.authority_epoch,bundle_digest=excluded.bundle_digest,admitted_at=excluded.admitted_at`, node, bundle.ID, bundle.DeploymentEpoch, epoch, digest, topologyDigest, time.Now().UTC())
	if err != nil { return StaticDeploymentReceipt{}, err }
	if err = tx.Commit(); err != nil { return StaticDeploymentReceipt{}, err }
	return receipt, nil
}

func insertStaticJSON(ctx context.Context, tx *sql.Tx, query string, args []any, raw []byte, insert string, values ...any) error {
	var existing []byte
	err := tx.QueryRowContext(ctx, query, args...).Scan(&existing)
	if err == nil { if !sameStaticJSON(existing, raw) { return ErrConflict }; return nil }
	if !errors.Is(err, sql.ErrNoRows) { return err }
	_, err = tx.ExecContext(ctx, insert, values...)
	return err
}

func sameStaticJSON(left, right []byte) bool {
	var a, b any
	d := json.NewDecoder(bytes.NewReader(left)); d.UseNumber()
	if d.Decode(&a) != nil { return false }
	d = json.NewDecoder(bytes.NewReader(right)); d.UseNumber()
	if d.Decode(&b) != nil { return false }
	x, _ := json.Marshal(a); y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func AdmittedStaticDeploymentTrust(ctx context.Context, db *sql.DB, bundle StaticDeployment) (FederatedIngressTrust, error) {
	if db == nil || ctx == nil || VerifyStaticDeployment(bundle, time.Now().UTC()) != nil { return FederatedIngressTrust{}, ErrForbidden }
	digest, err := StaticDeploymentDigest(bundle)
	if err != nil { return FederatedIngressTrust{}, err }
	var stored string
	if bundle.PeerControl != nil && bundle.Trust.PeerID == "" {
		err=db.QueryRowContext(ctx,`SELECT bundle_digest FROM ha_static_deployments_v1 WHERE node_id=? AND bundle_id=? AND deployment_epoch=? AND authority_epoch=?`,bundle.Trust.NodeID,bundle.ID,bundle.DeploymentEpoch,bundle.AuthorityEpoch).Scan(&stored)
		if err!=nil||stored!=digest{return FederatedIngressTrust{},ErrForbidden};return bundle.Trust,nil
	}
	err = db.QueryRowContext(ctx, `SELECT d.bundle_digest FROM ha_static_deployments_v1 d JOIN federation_state s ON s.node_id=d.node_id JOIN federation_peers p ON p.id=s.active_peer_id AND p.state='active' WHERE d.node_id=? AND d.bundle_id=? AND d.deployment_epoch=? AND d.authority_epoch=? AND s.authority_epoch=d.authority_epoch AND s.active_peer_id=?`, bundle.Trust.NodeID, bundle.ID, bundle.DeploymentEpoch, bundle.AuthorityEpoch, bundle.Trust.PeerID).Scan(&stored)
	if err != nil || stored != digest { return FederatedIngressTrust{}, ErrForbidden }
	return bundle.Trust, nil
}

// Peer HA authority survives loss of the optional central connection. Its
// committed deployment and voter membership are local root-admitted authority.
func LoadAdmittedPeerDeployment(ctx context.Context,db *sql.DB)(StaticDeployment,error){
	file,err:=readSignedStaticDeployment();if err!=nil{return StaticDeployment{},err}
	bundle:=file.Deployment
	if ctx==nil||db==nil||bundle.PeerControl==nil{return StaticDeployment{},ErrUnsupported}
	digest,err:=StaticDeploymentDigest(bundle);if err!=nil{return StaticDeployment{},err}
	var stored,membership string
	err=db.QueryRowContext(ctx,`SELECT d.bundle_digest,t.membership_digest FROM ha_static_deployments_v1 d JOIN ha_peer_topology_admissions_v1 t ON t.group_id=? WHERE d.node_id=? AND d.bundle_id=? AND d.deployment_epoch=? AND t.topology_epoch=?`,bundle.Group.ID,bundle.Trust.NodeID,bundle.ID,bundle.DeploymentEpoch,bundle.PeerControl.TopologyEpoch).Scan(&stored,&membership)
	if err!=nil||stored!=digest||membership!=PeerMembershipDigest(bundle.Group.ID,*bundle.PeerControl){return StaticDeployment{},ErrForbidden}
	return bundle,nil
}

func (service *StaticDeploymentService) Status(ctx context.Context) (StaticDeploymentReceipt, error) {
	if service == nil || service.DB == nil || ctx == nil { return StaticDeploymentReceipt{}, ErrInvalid }
	raw, err := ReadStaticDeploymentFile(StaticDeploymentIngressPath,1<<20)
	if err != nil { return StaticDeploymentReceipt{}, err }
	var file StaticDeploymentFile
	decoder := json.NewDecoder(bytes.NewReader(raw)); decoder.DisallowUnknownFields()
	if decoder.Decode(&file) != nil || decoder.Decode(&struct{}{}) != io.EOF { return StaticDeploymentReceipt{}, ErrForbidden }
	if _, err = AdmittedStaticDeploymentTrust(ctx,service.DB,file.Deployment); err != nil { return StaticDeploymentReceipt{}, err }
	digest, err := StaticDeploymentDigest(file.Deployment)
	if err != nil { return StaticDeploymentReceipt{}, err }
	return StaticDeploymentReceipt{ID:file.Deployment.ID,NodeID:file.Deployment.Trust.NodeID,DeploymentEpoch:file.Deployment.DeploymentEpoch,Digest:digest,State:"published",RestartRequired:true},nil
}

// ReadStaticDeploymentFile reads protected root-owned inputs, never a symlink
// or a file in a writable parent directory. Key and bundle size are bounded.
func ReadStaticDeploymentFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 || maximum > 1<<20 { return nil, ErrInvalid }
	if err := staticDeploymentParents(filepath.Dir(path), false); err != nil { return nil, err }
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil { return nil, err }
	defer file.Close()
	info, err := file.Stat()
	if err != nil { return nil, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > maximum { return nil, ErrForbidden }
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum { return nil, ErrInvalid }
	return raw, nil
}

func staticDeploymentParents(path string, create bool) error {
	if path == "/" { return nil }
	if err := staticDeploymentParents(filepath.Dir(path), create); err != nil { return err }
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && create && (path == "/etc/cyberpanel" || path == "/etc/cyberpanel/ha" || path == "/etc/cyberpanel/trust") { if err = os.Mkdir(path, 0755); err != nil { return err }; info, err = os.Lstat(path) }
	if err != nil { return err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 { return ErrForbidden }
	return nil
}

func LockStaticDeployment() (func(), error) {
	if os.Geteuid() != 0 { return nil, ErrForbidden }
	if err := staticDeploymentParents("/etc/cyberpanel/ha", true); err != nil { return nil, err }
	file, err := os.OpenFile("/etc/cyberpanel/ha/.deployment.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil { return nil, err }
	info, err := file.Stat()
	if err != nil { file.Close(); return nil, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 { file.Close(); return nil, ErrForbidden }
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { file.Close(); return nil, ErrConflict }
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}

// PublishStaticDeploymentFile is root-only. The database digest is admitted
// first; publication is an atomic rename and fsync. A crash between these steps
// leaves ingress disabled, not partially authorized, and exact replay repairs it.
func PublishStaticDeploymentFile(path string, raw []byte, replace bool) error {
	if os.Geteuid() != 0 || path != StaticDeploymentKeyPath && path != StaticDeploymentIngressPath || len(raw) == 0 || len(raw) > 1<<20 { return ErrForbidden }
	if err := staticDeploymentParents(filepath.Dir(path), true); err != nil { return err }
	existing, err := ReadStaticDeploymentFile(path, 1<<20)
	if err == nil { if bytes.Equal(existing, raw) { return nil }; if !replace { return ErrConflict } } else if !errors.Is(err, os.ErrNotExist) { return err }
	file, err := os.CreateTemp(filepath.Dir(path), ".ha-deployment-")
	if err != nil { return err }
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0444); err == nil { _, err = file.Write(raw) }
	if err == nil { err = file.Sync() }
	closeErr := file.Close()
	if err != nil { return err }; if closeErr != nil { return closeErr }
	if err = os.Rename(name, path); err != nil { return err }
	directory, err := os.Open(filepath.Dir(path))
	if err != nil { return err }; defer directory.Close()
	return directory.Sync()
}
