//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

type mariaDBReplicationProvisionReceipt struct {
	SecretID       secrets.ID `json:"secret_id"`
	Version        uint64     `json:"version"`
	BindingDigest  string     `json:"binding_digest"`
	RequestDigest  string     `json:"request_digest"`
	AudienceDigest string     `json:"audience_digest"`
	CompletedAt    time.Time  `json:"completed_at"`
}

// Only the channel identifier is argv. Credentials must arrive on stdin from
// the operator, never in arguments, environment variables or a config file.
func provisionMariaDBReplication(channelText string) error {
	if os.Geteuid() != 0 {
		return database.ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	binding, node, epoch, err := ha.ReadStaticReplicationBinding(ha.ChannelID(channelText))
	if err != nil {
		return err
	}
	recovery, err := apiserver.NewRecoveryClient("/run/cyberpanel-core/recovery.sock")
	if err != nil {
		return err
	}
	if err = recovery.VerifyStaticHAReplication(ctx, binding, node, epoch); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil {
		return err
	}
	defer func() { for index := range raw { raw[index] = 0 } }()
	credential, err := database.DecodeMariaDBReplicationCredential(raw)
	if err != nil {
		return err
	}
	defer credential.Wipe()
	if credential.ChannelID != binding.ChannelID || credential.AuthorityEpoch != epoch {
		return database.ErrUnauthorized
	}
	if binding.LocalRole == "source" {
		if credential.SourceNodeID != node || credential.TargetNodeID != binding.PeerNodeID {
			return database.ErrUnauthorized
		}
	} else if binding.LocalRole == "target" {
		if credential.TargetNodeID != node || credential.SourceNodeID != binding.PeerNodeID {
			return database.ErrUnauthorized
		}
	} else {
		return database.ErrUnauthorized
	}
	material, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	defer func() { for index := range material { material[index] = 0 } }()
	materialHash := sha256.Sum256(material)
	materialDigest := hex.EncodeToString(materialHash[:])
	client, err := secrets.NewLocalManagementClient()
	if err != nil {
		return err
	}
	release, err := apps.LinuxApplicationExecutorDigest()
	if err != nil {
		return err
	}
	owner, err := secrets.NewID("installation")
	if err != nil {
		return err
	}
	secretID := database.DatabaseSecretRecordID(binding.PurposeKeyRef)
	audience := secrets.AudienceBinding{AdapterID: database.MariaDBSecretAdapterID, AdapterVersion: database.MariaDBSecretAdapterVersion,
		Account: "local-mariadb", Origin: "local://panel-execd/mariadb", ResourceKind: "database_replication_channel",
		ResourceID: database.DatabaseAudienceID("replication-" + string(binding.ChannelID)), ResourceGeneration: binding.ChannelGeneration,
		Operations: []secrets.Operation{secrets.OperationAuthenticate}, ConsumerReleaseDigest: release}
	audienceDigest := rebootcontrol.ExecutionDigest(audience)
	requestDigest := rebootcontrol.ExecutionDigest(struct {
		Binding          ha.StaticReplicationBinding
		Node             ha.NodeID
		AuthorityEpoch   uint64
		DeploymentDigest string
		DeploymentEpoch  uint64
		SecretID         secrets.ID
		Owner            secrets.ID
		Audience         secrets.AudienceBinding
		MaterialDigest   string
	}{binding, node, epoch, binding.DeploymentDigest, binding.DeploymentEpoch, secretID, owner, audience, materialDigest})
	if audienceDigest == "" || requestDigest == "" {
		return database.ErrInvalidResource
	}
	controlUID, _, err := siteops.LookupControlIdentity()
	if err != nil {
		return err
	}
	admission, err := openExecutionAdmission(controlUID)
	if err != nil {
		return err
	}
	defer admission.DB.Close()
	lease, err := admission.AdmitExecution(ctx, rebootcontrol.ExecutionBinding{Boundary: "mariadb-replication-provision", Method: "put_exact",
		EffectID: "mariadb-replication-" + requestDigest, RequestDigest: requestDigest, Caller: "root-standalone-provisioner",
		Resource: rebootcontrol.ExecutionResource(struct {
			Channel          ha.ChannelID
			Generation       uint64
			Role             string
			Node             ha.NodeID
			Peer             ha.NodeID
			DeploymentDigest string
			DeploymentEpoch  uint64
			SecretID         secrets.ID
			AudienceDigest   string
		}{binding.ChannelID, binding.ChannelGeneration, binding.LocalRole, node, binding.PeerNodeID, binding.DeploymentDigest,
			binding.DeploymentEpoch, secretID, audienceDigest})})
	if err != nil {
		return err
	}
	if len(lease.Cached) != 0 {
		var receipt mariaDBReplicationProvisionReceipt
		if json.Unmarshal(lease.Cached, &receipt) != nil || !validMariaDBReplicationProvisionReceipt(receipt, secretID, requestDigest, audienceDigest) {
			return rebootcontrol.ErrIntegrity
		}
		return writeMariaDBReplicationProvisionReceipt(receipt)
	}
	defer func() { _ = rebootcontrol.SettleExecution(admission, lease, false, nil) }()
	metadata, err := client.PutExact(ctx, secrets.PutRequest{ID: secretID, OwnerTenantID: owner, Purpose: secrets.PurposeDatabase,
		Audience: audience, Plaintext: material})
	if err != nil {
		return err
	}
	if metadata.Validate() != nil || metadata.ID != secretID || metadata.OwnerTenantID != owner || metadata.Purpose != secrets.PurposeDatabase ||
		metadata.Version != 1 || metadata.State != secrets.StateActive || rebootcontrol.ExecutionDigest(metadata.Audience) != audienceDigest {
		return rebootcontrol.ErrIntegrity
	}
	receipt := mariaDBReplicationProvisionReceipt{SecretID: metadata.ID, Version: metadata.Version, BindingDigest: metadata.BindingDigest,
		RequestDigest: requestDigest, AudienceDigest: audienceDigest, CompletedAt: time.Now().UTC()}
	if !validMariaDBReplicationProvisionReceipt(receipt, secretID, requestDigest, audienceDigest) {
		return rebootcontrol.ErrIntegrity
	}
	if err = rebootcontrol.SettleExecution(admission, lease, true, receipt); err != nil {
		return err
	}
	return writeMariaDBReplicationProvisionReceipt(receipt)
}

func validMariaDBReplicationProvisionReceipt(receipt mariaDBReplicationProvisionReceipt, secretID secrets.ID, requestDigest, audienceDigest string) bool {
	if receipt.SecretID != secretID || receipt.Version != 1 || receipt.RequestDigest != requestDigest || receipt.AudienceDigest != audienceDigest ||
		receipt.CompletedAt.IsZero() || receipt.CompletedAt.After(time.Now().UTC().Add(time.Minute)) {
		return false
	}
	for _, digest := range []string{receipt.BindingDigest, receipt.RequestDigest, receipt.AudienceDigest} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size {
			return false
		}
	}
	return true
}

func writeMariaDBReplicationProvisionReceipt(receipt mariaDBReplicationProvisionReceipt) error {
	return json.NewEncoder(os.Stdout).Encode(struct {
		SecretID      secrets.ID `json:"secret_id"`
		Version       uint64     `json:"version"`
		BindingDigest string     `json:"binding_digest"`
	}{receipt.SecretID, receipt.Version, receipt.BindingDigest})
}
