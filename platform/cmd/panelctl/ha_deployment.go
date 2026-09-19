package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

func haDeployment(arguments []string) error {
	if os.Geteuid() != 0 { return errors.New("HA deployment requires local root") }
	if len(arguments) == 0 { return errors.New("HA deployment requires trust, provision, status, quorum, or commit") }
	if arguments[0] != "trust" && arguments[0] != "provision" && arguments[0] != "status" && arguments[0] != "quorum" && arguments[0] != "commit" { return errors.New("HA deployment permits only trust, provision, status, quorum, and commit") }
	flags := flag.NewFlagSet("ha "+arguments[0],flag.ContinueOnError)
	keyPath := flags.String("public-key","","root-owned raw Ed25519 deployment public-key file")
	bundlePath := flags.String("bundle","","root-owned signed static deployment JSON file")
	promotionID := flags.String("promotion","","locally persisted promotion ID")
	channelID := flags.String("channel","","locally persisted replication channel ID for genesis commit")
	checkpointID := flags.String("checkpoint","","locally persisted replication checkpoint ID for genesis commit")
	bootstrap := flags.Bool("bootstrap",false,"create the one-time revoked-genesis successor")
	if err := flags.Parse(arguments[1:]); err != nil { return err }
	if flags.NArg() != 0 { return errors.New("unexpected HA deployment arguments") }
	client, err := apiserver.NewRecoveryClient("/run/cyberpanel-core/recovery.sock")
	if err != nil { return err }
	ctx, cancel := context.WithTimeout(context.Background(),30*time.Second)
	defer cancel()
	if arguments[0] == "quorum" {
		if *keyPath!=""||*bundlePath!=""||*promotionID==""||*channelID!=""||*checkpointID!=""||*bootstrap{return errors.New("quorum requires only --promotion")}
		proof,err:=client.CollectHAPeerVotes(ctx,ha.PromotionID(*promotionID));if err!=nil{return err};return printJSON(proof)
	}
	if arguments[0] == "commit" {
		if *keyPath!=""||*bundlePath!=""{return errors.New("commit does not accept file flags")}
		input:=ha.PeerCommitInput{PromotionID:ha.PromotionID(*promotionID),ChannelID:ha.ChannelID(*channelID),CheckpointID:ha.CheckpointID(*checkpointID),Bootstrap:*bootstrap}
		if *bootstrap {
			if *promotionID!=""||*channelID==""||*checkpointID==""{return errors.New("bootstrap commit requires only --bootstrap, --channel, and --checkpoint")}
		} else if *promotionID==""||*channelID!=""||*checkpointID!="" {
			return errors.New("commit requires only --promotion unless --bootstrap is set")
		}
		status,err:=client.CollectHAPeerCommit(ctx,input);if err!=nil{return err};return printJSON(status)
	}
	if *promotionID!=""||*channelID!=""||*checkpointID!=""||*bootstrap{return errors.New("promotion, channel, checkpoint, and bootstrap flags are valid only for quorum or commit")}
	if arguments[0] == "status" {
		if *keyPath != "" || *bundlePath != "" { return errors.New("status accepts no file flags") }
		status, err := client.StaticHAStatus(ctx)
		if err != nil { return err }; return printJSON(status)
	}
	unlock, err := ha.LockStaticDeployment()
	if err != nil { return err }
	defer unlock()
	switch arguments[0] {
	case "trust":
		if *keyPath == "" || *bundlePath != "" { return errors.New("trust requires only --public-key") }
		key, err := ha.ReadStaticDeploymentFile(*keyPath,ed25519.PublicKeySize)
		if err != nil || len(key) != ed25519.PublicKeySize { return errors.New("deployment public key must be a protected 32-byte Ed25519 key") }
		if err = ha.PublishStaticDeploymentFile(ha.StaticDeploymentKeyPath,key,false); err != nil { return err }
		digest := sha256.Sum256(key)
		return printJSON(map[string]string{"state":"trusted","public_key_sha256":hex.EncodeToString(digest[:]),"path":ha.StaticDeploymentKeyPath})
	case "provision":
		if *bundlePath == "" || *keyPath != "" { return errors.New("provision requires only --bundle") }
		raw, err := ha.ReadStaticDeploymentFile(*bundlePath,1<<20)
		if err != nil { return err }
		var file ha.StaticDeploymentFile
		if err = decodeStrict(raw,&file); err != nil { return err }
		if err = ha.VerifyStaticDeployment(file.Deployment,time.Now().UTC()); err != nil { return err }
		digest, err := ha.StaticDeploymentDigest(file.Deployment)
		if err != nil { return err }
		receipt, err := client.AdmitStaticHA(ctx,file)
		if err != nil { return err }
		if receipt.ID != file.Deployment.ID || receipt.NodeID != file.Deployment.Trust.NodeID || receipt.DeploymentEpoch != file.Deployment.DeploymentEpoch || receipt.Digest != digest || receipt.State != "admitted" { return errors.New("HA deployment admission receipt does not match the signed bundle") }
		encoded, err := json.Marshal(file)
		if err != nil { return err }
		if err = ha.PublishStaticDeploymentFile(ha.StaticDeploymentIngressPath,encoded,true); err != nil { return err }
		status, err := client.StaticHAStatus(ctx)
		if err != nil { return err }
		if status.Digest != digest || status.DeploymentEpoch != receipt.DeploymentEpoch || status.State != "published" { return errors.New("HA deployment publication requires reconciliation") }
		return printJSON(status)
	default: return errors.New("HA deployment permits only trust, provision, status, quorum, and commit")
	}
}
