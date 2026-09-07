//go:build linux

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

type federationRuntimeIngress interface {
	federation.SchemaRegistry
	federation.AuthorityVerifier
	federation.LocalPolicy
	federation.CommandGateway
	Capabilities() []federation.Capability
}

// Feature adapters register their existing local authority boundary here.
// No configured adapter means lifecycle/telemetry only, never a permissive
// synthetic grant or a direct invocation of privileged executors.
var federationIngressFactory func(context.Context, *sql.DB, federation.ID, federation.ID, *localMariaDBHAProviders, func() time.Time) (federationRuntimeIngress, error)

func startFederationRuntime(ctx context.Context, db *sql.DB, providers *localMariaDBHAProviders) error {
	if ctx == nil || db == nil || providers == nil {
		return federation.ErrInvalid
	}
	store, err := federation.NewStore(db)
	if err != nil {
		return err
	}
	go superviseFederationRuntime(ctx, store, db, providers)
	return nil
}

func superviseFederationRuntime(ctx context.Context, store *federation.Store, db *sql.DB, providers *localMariaDBHAProviders) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var runningCancel context.CancelFunc
	var runningDone chan error
	var runningPeer federation.ID
	var runningCertificate string
	var runningEpoch uint64
	retryAfter := time.Time{}
	stop := func() {
		if runningCancel != nil {
			runningCancel()
			<-runningDone
			runningCancel, runningDone = nil, nil
		}
	}
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-runningDone:
			if runningCancel != nil { runningCancel() }
			runningCancel, runningDone = nil, nil
			retryAfter = time.Now().Add(5*time.Second)
		case <-ticker.C:
			node, epoch, peerID, err := store.State(ctx)
			if err != nil || peerID == "" {
				stop()
				continue
			}
			peer, err := store.Peer(ctx, peerID)
			if err != nil || peer.State != "active" {
				stop()
				continue
			}
			if runningCancel != nil && (runningPeer != peerID || runningCertificate != peer.NodeCertificateRef || runningEpoch != epoch) {
				stop()
				retryAfter = time.Time{}
			}
			if runningCancel != nil || time.Now().Before(retryAfter) {
				continue
			}
			runner, err := composeFederationRunner(ctx, store, db, providers, node, peerID)
			if err != nil {
				// Keep optional central failure out of standalone startup. Do not
				// emit certificate, key-reference, credential, or remote payloads.
				log.Print("federation runner unavailable; local workloads remain independent")
				retryAfter = time.Now().Add(time.Minute)
				continue
			}
			// Recheck after material loading so a concurrent activation or
			// local revoke cannot be hidden by the loading interval.
			current, err := store.Peer(ctx, peerID)
			_, currentEpoch, currentPeer, stateErr := store.State(ctx)
			if err != nil || stateErr != nil || currentPeer != peerID || currentEpoch != epoch || current.NodeCertificateRef != peer.NodeCertificateRef {
				continue
			}
			runContext, cancel := context.WithCancel(ctx)
			runningCancel, runningDone = cancel, make(chan error, 1)
			runningPeer, runningCertificate, runningEpoch = peerID, peer.NodeCertificateRef, epoch
			go func(active *federation.OutboundRunner, activeContext context.Context, done chan<- error) { done <- active.Run(activeContext) }(runner, runContext, runningDone)
		}
	}
}

func composeFederationRunner(ctx context.Context, store *federation.Store, db *sql.DB, providers *localMariaDBHAProviders, node, peer federation.ID) (*federation.OutboundRunner, error) {
	materialClient, err := secrets.NewLocalMaterialClient()
	if err != nil {
		return nil, err
	}
	material, err := (federation.EnrolledMaterialLoader{Store: store, Material: materialClient, Now: time.Now}).Load(ctx, peer)
	if err != nil {
		return nil, err
	}
	if err = configureFederationStreamEndpoint(material); err != nil {
		return nil, err
	}
	var ingress federationRuntimeIngress = unavailableFederationIngress{}
	if federationIngressFactory != nil {
		configured, loadErr := federationIngressFactory(ctx, db, node, peer, providers, time.Now)
		if loadErr != nil { return nil, loadErr }
		if configured != nil { ingress = configured }
	}
	agent, err := material.NewAgent(ingress, ingress, ingress, ingress)
	if err != nil {
		return nil, err
	}
	buildDigest, err := certificates.CurrentExecutableDigest()
	if err != nil {
		return nil, err
	}
	capabilities := func(ctx context.Context) (federation.CapabilitySet, error) {
		currentNode, epoch, activePeer, err := store.State(ctx)
		if err != nil { return federation.CapabilitySet{}, err }
		if currentNode != node || activePeer != peer { return federation.CapabilitySet{}, federation.ErrStale }
		value := federation.CapabilitySet{NodeID: node, ProtocolVersion: federationEnrollmentProtocolVersion, BuildDigest: buildDigest, OS: runtime.GOOS, Architecture: runtime.GOARCH, AuthorityEpoch: epoch, Capabilities: ingress.Capabilities(), GeneratedAt: time.Now().UTC()}
		value.Digest = value.CanonicalDigest()
		return value, nil
	}
	return material.NewRunner(agent, capabilities)
}

func configureFederationStreamEndpoint(material *federation.EnrolledRunnerMaterial) error {
	const configPath = "/etc/cyberpanel/federation/outbound.json"
	content, err := readCoreFile(configPath, 4096, true)
	if errors.Is(err, os.ErrNotExist) {
		// The saved enrollment endpoint remains the baseline for deployments
		// serving both protocols on the same address. Separate listeners must
		// explicitly supply the stream address; no guessed port is used.
		return nil
	}
	if err != nil { return err }
	var config struct { StreamEndpoint string `json:"stream_endpoint"` }
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return federation.ErrInvalid
	}
	endpoint, err := url.Parse(config.StreamEndpoint)
	enrolled, enrolledErr := url.Parse(material.Endpoint)
	if err != nil || enrolledErr != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Hostname() != enrolled.Hostname() || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.String() != config.StreamEndpoint {
		return federation.ErrForbidden
	}
	port := endpoint.Port()
	if port == "" { port = "443" }
	if value, parseErr := strconv.ParseUint(port, 10, 16); parseErr != nil || value == 0 { return federation.ErrInvalid }
	connector, ok := material.Connector.(*federation.TLSConnector)
	if !ok { return federation.ErrInvalid }
	connector.Address = net.JoinHostPort(endpoint.Hostname(), port)
	return nil
}

type unavailableFederationIngress struct{}

func (unavailableFederationIngress) Capabilities() []federation.Capability { return []federation.Capability{} }
func (unavailableFederationIngress) Capability(string) (federation.Capability, bool) { return federation.Capability{}, false }
func (unavailableFederationIngress) Decode(string, string, json.RawMessage) (any, error) { return nil, federation.ErrForbidden }
func (unavailableFederationIngress) VerifyGrant(context.Context, federation.MutationGrant) error { return federation.ErrForbidden }
func (unavailableFederationIngress) VerifyApproval(context.Context, federation.Intent) error { return federation.ErrForbidden }
func (unavailableFederationIngress) AuthorizeFederated(context.Context, federation.Intent, federation.MutationGrant, any) error { return federation.ErrForbidden }
func (unavailableFederationIngress) SubmitFederated(context.Context, federation.FederatedCommand) (federation.LocalResult, error) { return federation.LocalResult{}, federation.ErrForbidden }
func (unavailableFederationIngress) ObserveEffect(context.Context, string) (federation.LocalResult, error) { return federation.LocalResult{}, federation.ErrForbidden }
