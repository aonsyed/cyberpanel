//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

type haRootFenceObserver interface {
	ObserveDatabaseWriterFence(context.Context, json.RawMessage) (json.RawMessage, error)
	ObserveDatabaseWriterCandidate(context.Context, json.RawMessage) (json.RawMessage, error)
	WriterCertificateJSON(context.Context, json.RawMessage) (json.RawMessage, error)
}

func newHAPeerCommitRuntime(ctx context.Context, prepare *ha.PeerVoteService, transport *haPeerTransport, executor ha.DatabaseReplicationExecutor) (*ha.PeerCommitService, error) {
	root, available := executor.(haRootFenceObserver)
	service := &ha.PeerCommitService{Prepare: prepare, Transport: transport}
	service.ObserveLocal = func(ctx context.Context, plan ha.PeerCommitPlan, sourceFenceReceipt json.RawMessage) (ha.NodeFenceEvidence, error) {
		if !available {
			return ha.NodeFenceEvidence{}, ha.ErrUnsupported
		}
		cluster, err := (ha.SQLRepository{DB: prepare.DB}).LoadDatabaseCluster(ctx, ha.ID(plan.Lease.ResourceID))
		if err != nil {
			return ha.NodeFenceEvidence{}, err
		}
		topology, err := prepare.Topology(ctx)
		if err != nil {
			return ha.NodeFenceEvidence{}, err
		}
		var authority json.RawMessage
		if topology.NodeID == plan.Channel.SourceNodeID {
			authority, err = ha.LoadDatabaseSourceFenceAuthority(topology, plan, cluster)
			if err == nil {
				authority, err = root.ObserveDatabaseWriterFence(ctx, authority)
			}
		} else if topology.NodeID == plan.Channel.TargetNodeID {
			authority, err = ha.LoadDatabaseCandidateWriterAuthority(topology, plan, cluster, sourceFenceReceipt)
			if err == nil {
				authority, err = root.ObserveDatabaseWriterCandidate(ctx, authority)
			}
		} else {
			return ha.NodeFenceEvidence{}, ha.ErrForbidden
		}
		if err != nil {
			return ha.NodeFenceEvidence{}, err
		}
		var evidence ha.NodeFenceEvidence
		if err = decodeCanonicalHAPeerEvidence(authority, &evidence); err != nil {
			return ha.NodeFenceEvidence{}, err
		}
		return evidence, nil
	}
	service.CandidateLocal = func(ctx context.Context, plan ha.PeerCommitPlan, sourceFenceReceipt json.RawMessage) (ha.CandidateWriterEvidence, error) {
		if !available {
			return ha.CandidateWriterEvidence{}, ha.ErrUnsupported
		}
		cluster, err := (ha.SQLRepository{DB: prepare.DB}).LoadDatabaseCluster(ctx, ha.ID(plan.Lease.ResourceID))
		if err != nil {
			return ha.CandidateWriterEvidence{}, err
		}
		topology, err := prepare.Topology(ctx)
		if err != nil {
			return ha.CandidateWriterEvidence{}, err
		}
		authority, err := ha.LoadDatabaseCandidateWriterAuthority(topology, plan, cluster, sourceFenceReceipt)
		if err != nil {
			return ha.CandidateWriterEvidence{}, err
		}
		raw, err := root.WriterCertificateJSON(ctx, authority)
		if err != nil {
			return ha.CandidateWriterEvidence{}, err
		}
		var candidate ha.CandidateWriterEvidence
		if err = decodeCanonicalHAPeerEvidence(raw, &candidate); err != nil {
			return ha.CandidateWriterEvidence{}, err
		}
		if candidate.ClusterID != cluster.ID || candidate.ClusterGeneration != cluster.Generation {
			return ha.CandidateWriterEvidence{}, ha.ErrConflict
		}
		return candidate, nil
	}
	if err := service.Bootstrap(ctx); err != nil {
		return nil, err
	}
	// Existing writers are not replaced with genesis. A pristine admitted
	// topology receives only the deterministic revoked watermark.
	if _, err := service.ReconcileGenesis(ctx); err != nil {
		if !errors.Is(err, ha.ErrConflict) || !errors.Is(err, ha.ErrNotFound) {
			return nil, err
		}
	}
	return service, nil
}

func decodeCanonicalHAPeerEvidence(raw json.RawMessage, target any) error {
	if len(raw) == 0 || len(raw) > 256<<10 || target == nil {
		return ha.ErrInvalid
	}
	if err := decodeHAFederationJSON(raw, target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ha.ErrInvalid
	}
	return nil
}

func (transport *haPeerTransport) commitJSON(ctx context.Context, voter ha.PeerVoter, path string, input, target any) error {
	if path != "/v1/ha/commit-evidence" && path != "/v1/ha/commit-vote" && path != "/v1/ha/commit-certificate" {
		return ha.ErrForbidden
	}
	topology, err := transport.topology(ctx)
	if err != nil {
		return err
	}
	matched := false
	for _, configured := range topology.Control.Voters {
		if configured.NodeID == voter.NodeID && configured.Endpoint == voter.Endpoint && configured.SPKISHA256 == voter.SPKISHA256 {
			matched = true
		}
	}
	if !matched {
		return ha.ErrForbidden
	}
	u, err := url.Parse(voter.Endpoint)
	if err != nil {
		return err
	}
	configuration := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: transport.roots, ServerName: u.Hostname(), Certificates: []tls.Certificate{transport.certificate}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || haSenderDigest(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != voter.SPKISHA256 {
			return ha.ErrForbidden
		}
		return nil
	}}
	dialer := &net.Dialer{Timeout: time.Second}
	responseTimeout, requestTimeout := 5*time.Second, 6*time.Second
	if path != "/v1/ha/commit-evidence" {
		responseTimeout, requestTimeout = 13*time.Second, 14*time.Second
	}
	httpTransport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: configuration, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: responseTimeout, MaxResponseHeaderBytes: 8 << 10, DisableCompression: true, DisableKeepAlives: true, MaxConnsPerHost: 1}
	defer httpTransport.CloseIdleConnections()
	client := &http.Client{Transport: httpTransport, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ha.ErrForbidden }}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 256<<10 {
		return ha.ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, voter.Endpoint+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ha.ErrNoQuorum
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	if err != nil || len(body) > 256<<10 {
		return ha.ErrInvalid
	}
	return decodeHAFederationJSON(body, target)
}
func (transport *haPeerTransport) ObserveCommitNode(ctx context.Context, voter ha.PeerVoter, request ha.PeerCommitObservationRequest) (ha.PeerNodeEvidence, error) {
	var evidence ha.PeerNodeEvidence
	err := transport.commitJSON(ctx, voter, "/v1/ha/commit-evidence", request, &evidence)
	return evidence, err
}
func (transport *haPeerTransport) RequestCommit(ctx context.Context, voter ha.PeerVoter, request ha.PeerCommitRequest) (ha.PeerCommitVote, error) {
	var vote ha.PeerCommitVote
	err := transport.commitJSON(ctx, voter, "/v1/ha/commit-vote", request, &vote)
	return vote, err
}
func (transport *haPeerTransport) AdmitCommit(ctx context.Context, voter ha.PeerVoter, certificate ha.WriterActivationCertificate) error {
	var response struct {
		Admitted bool `json:"admitted"`
	}
	err := transport.commitJSON(ctx, voter, "/v1/ha/commit-certificate", certificate, &response)
	if err != nil {
		return err
	}
	if !response.Admitted {
		return ha.ErrNoQuorum
	}
	return nil
}

func serveHAPeerCommit(service *ha.PeerCommitService, transport *haPeerTransport, writer http.ResponseWriter, request *http.Request) bool {
	if !strings.HasPrefix(request.URL.Path, "/v1/ha/commit-") {
		return false
	}
	if service == nil || request.Method != http.MethodPost || request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" || request.TLS == nil {
		http.Error(writer, "not permitted", http.StatusForbidden)
		return true
	}
	ctx, cancel := context.WithTimeout(request.Context(), 13*time.Second)
	defer cancel()
	caller, err := transport.caller(ctx, *request.TLS)
	if err != nil {
		http.Error(writer, "not permitted", http.StatusForbidden)
		return true
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 256<<10))
	if err != nil {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return true
	}
	var result any
	switch request.URL.Path {
	case "/v1/ha/commit-evidence":
		var input ha.PeerCommitObservationRequest
		if decodeHAFederationJSON(body, &input) != nil {
			err = ha.ErrInvalid
		} else {
			result, err = service.ObserveNode(ctx, caller, input)
		}
	case "/v1/ha/commit-vote":
		var input ha.PeerCommitRequest
		if decodeHAFederationJSON(body, &input) != nil {
			err = ha.ErrInvalid
		} else {
			result, err = service.CastCommit(ctx, caller, input)
		}
	case "/v1/ha/commit-certificate":
		var input ha.WriterActivationCertificate
		if decodeHAFederationJSON(body, &input) != nil {
			err = ha.ErrInvalid
		} else {
			err = service.AdmitCertificate(ctx, input)
			result = struct {
				Admitted bool `json:"admitted"`
			}{err == nil}
		}
	default:
		err = ha.ErrForbidden
	}
	if err != nil {
		http.Error(writer, "commit authority unavailable", http.StatusConflict)
		return true
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(result)
	return true
}
