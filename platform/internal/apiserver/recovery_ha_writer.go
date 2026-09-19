package apiserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

const maximumHAWriterAuthorityBytes = 256 << 10

type HAWriterAuthorityStatus struct {
	Current  bool `json:"current,omitempty"`
	Admitted bool `json:"admitted,omitempty"`
}

func readRecoveryOpaqueJSON(request *http.Request, maximum int64) (json.RawMessage, error) {
	if request == nil || request.Body == nil || request.Header.Get("Content-Type") != ContentTypeJSON || request.ContentLength > maximum {
		return nil, invalid("writer authority")
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, invalid("writer authority")
	}
	return json.RawMessage(raw), nil
}

func (server *RecoveryServer) writerCommitService() (*ha.PeerCommitService, error) {
	if server == nil || server.Controller == nil || server.Controller.PeerCommits == nil || server.Controller.PeerCommits.Prepare == nil || server.Controller.PeerCommits.Prepare.DB == nil {
		return nil, ErrUnavailable
	}
	return server.Controller.PeerCommits, nil
}

func (server *RecoveryServer) verifyHAWriterSourceAuthority(writer http.ResponseWriter, request *http.Request) {
	service, err := server.writerCommitService()
	if err == nil {
		var raw json.RawMessage
		raw, err = readRecoveryOpaqueJSON(request, maximumHAWriterAuthorityBytes)
		if err == nil {
			err = ha.VerifyDatabaseWriterFenceAuthority(request.Context(), service.Prepare.DB, raw)
		}
	}
	server.writeHAWriterVerification(writer, err, false)
}

func (server *RecoveryServer) verifyHAWriterCandidateAuthority(writer http.ResponseWriter, request *http.Request) {
	service, err := server.writerCommitService()
	if err == nil {
		var raw json.RawMessage
		raw, err = readRecoveryOpaqueJSON(request, maximumHAWriterAuthorityBytes)
		if err == nil {
			err = ha.VerifyDatabaseWriterCandidateAuthority(request.Context(), service.Prepare.DB, raw)
		}
	}
	server.writeHAWriterVerification(writer, err, false)
}

func (server *RecoveryServer) loadHAWriterActivation(writer http.ResponseWriter, request *http.Request) {
	service, err := server.writerCommitService()
	if err != nil {
		writeProblem(writer, classifyError(err, ""), 1<<20)
		return
	}
	var input struct {
		LeaseID ha.WriterLeaseID `json:"lease_id"`
	}
	if err = readJSON(request, 4096, &input); err != nil {
		writeProblem(writer, classifyError(err, ""), 1<<20)
		return
	}
	lease, err := (ha.SQLRepository{DB: service.Prepare.DB}).LoadLease(request.Context(), input.LeaseID)
	if err != nil {
		writeStaticHAProblem(writer, err)
		return
	}
	raw, err := ha.LoadWriterActivation(request.Context(), service.Prepare.DB, lease)
	if err != nil {
		writeStaticHAProblem(writer, err)
		return
	}
	_ = writeJSON(writer, http.StatusOK, struct {
		Activation json.RawMessage `json:"activation"`
	}{Activation: raw}, maximumHAWriterAuthorityBytes+1024)
}

func (server *RecoveryServer) admitHAWriterActivation(writer http.ResponseWriter, request *http.Request) {
	service, err := server.writerCommitService()
	if err == nil {
		var raw json.RawMessage
		raw, err = readRecoveryOpaqueJSON(request, maximumHAWriterAuthorityBytes)
		if err == nil {
			err = ha.AdmitWriterActivation(request.Context(), service.Prepare.DB, raw)
		}
	}
	server.writeHAWriterVerification(writer, err, true)
}

func (server *RecoveryServer) verifyHAWriterActivation(writer http.ResponseWriter, request *http.Request) {
	service, err := server.writerCommitService()
	if err == nil {
		var raw json.RawMessage
		raw, err = readRecoveryOpaqueJSON(request, maximumHAWriterAuthorityBytes)
		if err == nil {
			err = ha.VerifyActiveWriterAuthority(request.Context(), service.Prepare.DB, raw)
		}
	}
	server.writeHAWriterVerification(writer, err, false)
}

func (server *RecoveryServer) writeHAWriterVerification(writer http.ResponseWriter, err error, admitted bool) {
	if err != nil {
		writeStaticHAProblem(writer, err)
		return
	}
	status := HAWriterAuthorityStatus{Current: !admitted, Admitted: admitted}
	_ = writeJSON(writer, http.StatusOK, status, 4096)
}

func (client *RecoveryClient) verifyHAWriterOpaque(ctx context.Context, path string, raw json.RawMessage, wantAdmitted bool) error {
	var result HAWriterAuthorityStatus
	if len(raw) == 0 {
		return ErrForbidden
	}
	if err := client.request(ctx, http.MethodPost, path, raw, &result); err != nil {
		return err
	}
	if wantAdmitted {
		if !result.Admitted {
			return ErrForbidden
		}
		return nil
	}
	if !result.Current {
		return ErrForbidden
	}
	return nil
}

func (client *RecoveryClient) VerifyDatabaseWriterFenceAuthority(ctx context.Context, raw json.RawMessage) error {
	return client.verifyHAWriterOpaque(ctx, "/recovery/v1/ha/writer/source-authority/verify", raw, false)
}

func (client *RecoveryClient) VerifyDatabaseWriterCandidateAuthority(ctx context.Context, raw json.RawMessage) error {
	return client.verifyHAWriterOpaque(ctx, "/recovery/v1/ha/writer/candidate-authority/verify", raw, false)
}

func (client *RecoveryClient) LoadWriterActivation(ctx context.Context, lease ha.WriterLease) (json.RawMessage, error) {
	var result struct {
		Activation json.RawMessage `json:"activation"`
	}
	input := struct {
		LeaseID ha.WriterLeaseID `json:"lease_id"`
	}{LeaseID: lease.ID}
	if err := client.request(ctx, http.MethodPost, "/recovery/v1/ha/writer/activation/load", input, &result); err != nil {
		return nil, err
	}
	if len(result.Activation) == 0 {
		return nil, ErrForbidden
	}
	return result.Activation, nil
}

func (client *RecoveryClient) AdmitWriterActivation(ctx context.Context, raw json.RawMessage) error {
	return client.verifyHAWriterOpaque(ctx, "/recovery/v1/ha/writer/activation/admit", raw, true)
}

func (client *RecoveryClient) VerifyActiveWriterAuthority(ctx context.Context, raw json.RawMessage) error {
	return client.verifyHAWriterOpaque(ctx, "/recovery/v1/ha/writer/activation/verify", raw, false)
}
