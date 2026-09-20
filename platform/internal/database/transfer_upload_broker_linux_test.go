//go:build linux

package database

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

func verifyNativeUploadBroker(t *testing.T, ctx context.Context, client *BrokerClient, source TransferUploadIntent) {
	t.Helper()
	store, err := NewLinuxTransferUploadStore(transferUploadRoot, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.artifacts.OpenTransferArtifact(ctx, source.ArtifactIdentity())
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	intent := source
	intent.ID, _ = NewResourceID("broker-upload-" + source.Digest[:32])
	intent, err = SealTransferUploadIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := store.artifacts.artifactPath(intent.ArtifactIdentity())
	t.Cleanup(func() {
		if e := os.RemoveAll(path); e != nil {
			t.Error(e)
		}
		if e := os.RemoveAll(filepath.Join(transferUploadRoot, ".upload-"+intent.Digest)); e != nil {
			t.Error(e)
		}
	})
	invoke := func(action string, offset uint64, data []byte) TransferUploadResult {
		t.Helper()
		r, e := client.ExecuteTransferUpload(ctx, TransferUploadRequest{Action: action, Intent: intent, Offset: offset, Data: data})
		if e != nil {
			t.Fatal(action, e)
		}
		return r
	}
	if r := invoke("begin", 0, nil); r.NextOffset != 0 {
		t.Fatal("new upload has bytes")
	}
	for offset := 0; offset < len(data); {
		end := offset + 17
		if end > len(data) {
			end = len(data)
		}
		if r := invoke("chunk", uint64(offset), data[offset:end]); r.NextOffset != uint64(end) {
			t.Fatal("incorrect chunk offset")
		}
		if r := invoke("chunk", uint64(offset), data[offset:end]); r.NextOffset != uint64(end) {
			t.Fatal("chunk replay differs")
		}
		if r := invoke("status", 0, nil); r.NextOffset != uint64(end) || r.Artifact != nil {
			t.Fatal("status cached stale offset")
		}
		offset = end
	}
	finished := invoke("finish", 0, nil)
	if finished.Artifact == nil || !intent.matchesArtifact(*finished.Artifact) {
		t.Fatal("missing finalized artifact")
	}
	if r := invoke("finish", 0, nil); r.Artifact == nil || *r.Artifact != *finished.Artifact {
		t.Fatal("finish replay differs")
	}
	if r := invoke("status", 0, nil); r.Artifact == nil || *r.Artifact != *finished.Artifact {
		t.Fatal("published status differs")
	}
	wrong := intent
	wrong.TenantID, _ = site.NewTenantID("foreign-upload-tenant")
	wrong, _ = SealTransferUploadIntent(wrong)
	if _, err = client.ExecuteTransferUpload(ctx, TransferUploadRequest{Action: "begin", Intent: wrong}); err == nil {
		t.Fatal("foreign tenant admitted by native executor")
	}
	intent.ID, _ = NewResourceID("discard-upload-" + intent.Digest[:32])
	intent, _ = SealTransferUploadIntent(intent)
	invoke("begin", 0, nil)
	invoke("chunk", 0, data[:3])
	invoke("discard", 0, nil)
	if _, err = client.ExecuteTransferUpload(ctx, TransferUploadRequest{Action: "status", Intent: intent}); err == nil {
		t.Fatal("discarded bytes survived")
	}
}

func TestTransferUploadBrokerClosedFrames(t *testing.T) {
	_, intent, data := uploadFixture(t, TransferCompressionNone)
	request := BrokerRequest{Version: DatabaseBrokerProtocolVersion, RequestID: "req-11111111111111111111111111111111", Operation: BrokerTransferUpload, Deadline: time.Now().Add(time.Minute), TransferUpload: &TransferUploadRequest{Action: "chunk", Intent: intent, Data: data}}
	if err := request.validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	response := BrokerResponse{Version: request.Version, RequestID: request.RequestID, Operation: request.Operation, TransferUpload: &TransferUploadResult{Action: "chunk", IntentDigest: intent.Digest, NextOffset: intent.Bytes}}
	if err := response.validate(request); err != nil {
		t.Fatal(err)
	}
	request.Workspace = &WorkspaceBrokerRequest{}
	if request.validate(time.Now()) == nil {
		t.Fatal("mixed request accepted")
	}
	request.Workspace = nil
	response.Query = &WorkspaceQueryResult{}
	if response.validate(request) == nil {
		t.Fatal("mixed response accepted")
	}
	response.Query = nil
	response.TransferUpload.NextOffset = intent.Bytes + 1
	if response.validate(request) == nil {
		t.Fatal("excess offset accepted")
	}
	request.TransferUpload.Action = "shell"
	if request.validate(time.Now()) == nil {
		t.Fatal("unknown action accepted")
	}
}
