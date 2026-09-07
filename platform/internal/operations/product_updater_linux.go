//go:build linux

package operations

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/install"
	"github.com/aonsyed/cyberpanel/platform/internal/productupdate"
)

const (
	ProductUpdaterProtocolVersion uint16 = 1
	ProductUpdaterSocketPath             = "/run/cyberpanel-product-updater/updater.sock"
	ProductUpdaterStateRoot              = "/var/lib/cyberpanel/product-updater"

	productUpdaterRuntimeRoot      = "/run/cyberpanel-product-updater"
	productUpdaterJournalRoot      = ProductUpdaterStateRoot + "/journal"
	productUpdaterBaselineRoot     = ProductUpdaterStateRoot + "/baselines"
	productUpdaterActivationPath   = ProductUpdaterStateRoot + "/activation.json"
	productUpdaterFeedFrontierPath = ProductUpdaterStateRoot + "/feed-frontier.json"
	productUpdaterStagingRoot      = "/var/lib/cyberpanel/control/product-update-staging"
	productUpdaterFeedSpoolRoot    = "/var/lib/cyberpanel/product-update-spool"
	productUpdaterOfflineRoot      = ProductUpdaterStateRoot + "/inbox"
	productUpdaterReleaseRoot      = "/var/lib/cyberpanel/product-updates"
	productUpdaterTrustPath        = "/etc/cyberpanel/product-update/trust.json"
	productUpdaterSlotRoot         = "/opt/cyberpanel/slots"
	productUpdaterExecutablePath   = "/usr/local/libexec/cyberpanel/panel-updated"
	productUpdaterMaximumFrame     = 8 << 20
	productUpdaterMaximumHookFrame = 1 << 20

	productUpdaterAuthorizationDomain      = "cyberpanel-product-update-authorization-v1\n"
	productUpdaterAuthorizationProofDomain = "cyberpanel-product-update-authorization-proof-v1\n"
)

var (
	errProductUpdaterProtocol  = errors.New("invalid product updater protocol")
	errProductUpdaterAmbiguous = errors.New("product updater recovery is ambiguous")
)

type ProductUpdaterMethod string

const (
	ProductUpdaterObserve ProductUpdaterMethod = "observe_or_apply"
	ProductUpdaterRecover ProductUpdaterMethod = "recover"
	ProductUpdaterImportFeed ProductUpdaterMethod = "import_feed"
	ProductUpdaterImportOffline ProductUpdaterMethod = "import_offline"
)

type ProductUpdateFeedArtifactReference struct {
	ID string `json:"id"`
	Digest string `json:"digest"`
	Size int64 `json:"size"`
}

type ProductUpdateFeedManifestReference struct {
	ID string `json:"id"`
	Sequence uint64 `json:"sequence"`
	Digest string `json:"digest"`
	SHA256 string `json:"sha256"`
	Size int64 `json:"size"`
	Artifacts []ProductUpdateFeedArtifactReference `json:"artifacts"`
}

type ProductUpdateFeedIndex struct {
	Version uint16 `json:"version"`
	Platform productupdate.PlatformTuple `json:"platform"`
	Manifest ProductUpdateFeedManifestReference `json:"manifest"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Digest string `json:"digest"`
}

func CanonicalProductUpdateFeedIndex(index ProductUpdateFeedIndex, now time.Time) (ProductUpdateFeedIndex, error) {
	if index.Version != 1 || index.Platform.Validate() != nil || !validProductUpdateIdentifier(index.Manifest.ID) ||
		index.Manifest.Sequence == 0 || !validSHA256(index.Manifest.Digest) || !validSHA256(index.Manifest.SHA256) ||
		index.Manifest.Size <= 0 || index.Manifest.Size > 16<<20 || len(index.Manifest.Artifacts) == 0 ||
		len(index.Manifest.Artifacts) > 256 || index.IssuedAt.IsZero() || index.ExpiresAt.IsZero() || now.IsZero() {
		return ProductUpdateFeedIndex{}, productupdate.ErrInvalid
	}
	index.IssuedAt, index.ExpiresAt, now = index.IssuedAt.UTC(), index.ExpiresAt.UTC(), now.UTC()
	if !index.ExpiresAt.After(index.IssuedAt) || index.ExpiresAt.Sub(index.IssuedAt) > 7*24*time.Hour ||
		now.Add(10*time.Minute).Before(index.IssuedAt) || !now.Add(-10*time.Minute).Before(index.ExpiresAt) {
		return ProductUpdateFeedIndex{}, productupdate.ErrExpired
	}
	index.Manifest.Artifacts = append([]ProductUpdateFeedArtifactReference(nil), index.Manifest.Artifacts...)
	sort.Slice(index.Manifest.Artifacts, func(i, j int) bool { return index.Manifest.Artifacts[i].ID < index.Manifest.Artifacts[j].ID })
	var total int64
	for position, artifact := range index.Manifest.Artifacts {
		if !validProductUpdateIdentifier(artifact.ID) || !validSHA256(artifact.Digest) || artifact.Size <= 0 || artifact.Size > 4<<30 ||
			position > 0 && index.Manifest.Artifacts[position-1].ID == artifact.ID || total > 16<<30-artifact.Size {
			return ProductUpdateFeedIndex{}, productupdate.ErrInvalid
		}
		total += artifact.Size
	}
	claimed := index.Digest
	index.Digest = ""
	index.Digest = productUpdateJSONDigest(index)
	if !validSHA256(claimed) || claimed != index.Digest { return ProductUpdateFeedIndex{}, productupdate.ErrIntegrity }
	return index, nil
}

type ProductUpdateFeedImport struct {
	Version uint16 `json:"version"`
	SpoolID string `json:"spool_id"`
	IndexDigest string `json:"index_digest"`
}

func (claim ProductUpdateFeedImport) validate() error {
	if claim.Version != 1 || !validSHA256(claim.IndexDigest) || claim.SpoolID != "feed-"+claim.IndexDigest { return productupdate.ErrInvalid }
	return nil
}

type ProductUpdateFeedImportReceipt struct {
	Version uint16 `json:"version"`
	SpoolID string `json:"spool_id"`
	IndexDigest string `json:"index_digest"`
	ManifestID string `json:"manifest_id"`
	ManifestDigest string `json:"manifest_digest"`
	Sequence uint64 `json:"sequence"`
	ArtifactCount int `json:"artifact_count"`
	ArtifactBytes int64 `json:"artifact_bytes"`
	ImportedAt time.Time `json:"imported_at"`
	EvidenceDigest string `json:"evidence_digest"`
}

func (receipt ProductUpdateFeedImportReceipt) validate(claim ProductUpdateFeedImport) error {
	evidence := receipt.EvidenceDigest;receipt.EvidenceDigest=""
	if claim.validate()!=nil || receipt.Version!=1 || receipt.SpoolID!=claim.SpoolID || receipt.IndexDigest!=claim.IndexDigest ||
		!validProductUpdateIdentifier(receipt.ManifestID) || !validSHA256(receipt.ManifestDigest) || receipt.Sequence==0 ||
		receipt.ArtifactCount<1 || receipt.ArtifactCount>256 || receipt.ArtifactBytes<=0 || receipt.ArtifactBytes>16<<30 ||
		receipt.ImportedAt.IsZero() || receipt.ImportedAt.Location()!=time.UTC || !validSHA256(evidence) || evidence!=productUpdateJSONDigest(receipt) {
		return productupdate.ErrIntegrity
	}
	return nil
}

type ProductUpdaterRequest struct {
	Version         uint16              `json:"version"`
	Method          ProductUpdaterMethod `json:"method"`
	OperationDigest string              `json:"operation_digest"`
	Effect          ProductUpdateEffect `json:"effect"`
	Import          *ProductUpdateFeedImport `json:"import,omitempty"`
	Deadline        time.Time           `json:"deadline"`
}

func (request ProductUpdaterRequest) validate(now time.Time) error {
	if request.Version != ProductUpdaterProtocolVersion || !validSHA256(request.OperationDigest) || request.Deadline.IsZero() || !request.Deadline.After(now) { return errProductUpdaterProtocol }
	if request.Method == ProductUpdaterImportFeed || request.Method == ProductUpdaterImportOffline {
		if request.Import == nil || request.Import.validate()!=nil || !productUpdaterEffectEmpty(request.Effect) ||
			request.OperationDigest!=productUpdateJSONDigest(*request.Import) || request.Deadline.After(now.Add(30*time.Minute)) { return errProductUpdaterProtocol }
	} else if (request.Method!=ProductUpdaterObserve && request.Method!=ProductUpdaterRecover) || request.Import!=nil ||
		request.OperationDigest!=productUpdaterEffectDigest(request.Effect) || request.Deadline.After(now.Add(10*time.Minute)) { return errProductUpdaterProtocol }
	return nil
}

func productUpdaterEffectEmpty(effect ProductUpdateEffect) bool { return effect.Action=="" && effect.NodeID=="" && effect.ObservedAt.IsZero() && effect.Authorization==nil && effect.Migration==nil && effect.Backup==nil && effect.MigrationRollback==nil && effect.RollbackInspection==nil && effect.Switch==nil && effect.Finalize==nil && effect.Probe==nil }

type ProductUpdaterResponse struct {
	Version         uint16               `json:"version"`
	Method          ProductUpdaterMethod `json:"method"`
	OperationDigest string               `json:"operation_digest"`
	Result          *ProductUpdateResult `json:"result,omitempty"`
	Import          *ProductUpdateFeedImportReceipt `json:"import,omitempty"`
	ErrorCode       string               `json:"error_code,omitempty"`
	CompletedAt     time.Time            `json:"completed_at"`
}

func (response ProductUpdaterResponse) validate(request ProductUpdaterRequest, now time.Time) error {
	if response.Version != ProductUpdaterProtocolVersion || response.Method != request.Method ||
		response.OperationDigest != request.OperationDigest || response.CompletedAt.IsZero() ||
		response.CompletedAt.After(now.Add(time.Minute)) || !validProductUpdaterErrorCode(response.ErrorCode) {
		return errProductUpdaterProtocol
	}
	if response.ErrorCode == "" {
		if request.Method == ProductUpdaterObserve {
			if response.Result == nil || response.Import!=nil || validateProductUpdateResult(request.Effect, *response.Result) != nil {
				return errProductUpdaterProtocol
			}
		} else if request.Method==ProductUpdaterImportFeed || request.Method==ProductUpdaterImportOffline {
			if response.Result!=nil || response.Import==nil || request.Import==nil || response.Import.validate(*request.Import)!=nil { return errProductUpdaterProtocol }
		} else if response.Result != nil || response.Import!=nil {
			return errProductUpdaterProtocol
		}
	}
	return nil
}

func validProductUpdaterErrorCode(value string) bool {
	switch value {
	case "", "invalid_request", "unauthorized", "rejected", "ambiguous", "internal_error":
		return true
	default:
		return false
	}
}

type ProductUpdaterClient struct{}

func NewLocalProductUpdateClient() (*ProductUpdaterClient, error) {
	info, err := os.Lstat(ProductUpdaterSocketPath)
	if err != nil {
		return nil, err
	}
	_, controlGID, identityErr := LookupOperationsControlIdentity()
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if identityErr!=nil || !ok || metadata.Uid != 0 || metadata.Gid!=controlGID || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
		return nil, ErrUnauthorized
	}
	return &ProductUpdaterClient{}, nil
}

func (client *ProductUpdaterClient) ObserveOrApply(ctx context.Context, effect ProductUpdateEffect) (ProductUpdateResult, error) {
	response, err := client.roundTrip(ctx, ProductUpdaterObserve, effect)
	if err != nil {
		return ProductUpdateResult{}, err
	}
	if response.Result == nil {
		return ProductUpdateResult{}, errProductUpdaterProtocol
	}
	return *response.Result, productUpdaterClientError(response.ErrorCode)
}

func (client *ProductUpdaterClient) Recover(ctx context.Context, effect ProductUpdateEffect) error {
	response, err := client.roundTrip(ctx, ProductUpdaterRecover, effect)
	if err != nil {
		return err
	}
	return productUpdaterClientError(response.ErrorCode)
}

func (client *ProductUpdaterClient) ImportFeed(ctx context.Context, claim ProductUpdateFeedImport) (ProductUpdateFeedImportReceipt, error) {
	return client.importBundle(ctx,ProductUpdaterImportFeed,claim)
}

// ImportOffline accepts only a content-addressed inbox ID, never a caller path.
func (client *ProductUpdaterClient) ImportOffline(ctx context.Context, bundleID string) (ProductUpdateFeedImportReceipt, error) {
	if os.Geteuid()!=0 { return ProductUpdateFeedImportReceipt{},ErrUnauthorized }
	claim:=ProductUpdateFeedImport{Version:1,SpoolID:bundleID,IndexDigest:strings.TrimPrefix(bundleID,"feed-")}
	return client.importBundle(ctx,ProductUpdaterImportOffline,claim)
}

func (client *ProductUpdaterClient) importBundle(ctx context.Context, method ProductUpdaterMethod, claim ProductUpdateFeedImport) (ProductUpdateFeedImportReceipt, error) {
	if client==nil || ctx==nil || claim.validate()!=nil { return ProductUpdateFeedImportReceipt{}, errProductUpdaterProtocol }
	now:=time.Now().UTC();deadline:=now.Add(30*time.Minute);if candidate,ok:=ctx.Deadline();ok&&candidate.Before(deadline){deadline=candidate.UTC()}
	request:=ProductUpdaterRequest{Version:ProductUpdaterProtocolVersion,Method:method,OperationDigest:productUpdateJSONDigest(claim),Import:&claim,Deadline:deadline}
	response,err:=client.exchange(ctx,request);if err!=nil{return ProductUpdateFeedImportReceipt{},err};if response.Import==nil{return ProductUpdateFeedImportReceipt{},errProductUpdaterProtocol}
	return *response.Import,productUpdaterClientError(response.ErrorCode)
}

func (client *ProductUpdaterClient) roundTrip(ctx context.Context, method ProductUpdaterMethod, effect ProductUpdateEffect) (ProductUpdaterResponse, error) {
	if client == nil || ctx == nil {
		return ProductUpdaterResponse{}, errProductUpdaterProtocol
	}
	digest := productUpdaterEffectDigest(effect)
	if digest == "" {
		return ProductUpdaterResponse{}, ErrInvalidEffect
	}
	now := time.Now().UTC()
	deadline := now.Add(10 * time.Minute)
	if candidate, ok := ctx.Deadline(); ok && candidate.Before(deadline) {
		deadline = candidate.UTC()
	}
	request := ProductUpdaterRequest{Version: ProductUpdaterProtocolVersion, Method: method, OperationDigest: digest, Effect: effect, Deadline: deadline}
	return client.exchange(ctx,request)
}

func (client *ProductUpdaterClient) exchange(ctx context.Context,request ProductUpdaterRequest)(ProductUpdaterResponse,error){
	if client==nil||ctx==nil||request.validate(time.Now().UTC())!=nil{return ProductUpdaterResponse{},errProductUpdaterProtocol}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", ProductUpdaterSocketPath)
	if err != nil {
		return ProductUpdaterResponse{}, err
	}
	defer connection.Close()
	if err = authorizeProductUpdaterConnection(connection, 0); err != nil {
		return ProductUpdaterResponse{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if err = connection.SetDeadline(request.Deadline); err != nil {
		return ProductUpdaterResponse{}, err
	}
	if err = writeProductUpdaterFrame(connection, request); err != nil {
		return ProductUpdaterResponse{}, err
	}
	var response ProductUpdaterResponse
	if err = readProductUpdaterFrame(connection, &response); err != nil {
		return ProductUpdaterResponse{}, err
	}
	if err = response.validate(request, time.Now().UTC()); err != nil {
		return ProductUpdaterResponse{}, err
	}
	return response, nil
}

func productUpdaterClientError(code string) error {
	switch code {
	case "":
		return nil
	case "invalid_request":
		return ErrInvalidEffect
	case "unauthorized":
		return ErrUnauthorized
	case "rejected":
		return ErrInvalidCommand
	case "ambiguous":
		return errProductUpdaterAmbiguous
	default:
		return ErrCompensationFailed
	}
}

type ProductUpdaterServer struct {
	Updater *LinuxProductUpdater
}

func (server *ProductUpdaterServer) Serve(listener net.Listener) error {
	if server == nil || server.Updater == nil || listener == nil {
		return errProductUpdaterProtocol
	}
	slots:=make(chan struct{},16)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select{case slots<-struct{}{}:go func(peer net.Conn){defer func(){<-slots}();server.serve(peer)}(connection);default:_=connection.Close()}
	}
}

func (server *ProductUpdaterServer) serve(connection net.Conn) {
	defer connection.Close()
	peerUID,peerErr:=productUpdaterPeerUID(connection);if peerErr!=nil{return}
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	var request ProductUpdaterRequest
	if readProductUpdaterFrame(connection, &request) != nil || request.validate(time.Now().UTC()) != nil {
		return
	}
	if request.Method==ProductUpdaterImportFeed { if peerUID!=server.Updater.controlUID{return} } else if peerUID!=0{return}
	if connection.SetDeadline(request.Deadline)!=nil{return}
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	response := ProductUpdaterResponse{Version: ProductUpdaterProtocolVersion, Method: request.Method,
		OperationDigest: request.OperationDigest, CompletedAt: time.Now().UTC()}
	var executionErr error
	if request.Method == ProductUpdaterObserve {
		result, err := server.Updater.ObserveOrApply(ctx, request.Effect)
		response.Result, executionErr = &result, err
	} else if request.Method==ProductUpdaterRecover {
		executionErr = server.Updater.Recover(ctx, request.Effect)
	} else if request.Method==ProductUpdaterImportOffline {
		receipt,err:=server.Updater.ImportOffline(ctx,*request.Import);response.Import,executionErr=&receipt,err
	} else {
		receipt,err:=server.Updater.ImportFeed(ctx,*request.Import);response.Import,executionErr=&receipt,err
	}
	response.ErrorCode = productUpdaterServerError(executionErr)
	response.CompletedAt = time.Now().UTC()
	if response.ErrorCode != "" || response.validate(request, time.Now().UTC()) == nil {
		if writeProductUpdaterFrame(connection, response) == nil && executionErr == nil && request.Method!=ProductUpdaterImportFeed && request.Effect.Action == ProductUpdateCommit {
			go server.Updater.restartSelfAfterAcknowledgement()
		}
	}
}

func productUpdaterServerError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrUnauthorized), errors.Is(err, productupdate.ErrUnauthorized), errors.Is(err, productupdate.ErrExpired):
		return "unauthorized"
	case errors.Is(err, ErrInvalidEffect), errors.Is(err, productupdate.ErrInvalid):
		return "invalid_request"
	case errors.Is(err, errProductUpdaterAmbiguous):
		return "ambiguous"
	case errors.Is(err, productupdate.ErrIncompatible), errors.Is(err, productupdate.ErrRollback), errors.Is(err, install.ErrUnhealthy):
		return "rejected"
	default:
		return "internal_error"
	}
}

func ListenProductUpdater() (*net.UnixListener, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnauthorized
	}
	if err := ensureProductUpdaterDirectory(productUpdaterRuntimeRoot, 0711); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(ProductUpdaterSocketPath); err == nil {
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 || info.Mode()&os.ModeSocket == 0 {
			return nil, ErrUnauthorized
		}
		if err = os.Remove(ProductUpdaterSocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: ProductUpdaterSocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	_,controlGID,identityErr:=LookupOperationsControlIdentity();if identityErr!=nil{_ = listener.Close();return nil,identityErr}
	if err = os.Chown(ProductUpdaterSocketPath, 0, int(controlGID)); err == nil {
		err = os.Chmod(ProductUpdaterSocketPath, 0660)
	}
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func authorizeProductUpdaterConnection(connection net.Conn, allowedUID uint32) error {
	uid,err:=productUpdaterPeerUID(connection);if err!=nil||uid!=allowedUID{return ErrUnauthorized};return nil
}

func productUpdaterPeerUID(connection net.Conn)(uint32,error){
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0,ErrUnauthorized
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0,ErrUnauthorized
	}
	var credential *syscall.Ucred
	var credentialErr error
	if err = raw.Control(func(fd uintptr) {
		credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credentialErr != nil || credential == nil || credential.Pid <= 1 {
		return 0,ErrUnauthorized
	}
	return credential.Uid,nil
}

func writeProductUpdaterFrame(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > productUpdaterMaximumFrame {
		return errProductUpdaterProtocol
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
	if err = writeProductUpdaterAll(writer, header[:]); err != nil {
		return err
	}
	return writeProductUpdaterAll(writer, encoded)
}

func writeProductUpdaterAll(writer io.Writer, content []byte) error {
	for len(content) != 0 {
		count, err := writer.Write(content)
		if err != nil {
			return err
		}
		if count <= 0 || count > len(content) {
			return io.ErrShortWrite
		}
		content = content[count:]
	}
	return nil
}

func readProductUpdaterFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > productUpdaterMaximumFrame {
		return errProductUpdaterProtocol
	}
	content := make([]byte, size)
	if _, err := io.ReadFull(reader, content); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errProductUpdaterProtocol
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, content) {
		return errProductUpdaterProtocol
	}
	return nil
}

func productUpdaterEffectDigest(effect ProductUpdateEffect) string {
	if validateProductUpdateEffect(effect) != nil {
		return ""
	}
	return productUpdateJSONDigest(effect)
}

type productUpdaterJournalState string

const (
	productUpdaterAccepted productUpdaterJournalState = "accepted"
	productUpdaterFrontier productUpdaterJournalState = "frontier"
	productUpdaterComplete productUpdaterJournalState = "complete"
)

type productUpdaterJournalRecord struct {
	Version               uint16                     `json:"version"`
	OperationDigest       string                     `json:"operation_digest"`
	Effect                ProductUpdateEffect        `json:"effect"`
	State                 productUpdaterJournalState `json:"state"`
	AcceptedAt            time.Time                  `json:"accepted_at"`
	FrontierAt            time.Time                  `json:"frontier_at,omitempty"`
	FrontierReceiptDigest string                     `json:"frontier_receipt_digest,omitempty"`
	Result                *ProductUpdateResult       `json:"result,omitempty"`
	LastFailure           string                     `json:"last_failure,omitempty"`
	CompletedAt           time.Time                  `json:"completed_at,omitempty"`
	RecordDigest          string                     `json:"record_digest"`
}

type productUpdaterActivation struct {
	Version          uint16         `json:"version"`
	ManifestID       string         `json:"manifest_id"`
	OperationDigest  string         `json:"operation_digest"`
	PreviousSlot     install.SlotID `json:"previous_slot"`
	PreviousID       string         `json:"previous_id"`
	PreviousDigest   string         `json:"previous_digest"`
	CandidateSlot    install.SlotID `json:"candidate_slot"`
	CandidateID      string         `json:"candidate_id"`
	CandidateDigest  string         `json:"candidate_digest"`
	State            string         `json:"state"`
	UpdatedAt        time.Time      `json:"updated_at"`
	RecordDigest     string         `json:"record_digest"`
}

type productUpdaterReleaseMarker struct {
	Version       uint16    `json:"version"`
	ReleaseID     string    `json:"release_id"`
	ReleaseDigest string    `json:"release_digest"`
	SourceRootID  string    `json:"source_root_id"`
	InstalledAt   time.Time `json:"installed_at"`
	RecordDigest  string    `json:"record_digest"`
}

type productUpdaterFeedFrontier struct {
	Version uint16 `json:"version"`
	State string `json:"state"`
	Offline bool `json:"offline,omitempty"`
	SpoolID string `json:"spool_id"`
	IndexDigest string `json:"index_digest"`
	Platform productupdate.PlatformTuple `json:"platform"`
	ManifestID string `json:"manifest_id"`
	ManifestDigest string `json:"manifest_digest"`
	Sequence uint64 `json:"sequence"`
	Receipt *ProductUpdateFeedImportReceipt `json:"receipt,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	RecordDigest string `json:"record_digest"`
}

type productUpdaterStagedFile struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type productUpdaterStagedRelease struct {
	ManifestID     string `json:"manifest_id"`
	ManifestDigest string `json:"manifest_digest"`
	Root           struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
	} `json:"root"`
	Artifacts []struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	} `json:"artifacts"`
	FileCount      int    `json:"file_count"`
	ExtractedBytes int64  `json:"extracted_bytes"`
	EvidenceDigest string `json:"evidence_digest"`
}

type productUpdaterHealthEvidence struct {
	Version       uint16          `json:"version"`
	NodeID        string          `json:"node_id"`
	ReleaseDigest string          `json:"release_digest"`
	Units         map[string]bool `json:"units"`
	Sockets       map[string]bool `json:"sockets"`
	ObservedAt    time.Time       `json:"observed_at"`
	Digest        string          `json:"digest"`
}

type LinuxProductUpdater struct {
	host       *install.LinuxHost
	controlUID uint32
	controlGID uint32
	now        func() time.Time
	mu         sync.Mutex
}

func NewLinuxProductUpdater() (*LinuxProductUpdater, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnauthorized
	}
	controlUID, controlGID, err := LookupOperationsControlIdentity()
	if err != nil {
		return nil, err
	}
	for _, directory := range []string{ProductUpdaterStateRoot, productUpdaterJournalRoot, productUpdaterBaselineRoot} {
		if err = ensureProductUpdaterDirectory(directory, 0700); err != nil {
			return nil, err
		}
	}
	return &LinuxProductUpdater{host: install.NewLinuxHost(), controlUID: controlUID,controlGID:controlGID, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (updater *LinuxProductUpdater) ObserveOrApply(ctx context.Context, effect ProductUpdateEffect) (ProductUpdateResult, error) {
	return updater.apply(ctx, effect)
}

func (updater *LinuxProductUpdater) Recover(ctx context.Context, effect ProductUpdateEffect) error {
	_, err := updater.apply(ctx, effect)
	return err
}

func (updater *LinuxProductUpdater) RecoverPending(ctx context.Context) error {
	if updater == nil || ctx == nil {
		return ErrInvalidEffect
	}
	entries, err := os.ReadDir(productUpdaterJournalRoot)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		digest := strings.TrimSuffix(entry.Name(), ".json")
		record, found, loadErr := updater.loadJournal(digest)
		if loadErr != nil {
			return loadErr
		}
		if found && record.State != productUpdaterComplete {
			if _, loadErr = updater.apply(ctx, record.Effect); loadErr != nil {
				return loadErr
			}
		}
	}
	return nil
}

func (updater *LinuxProductUpdater) ImportFeed(ctx context.Context,claim ProductUpdateFeedImport)(ProductUpdateFeedImportReceipt,error){
	if updater==nil||ctx==nil||claim.validate()!=nil{return ProductUpdateFeedImportReceipt{},productupdate.ErrInvalid}
	updater.mu.Lock();defer updater.mu.Unlock()
	return updater.importProductUpdateBundle(ctx,claim,productUpdaterFeedSpoolRoot,updater.controlUID,nil)
}

// ImportOffline shares the online trust and promotion pipeline, but only root
// peers may select this fixed inbox. The mutex also serializes online imports.
func (updater *LinuxProductUpdater) ImportOffline(ctx context.Context,claim ProductUpdateFeedImport)(ProductUpdateFeedImportReceipt,error){
	if updater==nil||ctx==nil||claim.validate()!=nil{return ProductUpdateFeedImportReceipt{},productupdate.ErrInvalid}
	updater.mu.Lock();defer updater.mu.Unlock()
	for _,directory:=range []string{ProductUpdaterStateRoot,productUpdaterOfflineRoot,filepath.Join(productUpdaterOfflineRoot,"ready"),filepath.Join(productUpdaterOfflineRoot,"accepted")}{
		if err:=verifyProductUpdaterDirectory(directory,0700,0);err!=nil{return ProductUpdateFeedImportReceipt{},err}
	}
	acceptedRoot:=filepath.Join(productUpdaterOfflineRoot,"accepted",claim.SpoolID)
	if _,err:=os.Lstat(acceptedRoot);err==nil{
		if err=verifyProductUpdaterDirectory(acceptedRoot,0700,0);err!=nil{return ProductUpdateFeedImportReceipt{},err}
		raw,readErr:=readProductUpdaterFile(filepath.Join(acceptedRoot,"receipt.json"),1<<20,0);if readErr!=nil{return ProductUpdateFeedImportReceipt{},readErr}
		var receipt ProductUpdateFeedImportReceipt
		if strictProductUpdaterJSON(raw,&receipt)!=nil||receipt.validate(claim)!=nil{return ProductUpdateFeedImportReceipt{},productupdate.ErrIntegrity}
		frontier,found,loadErr:=loadProductUpdaterFeedFrontier();if loadErr!=nil{return ProductUpdateFeedImportReceipt{},loadErr}
		if !found{return ProductUpdateFeedImportReceipt{},productupdate.ErrIntegrity}
		if frontier.Sequence<receipt.Sequence||frontier.Sequence==receipt.Sequence&&frontier.ManifestDigest!=receipt.ManifestDigest{return ProductUpdateFeedImportReceipt{},productupdate.ErrIntegrity}
		if err=syncProductUpdaterDirectory(filepath.Dir(acceptedRoot));err!=nil{return ProductUpdateFeedImportReceipt{},err}
		if err=syncProductUpdaterDirectory(filepath.Join(productUpdaterOfflineRoot,"ready"));err!=nil{return ProductUpdateFeedImportReceipt{},err}
		// A crash after the atomic disposition may precede frontier completion.
		if frontier.State=="accepted"&&frontier.SpoolID==claim.SpoolID{
			if !frontier.Offline||frontier.ManifestDigest!=receipt.ManifestDigest||frontier.ManifestID!=receipt.ManifestID||frontier.Sequence!=receipt.Sequence{return ProductUpdateFeedImportReceipt{},productupdate.ErrIntegrity}
			frontier.State,frontier.Receipt,frontier.UpdatedAt="complete",&receipt,updater.now()
			if err=storeProductUpdaterFeedFrontier(&frontier);err!=nil{return ProductUpdateFeedImportReceipt{},err}
		}
		return receipt,nil
	}else if !errors.Is(err,os.ErrNotExist){return ProductUpdateFeedImportReceipt{},err}
	return updater.importProductUpdateBundle(ctx,claim,productUpdaterOfflineRoot,0,func(receipt ProductUpdateFeedImportReceipt)error{
		readyRoot:=filepath.Join(productUpdaterOfflineRoot,"ready",claim.SpoolID)
		raw,err:=json.Marshal(receipt);if err!=nil{return err}
		if err=writeProductUpdaterFile(filepath.Join(readyRoot,"receipt.json"),raw,0600);err!=nil{return err}
		// Receipt and complete original bundle become visible together; failures
		// retain the accepted frontier and are recovered by resubmitting this ID.
		if err=os.Rename(readyRoot,acceptedRoot);err!=nil{return err}
		return errors.Join(syncProductUpdaterDirectory(filepath.Dir(acceptedRoot)),syncProductUpdaterDirectory(filepath.Dir(readyRoot)))
	})
}

// Caller holds updater.mu. Source roots and owners are selected internally,
// never supplied by the wire protocol, and no source file is made executable.
func (updater *LinuxProductUpdater) importProductUpdateBundle(ctx context.Context,claim ProductUpdateFeedImport,spoolRoot string,owner uint32,disposition func(ProductUpdateFeedImportReceipt)error)(ProductUpdateFeedImportReceipt,error){
	frontier,found,err:=loadProductUpdaterFeedFrontier();if err!=nil{return ProductUpdateFeedImportReceipt{},err}
	if disposition==nil&&found&&frontier.State=="complete"&&frontier.SpoolID==claim.SpoolID&&frontier.Receipt!=nil{return *frontier.Receipt,nil}
	if found&&frontier.State=="accepted"&&(frontier.SpoolID!=claim.SpoolID||frontier.IndexDigest!=claim.IndexDigest||frontier.Offline!=(disposition!=nil)){return ProductUpdateFeedImportReceipt{},productupdate.ErrConflict}
	readyRoot:=filepath.Join(spoolRoot,"ready");bundleRoot:=filepath.Join(readyRoot,claim.SpoolID);artifactRoot:=filepath.Join(bundleRoot,"artifacts")
	for _,directory:=range []string{spoolRoot,readyRoot,bundleRoot,artifactRoot}{if verifyProductUpdaterDirectory(directory,0700,owner)!=nil{return ProductUpdateFeedImportReceipt{},productupdate.ErrIntegrity}}
	indexRaw,err:=readProductUpdaterFile(filepath.Join(bundleRoot,"index.json"),1<<20,owner);if err!=nil{return ProductUpdateFeedImportReceipt{},err}
	var index ProductUpdateFeedIndex;if decodeProductUpdaterJSON(indexRaw,&index)!=nil{return ProductUpdateFeedImportReceipt{},productupdate.ErrIntegrity}
	index,err=CanonicalProductUpdateFeedIndex(index,updater.now());if err!=nil||index.Digest!=claim.IndexDigest||claim.SpoolID!="feed-"+index.Digest{return ProductUpdateFeedImportReceipt{},errors.Join(err,productupdate.ErrIntegrity)}
	verifier,limits,maximumManifest,err:=loadProductUpdaterManifestVerifier(updater.now());if err!=nil{return ProductUpdateFeedImportReceipt{},err}
	if index.Manifest.Size>maximumManifest{return ProductUpdateFeedImportReceipt{},productupdate.ErrCapacity}
	manifestRaw,err:=readProductUpdaterFile(filepath.Join(bundleRoot,"manifest.json"),index.Manifest.Size,owner);if err!=nil{return ProductUpdateFeedImportReceipt{},err}
	if int64(len(manifestRaw))!=index.Manifest.Size||digestProductUpdaterBytes(manifestRaw)!=index.Manifest.SHA256{return ProductUpdateFeedImportReceipt{},productupdate.ErrIntegrity}
	var manifest productupdate.ReleaseManifest;if decodeProductUpdaterJSON(manifestRaw,&manifest)!=nil{return ProductUpdateFeedImportReceipt{},productupdate.ErrIntegrity}
	manifest,err=productupdate.CanonicalManifest(manifest);if err!=nil{return ProductUpdateFeedImportReceipt{},err}
	if err=validateProductUpdaterFeedManifest(index,manifest,limits);err!=nil{return ProductUpdateFeedImportReceipt{},err}
	inventoryRaw,err:=readProductUpdaterFile(filepath.Join(productUpdaterReleaseRoot,"inventory.json"),1<<20,0);if err!=nil{return ProductUpdateFeedImportReceipt{},err}
	var inventory productupdate.InstalledInventory;if decodeProductUpdaterJSON(inventoryRaw,&inventory)!=nil{return ProductUpdateFeedImportReceipt{},productupdate.ErrIntegrity}
	acceptedSequence:=uint64(0);acceptedDigest:=""
	if found{acceptedSequence,acceptedDigest=frontier.Sequence,frontier.ManifestDigest}
	manifest,_,err=verifier.Verify(manifest,inventory,updater.now(),acceptedSequence,acceptedDigest);if err!=nil{return ProductUpdateFeedImportReceipt{},err}
	frontier=productUpdaterFeedFrontier{Version:1,State:"accepted",Offline:disposition!=nil,SpoolID:claim.SpoolID,IndexDigest:index.Digest,Platform:index.Platform,ManifestID:manifest.ID,ManifestDigest:manifest.Digest,Sequence:manifest.Sequence,UpdatedAt:updater.now()}
	if err=storeProductUpdaterFeedFrontier(&frontier);err!=nil{return ProductUpdateFeedImportReceipt{},err}
	if err=updater.verifyProductUpdaterReleaseDirectories();err!=nil{return ProductUpdateFeedImportReceipt{},err}
	var artifactBytes int64
	for _,artifact:=range manifest.Artifacts{source:=filepath.Join(artifactRoot,artifact.Digest+".tar");destination:=filepath.Join(productUpdaterReleaseRoot,"artifacts",artifact.Digest+".tar");if err=updater.promoteProductUpdaterFeedFile(ctx,source,destination,artifact.Size,artifact.Digest,owner);err!=nil{return ProductUpdateFeedImportReceipt{},err};artifactBytes+=artifact.Size}
	if err=updater.promoteProductUpdaterBytes(ctx,manifestRaw,filepath.Join(productUpdaterReleaseRoot,"manifests",manifest.ID+".json"),index.Manifest.SHA256);err!=nil{return ProductUpdateFeedImportReceipt{},err}
	indexCanonical,err:=json.Marshal(index);if err!=nil{return ProductUpdateFeedImportReceipt{},err};indexSHA:=digestProductUpdaterBytes(indexCanonical)
	if err=updater.promoteProductUpdaterBytes(ctx,indexCanonical,filepath.Join(productUpdaterReleaseRoot,"channels",index.Digest+".json"),indexSHA);err!=nil{return ProductUpdateFeedImportReceipt{},err}
	receipt:=ProductUpdateFeedImportReceipt{Version:1,SpoolID:claim.SpoolID,IndexDigest:index.Digest,ManifestID:manifest.ID,ManifestDigest:manifest.Digest,Sequence:manifest.Sequence,ArtifactCount:len(manifest.Artifacts),ArtifactBytes:artifactBytes,ImportedAt:updater.now()};receipt.EvidenceDigest=productUpdateJSONDigest(receipt)
	if disposition!=nil{if err=disposition(receipt);err!=nil{return ProductUpdateFeedImportReceipt{},err}}
	frontier.State,frontier.Receipt,frontier.UpdatedAt="complete",&receipt,updater.now();if err=storeProductUpdaterFeedFrontier(&frontier);err!=nil{return ProductUpdateFeedImportReceipt{},err}
	return receipt,nil
}

func validateProductUpdaterFeedManifest(index ProductUpdateFeedIndex,manifest productupdate.ReleaseManifest,limits productupdate.StagingLimits)error{
	if manifest.ID!=index.Manifest.ID||manifest.Sequence!=index.Manifest.Sequence||manifest.Digest!=index.Manifest.Digest||manifest.Platform!=index.Platform||len(manifest.Artifacts)!=len(index.Manifest.Artifacts){return productupdate.ErrIntegrity}
	var total int64
	for position,artifact:=range manifest.Artifacts{reference:=index.Manifest.Artifacts[position];if artifact.ID!=reference.ID||artifact.Digest!=reference.Digest||artifact.Size!=reference.Size||artifact.Size>limits.MaximumArtifactBytes||total>limits.MaximumTotalBytes-artifact.Size{return productupdate.ErrIntegrity};total+=artifact.Size}
	return nil
}

func loadProductUpdaterFeedFrontier()(productUpdaterFeedFrontier,bool,error){
	raw,err:=readProductUpdaterFile(productUpdaterFeedFrontierPath,1<<20,0);if errors.Is(err,os.ErrNotExist){return productUpdaterFeedFrontier{},false,nil};if err!=nil{return productUpdaterFeedFrontier{},false,err}
	var frontier productUpdaterFeedFrontier;if strictProductUpdaterJSON(raw,&frontier)!=nil||frontier.Version!=1||(frontier.State!="accepted"&&frontier.State!="complete")||frontier.SpoolID!="feed-"+frontier.IndexDigest||!validSHA256(frontier.IndexDigest)||frontier.Platform.Validate()!=nil||!validProductUpdateIdentifier(frontier.ManifestID)||!validSHA256(frontier.ManifestDigest)||frontier.Sequence==0||frontier.UpdatedAt.IsZero(){return productUpdaterFeedFrontier{},false,productupdate.ErrIntegrity}
	claimed:=frontier.RecordDigest;frontier.RecordDigest="";if claimed!=productUpdateJSONDigest(frontier){return productUpdaterFeedFrontier{},false,productupdate.ErrIntegrity};frontier.RecordDigest=claimed
	claim:=ProductUpdateFeedImport{Version:1,SpoolID:frontier.SpoolID,IndexDigest:frontier.IndexDigest};if frontier.State=="complete"{if frontier.Receipt==nil||frontier.Receipt.validate(claim)!=nil{return productUpdaterFeedFrontier{},false,productupdate.ErrIntegrity}}else if frontier.Receipt!=nil{return productUpdaterFeedFrontier{},false,productupdate.ErrIntegrity}
	return frontier,true,nil
}

func storeProductUpdaterFeedFrontier(frontier *productUpdaterFeedFrontier)error{frontier.RecordDigest="";frontier.RecordDigest=productUpdateJSONDigest(*frontier);raw,err:=json.Marshal(frontier);if err!=nil{return err};return writeProductUpdaterFile(productUpdaterFeedFrontierPath,raw,0600)}

func (updater *LinuxProductUpdater)verifyProductUpdaterReleaseDirectories()error{
	for _,path:=range []string{productUpdaterReleaseRoot,filepath.Join(productUpdaterReleaseRoot,"manifests"),filepath.Join(productUpdaterReleaseRoot,"artifacts"),filepath.Join(productUpdaterReleaseRoot,"channels")}{info,err:=os.Lstat(path);if err!=nil{return err};metadata,ok:=info.Sys().(*syscall.Stat_t);if !ok||metadata.Uid!=0||metadata.Gid!=updater.controlGID||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=0750{return productupdate.ErrIntegrity};resolved,err:=filepath.EvalSymlinks(path);if err!=nil||resolved!=path{return productupdate.ErrIntegrity}}
	return nil
}

func (updater *LinuxProductUpdater)promoteProductUpdaterFeedFile(ctx context.Context,source,destination string,size int64,digest string,owner uint32)error{
	before,err:=os.Lstat(source);if err!=nil{return err};metadata,ok:=before.Sys().(*syscall.Stat_t);if !ok||metadata.Uid!=owner||metadata.Nlink!=1||!before.Mode().IsRegular()||before.Mode()&os.ModeSymlink!=0||before.Mode().Perm()&0022!=0||before.Size()!=size{return productupdate.ErrIntegrity}
	file,err:=os.OpenFile(source,os.O_RDONLY|syscall.O_NOFOLLOW,0);if err!=nil{return err};opened,err:=file.Stat();if err!=nil||!os.SameFile(before,opened){_ = file.Close();return productupdate.ErrIntegrity};defer file.Close()
	return updater.promoteProductUpdaterReader(ctx,file,destination,size,digest)
}

func (updater *LinuxProductUpdater)promoteProductUpdaterBytes(ctx context.Context,content []byte,destination,digest string)error{return updater.promoteProductUpdaterReader(ctx,bytes.NewReader(content),destination,int64(len(content)),digest)}

func (updater *LinuxProductUpdater)promoteProductUpdaterReader(ctx context.Context,source io.Reader,destination string,size int64,digest string)error{
	if ctx==nil||!withinProductUpdaterRoot(productUpdaterReleaseRoot,destination)||size<=0||!validSHA256(digest){return productupdate.ErrInvalid}
	if _,err:=os.Lstat(destination);err==nil{return verifyPromotedProductUpdaterFile(destination,size,digest)}else if !errors.Is(err,os.ErrNotExist){return err}
	temporary:=destination+".import-"+digest[:16];_ = os.Remove(temporary)
	file,err:=os.OpenFile(temporary,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0440);if err!=nil{return err}
	hasher:=sha256.New();written,copyErr:=io.Copy(io.MultiWriter(file,hasher),io.LimitReader(&productUpdaterContextReader{ctx:ctx,reader:source},size+1))
	joined:=errors.Join(copyErr,file.Chown(0,int(updater.controlGID)),file.Chmod(0440),file.Sync(),file.Close());if joined!=nil||written!=size||hex.EncodeToString(hasher.Sum(nil))!=digest{_ = os.Remove(temporary);return errors.Join(joined,productupdate.ErrIntegrity)}
	if err=os.Link(temporary,destination);err!=nil{_ = os.Remove(temporary);if errors.Is(err,os.ErrExist){return verifyPromotedProductUpdaterFile(destination,size,digest)};return err};if err=os.Remove(temporary);err!=nil{return err};return syncProductUpdaterDirectory(filepath.Dir(destination))
}

type productUpdaterContextReader struct{ctx context.Context;reader io.Reader}
func (reader *productUpdaterContextReader)Read(content []byte)(int,error){select{case <-reader.ctx.Done():return 0,reader.ctx.Err();default:return reader.reader.Read(content)}}

func verifyPromotedProductUpdaterFile(path string,size int64,digest string)error{
	before,err:=os.Lstat(path);if err!=nil{return err};metadata,ok:=before.Sys().(*syscall.Stat_t);if !ok||metadata.Uid!=0||metadata.Nlink!=1||!before.Mode().IsRegular()||before.Mode()&os.ModeSymlink!=0||before.Mode().Perm()&0022!=0||before.Size()!=size{return productupdate.ErrIntegrity}
	file,err:=os.OpenFile(path,os.O_RDONLY|syscall.O_NOFOLLOW,0);if err!=nil{return err};hasher:=sha256.New();written,copyErr:=io.Copy(hasher,file);closeErr:=file.Close();if copyErr!=nil||closeErr!=nil||written!=size||hex.EncodeToString(hasher.Sum(nil))!=digest{return errors.Join(copyErr,closeErr,productupdate.ErrIntegrity)};return nil
}

func digestProductUpdaterBytes(content []byte)string{sum:=sha256.Sum256(content);return hex.EncodeToString(sum[:])}

func (updater *LinuxProductUpdater) apply(ctx context.Context, effect ProductUpdateEffect) (ProductUpdateResult, error) {
	if updater == nil || updater.host == nil || ctx == nil {
		return ProductUpdateResult{}, ErrInvalidEffect
	}
	digest := productUpdaterEffectDigest(effect)
	if digest == "" {
		return ProductUpdateResult{}, ErrInvalidEffect
	}
	updater.mu.Lock()
	defer updater.mu.Unlock()
	record, found, err := updater.loadJournal(digest)
	if err != nil {
		return ProductUpdateResult{}, err
	}
	if found {
		if productUpdaterEffectDigest(record.Effect) != digest || !sameProductUpdaterEffect(record.Effect, effect) {
			return ProductUpdateResult{}, ErrIdempotency
		}
		if record.State == productUpdaterComplete {
			if record.Result == nil || validateProductUpdateResult(effect, *record.Result) != nil {
				return ProductUpdateResult{}, ErrInvalidReceipt
			}
			return *record.Result, nil
		}
	} else {
		if err = updater.verifyEffectAuthorization(effect, updater.now()); err != nil {
			return ProductUpdateResult{}, err
		}
		record = productUpdaterJournalRecord{Version: 1, OperationDigest: digest, Effect: effect,
			State: productUpdaterAccepted, AcceptedAt: updater.now()}
		if err = updater.storeJournal(&record); err != nil {
			return ProductUpdateResult{}, err
		}
	}
	if record.State == productUpdaterAccepted && productUpdaterNeedsFrontier(effect.Action) {
		record.State = productUpdaterFrontier
		record.FrontierAt = updater.now()
		record.FrontierReceiptDigest = productUpdateJSONDigest(struct {
			OperationDigest string    `json:"operation_digest"`
			Action          string    `json:"action"`
			AcceptedAt      time.Time `json:"accepted_at"`
			FrontierAt      time.Time `json:"frontier_at"`
		}{record.OperationDigest, string(effect.Action), record.AcceptedAt, record.FrontierAt})
		if err = updater.storeJournal(&record); err != nil {
			return ProductUpdateResult{}, err
		}
	}
	result, err := updater.execute(ctx, record)
	if err != nil {
		record.LastFailure = boundedProductUpdaterFailure(err)
		_ = updater.storeJournal(&record)
		mutation := productUpdateActionIsMutation(effect.Action) || effect.Action == ProductUpdateProbe
		return ProductUpdateResult{MutationObserved: mutation}, err
	}
	if validateProductUpdateResult(effect, result) != nil {
		return ProductUpdateResult{}, ErrInvalidReceipt
	}
	record.State = productUpdaterComplete
	record.Result = &result
	record.LastFailure = ""
	record.CompletedAt = updater.now()
	if err = updater.storeJournal(&record); err != nil {
		return ProductUpdateResult{MutationObserved: result.MutationObserved}, err
	}
	return result, nil
}

func productUpdaterNeedsFrontier(action ProductUpdateAction) bool {
	return productUpdateActionIsMutation(action) || action == ProductUpdateInspectRollback || action == ProductUpdateProbe
}

func sameProductUpdaterEffect(left, right ProductUpdateEffect) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func boundedProductUpdaterFailure(err error) string {
	value := err.Error()
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func (updater *LinuxProductUpdater) execute(ctx context.Context, record productUpdaterJournalRecord) (ProductUpdateResult, error) {
	effect := record.Effect
	result := ProductUpdateResult{MutationObserved: productUpdateActionIsMutation(effect.Action)}
	if effect.Authorization != nil {
		result.AuthorizationDigest = effect.Authorization.Authorization.Digest
	}
	if result.MutationObserved {
		if !validSHA256(record.FrontierReceiptDigest) {
			return ProductUpdateResult{}, ErrInvalidReceipt
		}
		result.FrontierReceiptDigest = record.FrontierReceiptDigest
	}
	var err error
	switch effect.Action {
	case ProductUpdateReadiness:
		readiness := updater.readiness()
		result.Readiness = &readiness
	case ProductUpdateCurrent:
		var release productupdate.ActiveRelease
		release, _, err = updater.currentRelease(ctx)
		result.ActiveRelease = &release
	case ProductUpdateInspectRollback:
		var proof productupdate.RollbackProof
		proof, err = updater.inspectRollback(ctx, *effect.RollbackInspection)
		result.RollbackProof = &proof
	case ProductUpdateMigrationPreflight:
		var assessment productupdate.MigrationAssessment
		assessment, err = updater.preflightMigration(ctx, *effect.Migration)
		result.MigrationAssessment = &assessment
	case ProductUpdateMigrationBackup:
		var receipt productupdate.EffectReceipt
		receipt, err = updater.runMigrationHook(ctx, "backup", effect.Backup.Migration.ReleaseRoot, effect.Backup.Digest, effect.Backup)
		result.Effect = &receipt
	case ProductUpdateMigrationApply:
		var receipt productupdate.EffectReceipt
		receipt, err = updater.runMigrationHook(ctx, "apply", effect.Migration.ReleaseRoot, effect.Migration.Digest, effect.Migration)
		result.Effect = &receipt
	case ProductUpdateMigrationRollback:
		var receipt productupdate.EffectReceipt
		receipt, err = updater.runMigrationHook(ctx, "rollback", effect.MigrationRollback.Migration.ReleaseRoot, effect.MigrationRollback.Digest, effect.MigrationRollback)
		result.Effect = &receipt
	case ProductUpdateSwitch:
		var receipt productupdate.EffectReceipt
		receipt, err = updater.atomicSwitch(ctx, *effect.Switch)
		result.Effect = &receipt
	case ProductUpdateCommit:
		var receipt productupdate.EffectReceipt
		receipt, err = updater.commitSwitch(ctx, *effect.Finalize)
		result.Effect = &receipt
	case ProductUpdateRollback:
		var receipt productupdate.EffectReceipt
		receipt, err = updater.atomicRollback(ctx, *effect.Finalize)
		result.Effect = &receipt
	case ProductUpdateCaptureBaseline:
		var snapshot productupdate.HealthSnapshot
		snapshot, err = updater.captureBaseline(ctx, effect.NodeID)
		result.Health = &snapshot
	case ProductUpdateProbe:
		var snapshot productupdate.HealthSnapshot
		snapshot, err = updater.probeRelease(ctx, *effect.Probe)
		result.Health = &snapshot
	default:
		err = ErrInvalidEffect
	}
	if err != nil {
		return ProductUpdateResult{}, err
	}
	unsigned := result
	unsigned.ExecutionReceiptDigest = ""
	result.ExecutionReceiptDigest = productUpdateJSONDigest(struct {
		OperationDigest string              `json:"operation_digest"`
		Result          ProductUpdateResult `json:"result"`
	}{record.OperationDigest, unsigned})
	return result, nil
}

func (updater *LinuxProductUpdater) readiness() ProductUpdateRuntimeReadiness {
	signedAuthorization := updater.verifyTrustDocument(updater.now()) == nil
	durable := verifyProductUpdaterDirectory(ProductUpdaterStateRoot, 0700, 0) == nil &&
		verifyProductUpdaterDirectory(productUpdaterJournalRoot, 0700, 0) == nil
	_, executableErr := trustedProductUpdaterExecutable(productUpdaterExecutablePath)
	readiness := ProductUpdateRuntimeReadiness{AdapterID: "panel-updated", AdapterVersion: "linux-v1",
		SignedAuthorization: signedAuthorization, DurableAcceptance: durable, DurableFrontierReceipts: durable,
		AtomicActivation: executableErr == nil, MigrationGate: true, HealthVerification: true,
		RollbackRecovery: true, SelfUpdateIsolation: executableErr == nil}
	readiness.Complete = readiness.SignedAuthorization && readiness.DurableAcceptance && readiness.DurableFrontierReceipts &&
		readiness.AtomicActivation && readiness.MigrationGate && readiness.HealthVerification &&
		readiness.RollbackRecovery && readiness.SelfUpdateIsolation
	readiness.EvidenceDigest = productUpdateJSONDigest(readiness)
	return readiness
}

func (updater *LinuxProductUpdater) inspectRollback(ctx context.Context, operation productupdate.RollbackInspection) (productupdate.RollbackProof, error) {
	current, _, err := updater.currentRelease(ctx)
	if err != nil || current.ID != operation.Current.ID || current.Digest != operation.Current.Digest {
		return productupdate.RollbackProof{}, productupdate.ErrConflict
	}
	slot, err := updater.installInactive(ctx, operation.Target)
	if err != nil {
		return productupdate.RollbackProof{}, err
	}
	evidence := productUpdateJSONDigest(struct {
		Inspection string         `json:"inspection"`
		Slot       install.SlotID `json:"slot"`
		Current    string         `json:"current"`
		Target     string         `json:"target"`
	}{operation.Digest, slot, current.Digest, operation.Target.Digest})
	proof := productupdate.RollbackProof{InspectionDigest: operation.Digest, Valid: true,
		PreviousID: current.ID, PreviousDigest: current.Digest, EvidenceDigest: evidence}
	proof.Digest = productUpdateJSONDigest(proof)
	return proof, nil
}

func (updater *LinuxProductUpdater) preflightMigration(ctx context.Context, operation productupdate.MigrationOperation) (productupdate.MigrationAssessment, error) {
	if operation.Step.ForwardOnly && !operation.Step.BackupRequired {
		return productupdate.MigrationAssessment{}, productupdate.ErrRollback
	}
	response, err := updater.invokeMigrationHook(ctx, "preflight", operation.ReleaseRoot, operation.Digest, operation)
	if err != nil {
		return productupdate.MigrationAssessment{}, err
	}
	assessment := productupdate.MigrationAssessment{OperationDigest: operation.Digest,
		Reversible: response.Reversible && !operation.Step.ForwardOnly, EvidenceDigest: response.EvidenceDigest}
	assessment.Digest = productUpdateJSONDigest(assessment)
	return assessment, nil
}

func (updater *LinuxProductUpdater) runMigrationHook(ctx context.Context, action string, root productupdate.ReleaseRoot, operationDigest string, payload any) (productupdate.EffectReceipt, error) {
	response, err := updater.invokeMigrationHook(ctx, action, root, operationDigest, payload)
	if err != nil {
		return productupdate.EffectReceipt{}, err
	}
	if action == "backup" && !response.RecoveryTested {
		return productupdate.EffectReceipt{}, productupdate.ErrRollback
	}
	return newProductUpdaterEffectReceipt(operationDigest, response.EvidenceDigest, updater.now()), nil
}

type productUpdaterHookRequest struct {
	Version         uint16          `json:"version"`
	Action          string          `json:"action"`
	OperationDigest string          `json:"operation_digest"`
	Payload         json.RawMessage `json:"payload"`
}

type productUpdaterHookResponse struct {
	Version         uint16 `json:"version"`
	Action          string `json:"action"`
	OperationDigest string `json:"operation_digest"`
	State           string `json:"state"`
	Reversible      bool   `json:"reversible"`
	RecoveryTested  bool   `json:"recovery_tested"`
	EvidenceDigest  string `json:"evidence_digest"`
}

func (updater *LinuxProductUpdater) invokeMigrationHook(ctx context.Context, action string, root productupdate.ReleaseRoot, operationDigest string, payload any) (productUpdaterHookResponse, error) {
	if action != "preflight" && action != "backup" && action != "apply" && action != "rollback" {
		return productUpdaterHookResponse{}, productupdate.ErrInvalid
	}
	slot, err := updater.slotForRelease(root.ID, root.Digest)
	if err != nil {
		return productUpdaterHookResponse{}, err
	}
	hook := filepath.Join(productUpdaterSlotRoot, string(slot), "hooks", "product-update")
	if _, err = trustedProductUpdaterExecutable(hook); err != nil {
		return productUpdaterHookResponse{}, err
	}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) == 0 || len(raw) > productUpdaterMaximumHookFrame {
		return productUpdaterHookResponse{}, productupdate.ErrInvalid
	}
	request := productUpdaterHookRequest{Version: 1, Action: action, OperationDigest: operationDigest, Payload: raw}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return productUpdaterHookResponse{}, err
	}
	command := exec.CommandContext(ctx, hook)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "CYBERPANEL_PRODUCT_UPDATER=1"}
	command.Stdin = bytes.NewReader(requestJSON)
	var output bytes.Buffer
	command.Stdout = &limitedProductUpdaterWriter{writer: &output, remaining: productUpdaterMaximumHookFrame}
	command.Stderr = io.Discard
	if err = command.Run(); err != nil {
		return productUpdaterHookResponse{}, err
	}
	var response productUpdaterHookResponse
	if strictProductUpdaterJSON(output.Bytes(), &response) != nil || response.Version != 1 || response.Action != action ||
		response.OperationDigest != operationDigest || response.State != "completed" || !validSHA256(response.EvidenceDigest) {
		return productUpdaterHookResponse{}, ErrInvalidReceipt
	}
	return response, nil
}

type limitedProductUpdaterWriter struct {
	writer    io.Writer
	remaining int
}

func (writer *limitedProductUpdaterWriter) Write(content []byte) (int, error) {
	if len(content) > writer.remaining {
		return 0, productupdate.ErrCapacity
	}
	count, err := writer.writer.Write(content)
	writer.remaining -= count
	return count, err
}

func (updater *LinuxProductUpdater) atomicSwitch(ctx context.Context, operation productupdate.SwitchOperation) (productupdate.EffectReceipt, error) {
	current, previousSlot, err := updater.currentRelease(ctx)
	if err != nil {
		return productupdate.EffectReceipt{}, err
	}
	if current.ID != operation.Previous.ID || current.Digest != operation.Previous.Digest {
		if current.ID == operation.Target.ID && current.Digest == operation.Target.Digest {
			return newProductUpdaterEffectReceipt(operation.Digest, current.Evidence, updater.now()), nil
		}
		return productupdate.EffectReceipt{}, productupdate.ErrConflict
	}
	candidateSlot, err := updater.installInactive(ctx, operation.Target)
	if err != nil {
		return productupdate.EffectReceipt{}, err
	}
	activation := productUpdaterActivation{Version: 1, ManifestID: operation.ManifestID, OperationDigest: operation.Digest,
		PreviousSlot: previousSlot, PreviousID: current.ID, PreviousDigest: current.Digest,
		CandidateSlot: candidateSlot, CandidateID: operation.Target.ID, CandidateDigest: operation.Target.Digest,
		State: "switching", UpdatedAt: updater.now()}
	if err = updater.storeActivation(&activation); err != nil {
		return productupdate.EffectReceipt{}, err
	}
	if _, err = updater.host.ActivateSlot(ctx, candidateSlot, operation.Target.ID); err != nil {
		return productupdate.EffectReceipt{}, err
	}
	active, activeSlot, err := updater.currentRelease(ctx)
	if err != nil || activeSlot != candidateSlot || active.ID != operation.Target.ID || active.Digest != operation.Target.Digest {
		return productupdate.EffectReceipt{}, errProductUpdaterAmbiguous
	}
	activation.State = "switched"
	activation.UpdatedAt = updater.now()
	if err = updater.storeActivation(&activation); err != nil {
		return productupdate.EffectReceipt{}, err
	}
	return newProductUpdaterEffectReceipt(operation.Digest, active.Evidence, updater.now()), nil
}

func (updater *LinuxProductUpdater) commitSwitch(ctx context.Context, operation productupdate.FinalizeOperation) (productupdate.EffectReceipt, error) {
	activation, err := updater.loadActivation()
	if err != nil {
		return productupdate.EffectReceipt{}, err
	}
	active, slot, err := updater.currentRelease(ctx)
	if err != nil || slot != activation.CandidateSlot || active.ID != operation.ActiveReleaseID || active.Digest != operation.ActiveDigest ||
		activation.CandidateID != operation.ActiveReleaseID || activation.CandidateDigest != operation.ActiveDigest ||
		activation.PreviousID != operation.PreviousID || activation.PreviousDigest != operation.PreviousDigest {
		return productupdate.EffectReceipt{}, errProductUpdaterAmbiguous
	}
	updaterBinary := filepath.Join(productUpdaterSlotRoot, string(slot), "components", "panel_execd", "panel-updated")
	if _, err = trustedProductUpdaterExecutable(updaterBinary); err != nil {
		return productupdate.EffectReceipt{}, err
	}
	if err = atomicProductUpdaterSymlink(productUpdaterExecutablePath, updaterBinary); err != nil {
		return productupdate.EffectReceipt{}, err
	}
	activation.State = "committed"
	activation.UpdatedAt = updater.now()
	if err = updater.storeActivation(&activation); err != nil {
		return productupdate.EffectReceipt{}, err
	}
	evidence := productUpdateJSONDigest(struct {
		Active  string `json:"active"`
		Updater string `json:"updater"`
	}{active.Digest, updaterBinary})
	return newProductUpdaterEffectReceipt(operation.Digest, evidence, updater.now()), nil
}

func (updater *LinuxProductUpdater) atomicRollback(ctx context.Context, operation productupdate.FinalizeOperation) (productupdate.EffectReceipt, error) {
	activation, err := updater.loadActivation()
	if err != nil {
		return productupdate.EffectReceipt{}, err
	}
	if activation.PreviousID != operation.PreviousID || activation.PreviousDigest != operation.PreviousDigest ||
		activation.CandidateID != operation.ActiveReleaseID || activation.CandidateDigest != operation.ActiveDigest {
		return productupdate.EffectReceipt{}, productupdate.ErrConflict
	}
	if err = updater.rollbackActivation(ctx, &activation); err != nil {
		return productupdate.EffectReceipt{}, err
	}
	active, _, err := updater.currentRelease(ctx)
	if err != nil || active.ID != operation.PreviousID || active.Digest != operation.PreviousDigest {
		return productupdate.EffectReceipt{}, errProductUpdaterAmbiguous
	}
	return newProductUpdaterEffectReceipt(operation.Digest, active.Evidence, updater.now()), nil
}

func (updater *LinuxProductUpdater) rollbackActivation(ctx context.Context, activation *productUpdaterActivation) error {
	active, slot, err := updater.currentRelease(ctx)
	if err == nil && slot == activation.PreviousSlot && active.ID == activation.PreviousID && active.Digest == activation.PreviousDigest {
		activation.State = "rolled_back"
		activation.UpdatedAt = updater.now()
		return updater.storeActivation(activation)
	}
	if _, err = updater.host.ActivateSlot(ctx, activation.PreviousSlot, activation.PreviousID); err != nil {
		return err
	}
	active, slot, err = updater.currentRelease(ctx)
	if err != nil || slot != activation.PreviousSlot || active.ID != activation.PreviousID || active.Digest != activation.PreviousDigest {
		return errProductUpdaterAmbiguous
	}
	activation.State = "rolled_back"
	activation.UpdatedAt = updater.now()
	return updater.storeActivation(activation)
}

func (updater *LinuxProductUpdater) captureBaseline(ctx context.Context, nodeID string) (productupdate.HealthSnapshot, error) {
	release, _, err := updater.currentRelease(ctx)
	if err != nil {
		return productupdate.HealthSnapshot{}, err
	}
	evidence := updater.observeHealth(ctx, nodeID, release.Digest)
	if err = updater.storeHealthEvidence(evidence); err != nil {
		return productupdate.HealthSnapshot{}, err
	}
	snapshot := productupdate.HealthSnapshot{ID: "baseline-" + evidence.Digest[:32], NodeID: nodeID,
		ActiveReleaseDigest: release.Digest, ControlPlaneHealthy: controlPlaneHealthy(evidence),
		HostedWorkloadNonRegression: true, ObservedAt: evidence.ObservedAt, EvidenceDigest: evidence.Digest}
	snapshot.Digest = productUpdateJSONDigest(snapshot)
	if err = updater.storeHealthEvidenceForSnapshot(snapshot.Digest, evidence); err != nil {
		return productupdate.HealthSnapshot{}, err
	}
	return snapshot, nil
}

func (updater *LinuxProductUpdater) probeRelease(ctx context.Context, operation productupdate.ProbeOperation) (productupdate.HealthSnapshot, error) {
	baseline, err := updater.loadHealthEvidence(operation.BaselineDigest)
	if err != nil || baseline.NodeID != operation.NodeID {
		return productupdate.HealthSnapshot{}, productupdate.ErrIntegrity
	}
	release, _, err := updater.currentRelease(ctx)
	if err != nil || release.Digest != operation.ExpectedReleaseDigest {
		return productupdate.HealthSnapshot{}, productupdate.ErrConflict
	}
	evidence := updater.observeHealth(ctx, operation.NodeID, release.Digest)
	healthy := controlPlaneHealthy(evidence)
	nonRegression := workloadNonRegression(baseline, evidence)
	snapshot := productupdate.HealthSnapshot{ID: "probe-" + operation.Digest[:32], NodeID: operation.NodeID,
		ActiveReleaseDigest: release.Digest, ControlPlaneHealthy: healthy,
		HostedWorkloadNonRegression: nonRegression, ObservedAt: evidence.ObservedAt, EvidenceDigest: evidence.Digest}
	snapshot.Digest = productUpdateJSONDigest(snapshot)
	if healthy && nonRegression {
		return snapshot, nil
	}
	activation, activationErr := updater.loadActivation()
	if activationErr != nil || activation.CandidateDigest != operation.ExpectedReleaseDigest {
		return productupdate.HealthSnapshot{}, errProductUpdaterAmbiguous
	}
	if rollbackErr := updater.rollbackActivation(ctx, &activation); rollbackErr != nil {
		return productupdate.HealthSnapshot{}, errors.Join(install.ErrUnhealthy, rollbackErr)
	}
	return productupdate.HealthSnapshot{}, install.ErrUnhealthy
}

var productUpdaterControlUnits = []string{
	"panel-authd.service", "panel-secretd.service", "panel-execd.service", "panel-providerd.service", "panel-core.service", "panel-gateway.service", "panel-update-fetchd.service",
}

var productUpdaterWorkloadUnits = []string{
	"lsws.service", "mariadb.service", "pdns.service", "pure-ftpd.service", "postfix.service", "dovecot.service", "rspamd.service", "redis.service",
}

var productUpdaterSockets = []string{
	"/run/cyberpanel-auth/auth-verifier.sock", "/run/cyberpanel-secrets/material.sock", "/run/cyberpanel/operations.sock", "/run/cyberpanel-core/core.sock",
}

func (updater *LinuxProductUpdater) observeHealth(ctx context.Context, nodeID, releaseDigest string) productUpdaterHealthEvidence {
	evidence := productUpdaterHealthEvidence{Version: 1, NodeID: nodeID, ReleaseDigest: releaseDigest,
		Units: make(map[string]bool), Sockets: make(map[string]bool), ObservedAt: updater.now()}
	for _, unit := range append(append([]string(nil), productUpdaterControlUnits...), productUpdaterWorkloadUnits...) {
		command := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--", unit)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
		output, err := command.Output()
		evidence.Units[unit] = err == nil && strings.TrimSpace(string(output)) == "active"
	}
	for _, path := range productUpdaterSockets {
		connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		evidence.Sockets[path] = err == nil
		if connection != nil {
			_ = connection.Close()
		}
	}
	evidence.Digest = productUpdateJSONDigest(evidence)
	return evidence
}

func controlPlaneHealthy(evidence productUpdaterHealthEvidence) bool {
	for _, unit := range productUpdaterControlUnits {
		if !evidence.Units[unit] {
			return false
		}
	}
	for _, path := range productUpdaterSockets {
		if !evidence.Sockets[path] {
			return false
		}
	}
	return true
}

func workloadNonRegression(baseline, observed productUpdaterHealthEvidence) bool {
	for _, unit := range productUpdaterWorkloadUnits {
		if baseline.Units[unit] && !observed.Units[unit] {
			return false
		}
	}
	return true
}

func (updater *LinuxProductUpdater) currentRelease(ctx context.Context) (productupdate.ActiveRelease, install.SlotID, error) {
	slot, releaseID, err := updater.host.CurrentSlot(ctx)
	if err != nil {
		return productupdate.ActiveRelease{}, "", err
	}
	root := filepath.Join(productUpdaterSlotRoot, string(slot))
	marker, markerErr := loadProductUpdaterReleaseMarker(filepath.Join(root, ".product-release.json"))
	digest := ""
	if markerErr == nil {
		if marker.ReleaseID != releaseID {
			return productupdate.ActiveRelease{}, "", productupdate.ErrIntegrity
		}
		digest = marker.ReleaseDigest
	} else if errors.Is(markerErr, os.ErrNotExist) {
		digest, err = digestProductUpdaterTree(root, true)
		if err != nil {
			return productupdate.ActiveRelease{}, "", err
		}
	} else {
		return productupdate.ActiveRelease{}, "", markerErr
	}
	evidence := productUpdateJSONDigest(struct {
		Slot    install.SlotID `json:"slot"`
		Release string         `json:"release"`
		Digest  string         `json:"digest"`
	}{slot, releaseID, digest})
	return productupdate.ActiveRelease{ID: releaseID, Digest: digest, Evidence: evidence}, slot, nil
}

func (updater *LinuxProductUpdater) installInactive(ctx context.Context, root productupdate.ReleaseRoot) (install.SlotID, error) {
	if !validProductUpdateIdentifier(root.ID) || !validSHA256(root.Digest) {
		return "", productupdate.ErrInvalid
	}
	_, activeSlot, err := updater.currentRelease(ctx)
	if err != nil {
		return "", err
	}
	targetSlot := activeSlot.Other()
	target := filepath.Join(productUpdaterSlotRoot, string(targetSlot))
	if marker, markerErr := loadProductUpdaterReleaseMarker(filepath.Join(target, ".product-release.json")); markerErr == nil &&
		marker.ReleaseID == root.ID && marker.ReleaseDigest == root.Digest {
		return targetSlot, nil
	}
	source, err := updater.verifyStagedRelease(root)
	if err != nil {
		return "", err
	}
	parent := productUpdaterSlotRoot
	if err = ensureProductUpdaterDirectory(parent, 0755); err != nil {
		return "", err
	}
	temporary := filepath.Join(parent, ".candidate-"+string(targetSlot)+"-"+root.Digest[:16])
	superseded := filepath.Join(parent, ".superseded-"+string(targetSlot))
	if err = removeProductUpdaterTree(temporary, parent); err != nil {
		return "", err
	}
	if err = os.Mkdir(temporary, 0755); err != nil {
		return "", err
	}
	if err = copyProductUpdaterTree(ctx, source, temporary); err != nil {
		_ = removeProductUpdaterTree(temporary, parent)
		return "", err
	}
	digest, err := digestProductUpdaterTree(temporary, false)
	if err != nil || digest != root.Digest {
		_ = removeProductUpdaterTree(temporary, parent)
		return "", productupdate.ErrIntegrity
	}
	marker := productUpdaterReleaseMarker{Version: 1, ReleaseID: root.ID, ReleaseDigest: root.Digest,
		SourceRootID: root.ID, InstalledAt: updater.now()}
	if err = storeProductUpdaterReleaseMarker(filepath.Join(temporary, ".product-release.json"), &marker); err != nil {
		_ = removeProductUpdaterTree(temporary, parent)
		return "", err
	}
	if err = writeProductUpdaterFile(filepath.Join(temporary, "RELEASE"), []byte(root.ID+"\n"), 0644); err != nil {
		_ = removeProductUpdaterTree(temporary, parent)
		return "", err
	}
	if _, err = trustedProductUpdaterExecutable(filepath.Join(temporary, "components", "panel_execd", "panel-updated")); err != nil {
		_ = removeProductUpdaterTree(temporary, parent)
		return "", err
	}
	if err = makeProductUpdaterTreeImmutable(temporary); err != nil {
		_ = removeProductUpdaterTree(temporary, parent)
		return "", err
	}
	if err = removeProductUpdaterTree(superseded, parent); err != nil {
		return "", err
	}
	if _, statErr := os.Lstat(target); statErr == nil {
		if err = os.Rename(target, superseded); err != nil {
			return "", err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	if err = os.Rename(temporary, target); err != nil {
		_ = os.Rename(superseded, target)
		return "", err
	}
	if err = syncProductUpdaterDirectory(parent); err != nil {
		return "", err
	}
	if err = removeProductUpdaterTree(superseded, parent); err != nil {
		return "", err
	}
	return targetSlot, nil
}

func (updater *LinuxProductUpdater) verifyStagedRelease(root productupdate.ReleaseRoot) (string, error) {
	if err := verifyProductUpdaterDirectory(productUpdaterStagingRoot, 0700, updater.controlUID); err != nil {
		return "", err
	}
	releaseRoot := filepath.Join(productUpdaterStagingRoot, "releases", root.ID)
	if !withinProductUpdaterRoot(filepath.Join(productUpdaterStagingRoot, "releases"), releaseRoot) {
		return "", productupdate.ErrIntegrity
	}
	markerRaw, err := readProductUpdaterFile(filepath.Join(releaseRoot, "release.json"), 1<<20, updater.controlUID)
	if err != nil {
		return "", err
	}
	var release productUpdaterStagedRelease
	if strictProductUpdaterJSON(markerRaw, &release) != nil || release.Root.ID != root.ID || release.Root.Digest != root.Digest ||
		!validProductUpdateIdentifier(release.ManifestID) || !validSHA256(release.ManifestDigest) || !validSHA256(release.EvidenceDigest) ||
		release.FileCount <= 0 || release.ExtractedBytes <= 0 {
		return "", productupdate.ErrIntegrity
	}
	content := filepath.Join(releaseRoot, "content")
	if err = verifyProductUpdaterDirectory(content, 0555, updater.controlUID); err != nil {
		return "", err
	}
	digest, err := digestProductUpdaterTree(content, false)
	if err != nil || digest != root.Digest {
		return "", productupdate.ErrIntegrity
	}
	return content, nil
}

func (updater *LinuxProductUpdater) slotForRelease(id, digest string) (install.SlotID, error) {
	for _, slot := range []install.SlotID{install.SlotA, install.SlotB} {
		marker, err := loadProductUpdaterReleaseMarker(filepath.Join(productUpdaterSlotRoot, string(slot), ".product-release.json"))
		if err == nil && marker.ReleaseID == id && marker.ReleaseDigest == digest {
			return slot, nil
		}
	}
	return "", productupdate.ErrNotFound
}

func (updater *LinuxProductUpdater) journalPath(digest string) (string, error) {
	if !validSHA256(digest) {
		return "", ErrInvalidEffect
	}
	return filepath.Join(productUpdaterJournalRoot, digest+".json"), nil
}

func (updater *LinuxProductUpdater) loadJournal(digest string) (productUpdaterJournalRecord, bool, error) {
	path, err := updater.journalPath(digest)
	if err != nil {
		return productUpdaterJournalRecord{}, false, err
	}
	raw, err := readProductUpdaterFile(path, productUpdaterMaximumFrame, 0)
	if errors.Is(err, os.ErrNotExist) {
		return productUpdaterJournalRecord{}, false, nil
	}
	if err != nil {
		return productUpdaterJournalRecord{}, false, err
	}
	var record productUpdaterJournalRecord
	if strictProductUpdaterJSON(raw, &record) != nil || record.Version != 1 || record.OperationDigest != digest ||
		productUpdaterEffectDigest(record.Effect) != digest || record.AcceptedAt.IsZero() || record.AcceptedAt.Location() != time.UTC ||
		(record.State != productUpdaterAccepted && record.State != productUpdaterFrontier && record.State != productUpdaterComplete) {
		return productUpdaterJournalRecord{}, false, ErrInvalidReceipt
	}
	claimed := record.RecordDigest
	record.RecordDigest = ""
	if claimed != productUpdateJSONDigest(record) {
		return productUpdaterJournalRecord{}, false, ErrInvalidReceipt
	}
	record.RecordDigest = claimed
	if record.State == productUpdaterComplete && (record.Result == nil || validateProductUpdateResult(record.Effect, *record.Result) != nil) {
		return productUpdaterJournalRecord{}, false, ErrInvalidReceipt
	}
	return record, true, nil
}

func (updater *LinuxProductUpdater) storeJournal(record *productUpdaterJournalRecord) error {
	path, err := updater.journalPath(record.OperationDigest)
	if err != nil {
		return err
	}
	record.RecordDigest = ""
	record.RecordDigest = productUpdateJSONDigest(*record)
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > productUpdaterMaximumFrame {
		return ErrInvalidReceipt
	}
	return writeProductUpdaterFile(path, raw, 0600)
}

func (updater *LinuxProductUpdater) loadActivation() (productUpdaterActivation, error) {
	raw, err := readProductUpdaterFile(productUpdaterActivationPath, 1<<20, 0)
	if err != nil {
		return productUpdaterActivation{}, err
	}
	var activation productUpdaterActivation
	if strictProductUpdaterJSON(raw, &activation) != nil || activation.Version != 1 ||
		(activation.PreviousSlot != install.SlotA && activation.PreviousSlot != install.SlotB) ||
		(activation.CandidateSlot != install.SlotA && activation.CandidateSlot != install.SlotB) ||
		activation.PreviousSlot == activation.CandidateSlot || !validSHA256(activation.PreviousDigest) ||
		!validSHA256(activation.CandidateDigest) || !validProductUpdateIdentifier(activation.PreviousID) ||
		!validProductUpdateIdentifier(activation.CandidateID) {
		return productUpdaterActivation{}, ErrInvalidReceipt
	}
	claimed := activation.RecordDigest
	activation.RecordDigest = ""
	if claimed != productUpdateJSONDigest(activation) {
		return productUpdaterActivation{}, ErrInvalidReceipt
	}
	activation.RecordDigest = claimed
	return activation, nil
}

func (updater *LinuxProductUpdater) storeActivation(activation *productUpdaterActivation) error {
	activation.RecordDigest = ""
	activation.RecordDigest = productUpdateJSONDigest(*activation)
	raw, err := json.Marshal(activation)
	if err != nil {
		return err
	}
	return writeProductUpdaterFile(productUpdaterActivationPath, raw, 0600)
}

func (updater *LinuxProductUpdater) storeHealthEvidence(evidence productUpdaterHealthEvidence) error {
	if !validSHA256(evidence.Digest) {
		return ErrInvalidReceipt
	}
	path := filepath.Join(productUpdaterBaselineRoot, "evidence-"+evidence.Digest+".json")
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	return writeProductUpdaterFile(path, raw, 0600)
}

func (updater *LinuxProductUpdater) storeHealthEvidenceForSnapshot(snapshotDigest string, evidence productUpdaterHealthEvidence) error {
	if !validSHA256(snapshotDigest) {
		return ErrInvalidReceipt
	}
	path := filepath.Join(productUpdaterBaselineRoot, snapshotDigest+".json")
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	return writeProductUpdaterFile(path, raw, 0600)
}

func (updater *LinuxProductUpdater) loadHealthEvidence(snapshotDigest string) (productUpdaterHealthEvidence, error) {
	if !validSHA256(snapshotDigest) {
		return productUpdaterHealthEvidence{}, productupdate.ErrInvalid
	}
	raw, err := readProductUpdaterFile(filepath.Join(productUpdaterBaselineRoot, snapshotDigest+".json"), 1<<20, 0)
	if err != nil {
		return productUpdaterHealthEvidence{}, err
	}
	var evidence productUpdaterHealthEvidence
	if strictProductUpdaterJSON(raw, &evidence) != nil || evidence.Version != 1 || !validSHA256(evidence.Digest) {
		return productUpdaterHealthEvidence{}, ErrInvalidReceipt
	}
	claimed := evidence.Digest
	evidence.Digest = ""
	if claimed != productUpdateJSONDigest(evidence) {
		return productUpdaterHealthEvidence{}, ErrInvalidReceipt
	}
	evidence.Digest = claimed
	return evidence, nil
}

type productUpdaterTrustDocument struct {
	CurrentEpoch            uint64            `json:"current_epoch"`
	Threshold               uint16            `json:"threshold"`
	MaximumClockSkewSeconds int64             `json:"maximum_clock_skew_seconds"`
	MaximumLifetimeSeconds  int64             `json:"maximum_lifetime_seconds"`
	MaximumManifestBytes    int64             `json:"maximum_manifest_bytes"`
	ManifestRoots           []productUpdaterManifestRootDocument `json:"manifest_roots"`
	AuthorizationRootsPEM   string            `json:"authorization_roots_pem"`
	Staging                 productUpdaterStagingLimitsDocument `json:"staging"`
}

type productUpdaterManifestRootDocument struct{KeyID string `json:"key_id"`;Epoch uint64 `json:"epoch"`;PublicKey string `json:"public_key"`;NotBefore time.Time `json:"not_before"`;NotAfter time.Time `json:"not_after"`;Revoked bool `json:"revoked"`}
type productUpdaterStagingLimitsDocument struct{MaximumArtifactBytes int64 `json:"maximum_artifact_bytes"`;MaximumTotalBytes int64 `json:"maximum_total_bytes"`;MaximumExtractedBytes int64 `json:"maximum_extracted_bytes"`;MaximumFileBytes int64 `json:"maximum_file_bytes"`;MaximumFiles int `json:"maximum_files"`;MaximumPathBytes int `json:"maximum_path_bytes"`}

func loadProductUpdaterManifestVerifier(now time.Time)(*productupdate.Verifier,productupdate.StagingLimits,int64,error){
	raw,err:=readProductUpdaterFile(productUpdaterTrustPath,1<<20,0);if err!=nil{return nil,productupdate.StagingLimits{},0,err};var document productUpdaterTrustDocument
	if decodeProductUpdaterJSON(raw,&document)!=nil||document.Threshold<2||document.MaximumClockSkewSeconds<0||document.MaximumClockSkewSeconds>600||document.MaximumLifetimeSeconds<=0||document.MaximumLifetimeSeconds>int64((366*24*time.Hour)/time.Second)||document.MaximumManifestBytes<=0||document.MaximumManifestBytes>16<<20||len(document.ManifestRoots)<int(document.Threshold){return nil,productupdate.StagingLimits{},0,productupdate.ErrInvalid}
	limits:=productupdate.StagingLimits{MaximumArtifactBytes:document.Staging.MaximumArtifactBytes,MaximumTotalBytes:document.Staging.MaximumTotalBytes,MaximumExtractedBytes:document.Staging.MaximumExtractedBytes,MaximumFileBytes:document.Staging.MaximumFileBytes,MaximumFiles:document.Staging.MaximumFiles,MaximumPathBytes:document.Staging.MaximumPathBytes}
	if limits.MaximumArtifactBytes<=0||limits.MaximumArtifactBytes>4<<30||limits.MaximumTotalBytes<limits.MaximumArtifactBytes||limits.MaximumTotalBytes>16<<30||limits.MaximumExtractedBytes<=0||limits.MaximumExtractedBytes>32<<30||limits.MaximumFileBytes<=0||limits.MaximumFileBytes>limits.MaximumExtractedBytes||limits.MaximumFiles<=0||limits.MaximumFiles>1000000||limits.MaximumPathBytes<16||limits.MaximumPathBytes>4096{return nil,productupdate.StagingLimits{},0,productupdate.ErrInvalid}
	roots:=make([]productupdate.TrustRoot,0,len(document.ManifestRoots));active:=0
	for _,entry:=range document.ManifestRoots{key,decodeErr:=decodeProductUpdaterPublicKey(entry.PublicKey);if decodeErr!=nil{return nil,productupdate.StagingLimits{},0,decodeErr};root:=productupdate.TrustRoot{KeyID:entry.KeyID,Epoch:entry.Epoch,PublicKey:key,NotBefore:entry.NotBefore.UTC(),NotAfter:entry.NotAfter.UTC(),Revoked:entry.Revoked};if !root.Revoked&&root.Epoch==document.CurrentEpoch&&!now.Before(root.NotBefore)&&now.Before(root.NotAfter){active++};roots=append(roots,root)}
	if active<int(document.Threshold){return nil,productupdate.StagingLimits{},0,productupdate.ErrUnauthorized}
	verifier,err:=productupdate.NewVerifier(productupdate.TrustPolicy{Roots:roots,Threshold:document.Threshold,CurrentEpoch:document.CurrentEpoch,MaximumClockSkew:time.Duration(document.MaximumClockSkewSeconds)*time.Second,MaximumLifetime:time.Duration(document.MaximumLifetimeSeconds)*time.Second,MaximumBytes:document.MaximumManifestBytes});if err!=nil{return nil,productupdate.StagingLimits{},0,err}
	return verifier,limits,document.MaximumManifestBytes,nil
}

func decodeProductUpdaterPublicKey(value string)(ed25519.PublicKey,error){value=strings.TrimSpace(value);var decoded []byte;var err error;for _,encoding:=range []*base64.Encoding{base64.RawURLEncoding,base64.URLEncoding,base64.RawStdEncoding,base64.StdEncoding}{decoded,err=encoding.DecodeString(value);if err==nil{break}};if err!=nil{decoded,err=hex.DecodeString(value)};if err!=nil||len(decoded)!=ed25519.PublicKeySize{return nil,productupdate.ErrInvalid};return ed25519.PublicKey(decoded),nil}

func (updater *LinuxProductUpdater) verifyTrustDocument(now time.Time) error {
	_, err := loadProductUpdaterAuthorizationRoots(now)
	return err
}

func (updater *LinuxProductUpdater) verifyEffectAuthorization(effect ProductUpdateEffect, now time.Time) error {
	if effect.Authorization == nil {
		switch effect.Action {
		case ProductUpdateReadiness, ProductUpdateCurrent, ProductUpdateCaptureBaseline:
			return nil
		default:
			return ErrUnauthorized
		}
	}
	action, err := productUpdaterAuthorizationAction(effect.Action)
	if err != nil {
		return err
	}
	envelope := effect.Authorization
	authorization, err := productupdate.CanonicalAuthorization(envelope.Authorization,
		productupdate.ReleaseManifest{Digest: envelope.Authorization.ManifestDigest}, effect.NodeID, action, now.UTC())
	if err != nil {
		return err
	}
	roots, err := loadProductUpdaterAuthorizationRoots(now)
	if err != nil {
		return err
	}
	certificates, err := parseProductUpdaterCertificateChain([]byte(envelope.CertificateChainPEM))
	if err != nil {
		return err
	}
	leaf := certificates[0]
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil || leaf.IsCA ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !productUpdaterCertificateAllowsCodeSigning(leaf) ||
		authorization.IssuedAt.Before(leaf.NotBefore) || authorization.ExpiresAt.After(leaf.NotAfter) {
		return ErrUnauthorized
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return ErrUnauthorized
	}
	payloadAuthorization := authorization
	payloadAuthorization.ProofDigest = ""
	payloadAuthorization.Digest = ""
	payload, err := json.Marshal(payloadAuthorization)
	if err != nil {
		return err
	}
	signature, err := decodeProductUpdaterSignature(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, append([]byte(productUpdaterAuthorizationDomain), payload...), signature) {
		return ErrUnauthorized
	}
	proof := sha256.New()
	_, _ = proof.Write([]byte(productUpdaterAuthorizationProofDomain))
	_, _ = proof.Write(leaf.RawSubjectPublicKeyInfo)
	_, _ = proof.Write([]byte{0})
	_, _ = proof.Write(signature)
	_, _ = proof.Write([]byte{0})
	_, _ = proof.Write(payload)
	keyDigest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	wantedIssuer := "update-authority-" + hex.EncodeToString(keyDigest[:])[:32]
	if authorization.ProofDigest != hex.EncodeToString(proof.Sum(nil)) || authorization.Issuer != wantedIssuer {
		return ErrUnauthorized
	}
	return nil
}

func productUpdaterAuthorizationAction(action ProductUpdateAction) (productupdate.UpdateAction, error) {
	switch action {
	case ProductUpdateInspectRollback, ProductUpdateMigrationPreflight, ProductUpdateMigrationBackup, ProductUpdateMigrationApply:
		return productupdate.ActionPreflight, nil
	case ProductUpdateSwitch:
		return productupdate.ActionSwitch, nil
	case ProductUpdateMigrationRollback, ProductUpdateCommit, ProductUpdateRollback, ProductUpdateProbe:
		return productupdate.ActionFinalize, nil
	default:
		return "", ErrUnauthorized
	}
}

func loadProductUpdaterAuthorizationRoots(now time.Time) (*x509.CertPool, error) {
	raw, err := readProductUpdaterFile(productUpdaterTrustPath, 1<<20, 0)
	if err != nil {
		return nil, err
	}
	var document productUpdaterTrustDocument
	if decodeProductUpdaterJSON(raw, &document) != nil || len(document.AuthorizationRootsPEM) == 0 {
		return nil, productupdate.ErrIntegrity
	}
	pool := x509.NewCertPool()
	rest := []byte(document.AuthorizationRootsPEM)
	count := 0
	for len(bytes.TrimSpace(rest)) != 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(next) >= len(rest) || count == 16 {
			return nil, productupdate.ErrIntegrity
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
			certificate.CheckSignatureFrom(certificate) != nil {
			return nil, ErrUnauthorized
		}
		pool.AddCert(certificate)
		count++
		rest = next
	}
	if count == 0 {
		return nil, productupdate.ErrIntegrity
	}
	return pool, nil
}

func parseProductUpdaterCertificateChain(content []byte) ([]*x509.Certificate, error) {
	if len(content) == 0 || len(content) > 1<<20 {
		return nil, productupdate.ErrInvalid
	}
	result := make([]*x509.Certificate, 0, 4)
	rest := content
	for len(bytes.TrimSpace(rest)) != 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(next) >= len(rest) || len(result) == 8 {
			return nil, productupdate.ErrInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, productupdate.ErrInvalid
		}
		result = append(result, certificate)
		rest = next
	}
	if len(result) == 0 {
		return nil, productupdate.ErrInvalid
	}
	return result, nil
}

func productUpdaterCertificateAllowsCodeSigning(certificate *x509.Certificate) bool {
	if certificate == nil || len(certificate.ExtKeyUsage) == 0 {
		return false
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

func decodeProductUpdaterSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) == ed25519.SignatureSize {
			return decoded, nil
		}
	}
	return nil, productupdate.ErrInvalid
}

func newProductUpdaterEffectReceipt(operationDigest, evidenceDigest string, now time.Time) productupdate.EffectReceipt {
	receipt := productupdate.EffectReceipt{ID: "updater-effect-" + operationDigest[:32], OperationDigest: operationDigest,
		EvidenceDigest: evidenceDigest, Completed: true, At: now.UTC()}
	receipt.Digest = productUpdateJSONDigest(receipt)
	return receipt
}

func loadProductUpdaterReleaseMarker(path string) (productUpdaterReleaseMarker, error) {
	raw, err := readProductUpdaterFile(path, 1<<20, 0)
	if err != nil {
		return productUpdaterReleaseMarker{}, err
	}
	var marker productUpdaterReleaseMarker
	if strictProductUpdaterJSON(raw, &marker) != nil || marker.Version != 1 || !validProductUpdateIdentifier(marker.ReleaseID) ||
		!validSHA256(marker.ReleaseDigest) || !validProductUpdateIdentifier(marker.SourceRootID) || marker.InstalledAt.IsZero() {
		return productUpdaterReleaseMarker{}, productupdate.ErrIntegrity
	}
	claimed := marker.RecordDigest
	marker.RecordDigest = ""
	if claimed != productUpdateJSONDigest(marker) {
		return productUpdaterReleaseMarker{}, productupdate.ErrIntegrity
	}
	marker.RecordDigest = claimed
	return marker, nil
}

func storeProductUpdaterReleaseMarker(path string, marker *productUpdaterReleaseMarker) error {
	marker.RecordDigest = ""
	marker.RecordDigest = productUpdateJSONDigest(*marker)
	raw, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	return writeProductUpdaterFile(path, raw, 0444)
}

func digestProductUpdaterTree(root string, ignoreReleaseMetadata bool) (string, error) {
	files := make([]productUpdaterStagedFile, 0)
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return productupdate.ErrIntegrity
		}
		if info.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if ignoreReleaseMetadata && (relative == "RELEASE" || relative == ".product-release.json") {
			return nil
		}
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		hasher := sha256.New()
		size, copyErr := io.Copy(hasher, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || size != info.Size() {
			return errors.Join(copyErr, closeErr, productupdate.ErrIntegrity)
		}
		files = append(files, productUpdaterStagedFile{Path: filepath.ToSlash(relative), Mode: uint32(info.Mode().Perm() & 0555),
			Size: size, Digest: hex.EncodeToString(hasher.Sum(nil))})
		return nil
	})
	if err != nil || len(files) == 0 {
		return "", errors.Join(err, productupdate.ErrIntegrity)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return productUpdateJSONDigest(files), nil
}

func copyProductUpdaterTree(ctx context.Context, source, destination string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return productupdate.ErrIntegrity
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return productupdate.ErrIntegrity
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			if relative == "." {
				return nil
			}
			return os.Mkdir(target, 0755)
		}
		input, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		mode := info.Mode().Perm() & 0555
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		joined := errors.Join(copyErr, output.Sync(), output.Chown(0, 0), output.Chmod(mode), output.Close(), input.Close())
		return joined
	})
}

func makeProductUpdaterTreeImmutable(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return productupdate.ErrIntegrity
		}
		if info.IsDir() {
			return os.Chmod(path, 0555)
		}
		return os.Chmod(path, info.Mode().Perm()&0555)
	})
}

func trustedProductUpdaterExecutable(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return "", productupdate.ErrIntegrity
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func atomicProductUpdaterSymlink(path, target string) error {
	if path != productUpdaterExecutablePath || !filepath.IsAbs(target) || !withinProductUpdaterRoot(productUpdaterSlotRoot, target) {
		return productupdate.ErrInvalid
	}
	temporary := path + ".new"
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncProductUpdaterDirectory(filepath.Dir(path))
}

func (updater *LinuxProductUpdater) restartSelfAfterAcknowledgement() {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	command := exec.Command("/usr/bin/systemctl", "--no-block", "restart", "panel-updated.service")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	_ = command.Run()
}

func ensureProductUpdaterDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return productupdate.ErrInvalid
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return verifyProductUpdaterDirectory(path, mode, 0)
}

func verifyProductUpdaterDirectory(path string, maximum os.FileMode, owner uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != owner || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&^maximum != 0 || info.Mode().Perm()&0022 != 0 {
		return productupdate.ErrIntegrity
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return productupdate.ErrIntegrity
	}
	return nil
}

func readProductUpdaterFile(path string, maximum int64, owner uint32) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, productupdate.ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	metadata, ok := before.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != owner || metadata.Nlink != 1 || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&0022 != 0 || before.Size() <= 0 || before.Size() > maximum {
		return nil, productupdate.ErrIntegrity
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, productupdate.ErrIntegrity
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != before.Size() {
		return nil, productupdate.ErrIntegrity
	}
	return raw, nil
}

func writeProductUpdaterFile(path string, content []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || mode&0022 != 0 || len(content) == 0 {
		return productupdate.ErrInvalid
	}
	directory := filepath.Dir(path)
	if err := verifyProductUpdaterDirectory(directory, 0755, 0); err != nil {
		return err
	}
	temporary := path + ".new"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	joined := errors.Join(writeErr, file.Sync(), file.Chown(0, 0), file.Chmod(mode), file.Close())
	if joined != nil {
		_ = os.Remove(temporary)
		return joined
	}
	if err = os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncProductUpdaterDirectory(directory)
}

func strictProductUpdaterJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return productupdate.ErrIntegrity
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, raw) {
		return productupdate.ErrIntegrity
	}
	return nil
}

func decodeProductUpdaterJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return productupdate.ErrIntegrity
	}
	return nil
}

func removeProductUpdaterTree(path, parent string) error {
	if !withinProductUpdaterRoot(parent, path) || filepath.Dir(path) != parent {
		return productupdate.ErrInvalid
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return os.RemoveAll(path)
}

func withinProductUpdaterRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) && !filepath.IsAbs(relative)
}

func syncProductUpdaterDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

var _ ProductUpdateExecutor = (*ProductUpdaterClient)(nil)
var _ ProductUpdateExecutor = (*LinuxProductUpdater)(nil)
