//go:build linux

package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const MailDaemonSocketPath = "/run/cyberpanel/maild.sock"
const mailDaemonLockPath = "/run/cyberpanel/maild.lock"
const mailBrokerFrameLimit = 32 << 20

type MailBrokerOperation string

const (
	MailBrokerApply             MailBrokerOperation = "apply_generation"
	MailBrokerQueueList         MailBrokerOperation = "queue_list"
	MailBrokerQueueAction       MailBrokerOperation = "queue_action"
	MailBrokerService           MailBrokerOperation = "service"
	MailBrokerWebmailFolders    MailBrokerOperation = "webmail_folders"
	MailBrokerWebmailSearch     MailBrokerOperation = "webmail_search"
	MailBrokerWebmailRead       MailBrokerOperation = "webmail_read"
	MailBrokerWebmailAttachment MailBrokerOperation = "webmail_attachment"
	MailBrokerWebmailMove       MailBrokerOperation = "webmail_move"
	MailBrokerWebmailDelete     MailBrokerOperation = "webmail_delete"
	MailBrokerWebmailFlags      MailBrokerOperation = "webmail_flags"
	MailBrokerWebmailSubmit     MailBrokerOperation = "webmail_submit"
	MailBrokerCampaignSubmit    MailBrokerOperation = "campaign_submit"
)

type WebmailBinding struct {
	TenantID   string    `json:"tenant_id"`
	MailboxID  MailboxID `json:"mailbox_id"`
	Address    Address   `json:"address"`
	ServerName string    `json:"server_name"`
}

func (binding WebmailBinding) Validate() error {
	if !validOpaque(binding.TenantID) || !validOpaque(string(binding.MailboxID)) || ValidateAddress(binding.Address) != nil || !validHostname(binding.ServerName) {
		return ErrInvalidCommand
	}
	return nil
}

type MailBrokerRequest struct {
	Version       uint8                   `json:"version"`
	RequestID     string                  `json:"request_id"`
	Operation     MailBrokerOperation     `json:"operation"`
	Deadline      time.Time               `json:"deadline"`
	Effect        EffectRequest           `json:"effect,omitempty"`
	Generation    ConfigGeneration        `json:"generation,omitempty"`
	QueueAction   MailQueueAction         `json:"queue_action,omitempty"`
	QueueID       QueueID                 `json:"queue_id,omitempty"`
	QueueLimit    uint32                  `json:"queue_limit,omitempty"`
	Service       MailService             `json:"service,omitempty"`
	ServiceAction MailServiceAction       `json:"service_action,omitempty"`
	Webmail       WebmailBinding          `json:"webmail,omitempty"`
	MessageQuery  MessageQuery            `json:"message_query,omitempty"`
	MessageID     MessageID               `json:"message_id,omitempty"`
	AttachmentID  AttachmentID            `json:"attachment_id,omitempty"`
	FolderID      FolderID                `json:"folder_id,omitempty"`
	Flags         []string                `json:"flags,omitempty"`
	Compose       ComposeMessage          `json:"compose,omitempty"`
	Campaign      CampaignSubmission      `json:"campaign,omitempty"`
	Maildir       *MaildirImportRequest   `json:"maildir,omitempty"`
	Publication   *MailPublicationRequest `json:"publication,omitempty"`
}
type MailBrokerResponse struct {
	Version           uint8                   `json:"version"`
	RequestID         string                  `json:"request_id"`
	Operation         MailBrokerOperation     `json:"operation"`
	FailureCode       string                  `json:"failure_code,omitempty"`
	Effect            EffectReceipt           `json:"effect,omitempty"`
	Activation        MailActivationReceipt   `json:"activation,omitempty"`
	Queue             []MailQueueRecord       `json:"queue,omitempty"`
	QueueReceipt      MailQueueReceipt        `json:"queue_receipt,omitempty"`
	ServiceReceipt    MailServiceReceipt      `json:"service_receipt,omitempty"`
	EvidenceDigest    string                  `json:"evidence_digest,omitempty"`
	Folders           []Folder                `json:"folders,omitempty"`
	MessagePage       MessagePage             `json:"message_page,omitempty"`
	MessageView       MessageView             `json:"message_view,omitempty"`
	AttachmentInfo    AttachmentInfo          `json:"attachment_info,omitempty"`
	AttachmentContent []byte                  `json:"attachment_content,omitempty"`
	SubmittedQueueID  QueueID                 `json:"submitted_queue_id,omitempty"`
	Maildir           *MaildirImportReceipt   `json:"maildir,omitempty"`
	Publication       *MailPublicationReceipt `json:"publication,omitempty"`
	ObservedAt        time.Time               `json:"observed_at"`
}

func (request MailBrokerRequest) Validate(now time.Time) error {
	if request.Version != 1 || !validBrokerID(request.RequestID) || request.Deadline.Before(now.Add(-time.Second)) || request.Deadline.After(now.Add(5*time.Minute)) {
		return ErrInvalidCommand
	}
	switch request.Operation {
	case MailBrokerMaildirImport:
		if request.Maildir == nil || request.Maildir.Validate() != nil {
			return ErrInvalidCommand
		}
	case MailBrokerMigrationPublication:
		if request.Publication == nil || request.Publication.Validate() != nil {
			return ErrInvalidCommand
		}
	case MailBrokerApply:
		if !validBrokerID(request.Effect.EffectID) || request.Effect.Generation == 0 || !validMailEvidenceDigest(request.Effect.DesiredDigest) || !validMailGenerationID(request.Generation.ID) || !validMailEvidenceDigest(request.Generation.Digest) {
			return ErrInvalidCommand
		}
	case MailBrokerQueueList:
		if request.QueueLimit == 0 || request.QueueLimit > 10000 {
			return ErrInvalidCommand
		}
	case MailBrokerQueueAction:
		if !validQueueAction(request.QueueAction) {
			return ErrInvalidCommand
		}
		if request.QueueAction == QueueFlush {
			if request.QueueID != "" {
				return ErrInvalidCommand
			}
		} else if !validPostfixQueueID(request.QueueID) {
			return ErrInvalidCommand
		}
	case MailBrokerService:
		if !validMailService(request.Service) || !validServiceAction(request.ServiceAction) {
			return ErrInvalidCommand
		}
	case MailBrokerWebmailFolders, MailBrokerWebmailSearch, MailBrokerWebmailRead, MailBrokerWebmailAttachment, MailBrokerWebmailMove, MailBrokerWebmailDelete, MailBrokerWebmailFlags, MailBrokerWebmailSubmit:
		if validWebmailBrokerRequest(request) != nil {
			return ErrInvalidCommand
		}
	case MailBrokerCampaignSubmit:
		if request.Campaign.Validate() != nil {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}
func (response MailBrokerResponse) Validate(request MailBrokerRequest, now time.Time) error {
	if response.Version != 1 || response.RequestID != request.RequestID || response.Operation != request.Operation || response.ObservedAt.IsZero() || response.ObservedAt.After(now.Add(time.Minute)) {
		return ErrInvalidReceipt
	}
	if response.FailureCode != "" && !validMailFailureCode(response.FailureCode) {
		return ErrInvalidReceipt
	}
	switch request.Operation {
	case MailBrokerMaildirImport:
		if request.Maildir == nil || response.Maildir == nil || !response.Maildir.valid(*request.Maildir) || response.FailureCode != "" {
			return ErrInvalidReceipt
		}
	case MailBrokerMigrationPublication:
		if request.Publication == nil || response.Publication == nil || !response.Publication.valid(*request.Publication) {
			return ErrInvalidReceipt
		}
	case MailBrokerApply:
		if !validEffect(response.Effect, request.Effect) || !validMailActivationReceipt(response.Activation, response.Effect, now) {
			return ErrInvalidReceipt
		}
		if response.Effect.Outcome == EffectConfirmed && response.FailureCode != "" || response.Effect.Outcome != EffectConfirmed && response.FailureCode == "" {
			return ErrInvalidReceipt
		}
	case MailBrokerQueueList:
		if response.FailureCode != "" || uint32(len(response.Queue)) > request.QueueLimit || !validMailEvidenceDigest(response.EvidenceDigest) {
			return ErrInvalidReceipt
		}
		for _, record := range response.Queue {
			if !validMailQueueRecord(record, now) {
				return ErrInvalidReceipt
			}
		}
	case MailBrokerQueueAction:
		if response.FailureCode != "" || response.QueueReceipt.Action != request.QueueAction || response.QueueReceipt.QueueID != request.QueueID || !validMailEvidenceDigest(response.QueueReceipt.EvidenceDigest) || response.QueueReceipt.ObservedAt.IsZero() || response.QueueReceipt.ObservedAt.After(now.Add(time.Minute)) {
			return ErrInvalidReceipt
		}
	case MailBrokerService:
		if response.FailureCode != "" || response.ServiceReceipt.Service != request.Service || response.ServiceReceipt.Action != request.ServiceAction || !validMailEvidenceDigest(response.ServiceReceipt.EvidenceDigest) || response.ServiceReceipt.ObservedAt.IsZero() || response.ServiceReceipt.ObservedAt.After(now.Add(time.Minute)) {
			return ErrInvalidReceipt
		}
	case MailBrokerWebmailFolders:
		if len(response.Folders) > 10000 {
			return ErrInvalidReceipt
		}
	case MailBrokerWebmailSearch:
		if len(response.MessagePage.Items) > 200 {
			return ErrInvalidReceipt
		}
	case MailBrokerWebmailRead:
		if response.MessageView.Summary.ID != request.MessageID {
			return ErrInvalidReceipt
		}
	case MailBrokerWebmailAttachment:
		if response.AttachmentInfo.ID != request.AttachmentID || uint64(len(response.AttachmentContent)) != response.AttachmentInfo.Size {
			return ErrInvalidReceipt
		}
	case MailBrokerWebmailSubmit, MailBrokerCampaignSubmit:
		if !validPostfixQueueID(response.SubmittedQueueID) {
			return ErrInvalidReceipt
		}
	}
	return nil
}

type MailBrokerTransport interface {
	RoundTrip(context.Context, MailBrokerRequest) (MailBrokerResponse, error)
}
type MailDaemonClient struct {
	Transport MailBrokerTransport
	Now       func() time.Time
}

func NewLocalMailDaemonClient() *MailDaemonClient {
	return &MailDaemonClient{Transport: MailFramedTransport{Dialer: MailUnixDialer{}}}
}
func (client *MailDaemonClient) now() time.Time {
	if client.Now != nil {
		return client.Now().UTC()
	}
	return time.Now().UTC()
}
func (client *MailDaemonClient) request(ctx context.Context, request MailBrokerRequest) (MailBrokerResponse, error) {
	if client == nil || client.Transport == nil {
		return MailBrokerResponse{}, ErrInvalidCommand
	}
	id, err := newMailBrokerID()
	if err != nil {
		return MailBrokerResponse{}, err
	}
	request.Version = 1
	request.RequestID = id
	request.Deadline = client.now().Add(2 * time.Minute)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(request.Deadline) {
		request.Deadline = deadline
	}
	if err = request.Validate(client.now()); err != nil {
		return MailBrokerResponse{}, err
	}
	response, err := client.Transport.RoundTrip(ctx, request)
	if err != nil {
		return MailBrokerResponse{}, err
	}
	if err = response.Validate(request, client.now()); err != nil {
		return MailBrokerResponse{}, err
	}
	if response.FailureCode != "" {
		return response, mailBrokerError(response.FailureCode)
	}
	return response, nil
}
func (client *MailDaemonClient) ObserveOrApplyMail(ctx context.Context, effect EffectRequest, generation ConfigGeneration) (EffectReceipt, error) {
	response, err := client.request(ctx, MailBrokerRequest{Operation: MailBrokerApply, Effect: effect, Generation: generation})
	return response.Effect, err
}
func (client *MailDaemonClient) ApplyGeneration(ctx context.Context, effect EffectRequest, generation ConfigGeneration) (EffectReceipt, MailActivationReceipt, error) {
	response, err := client.request(ctx, MailBrokerRequest{Operation: MailBrokerApply, Effect: effect, Generation: generation})
	return response.Effect, response.Activation, err
}
func (client *MailDaemonClient) Queue(ctx context.Context, action MailQueueAction, id QueueID) (MailQueueReceipt, error) {
	response, err := client.request(ctx, MailBrokerRequest{Operation: MailBrokerQueueAction, QueueAction: action, QueueID: id})
	return response.QueueReceipt, err
}
func (client *MailDaemonClient) ListQueue(ctx context.Context, limit uint32) ([]MailQueueRecord, string, error) {
	response, err := client.request(ctx, MailBrokerRequest{Operation: MailBrokerQueueList, QueueLimit: limit})
	return response.Queue, response.EvidenceDigest, err
}
func (client *MailDaemonClient) ControlService(ctx context.Context, service MailService, action MailServiceAction) (MailServiceReceipt, error) {
	response, err := client.request(ctx, MailBrokerRequest{Operation: MailBrokerService, Service: service, ServiceAction: action})
	return response.ServiceReceipt, err
}
func (client *MailDaemonClient) SubmitCampaign(ctx context.Context, submission CampaignSubmission) (QueueID, error) {
	response, err := client.request(ctx, MailBrokerRequest{Operation: MailBrokerCampaignSubmit, Campaign: submission})
	return response.SubmittedQueueID, err
}

type MailUnixDialer struct{}

func (MailUnixDialer) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", MailDaemonSocketPath)
}

type MailConnectionDialer interface {
	DialContext(context.Context) (net.Conn, error)
}
type MailFramedTransport struct{ Dialer MailConnectionDialer }

func (transport MailFramedTransport) RoundTrip(ctx context.Context, request MailBrokerRequest) (MailBrokerResponse, error) {
	if transport.Dialer == nil {
		return MailBrokerResponse{}, ErrInvalidCommand
	}
	connection, err := transport.Dialer.DialContext(ctx)
	if err != nil {
		return MailBrokerResponse{}, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if err = connection.SetDeadline(request.Deadline); err != nil {
		return MailBrokerResponse{}, err
	}
	if err = writeMailFrame(connection, request); err != nil {
		return MailBrokerResponse{}, err
	}
	var reply mailWireReply
	if err = readMailFrame(connection, &reply); err != nil {
		return MailBrokerResponse{}, err
	}
	if reply.Error != "" {
		return MailBrokerResponse{}, mailBrokerError(reply.Error)
	}
	return reply.Response, nil
}

type mailWireReply struct {
	Response MailBrokerResponse `json:"response"`
	Error    string             `json:"error,omitempty"`
}
type MailDaemonPeerPolicy struct{ AllowedUIDs map[uint32]bool }

func NewMailDaemonPeerPolicy(controlUID uint32) (*MailDaemonPeerPolicy, error) {
	if controlUID == 0 {
		return nil, ErrInvalidCommand
	}
	return &MailDaemonPeerPolicy{AllowedUIDs: map[uint32]bool{0: true, controlUID: true}}, nil
}
func (policy *MailDaemonPeerPolicy) Authorize(connection net.Conn) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || policy == nil {
		return ErrUnauthorized
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return ErrUnauthorized
	}
	var credential *syscall.Ucred
	var controlErr error
	if err = raw.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || controlErr != nil || credential == nil || credential.Pid <= 1 || !policy.AllowedUIDs[credential.Uid] {
		return ErrUnauthorized
	}
	return nil
}

type MailUnixListener struct {
	*net.UnixListener
	lock *os.File
	once sync.Once
}

func ListenMailDaemon(controlGID uint32) (*MailUnixListener, error) {
	if controlGID == 0 {
		return nil, ErrInvalidCommand
	}
	directory := filepath.Dir(MailDaemonSocketPath)
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, ErrInvalidCommand
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		return nil, ErrInvalidCommand
	}
	lock, err := acquireMailDaemonLock()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*MailUnixListener, error) {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
		return nil, cause
	}
	if existing, statErr := os.Lstat(MailDaemonSocketPath); statErr == nil {
		socketMetadata, socketOK := existing.Sys().(*syscall.Stat_t)
		if existing.Mode()&os.ModeSocket == 0 || !socketOK || socketMetadata.Uid != 0 {
			return fail(ErrUnauthorized)
		}
		if err = os.Remove(MailDaemonSocketPath); err != nil {
			return fail(err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fail(statErr)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: MailDaemonSocketPath, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chown(MailDaemonSocketPath, 0, int(controlGID)); err == nil {
		err = os.Chmod(MailDaemonSocketPath, 0660)
	}
	if err != nil {
		listener.Close()
		_ = os.Remove(MailDaemonSocketPath)
		return fail(err)
	}
	return &MailUnixListener{UnixListener: listener, lock: lock}, nil
}
func acquireMailDaemonLock() (*os.File, error) {
	fd, err := syscall.Open(mailDaemonLockPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), mailDaemonLockPath)
	info, err := lock.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		lock.Close()
		return nil, ErrUnauthorized
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		lock.Close()
		return nil, ErrUnauthorized
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}
func (listener *MailUnixListener) Close() error {
	if listener == nil {
		return nil
	}
	var result error
	listener.once.Do(func() {
		if listener.UnixListener != nil {
			result = listener.UnixListener.Close()
		}
		if err := os.Remove(MailDaemonSocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
		if listener.lock != nil {
			result = errors.Join(result, syscall.Flock(int(listener.lock.Fd()), syscall.LOCK_UN), listener.lock.Close())
		}
	})
	return result
}

type MailDaemonServer struct {
	Host                      *LinuxMailHost
	Peer                      *MailDaemonPeerPolicy
	MaximumConcurrent         uint32
	MaximumCampaignConcurrent uint32
	Now                       func() time.Time
	once                      sync.Once
	semaphore                 chan struct{}
	campaignSemaphore         chan struct{}
}

func NewMailDaemonServer(host *LinuxMailHost, peer *MailDaemonPeerPolicy) (*MailDaemonServer, error) {
	if host == nil || host.Store == nil || host.Material == nil || peer == nil {
		return nil, ErrInvalidCommand
	}
	return &MailDaemonServer{Host: host, Peer: peer}, nil
}
func (server *MailDaemonServer) Serve(listener net.Listener) error {
	if server == nil || server.Host == nil || server.Peer == nil || listener == nil {
		return ErrInvalidCommand
	}
	server.once.Do(func() {
		maximum := server.MaximumConcurrent
		if maximum == 0 {
			maximum = 16
		}
		if maximum > 64 {
			maximum = 64
		}
		campaignMaximum := server.MaximumCampaignConcurrent
		if campaignMaximum == 0 {
			campaignMaximum = 4
		}
		if campaignMaximum > 8 {
			campaignMaximum = 8
		}
		if campaignMaximum > maximum {
			campaignMaximum = maximum
		}
		server.semaphore = make(chan struct{}, maximum)
		server.campaignSemaphore = make(chan struct{}, campaignMaximum)
	})
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case server.semaphore <- struct{}{}:
			go func(connection net.Conn) {
				defer func() { <-server.semaphore; connection.Close() }()
				server.serve(connection)
			}(connection)
		default:
			_ = connection.Close()
		}
	}
}
func (server *MailDaemonServer) serve(connection net.Conn) {
	if server.Peer.Authorize(connection) != nil {
		return
	}
	now := time.Now().UTC()
	if server.Now != nil {
		now = server.Now().UTC()
	}
	_ = connection.SetReadDeadline(now.Add(15 * time.Second))
	var request MailBrokerRequest
	defer func() {
		if request.Maildir != nil {
			wipeMailBytes(request.Maildir.Archive)
		}
	}()
	if readMailFrame(connection, &request) != nil || request.Validate(now) != nil {
		_ = writeMailFrame(connection, mailWireReply{Error: "invalid_request"})
		return
	}
	if request.Operation == MailBrokerCampaignSubmit {
		select {
		case server.campaignSemaphore <- struct{}{}:
			defer func() { <-server.campaignSemaphore }()
		default:
			_ = writeMailFrame(connection, mailWireReply{Error: "rate_limited"})
			return
		}
	}
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	response := MailBrokerResponse{Version: 1, RequestID: request.RequestID, Operation: request.Operation, ObservedAt: time.Now().UTC()}
	var err error
	switch request.Operation {
	case MailBrokerMaildirImport:
		var receipt MaildirImportReceipt
		receipt, err = server.Host.ImportMaildir(ctx, *request.Maildir)
		response.Maildir = &receipt
	case MailBrokerMigrationPublication:
		var receipt MailPublicationReceipt
		switch request.Publication.Operation {
		case "stage":
			receipt, err = server.Host.StageMigrationPublication(ctx, request.Publication.Bundle, request.Publication.Generation)
		case "activate":
			receipt, err = server.Host.ActivateMigrationPublication(ctx, request.Publication.Bundle, request.Publication.Generation, request.Publication.SourceFenceDigest)
		case "observe":
			receipt, err = server.Host.ObserveMigrationPublication(ctx, request.Publication.Bundle, request.Publication.Generation)
		case "cancel":
			receipt, err = server.Host.CancelMigrationPublication(ctx, request.Publication.Bundle, request.Publication.Generation)
		}
		response.Publication = &receipt
	case MailBrokerApply:
		response.Effect, response.Activation, err = server.Host.ObserveOrApplyMailWithActivation(ctx, request.Effect, request.Generation)
	case MailBrokerQueueList:
		response.Queue, response.EvidenceDigest, err = server.Host.ListQueue(ctx, request.QueueLimit)
	case MailBrokerQueueAction:
		response.QueueReceipt, err = server.Host.Queue(ctx, request.QueueAction, request.QueueID)
	case MailBrokerService:
		response.ServiceReceipt, err = server.Host.ControlService(ctx, request.Service, request.ServiceAction)
	case MailBrokerWebmailFolders:
		response.Folders, err = server.Host.WebmailFolders(ctx, request.Webmail)
	case MailBrokerWebmailSearch:
		response.MessagePage, err = server.Host.WebmailSearch(ctx, request.Webmail, request.MessageQuery)
	case MailBrokerWebmailRead:
		response.MessageView, err = server.Host.WebmailRead(ctx, request.Webmail, request.MessageID)
	case MailBrokerWebmailAttachment:
		response.AttachmentInfo, response.AttachmentContent, err = server.Host.WebmailAttachment(ctx, request.Webmail, request.MessageID, request.AttachmentID)
	case MailBrokerWebmailMove:
		err = server.Host.WebmailMove(ctx, request.Webmail, request.MessageID, request.FolderID)
	case MailBrokerWebmailDelete:
		err = server.Host.WebmailDelete(ctx, request.Webmail, request.MessageID)
	case MailBrokerWebmailFlags:
		err = server.Host.WebmailFlags(ctx, request.Webmail, request.MessageID, request.Flags)
	case MailBrokerWebmailSubmit:
		response.SubmittedQueueID, err = server.Host.WebmailSubmit(ctx, request.Webmail, request.Compose)
	case MailBrokerCampaignSubmit:
		response.SubmittedQueueID, err = server.Host.CampaignSubmit(ctx, request.Campaign)
	}
	if err != nil {
		if request.Operation == MailBrokerApply && validEffect(response.Effect, request.Effect) || request.Operation == MailBrokerMigrationPublication && response.Publication != nil && response.Publication.valid(*request.Publication) {
			response.FailureCode = mailBrokerErrorCode(err)
			if response.Validate(request, time.Now().UTC()) == nil {
				_ = writeMailFrame(connection, mailWireReply{Response: response})
				return
			}
		}
		_ = writeMailFrame(connection, mailWireReply{Error: mailBrokerErrorCode(err)})
		return
	}
	if response.Validate(request, time.Now().UTC()) != nil {
		_ = writeMailFrame(connection, mailWireReply{Error: "invalid_response"})
		return
	}
	_ = writeMailFrame(connection, mailWireReply{Response: response})
}
func writeMailFrame(writer io.Writer, value any) error {
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > mailBrokerFrameLimit {
		return ErrInvalidCommand
	}
	defer wipeMailBytes(content)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(content)))
	if _, err = writer.Write(header[:]); err != nil {
		return err
	}
	for len(content) > 0 {
		written, writeErr := writer.Write(content)
		if writeErr != nil {
			return writeErr
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}
func readMailFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > mailBrokerFrameLimit {
		return ErrInvalidCommand
	}
	content := make([]byte, size)
	defer wipeMailBytes(content)
	if _, err := io.ReadFull(reader, content); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidCommand
	}
	return nil
}
func newMailBrokerID() (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", err
	}
	return "mailreq_" + hex.EncodeToString(raw[:]), nil
}
func validBrokerID(value string) bool {
	if len(value) < 16 || len(value) > 80 {
		return false
	}
	for _, r := range value {
		if !(r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}
func validQueueAction(action MailQueueAction) bool {
	switch action {
	case QueueRetry, QueueDelete, QueueHold, QueueRelease, QueueFlush:
		return true
	}
	return false
}
func validMailService(service MailService) bool {
	switch service {
	case ServicePostfix, ServiceDovecot, ServiceRspamd, ServiceOpenDKIM, ServiceRedis, ServiceClamAV:
		return true
	}
	return false
}
func validServiceAction(action MailServiceAction) bool {
	switch action {
	case ServiceStart, ServiceStop, ServiceRestart, ServiceReload, ServiceProbe:
		return true
	}
	return false
}
func validMailEvidenceDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func validMailQueueRecord(record MailQueueRecord, now time.Time) bool {
	if !validPostfixQueueID(record.ID) || len(record.QueueName) < 1 || len(record.QueueName) > 32 || record.MessageSize > 2<<30 || record.ArrivalTime.IsZero() || record.ArrivalTime.After(now.Add(time.Minute)) || len(record.Recipients) > 10000 {
		return false
	}
	for _, r := range record.QueueName {
		if !(r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	if record.Sender != "<>" && ValidateAddress(record.Sender) != nil {
		return false
	}
	for _, recipient := range record.Recipients {
		if ValidateAddress(recipient.Address) != nil || len(recipient.DelayReason) > 4096 {
			return false
		}
	}
	return true
}
func validMailFailureCode(value string) bool {
	switch value {
	case "unauthorized", "conflict", "not_found", "ambiguous", "rate_limited", "operation_failed":
		return true
	}
	return false
}
func validMailActivationReceipt(receipt MailActivationReceipt, effect EffectReceipt, now time.Time) bool {
	if !validMailGenerationID(receipt.GenerationID) || !validMailEvidenceDigest(receipt.GenerationDigest) || receipt.ObservedAt.IsZero() || receipt.ObservedAt.After(now.Add(time.Minute)) {
		return false
	}
	if receipt.PreviousGeneration != "" && !validMailGenerationID(receipt.PreviousGeneration) {
		return false
	}
	for _, digest := range []string{receipt.ValidationDigest, receipt.ActivationDigest, receipt.ReloadDigest, receipt.ProbeDigest, receipt.RollbackDigest} {
		if digest != "" && !validMailEvidenceDigest(digest) {
			return false
		}
	}
	if effect.AppliedGeneration != receipt.GenerationDigest || effect.ProbeDigest != receipt.ProbeDigest {
		return false
	}
	if effect.Outcome == EffectConfirmed && receipt.ProbeDigest == "" {
		return false
	}
	if receipt.RolledBack && receipt.RollbackDigest == "" {
		return false
	}
	return true
}
func validMailGenerationID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}
func mailBrokerErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrAmbiguous):
		return "ambiguous"
	case errors.Is(err, ErrRateLimited):
		return "rate_limited"
	default:
		return "operation_failed"
	}
}
func mailBrokerError(code string) error {
	switch code {
	case "unauthorized":
		return ErrUnauthorized
	case "conflict":
		return ErrConflict
	case "not_found":
		return ErrNotFound
	case "ambiguous":
		return ErrAmbiguous
	case "rate_limited":
		return ErrRateLimited
	case "invalid_request", "invalid_response":
		return ErrInvalidCommand
	default:
		return errors.New("mail daemon operation failed")
	}
}
