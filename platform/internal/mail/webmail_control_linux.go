//go:build linux

package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"os"
	"strings"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const MailSessionCredentialPath = "/run/credentials/panel-core.service/webmail-session.key"

type SQLWebmailDirectory struct{ Store SQLControlRepository; ServerName string }

func (directory SQLWebmailDirectory) ResolveWebmailBinding(ctx context.Context, tenant string, mailboxID MailboxID) (WebmailBinding, error) {
	if ctx == nil || directory.Store.DB == nil || !validOpaque(tenant) || !validOpaque(string(mailboxID)) { return WebmailBinding{}, ErrInvalidCommand }
	resource, found, err := directory.Store.Load(ctx, tenant, ResourceMailbox, string(mailboxID)); if err != nil { return WebmailBinding{}, err }; if !found || resource.State != StateActive { return WebmailBinding{}, ErrNotFound }
	var mailbox Mailbox; if err = strictJSON(resource.Spec, &mailbox); err != nil || mailbox.ID != mailboxID || mailbox.Domain == "" || !mailbox.Enabled { return WebmailBinding{}, ErrNotFound }
	domainResource, found, err := directory.Store.Load(ctx, tenant, ResourceDomain, string(mailbox.Domain)); if err != nil { return WebmailBinding{}, err }; if !found || domainResource.State != StateActive { return WebmailBinding{}, ErrNotFound }
	var domain Domain; if err = strictJSON(domainResource.Spec, &domain); err != nil || domain.ID != mailbox.Domain || domain.Tenant != tenant { return WebmailBinding{}, ErrInvalidReceipt }
	address := Address(strings.ToLower(mailbox.Local + "@" + domain.Name)); binding := WebmailBinding{TenantID:tenant, MailboxID:mailboxID, Address:address, ServerName:directory.ServerName}; return binding, binding.Validate()
}

type LocalWebmailBackend struct{ Client *MailDaemonClient; Directory SQLWebmailDirectory }

func NewLocalWebmailService(key []byte, audience string, serverName string, store *WebmailStore, control SQLControlRepository) (*WebmailService, *MailSessionAuthority, error) {
	if store == nil || store.DB == nil || control.DB == nil || !validHostname(serverName) { return nil, nil, ErrInvalidCommand }
	authority, err := NewMailSessionAuthority(key, audience); if err != nil { return nil, nil, err }
	backend := &LocalWebmailBackend{Client:NewLocalMailDaemonClient(), Directory:SQLWebmailDirectory{Store:control,ServerName:serverName}}
	service := &WebmailService{Sessions:authority, IMAP:backend, Submission:backend, Sanitizer:EscapingHTMLSanitizer{}, Store:store, MaxAttachmentBytes:4<<20}
	return service, authority, nil
}

func LoadMailSessionCredential(path string) ([]byte,error) {
	if path != MailSessionCredentialPath { return nil, ErrInvalidCommand }
	return loadCoreMailCredential(path)
}

func loadCoreMailCredential(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != 32 { return nil, ErrUnauthorized }
	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) { return nil, ErrUnauthorized }
	if opened.Mode().Perm()&0077 != 0 && !secrets.PrivateSystemdCredential(file) { return nil, ErrUnauthorized }
	content, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(content) != 32 { wipeMailBytes(content); return nil, ErrUnauthorized }
	return content, nil
}

type EscapingHTMLSanitizer struct{}
func (EscapingHTMLSanitizer) SanitizeMailHTML(ctx context.Context, source string) (string,error) {
	if ctx==nil||len(source)>8<<20||strings.ContainsRune(source,'\x00'){return "",ErrInvalidCommand};if err:=ctx.Err();err!=nil{return "",err}
	return "<pre>"+html.EscapeString(source)+"</pre>",nil
}

func (backend *LocalWebmailBackend) binding(ctx context.Context, session MailSession) (WebmailBinding,error) { if backend==nil||backend.Client==nil{return WebmailBinding{},ErrInvalidCommand};return backend.Directory.ResolveWebmailBinding(ctx,session.TenantID,session.MailboxID) }
func (backend *LocalWebmailBackend) ListFolders(ctx context.Context,session MailSession)([]Folder,error){binding,err:=backend.binding(ctx,session);if err!=nil{return nil,err};response,err:=backend.Client.request(ctx,MailBrokerRequest{Operation:MailBrokerWebmailFolders,Webmail:binding});return response.Folders,err}
func (backend *LocalWebmailBackend) QueryMessages(ctx context.Context,session MailSession,query MessageQuery)(MessagePage,error){binding,err:=backend.binding(ctx,session);if err!=nil{return MessagePage{},err};response,err:=backend.Client.request(ctx,MailBrokerRequest{Operation:MailBrokerWebmailSearch,Webmail:binding,MessageQuery:query});return response.MessagePage,err}
func (backend *LocalWebmailBackend) ReadMessage(ctx context.Context,session MailSession,id MessageID)(MessageView,error){binding,err:=backend.binding(ctx,session);if err!=nil{return MessageView{},err};response,err:=backend.Client.request(ctx,MailBrokerRequest{Operation:MailBrokerWebmailRead,Webmail:binding,MessageID:id});return response.MessageView,err}
func (backend *LocalWebmailBackend) OpenAttachment(ctx context.Context,session MailSession,message MessageID,id AttachmentID)(AttachmentStream,error){binding,err:=backend.binding(ctx,session);if err!=nil{return AttachmentStream{},err};response,err:=backend.Client.request(ctx,MailBrokerRequest{Operation:MailBrokerWebmailAttachment,Webmail:binding,MessageID:message,AttachmentID:id});if err!=nil{return AttachmentStream{},err};return AttachmentStream{Info:response.AttachmentInfo,Reader:io.NopCloser(bytes.NewReader(response.AttachmentContent))},nil}
func (backend *LocalWebmailBackend) Move(ctx context.Context,session MailSession,message MessageID,folder FolderID)error{binding,err:=backend.binding(ctx,session);if err!=nil{return err};_,err=backend.Client.request(ctx,MailBrokerRequest{Operation:MailBrokerWebmailMove,Webmail:binding,MessageID:message,FolderID:folder});return err}
func (backend *LocalWebmailBackend) Delete(ctx context.Context,session MailSession,message MessageID)error{binding,err:=backend.binding(ctx,session);if err!=nil{return err};_,err=backend.Client.request(ctx,MailBrokerRequest{Operation:MailBrokerWebmailDelete,Webmail:binding,MessageID:message});return err}
func (backend *LocalWebmailBackend) SetFlags(ctx context.Context,session MailSession,message MessageID,flags []string)error{binding,err:=backend.binding(ctx,session);if err!=nil{return err};_,err=backend.Client.request(ctx,MailBrokerRequest{Operation:MailBrokerWebmailFlags,Webmail:binding,MessageID:message,Flags:flags});return err}
func (backend *LocalWebmailBackend) Submit(ctx context.Context,session MailSession,message ComposeMessage)(QueueID,error){binding,err:=backend.binding(ctx,session);if err!=nil{return "",err};response,err:=backend.Client.request(ctx,MailBrokerRequest{Operation:MailBrokerWebmailSubmit,Webmail:binding,Compose:message});return response.SubmittedQueueID,err}

func strictWebmailJSON(raw []byte,target any)error{decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{return err};if err:=decoder.Decode(&struct{}{});!errors.Is(err,io.EOF){return ErrInvalidReceipt};return nil}

var _ IMAPBackend = (*LocalWebmailBackend)(nil)
var _ SubmissionBackend = (*LocalWebmailBackend)(nil)
