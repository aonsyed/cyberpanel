package mail

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

type MailSession struct { ID string `json:"id"`; Token string `json:"token"`; TenantID string `json:"-"`; MailboxID MailboxID `json:"-"`; PrincipalID string `json:"-"`; AuthzEpoch uint64 `json:"-"`; ExpiresAt time.Time `json:"expires_at"` }
type MessageQuery struct { FolderID FolderID `json:"folder_id"`; Terms string `json:"terms,omitempty"`; Cursor string `json:"cursor,omitempty"`; Limit uint16 `json:"limit"`; Sort string `json:"sort"` }
type MessagePage struct { Items []MessageSummary `json:"items"`; NextCursor string `json:"next_cursor,omitempty"`; TotalEstimate uint64 `json:"total_estimate,omitempty"` }
type MessageSummary struct { ID MessageID `json:"id"`; FolderID FolderID `json:"folder_id"`; Subject string `json:"subject"`; From Address `json:"from"`; To []Address `json:"to"`; Flags []string `json:"flags"`; ReceivedAt time.Time `json:"received_at"`; Size uint64 `json:"size"`; HasAttachments bool `json:"has_attachments"` }
type MessageView struct { Summary MessageSummary `json:"summary"`; Text string `json:"text,omitempty"`; SanitizedHTML string `json:"sanitized_html,omitempty"`; Attachments []AttachmentInfo `json:"attachments"`; RemoteImagesBlocked bool `json:"remote_images_blocked"` }
type AttachmentInfo struct { ID AttachmentID `json:"id"`; Name string `json:"name"`; ContentType string `json:"content_type"`; Size uint64 `json:"size"`; SHA256 string `json:"sha256,omitempty"` }
type AttachmentStream struct { Info AttachmentInfo; Reader io.ReadCloser }
type ComposeMessage struct { From MailboxID `json:"from"`; To []Address `json:"to"`; CC []Address `json:"cc,omitempty"`; BCC []Address `json:"bcc,omitempty"`; Subject string `json:"subject"`; Text string `json:"text,omitempty"`; SanitizedHTML string `json:"sanitized_html,omitempty"`; AttachmentBlobRefs []string `json:"attachment_blob_refs,omitempty"`; InReplyTo MessageID `json:"in_reply_to,omitempty"` }
type DraftRecord struct { ID DraftID `json:"id"`; TenantID string `json:"tenant_id"`; MailboxID MailboxID `json:"mailbox_id"`; Generation uint64 `json:"generation"`; Message ComposeMessage `json:"message"`; UpdatedAt time.Time `json:"updated_at"` }

type SessionAuthority interface { ValidateMailSession(context.Context,MailSession)(MailSession,error) }
type IMAPBackend interface {
	ListFolders(context.Context,MailSession)([]Folder,error)
	QueryMessages(context.Context,MailSession,MessageQuery)(MessagePage,error)
	ReadMessage(context.Context,MailSession,MessageID)(MessageView,error)
	OpenAttachment(context.Context,MailSession,MessageID,AttachmentID)(AttachmentStream,error)
	Move(context.Context,MailSession,MessageID,FolderID)error
	Delete(context.Context,MailSession,MessageID)error
	SetFlags(context.Context,MailSession,MessageID,[]string)error
}
type SubmissionBackend interface { Submit(context.Context,MailSession,ComposeMessage)(QueueID,error) }
type HTMLSanitizer interface { SanitizeMailHTML(context.Context,string)(string,error) }
type ImageProxy interface { Fetch(context.Context,MailSession,string,uint64)(AttachmentStream,error) }

type WebmailService struct { Sessions SessionAuthority; IMAP IMAPBackend; Submission SubmissionBackend; Sanitizer HTMLSanitizer; Store *WebmailStore; Images ImageProxy; MaxAttachmentBytes uint64 }
func (s WebmailService) Folders(ctx context.Context,session MailSession)([]Folder,error){verified,err:=s.session(ctx,session);if err!=nil{return nil,err};folders,err:=s.IMAP.ListFolders(ctx,verified);if err!=nil{return nil,err};if len(folders)>10000{return nil,fmt.Errorf("too many folders")};return folders,nil}
func (s WebmailService) Search(ctx context.Context,session MailSession,query MessageQuery)(MessagePage,error){verified,err:=s.session(ctx,session);if err!=nil{return MessagePage{},err};if query.Limit==0{query.Limit=50};if query.Limit>200||len(query.Terms)>512||len(query.Cursor)>1024||(query.Sort!=""&&query.Sort!="newest"&&query.Sort!="oldest"){return MessagePage{},ErrInvalidCommand};page,err:=s.IMAP.QueryMessages(ctx,verified,query);if err!=nil{return MessagePage{},err};if len(page.Items)>int(query.Limit)||len(page.NextCursor)>1024{return MessagePage{},ErrInvalidReceipt};for _,item:=range page.Items{if item.ID==""||item.FolderID==""||item.Size>1<<40{return MessagePage{},ErrInvalidReceipt}};return page,nil}
func (s WebmailService) Read(ctx context.Context,session MailSession,id MessageID)(MessageView,error){verified,err:=s.session(ctx,session);if err!=nil{return MessageView{},err};if id==""{return MessageView{},ErrInvalidCommand};view,err:=s.IMAP.ReadMessage(ctx,verified,id);if err!=nil{return MessageView{},err};if view.Summary.ID!=id||len(view.Text)>8<<20||len(view.SanitizedHTML)>8<<20||len(view.Attachments)>1000{return MessageView{},ErrInvalidReceipt};if view.SanitizedHTML!=""{if s.Sanitizer==nil{return MessageView{},errors.New("mail HTML sanitizer required")};view.SanitizedHTML,err=s.Sanitizer.SanitizeMailHTML(ctx,view.SanitizedHTML);if err!=nil{return MessageView{},err}};view.RemoteImagesBlocked=true;return view,nil}
func (s WebmailService) Attachment(ctx context.Context,session MailSession,message MessageID,id AttachmentID)(AttachmentStream,error){verified,err:=s.session(ctx,session);if err!=nil{return AttachmentStream{},err};if message==""||id==""{return AttachmentStream{},ErrInvalidCommand};stream,err:=s.IMAP.OpenAttachment(ctx,verified,message,id);if err!=nil{return AttachmentStream{},err};if stream.Reader==nil||stream.Info.ID!=id||stream.Info.Size>s.attachmentLimit(){if stream.Reader!=nil{stream.Reader.Close()};return AttachmentStream{},ErrInvalidReceipt};stream.Info.Name=safeFilename(stream.Info.Name);stream.Info.ContentType=safeMIME(stream.Info.ContentType);stream.Reader=&boundedReadCloser{Reader:io.LimitReader(stream.Reader,int64(stream.Info.Size)+1),closer:stream.Reader,remaining:stream.Info.Size};return stream,nil}
func (s WebmailService) SaveDraft(ctx context.Context,session MailSession,draft DraftRecord,expected uint64)(DraftRecord,error){verified,err:=s.session(ctx,session);if err!=nil{return DraftRecord{},err};if s.Store==nil||draft.ID==""{return DraftRecord{},ErrInvalidCommand};draft.MailboxID=verified.MailboxID;draft.TenantID=verified.TenantID;draft.Message.From=verified.MailboxID;normalized,err:=s.normalizeCompose(ctx,draft.Message,verified.MailboxID);if err!=nil{return DraftRecord{},err};draft.Message=normalized;return s.Store.SaveDraft(ctx,draft,expected)}
func (s WebmailService) Send(ctx context.Context,session MailSession,message ComposeMessage)(QueueID,error){verified,err:=s.session(ctx,session);if err!=nil{return "",err};if s.Submission==nil{return "",errors.New("mail submission backend required")};message.From=verified.MailboxID;normalized,err:=s.normalizeCompose(ctx,message,verified.MailboxID);if err!=nil{return "",err};return s.Submission.Submit(ctx,verified,normalized)}
func (s WebmailService) Move(ctx context.Context,session MailSession,message MessageID,folder FolderID)error{verified,err:=s.session(ctx,session);if err!=nil{return err};if message==""||folder==""{return ErrInvalidCommand};return s.IMAP.Move(ctx,verified,message,folder)}
func (s WebmailService) Delete(ctx context.Context,session MailSession,message MessageID)error{verified,err:=s.session(ctx,session);if err!=nil{return err};if message==""{return ErrInvalidCommand};return s.IMAP.Delete(ctx,verified,message)}
func (s WebmailService) Flags(ctx context.Context,session MailSession,message MessageID,flags []string)error{verified,err:=s.session(ctx,session);if err!=nil{return err};if message==""||len(flags)>32{return ErrInvalidCommand};allowed:=map[string]bool{"seen":true,"answered":true,"flagged":true,"deleted":true,"draft":true};seen:=map[string]bool{};for index,value:=range flags{value=strings.ToLower(strings.TrimPrefix(value,"\\"));if !allowed[value]||seen[value]{return ErrInvalidCommand};seen[value]=true;flags[index]=value};return s.IMAP.SetFlags(ctx,verified,message,flags)}
func (s WebmailService) ProxyImage(ctx context.Context,session MailSession,rawURL string)(AttachmentStream,error){verified,err:=s.session(ctx,session);if err!=nil{return AttachmentStream{},err};if s.Images==nil{return AttachmentStream{},errors.New("remote images are disabled")};parsed,err:=url.Parse(rawURL);if err!=nil||parsed.Scheme!="https"||parsed.User!=nil||parsed.Hostname()==""||parsed.Fragment!=""||isForbiddenHost(parsed.Hostname()){return AttachmentStream{},ErrInvalidCommand};return s.Images.Fetch(ctx,verified,parsed.String(),8<<20)}
func (s WebmailService) ResolveSession(ctx context.Context,session MailSession)(MailSession,error){return s.session(ctx,session)}
func (s WebmailService) session(ctx context.Context,session MailSession)(MailSession,error){if ctx==nil||s.Sessions==nil||s.IMAP==nil{return MailSession{},ErrInvalidCommand};verified,err:=s.Sessions.ValidateMailSession(ctx,session);if err!=nil{return MailSession{},err};if verified.ID!=session.ID||verified.TenantID!=session.TenantID||verified.PrincipalID!=session.PrincipalID||verified.AuthzEpoch!=session.AuthzEpoch||verified.MailboxID==""||time.Now().After(verified.ExpiresAt){return MailSession{},ErrUnauthorized};return verified,nil}
func (s WebmailService) normalizeCompose(ctx context.Context,message ComposeMessage,mailbox MailboxID)(ComposeMessage,error){if message.From!=mailbox||len(message.Subject)>998||len(message.Text)>8<<20||len(message.SanitizedHTML)>8<<20||len(message.AttachmentBlobRefs)>100{return ComposeMessage{},ErrInvalidCommand};var err error;if message.To,err=NormalizeAddresses(message.To);err!=nil{return ComposeMessage{},err};if message.CC,err=NormalizeAddresses(message.CC);err!=nil&&len(message.CC)>0{return ComposeMessage{},err};if message.BCC,err=NormalizeAddresses(message.BCC);err!=nil&&len(message.BCC)>0{return ComposeMessage{},err};if len(message.To)+len(message.CC)+len(message.BCC)==0||len(message.To)+len(message.CC)+len(message.BCC)>500{return ComposeMessage{},ErrInvalidCommand};if message.SanitizedHTML!=""{if s.Sanitizer==nil{return ComposeMessage{},errors.New("mail HTML sanitizer required")};message.SanitizedHTML,err=s.Sanitizer.SanitizeMailHTML(ctx,message.SanitizedHTML);if err!=nil{return ComposeMessage{},err}};for _,ref:=range message.AttachmentBlobRefs{if !validOpaque(ref){return ComposeMessage{},ErrInvalidCommand}};return message,nil}
func (s WebmailService) attachmentLimit()uint64{if s.MaxAttachmentBytes==0{return 256<<20};return s.MaxAttachmentBytes}

type boundedReadCloser struct{io.Reader;closer io.Closer;remaining uint64}
func (r *boundedReadCloser)Close()error{return r.closer.Close()}
type WebmailStore struct{DB *sql.DB}
const webmailSchema=`CREATE TABLE IF NOT EXISTS mail_drafts_v2(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,generation INTEGER NOT NULL,draft_json BLOB NOT NULL,updated_at TIMESTAMP NOT NULL);CREATE INDEX IF NOT EXISTS mail_drafts_v2_mailbox ON mail_drafts_v2(tenant_id,mailbox_id,updated_at);CREATE TABLE IF NOT EXISTS mail_contacts_v2(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,contact_json BLOB NOT NULL);CREATE TABLE IF NOT EXISTS mail_groups_v2(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,group_json BLOB NOT NULL);CREATE TABLE IF NOT EXISTS mail_sieve_v2(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,generation INTEGER NOT NULL,rule_json BLOB NOT NULL);`
func (s *WebmailStore)Bootstrap(ctx context.Context)error{if s==nil||s.DB==nil{return errors.New("webmail database required")};_,err:=s.DB.ExecContext(ctx,webmailSchema);return err}
func (s *WebmailStore)SaveDraft(ctx context.Context,draft DraftRecord,expected uint64)(DraftRecord,error){if s==nil||s.DB==nil{return DraftRecord{},errors.New("webmail database required")};tx,err:=s.DB.BeginTx(ctx,nil);if err!=nil{return DraftRecord{},err};defer tx.Rollback();var current uint64;err=tx.QueryRowContext(ctx,`SELECT generation FROM mail_drafts_v2 WHERE id=? AND tenant_id=? AND mailbox_id=?`,draft.ID,draft.TenantID,draft.MailboxID).Scan(&current);if errors.Is(err,sql.ErrNoRows){if expected!=0{return DraftRecord{},ErrConflict};draft.Generation=1}else if err!=nil{return DraftRecord{},err}else{if current!=expected{return DraftRecord{},ErrConflict};draft.Generation=current+1};draft.UpdatedAt=time.Now().UTC();raw,err:=json.Marshal(draft);if err!=nil{return DraftRecord{},err};if _,err=tx.ExecContext(ctx,`INSERT INTO mail_drafts_v2(id,tenant_id,mailbox_id,generation,draft_json,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,draft_json=excluded.draft_json,updated_at=excluded.updated_at`,draft.ID,draft.TenantID,draft.MailboxID,draft.Generation,raw,draft.UpdatedAt);err!=nil{return DraftRecord{},err};if err=tx.Commit();err!=nil{return DraftRecord{},err};return draft,nil}
func (s *WebmailStore)ListDrafts(ctx context.Context,tenant string,mailbox MailboxID,limit int,cursor string)([]DraftRecord,string,error){if s==nil||s.DB==nil{return nil,"",errors.New("webmail database required")};if limit<1||limit>200{limit=50};before:=time.Now().UTC();if cursor!=""{raw,err:=base64.RawURLEncoding.DecodeString(cursor);if err!=nil{return nil,"",ErrInvalidCommand};if before,err=time.Parse(time.RFC3339Nano,string(raw));err!=nil{return nil,"",ErrInvalidCommand}};rows,err:=s.DB.QueryContext(ctx,`SELECT draft_json,updated_at FROM mail_drafts_v2 WHERE tenant_id=? AND mailbox_id=? AND updated_at<? ORDER BY updated_at DESC LIMIT ?`,tenant,mailbox,before,limit+1);if err!=nil{return nil,"",err};defer rows.Close();items:=make([]DraftRecord,0,limit+1);for rows.Next(){var raw []byte;var at time.Time;if err=rows.Scan(&raw,&at);err!=nil{return nil,"",err};var item DraftRecord;if err=strictJSON(raw,&item);err!=nil{return nil,"",err};items=append(items,item)};if err=rows.Err();err!=nil{return nil,"",err};next:="";if len(items)>limit{next=base64.RawURLEncoding.EncodeToString([]byte(items[limit-1].UpdatedAt.Format(time.RFC3339Nano)));items=items[:limit]};return items,next,nil}

// ListContacts and ListSieveRules expose only records owned by the verified
// mailbox session. Their cursors are opaque record identifiers and the fixed
// SQL statements never accept a caller-provided predicate or ordering clause.
func (s *WebmailStore) ListContacts(ctx context.Context, tenant string, mailbox MailboxID, limit int, cursor string) ([]Contact, string, error) {
	if s == nil || s.DB == nil || ctx == nil || tenant == "" || mailbox == "" || len(cursor) > 256 {
		return nil, "", ErrInvalidCommand
	}
	if limit < 1 || limit > 200 { limit = 50 }
	rows, err := s.DB.QueryContext(ctx, `SELECT id,contact_json FROM mail_contacts_v2 WHERE tenant_id=? AND mailbox_id=? AND id>? ORDER BY id LIMIT ?`, tenant, mailbox, cursor, limit+1)
	if err != nil { return nil, "", err }
	defer rows.Close()
	items := make([]Contact, 0, limit+1)
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil { return nil, "", err }
		var item Contact
		if err = strictJSON(raw, &item); err != nil || string(item.ID) != id || item.Mailbox != mailbox {
			return nil, "", ErrInvalidReceipt
		}
		items = append(items, item)
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil { return nil, "", err }
	next := ""
	if len(items) > limit {
		next = ids[limit-1]
		items = items[:limit]
	}
	return items, next, nil
}

func (s *WebmailStore) ListSieveRules(ctx context.Context, tenant string, mailbox MailboxID, limit int, cursor string) ([]SieveRule, string, error) {
	if s == nil || s.DB == nil || ctx == nil || tenant == "" || mailbox == "" || len(cursor) > 256 {
		return nil, "", ErrInvalidCommand
	}
	if limit < 1 || limit > 200 { limit = 50 }
	rows, err := s.DB.QueryContext(ctx, `SELECT id,rule_json FROM mail_sieve_v2 WHERE tenant_id=? AND mailbox_id=? AND id>? ORDER BY id LIMIT ?`, tenant, mailbox, cursor, limit+1)
	if err != nil { return nil, "", err }
	defer rows.Close()
	items := make([]SieveRule, 0, limit+1)
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil { return nil, "", err }
		var item SieveRule
		if err = strictJSON(raw, &item); err != nil || string(item.ID) != id || item.Mailbox != mailbox || len(item.Script) > 1<<20 {
			return nil, "", ErrInvalidReceipt
		}
		items = append(items, item)
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil { return nil, "", err }
	next := ""
	if len(items) > limit {
		next = ids[limit-1]
		items = items[:limit]
	}
	return items, next, nil
}
func safeFilename(value string)string{value=strings.TrimSpace(strings.Map(func(r rune)rune{if r<' '||r=='/'||r=='\\'||r==':'{return -1};return r},value));if value==""{return"attachment.bin"};runes:=[]rune(value);if len(runes)>180{runes=runes[:180]};return string(runes)}
func safeMIME(value string)string{value=strings.ToLower(strings.TrimSpace(strings.Split(value,";")[0]));allowed:=map[string]bool{"text/plain":true,"image/png":true,"image/jpeg":true,"image/gif":true,"application/pdf":true,"application/zip":true,"application/octet-stream":true};if !allowed[value]{return"application/octet-stream"};return value}
func isForbiddenHost(host string)bool{host=strings.ToLower(strings.TrimSuffix(host,"."));return host=="localhost"||host=="metadata.google.internal"||strings.HasSuffix(host,".local")||strings.HasSuffix(host,".internal")||strings.HasPrefix(host,"127.")||strings.HasPrefix(host,"10.")||strings.HasPrefix(host,"192.168.")||strings.HasPrefix(host,"169.254.")||host=="::1"}
