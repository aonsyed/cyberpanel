package apiserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	securewebmail "github.com/aonsyed/cyberpanel/platform/internal/webmail"
	"io"
	"strings"
	"testing"
)

func TestWebmailAttachmentProjectionAndLeaseOwner(t *testing.T) {
	unknown := apiWebmailRenderedMessage(securewebmail.RenderedMessage{Attachments: []securewebmail.AttachmentReference{{PartID: "3", Filename: "bundle.mime", ContentType: "multipart/mixed; boundary=nested", SizeUnknown: true}}})
	if len(unknown.Attachments) != 1 || !unknown.Attachments[0].SizeUnknown || unknown.Attachments[0].Size != 0 {
		t.Fatal("multipart unknown size lost at API boundary")
	}
	projected := apiWebmailRenderedMessage(securewebmail.RenderedMessage{Attachments: []securewebmail.AttachmentReference{{PartID: "2", Filename: "proof.bin", ContentType: "application/octet-stream", Size: 4}}})
	if len(projected.Attachments) != 1 || projected.Attachments[0].PartID != "2" || projected.Attachments[0].Filename != "proof.bin" || projected.Attachments[0].ContentType != "application/octet-stream" || projected.Attachments[0].Size != 4 {
		t.Fatal("attachment metadata lost at API boundary")
	}
	principal, _ := identity.NewID("user_one")
	session, _ := identity.NewID("session_one")
	inv := Invocation{Actor: Actor{PrincipalID: principal, SessionID: session}, Request: RequestEnvelope{TenantID: "tenant_one", ResourceID: "mailbox_one", RequestID: "request_one"}, IdempotencyKey: "attachment_one"}
	content := []byte{0, 1, 128, 255}
	store := &webmailDownloadStore{items: map[string]*webmailDownloadLease{}}
	lease, err := store.issue(inv, securewebmail.AttachmentDownload{Filename: "proof.bin", ContentType: "application/octet-stream", Size: 4, Digest: strings.Repeat("a", 64), MalwareState: "clean", Body: io.NopCloser(bytes.NewReader(content))})
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []struct{ tenant, mailbox string }{{"tenant_other", "mailbox_one"}, {"tenant_one", "mailbox_other"}} {
		other := inv
		other.Request.TenantID = wrong.tenant
		other.Request.ResourceID = wrong.mailbox
		if _, err := store.get(other, lease.ID); err == nil {
			t.Fatal("foreign lease metadata exposed")
		}
		if _, err := store.read(context.Background(), other, WebmailAttachmentReadPayload{DownloadID: lease.ID, Length: 4}); err == nil {
			t.Fatal("foreign attachment bytes exposed")
		}
	}
	result, err := store.read(context.Background(), inv, WebmailAttachmentReadPayload{DownloadID: lease.ID, Length: 4})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := base64.RawStdEncoding.DecodeString(result.ContentBase64)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("attachment bytes changed")
	}
	if err = store.close(inv, lease.ID); err != nil {
		t.Fatal(err)
	}
}
