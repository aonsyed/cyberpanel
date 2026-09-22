package webmail

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/mail"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRenderedAttachmentMetadata(t *testing.T) {
	raw := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/plain\r\n\r\nbody\r\n--inner--\r\n--outer\r\nContent-Type: application/octet-stream; name=proof.bin\r\nContent-Disposition: attachment; filename=proof.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAEC/w==\r\n--outer--\r\n"
	message, err := mail.ReadMessage(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	state := &renderedParts{}
	if err = walkMIME(textproto.MIMEHeader(message.Header), message.Body, 0, state); err != nil {
		t.Fatal(err)
	}
	if len(state.attachments) != 1 {
		t.Fatal("read projection discarded attachment metadata")
	}
	if state.attachments[0] != (AttachmentReference{PartID: "2", Filename: "proof.bin", ContentType: "application/octet-stream", Size: 4}) {
		t.Fatal("attachment metadata or decoded size mismatch")
	}
}

func TestAttachmentBlobBoundsAndOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewLocalBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	owner := BlobOwner{TenantID: "tenant_one", UserID: "user_one", MailboxID: "mailbox_one"}
	blob := BlobInfo{ID: "upload_one", Owner: owner, Filename: "proof.bin", ContentType: "application/octet-stream", ExpiresAt: time.Now().Add(time.Minute)}
	content := []byte{0, 1, 2, 13, 10, 127, 128, 254, 255}
	stored, err := store.Put(context.Background(), blob, bytes.NewReader(content), uint64(len(content)))
	if err != nil || stored.Size != uint64(len(content)) {
		t.Fatal("exact bounded upload", err)
	}
	reader, _, err := store.Open(context.Background(), owner, blob.ID)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("binary upload changed")
	}
	for _, wrong := range []BlobOwner{{"tenant_other", owner.UserID, owner.MailboxID}, {owner.TenantID, "user_other", owner.MailboxID}, {owner.TenantID, owner.UserID, "mailbox_other"}} {
		if _, _, err := store.Open(context.Background(), wrong, blob.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross-owner blob readable", err)
		}
	}
	blob.ID = "upload_large"
	if _, err := store.Put(context.Background(), blob, bytes.NewReader(content), uint64(len(content)-1)); !errors.Is(err, ErrLimit) {
		t.Fatal("oversized upload accepted", err)
	}
	if _, _, err := store.Open(context.Background(), owner, blob.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("partial oversized blob retained", err)
	}
}

func TestAttachmentMetadataRejectsMalformedEncoding(t *testing.T) {
	header := textproto.MIMEHeader{"Content-Type": {"application/octet-stream"}, "Content-Disposition": {"attachment; filename=proof.bin"}, "Content-Transfer-Encoding": {"base64"}}
	if err := walkMIME(header, strings.NewReader("invalid!"), 0, &renderedParts{}); err == nil {
		t.Fatal("malformed attachment encoding accepted")
	}
}
