package webmail

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"
)

type attachmentZeroReader struct{}

func (attachmentZeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestRawAttachmentMessageStreamingBound(t *testing.T) {
	for _, size := range []int64{(8 << 20) + 1, 36 << 20, (36 << 20) + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			connection, server := net.Pipe()
			defer connection.Close()
			defer server.Close()
			go func() {
				line, err := bufio.NewReader(server).ReadString('\n')
				if err != nil {
					return
				}
				tag := strings.Fields(line)[0]
				fmt.Fprintf(server, "* 1 FETCH (UID 3 BODY[] {%d}\r\n", size)
				if size <= 36<<20 {
					io.CopyN(server, attachmentZeroReader{}, size)
					fmt.Fprintf(server, ")\r\n%s OK done\r\n", tag)
				}
			}()
			client := &imapClient{connection: connection, reader: bufio.NewReader(connection), timeout: 10 * time.Second}
			reader, _, err := client.literalCommand("UID FETCH 3 (UID BODY.PEEK[])", 3, 36<<20)
			if size > 36<<20 {
				if !errors.Is(err, ErrLimit) {
					t.Fatal("oversize raw literal not rejected", err)
				}
				return
			}
			if err != nil {
				t.Fatal("supported attachment raw envelope rejected", err)
			}
			n, err := io.Copy(io.Discard, reader)
			if err != nil || reader.Close() != nil || n != size {
				t.Fatal("bounded raw stream failed", err)
			}
		})
	}
}

func TestDecodedAttachmentMaximum(t *testing.T) {
	header := textproto.MIMEHeader{"Content-Type": {"application/octet-stream"}, "Content-Disposition": {"attachment; filename=maximum.bin"}}
	for _, size := range []int64{MaximumAttachmentBytes, MaximumAttachmentBytes + 1} {
		state := &renderedParts{}
		err := walkMIME(header, io.LimitReader(attachmentZeroReader{}, size), 0, state)
		if size > MaximumAttachmentBytes {
			if !errors.Is(err, ErrLimit) {
				t.Fatal("oversize decoded attachment accepted", err)
			}
			continue
		}
		if err != nil || len(state.attachments) != 1 || state.attachments[0].Size != uint64(size) {
			t.Fatal("maximum attachment metadata failed", err)
		}
	}
}

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
	for _, contentType := range []string{"multipart/mixed; boundary=outer", "message/rfc822"} {
		header.Set("Content-Type", contentType)
		if err := walkMIME(header, strings.NewReader(""), 0, &renderedParts{}); !errors.Is(err, ErrProtocol) {
			t.Fatal("unsupported attachment container advertised", err)
		}
	}
}
