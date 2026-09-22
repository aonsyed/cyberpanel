package webmail

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQEMUNativeContainerAttachments(t *testing.T) {
	root := os.Getenv("CYBERPANEL_QEMU_NESTED_ATTACHMENT")
	if root == "" {
		t.Skip("requires retained disposable nested fixture")
	}
	var account struct{ Address, Password string }
	accountBytes, err := os.ReadFile(os.Getenv("CYBERPANEL_QEMU_WEBMAIL_ACCOUNT"))
	if err != nil || json.Unmarshal(accountBytes, &account) != nil {
		t.Fatal("fixture unavailable")
	}
	defer clear(accountBytes)
	var evidence struct {
		UID         uint32
		UIDValidity uint64
	}
	evidenceBytes, err := os.ReadFile(filepath.Join(root, "evidence.json"))
	if err != nil || json.Unmarshal(evidenceBytes, &evidence) != nil {
		t.Fatal("evidence unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(root, "message.bin"))
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	state := &renderedParts{}
	if err := walkMIME(textproto.MIMEHeader(message.Header), message.Body, 0, state); err != nil {
		t.Fatal("container metadata", err)
	}
	if len(state.attachments) != 2 || state.plain != "Visible parent only" || state.html != "" {
		t.Fatal("embedded active content rendered or attachments lost")
	}
	pem, err := os.ReadFile("/var/lib/cyberpanel/certificates/public/mail-default.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("invalid trust")
	}
	for index, part := range state.attachments {
		expected, err := os.ReadFile(filepath.Join(root, "part"+part.PartID+".bin"))
		if err != nil {
			t.Fatal(err)
		}
		if index == 1 {
			expected = append(expected, '\r', '\n')
		}
		connection, err := tls.Dial("tcp", "127.0.0.1:993", &tls.Config{RootCAs: roots, ServerName: "cyberpanel.invalid", MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		client := &imapClient{connection: connection, reader: bufio.NewReader(connection), timeout: 10 * time.Second}
		if _, _, err := client.readResponseLine(); err != nil {
			t.Fatal(err)
		}
		username, _ := imapQuote(account.Address)
		password, _ := imapQuote(account.Password)
		if _, err := client.command("LOGIN " + username + " " + password); err != nil {
			t.Fatal("native login failed")
		}
		selected, err := selectMailbox(client, "INBOX")
		if err != nil || uint64(selected.UIDValidity) != evidence.UIDValidity {
			t.Fatal("fixture identity changed", err)
		}
		maximum := part.Size
		if part.SizeUnknown {
			maximum = MaximumAttachmentBytes
		}
		stream, size, err := openIMAPPart(client, evidence.UID, part.PartID, maximum)
		if err != nil {
			t.Fatal("native container section", err)
		}
		actual, err := io.ReadAll(stream)
		if index == 1 && err == nil {
			leaf, _, leafErr := openIMAPPart(client, evidence.UID, "3.1", 4)
			if leafErr != nil {
				t.Fatal("native leaf regression", leafErr)
			}
			decoded, leafErr := io.ReadAll(leaf)
			if leafErr != nil || leaf.Close() != nil || !bytes.Equal(decoded, []byte{0, 1, 2, 255}) {
				t.Fatal("native leaf was not transfer-decoded", leafErr)
			}
		}
		closeErr := stream.Close()
		if err != nil || closeErr != nil || !bytes.Equal(actual, expected) || !part.SizeUnknown && size != part.Size || size != uint64(len(expected)) {
			t.Fatal("container exact bytes/size mismatch", part.PartID, err, closeErr, size, part.Size, len(expected))
		}
		if index == 0 {
			if part.ContentType != "message/rfc822" || part.Filename != "forwarded.eml" {
				t.Fatal("message metadata lost")
			}
		} else {
			typ, params, err := mime.ParseMediaType(part.ContentType)
			if err != nil || typ != "multipart/mixed" || params["boundary"] != "nested" || part.Filename != "bundle.mime" {
				t.Fatal("multipart boundary metadata lost")
			}
			child, err := multipart.NewReader(bytes.NewReader(actual), params["boundary"]).NextPart()
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := io.ReadAll(child)
			if err != nil || string(encoded) != "AAEC/w==" {
				t.Fatal("native recursively transformed encoded child")
			}
		}
		t.Logf("native container part %s: exact %d bytes; safe metadata; embedded HTML not rendered", part.PartID, len(actual))
	}
}
