package webmail

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"
)

func TestQEMUDovecotNativeResponses(t *testing.T) {
	fixture := os.Getenv("CYBERPANEL_QEMU_WEBMAIL_ACCOUNT")
	if fixture == "" {
		t.Skip("requires guest-only QA mailbox and root access to installed certificate")
	}
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var account struct{ Address, Password string }
	if json.Unmarshal(raw, &account) != nil {
		t.Fatal("invalid fixture")
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	pem, err := os.ReadFile("/var/lib/cyberpanel/mail/tls/default/fullchain.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("invalid test trust anchor")
	}
	connection, err := tls.Dial("tcp", "127.0.0.1:993", &tls.Config{RootCAs: roots, ServerName: "cyberpanel.invalid", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := &imapClient{connection: connection, reader: bufio.NewReader(connection), timeout: 10 * time.Second}
	if _, _, err := client.readResponseLine(); err != nil {
		t.Fatal(err)
	}
	username, _ := imapQuote(account.Address)
	password, _ := imapQuote(account.Password)
	if _, err := client.command("LOGIN " + username + " " + password); err != nil {
		t.Fatal("native ordinary authentication failed")
	}
	lines, err := client.command(`LIST "" "*" RETURN (SUBSCRIBED CHILDREN SPECIAL-USE STATUS (MESSAGES UNSEEN UIDNEXT UIDVALIDITY HIGHESTMODSEQ))`)
	if err != nil {
		t.Fatal(err)
	}
	quota, err := readQuota(client)
	if err != nil {
		t.Fatal(err)
	}
	folders, err := parseFolders(lines, quota)
	if err != nil || len(folders) == 0 {
		t.Fatal("native folder parsing", err)
	}
	if _, err := selectMailbox(client, "INBOX"); err != nil {
		t.Fatal(err)
	}
	for _, order := range []MessageSort{SortNewest, SortOldest} {
		if _, _, err := boundedUIDSearch(client, order, 0, 2, "ALL"); err != nil {
			t.Fatal("native bounded search", order, err)
		}
	}
	if evidence := os.Getenv("CYBERPANEL_QEMU_WEBMAIL_READ_EVIDENCE"); evidence != "" {
		data, err := os.ReadFile(evidence)
		var probe struct{ Subject string }
		if err != nil || json.Unmarshal(data, &probe) != nil || probe.Subject == "" {
			t.Fatal("invalid read probe evidence")
		}
		subject, _ := imapQuote(probe.Subject)
		uids, _, err := boundedUIDSearch(client, SortNewest, 0, 2, "HEADER Subject "+subject)
		if err != nil || len(uids) != 1 {
			t.Fatal("unique delivered probe not found", err)
		}
		stream, _, err := client.literalCommand(fmt.Sprintf("UID FETCH %d (UID BODY.PEEK[])", uids[0]), uids[0], MaximumRawMessageBytes)
		if err != nil {
			t.Fatal("native delivered probe literal", err)
		}
		body, err := io.ReadAll(stream)
		closeErr := error(nil)
		if os.Getenv("CYBERPANEL_QEMU_WEBMAIL_ATTACHMENT") == "" {
			closeErr = stream.Close()
		}
		if err != nil || closeErr != nil || !strings.Contains(string(body), "Local-only installed panel webmail proof.") {
			t.Fatal("native delivered probe body mismatch", err, closeErr)
		}
		t.Log("native delivered probe exact body read without mutation")
		if os.Getenv("CYBERPANEL_QEMU_WEBMAIL_ATTACHMENT") != "" {
			message, err := mail.ReadMessage(bufio.NewReader(strings.NewReader(string(body))))
			if err != nil {
				t.Fatal(err)
			}
			state := &renderedParts{}
			if err := walkMIME(textproto.MIMEHeader(message.Header), message.Body, 0, state); err != nil || len(state.attachments) != 1 || state.attachments[0].PartID != "2" || state.attachments[0].Filename != "proof-bytes.bin" || state.attachments[0].ContentType != "application/octet-stream" {
				t.Fatal("native attachment metadata mismatch", err)
			}
			part, _, err := client.literalCommand(fmt.Sprintf("UID FETCH %d (UID BINARY.PEEK[2])", uids[0]), uids[0], MaximumAttachmentBytes)
			if err != nil {
				t.Fatal("native attachment literal", err)
			}
			content, err := io.ReadAll(part)
			if err != nil || part.Close() != nil || string(content) != string(append([]byte{0, 1, 2, 13, 10, 127, 128, 254, 255}, []byte("Attachment exact bytes")...)) {
				t.Fatal("native attachment bytes mismatch", err)
			}
			if state.attachments[0].Size != uint64(len(content)) {
				t.Fatal("decoded attachment size mismatch")
			}
			t.Log("native uploaded/sent attachment metadata and exact binary bytes verified")
		}
	}
}
