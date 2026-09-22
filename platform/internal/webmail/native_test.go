package webmail

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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
		closeErr := stream.Close()
		if err != nil || closeErr != nil || !strings.Contains(string(body), "Local-only installed panel webmail proof.") {
			t.Fatal("native delivered probe body mismatch", err, closeErr)
		}
		t.Log("native delivered probe exact body read without mutation")
	}
}
