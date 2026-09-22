package webmail

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIMAPNegotiatesAuthenticatedCapabilities(t *testing.T) {
	for _, authenticated := range []bool{true, false} {
		t.Run(fmt.Sprint(authenticated), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "imap.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			finished := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					finished <- err
					return
				}
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(3 * time.Second))
				fmt.Fprint(connection, "* OK native Dovecot greeting\r\n")
				reader := bufio.NewReader(connection)
				for step, expected := range []string{"CAPABILITY", "AUTHENTICATE OAUTHBEARER", "CAPABILITY"} {
					line, err := reader.ReadString('\n')
					if err != nil {
						finished <- err
						return
					}
					fields := strings.SplitN(strings.TrimSpace(line), " ", 2)
					if len(fields) != 2 || !strings.HasPrefix(fields[1], expected) {
						finished <- fmt.Errorf("unexpected negotiation step %d", step)
						return
					}
					if step == 0 {
						fmt.Fprint(connection, "* CAPABILITY IMAP4rev1 SASL-IR AUTH=OAUTHBEARER\r\n")
					}
					if step == 2 {
						capabilities := "IMAP4rev1 ESEARCH CONTEXT=SEARCH SORT CONDSTORE LIST-EXTENDED LIST-STATUS QUOTA BINARY MOVE UIDPLUS"
						if !authenticated {
							capabilities = "IMAP4rev1"
						}
						fmt.Fprint(connection, "* CAPABILITY "+capabilities+"\r\n")
					}
					fmt.Fprintf(connection, "%s OK complete\r\n", fields[0])
				}
				finished <- nil
			}()
			client, err := dialIMAP(context.Background(), Endpoint{UnixSocket: path, DialTimeout: time.Second, CommandTimeout: time.Second}, strings.Repeat("x", 32))
			if client != nil {
				client.stop()
				client.connection.Close()
			}
			if (err == nil) != authenticated {
				t.Errorf("authenticated features accepted=%v, want %v", err == nil, authenticated)
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeDovecotSearchAndFolderResponses(t *testing.T) {
	uids, err := parseESearch([]string{`* ESEARCH (TAG "c") UID PARTIAL (1:2 NIL)`}, 2)
	if err != nil || len(uids) != 0 {
		t.Fatal("native empty PARTIAL", err)
	}
	count, err := parseESearchCount([]string{`* ESEARCH (TAG "c") UID COUNT 13`})
	if err != nil || count != 13 {
		t.Fatal("native COUNT", err)
	}
	for _, line := range []string{`* ESEARCH UID COUNT -1`, `* ESEARCH UID COUNT 4294967296`, `* ESEARCH UID ALL 1:4`} {
		if _, err := parseESearchCount([]string{line}); err == nil {
			t.Fatal("invalid count accepted")
		}
	}
	folders, err := parseFolders([]string{`* LIST (\HasNoChildren) "." INBOX`, `* OK [HIGHESTMODSEQ 4] Highest`, `* STATUS INBOX (MESSAGES 0 UIDNEXT 2 UIDVALIDITY 1789948322 UNSEEN 0 HIGHESTMODSEQ 4)`}, Quota{})
	if err != nil || len(folders) != 1 || folders[0].Name != "INBOX" {
		t.Fatal("native informational folder response", err)
	}
	if _, err := parseFolders([]string{`* NO rejected`}, Quota{}); err == nil {
		t.Fatal("ignored noninformational error")
	}
}

func TestBoundedUIDSearchUsesPositiveTailRange(t *testing.T) {
	connection, server := net.Pipe()
	defer connection.Close()
	defer server.Close()
	finished := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(server)
		for _, step := range []struct{ command, response string }{
			{"UID SEARCH RETURN (COUNT) CHARSET UTF-8 UID 1:98 ALL", `* ESEARCH UID COUNT 13`},
			{"UID SEARCH RETURN (PARTIAL 11:13) CHARSET UTF-8 UID 1:98 ALL", `* ESEARCH UID PARTIAL (11:13 65,80,98)`},
		} {
			line, err := reader.ReadString('\n')
			if err != nil {
				finished <- err
				return
			}
			fields := strings.SplitN(strings.TrimSpace(line), " ", 2)
			if len(fields) != 2 || fields[1] != step.command {
				finished <- fmt.Errorf("unexpected bounded search command")
				return
			}
			fmt.Fprintf(server, "%s\r\n%s OK complete\r\n", step.response, fields[0])
		}
		finished <- nil
	}()
	client := &imapClient{connection: connection, reader: bufio.NewReader(connection), timeout: time.Second}
	uids, more, err := boundedUIDSearch(client, SortNewest, 99, 3, "ALL")
	if err != nil || !more || !reflect.DeepEqual(uids, []uint32{98, 80, 65}) {
		t.Fatalf("bounded newest page: %v %v %v", uids, more, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
