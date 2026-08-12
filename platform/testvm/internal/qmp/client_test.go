package qmp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

const validGreeting = `{"QMP":{"version":{"qemu":{"major":11,"minor":0,"micro":3},"package":""},"capabilities":[]}}` + "\r\n"

func TestDialNegotiatesCapabilitiesAndHandlesFragmentedFrames(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	done := runScript(serverConn, func(conn net.Conn) error {
		if err := writeFragments(conn, validGreeting, 1, 2, 5, 3, 8); err != nil {
			return err
		}
		request, err := readRequest(conn)
		if err != nil {
			return err
		}
		if err := requireRequest(request, "qmp_capabilities", "cyberpanel-qmp-1", map[string]any{"enable": []any{}}); err != nil {
			return err
		}
		return writeFragments(conn, `{"return":{},"id":"cyberpanel-qmp-1"}`+"\r\n", 2, 1, 7)
	})

	called := false
	client, err := Dial(context.Background(), func(context.Context) (net.Conn, error) {
		called = true
		return clientConn, nil
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	if !called {
		t.Fatal("Dial() did not call the supplied dial function")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	awaitScript(t, done)
}

func TestNewRejectsUnexpectedGreetingContracts(t *testing.T) {
	tests := []struct {
		name     string
		greeting string
		wantErr  string
	}{
		{
			name:     "version",
			greeting: `{"QMP":{"version":{"qemu":{"major":11,"minor":0,"micro":2},"package":""},"capabilities":[]}}` + "\r\n",
			wantErr:  "version",
		},
		{
			name:     "package",
			greeting: `{"QMP":{"version":{"qemu":{"major":11,"minor":0,"micro":3},"package":"vendor-build"},"capabilities":[]}}` + "\r\n",
			wantErr:  "package",
		},
		{
			name:     "capability",
			greeting: `{"QMP":{"version":{"qemu":{"major":11,"minor":0,"micro":3},"package":""},"capabilities":["unknown-wire-mode"]}}` + "\r\n",
			wantErr:  "capability",
		},
		{
			name:     "unknown top-level member",
			greeting: `{"QMP":{"version":{"qemu":{"major":11,"minor":0,"micro":3},"package":""},"capabilities":[]},"return":{}}` + "\r\n",
			wantErr:  "top-level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			done := runScript(serverConn, func(conn net.Conn) error {
				_, err := conn.Write([]byte(tt.greeting))
				return err
			})

			_, err := New(context.Background(), clientConn)
			if err == nil {
				t.Fatal("New() error = nil, want greeting rejection")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Fatalf("New() error = %q, want it to contain %q", err, tt.wantErr)
			}
			awaitScript(t, done)
		})
	}
}

func TestQueryNameSkipsBoundedInterleavedEventsAndMatchesID(t *testing.T) {
	client, done := connectedClient(t, func(conn net.Conn) error {
		request, err := readRequest(conn)
		if err != nil {
			return err
		}
		if err := requireRequest(request, "query-name", "cyberpanel-qmp-2", nil); err != nil {
			return err
		}
		frames := []string{
			`{"event":"RESET","data":{"guest":false,"reason":"guest-reset"},"timestamp":{"seconds":1,"microseconds":2}}` + "\r\n",
			`{"event":"RESUME"}` + "\r\n",
			`{"return":{"name":"cp-arm64-test"},"id":"cyberpanel-qmp-2"}` + "\r\n",
		}
		for _, frame := range frames {
			if _, err := conn.Write([]byte(frame)); err != nil {
				return err
			}
		}
		return nil
	})

	name, err := client.QueryName(context.Background())
	if err != nil {
		t.Fatalf("QueryName() error = %v", err)
	}
	if name != "cp-arm64-test" {
		t.Fatalf("QueryName() = %q, want %q", name, "cp-arm64-test")
	}
	finishClient(t, client, done)
}

func TestTypedCommandsEmitOnlyClosedQMPRequests(t *testing.T) {
	client, done := connectedClient(t, func(conn net.Conn) error {
		requests := []struct {
			command   string
			id        string
			arguments map[string]any
			result    string
		}{
			{"system_powerdown", "cyberpanel-qmp-2", nil, `{}`},
			{"human-monitor-command", "cyberpanel-qmp-3", map[string]any{"command-line": "info usernet"}, `"Hub -1 (net0):\n  TCP[HOST_FORWARD] 127.0.0.1 40123 10.0.2.15 22\n"`},
			{"quit", "cyberpanel-qmp-4", nil, `{}`},
		}
		for _, want := range requests {
			request, err := readRequest(conn)
			if err != nil {
				return err
			}
			if err := requireRequest(request, want.command, want.id, want.arguments); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(conn, `{"return":%s,"id":%q}`+"\r\n", want.result, want.id); err != nil {
				return err
			}
		}
		return nil
	})

	if err := client.SystemPowerdown(context.Background()); err != nil {
		t.Fatalf("SystemPowerdown() error = %v", err)
	}
	usernet, err := client.QueryUsernet(context.Background())
	if err != nil {
		t.Fatalf("QueryUsernet() error = %v", err)
	}
	if !strings.Contains(usernet, "40123") {
		t.Fatalf("QueryUsernet() = %q, want fixed HMP result", usernet)
	}
	if err := client.Quit(context.Background()); err != nil {
		t.Fatalf("Quit() error = %v", err)
	}
	finishClient(t, client, done)
}

func TestExecuteRejectsMissingMismatchedAndAmbiguousResponses(t *testing.T) {
	tests := []struct {
		name    string
		frame   string
		wantErr string
	}{
		{"missing id", `{"return":{"name":"vm"}}` + "\r\n", "missing id"},
		{"mismatched id", `{"return":{"name":"vm"},"id":"cyberpanel-qmp-999"}` + "\r\n", "mismatched id"},
		{"return and error", `{"return":{},"error":{"class":"GenericError","desc":"bad"},"id":"cyberpanel-qmp-2"}` + "\r\n", "both return and error"},
		{"duplicate return", `{"return":{"name":"first"},"return":{"name":"second"},"id":"cyberpanel-qmp-2"}` + "\r\n", "duplicate"},
		{"malformed JSON", `{"return":` + "\r\n", "malformed"},
		{"unknown top-level", `{"return":{"name":"vm"},"id":"cyberpanel-qmp-2","execute":"query-name"}` + "\r\n", "top-level"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, done := connectedClient(t, func(conn net.Conn) error {
				if _, err := readRequest(conn); err != nil {
					return err
				}
				_, err := conn.Write([]byte(tt.frame))
				return err
			})

			_, err := client.QueryName(context.Background())
			if err == nil {
				t.Fatal("QueryName() error = nil, want response rejection")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Fatalf("QueryName() error = %q, want it to contain %q", err, tt.wantErr)
			}
			finishClient(t, client, done)
		})
	}
}

func TestExecuteReturnsTypedQMPError(t *testing.T) {
	client, done := connectedClient(t, func(conn net.Conn) error {
		if _, err := readRequest(conn); err != nil {
			return err
		}
		_, err := conn.Write([]byte(`{"error":{"class":"CommandNotFound","desc":"unknown command"},"id":"cyberpanel-qmp-2"}` + "\r\n"))
		return err
	})

	err := client.SystemPowerdown(context.Background())
	var commandErr *CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("SystemPowerdown() error = %T %v, want *CommandError", err, err)
	}
	if commandErr.Class != "CommandNotFound" || commandErr.Description != "unknown command" {
		t.Fatalf("CommandError = %#v", commandErr)
	}
	finishClient(t, client, done)
}

func TestExecuteRejectsOversizedFrame(t *testing.T) {
	client, done := connectedClient(t, func(conn net.Conn) error {
		if _, err := readRequest(conn); err != nil {
			return err
		}
		frame := `{"return":{"name":"` + strings.Repeat("x", MaxFrameBytes) + `"},"id":"cyberpanel-qmp-2"}` + "\r\n"
		_, err := conn.Write([]byte(frame))
		return err
	})

	_, err := client.QueryName(context.Background())
	var sizeErr *FrameTooLargeError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("QueryName() error = %T %v, want *FrameTooLargeError", err, err)
	}
	finishClient(t, client, done)
}

func TestExecuteRejectsUnboundedEventFlood(t *testing.T) {
	client, done := connectedClient(t, func(conn net.Conn) error {
		if _, err := readRequest(conn); err != nil {
			return err
		}
		for i := 0; i <= MaxEventsPerCommand; i++ {
			if _, err := conn.Write([]byte(`{"event":"RESET"}` + "\r\n")); err != nil {
				return err
			}
		}
		return nil
	})

	_, err := client.QueryName(context.Background())
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "too many events") {
		t.Fatalf("QueryName() error = %v, want event-bound rejection", err)
	}
	finishClient(t, client, done)
}

func TestContextDeadlineInterruptsBlockedRead(t *testing.T) {
	client, done := connectedClient(t, func(conn net.Conn) error {
		if _, err := readRequest(conn); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.QueryName(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("QueryName() error = %T %v, want context deadline exceeded", err, err)
	}
	finishClient(t, client, done)
}

func connectedClient(t *testing.T, script func(net.Conn) error) (*Client, <-chan error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	done := runScript(serverConn, func(conn net.Conn) error {
		if _, err := conn.Write([]byte(validGreeting)); err != nil {
			return err
		}
		request, err := readRequest(conn)
		if err != nil {
			return err
		}
		if err := requireRequest(request, "qmp_capabilities", "cyberpanel-qmp-1", map[string]any{"enable": []any{}}); err != nil {
			return err
		}
		if _, err := conn.Write([]byte(`{"return":{},"id":"cyberpanel-qmp-1"}` + "\r\n")); err != nil {
			return err
		}
		return script(conn)
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := New(ctx, clientConn)
	if err != nil {
		clientConn.Close()
		awaitScript(t, done)
		t.Fatalf("New() error = %v", err)
	}
	return client, done
}

func finishClient(t *testing.T, client *Client, done <-chan error) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	awaitScript(t, done)
}

func runScript(conn net.Conn, script func(net.Conn) error) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer conn.Close()
		done <- script(conn)
	}()
	return done
}

func awaitScript(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("scripted QMP server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("scripted QMP server did not finish")
	}
}

func readRequest(conn net.Conn) (map[string]any, error) {
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, err
	}
	var request map[string]any
	if err := json.Unmarshal([]byte(line), &request); err != nil {
		return nil, err
	}
	return request, nil
}

func requireRequest(request map[string]any, command, id string, arguments map[string]any) error {
	if got := request["execute"]; got != command {
		return fmt.Errorf("execute = %#v, want %q", got, command)
	}
	if got := request["id"]; got != id {
		return fmt.Errorf("id = %#v, want %q", got, id)
	}
	gotArguments, present := request["arguments"]
	if arguments == nil {
		if present {
			return fmt.Errorf("arguments = %#v, want absent", gotArguments)
		}
		return nil
	}
	if !present || !reflect.DeepEqual(gotArguments, arguments) {
		return fmt.Errorf("arguments = %#v, want %#v", gotArguments, arguments)
	}
	return nil
}

func writeFragments(conn net.Conn, value string, sizes ...int) error {
	remaining := []byte(value)
	for _, size := range sizes {
		if len(remaining) == 0 {
			break
		}
		if size > len(remaining) {
			size = len(remaining)
		}
		if _, err := conn.Write(remaining[:size]); err != nil {
			return err
		}
		remaining = remaining[size:]
	}
	if len(remaining) > 0 {
		_, err := conn.Write(remaining)
		return err
	}
	return nil
}
