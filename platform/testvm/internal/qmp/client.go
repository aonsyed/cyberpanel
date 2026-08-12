// Package qmp implements the closed subset of the QEMU Machine Protocol used
// by the disposable test-VM harness.
package qmp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// MaxFrameBytes is the largest JSON object accepted from QEMU, excluding
	// the protocol's terminating CRLF.
	MaxFrameBytes = 64 * 1024
	// MaxEventsPerCommand prevents an event stream from postponing a command
	// response without bound.
	MaxEventsPerCommand = 32

	expectedMajor   = 11
	expectedMinor   = 0
	expectedMicro   = 3
	expectedPackage = ""
)

// DialFunc establishes one QMP transport. The returned connection becomes the
// Client's property, including when protocol negotiation fails.
type DialFunc func(context.Context) (net.Conn, error)

// CommandError is an error response produced by QEMU for a valid QMP command.
type CommandError struct {
	Class       string
	Description string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("qmp command failed (%s): %s", e.Class, e.Description)
}

// FrameTooLargeError reports a peer frame that exceeded MaxFrameBytes.
type FrameTooLargeError struct {
	Max int
}

func (e *FrameTooLargeError) Error() string {
	return fmt.Sprintf("qmp frame exceeds %d bytes", e.Max)
}

// ProtocolError reports a message that violates the closed QMP contract.
type ProtocolError struct {
	Problem string
}

func (e *ProtocolError) Error() string {
	return "qmp protocol: " + e.Problem
}

// Client owns one negotiated QMP connection. Commands are serialized because
// this client deliberately does not enable QMP out-of-band execution.
type Client struct {
	conn   net.Conn
	reader *bufio.Reader
	gate   chan struct{}

	nextID uint64

	closeOnce sync.Once
	closeErr  error
}

// Dial establishes and negotiates a QMP connection through dial.
func Dial(ctx context.Context, dial DialFunc) (*Client, error) {
	if ctx == nil {
		return nil, errors.New("qmp: nil context")
	}
	if dial == nil {
		return nil, errors.New("qmp: nil dial function")
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("qmp dial: %w", err)
	}
	if conn == nil {
		return nil, errors.New("qmp dial: dial function returned a nil connection")
	}
	return New(ctx, conn)
}

// New validates the QEMU 11.0.3 greeting and completes qmp_capabilities
// negotiation. It closes conn if negotiation fails.
func New(ctx context.Context, conn net.Conn) (*Client, error) {
	if ctx == nil {
		return nil, errors.New("qmp: nil context")
	}
	if conn == nil {
		return nil, errors.New("qmp: nil connection")
	}

	client := &Client{
		conn:   conn,
		reader: bufio.NewReaderSize(conn, MaxFrameBytes+2),
		gate:   make(chan struct{}, 1),
	}
	client.gate <- struct{}{}

	err := client.withDeadline(ctx, func() error {
		frame, err := client.readFrame()
		if err != nil {
			return fmt.Errorf("read greeting: %w", err)
		}
		if err := validateGreeting(frame); err != nil {
			return err
		}

		id := client.newID()
		arguments := map[string]any{"enable": []string{}}
		if err := client.writeCommand("qmp_capabilities", arguments, id); err != nil {
			return fmt.Errorf("negotiate capabilities: %w", err)
		}
		result, err := client.awaitResponse(id, false)
		if err != nil {
			return fmt.Errorf("negotiate capabilities: %w", err)
		}
		if err := requireEmptyObject(result); err != nil {
			return fmt.Errorf("negotiate capabilities: %w", err)
		}
		return nil
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

// Close releases the QMP transport.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}

// QueryName returns the configured QEMU VM name.
func (c *Client) QueryName(ctx context.Context) (string, error) {
	result, err := c.execute(ctx, "query-name", nil)
	if err != nil {
		return "", err
	}
	object, err := strictObject(result, "query-name return", "name")
	if err != nil {
		return "", err
	}
	var name string
	if err := json.Unmarshal(object["name"], &name); err != nil {
		return "", protocolf("query-name return name is not a string")
	}
	return name, nil
}

// SystemPowerdown requests an ACPI-style guest shutdown.
func (c *Client) SystemPowerdown(ctx context.Context) error {
	result, err := c.execute(ctx, "system_powerdown", nil)
	if err != nil {
		return err
	}
	return requireEmptyObject(result)
}

// Quit requests graceful QEMU process termination. An EOF before QEMU's
// matching response remains an error because it cannot prove command receipt.
func (c *Client) Quit(ctx context.Context) error {
	result, err := c.execute(ctx, "quit", nil)
	if err != nil {
		return err
	}
	return requireEmptyObject(result)
}

// QueryUsernet runs the single HMP command needed to discover the host port
// QEMU selected for the harness's fixed SSH forwarding rule. Callers cannot
// supply an arbitrary HMP command line.
func (c *Client) QueryUsernet(ctx context.Context) (string, error) {
	result, err := c.execute(ctx, "human-monitor-command", map[string]string{
		"command-line": "info usernet",
	})
	if err != nil {
		return "", err
	}
	var output string
	if err := json.Unmarshal(result, &output); err != nil {
		return "", protocolf("human-monitor-command return is not a string")
	}
	return output, nil
}

func (c *Client) execute(ctx context.Context, command string, arguments any) (json.RawMessage, error) {
	if c == nil {
		return nil, errors.New("qmp: nil client")
	}
	if ctx == nil {
		return nil, errors.New("qmp: nil context")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.gate:
	}
	defer func() { c.gate <- struct{}{} }()

	var result json.RawMessage
	err := c.withDeadline(ctx, func() error {
		id := c.newID()
		if err := c.writeCommand(command, arguments, id); err != nil {
			return err
		}
		var err error
		result, err = c.awaitResponse(id, true)
		return err
	})
	if err != nil {
		var commandErr *CommandError
		if errors.As(err, &commandErr) {
			return nil, commandErr
		}
		return nil, fmt.Errorf("qmp %s: %w", command, err)
	}
	return result, nil
}

func (c *Client) newID() string {
	c.nextID++
	return fmt.Sprintf("cyberpanel-qmp-%d", c.nextID)
}

func (c *Client) withDeadline(ctx context.Context, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	deadline := time.Time{}
	if value, ok := ctx.Deadline(); ok {
		deadline = value
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set connection deadline: %w", err)
	}
	cancelFinished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c.conn.SetDeadline(time.Now())
		close(cancelFinished)
	})
	defer func() {
		if !stop() {
			<-cancelFinished
		}
		_ = c.conn.SetDeadline(time.Time{})
	}()

	err := operation()
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	// A connection deadline and a context deadline share the same instant, but
	// the network poller may report its timeout before the context timer goroutine
	// publishes ctx.Err(). Preserve the context contract deterministically.
	var networkErr net.Error
	if !deadline.IsZero() && errors.As(err, &networkErr) && networkErr.Timeout() && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

func (c *Client) writeCommand(command string, arguments any, id string) error {
	request := struct {
		Execute   string `json:"execute"`
		Arguments any    `json:"arguments,omitempty"`
		ID        string `json:"id"`
	}{
		Execute:   command,
		Arguments: arguments,
		ID:        id,
	}
	frame, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode command: %w", err)
	}
	if len(frame) > MaxFrameBytes {
		return &FrameTooLargeError{Max: MaxFrameBytes}
	}
	frame = append(frame, '\r', '\n')
	for len(frame) > 0 {
		written, err := c.conn.Write(frame)
		if err != nil {
			return fmt.Errorf("write command: %w", err)
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[written:]
	}
	return nil
}

func (c *Client) readFrame() ([]byte, error) {
	line, err := c.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, &FrameTooLargeError{Max: MaxFrameBytes}
	}
	if err != nil {
		return nil, err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, protocolf("frame is not terminated by CRLF")
	}
	payload := line[:len(line)-2]
	if len(payload) > MaxFrameBytes {
		return nil, &FrameTooLargeError{Max: MaxFrameBytes}
	}
	if len(payload) == 0 {
		return nil, protocolf("empty frame")
	}
	return payload, nil
}

func (c *Client) awaitResponse(expectedID string, allowEvents bool) (json.RawMessage, error) {
	events := 0
	for {
		frame, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		object, err := decodeObject(frame, "top-level")
		if err != nil {
			return nil, err
		}
		if _, event := object["event"]; event {
			if !allowEvents {
				return nil, protocolf("event received during capabilities negotiation")
			}
			if err := validateEvent(object); err != nil {
				return nil, err
			}
			events++
			if events > MaxEventsPerCommand {
				return nil, protocolf("too many events before command response")
			}
			continue
		}
		return validateResponse(object, expectedID)
	}
}

func validateGreeting(frame []byte) error {
	object, err := decodeObject(frame, "greeting top-level")
	if err != nil {
		return err
	}
	if err := requireOnly(object, "greeting top-level", "QMP"); err != nil {
		return err
	}
	greeting, err := decodeObject(object["QMP"], "greeting QMP")
	if err != nil {
		return err
	}
	if err := requireOnly(greeting, "greeting QMP", "version", "capabilities"); err != nil {
		return err
	}

	version, err := decodeObject(greeting["version"], "greeting version")
	if err != nil {
		return err
	}
	if err := requireOnly(version, "greeting version", "qemu", "package"); err != nil {
		return err
	}
	qemuVersion, err := decodeObject(version["qemu"], "greeting qemu version")
	if err != nil {
		return err
	}
	if err := requireOnly(qemuVersion, "greeting qemu version", "major", "minor", "micro"); err != nil {
		return err
	}
	var numbers struct {
		Major int
		Minor int
		Micro int
	}
	if err := json.Unmarshal(version["qemu"], &numbers); err != nil {
		return protocolf("greeting version contains non-integer components")
	}
	if numbers.Major != expectedMajor || numbers.Minor != expectedMinor || numbers.Micro != expectedMicro {
		return protocolf("greeting version is %d.%d.%d, want %d.%d.%d",
			numbers.Major, numbers.Minor, numbers.Micro,
			expectedMajor, expectedMinor, expectedMicro)
	}
	var packageName string
	if err := json.Unmarshal(version["package"], &packageName); err != nil {
		return protocolf("greeting package is not a string")
	}
	if packageName != expectedPackage {
		return protocolf("greeting package is %q, want %q", packageName, expectedPackage)
	}

	var capabilities []string
	if err := json.Unmarshal(greeting["capabilities"], &capabilities); err != nil || capabilities == nil {
		return protocolf("greeting capabilities is not an array")
	}
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if capability != "oob" {
			return protocolf("greeting advertises unsupported capability %q", capability)
		}
		if _, duplicate := seen[capability]; duplicate {
			return protocolf("greeting repeats capability %q", capability)
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func validateEvent(object map[string]json.RawMessage) error {
	if err := allowOnly(object, "event top-level", "event", "data", "timestamp"); err != nil {
		return err
	}
	if _, ok := object["event"]; !ok {
		return protocolf("event top-level is missing %q", "event")
	}
	var name string
	if err := json.Unmarshal(object["event"], &name); err != nil || name == "" {
		return protocolf("event name is not a non-empty string")
	}
	if data, ok := object["data"]; ok {
		if _, err := decodeObject(data, "event data"); err != nil {
			return err
		}
	}
	if timestamp, ok := object["timestamp"]; ok {
		value, err := decodeObject(timestamp, "event timestamp")
		if err != nil {
			return err
		}
		if err := requireOnly(value, "event timestamp", "seconds", "microseconds"); err != nil {
			return err
		}
		var parsed struct {
			Seconds      int64 `json:"seconds"`
			Microseconds int64 `json:"microseconds"`
		}
		if err := json.Unmarshal(timestamp, &parsed); err != nil {
			return protocolf("event timestamp is malformed")
		}
	}
	return nil
}

func validateResponse(object map[string]json.RawMessage, expectedID string) (json.RawMessage, error) {
	if err := allowOnly(object, "response top-level", "return", "error", "id"); err != nil {
		return nil, err
	}
	idValue, ok := object["id"]
	if !ok {
		return nil, protocolf("response is missing id")
	}
	var id string
	if err := json.Unmarshal(idValue, &id); err != nil {
		return nil, protocolf("response id is not a string")
	}
	if id != expectedID {
		return nil, protocolf("response has mismatched id %q, want %q", id, expectedID)
	}

	result, hasResult := object["return"]
	errorValue, hasError := object["error"]
	if hasResult && hasError {
		return nil, protocolf("response contains both return and error")
	}
	if !hasResult && !hasError {
		return nil, protocolf("response contains neither return nor error")
	}
	if hasResult {
		return result, nil
	}

	errorObject, err := decodeObject(errorValue, "error response")
	if err != nil {
		return nil, err
	}
	if err := requireOnly(errorObject, "error response", "class", "desc"); err != nil {
		return nil, err
	}
	var wireError struct {
		Class       string `json:"class"`
		Description string `json:"desc"`
	}
	if err := json.Unmarshal(errorValue, &wireError); err != nil || wireError.Class == "" || wireError.Description == "" {
		return nil, protocolf("error response class and desc must be non-empty strings")
	}
	return nil, &CommandError{Class: wireError.Class, Description: wireError.Description}
}

func requireEmptyObject(value json.RawMessage) error {
	object, err := decodeObject(value, "command return")
	if err != nil {
		return err
	}
	if len(object) != 0 {
		return protocolf("command return object is not empty")
	}
	return nil
}

func strictObject(value json.RawMessage, label string, keys ...string) (map[string]json.RawMessage, error) {
	object, err := decodeObject(value, label)
	if err != nil {
		return nil, err
	}
	if err := requireOnly(object, label, keys...); err != nil {
		return nil, err
	}
	return object, nil
}

func decodeObject(value []byte, label string) (map[string]json.RawMessage, error) {
	if err := rejectDuplicateMembers(value); err != nil {
		return nil, protocolf("%s is malformed: %v", label, err)
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(value))
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, protocolf("%s is not a JSON object", label)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, protocolf("%s contains trailing JSON", label)
	}
	return object, nil
}

func requireOnly(object map[string]json.RawMessage, label string, required ...string) error {
	allowed := make(map[string]struct{}, len(required))
	for _, key := range required {
		allowed[key] = struct{}{}
		if _, ok := object[key]; !ok {
			return protocolf("%s is missing %q", label, key)
		}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return protocolf("%s contains unknown member %q", label, key)
		}
	}
	return nil
}

func allowOnly(object map[string]json.RawMessage, label string, allowedKeys ...string) error {
	allowed := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return protocolf("%s contains unknown member %q", label, key)
		}
	}
	return nil
}

func rejectDuplicateMembers(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object member name is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate object member %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim('}') {
				return errors.New("object has invalid closing delimiter")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim(']') {
				return errors.New("array has invalid closing delimiter")
			}
		default:
			return fmt.Errorf("unexpected delimiter %q", delimiter)
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func protocolf(format string, arguments ...any) error {
	return &ProtocolError{Problem: fmt.Sprintf(format, arguments...)}
}
