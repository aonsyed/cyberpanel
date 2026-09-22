package webmaildata

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultManageSieveTimeout = 10 * time.Second
	maximumManageSieveTimeout = 30 * time.Second
	defaultManageSieveBytes   = 512 << 10
	maximumManageSieveBytes   = 1 << 20
	maximumManageSieveLines   = 256
	maximumManageSieveLine    = 16 << 10
	maximumManageSieveResponse = 256 << 10
)

type ManageSieveCredentials struct {
	Username string
	Secret   []byte
	OAuthBearer bool
}

type ManageSieveCredentialProvider interface {
	CredentialsForManageSieve(context.Context, Scope) (ManageSieveCredentials, error)
}

type LocalManageSieveAdapter struct {
	UnixSocket       string
	Credentials     ManageSieveCredentialProvider
	Timeout          time.Duration
	MaximumScriptBytes int
}

func (adapter *LocalManageSieveAdapter) Stage(ctx context.Context, request ManageSieveStageRequest) (ManageSieveReceipt, error) {
	if err := adapter.validateProgramCall(ctx, request.Program); err != nil || !opaquePattern.MatchString(request.OperationID) {
		if err != nil { return ManageSieveReceipt{}, err }
		return ManageSieveReceipt{}, ErrInvalid
	}
	name := manageSieveGenerationName(request.Program)
	client, err := adapter.connect(ctx, request.Program.Scope)
	if err != nil { return ManageSieveReceipt{}, err }
	existing, _, err := client.listScripts()
	if err != nil { client.close(); return ManageSieveReceipt{}, err }
	if existing[name] {
		stored, getErr := client.getScript(name); client.close()
		if getErr != nil { return ManageSieveReceipt{}, getErr }
		if stored != request.Program.Script { return ManageSieveReceipt{}, ErrConflict }
		return stagedReceipt(request), nil
	}
	err = client.putScript(name, request.Program.Script)
	client.close()
	if err != nil {
		reconciled, reconcileErr := adapter.scriptEquals(ctx, request.Program.Scope, name, request.Program.Script)
		if reconcileErr != nil || !reconciled { return ManageSieveReceipt{}, errors.Join(ErrActivation, err, reconcileErr) }
	}
	return stagedReceipt(request), nil
}

func (adapter *LocalManageSieveAdapter) ValidateCompile(ctx context.Context, request ManageSieveValidationRequest) (ManageSieveReceipt, error) {
	if err := adapter.validateProgramCall(ctx, request.Program); err != nil || request.Scope != request.Program.Scope || request.Generation != request.Program.Generation || request.Digest != request.Program.Digest {
		if err != nil { return ManageSieveReceipt{}, err }
		return ManageSieveReceipt{}, ErrInvalid
	}
	client, err := adapter.connect(ctx, request.Scope)
	if err != nil { return ManageSieveReceipt{}, err }
	existing, _, err := client.listScripts()
	if err == nil && !existing[manageSieveGenerationName(request.Program)] { err = ErrConflict }
	if err == nil { err = client.checkScript(request.Program.Script) }
	client.close()
	if err != nil { return ManageSieveReceipt{}, err }
	return ManageSieveReceipt{Scope: request.Scope, Generation: request.Generation, Digest: request.Digest, Validated: true}, nil
}

func (adapter *LocalManageSieveAdapter) ActivateCAS(ctx context.Context, request ManageSieveActivationRequest) (ManageSieveReceipt, error) {
	if adapter == nil || ctx == nil || adapter.Credentials == nil || adapter.UnixSocket == "" || !filepath.IsAbs(adapter.UnixSocket) || adapter.timeout() <= 0 || adapter.timeout() > maximumManageSieveTimeout || adapter.maximumBytes() < 1 || adapter.maximumBytes() > maximumManageSieveBytes || !request.Scope.Valid() || !opaquePattern.MatchString(request.OperationID) || request.ExpectedGeneration > MaximumRevision || (request.ExpectedGeneration == 0) != (request.ExpectedDigest == "") || request.ExpectedDigest != "" && !validDigest(request.ExpectedDigest) || request.Remove == (request.Program.Generation != 0) {
		return ManageSieveReceipt{}, ErrInvalid
	}
	if !request.Remove { if err := adapter.validateProgramCall(ctx, request.Program); err != nil || request.Program.Scope != request.Scope { if err != nil { return ManageSieveReceipt{}, err }; return ManageSieveReceipt{}, ErrInvalid } }
	client, err := adapter.connect(ctx, request.Scope)
	if err != nil { return ManageSieveReceipt{}, err }
	existing, activeName, err := client.listScripts()
	if err != nil { client.close(); return ManageSieveReceipt{}, err }
	activeGeneration, activeDigest, recognized := manageSieveGeneration(activeName)
	if activeName != "" && !recognized || activeGeneration != request.ExpectedGeneration || activeDigest != request.ExpectedDigest { client.close(); return ManageSieveReceipt{}, ErrConflict }
	desiredName, desiredDigest, generation := "", "", uint64(0)
	if !request.Remove {
		desiredName, desiredDigest, generation = manageSieveGenerationName(request.Program), request.Program.Digest, request.Program.Generation
		if !existing[desiredName] { client.close(); return ManageSieveReceipt{}, ErrConflict }
	}
	err = client.setActive(desiredName)
	client.close()
	observedName, observeErr := adapter.observeActive(ctx, request.Scope)
	observedGeneration, observedDigest, observedRecognized := manageSieveGeneration(observedName)
	if observedName != "" && !observedRecognized { return ManageSieveReceipt{}, errors.Join(ErrIntegrity, err, observeErr) }
	if observeErr == nil && observedGeneration == generation && observedDigest == desiredDigest {
		return ManageSieveReceipt{OperationID: request.OperationID, Scope: request.Scope, Generation: generation, Digest: desiredDigest, PreviousGeneration: request.ExpectedGeneration, PreviousDigest: request.ExpectedDigest, Validated: !request.Remove, Activated: true}, nil
	}
	if observeErr == nil && observedGeneration == request.ExpectedGeneration && observedDigest == request.ExpectedDigest { return ManageSieveReceipt{}, errors.Join(ErrActivation, err) }
	return ManageSieveReceipt{}, errors.Join(ErrActivation, err, observeErr)
}

func (adapter *LocalManageSieveAdapter) Test(ctx context.Context, program SieveProgram, message SieveTestMessage) (SieveEvaluation, error) {
	if err := adapter.validateProgramCall(ctx, program); err != nil { return SieveEvaluation{}, err }
	client, err := adapter.connect(ctx, program.Scope)
	if err != nil { return SieveEvaluation{}, err }
	err = client.checkScript(program.Script); client.close()
	if err != nil { return SieveEvaluation{}, err }
	return EvaluateSieve(program, message)
}

func (adapter *LocalManageSieveAdapter) validateProgramCall(ctx context.Context, program SieveProgram) error {
	if adapter == nil || ctx == nil || adapter.Credentials == nil || adapter.UnixSocket == "" || !filepath.IsAbs(adapter.UnixSocket) || adapter.timeout() <= 0 || adapter.timeout() > maximumManageSieveTimeout || adapter.maximumBytes() < 1 || adapter.maximumBytes() > maximumManageSieveBytes { return ErrInvalid }
	if err := program.Validate(); err != nil || len(program.Script) > adapter.maximumBytes() { if err != nil { return err }; return ErrLimit }
	return nil
}

func (adapter *LocalManageSieveAdapter) connect(ctx context.Context, scope Scope) (*manageSieveClient, error) {
	if adapter == nil || ctx == nil || !scope.Valid() || adapter.Credentials == nil || adapter.UnixSocket == "" || !filepath.IsAbs(adapter.UnixSocket) { return nil, ErrInvalid }
	credentials, err := adapter.Credentials.CredentialsForManageSieve(ctx, scope)
	if err != nil { return nil, err }
	defer wipeManageSieveSecret(credentials.Secret)
	if credentials.Username == "" || len(credentials.Username) > 254 || strings.ContainsAny(credentials.Username, "\x00\r\n") || len(credentials.Secret) == 0 || len(credentials.Secret) > 16<<10 { return nil, ErrInvalid }
	for _, character := range credentials.Username { if character < 32 || character == 127 { return nil, ErrInvalid } }
	dialer := net.Dialer{Timeout: adapter.timeout()}
	connection, err := dialer.DialContext(ctx, "unix", adapter.UnixSocket)
	if err != nil { return nil, err }
	deadline := time.Now().Add(adapter.timeout()); if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) { deadline = contextDeadline }
	if err = connection.SetDeadline(deadline); err != nil { connection.Close(); return nil, err }
	client := &manageSieveClient{connection: connection, reader: bufio.NewReaderSize(connection, maximumManageSieveLine), maximumBytes: adapter.maximumBytes()}
	if _, err = client.readResponse(); err != nil { client.close(); return nil, err }
	capabilities, err := client.capabilities()
	if err != nil { client.close(); return nil, err }
	mechanism := "PLAIN"
	if credentials.OAuthBearer { mechanism = "OAUTHBEARER" }
	if !capabilities["SIEVE"] || !capabilities["SASL:"+mechanism] { client.close(); return nil, ErrActivation }
	authentication := append([]byte{0}, []byte(credentials.Username)...); authentication = append(authentication, 0); authentication = append(authentication, credentials.Secret...)
	if credentials.OAuthBearer {
		wipeManageSieveSecret(authentication)
		if strings.ContainsAny(credentials.Username, "\x01\x7f") { client.close(); return nil, ErrInvalid }
		username := strings.NewReplacer("=", "=3D", ",", "=2C").Replace(credentials.Username)
		authentication = append([]byte("n,a="+username+",\x01auth=Bearer "), credentials.Secret...)
		authentication = append(authentication, 1, 1)
	}
	encoded := base64.StdEncoding.EncodeToString(authentication); wipeManageSieveSecret(authentication)
	_, err = client.command(`AUTHENTICATE "` + mechanism + `" "` + encoded + `"`)
	if err != nil { client.close(); return nil, ErrUnauthorized }
	return client, nil
}

func (adapter *LocalManageSieveAdapter) scriptEquals(ctx context.Context, scope Scope, name, expected string) (bool, error) {
	client, err := adapter.connect(ctx, scope); if err != nil { return false, err }; defer client.close()
	existing, _, err := client.listScripts(); if err != nil || !existing[name] { return false, err }
	actual, err := client.getScript(name); return err == nil && actual == expected, err
}

func (adapter *LocalManageSieveAdapter) observeActive(ctx context.Context, scope Scope) (string, error) {
	client, err := adapter.connect(ctx, scope); if err != nil { return "", err }; defer client.close()
	_, active, err := client.listScripts(); return active, err
}

func (adapter *LocalManageSieveAdapter) timeout() time.Duration { if adapter.Timeout == 0 { return defaultManageSieveTimeout }; return adapter.Timeout }
func (adapter *LocalManageSieveAdapter) maximumBytes() int { if adapter.MaximumScriptBytes == 0 { return defaultManageSieveBytes }; return adapter.MaximumScriptBytes }

type manageSieveClient struct { connection net.Conn; reader *bufio.Reader; maximumBytes int }

func (client *manageSieveClient) close() { if client != nil && client.connection != nil { _ = client.connection.Close() } }

func (client *manageSieveClient) capabilities() (map[string]bool, error) {
	lines, err := client.command("CAPABILITY")
	if err != nil { return nil, err }
	result := map[string]bool{}
	for _, line := range lines { name, rest, parseErr := parseManageSieveQuoted(line); if parseErr != nil { return nil, ErrIntegrity }; name = strings.ToUpper(name); result[name] = true; if name == "SASL" { mechanisms, _, mechanismErr := parseManageSieveQuoted(rest); if mechanismErr != nil { return nil, ErrIntegrity }; for _, mechanism := range strings.Fields(mechanisms) { result["SASL:"+strings.ToUpper(mechanism)] = true } } }
	return result, nil
}

func (client *manageSieveClient) listScripts() (map[string]bool, string, error) {
	lines, err := client.command("LISTSCRIPTS")
	if err != nil { return nil, "", err }
	result, active := map[string]bool{}, ""
	for _, line := range lines {
		name, rest, parseErr := parseManageSieveQuoted(line); if parseErr != nil || len(name) > 128 { return nil, "", ErrIntegrity }
		result[name] = true
		if strings.EqualFold(rest, "ACTIVE") { if active != "" { return nil, "", ErrIntegrity }; active = name } else if rest != "" { return nil, "", ErrIntegrity }
	}
	return result, active, nil
}

func (client *manageSieveClient) putScript(name, script string) error { _, err := client.literalCommand(`PUTSCRIPT "`+quoteManageSieve(name)+`"`, script); return err }
func (client *manageSieveClient) checkScript(script string) error { _, err := client.literalCommand("CHECKSCRIPT", script); return err }
func (client *manageSieveClient) setActive(name string) error { _, err := client.command(`SETACTIVE "` + quoteManageSieve(name) + `"`); return err }

func (client *manageSieveClient) getScript(name string) (string, error) {
	if err := client.writeLine(`GETSCRIPT "` + quoteManageSieve(name) + `"`); err != nil { return "", err }
	line, err := client.readLine(); if err != nil { return "", err }
	if status, statusErr := manageSieveStatus(line); status { if statusErr != nil { return "", statusErr }; return "", ErrIntegrity }
	if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
		size, parseErr := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(line, "{"), "}")); if parseErr != nil || size < 0 || size > client.maximumBytes { return "", ErrLimit }
		buffer := make([]byte, size+2); if _, err = io.ReadFull(client.reader, buffer); err != nil { return "", err }; if string(buffer[size:]) != "\r\n" { return "", ErrIntegrity }
		if _, err = client.readResponse(); err != nil { return "", err }; return string(buffer[:size]), nil
	}
	value, err := strconv.Unquote(line); if err != nil || len(value) > client.maximumBytes { return "", ErrIntegrity }
	if _, err = client.readResponse(); err != nil { return "", err }; return value, nil
}

func (client *manageSieveClient) literalCommand(command, value string) ([]string, error) {
	if len(value) > client.maximumBytes { return nil, ErrLimit }
	if _, err := fmt.Fprintf(client.connection, "%s {%d+}\r\n%s\r\n", command, len(value), value); err != nil { return nil, err }
	return client.readResponse()
}

func (client *manageSieveClient) command(command string) ([]string, error) { if err := client.writeLine(command); err != nil { return nil, err }; return client.readResponse() }
func (client *manageSieveClient) writeLine(value string) error { if strings.ContainsAny(value, "\r\n\x00") || len(value) > maximumManageSieveLine { return ErrInvalid }; _, err := io.WriteString(client.connection, value+"\r\n"); return err }

func (client *manageSieveClient) readResponse() ([]string, error) {
	lines := make([]string, 0, 8)
	total := 0
	for count := 0; count < maximumManageSieveLines; count++ {
		line, err := client.readLine(); if err != nil { return nil, err }
		total += len(line); if total > maximumManageSieveResponse { return nil, ErrLimit }
		if status, statusErr := manageSieveStatus(line); status {
			// The terminal diagnostic may be a literal, including OK (WARNINGS).
			// Drain it without treating diagnostic text as another command response.
			if start:=strings.LastIndex(line," {");start>=0&&strings.HasSuffix(line,"}") {
				size,parseErr:=strconv.Atoi(line[start+2:len(line)-1])
				if parseErr!=nil||size<0||size>maximumManageSieveResponse-total {return nil,ErrLimit}
				body:=make([]byte,size+2);if _,err=io.ReadFull(client.reader,body);err!=nil{return nil,err}
				if string(body[size:])!="\r\n" {return nil,ErrIntegrity}
			}
			return lines, statusErr
		}
		lines = append(lines, line)
	}
	return nil, ErrLimit
}

func (client *manageSieveClient) readLine() (string, error) {
	raw, err := client.reader.ReadSlice('\n'); if errors.Is(err, bufio.ErrBufferFull) { return "", ErrLimit }; if err != nil { return "", err }; line := string(raw)
	if len(line) > maximumManageSieveLine || !strings.HasSuffix(line, "\r\n") { return "", ErrLimit }
	return strings.TrimSuffix(line, "\r\n"), nil
}

func manageSieveStatus(line string) (bool, error) {
	upper := strings.ToUpper(line)
	if upper == "OK" || strings.HasPrefix(upper, "OK ") { return true, nil }
	if upper == "NO" || strings.HasPrefix(upper, "NO ") { return true, ErrConflict }
	if upper == "BYE" || strings.HasPrefix(upper, "BYE ") { return true, ErrActivation }
	return false, nil
}

func parseManageSieveQuoted(line string) (string, string, error) {
	if len(line) < 2 || line[0] != '"' { return "", "", ErrIntegrity }
	escaped := false
	for index := 1; index < len(line); index++ {
		if escaped { escaped = false; continue }
		if line[index] == '\\' { escaped = true; continue }
		if line[index] == '"' { value, err := strconv.Unquote(line[:index+1]); if err != nil { return "", "", ErrIntegrity }; return value, strings.TrimSpace(line[index+1:]), nil }
	}
	return "", "", ErrIntegrity
}

func manageSieveGenerationName(program SieveProgram) string { return fmt.Sprintf("cp-%020d-%s", program.Generation, program.Digest) }
func manageSieveGeneration(name string) (uint64, string, bool) { if name == "" { return 0, "", true }; parts := strings.Split(name, "-"); if len(parts) != 3 || parts[0] != "cp" || len(parts[1]) != 20 || !validDigest(parts[2]) { return 0, "", false }; generation, err := strconv.ParseUint(parts[1], 10, 64); if err != nil || generation == 0 || generation > MaximumRevision { return 0, "", false }; return generation, parts[2], true }
func quoteManageSieve(value string) string { return strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value) }
func wipeManageSieveSecret(value []byte) { for index := range value { value[index] = 0 } }
func stagedReceipt(request ManageSieveStageRequest) ManageSieveReceipt { return ManageSieveReceipt{OperationID: request.OperationID, Scope: request.Program.Scope, Generation: request.Program.Generation, Digest: request.Program.Digest} }
