//go:build linux

package maildelivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
)

const (
	PostfixRelayConfigurationRoot = "/var/lib/cyberpanel/maildelivery-relay"
	postfixBinary = "/usr/sbin/postfix"
	postfixOutputLimit = 1 << 20
)

type PostfixRelayDomainResolver interface {
	ResolvePostfixRelayDomain(context.Context, TenantID, DomainID) (string, error)
}

type PostfixCommand string

const (
	PostfixCheck PostfixCommand = "check"
	PostfixReload PostfixCommand = "reload"
)

type PostfixCommandRunner interface {
	RunPostfix(context.Context, PostfixCommand) ([]byte, error)
}

type LinuxPostfixCommandRunner struct{}

func (LinuxPostfixCommandRunner) RunPostfix(ctx context.Context, operation PostfixCommand) ([]byte, error) {
	if ctx == nil || operation != PostfixCheck && operation != PostfixReload {
		return nil, ErrInvalid
	}
	commandContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, postfixBinary, string(operation))
	command.Stdin = nil
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output := &boundedPostfixOutput{maximum: postfixOutputLimit}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	content := append([]byte(nil), output.content.Bytes()...)
	if output.overflow {
		return content, errors.Join(ErrUnavailable, err)
	}
	if err != nil {
		return content, ErrUnavailable
	}
	return content, nil
}

type LinuxPostfixRelay struct {
	store *daemoncfg.Store
	postfixGID uint32
	domains PostfixRelayDomainResolver
	secrets SMTPSecretResolver
	runner PostfixCommandRunner
	now func() time.Time
	mutex sync.Mutex
}

func OpenLinuxPostfixRelay(postfixGID uint32, domains PostfixRelayDomainResolver, secrets SMTPSecretResolver, runner PostfixCommandRunner) (*LinuxPostfixRelay, error) {
	if postfixGID == 0 || domains == nil || secrets == nil {
		return nil, ErrInvalid
	}
	if runner == nil {
		runner = LinuxPostfixCommandRunner{}
	}
	store, err := daemoncfg.OpenStore(PostfixRelayConfigurationRoot, PostfixRelayConfigurationRoot)
	if err != nil {
		return nil, err
	}
	return &LinuxPostfixRelay{store: store, postfixGID: postfixGID, domains: domains, secrets: secrets, runner: runner, now: time.Now}, nil
}

func (relay *LinuxPostfixRelay) Close() error {
	if relay == nil {
		return nil
	}
	relay.mutex.Lock()
	defer relay.mutex.Unlock()
	if relay.store == nil {
		return nil
	}
	err := relay.store.Close()
	relay.store = nil
	return err
}

type renderedPostfixRelay struct {
	domains []string
	transport []byte
	tlsPolicy []byte
}

func (relay *LinuxPostfixRelay) RenderPostfixRelay(ctx context.Context, spec PostfixRelaySpec) (PostfixRelayGeneration, error) {
	if relay == nil || relay.store == nil || ctx == nil || spec.Validate() != nil {
		return PostfixRelayGeneration{}, ErrInvalid
	}
	rendered, err := relay.render(ctx, spec)
	if err != nil {
		return PostfixRelayGeneration{}, err
	}
	transportDigest := digestPostfixBytes(rendered.transport)
	tlsDigest := digestPostfixBytes(rendered.tlsPolicy)
	manifest, err := json.Marshal(struct {
		Version uint8 `json:"version"`
		Spec PostfixRelaySpec `json:"spec"`
		Domains []string `json:"domains"`
		TransportDigest string `json:"transport_digest"`
		TLSDigest string `json:"tls_digest"`
	}{Version: 1, Spec: spec, Domains: rendered.domains, TransportDigest: transportDigest, TLSDigest: tlsDigest})
	clearBytes(rendered.transport)
	clearBytes(rendered.tlsPolicy)
	if err != nil {
		return PostfixRelayGeneration{}, err
	}
	manifestDigest := digestPostfixBytes(manifest)
	generation := PostfixRelayGeneration{ID: "relay_" + manifestDigest[:48], Spec: spec, ManifestDigest: manifestDigest,
		CredentialMapReference: spec.Credential.Reference, TransportArtifactDigest: transportDigest, TLSArtifactDigest: tlsDigest}
	if generation.Validate() != nil {
		return PostfixRelayGeneration{}, ErrInvalid
	}
	return generation, nil
}

func (relay *LinuxPostfixRelay) StagePostfixRelay(ctx context.Context, generation PostfixRelayGeneration) (PostfixRelayStageReceipt, error) {
	receipt := PostfixRelayStageReceipt{GenerationID: generation.ID, StagedAt: relay.currentTime()}
	if relay == nil || relay.store == nil || ctx == nil || generation.Validate() != nil {
		return receipt, ErrInvalid
	}
	relay.mutex.Lock()
	defer relay.mutex.Unlock()
	rendered, err := relay.render(ctx, generation.Spec)
	if err != nil || digestPostfixBytes(rendered.transport) != generation.TransportArtifactDigest ||
		digestPostfixBytes(rendered.tlsPolicy) != generation.TLSArtifactDigest {
		clearRenderedPostfixRelay(&rendered)
		return receipt, errors.Join(ErrConflict, err)
	}
	secret, err := relay.secrets.ResolveSMTPAuthSecret(ctx, generation.Spec.Credential)
	if err != nil || secret.Validate() != nil {
		clearRenderedPostfixRelay(&rendered)
		if secret.Cleanup != nil {
			secret.Cleanup()
		}
		clearBytes(secret.Username)
		clearBytes(secret.Password)
		return receipt, ErrUnavailable
	}
	defer secret.Cleanup()
	defer clearBytes(secret.Username)
	defer clearBytes(secret.Password)
	var credentials bytes.Buffer
	endpoint := []byte("[" + generation.Spec.Origin.Host + "]:" + strconv.Itoa(int(generation.Spec.Origin.Port)) + " ")
	_, _ = credentials.Write(endpoint)
	_, _ = credentials.Write(secret.Username)
	_ = credentials.WriteByte(':')
	_, _ = credentials.Write(secret.Password)
	_ = credentials.WriteByte('\n')
	clearBytes(endpoint)
	credentialContent := append([]byte(nil), credentials.Bytes()...)
	clearBytes(credentials.Bytes())
	artifacts := []daemoncfg.Artifact{
		{Path: "postfix/relay_transport.map", Mode: 0440, GID: relay.postfixGID, Content: rendered.transport},
		{Path: "postfix/relay_tls_policy.map", Mode: 0440, GID: relay.postfixGID, Content: rendered.tlsPolicy},
		{Path: "postfix/relay_sasl.map", Mode: 0440, GID: relay.postfixGID, Content: credentialContent},
	}
	defer clearPostfixArtifacts(artifacts)
	receipt.StageDigest, err = daemoncfg.ComputeDigest(artifacts)
	if err != nil {
		return receipt, err
	}
	_, err = relay.store.Stage(ctx, generation.ID, receipt.StageDigest, artifacts)
	if err != nil {
		return receipt, err
	}
	return receipt, nil
}

func (relay *LinuxPostfixRelay) ValidatePostfixRelay(ctx context.Context, generation PostfixRelayGeneration, stage PostfixRelayStageReceipt) (PostfixRelayValidationReceipt, error) {
	receipt := PostfixRelayValidationReceipt{GenerationID: generation.ID, ValidatedAt: relay.currentTime()}
	if relay == nil || relay.store == nil || ctx == nil || generation.Validate() != nil || stage.GenerationID != generation.ID ||
		!validDigest(stage.StageDigest) || stage.StagedAt.IsZero() {
		return receipt, ErrInvalid
	}
	relay.mutex.Lock()
	defer relay.mutex.Unlock()
	manifest, err := relay.store.Verify(generation.ID, stage.StageDigest)
	if err != nil || manifest.GenerationID != generation.ID || manifest.Digest != stage.StageDigest {
		return receipt, errors.Join(ErrConflict, err)
	}
	output, checkErr := relay.runner.RunPostfix(ctx, PostfixCheck)
	receipt.ValidationDigest = digestPostfixEvidence(generation.ManifestDigest, stage.StageDigest, digestPostfixBytes(output), errorClass(checkErr))
	clearBytes(output)
	if checkErr != nil {
		return receipt, checkErr
	}
	return receipt, nil
}

func (relay *LinuxPostfixRelay) ActivatePostfixRelay(ctx context.Context, generation PostfixRelayGeneration, stage PostfixRelayStageReceipt, validation PostfixRelayValidationReceipt, expectedCurrent string) (PostfixRelayActivationReceipt, error) {
	receipt := PostfixRelayActivationReceipt{GenerationID: generation.ID, ActivatedAt: relay.currentTime()}
	if relay == nil || relay.store == nil || ctx == nil || generation.Validate() != nil || stage.GenerationID != generation.ID ||
		validation.GenerationID != generation.ID || !validDigest(stage.StageDigest) || !validDigest(validation.ValidationDigest) ||
		validation.ValidatedAt.Before(stage.StagedAt) || expectedCurrent != "" && !validID(expectedCurrent) {
		return receipt, ErrInvalid
	}
	relay.mutex.Lock()
	defer relay.mutex.Unlock()
	current, err := relay.store.Current()
	if err != nil || current != expectedCurrent {
		return receipt, errors.Join(ErrStale, err)
	}
	if _, err = relay.store.Verify(generation.ID, stage.StageDigest); err != nil {
		return receipt, err
	}
	previous, err := relay.store.Activate(ctx, generation.ID)
	receipt.PreviousGenerationID = previous
	receipt.ActivationDigest = digestPostfixEvidence(generation.ID, previous, errorClass(err))
	if err != nil {
		return receipt, err
	}
	checkOutput, checkErr := relay.runner.RunPostfix(ctx, PostfixCheck)
	reloadOutput, reloadErr := relay.runner.RunPostfix(ctx, PostfixReload)
	receipt.ReloadDigest = digestPostfixEvidence(digestPostfixBytes(checkOutput), digestPostfixBytes(reloadOutput), errorClass(checkErr), errorClass(reloadErr))
	clearBytes(checkOutput)
	clearBytes(reloadOutput)
	if checkErr == nil && reloadErr == nil {
		return receipt, nil
	}
	original := errors.Join(checkErr, reloadErr)
	rollbackErr := relay.store.Rollback(ctx, previous)
	rollbackCheck, rollbackCheckErr := relay.runner.RunPostfix(ctx, PostfixCheck)
	rollbackReload, rollbackReloadErr := relay.runner.RunPostfix(ctx, PostfixReload)
	observed, observedErr := relay.store.Current()
	receipt.RollbackDigest = digestPostfixEvidence(previous, observed, digestPostfixBytes(rollbackCheck), digestPostfixBytes(rollbackReload),
		errorClass(rollbackErr), errorClass(rollbackCheckErr), errorClass(rollbackReloadErr), errorClass(observedErr))
	clearBytes(rollbackCheck)
	clearBytes(rollbackReload)
	receipt.RolledBack = rollbackErr == nil && rollbackCheckErr == nil && rollbackReloadErr == nil && observedErr == nil && observed == previous
	if receipt.RolledBack {
		return receipt, original
	}
	receipt.Ambiguous = true
	return receipt, errors.Join(ErrAmbiguous, original, rollbackErr, rollbackCheckErr, rollbackReloadErr, observedErr)
}

func (relay *LinuxPostfixRelay) ObservePostfixRelay(ctx context.Context, generation PostfixRelayGeneration) (PostfixRelayObservation, error) {
	observation := PostfixRelayObservation{GenerationID: generation.ID, ObservedAt: relay.currentTime()}
	if relay == nil || relay.store == nil || ctx == nil || generation.Validate() != nil {
		return observation, ErrInvalid
	}
	relay.mutex.Lock()
	defer relay.mutex.Unlock()
	current, err := relay.store.Current()
	observation.CurrentGenerationID = current
	observation.Active = err == nil && current == generation.ID
	var checkOutput []byte
	if observation.Active && err == nil {
		checkOutput, err = relay.runner.RunPostfix(ctx, PostfixCheck)
	}
	observation.Valid = observation.Active && err == nil
	observation.EvidenceDigest = digestPostfixEvidence(generation.ID, current, generation.ManifestDigest, digestPostfixBytes(checkOutput), errorClass(err))
	clearBytes(checkOutput)
	return observation, err
}

func (relay *LinuxPostfixRelay) render(ctx context.Context, spec PostfixRelaySpec) (renderedPostfixRelay, error) {
	var rendered renderedPostfixRelay
	if spec.Validate() != nil {
		return rendered, ErrInvalid
	}
	seen := make(map[string]struct{}, len(spec.DomainIDs))
	for _, domainID := range spec.DomainIDs {
		domain, err := relay.domains.ResolvePostfixRelayDomain(ctx, spec.TenantID, domainID)
		if err != nil || !validHostname(domain) {
			return rendered, errors.Join(ErrInvalid, err)
		}
		if _, exists := seen[domain]; exists {
			return rendered, ErrConflict
		}
		seen[domain] = struct{}{}
		rendered.domains = append(rendered.domains, domain)
	}
	sort.Strings(rendered.domains)
	endpoint := "[" + spec.Origin.Host + "]:" + strconv.Itoa(int(spec.Origin.Port))
	var transport bytes.Buffer
	for _, domain := range rendered.domains {
		_, _ = fmt.Fprintf(&transport, "%s smtp:%s\n", domain, endpoint)
	}
	rendered.transport = append([]byte(nil), transport.Bytes()...)
	rendered.tlsPolicy = []byte(endpoint + " secure match=" + spec.Origin.ServerName + "\n")
	return rendered, nil
}

func (relay *LinuxPostfixRelay) currentTime() time.Time {
	if relay == nil || relay.now == nil {
		return time.Now().UTC()
	}
	return relay.now().UTC()
}

func clearRenderedPostfixRelay(rendered *renderedPostfixRelay) {
	if rendered == nil {
		return
	}
	clearBytes(rendered.transport)
	clearBytes(rendered.tlsPolicy)
	rendered.domains = nil
}

func clearPostfixArtifacts(artifacts []daemoncfg.Artifact) {
	for index := range artifacts {
		clearBytes(artifacts[index].Content)
		artifacts[index].Content = nil
	}
}

func digestPostfixBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func digestPostfixEvidence(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func errorClass(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	if errors.Is(err, ErrStale) {
		return "stale"
	}
	if errors.Is(err, ErrConflict) {
		return "conflict"
	}
	return "failed"
}

type boundedPostfixOutput struct {
	content bytes.Buffer
	maximum int
	overflow bool
}

func (output *boundedPostfixOutput) Write(content []byte) (int, error) {
	original := len(content)
	remaining := output.maximum - output.content.Len()
	if remaining <= 0 {
		output.overflow = true
		return original, nil
	}
	if len(content) > remaining {
		content = content[:remaining]
		output.overflow = true
	}
	_, _ = output.content.Write(content)
	return original, nil
}
