//go:build linux

package mail

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
)

const MailConfigurationRoot = "/var/lib/cyberpanel/mail"

type LinuxMailPlatform string

const (
	MailUbuntuNoble LinuxMailPlatform = "ubuntu-noble"
	MailAlma9       LinuxMailPlatform = "alma-9"
)

type MailService string

const (
	ServicePostfix  MailService = "postfix"
	ServiceDovecot  MailService = "dovecot"
	ServiceRspamd   MailService = "rspamd"
	ServiceOpenDKIM MailService = "opendkim"
	ServiceRedis    MailService = "redis"
	ServiceClamAV   MailService = "clamav"
)

type MailServiceAction string

const (
	ServiceStart   MailServiceAction = "start"
	ServiceStop    MailServiceAction = "stop"
	ServiceRestart MailServiceAction = "restart"
	ServiceReload  MailServiceAction = "reload"
	ServiceProbe   MailServiceAction = "probe"
)

type MailQueueAction string

const (
	QueueRetry   MailQueueAction = "retry"
	QueueDelete  MailQueueAction = "delete"
	QueueHold    MailQueueAction = "hold"
	QueueRelease MailQueueAction = "release"
	QueueFlush   MailQueueAction = "flush"
)

type MailOwnership struct {
	PostfixGID  uint32 `json:"postfix_gid"`
	DovecotGID  uint32 `json:"dovecot_gid"`
	RspamdGID   uint32 `json:"rspamd_gid"`
	OpenDKIMGID uint32 `json:"opendkim_gid"`
	RedisGID    uint32 `json:"redis_gid"`
	ClamAVGID   uint32 `json:"clamav_gid"`
}

func (ownership MailOwnership) Validate() error {
	for _, gid := range []uint32{ownership.PostfixGID, ownership.DovecotGID, ownership.RspamdGID, ownership.OpenDKIMGID, ownership.RedisGID, ownership.ClamAVGID} {
		if gid == 0 {
			return ErrInvalidCommand
		}
	}
	return nil
}

type MailActivationReceipt struct {
	GenerationID       string    `json:"generation_id"`
	GenerationDigest   string    `json:"generation_digest"`
	PreviousGeneration string    `json:"previous_generation,omitempty"`
	ValidationDigest   string    `json:"validation_digest"`
	ActivationDigest   string    `json:"activation_digest"`
	ReloadDigest       string    `json:"reload_digest"`
	ProbeDigest        string    `json:"probe_digest"`
	RolledBack         bool      `json:"rolled_back"`
	RollbackDigest     string    `json:"rollback_digest,omitempty"`
	ObservedAt         time.Time `json:"observed_at"`
}
type MailServiceReceipt struct {
	Service        MailService       `json:"service"`
	Action         MailServiceAction `json:"action"`
	Active         bool              `json:"active"`
	EvidenceDigest string            `json:"evidence_digest"`
	ObservedAt     time.Time         `json:"observed_at"`
}
type MailQueueRecipient struct {
	Address     Address `json:"address"`
	DelayReason string  `json:"delay_reason,omitempty"`
}
type MailQueueRecord struct {
	ID          QueueID              `json:"id"`
	QueueName   string               `json:"queue_name"`
	Sender      Address              `json:"sender"`
	Recipients  []MailQueueRecipient `json:"recipients"`
	MessageSize uint64               `json:"message_size"`
	ArrivalTime time.Time            `json:"arrival_time"`
}
type MailQueueReceipt struct {
	Action         MailQueueAction `json:"action"`
	QueueID        QueueID         `json:"queue_id,omitempty"`
	EvidenceDigest string          `json:"evidence_digest"`
	ObservedAt     time.Time       `json:"observed_at"`
}
type mailProfile struct {
	systemctl, postfix, postqueue, postsuper, doveconf, rspamadm, opendkim, redisServer, redisCLI, clamd string
	units                                                                                                map[MailService]string
	bindings                                                                                             []mailBinding
}
type mailBinding struct{ link, target string }

func profileForMail(platform LinuxMailPlatform) (mailProfile, error) {
	base := mailProfile{systemctl: "/usr/bin/systemctl", postfix: "/usr/sbin/postfix", postqueue: "/usr/sbin/postqueue", postsuper: "/usr/sbin/postsuper", doveconf: "/usr/bin/doveconf", rspamadm: "/usr/bin/rspamadm", opendkim: "/usr/sbin/opendkim", redisServer: "/usr/bin/redis-server", redisCLI: "/usr/bin/redis-cli", clamd: "/usr/sbin/clamd", units: map[MailService]string{ServicePostfix: "postfix.service", ServiceDovecot: "dovecot.service", ServiceRspamd: "rspamd.service", ServiceOpenDKIM: "opendkim.service"}, bindings: []mailBinding{{"/etc/postfix/main.cf", MailConfigurationRoot + "/current/postfix/main.cf"}, {"/etc/postfix/master.cf", MailConfigurationRoot + "/current/postfix/master.cf"}, {"/etc/postfix/tls_sni.map", MailConfigurationRoot + "/current/postfix/tls_sni.map"}, {"/etc/dovecot/dovecot.conf", MailConfigurationRoot + "/current/dovecot/dovecot.conf"}, {"/etc/rspamd/local.d/worker-controller.inc", MailConfigurationRoot + "/current/rspamd/worker-controller.inc"}, {"/etc/rspamd/local.d/redis.conf", MailConfigurationRoot + "/current/rspamd/redis.conf"}, {"/etc/rspamd/local.d/antivirus.conf", MailConfigurationRoot + "/current/rspamd/antivirus.conf"}, {"/etc/opendkim.conf", MailConfigurationRoot + "/current/opendkim/opendkim.conf"}, {"/etc/opendkim/KeyTable", MailConfigurationRoot + "/current/opendkim/KeyTable"}, {"/etc/opendkim/SigningTable", MailConfigurationRoot + "/current/opendkim/SigningTable"}}}
	switch platform {
	case MailUbuntuNoble:
		base.units[ServiceRedis] = "redis-server@cyberpanel-mail.service"
		base.units[ServiceClamAV] = "clamav-daemon.service"
		base.bindings = append(base.bindings, mailBinding{"/etc/cyberpanel/mail/redis.conf", MailConfigurationRoot + "/current/redis/redis.conf"}, mailBinding{"/etc/clamav/clamd.conf", MailConfigurationRoot + "/current/clamav/clamd.conf"})
	case MailAlma9:
		base.units[ServiceRedis] = "redis@cyberpanel-mail.service"
		base.units[ServiceClamAV] = "clamd@cyberpanel.service"
		base.bindings = append(base.bindings, mailBinding{"/etc/cyberpanel/mail/redis.conf", MailConfigurationRoot + "/current/redis/redis.conf"}, mailBinding{"/etc/clamd.d/cyberpanel.conf", MailConfigurationRoot + "/current/clamav/clamd.conf"})
	default:
		return mailProfile{}, ErrInvalidCommand
	}
	return base, nil
}

type LinuxMailHost struct {
	Store        *daemoncfg.Store
	SiteRegistry *siteops.DurableRegistry
	Platform     LinuxMailPlatform
	Ownership    MailOwnership
	Material     MailMaterialResolver
	profile      mailProfile
	Now          func() time.Time
	serviceMu    sync.Mutex
}

func OpenLinuxMailHost(platform LinuxMailPlatform, ownership MailOwnership) (*LinuxMailHost, error) {
	material, err := NewLocalMailMaterialResolver()
	if err != nil {
		return nil, err
	}
	return OpenLinuxMailHostWithMaterial(platform, ownership, material)
}
func OpenLinuxMailHostWithMaterial(platform LinuxMailPlatform, ownership MailOwnership, material MailMaterialResolver) (*LinuxMailHost, error) {
	if err := ownership.Validate(); err != nil || material == nil {
		return nil, errors.Join(ErrInvalidCommand, err)
	}
	profile, err := profileForMail(platform)
	if err != nil {
		return nil, err
	}
	store, err := daemoncfg.OpenStore(MailConfigurationRoot, MailConfigurationRoot)
	if err != nil {
		return nil, err
	}
	return &LinuxMailHost{Store: store, Platform: platform, Ownership: ownership, Material: material, profile: profile}, nil
}
func (host *LinuxMailHost) Close() error {
	if host == nil {
		return nil
	}
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	if host.Store == nil {
		return nil
	}
	err := host.Store.Close()
	host.Store = nil
	return err
}
func (host *LinuxMailHost) now() time.Time {
	if host.Now != nil {
		return host.Now().UTC()
	}
	return time.Now().UTC()
}
func (host *LinuxMailHost) EnsureBindings(ctx context.Context) error {
	if host == nil {
		return ErrInvalidCommand
	}
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	return host.ensureBindings(ctx)
}
func (host *LinuxMailHost) ensureBindings(ctx context.Context) error {
	if host.Store == nil || ctx == nil {
		return ErrInvalidCommand
	}
	for _, binding := range host.profile.bindings {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := ensureMailBinding(binding); err != nil {
			return err
		}
	}
	return nil
}
func (host *LinuxMailHost) ObserveOrApplyMail(ctx context.Context, request EffectRequest, generation ConfigGeneration) (EffectReceipt, error) {
	effect, _, err := host.ObserveOrApplyMailWithActivation(ctx, request, generation)
	return effect, err
}
func (host *LinuxMailHost) ObserveOrApplyMailWithActivation(ctx context.Context, request EffectRequest, generation ConfigGeneration) (EffectReceipt, MailActivationReceipt, error) {
	receipt, err := host.ApplyGeneration(ctx, generation)
	effect := EffectReceipt{EffectID: request.EffectID, DesiredDigest: request.DesiredDigest, Generation: request.Generation, AppliedGeneration: receipt.GenerationDigest, ProbeDigest: receipt.ProbeDigest, ObservedAt: receipt.ObservedAt}
	if err == nil {
		effect.Outcome = EffectConfirmed
		return effect, receipt, nil
	}
	if receipt.RolledBack {
		effect.Outcome = EffectRejected
		effect.Detail = "mail generation rejected and previous generation restored"
		return effect, receipt, err
	}
	if receipt.ActivationDigest == "" && receipt.ReloadDigest == "" && receipt.ProbeDigest == "" {
		effect.Outcome = EffectRejected
		effect.Detail = "mail generation rejected before activation"
		return effect, receipt, err
	}
	effect.Outcome = EffectUnknown
	effect.Detail = "mail generation outcome requires reconciliation"
	return effect, receipt, errors.Join(ErrAmbiguous, err)
}
func (host *LinuxMailHost) ApplyGeneration(ctx context.Context, generation ConfigGeneration) (MailActivationReceipt, error) {
	receipt := MailActivationReceipt{GenerationID: generation.ID, GenerationDigest: generation.Digest, ObservedAt: time.Now().UTC()}
	if host == nil || host.Store == nil || host.Material == nil || ctx == nil {
		return receipt, ErrInvalidCommand
	}
	receipt.ObservedAt = host.now()
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	if err := host.ensureBindings(ctx); err != nil {
		return receipt, err
	}
	canonical, err := ConfigRenderer{}.Render(generation.Snapshot)
	if err != nil || !equalMailGenerations(canonical, generation) {
		return receipt, errors.Join(ErrInvalidCommand, err)
	}
	artifacts, err := host.storeArtifacts(ctx, generation)
	if err != nil {
		return receipt, err
	}
	defer wipeMailArtifacts(artifacts)
	storageDigest, err := daemoncfg.ComputeDigest(artifacts)
	if err != nil {
		return receipt, err
	}
	storeGenerationID := generation.ID + "-" + storageDigest[:16]
	receipt.GenerationID = storeGenerationID
	receipt.GenerationDigest = storageDigest
	if _, err = host.Store.Stage(ctx, storeGenerationID, storageDigest, artifacts); err != nil {
		return receipt, err
	}
	if err = host.prepareNativeConfigAccess(storeGenerationID, storageDigest); err != nil {
		return receipt, err
	}
	current, err := host.Store.Current()
	if err != nil {
		return receipt, err
	}
	receipt.PreviousGeneration = current
	if current == storeGenerationID {
		probe, probeErr := host.probeAll(ctx)
		receipt.ProbeDigest = probe
		return receipt, probeErr
	}
	previous, err := host.Store.Activate(ctx, storeGenerationID)
	receipt.ActivationDigest = digestMailEvidence(storeGenerationID, previous, errorText(err))
	if err != nil {
		return receipt, err
	}
	receipt.PreviousGeneration = previous
	validation, validationErr := host.validateGeneration(ctx, storeGenerationID)
	receipt.ValidationDigest = validation
	if validationErr != nil {
		rollbackErr := host.Store.Rollback(ctx, previous)
		rollbackProbe, rollbackProbeErr := host.probeAll(ctx)
		receipt.RollbackDigest = digestMailEvidence(rollbackProbe, errorText(rollbackErr), errorText(rollbackProbeErr), errorText(validationErr))
		receipt.RolledBack = rollbackErr == nil && rollbackProbeErr == nil
		if receipt.RolledBack {
			return receipt, validationErr
		}
		return receipt, errors.Join(ErrAmbiguous, validationErr, rollbackErr, rollbackProbeErr)
	}
	reloadDigest, reloadErr := host.reloadAll(ctx)
	receipt.ReloadDigest = reloadDigest
	probeDigest, probeErr := host.probeAll(ctx)
	receipt.ProbeDigest = probeDigest
	if reloadErr == nil && probeErr == nil {
		return receipt, nil
	}
	rollbackErr := host.Store.Rollback(ctx, previous)
	rollbackReload, rollbackReloadErr := host.reloadAll(ctx)
	rollbackProbe, rollbackProbeErr := host.probeAll(ctx)
	receipt.RollbackDigest = digestMailEvidence(rollbackReload, rollbackProbe, errorText(rollbackErr), errorText(rollbackReloadErr), errorText(rollbackProbeErr))
	receipt.RolledBack = rollbackErr == nil && rollbackReloadErr == nil && rollbackProbeErr == nil
	if receipt.RolledBack {
		return receipt, errors.Join(reloadErr, probeErr)
	}
	return receipt, errors.Join(ErrAmbiguous, reloadErr, probeErr, rollbackErr, rollbackReloadErr, rollbackProbeErr)
}
func (host *LinuxMailHost) ControlService(ctx context.Context, service MailService, action MailServiceAction) (MailServiceReceipt, error) {
	if host == nil {
		return MailServiceReceipt{}, ErrInvalidCommand
	}
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	if host.Store == nil {
		return MailServiceReceipt{}, ErrInvalidCommand
	}
	return host.controlService(ctx, service, action)
}
func (host *LinuxMailHost) controlService(ctx context.Context, service MailService, action MailServiceAction) (MailServiceReceipt, error) {
	unit, ok := host.profile.units[service]
	if !ok {
		return MailServiceReceipt{}, ErrInvalidCommand
	}
	receipt := MailServiceReceipt{Service: service, Action: action, ObservedAt: host.now()}
	if action == ServiceProbe {
		output, err := runMailProcess(ctx, host.profile.systemctl, "is-active", "--quiet", unit)
		receipt.Active = err == nil
		receipt.EvidenceDigest = digestMailEvidence(string(output), errorText(err))
		return receipt, err
	}
	verb := ""
	switch action {
	case ServiceStart:
		verb = "start"
	case ServiceStop:
		verb = "stop"
	case ServiceRestart:
		verb = "restart"
	case ServiceReload:
		verb = "reload"
	default:
		return receipt, ErrInvalidCommand
	}
	output, err := runMailProcess(ctx, host.profile.systemctl, verb, unit)
	receipt.EvidenceDigest = digestMailEvidence(string(output), errorText(err))
	if err == nil && action != ServiceStop {
		_, probeErr := runMailProcess(ctx, host.profile.systemctl, "is-active", "--quiet", unit)
		receipt.Active = probeErr == nil
		if probeErr != nil {
			err = probeErr
		}
	}
	return receipt, err
}
func (host *LinuxMailHost) Queue(ctx context.Context, action MailQueueAction, id QueueID) (MailQueueReceipt, error) {
	receipt := MailQueueReceipt{Action: action, QueueID: id, ObservedAt: time.Now().UTC()}
	if host == nil {
		return receipt, ErrInvalidCommand
	}
	receipt.ObservedAt = host.now()
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	if host.Store == nil {
		return receipt, ErrInvalidCommand
	}
	var executable string
	var arguments []string
	switch action {
	case QueueFlush:
		if id != "" {
			return receipt, ErrInvalidCommand
		}
		executable = host.profile.postqueue
		arguments = []string{"-f"}
	case QueueRetry, QueueDelete, QueueHold, QueueRelease:
		if !validPostfixQueueID(id) {
			return receipt, ErrInvalidCommand
		}
		executable = host.profile.postsuper
		flag := map[MailQueueAction]string{QueueRetry: "-r", QueueDelete: "-d", QueueHold: "-h", QueueRelease: "-H"}[action]
		arguments = []string{flag, string(id)}
	default:
		return receipt, ErrInvalidCommand
	}
	output, err := runMailProcess(ctx, executable, arguments...)
	receipt.EvidenceDigest = digestMailEvidence(string(output), errorText(err))
	return receipt, err
}
func (host *LinuxMailHost) ListQueue(ctx context.Context, limit uint32) ([]MailQueueRecord, string, error) {
	if host == nil || limit == 0 || limit > 10000 {
		return nil, "", ErrInvalidCommand
	}
	host.serviceMu.Lock()
	defer host.serviceMu.Unlock()
	if host.Store == nil {
		return nil, "", ErrInvalidCommand
	}
	output, err := runMailProcessLimit(ctx, 16<<20, host.profile.postqueue, "-j")
	if err != nil {
		return nil, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	records := make([]MailQueueRecord, 0)
	for {
		var raw struct {
			QueueID     string `json:"queue_id"`
			QueueName   string `json:"queue_name"`
			ArrivalTime int64  `json:"arrival_time"`
			MessageSize uint64 `json:"message_size"`
			Sender      string `json:"sender"`
			Recipients  []struct {
				Address     string `json:"address"`
				DelayReason string `json:"delay_reason"`
			} `json:"recipients"`
		}
		decodeErr := decoder.Decode(&raw)
		if errors.Is(decodeErr, io.EOF) {
			break
		}
		if decodeErr != nil {
			return nil, "", ErrInvalidCommand
		}
		if !validPostfixQueueID(QueueID(raw.QueueID)) || len(raw.QueueName) > 32 || raw.MessageSize > 2<<30 {
			return nil, "", ErrInvalidCommand
		}
		sender := Address(raw.Sender)
		if raw.Sender == "" {
			sender = "<>"
		} else if ValidateAddress(sender) != nil {
			return nil, "", ErrInvalidCommand
		}
		record := MailQueueRecord{ID: QueueID(raw.QueueID), QueueName: raw.QueueName, Sender: sender, MessageSize: raw.MessageSize, ArrivalTime: time.Unix(raw.ArrivalTime, 0).UTC()}
		for _, recipient := range raw.Recipients {
			address := Address(recipient.Address)
			if ValidateAddress(address) != nil || len(recipient.DelayReason) > 4096 {
				return nil, "", ErrInvalidCommand
			}
			record.Recipients = append(record.Recipients, MailQueueRecipient{Address: address, DelayReason: recipient.DelayReason})
		}
		records = append(records, record)
		if uint32(len(records)) >= limit {
			break
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, digestMailEvidence(string(output)), nil
}

func (host *LinuxMailHost) storeArtifacts(ctx context.Context, generation ConfigGeneration) ([]daemoncfg.Artifact, error) {
	result := make([]daemoncfg.Artifact, 0, len(generation.Artifacts)+len(generation.Snapshot.Domains)+1)
	for _, item := range generation.Artifacts {
		gid := uint32(0)
		switch item.Role {
		case ArtifactPostfixMain, ArtifactPostfixMaster, ArtifactPostfixTLSMap, ArtifactPostfixRelay, ArtifactPostfixRelayTLS, ArtifactPostfixStaticDomains, ArtifactPostfixStaticMailboxes, ArtifactPostfixStaticAliases:
			gid = host.Ownership.PostfixGID
		case ArtifactDovecot:
			gid = host.Ownership.DovecotGID
		case ArtifactRspamd, ArtifactRspamdRedis, ArtifactRspamdAntivirus:
			gid = host.Ownership.RspamdGID
		case ArtifactOpenDKIM, ArtifactOpenDKIMKeyTable, ArtifactOpenDKIMSigningTable, ArtifactOpenDKIMTrustedHosts:
			gid = host.Ownership.OpenDKIMGID
		case ArtifactRedis:
			gid = host.Ownership.RedisGID
		case ArtifactClamAV:
			gid = host.Ownership.ClamAVGID
		default:
			wipeMailArtifacts(result)
			return nil, ErrInvalidCommand
		}
		content := append([]byte(nil), item.Content...)
		contentDigest := item.SHA256
		if item.Role == ArtifactDovecot {
			content = bytes.ReplaceAll(content, []byte("/run/cyberpanel/mail/dovecot-users"), []byte("/var/lib/cyberpanel/mail/current/dovecot/users"))
			content = bytes.ReplaceAll(content, []byte("last_valid_uid = 299999"), []byte("last_valid_uid = 599999"))
			sum := sha256.Sum256(content)
			contentDigest = hex.EncodeToString(sum[:])
		}
		if item.Role == ArtifactClamAV && host.Platform == MailAlma9 {
			content = bytes.ReplaceAll(content, []byte("User clamav\n"), []byte("User clamscan\n"))
			sum := sha256.Sum256(content)
			contentDigest = hex.EncodeToString(sum[:])
		}
		result = append(result, daemoncfg.Artifact{Path: item.Key, Mode: item.Mode, GID: gid, Content: content, SHA256: contentDigest})
	}
	var relayCredentials bytes.Buffer
	for _, projection := range generation.Snapshot.Domains {
		dkim := projection.Domain.DKIM
		if dkim.Enabled {
			material, err := host.Material.ResolveDKIMPrivateKey(ctx, projection.Domain.Tenant, dkim.PrivateKeyRef, projection.Domain.Name, dkim.Selector)
			if err != nil {
				wipeMailArtifacts(result)
				wipeMailBytes(relayCredentials.Bytes())
				return nil, err
			}
			canonical, validationErr := validatedDKIMPrivateKey(material, dkim.PublicKey)
			wipeMailBytes(material)
			if validationErr != nil {
				wipeMailArtifacts(result)
				wipeMailBytes(relayCredentials.Bytes())
				return nil, validationErr
			}
			path := "opendkim/keys/" + projection.Domain.Name + "/" + dkim.Selector + "/private.key"
			sum := sha256.Sum256(canonical)
			result = append(result, daemoncfg.Artifact{Path: path, Mode: 0440, GID: host.Ownership.OpenDKIMGID, Content: canonical, SHA256: hex.EncodeToString(sum[:])})
		}
		relay := projection.Domain.Relay
		if relay.Host != "" {
			credential, err := host.Material.ResolveRelayCredential(ctx, projection.Domain.Tenant, relay.CredentialRef, projection.Domain.Name)
			if err != nil {
				wipeMailArtifacts(result)
				wipeMailBytes(relayCredentials.Bytes())
				return nil, err
			}
			fmt.Fprintf(&relayCredentials, "@%s %s:%s\n", projection.Domain.Name, credential.Username, credential.Password)
			credential.Wipe()
		}
	}
	relayContent := append([]byte(nil), relayCredentials.Bytes()...)
	wipeMailBytes(relayCredentials.Bytes())
	relaySum := sha256.Sum256(relayContent)
	result = append(result, daemoncfg.Artifact{Path: "postfix/relay_sasl.map", Mode: 0440, GID: host.Ownership.PostfixGID, Content: relayContent, SHA256: hex.EncodeToString(relaySum[:])})
	mailboxArtifacts, mailboxErr := host.mailboxArtifacts(ctx, generation.Snapshot)
	if mailboxErr != nil {
		wipeMailArtifacts(result)
		return nil, mailboxErr
	}
	result = append(result, mailboxArtifacts...)
	return result, nil
}
func validatedDKIMPrivateKey(material []byte, publicBinding string) ([]byte, error) {
	if len(material) == 0 || len(material) > 128<<10 {
		return nil, ErrInvalidCommand
	}
	block, remainder := pem.Decode(material)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, ErrInvalidCommand
	}
	defer wipeMailBytes(block.Bytes)
	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidCommand
		}
		privateKey = parsed
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidCommand
		}
		var ok bool
		privateKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidCommand
		}
	default:
		return nil, ErrInvalidCommand
	}
	if privateKey.Validate() != nil || privateKey.N.BitLen() < 2048 || privateKey.N.BitLen() > 8192 || privateKey.E != 65537 {
		return nil, ErrInvalidCommand
	}
	publicDER, err := decodeDKIMPublicBinding(publicBinding)
	if err != nil {
		return nil, err
	}
	defer wipeMailBytes(publicDER)
	pkcs1 := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	pkix, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, ErrInvalidCommand
	}
	if !bytes.Equal(publicDER, pkcs1) && !bytes.Equal(publicDER, pkix) {
		return nil, ErrInvalidCommand
	}
	canonical := append([]byte(nil), material...)
	if canonical[len(canonical)-1] != '\n' {
		canonical = append(canonical, '\n')
	}
	return canonical, nil
}
func decodeDKIMPublicBinding(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	encoded := value
	if strings.Contains(value, ";") {
		tags := map[string]string{}
		for _, part := range strings.Split(value, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			fields := strings.SplitN(part, "=", 2)
			if len(fields) != 2 {
				return nil, ErrInvalidCommand
			}
			key := strings.ToLower(strings.TrimSpace(fields[0]))
			entry := strings.TrimSpace(fields[1])
			if _, exists := tags[key]; exists {
				return nil, ErrInvalidCommand
			}
			switch key {
			case "v", "k", "p":
				tags[key] = entry
			default:
				return nil, ErrInvalidCommand
			}
		}
		if !strings.EqualFold(tags["v"], "DKIM1") || !strings.EqualFold(tags["k"], "rsa") || tags["p"] == "" {
			return nil, ErrInvalidCommand
		}
		encoded = tags["p"]
	}
	if encoded == "" || strings.TrimSpace(encoded) != encoded || strings.ContainsAny(encoded, " \t\r\n") {
		return nil, ErrInvalidCommand
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) < 256 || base64.StdEncoding.EncodeToString(decoded) != encoded {
		wipeMailBytes(decoded)
		return nil, ErrInvalidCommand
	}
	return decoded, nil
}
func wipeMailArtifacts(artifacts []daemoncfg.Artifact) {
	for index := range artifacts {
		wipeMailBytes(artifacts[index].Content)
	}
}
func (host *LinuxMailHost) validateGeneration(ctx context.Context, id string) (string, error) {
	root := filepath.Join(MailConfigurationRoot, "generations", id)
	commands := [][]string{{host.profile.postfix, "-c", filepath.Join(root, "postfix"), "check"}, {host.profile.doveconf, "-c", filepath.Join(root, "dovecot/dovecot.conf"), "-n"}, {host.profile.rspamadm, "configtest", "-c", filepath.Join(root, "rspamd/worker-controller.inc")}, {host.profile.rspamadm, "configtest", "-c", filepath.Join(root, "rspamd/redis.conf")}, {host.profile.rspamadm, "configtest", "-c", filepath.Join(root, "rspamd/antivirus.conf")}, {host.profile.opendkim, "-n", "-x", filepath.Join(root, "opendkim/opendkim.conf")}}
	evidence := []string{}
	for _, command := range commands {
		output, err := runMailProcess(ctx, command[0], command[1:]...)
		evidence = append(evidence, command[0], string(output), errorText(err))
		if err != nil {
			return digestMailEvidence(evidence...), err
		}
	}
	redisEvidence, err := host.validateRedisConfig(ctx, filepath.Join(root, "redis/redis.conf"))
	evidence = append(evidence, redisEvidence)
	if err != nil {
		return digestMailEvidence(evidence...), err
	}
	clamEvidence, err := validateClamAVConfig(ctx, filepath.Join(root, "clamav"))
	evidence = append(evidence, clamEvidence)
	return digestMailEvidence(evidence...), err
}
func (host *LinuxMailHost) reloadAll(ctx context.Context) (string, error) {
	evidence := []string{}
	var failures []error
	for _, service := range []MailService{ServiceRedis, ServiceClamAV, ServiceRspamd, ServiceOpenDKIM, ServiceDovecot, ServicePostfix} {
		receipt, err := host.controlService(ctx, service, ServiceReload)
		evidence = append(evidence, string(service), receipt.EvidenceDigest)
		if err != nil {
			restart, restErr := host.controlService(ctx, service, ServiceRestart)
			evidence = append(evidence, restart.EvidenceDigest)
			if restErr != nil {
				failures = append(failures, errors.Join(err, restErr))
			}
		}
	}
	return digestMailEvidence(evidence...), errors.Join(failures...)
}
func (host *LinuxMailHost) probeAll(ctx context.Context) (string, error) {
	evidence := []string{}
	var failures []error
	for _, service := range []MailService{ServiceRedis, ServiceClamAV, ServiceRspamd, ServiceOpenDKIM, ServiceDovecot, ServicePostfix} {
		receipt, err := host.controlService(ctx, service, ServiceProbe)
		evidence = append(evidence, string(service), receipt.EvidenceDigest)
		if err != nil {
			failures = append(failures, err)
		}
	}
	redisOutput, redisErr := runMailProcess(ctx, host.profile.redisCLI, "-s", "/run/cyberpanel-mail-redis/redis.sock", "PING")
	evidence = append(evidence, string(redisOutput), errorText(redisErr))
	if redisErr != nil || strings.TrimSpace(string(redisOutput)) != "PONG" {
		failures = append(failures, errors.Join(ErrInvalidReceipt, redisErr))
	}
	return digestMailEvidence(evidence...), errors.Join(failures...)
}
func equalMailGenerations(left, right ConfigGeneration) bool {
	if left.ID != right.ID || left.NodeID != right.NodeID || left.SnapshotGeneration != right.SnapshotGeneration || left.Digest != right.Digest || len(left.Artifacts) != len(right.Artifacts) {
		return false
	}
	for index := range left.Artifacts {
		a, b := left.Artifacts[index], right.Artifacts[index]
		if a.Role != b.Role || a.Key != b.Key || a.Mode != b.Mode || a.SHA256 != b.SHA256 || !bytes.Equal(a.Content, b.Content) {
			return false
		}
	}
	return true
}
func ensureMailBinding(binding mailBinding) error {
	directory := filepath.Dir(binding.link)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return ErrInvalidCommand
	}
	if metadata, ok := info.Sys().(*syscall.Stat_t); !ok || metadata.Uid != 0 {
		return ErrInvalidCommand
	}
	existing, err := os.Lstat(binding.link)
	if errors.Is(err, os.ErrNotExist) {
		return os.Symlink(binding.target, binding.link)
	}
	if err != nil {
		return err
	}
	if existing.Mode()&os.ModeSymlink == 0 {
		return ErrConflict
	}
	target, err := os.Readlink(binding.link)
	if err != nil || target != binding.target {
		return ErrConflict
	}
	return nil
}
func runMailProcess(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	return runMailProcessLimit(ctx, 1<<20, executable, arguments...)
}
func runMailProcessLimit(ctx context.Context, limit int, executable string, arguments ...string) ([]byte, error) {
	if ctx == nil || !validMailExecutable(executable) || limit < 1 || limit > 16<<20 {
		return nil, ErrInvalidCommand
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdin = nil
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output := &mailBoundedOutput{limit: limit}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if output.overflow {
		return output.buffer.Bytes(), errors.Join(ErrInvalidReceipt, err)
	}
	if err != nil {
		return output.buffer.Bytes(), fmt.Errorf("fixed mail operation failed: %w", err)
	}
	return append([]byte(nil), output.buffer.Bytes()...), nil
}
func validMailExecutable(executable string) bool {
	switch executable {
	case "/usr/bin/systemctl", "/usr/sbin/postfix", "/usr/sbin/postqueue", "/usr/sbin/postsuper", "/usr/bin/doveconf", "/usr/bin/rspamadm", "/usr/sbin/opendkim", "/usr/bin/redis-server", "/usr/bin/redis-cli", "/usr/sbin/clamd", "/usr/bin/clamconf":
		return true
	}
	return false
}

type mailBoundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (output *mailBoundedOutput) Write(value []byte) (int, error) {
	original := len(value)
	remaining := output.limit - output.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
			output.overflow = true
		}
		_, _ = output.buffer.Write(value)
	} else {
		output.overflow = true
	}
	return original, nil
}
func validPostfixQueueID(id QueueID) bool {
	if len(id) < 5 || len(id) > 32 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F' || r >= 'a' && r <= 'f' || r == '*' || r == '!') {
			return false
		}
	}
	return true
}
func digestMailEvidence(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(hash, strconv.Itoa(len(value)))
		_, _ = io.WriteString(hash, ":")
		_, _ = io.WriteString(hash, value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
