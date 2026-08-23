package access

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// SecretMaterial is short-lived caller-owned memory. It is never serializable
// and is never accepted by a persistence interface.
type SecretMaterial struct{ value []byte }

func NewSecretMaterial(value []byte) (SecretMaterial, error) {
	if len(value) < 12 || len(value) > 1024 {
		return SecretMaterial{}, fmt.Errorf("secret must contain 12 through 1024 bytes")
	}
	copyOfValue := append([]byte(nil), value...)
	return SecretMaterial{value: copyOfValue}, nil
}

func (secret SecretMaterial) bytes() []byte { return append([]byte(nil), secret.value...) }

func (secret *SecretMaterial) Destroy() {
	if secret == nil { return }
	for index := range secret.value { secret.value[index] = 0 }
	secret.value = nil
}

type FTPSPermission string

const (
	FTPSReadWrite FTPSPermission = "read_write"
	FTPSReadOnly  FTPSPermission = "read_only"
)

type FTPSAccount struct {
	ID             FTPSAccountID `json:"id"`
	SiteID         SiteID        `json:"site_id"`
	Username       string        `json:"username"`
	Root           SiteRoot      `json:"root"`
	Home           RelativePath  `json:"home"`
	Permission     FTPSPermission `json:"permission"`
	QuotaBytes     int64         `json:"quota_bytes"`
	AllowedNetworks CIDRSet      `json:"allowed_networks,omitempty"`
	TLSRequired    bool          `json:"tls_required"`
	ExpiresAt      time.Time     `json:"expires_at,omitempty"`
	State          ResourceState `json:"state"`
	Generation     uint64        `json:"generation"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	ExecutorReceipt string       `json:"executor_receipt,omitempty"`
}

func (account FTPSAccount) Validate() error {
	if err := requireID("FTPS account", string(account.ID)); err != nil { return err }
	if err := requireID("site", string(account.SiteID)); err != nil { return err }
	if err := validateLoginName(account.Username); err != nil { return err }
	if err := account.Root.Validate(); err != nil { return err }
	if account.Root.SiteID != account.SiteID { return ErrUnauthorized }
	if account.Permission != FTPSReadWrite && account.Permission != FTPSReadOnly { return fmt.Errorf("invalid FTPS permission") }
	if account.QuotaBytes < 0 || account.QuotaBytes > 1<<60 { return fmt.Errorf("invalid FTPS quota") }
	if err := account.AllowedNetworks.Validate(); err != nil { return err }
	if !account.TLSRequired { return fmt.Errorf("unencrypted FTP is not supported") }
	if account.Generation == 0 || account.State == "" { return ErrInvalidState }
	return nil
}

func validateLoginName(value string) error {
	if len(value) < 1 || len(value) > 64 || value[0] == '-' || value[0] == '.' { return fmt.Errorf("invalid login name") }
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.') { return fmt.Errorf("invalid login name") }
	}
	return nil
}

type SSHAlgorithm string

const (
	SSHED25519       SSHAlgorithm = "ssh-ed25519"
	SSHECDSAP256     SSHAlgorithm = "ecdsa-sha2-nistp256"
	SSHSecurityKeyED SSHAlgorithm = "sk-ssh-ed25519@openssh.com"
)

type PublicKey struct {
	Algorithm   SSHAlgorithm `json:"algorithm"`
	Wire        string       `json:"wire"`
	Comment     string       `json:"comment,omitempty"`
	Fingerprint string       `json:"fingerprint"`
}

func ParsePublicKey(raw string) (PublicKey, error) {
	if len(raw) > 32768 || strings.ContainsAny(raw, "\r\x00") { return PublicKey{}, fmt.Errorf("invalid SSH public key") }
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) < 2 || len(fields) > 3 { return PublicKey{}, fmt.Errorf("invalid SSH public key") }
	algorithm := SSHAlgorithm(fields[0])
	if algorithm != SSHED25519 && algorithm != SSHECDSAP256 && algorithm != SSHSecurityKeyED { return PublicKey{}, fmt.Errorf("unsupported SSH public key algorithm") }
	wire, err := base64.StdEncoding.Strict().DecodeString(fields[1]); if err != nil || len(wire) < 16 || len(wire) > 16384 { return PublicKey{}, fmt.Errorf("invalid SSH public key wire data") }
	digest := sha256.Sum256(wire)
	comment := ""; if len(fields) == 3 { comment = fields[2]; if len(comment) > 256 { return PublicKey{}, fmt.Errorf("SSH key comment too long") } }
	return PublicKey{Algorithm: algorithm, Wire: fields[1], Comment: comment, Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])}, nil
}

func (key PublicKey) AuthorizedKey() string {
	line := string(key.Algorithm) + " " + key.Wire
	if key.Comment != "" { line += " " + key.Comment }
	return line
}

type SSHKey struct {
	ID         SSHKeyID      `json:"id"`
	TenantID   TenantID      `json:"tenant_id"`
	PrincipalID PrincipalID  `json:"principal_id"`
	Name       string        `json:"name"`
	PublicKey  PublicKey     `json:"public_key"`
	State      ResourceState `json:"state"`
	Generation uint64        `json:"generation"`
	CreatedAt  time.Time     `json:"created_at"`
	LastUsedAt time.Time     `json:"last_used_at,omitempty"`
}

func (key SSHKey) Validate() error {
	if err := requireID("SSH key", string(key.ID)); err != nil { return err }
	if err := requireID("tenant", string(key.TenantID)); err != nil { return err }
	if err := requireID("principal", string(key.PrincipalID)); err != nil { return err }
	parsed, err := ParsePublicKey(key.PublicKey.AuthorizedKey()); if err != nil { return err }
	if parsed.Fingerprint != key.PublicKey.Fingerprint { return ErrIntegrity }
	if strings.TrimSpace(key.Name) == "" || len(key.Name) > 128 || key.Generation == 0 { return fmt.Errorf("invalid SSH key metadata") }
	return nil
}

type AccessProtocol string

const (
	ProtocolSFTP     AccessProtocol = "sftp"
	ProtocolSSH      AccessProtocol = "ssh"
	ProtocolTerminal AccessProtocol = "web_terminal"
)

type AccessPermission string

const (
	AccessReadOnly  AccessPermission = "read_only"
	AccessReadWrite AccessPermission = "read_write"
	AccessTerminal  AccessPermission = "terminal"
)

type AccessGrant struct {
	ID          AccessGrantID   `json:"id"`
	SiteID      SiteID          `json:"site_id"`
	TenantID    TenantID        `json:"tenant_id"`
	PrincipalID PrincipalID     `json:"principal_id"`
	SSHKeyID    SSHKeyID        `json:"ssh_key_id,omitempty"`
	Protocol    AccessProtocol  `json:"protocol"`
	Permission  AccessPermission `json:"permission"`
	Root        SiteRoot        `json:"root"`
	WorkingDirectory RelativePath `json:"working_directory"`
	AllowedNetworks CIDRSet     `json:"allowed_networks,omitempty"`
	ExpiresAt   time.Time       `json:"expires_at,omitempty"`
	State       ResourceState   `json:"state"`
	Generation  uint64          `json:"generation"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	ExecutorReceipt string      `json:"executor_receipt,omitempty"`
}

func (grant AccessGrant) Validate(now time.Time) error {
	if err := requireID("access grant", string(grant.ID)); err != nil { return err }
	if err := requireID("site", string(grant.SiteID)); err != nil { return err }
	if err := requireID("tenant", string(grant.TenantID)); err != nil { return err }
	if err := requireID("principal", string(grant.PrincipalID)); err != nil { return err }
	if err := grant.Root.Validate(); err != nil { return err }
	if grant.Root.SiteID != grant.SiteID { return ErrUnauthorized }
	if err := grant.AllowedNetworks.Validate(); err != nil { return err }
	if !grant.ExpiresAt.IsZero() && !grant.ExpiresAt.After(now) { return fmt.Errorf("access grant already expired") }
	switch grant.Protocol {
	case ProtocolSFTP, ProtocolSSH:
		if err := requireID("SSH key", string(grant.SSHKeyID)); err != nil { return err }
	case ProtocolTerminal:
		if grant.SSHKeyID != "" { return fmt.Errorf("web terminal grant cannot bind an SSH key") }
	default:
		return fmt.Errorf("invalid access protocol")
	}
	if grant.Protocol == ProtocolTerminal && grant.Permission != AccessTerminal { return fmt.Errorf("terminal grant requires terminal permission") }
	if grant.Protocol != ProtocolTerminal && grant.Permission != AccessReadOnly && grant.Permission != AccessReadWrite && grant.Permission != AccessTerminal { return fmt.Errorf("invalid access permission") }
	if grant.Generation == 0 { return ErrInvalidState }
	return nil
}

type TerminalRequest struct {
	GrantID    AccessGrantID `json:"grant_id"`
	SourceIP   string        `json:"source_ip"`
	Columns    uint16        `json:"columns"`
	Rows       uint16        `json:"rows"`
	ClientNonce string       `json:"client_nonce"`
}

type TerminalSession struct {
	ID          TerminalSessionID `json:"id"`
	GrantID     AccessGrantID     `json:"grant_id"`
	Endpoint    string            `json:"endpoint"`
	OneTimeToken string           `json:"one_time_token"`
	HostKeyFingerprint string     `json:"host_key_fingerprint"`
	IssuedAt    time.Time         `json:"issued_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	State       ResourceState     `json:"state"`
}

type CredentialExecutor interface {
	ApplyFTPSAccount(context.Context, FTPSAccount, SecretMaterial) (string, error)
	RotateFTPSPassword(context.Context, FTPSAccount, SecretMaterial) (string, error)
	SetFTPSAccountEnabled(context.Context, FTPSAccount, bool) (string, error)
	DeleteFTPSAccount(context.Context, FTPSAccount) (string, error)
	ApplySSHKey(context.Context, SSHKey) (string, error)
	RemoveSSHKey(context.Context, SSHKey) (string, error)
	ApplyAccessGrant(context.Context, AccessGrant, SSHKey) (string, error)
	RemoveAccessGrant(context.Context, AccessGrant) (string, error)
}

type TerminalBroker interface {
	Issue(context.Context, AccessGrant, TerminalRequest) (TerminalSession, error)
	Revoke(context.Context, TerminalSession) error
}

type CredentialStore interface {
	CreateFTPS(context.Context, FTPSAccount) error
	LoadFTPS(context.Context, FTPSAccountID) (FTPSAccount, error)
	AdvanceFTPS(context.Context, FTPSAccount, uint64) error
	CreateSSHKey(context.Context, SSHKey) error
	LoadSSHKey(context.Context, SSHKeyID) (SSHKey, error)
	AdvanceSSHKey(context.Context, SSHKey, uint64) error
	CreateAccessGrant(context.Context, AccessGrant) error
	LoadAccessGrant(context.Context, AccessGrantID) (AccessGrant, error)
	AdvanceAccessGrant(context.Context, AccessGrant, uint64) error
	SaveTerminalSession(context.Context, TerminalSession) error
	LoadTerminalSession(context.Context, TerminalSessionID) (TerminalSession, error)
	DeleteTerminalSession(context.Context, TerminalSessionID) error
}

type CredentialService struct {
	Executor CredentialExecutor
	Terminal TerminalBroker
	Store    CredentialStore
	Now      func() time.Time
}

func (service CredentialService) now() time.Time { if service.Now != nil { return service.Now().UTC() }; return time.Now().UTC() }

func (service CredentialService) CreateFTPS(ctx context.Context, account FTPSAccount, password *SecretMaterial) (FTPSAccount, error) {
	if service.Executor == nil || service.Store == nil || password == nil { return FTPSAccount{}, errors.New("credential executor, store, and password are required") }
	defer password.Destroy()
	now := service.now(); account.State, account.Generation, account.CreatedAt, account.UpdatedAt = StatePending, 1, now, now
	if err := account.Validate(); err != nil { return FTPSAccount{}, err }
	if err := service.Store.CreateFTPS(ctx, account); err != nil { return FTPSAccount{}, err }
	receipt, err := service.Executor.ApplyFTPSAccount(ctx, account, *password)
	previous := account.Generation; account.Generation++; account.UpdatedAt = service.now()
	if err != nil { account.State = StateFailed; _ = service.Store.AdvanceFTPS(ctx, account, previous); return FTPSAccount{}, err }
	account.State, account.ExecutorReceipt = StateActive, receipt
	if err = service.Store.AdvanceFTPS(ctx, account, previous); err != nil { return FTPSAccount{}, err }
	return account, nil
}

func (service CredentialService) RotateFTPSPassword(ctx context.Context, id FTPSAccountID, password *SecretMaterial) (FTPSAccount, error) {
	if password == nil { return FTPSAccount{}, errors.New("password is required") }; defer password.Destroy()
	account, err := service.Store.LoadFTPS(ctx, id); if err != nil { return FTPSAccount{}, err }
	if account.State != StateActive && account.State != StateDisabled { return FTPSAccount{}, ErrInvalidState }
	receipt, err := service.Executor.RotateFTPSPassword(ctx, account, *password); if err != nil { return FTPSAccount{}, err }
	previous := account.Generation; account.Generation++; account.UpdatedAt, account.ExecutorReceipt = service.now(), receipt
	if err = service.Store.AdvanceFTPS(ctx, account, previous); err != nil { return FTPSAccount{}, err }
	return account, nil
}

func (service CredentialService) SetFTPSEnabled(ctx context.Context, id FTPSAccountID, enabled bool) (FTPSAccount, error) {
	account, err := service.Store.LoadFTPS(ctx, id); if err != nil { return FTPSAccount{}, err }
	target := StateDisabled; if enabled { target = StateActive }
	if !validResourceTransition(account.State, target) { return FTPSAccount{}, ErrInvalidTransition }
	receipt, err := service.Executor.SetFTPSAccountEnabled(ctx, account, enabled); if err != nil { return FTPSAccount{}, err }
	previous := account.Generation; account.Generation++; account.State, account.UpdatedAt, account.ExecutorReceipt = target, service.now(), receipt
	if err = service.Store.AdvanceFTPS(ctx, account, previous); err != nil { return FTPSAccount{}, err }
	return account, nil
}

func (service CredentialService) DeleteFTPS(ctx context.Context, id FTPSAccountID) error {
	account, err := service.Store.LoadFTPS(ctx, id); if err != nil { return err }
	if account.State == StateDeleted { return nil }
	if account.State == StateDeleting { return ErrConflict }
	previous := account.Generation; account.Generation++; account.State, account.UpdatedAt = StateDeleting, service.now()
	if err = service.Store.AdvanceFTPS(ctx, account, previous); err != nil { return err }
	receipt, err := service.Executor.DeleteFTPSAccount(ctx, account); if err != nil { return err }
	previous = account.Generation; account.Generation++; account.State, account.UpdatedAt, account.ExecutorReceipt = StateDeleted, service.now(), receipt
	return service.Store.AdvanceFTPS(ctx, account, previous)
}

func (service CredentialService) RegisterSSHKey(ctx context.Context, key SSHKey) (SSHKey, error) {
	if service.Executor == nil || service.Store == nil { return SSHKey{}, errors.New("credential executor and store are required") }
	key.State, key.Generation, key.CreatedAt = StatePending, 1, service.now()
	if err := key.Validate(); err != nil { return SSHKey{}, err }
	if err := service.Store.CreateSSHKey(ctx, key); err != nil { return SSHKey{}, err }
	_, err := service.Executor.ApplySSHKey(ctx, key)
	previous := key.Generation; key.Generation++
	if err != nil { key.State = StateFailed; _ = service.Store.AdvanceSSHKey(ctx, key, previous); return SSHKey{}, err }
	key.State = StateActive
	if err = service.Store.AdvanceSSHKey(ctx, key, previous); err != nil { return SSHKey{}, err }
	return key, nil
}

func (service CredentialService) RevokeSSHKey(ctx context.Context, id SSHKeyID) error {
	key, err := service.Store.LoadSSHKey(ctx, id); if err != nil { return err }
	if key.State == StateDeleted { return nil }
	if _, err = service.Executor.RemoveSSHKey(ctx, key); err != nil { return err }
	previous := key.Generation; key.Generation++; key.State = StateDeleted
	return service.Store.AdvanceSSHKey(ctx, key, previous)
}

func (service CredentialService) Grant(ctx context.Context, grant AccessGrant) (AccessGrant, error) {
	if service.Executor == nil || service.Store == nil { return AccessGrant{}, errors.New("credential executor and store are required") }
	now := service.now(); grant.State, grant.Generation, grant.CreatedAt, grant.UpdatedAt = StatePending, 1, now, now
	if err := grant.Validate(now); err != nil { return AccessGrant{}, err }
	var key SSHKey
	var err error
	if grant.SSHKeyID != "" { key, err = service.Store.LoadSSHKey(ctx, grant.SSHKeyID); if err != nil { return AccessGrant{}, err }; if key.State != StateActive || key.TenantID != grant.TenantID || key.PrincipalID != grant.PrincipalID { return AccessGrant{}, ErrUnauthorized } }
	if err = service.Store.CreateAccessGrant(ctx, grant); err != nil { return AccessGrant{}, err }
	receipt, err := service.Executor.ApplyAccessGrant(ctx, grant, key)
	previous := grant.Generation; grant.Generation++; grant.UpdatedAt = service.now()
	if err != nil { grant.State = StateFailed; _ = service.Store.AdvanceAccessGrant(ctx, grant, previous); return AccessGrant{}, err }
	grant.State, grant.ExecutorReceipt = StateActive, receipt
	if err = service.Store.AdvanceAccessGrant(ctx, grant, previous); err != nil { return AccessGrant{}, err }
	return grant, nil
}

func (service CredentialService) RevokeGrant(ctx context.Context, id AccessGrantID) error {
	grant, err := service.Store.LoadAccessGrant(ctx, id); if err != nil { return err }
	if grant.State == StateDeleted { return nil }
	if _, err = service.Executor.RemoveAccessGrant(ctx, grant); err != nil { return err }
	previous := grant.Generation; grant.Generation++; grant.State, grant.UpdatedAt = StateDeleted, service.now()
	return service.Store.AdvanceAccessGrant(ctx, grant, previous)
}

func (service CredentialService) OpenTerminal(ctx context.Context, request TerminalRequest) (TerminalSession, error) {
	if service.Terminal == nil || service.Store == nil { return TerminalSession{}, errors.New("terminal broker and store are required") }
	grant, err := service.Store.LoadAccessGrant(ctx, request.GrantID); if err != nil { return TerminalSession{}, err }
	if grant.State != StateActive || grant.Protocol != ProtocolTerminal || !grant.ExpiresAt.IsZero() && !grant.ExpiresAt.After(service.now()) { return TerminalSession{}, ErrUnauthorized }
	if request.Columns < 20 || request.Columns > 500 || request.Rows < 5 || request.Rows > 300 || len(request.ClientNonce) < 16 || len(request.ClientNonce) > 256 { return TerminalSession{}, fmt.Errorf("invalid terminal request") }
	if !sourceAllowed(request.SourceIP, grant.AllowedNetworks) { return TerminalSession{}, ErrUnauthorized }
	session, err := service.Terminal.Issue(ctx, grant, request); if err != nil { return TerminalSession{}, err }
	if err = validateTerminalSession(session, grant.ID, service.now()); err != nil { _ = service.Terminal.Revoke(ctx, session); return TerminalSession{}, err }
	if err = service.Store.SaveTerminalSession(ctx, session); err != nil { _ = service.Terminal.Revoke(ctx, session); return TerminalSession{}, err }
	return session, nil
}

func (service CredentialService) CloseTerminal(ctx context.Context, id TerminalSessionID) error {
	session, err := service.Store.LoadTerminalSession(ctx, id); if err != nil { return err }
	if err = service.Terminal.Revoke(ctx, session); err != nil { return err }
	return service.Store.DeleteTerminalSession(ctx, id)
}

func validateTerminalSession(session TerminalSession, grant AccessGrantID, now time.Time) error {
	if err := requireID("terminal session", string(session.ID)); err != nil { return err }
	if session.GrantID != grant || session.Endpoint == "" || len(session.Endpoint) > 2048 || len(session.OneTimeToken) < 32 || len(session.OneTimeToken) > 8192 || session.HostKeyFingerprint == "" { return ErrIntegrity }
	if session.IssuedAt.After(now.Add(time.Minute)) || !session.ExpiresAt.After(now) || session.ExpiresAt.After(now.Add(15*time.Minute)) || session.State != StateActive { return ErrIntegrity }
	return nil
}

func sourceAllowed(rawIP string, networks CIDRSet) bool {
	if len(networks) == 0 { return true }
	ip := net.ParseIP(rawIP); if ip == nil { return false }
	for _, raw := range networks { _, network, _ := net.ParseCIDR(raw); if network != nil && network.Contains(ip) { return true } }
	return false
}
