package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type GitProvider string

const (
	GitHub    GitProvider = "github"
	GitLab    GitProvider = "gitlab"
	Bitbucket GitProvider = "bitbucket"
	GitGeneric GitProvider = "generic"
)

type GitTransport string

const (
	GitSSH   GitTransport = "ssh"
	GitHTTPS GitTransport = "https"
)

type RemoteRepository struct {
	Transport GitTransport `json:"transport"`
	Host      string       `json:"host"`
	Port      uint16       `json:"port"`
	OwnerPath string       `json:"owner_path"`
	Name      string       `json:"name"`
}

func ParseRemoteRepository(raw string) (RemoteRepository, error) {
	if raw == "" || len(raw) > 4096 || strings.ContainsAny(raw, "\x00\r\n") { return RemoteRepository{}, fmt.Errorf("invalid Git remote") }
	if !strings.Contains(raw, "://") {
		at := strings.LastIndexByte(raw, '@'); colon := strings.IndexByte(raw, ':')
		if at < 1 || colon <= at+1 || strings.IndexByte(raw[colon+1:], ':') >= 0 { return RemoteRepository{}, fmt.Errorf("invalid SCP-style Git remote") }
		raw = "ssh://" + raw[:colon] + "/" + raw[colon+1:]
	}
	parsed, err := url.Parse(raw); if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" { return RemoteRepository{}, fmt.Errorf("invalid Git remote URL") }
	transport := GitTransport(parsed.Scheme); if transport != GitSSH && transport != GitHTTPS { return RemoteRepository{}, fmt.Errorf("unsupported Git transport") }
	if transport == GitSSH && (parsed.User == nil || parsed.User.Username() != "git" || parsed.User.String() != "git") { return RemoteRepository{}, fmt.Errorf("SSH Git remote requires the git user") }
	if transport == GitHTTPS && parsed.User != nil { return RemoteRepository{}, fmt.Errorf("HTTPS Git credentials must use a secret reference") }
	host := strings.ToLower(parsed.Hostname()); if host == "" || len(host) > 253 || strings.Contains(host, "_") { return RemoteRepository{}, fmt.Errorf("invalid Git host") }
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") { if label == "" || label[0] == '-' || label[len(label)-1] == '-' { return RemoteRepository{}, fmt.Errorf("invalid Git host") }; for index := range label { if !asciiAlphaNumeric(label[index]) && label[index] != '-' { return RemoteRepository{}, fmt.Errorf("invalid Git host") } } }
	}
	port := uint16(22); if transport == GitHTTPS { port = 443 }
	if parsed.Port() != "" { value, err := strconv.ParseUint(parsed.Port(), 10, 16); if err != nil || value == 0 { return RemoteRepository{}, fmt.Errorf("invalid Git port") }; port = uint16(value) }
	escapedPath := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if escapedPath == "" || strings.HasSuffix(escapedPath, "/") { return RemoteRepository{}, fmt.Errorf("invalid Git repository path") }
	cleaned := escapedPath
	decoded, err := url.PathUnescape(cleaned); if err != nil || decoded == "." { return RemoteRepository{}, fmt.Errorf("invalid Git repository path") }
	segments := strings.Split(decoded, "/"); if len(segments) < 2 { return RemoteRepository{}, fmt.Errorf("Git remote requires owner and repository") }
	for _, segment := range segments { if segment == "" || segment == "." || segment == ".." { return RemoteRepository{}, fmt.Errorf("invalid Git repository path") } }
	name := strings.TrimSuffix(segments[len(segments)-1], ".git"); owner := strings.Join(segments[:len(segments)-1], "/")
	if !validGitPath(owner) || !validGitName(name) { return RemoteRepository{}, fmt.Errorf("invalid Git repository path") }
	return RemoteRepository{Transport: transport, Host: host, Port: port, OwnerPath: owner, Name: name}, nil
}

func (remote RemoteRepository) URL() string {
	port := ""; defaultPort := remote.Transport == GitSSH && remote.Port == 22 || remote.Transport == GitHTTPS && remote.Port == 443
	if !defaultPort { port = ":" + strconv.Itoa(int(remote.Port)) }
	if remote.Transport == GitSSH { return "ssh://git@" + remote.Host + port + "/" + remote.OwnerPath + "/" + remote.Name + ".git" }
	return "https://" + remote.Host + port + "/" + remote.OwnerPath + "/" + remote.Name + ".git"
}

func validGitPath(value string) bool {
	if value == "" || len(value) > 2048 { return false }
	for _, segment := range strings.Split(value, "/") { if !validGitName(segment) { return false } }
	return true
}

func validGitName(value string) bool {
	if value == "" || len(value) > 255 || value == "." || value == ".." || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") { return false }
	for index := 0; index < len(value); index++ { character := value[index]; if !(asciiAlphaNumeric(character) || character == '-' || character == '_' || character == '.') { return false } }
	return true
}

type GitStrategy string

const (
	GitFastForward GitStrategy = "fast_forward_only"
	GitHardDeploy  GitStrategy = "immutable_deploy"
	GitManual      GitStrategy = "manual"
)

type GitRepository struct {
	ID          GitRepositoryID `json:"id"`
	SiteID      SiteID          `json:"site_id"`
	Provider    GitProvider      `json:"provider"`
	Remote      RemoteRepository `json:"remote"`
	CredentialRef string         `json:"credential_ref,omitempty"`
	DeployKeyID DeployKeyID     `json:"deploy_key_id,omitempty"`
	Worktree    FileLocator     `json:"worktree"`
	Branch      string          `json:"branch"`
	Strategy    GitStrategy     `json:"strategy"`
	AutoDeploy  bool            `json:"auto_deploy"`
	State       ResourceState   `json:"state"`
	Generation  uint64          `json:"generation"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	HeadRevision string         `json:"head_revision,omitempty"`
	ExecutorReceipt string      `json:"executor_receipt,omitempty"`
}

func (repository GitRepository) Validate() error {
	if err := requireID("Git repository", string(repository.ID)); err != nil { return err }
	if err := requireID("site", string(repository.SiteID)); err != nil { return err }
	if repository.Provider != GitHub && repository.Provider != GitLab && repository.Provider != Bitbucket && repository.Provider != GitGeneric { return fmt.Errorf("invalid Git provider") }
	parsed, err := ParseRemoteRepository(repository.Remote.URL()); if err != nil { return err }
	if parsed != repository.Remote { return ErrIntegrity }
	if err = repository.Worktree.Validate(); err != nil { return err }
	if repository.Worktree.Root.SiteID != repository.SiteID { return ErrUnauthorized }
	if !validGitRef(repository.Branch) { return fmt.Errorf("invalid Git branch") }
	if repository.Strategy != GitFastForward && repository.Strategy != GitHardDeploy && repository.Strategy != GitManual { return fmt.Errorf("invalid Git strategy") }
	if repository.Remote.Transport == GitSSH { if err := requireID("deploy key", string(repository.DeployKeyID)); err != nil { return err }; if repository.CredentialRef != "" { return fmt.Errorf("SSH remote cannot use HTTPS credential") } }
	if repository.Remote.Transport == GitHTTPS && repository.CredentialRef != "" && !validID(repository.CredentialRef) { return fmt.Errorf("invalid Git credential reference") }
	if repository.Generation == 0 { return ErrInvalidState }
	return nil
}

func validGitRef(value string) bool {
	if value == "" || len(value) > 255 || strings.HasPrefix(value, ".") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, ".") || strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".lock") || strings.Contains(value, "..") || strings.Contains(value, "@{") || strings.ContainsAny(value, " ~^:?*[\\\x00") { return false }
	for _, segment := range strings.Split(value, "/") { if segment == "" || strings.HasPrefix(segment, ".") { return false } }
	return true
}

func validRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 { return false }
	_, err := hex.DecodeString(value); return err == nil
}

type DeployKey struct {
	ID          DeployKeyID     `json:"id"`
	SiteID      SiteID          `json:"site_id"`
	RepositoryID GitRepositoryID `json:"repository_id"`
	Name        string          `json:"name"`
	PublicKey   PublicKey       `json:"public_key"`
	PrivateKeyRef string        `json:"private_key_ref"`
	ReadOnly    bool            `json:"read_only"`
	State       ResourceState   `json:"state"`
	Generation  uint64          `json:"generation"`
	CreatedAt   time.Time       `json:"created_at"`
	ExecutorReceipt string      `json:"executor_receipt,omitempty"`
}

func (key DeployKey) Validate() error {
	if err := requireID("deploy key", string(key.ID)); err != nil { return err }
	if err := requireID("site", string(key.SiteID)); err != nil { return err }
	if err := requireID("repository", string(key.RepositoryID)); err != nil { return err }
	if !validID(key.PrivateKeyRef) || strings.TrimSpace(key.Name) == "" || len(key.Name) > 128 { return fmt.Errorf("invalid deploy key metadata") }
	parsed, err := ParsePublicKey(key.PublicKey.AuthorizedKey()); if err != nil || parsed.Fingerprint != key.PublicKey.Fingerprint { return ErrIntegrity }
	if key.Generation == 0 { return ErrInvalidState }
	return nil
}

type WebhookEvent string

const (
	WebhookPush WebhookEvent = "push"
	WebhookTag  WebhookEvent = "tag"
	WebhookManual WebhookEvent = "manual"
)

type Webhook struct {
	ID          WebhookID       `json:"id"`
	RepositoryID GitRepositoryID `json:"repository_id"`
	Provider    GitProvider     `json:"provider"`
	SecretRef   string          `json:"secret_ref"`
	Events      []WebhookEvent  `json:"events"`
	State       ResourceState   `json:"state"`
	Generation  uint64          `json:"generation"`
	CreatedAt   time.Time       `json:"created_at"`
	LastDeliveryAt time.Time    `json:"last_delivery_at,omitempty"`
}

func (webhook Webhook) Validate() error {
	if err := requireID("webhook", string(webhook.ID)); err != nil { return err }
	if err := requireID("repository", string(webhook.RepositoryID)); err != nil { return err }
	if !validID(webhook.SecretRef) || len(webhook.Events) == 0 || len(webhook.Events) > 8 || webhook.Generation == 0 { return fmt.Errorf("invalid webhook") }
	seen := map[WebhookEvent]struct{}{}
	for _, event := range webhook.Events { if event != WebhookPush && event != WebhookTag && event != WebhookManual { return fmt.Errorf("invalid webhook event") }; if _, exists := seen[event]; exists { return fmt.Errorf("duplicate webhook event") }; seen[event] = struct{}{} }
	return nil
}

type WebhookDelivery struct {
	WebhookID WebhookID    `json:"webhook_id"`
	DeliveryID string      `json:"delivery_id"`
	Event      WebhookEvent `json:"event"`
	Signature  string      `json:"signature"`
	Body       []byte      `json:"body"`
	ReceivedAt time.Time   `json:"received_at"`
}

type DeploymentState string

const (
	DeploymentQueued     DeploymentState = "queued"
	DeploymentPreparing  DeploymentState = "preparing"
	DeploymentPrepared   DeploymentState = "prepared"
	DeploymentPromoting  DeploymentState = "promoting"
	DeploymentVerifying  DeploymentState = "verifying"
	DeploymentSucceeded  DeploymentState = "succeeded"
	DeploymentFailed     DeploymentState = "failed"
	DeploymentRollingBack DeploymentState = "rolling_back"
	DeploymentRolledBack DeploymentState = "rolled_back"
	DeploymentCancelled  DeploymentState = "cancelled"
)

type DeploymentTrigger string

const (
	TriggerManual  DeploymentTrigger = "manual"
	TriggerWebhook DeploymentTrigger = "webhook"
	TriggerSchedule DeploymentTrigger = "schedule"
)

type Deployment struct {
	ID           DeploymentID   `json:"id"`
	RepositoryID GitRepositoryID `json:"repository_id"`
	SiteID       SiteID         `json:"site_id"`
	Trigger      DeploymentTrigger `json:"trigger"`
	RequestedRevision string    `json:"requested_revision"`
	ResolvedRevision  string    `json:"resolved_revision,omitempty"`
	State        DeploymentState `json:"state"`
	Generation   uint64          `json:"generation"`
	WorkspaceToken string        `json:"workspace_token,omitempty"`
	PreviousRelease string       `json:"previous_release,omitempty"`
	HealthReceipt string         `json:"health_receipt,omitempty"`
	FailureCode string           `json:"failure_code,omitempty"`
	RequestedAt time.Time        `json:"requested_at"`
	StartedAt   time.Time        `json:"started_at,omitempty"`
	FinishedAt  time.Time        `json:"finished_at,omitempty"`
}

func (deployment Deployment) Validate() error {
	if err := requireID("deployment", string(deployment.ID)); err != nil { return err }
	if err := requireID("repository", string(deployment.RepositoryID)); err != nil { return err }
	if err := requireID("site", string(deployment.SiteID)); err != nil { return err }
	if deployment.RequestedRevision != "" && !validRevision(deployment.RequestedRevision) && !validGitRef(deployment.RequestedRevision) { return fmt.Errorf("invalid requested Git revision") }
	if deployment.Trigger != TriggerManual && deployment.Trigger != TriggerWebhook && deployment.Trigger != TriggerSchedule { return fmt.Errorf("invalid deployment trigger") }
	if deployment.State == "" || deployment.Generation == 0 || deployment.RequestedAt.IsZero() { return ErrInvalidState }
	return nil
}

func validDeploymentTransition(from, to DeploymentState) bool {
	switch from {
	case DeploymentQueued: return to == DeploymentPreparing || to == DeploymentCancelled
	case DeploymentPreparing: return to == DeploymentPrepared || to == DeploymentFailed
	case DeploymentPrepared: return to == DeploymentPromoting || to == DeploymentCancelled || to == DeploymentFailed
	case DeploymentPromoting: return to == DeploymentVerifying || to == DeploymentRollingBack || to == DeploymentFailed
	case DeploymentVerifying: return to == DeploymentSucceeded || to == DeploymentRollingBack
	case DeploymentRollingBack: return to == DeploymentRolledBack || to == DeploymentFailed
	default: return false
	}
}

type GitStatus struct {
	HeadRevision string   `json:"head_revision"`
	Branch       string   `json:"branch"`
	Ahead        uint32   `json:"ahead"`
	Behind       uint32   `json:"behind"`
	DirtyPaths   []RelativePath `json:"dirty_paths"`
}

type GitCommit struct {
	Revision  string    `json:"revision"`
	Parents   []string  `json:"parents"`
	Author    string    `json:"author"`
	Subject   string    `json:"subject"`
	CommittedAt time.Time `json:"committed_at"`
}

type GitPage struct { Commits []GitCommit `json:"commits"`; NextCursor string `json:"next_cursor,omitempty"` }

type GitChangeSet struct {
	Paths   []RelativePath `json:"paths"`
	Message string         `json:"message"`
	AuthorName string      `json:"author_name"`
	AuthorEmail string     `json:"author_email"`
}

type DeploymentPreparation struct {
	WorkspaceToken  string `json:"workspace_token"`
	ResolvedRevision string `json:"resolved_revision"`
	PreviousRelease string `json:"previous_release"`
	Receipt          string `json:"receipt"`
}

type DeploymentHealth struct {
	Healthy bool   `json:"healthy"`
	Receipt string `json:"receipt"`
	Detail  string `json:"detail,omitempty"`
}

// GitExecutor is a closed exec protocol. Implementations may invoke git only
// with argument vectors derived from these fields and never through a shell.
type GitExecutor interface {
	GenerateDeployKey(context.Context, DeployKey) (DeployKey, error)
	DeleteDeployKey(context.Context, DeployKey) error
	Attach(context.Context, GitRepository, DeployKey) (string, string, error)
	Initialize(context.Context, GitRepository) (string, error)
	Detach(context.Context, GitRepository, bool) (string, error)
	Status(context.Context, GitRepository) (GitStatus, error)
	Fetch(context.Context, GitRepository, bool) (GitStatus, error)
	Checkout(context.Context, GitRepository, string, bool) (GitStatus, error)
	Pull(context.Context, GitRepository) (GitStatus, error)
	Commit(context.Context, GitRepository, GitChangeSet) (GitCommit, error)
	Push(context.Context, GitRepository, string) (GitStatus, error)
	Log(context.Context, GitRepository, PageRequest) (GitPage, error)
	WriteIgnore(context.Context, GitRepository, []string) (string, error)
	PrepareDeployment(context.Context, GitRepository, Deployment) (DeploymentPreparation, error)
	PromoteDeployment(context.Context, GitRepository, Deployment) (string, error)
	VerifyDeployment(context.Context, GitRepository, Deployment) (DeploymentHealth, error)
	RollbackDeployment(context.Context, GitRepository, Deployment) (string, error)
	DiscardDeployment(context.Context, GitRepository, Deployment) error
}

type WebhookVerifier interface {
	Verify(context.Context, GitProvider, string, string, []byte) error
	Decode(context.Context, GitProvider, WebhookEvent, []byte) (string, string, error)
}

type DeploymentQueue interface { Enqueue(context.Context, DeploymentID) error }

type GitStore interface {
	CreateRepository(context.Context, GitRepository) error
	LoadRepository(context.Context, GitRepositoryID) (GitRepository, error)
	AdvanceRepository(context.Context, GitRepository, uint64) error
	CreateDeployKey(context.Context, DeployKey) error
	LoadDeployKey(context.Context, DeployKeyID) (DeployKey, error)
	AdvanceDeployKey(context.Context, DeployKey, uint64) error
	CreateWebhook(context.Context, Webhook) error
	LoadWebhook(context.Context, WebhookID) (Webhook, error)
	AdvanceWebhook(context.Context, Webhook, uint64) error
	ClaimWebhookDelivery(context.Context, WebhookDelivery) (bool, error)
	CreateDeployment(context.Context, Deployment) error
	LoadDeployment(context.Context, DeploymentID) (Deployment, error)
	AdvanceDeployment(context.Context, Deployment, uint64) error
}

type GitService struct {
	Executor GitExecutor
	Verifier WebhookVerifier
	Queue    DeploymentQueue
	Store    GitStore
	Now      func() time.Time
}

func (service GitService) now() time.Time { if service.Now != nil { return service.Now().UTC() }; return time.Now().UTC() }
func (service GitService) require() error { if service.Executor == nil || service.Store == nil { return errors.New("Git executor and store are required") }; return nil }

func (service GitService) Status(ctx context.Context, id GitRepositoryID) (GitStatus, error) {
	if err := service.require(); err != nil { return GitStatus{}, err }
	repository, err := service.Store.LoadRepository(ctx, id); if err != nil { return GitStatus{}, err }
	if repository.State != StateActive { return GitStatus{}, ErrInvalidState }
	return service.Executor.Status(ctx, repository)
}

func (service GitService) Fetch(ctx context.Context, id GitRepositoryID, prune bool) (GitStatus, error) {
	if err := service.require(); err != nil { return GitStatus{}, err }
	repository, err := service.Store.LoadRepository(ctx, id); if err != nil { return GitStatus{}, err }
	if repository.State != StateActive { return GitStatus{}, ErrInvalidState }
	return service.Executor.Fetch(ctx, repository, prune)
}

func (service GitService) Log(ctx context.Context, id GitRepositoryID, page PageRequest) (GitPage, error) {
	if err := service.require(); err != nil { return GitPage{}, err }
	repository, err := service.Store.LoadRepository(ctx, id); if err != nil { return GitPage{}, err }
	if repository.State != StateActive { return GitPage{}, ErrInvalidState }
	normalized, err := page.normalized(); if err != nil { return GitPage{}, err }
	return service.Executor.Log(ctx, repository, normalized)
}

func (service GitService) WriteIgnore(ctx context.Context, id GitRepositoryID, rules []string) (string, error) {
	if err := service.require(); err != nil { return "", err }
	if len(rules) > 4096 { return "", ErrLimitExceeded }
	for _, rule := range rules { if len(rule) > 4096 || strings.ContainsAny(rule, "\x00\r") { return "", fmt.Errorf("invalid gitignore rule") } }
	repository, err := service.Store.LoadRepository(ctx, id); if err != nil { return "", err }
	if repository.State != StateActive { return "", ErrInvalidState }
	return service.Executor.WriteIgnore(ctx, repository, rules)
}

func (service GitService) GenerateDeployKey(ctx context.Context, key DeployKey) (DeployKey, error) {
	if err := service.require(); err != nil { return DeployKey{}, err }
	key.State, key.Generation, key.CreatedAt = StatePending, 1, service.now()
	if err := requireID("deploy key", string(key.ID)); err != nil { return DeployKey{}, err }
	if err := requireID("site", string(key.SiteID)); err != nil { return DeployKey{}, err }
	if err := requireID("repository", string(key.RepositoryID)); err != nil { return DeployKey{}, err }
	if err := service.Store.CreateDeployKey(ctx, key); err != nil { return DeployKey{}, err }
	created, err := service.Executor.GenerateDeployKey(ctx, key)
	previous := key.Generation
	if err != nil { key.State, key.Generation = StateFailed, 2; _ = service.Store.AdvanceDeployKey(ctx, key, previous); return DeployKey{}, err }
	created.State, created.Generation, created.CreatedAt = StateActive, 2, key.CreatedAt
	if err = created.Validate(); err != nil { return DeployKey{}, err }
	if err = service.Store.AdvanceDeployKey(ctx, created, previous); err != nil { return DeployKey{}, err }
	return created, nil
}

func (service GitService) Attach(ctx context.Context, repository GitRepository) (GitRepository, error) {
	if err := service.require(); err != nil { return GitRepository{}, err }
	now := service.now(); repository.State, repository.Generation, repository.CreatedAt, repository.UpdatedAt = StatePending, 1, now, now
	if err := repository.Validate(); err != nil { return GitRepository{}, err }
	var key DeployKey
	var err error
	if repository.DeployKeyID != "" { key, err = service.Store.LoadDeployKey(ctx, repository.DeployKeyID); if err != nil { return GitRepository{}, err }; if key.State != StateActive || key.SiteID != repository.SiteID || key.RepositoryID != repository.ID { return GitRepository{}, ErrUnauthorized } }
	if err = service.Store.CreateRepository(ctx, repository); err != nil { return GitRepository{}, err }
	revision, receipt, err := service.Executor.Attach(ctx, repository, key)
	previous := repository.Generation; repository.Generation++; repository.UpdatedAt = service.now()
	if err != nil { repository.State = StateFailed; _ = service.Store.AdvanceRepository(ctx, repository, previous); return GitRepository{}, err }
	if !validRevision(revision) || receipt == "" { return GitRepository{}, ErrIntegrity }
	repository.State, repository.HeadRevision, repository.ExecutorReceipt = StateActive, revision, receipt
	if err = service.Store.AdvanceRepository(ctx, repository, previous); err != nil { return GitRepository{}, err }
	return repository, nil
}

func (service GitService) Initialize(ctx context.Context, repository GitRepository) (GitRepository, error) {
	if err := service.require(); err != nil { return GitRepository{}, err }
	now := service.now(); repository.State, repository.Generation, repository.CreatedAt, repository.UpdatedAt = StatePending, 1, now, now
	if repository.DeployKeyID == "" && repository.Remote.Host == "" {
		if err := requireID("Git repository", string(repository.ID)); err != nil { return GitRepository{}, err }
		if err := requireID("site", string(repository.SiteID)); err != nil { return GitRepository{}, err }
		if err := repository.Worktree.Validate(); err != nil { return GitRepository{}, err }
		if repository.Worktree.Root.SiteID != repository.SiteID || !validGitRef(repository.Branch) || repository.Strategy != GitFastForward && repository.Strategy != GitHardDeploy && repository.Strategy != GitManual { return GitRepository{}, fmt.Errorf("invalid local Git repository") }
	} else if err := repository.Validate(); err != nil { return GitRepository{}, err }
	if err := service.Store.CreateRepository(ctx, repository); err != nil { return GitRepository{}, err }
	receipt, err := service.Executor.Initialize(ctx, repository)
	previous := repository.Generation; repository.Generation++
	if err != nil { repository.State = StateFailed; _ = service.Store.AdvanceRepository(ctx, repository, previous); return GitRepository{}, err }
	repository.State, repository.ExecutorReceipt = StateActive, receipt
	if err = service.Store.AdvanceRepository(ctx, repository, previous); err != nil { return GitRepository{}, err }
	return repository, nil
}

func (service GitService) ChangeBranch(ctx context.Context, id GitRepositoryID, branch string, force bool) (GitRepository, GitStatus, error) {
	if !validGitRef(branch) { return GitRepository{}, GitStatus{}, fmt.Errorf("invalid Git branch") }
	repository, err := service.Store.LoadRepository(ctx, id); if err != nil { return GitRepository{}, GitStatus{}, err }
	if repository.State != StateActive { return GitRepository{}, GitStatus{}, ErrInvalidState }
	status, err := service.Executor.Checkout(ctx, repository, branch, force); if err != nil { return GitRepository{}, GitStatus{}, err }
	previous := repository.Generation; repository.Generation++; repository.Branch, repository.HeadRevision, repository.UpdatedAt = branch, status.HeadRevision, service.now()
	if err = service.Store.AdvanceRepository(ctx, repository, previous); err != nil { return GitRepository{}, GitStatus{}, err }
	return repository, status, nil
}

func (service GitService) Pull(ctx context.Context, id GitRepositoryID) (GitRepository, GitStatus, error) {
	repository, err := service.Store.LoadRepository(ctx, id); if err != nil { return GitRepository{}, GitStatus{}, err }
	if repository.State != StateActive { return GitRepository{}, GitStatus{}, ErrInvalidState }
	status, err := service.Executor.Pull(ctx, repository); if err != nil { return GitRepository{}, GitStatus{}, err }
	if !validRevision(status.HeadRevision) { return GitRepository{}, GitStatus{}, ErrIntegrity }
	previous := repository.Generation; repository.Generation++; repository.HeadRevision, repository.UpdatedAt = status.HeadRevision, service.now()
	if err = service.Store.AdvanceRepository(ctx, repository, previous); err != nil { return GitRepository{}, GitStatus{}, err }
	return repository, status, nil
}

func (service GitService) Commit(ctx context.Context, id GitRepositoryID, changes GitChangeSet) (GitCommit, error) {
	repository, err := service.Store.LoadRepository(ctx, id); if err != nil { return GitCommit{}, err }
	if repository.State != StateActive || strings.TrimSpace(changes.Message) == "" || len(changes.Message) > 4096 || len(changes.Paths) > MaxBatchPaths || len(changes.AuthorName) > 256 || len(changes.AuthorEmail) > 320 { return GitCommit{}, ErrInvalidState }
	commit, err := service.Executor.Commit(ctx, repository, changes); if err != nil { return GitCommit{}, err }
	if !validRevision(commit.Revision) { return GitCommit{}, ErrIntegrity }
	previous := repository.Generation; repository.Generation++; repository.HeadRevision, repository.UpdatedAt = commit.Revision, service.now()
	if err = service.Store.AdvanceRepository(ctx, repository, previous); err != nil { return GitCommit{}, err }
	return commit, nil
}

func (service GitService) Push(ctx context.Context, id GitRepositoryID, ref string) (GitStatus, error) {
	repository, err := service.Store.LoadRepository(ctx, id); if err != nil { return GitStatus{}, err }
	if repository.State != StateActive || !validGitRef(ref) { return GitStatus{}, ErrInvalidState }
	return service.Executor.Push(ctx, repository, ref)
}

func (service GitService) Detach(ctx context.Context, id GitRepositoryID, retainFiles bool) error {
	repository, err := service.Store.LoadRepository(ctx, id); if err != nil { return err }
	if repository.State == StateDeleted { return nil }
	if _, err = service.Executor.Detach(ctx, repository, retainFiles); err != nil { return err }
	previous := repository.Generation; repository.Generation++; repository.State, repository.UpdatedAt = StateDeleted, service.now()
	return service.Store.AdvanceRepository(ctx, repository, previous)
}

func (service GitService) RegisterWebhook(ctx context.Context, webhook Webhook) (Webhook, error) {
	webhook.State, webhook.Generation, webhook.CreatedAt = StateActive, 1, service.now()
	if err := webhook.Validate(); err != nil { return Webhook{}, err }
	repository, err := service.Store.LoadRepository(ctx, webhook.RepositoryID); if err != nil { return Webhook{}, err }
	if repository.State != StateActive || repository.Provider != webhook.Provider { return Webhook{}, ErrUnauthorized }
	if err = service.Store.CreateWebhook(ctx, webhook); err != nil { return Webhook{}, err }
	return webhook, nil
}

func (service GitService) ReceiveWebhook(ctx context.Context, delivery WebhookDelivery, deploymentID DeploymentID) (Deployment, error) {
	if service.Verifier == nil || service.Queue == nil { return Deployment{}, errors.New("webhook verifier and deployment queue are required") }
	if len(delivery.Body) == 0 || len(delivery.Body) > 10<<20 || !validID(delivery.DeliveryID) || delivery.ReceivedAt.IsZero() { return Deployment{}, fmt.Errorf("invalid webhook delivery") }
	webhook, err := service.Store.LoadWebhook(ctx, delivery.WebhookID); if err != nil { return Deployment{}, err }
	if webhook.State != StateActive || !containsWebhookEvent(webhook.Events, delivery.Event) { return Deployment{}, ErrUnauthorized }
	if err = service.Verifier.Verify(ctx, webhook.Provider, webhook.SecretRef, delivery.Signature, delivery.Body); err != nil { return Deployment{}, ErrUnauthorized }
	claimed, err := service.Store.ClaimWebhookDelivery(ctx, delivery); if err != nil { return Deployment{}, err }; if !claimed { return Deployment{}, ErrConflict }
	reference, revision, err := service.Verifier.Decode(ctx, webhook.Provider, delivery.Event, delivery.Body); if err != nil { return Deployment{}, err }
	repository, err := service.Store.LoadRepository(ctx, webhook.RepositoryID); if err != nil { return Deployment{}, err }
	if !repository.AutoDeploy || reference != repository.Branch || !validRevision(revision) { return Deployment{}, ErrUnauthorized }
	deployment := Deployment{ID: deploymentID, RepositoryID: repository.ID, SiteID: repository.SiteID, Trigger: TriggerWebhook, RequestedRevision: revision, State: DeploymentQueued, Generation: 1, RequestedAt: service.now()}
	if err = deployment.Validate(); err != nil { return Deployment{}, err }
	if err = service.Store.CreateDeployment(ctx, deployment); err != nil { return Deployment{}, err }
	if err = service.Queue.Enqueue(ctx, deployment.ID); err != nil { return Deployment{}, err }
	return deployment, nil
}

func containsWebhookEvent(events []WebhookEvent, wanted WebhookEvent) bool { for _, event := range events { if event == wanted { return true } }; return false }

func (service GitService) RequestDeployment(ctx context.Context, deployment Deployment) (Deployment, error) {
	if service.Queue == nil { return Deployment{}, errors.New("deployment queue is required") }
	deployment.State, deployment.Generation, deployment.RequestedAt = DeploymentQueued, 1, service.now()
	if err := deployment.Validate(); err != nil { return Deployment{}, err }
	repository, err := service.Store.LoadRepository(ctx, deployment.RepositoryID); if err != nil { return Deployment{}, err }
	if repository.State != StateActive || repository.SiteID != deployment.SiteID { return Deployment{}, ErrUnauthorized }
	if err = service.Store.CreateDeployment(ctx, deployment); err != nil { return Deployment{}, err }
	if err = service.Queue.Enqueue(ctx, deployment.ID); err != nil { return Deployment{}, err }
	return deployment, nil
}

func (service GitService) ExecuteDeployment(ctx context.Context, id DeploymentID) (Deployment, error) {
	if err := service.require(); err != nil { return Deployment{}, err }
	deployment, err := service.Store.LoadDeployment(ctx, id); if err != nil { return Deployment{}, err }
	if deployment.State != DeploymentQueued { return Deployment{}, ErrInvalidState }
	repository, err := service.Store.LoadRepository(ctx, deployment.RepositoryID); if err != nil { return Deployment{}, err }
	if err = service.transitionDeployment(ctx, &deployment, DeploymentPreparing); err != nil { return Deployment{}, err }
	preparation, err := service.Executor.PrepareDeployment(ctx, repository, deployment)
	if err != nil { _ = service.failDeployment(ctx, &deployment, err); return Deployment{}, err }
	if !validRevision(preparation.ResolvedRevision) || preparation.WorkspaceToken == "" || preparation.Receipt == "" { _ = service.failDeployment(ctx, &deployment, ErrIntegrity); return Deployment{}, ErrIntegrity }
	deployment.ResolvedRevision, deployment.WorkspaceToken, deployment.PreviousRelease = preparation.ResolvedRevision, preparation.WorkspaceToken, preparation.PreviousRelease
	if err = service.transitionDeployment(ctx, &deployment, DeploymentPrepared); err != nil { return Deployment{}, err }
	if err = service.transitionDeployment(ctx, &deployment, DeploymentPromoting); err != nil { return Deployment{}, err }
	if _, err = service.Executor.PromoteDeployment(ctx, repository, deployment); err != nil { return service.rollbackDeployment(ctx, repository, deployment, err) }
	if err = service.transitionDeployment(ctx, &deployment, DeploymentVerifying); err != nil { return Deployment{}, err }
	health, err := service.Executor.VerifyDeployment(ctx, repository, deployment)
	if err != nil || !health.Healthy || health.Receipt == "" { if err == nil { err = fmt.Errorf("deployment health verification failed: %s", health.Detail) }; return service.rollbackDeployment(ctx, repository, deployment, err) }
	deployment.HealthReceipt = health.Receipt
	if err = service.transitionDeployment(ctx, &deployment, DeploymentSucceeded); err != nil { return Deployment{}, err }
	previous := repository.Generation; repository.Generation++; repository.HeadRevision, repository.UpdatedAt = deployment.ResolvedRevision, service.now()
	if err = service.Store.AdvanceRepository(ctx, repository, previous); err != nil { return Deployment{}, err }
	return deployment, nil
}

func (service GitService) transitionDeployment(ctx context.Context, deployment *Deployment, next DeploymentState) error {
	if !validDeploymentTransition(deployment.State, next) { return ErrInvalidTransition }
	previous := deployment.Generation; deployment.Generation++; deployment.State = next
	if next == DeploymentPreparing { deployment.StartedAt = service.now() }
	if next == DeploymentSucceeded || next == DeploymentFailed || next == DeploymentRolledBack || next == DeploymentCancelled { deployment.FinishedAt = service.now() }
	return service.Store.AdvanceDeployment(ctx, *deployment, previous)
}

func (service GitService) failDeployment(ctx context.Context, deployment *Deployment, cause error) error {
	deployment.FailureCode = classifyError(cause)
	return service.transitionDeployment(ctx, deployment, DeploymentFailed)
}

func (service GitService) rollbackDeployment(ctx context.Context, repository GitRepository, deployment Deployment, cause error) (Deployment, error) {
	deployment.FailureCode = classifyError(cause)
	if transitionErr := service.transitionDeployment(ctx, &deployment, DeploymentRollingBack); transitionErr != nil { return Deployment{}, transitionErr }
	if _, rollbackErr := service.Executor.RollbackDeployment(ctx, repository, deployment); rollbackErr != nil { _ = service.failDeployment(ctx, &deployment, rollbackErr); return Deployment{}, errors.Join(cause, rollbackErr) }
	if transitionErr := service.transitionDeployment(ctx, &deployment, DeploymentRolledBack); transitionErr != nil { return Deployment{}, transitionErr }
	return deployment, cause
}

type SyncDirection string

const (
	SyncLiveToStaging SyncDirection = "live_to_staging"
	SyncStagingToLive SyncDirection = "staging_to_live"
)

type SyncComponent string

const (
	SyncFiles    SyncComponent = "files"
	SyncDatabase SyncComponent = "database"
	SyncUploads  SyncComponent = "uploads"
)

type PathRule struct{ value string }

func ParsePathRule(raw string) (PathRule, error) {
	if raw == "" || len(raw) > 1024 || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\\") || strings.Contains(raw, "..") || strings.IndexByte(raw, 0) >= 0 { return PathRule{}, fmt.Errorf("invalid staging path rule") }
	for _, character := range raw { if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("/_-.?*[]", character)) { return PathRule{}, fmt.Errorf("invalid staging path rule") } }
	return PathRule{value: raw}, nil
}

func (rule PathRule) String() string { return rule.value }
func (rule PathRule) MarshalText() ([]byte, error) { return []byte(rule.value), nil }
func (rule *PathRule) UnmarshalText(data []byte) error { parsed, err := ParsePathRule(string(data)); if err == nil { *rule = parsed }; return err }

type StagingSyncState string

const (
	SyncQueued      StagingSyncState = "queued"
	SyncSnapshotting StagingSyncState = "snapshotting"
	SyncApplying    StagingSyncState = "applying"
	SyncVerifying   StagingSyncState = "verifying"
	SyncPromoting   StagingSyncState = "promoting"
	SyncSucceeded   StagingSyncState = "succeeded"
	SyncRollingBack StagingSyncState = "rolling_back"
	SyncRolledBack  StagingSyncState = "rolled_back"
	SyncFailed      StagingSyncState = "failed"
)

type StagingSync struct {
	ID          StagingSyncID  `json:"id"`
	LiveSiteID  SiteID         `json:"live_site_id"`
	StagingSiteID SiteID       `json:"staging_site_id"`
	Direction   SyncDirection  `json:"direction"`
	Components  []SyncComponent `json:"components"`
	Excludes    []PathRule     `json:"excludes,omitempty"`
	DeleteExtraneous bool      `json:"delete_extraneous"`
	SourceDatabaseID string    `json:"source_database_id,omitempty"`
	TargetDatabaseID string    `json:"target_database_id,omitempty"`
	State       StagingSyncState `json:"state"`
	Generation  uint64          `json:"generation"`
	SnapshotToken string        `json:"snapshot_token,omitempty"`
	ApplyToken   string          `json:"apply_token,omitempty"`
	Receipt      string          `json:"receipt,omitempty"`
	FailureCode  string          `json:"failure_code,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	FinishedAt   time.Time       `json:"finished_at,omitempty"`
}

func (sync StagingSync) Validate() error {
	if err := requireID("staging sync", string(sync.ID)); err != nil { return err }
	if err := requireID("live site", string(sync.LiveSiteID)); err != nil { return err }
	if err := requireID("staging site", string(sync.StagingSiteID)); err != nil { return err }
	if sync.LiveSiteID == sync.StagingSiteID || sync.Direction != SyncLiveToStaging && sync.Direction != SyncStagingToLive || len(sync.Components) == 0 || len(sync.Components) > 3 || len(sync.Excludes) > 256 || sync.Generation == 0 || sync.State == "" { return fmt.Errorf("invalid staging sync") }
	seen := map[SyncComponent]struct{}{}
	for _, component := range sync.Components { if component != SyncFiles && component != SyncDatabase && component != SyncUploads { return fmt.Errorf("invalid sync component") }; if _, exists := seen[component]; exists { return fmt.Errorf("duplicate sync component") }; seen[component] = struct{}{} }
	if _, database := seen[SyncDatabase]; database { if !validID(sync.SourceDatabaseID) || !validID(sync.TargetDatabaseID) { return fmt.Errorf("database sync requires database resources") } }
	return nil
}

type SyncSnapshot struct { Token string `json:"token"`; Frontier uint64 `json:"frontier"`; Digest string `json:"digest"` }
type SyncApplication struct { Token string `json:"token"`; Digest string `json:"digest"`; Receipt string `json:"receipt"` }

type StagingExecutor interface {
	SnapshotSyncSource(context.Context, StagingSync) (SyncSnapshot, error)
	ApplyStagingSync(context.Context, StagingSync, SyncSnapshot) (SyncApplication, error)
	VerifyStagingSync(context.Context, StagingSync, SyncApplication) (string, error)
	PromoteStagingSync(context.Context, StagingSync, SyncApplication) (string, error)
	RollbackStagingSync(context.Context, StagingSync, SyncApplication) (string, error)
	ReleaseSyncSnapshot(context.Context, SyncSnapshot) error
}

type StagingStore interface {
	CreateStagingSync(context.Context, StagingSync) error
	LoadStagingSync(context.Context, StagingSyncID) (StagingSync, error)
	AdvanceStagingSync(context.Context, StagingSync, uint64) error
}

type StagingService struct { Executor StagingExecutor; Store StagingStore; Now func() time.Time }
func (service StagingService) now() time.Time { if service.Now != nil { return service.Now().UTC() }; return time.Now().UTC() }

func (service StagingService) Execute(ctx context.Context, sync StagingSync) (StagingSync, error) {
	if service.Executor == nil || service.Store == nil { return StagingSync{}, errors.New("staging executor and store are required") }
	sync.State, sync.Generation, sync.CreatedAt = SyncQueued, 1, service.now()
	if err := sync.Validate(); err != nil { return StagingSync{}, err }
	if err := service.Store.CreateStagingSync(ctx, sync); err != nil { return StagingSync{}, err }
	if err := service.transition(ctx, &sync, SyncSnapshotting); err != nil { return StagingSync{}, err }
	snapshot, err := service.Executor.SnapshotSyncSource(ctx, sync); if err != nil { return service.fail(ctx, sync, err) }
	if snapshot.Token == "" || snapshot.Digest == "" { return service.fail(ctx, sync, ErrIntegrity) }
	defer service.Executor.ReleaseSyncSnapshot(ctx, snapshot)
	sync.SnapshotToken = snapshot.Token
	if err = service.transition(ctx, &sync, SyncApplying); err != nil { return StagingSync{}, err }
	application, err := service.Executor.ApplyStagingSync(ctx, sync, snapshot); if err != nil { return service.fail(ctx, sync, err) }
	if application.Token == "" || application.Digest == "" || application.Receipt == "" { return service.fail(ctx, sync, ErrIntegrity) }
	sync.ApplyToken = application.Token
	if err = service.transition(ctx, &sync, SyncVerifying); err != nil { return StagingSync{}, err }
	verification, err := service.Executor.VerifyStagingSync(ctx, sync, application); if err != nil || verification == "" { if err == nil { err = ErrIntegrity }; return service.rollback(ctx, sync, application, err) }
	if err = service.transition(ctx, &sync, SyncPromoting); err != nil { return StagingSync{}, err }
	receipt, err := service.Executor.PromoteStagingSync(ctx, sync, application); if err != nil { return service.rollback(ctx, sync, application, err) }
	sync.Receipt = receipt
	if err = service.transition(ctx, &sync, SyncSucceeded); err != nil { return StagingSync{}, err }
	return sync, nil
}

func validSyncTransition(from, to StagingSyncState) bool {
	switch from {
	case SyncQueued: return to == SyncSnapshotting || to == SyncFailed
	case SyncSnapshotting: return to == SyncApplying || to == SyncFailed
	case SyncApplying: return to == SyncVerifying || to == SyncRollingBack || to == SyncFailed
	case SyncVerifying: return to == SyncPromoting || to == SyncRollingBack || to == SyncFailed
	case SyncPromoting: return to == SyncSucceeded || to == SyncRollingBack || to == SyncFailed
	case SyncRollingBack: return to == SyncRolledBack || to == SyncFailed
	default: return false
	}
}

func (service StagingService) transition(ctx context.Context, sync *StagingSync, next StagingSyncState) error {
	if !validSyncTransition(sync.State, next) { return ErrInvalidTransition }
	previous := sync.Generation; sync.Generation++; sync.State = next
	if next == SyncSucceeded || next == SyncRolledBack || next == SyncFailed { sync.FinishedAt = service.now() }
	return service.Store.AdvanceStagingSync(ctx, *sync, previous)
}

func (service StagingService) fail(ctx context.Context, sync StagingSync, cause error) (StagingSync, error) {
	sync.FailureCode = classifyError(cause); if err := service.transition(ctx, &sync, SyncFailed); err != nil { return StagingSync{}, err }; return sync, cause
}

func (service StagingService) rollback(ctx context.Context, sync StagingSync, application SyncApplication, cause error) (StagingSync, error) {
	sync.FailureCode = classifyError(cause); if err := service.transition(ctx, &sync, SyncRollingBack); err != nil { return StagingSync{}, err }
	receipt, err := service.Executor.RollbackStagingSync(ctx, sync, application); if err != nil { return service.fail(ctx, sync, errors.Join(cause, err)) }
	sync.Receipt = receipt; if err = service.transition(ctx, &sync, SyncRolledBack); err != nil { return StagingSync{}, err }; return sync, cause
}

func deploymentPayloadDigest(body []byte) string { digest := sha256.Sum256(body); return hex.EncodeToString(digest[:]) }
