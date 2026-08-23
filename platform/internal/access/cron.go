package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type CronExpression struct{ value string }

func ParseCronExpression(raw string) (CronExpression, error) {
	raw = strings.TrimSpace(raw)
	switch raw {
	case "@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly":
		return CronExpression{value: raw}, nil
	}
	fields := strings.Fields(raw)
	if len(fields) != 5 { return CronExpression{}, fmt.Errorf("cron expression requires five fields") }
	limits := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	for index, field := range fields {
		if err := validateCronField(field, limits[index][0], limits[index][1]); err != nil { return CronExpression{}, fmt.Errorf("cron field %d: %w", index+1, err) }
	}
	return CronExpression{value: strings.Join(fields, " ")}, nil
}

func (expression CronExpression) String() string { return expression.value }

func (expression CronExpression) MarshalText() ([]byte, error) { return []byte(expression.value), nil }
func (expression *CronExpression) UnmarshalText(data []byte) error { parsed, err := ParseCronExpression(string(data)); if err == nil { *expression = parsed }; return err }

func validateCronField(field string, minimum, maximum int) error {
	if field == "" || len(field) > 128 { return fmt.Errorf("invalid length") }
	for _, listPart := range strings.Split(field, ",") {
		base, stepText, hasStep := strings.Cut(listPart, "/")
		if hasStep { step, err := strconv.Atoi(stepText); if err != nil || step < 1 || step > maximum-minimum+1 || strings.Contains(stepText, "/") { return fmt.Errorf("invalid step") } }
		if base == "*" { continue }
		startText, endText, hasRange := strings.Cut(base, "-")
		start, err := strconv.Atoi(startText); if err != nil || start < minimum || start > maximum { return fmt.Errorf("value out of range") }
		if hasRange { end, err := strconv.Atoi(endText); if err != nil || end < start || end > maximum || strings.Contains(endText, "-") { return fmt.Errorf("invalid range") } }
	}
	return nil
}

type InvocationKind string

const (
	InvocationProgram InvocationKind = "program"
	InvocationHTTP    InvocationKind = "http"
)

type RuntimeProgram string

const (
	ProgramPHP      RuntimeProgram = "php"
	ProgramWPCLI    RuntimeProgram = "wp_cli"
	ProgramComposer RuntimeProgram = "composer"
	ProgramNode     RuntimeProgram = "node"
	ProgramPython   RuntimeProgram = "python"
	ProgramSiteBinary RuntimeProgram = "site_binary"
)

type ProgramInvocation struct {
	Program    RuntimeProgram     `json:"program"`
	Entrypoint RelativePath       `json:"entrypoint"`
	Arguments  []string           `json:"arguments,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

func (invocation ProgramInvocation) Validate() error {
	switch invocation.Program {
	case ProgramPHP, ProgramWPCLI, ProgramComposer, ProgramNode, ProgramPython, ProgramSiteBinary:
	default: return fmt.Errorf("unsupported cron runtime program")
	}
	if invocation.Program != ProgramWPCLI && invocation.Program != ProgramComposer && invocation.Entrypoint.IsRoot() { return fmt.Errorf("cron entrypoint is required") }
	if len(invocation.Arguments) > 128 || len(invocation.Environment) > 64 { return ErrLimitExceeded }
	for _, argument := range invocation.Arguments { if len(argument) > 4096 || strings.IndexByte(argument, 0) >= 0 { return fmt.Errorf("invalid cron argument") } }
	for key, value := range invocation.Environment {
		if !validEnvironmentKey(key) || len(value) > 8192 || strings.IndexByte(value, 0) >= 0 { return fmt.Errorf("invalid cron environment") }
	}
	return nil
}

func validEnvironmentKey(value string) bool {
	if value == "" || len(value) > 128 || !(value[0] >= 'A' && value[0] <= 'Z' || value[0] == '_') { return false }
	for index := 1; index < len(value); index++ { character := value[index]; if !(character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_') { return false } }
	return true
}

type HTTPInvocation struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers,omitempty"`
	BodySecretRef string        `json:"body_secret_ref,omitempty"`
	ExpectedStatuses []int      `json:"expected_statuses,omitempty"`
}

func (invocation HTTPInvocation) Validate() error {
	parsed, err := url.ParseRequestURI(invocation.URL); if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil { return fmt.Errorf("cron HTTP target must be an HTTPS URL") }
	if invocation.Method == "" { invocation.Method = http.MethodGet }
	if invocation.Method != http.MethodGet && invocation.Method != http.MethodHead && invocation.Method != http.MethodPost { return fmt.Errorf("unsupported cron HTTP method") }
	if len(invocation.Headers) > 32 || len(invocation.ExpectedStatuses) > 32 { return ErrLimitExceeded }
	for name, value := range invocation.Headers {
		if !validHTTPHeaderName(name) || len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00") { return fmt.Errorf("invalid cron HTTP header") }
		if strings.EqualFold(name, "host") || strings.EqualFold(name, "content-length") || strings.EqualFold(name, "authorization") { return fmt.Errorf("managed HTTP header cannot be overridden") }
	}
	for _, status := range invocation.ExpectedStatuses { if status < 100 || status > 599 { return fmt.Errorf("invalid expected HTTP status") } }
	if invocation.BodySecretRef != "" && !validID(invocation.BodySecretRef) { return fmt.Errorf("invalid body secret reference") }
	return nil
}

func validHTTPHeaderName(value string) bool {
	if value == "" || len(value) > 128 { return false }
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(asciiAlphaNumeric(character) || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))) { return false }
	}
	return true
}

type CronInvocation struct {
	Kind    InvocationKind   `json:"kind"`
	Program *ProgramInvocation `json:"program,omitempty"`
	HTTP    *HTTPInvocation  `json:"http,omitempty"`
}

func (invocation CronInvocation) Validate() error {
	switch invocation.Kind {
	case InvocationProgram:
		if invocation.Program == nil || invocation.HTTP != nil { return fmt.Errorf("invalid program invocation") }
		return invocation.Program.Validate()
	case InvocationHTTP:
		if invocation.HTTP == nil || invocation.Program != nil { return fmt.Errorf("invalid HTTP invocation") }
		return invocation.HTTP.Validate()
	default:
		return fmt.Errorf("invalid cron invocation kind")
	}
}

type ConcurrencyPolicy string

const (
	ConcurrencyAllow   ConcurrencyPolicy = "allow"
	ConcurrencyForbid  ConcurrencyPolicy = "forbid"
	ConcurrencyReplace ConcurrencyPolicy = "replace"
)

type OutputPolicy string

const (
	OutputDiscard OutputPolicy = "discard"
	OutputCapture OutputPolicy = "capture"
	OutputSiteLog OutputPolicy = "site_log"
)

type CronJob struct {
	ID          CronJobID       `json:"id"`
	SiteID      SiteID          `json:"site_id"`
	Name        string          `json:"name"`
	Schedule    CronExpression  `json:"schedule"`
	Timezone    string          `json:"timezone"`
	Invocation  CronInvocation  `json:"invocation"`
	Concurrency ConcurrencyPolicy `json:"concurrency"`
	TimeoutSeconds uint32       `json:"timeout_seconds"`
	Output      OutputPolicy    `json:"output"`
	Enabled     bool            `json:"enabled"`
	State       ResourceState   `json:"state"`
	Generation  uint64          `json:"generation"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	LastRunAt   time.Time       `json:"last_run_at,omitempty"`
	LastStatus  string          `json:"last_status,omitempty"`
	ExecutorReceipt string      `json:"executor_receipt,omitempty"`
}

func (job CronJob) Validate() error {
	if err := requireID("cron job", string(job.ID)); err != nil { return err }
	if err := requireID("site", string(job.SiteID)); err != nil { return err }
	if strings.TrimSpace(job.Name) == "" || len(job.Name) > 128 || job.Schedule.String() == "" { return fmt.Errorf("invalid cron metadata") }
	if _, err := ParseCronExpression(job.Schedule.String()); err != nil { return err }
	if job.Timezone == "" { return fmt.Errorf("cron timezone is required") }
	if _, err := time.LoadLocation(job.Timezone); err != nil { return fmt.Errorf("invalid cron timezone") }
	if err := job.Invocation.Validate(); err != nil { return err }
	if job.Concurrency != ConcurrencyAllow && job.Concurrency != ConcurrencyForbid && job.Concurrency != ConcurrencyReplace { return fmt.Errorf("invalid concurrency policy") }
	if job.TimeoutSeconds < 1 || job.TimeoutSeconds > 86400 { return fmt.Errorf("invalid cron timeout") }
	if job.Output != OutputDiscard && job.Output != OutputCapture && job.Output != OutputSiteLog { return fmt.Errorf("invalid output policy") }
	if job.Generation == 0 { return ErrInvalidState }
	return nil
}

type CronApplyReceipt struct {
	SiteID     SiteID    `json:"site_id"`
	Generation uint64    `json:"generation"`
	Digest     string    `json:"digest"`
	Receipt    string    `json:"receipt"`
	AppliedAt  time.Time `json:"applied_at"`
}

type CronRun struct {
	JobID      CronJobID `json:"job_id"`
	RunID      string    `json:"run_id"`
	State      string    `json:"state"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	ExitCode   int       `json:"exit_code,omitempty"`
	OutputRef  string    `json:"output_ref,omitempty"`
}

// CronExecutor receives a complete desired site schedule and must replace the
// site user's crontab atomically. Program invocations are executed with execve,
// never through a shell.
type CronExecutor interface {
	ApplySchedule(context.Context, SiteID, uint64, []CronJob) (CronApplyReceipt, error)
	RunNow(context.Context, CronJob) (CronRun, error)
	CancelRun(context.Context, CronRun) error
}

type CronStore interface {
	CreateCron(context.Context, CronJob) error
	LoadCron(context.Context, CronJobID) (CronJob, error)
	ListCrons(context.Context, SiteID, bool) ([]CronJob, error)
	AdvanceCron(context.Context, CronJob, uint64) error
	DeleteCron(context.Context, CronJobID, uint64) error
	NextCronGeneration(context.Context, SiteID) (uint64, error)
	SaveCronReceipt(context.Context, CronApplyReceipt) error
	SaveCronRun(context.Context, CronRun) error
}

type CronService struct {
	Executor CronExecutor
	Store    CronStore
	Now      func() time.Time
}

func (service CronService) now() time.Time { if service.Now != nil { return service.Now().UTC() }; return time.Now().UTC() }
func (service CronService) require() error { if service.Executor == nil || service.Store == nil { return errors.New("cron executor and store are required") }; return nil }

func (service CronService) Create(ctx context.Context, job CronJob) (CronJob, error) {
	if err := service.require(); err != nil { return CronJob{}, err }
	now := service.now(); job.State, job.Generation, job.CreatedAt, job.UpdatedAt = StatePending, 1, now, now
	if err := job.Validate(); err != nil { return CronJob{}, err }
	if err := service.Store.CreateCron(ctx, job); err != nil { return CronJob{}, err }
	return service.activate(ctx, job)
}

func (service CronService) Update(ctx context.Context, desired CronJob, expected uint64) (CronJob, error) {
	if err := service.require(); err != nil { return CronJob{}, err }
	current, err := service.Store.LoadCron(ctx, desired.ID); if err != nil { return CronJob{}, err }
	if current.Generation != expected || desired.SiteID != current.SiteID { return CronJob{}, ErrStaleGeneration }
	desired.Generation, desired.State, desired.CreatedAt, desired.UpdatedAt = expected+1, StatePending, current.CreatedAt, service.now()
	if err = desired.Validate(); err != nil { return CronJob{}, err }
	if err = service.Store.AdvanceCron(ctx, desired, expected); err != nil { return CronJob{}, err }
	return service.activate(ctx, desired)
}

func (service CronService) activate(ctx context.Context, pending CronJob) (CronJob, error) {
	jobs, err := service.Store.ListCrons(ctx, pending.SiteID, true); if err != nil { return CronJob{}, err }
	generation, err := service.Store.NextCronGeneration(ctx, pending.SiteID); if err != nil { return CronJob{}, err }
	receipt, err := service.Executor.ApplySchedule(ctx, pending.SiteID, generation, jobs)
	previous := pending.Generation; pending.Generation++; pending.UpdatedAt = service.now()
	if err != nil { pending.State, pending.LastStatus = StateFailed, classifyError(err); _ = service.Store.AdvanceCron(ctx, pending, previous); return CronJob{}, err }
	if receipt.SiteID != pending.SiteID || receipt.Generation != generation || receipt.Digest == "" || receipt.Receipt == "" { return CronJob{}, ErrIntegrity }
	pending.State, pending.ExecutorReceipt = StateActive, receipt.Receipt
	if err = service.Store.AdvanceCron(ctx, pending, previous); err != nil { return CronJob{}, err }
	if err = service.Store.SaveCronReceipt(ctx, receipt); err != nil { return CronJob{}, err }
	return pending, nil
}

func (service CronService) Delete(ctx context.Context, id CronJobID, expected uint64) error {
	if err := service.require(); err != nil { return err }
	job, err := service.Store.LoadCron(ctx, id); if err != nil { return err }
	if job.Generation != expected { return ErrStaleGeneration }
	if err = service.Store.DeleteCron(ctx, id, expected); err != nil { return err }
	jobs, err := service.Store.ListCrons(ctx, job.SiteID, true); if err != nil { return err }
	generation, err := service.Store.NextCronGeneration(ctx, job.SiteID); if err != nil { return err }
	receipt, err := service.Executor.ApplySchedule(ctx, job.SiteID, generation, jobs); if err != nil { return err }
	return service.Store.SaveCronReceipt(ctx, receipt)
}

func (service CronService) RunNow(ctx context.Context, id CronJobID) (CronRun, error) {
	if err := service.require(); err != nil { return CronRun{}, err }
	job, err := service.Store.LoadCron(ctx, id); if err != nil { return CronRun{}, err }
	if job.State != StateActive || !job.Enabled { return CronRun{}, ErrInvalidState }
	run, err := service.Executor.RunNow(ctx, job); if err != nil { return CronRun{}, err }
	if run.JobID != id || !validID(run.RunID) || run.State == "" { return CronRun{}, ErrIntegrity }
	if err = service.Store.SaveCronRun(ctx, run); err != nil { return CronRun{}, err }
	return run, nil
}
