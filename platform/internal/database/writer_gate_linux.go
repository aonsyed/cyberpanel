//go:build linux

package database

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

const (
	writerGateJournal           = "ha-writer-gate.json"
	writerFenceConfiguration    = "[mysqld]\nread_only=ON\n"
	writerFenceUbuntuConfigPath = "/etc/mysql/mariadb.conf.d/91-cyberpanel-ha-fence.cnf"
	writerFenceAlmaConfigPath   = "/etc/my.cnf.d/91-cyberpanel-ha-fence.cnf"
)

type mariaDBWriterGate struct {
	mu         sync.Mutex
	transition sync.Mutex
	managed    bool
	open       bool
	safe       bool
	supervised bool
	serial     uint64
	next       uint64
	active     *DatabaseWriterTransfer
	running    map[uint64]context.CancelFunc
}

type writerGateReceipt struct {
	State             string                  `json:"state"`
	Reason            string                  `json:"reason"`
	Transfer          *DatabaseWriterTransfer `json:"transfer,omitempty"`
	ObservationDigest string                  `json:"observation_digest,omitempty"`
	SessionPolicy     string                  `json:"session_policy"`
	ObservedAt        time.Time               `json:"observed_at"`
}

type writerActivationCursor struct {
	FencingToken  uint64 `json:"fencing_token"`
	CertificateID string `json:"certificate_id"`
}

type writerCandidateEvidenceRecord struct {
	RequestDigest      string                    `json:"request_digest"`
	SourceFenceReceipt json.RawMessage           `json:"source_fence_receipt"`
	Certificate        DatabaseWriterCertificate `json:"certificate"`
}

type writerFenceEvidenceRecord struct {
	RequestDigest string                      `json:"request_digest"`
	Evidence      DatabaseWriterFenceEvidence `json:"evidence"`
}

// sqlMaintenanceCapability is private and issued only after closed replication
// authority validation. It cannot carry arbitrary SQL or authorize promotion.
type sqlMaintenanceCapability struct{}
type writerFenceCapability struct{}
type writerAuditCapability struct{}
type writerActivationCapability struct{ Serial uint64 }
type writerActivationContextKey struct{}

func (executor *LinuxMariaDBExecutor) initializeWriterGate() error {
	executor.writer.running = make(map[uint64]context.CancelFunc)
	_, deploymentErr := os.Lstat("/etc/cyberpanel/ha/federated-ingress.json")
	var prior writerGateReceipt
	journalErr := executor.readNamed("effects", writerGateJournal, &prior)
	var fence localMariaDBHAReceipt
	fenceErr := executor.readNamed("effects", "ha-fence-cursor.json", &fence)
	if errors.Is(deploymentErr, os.ErrNotExist) && errors.Is(journalErr, ErrNotFound) && errors.Is(fenceErr, ErrNotFound) {
		return nil
	}
	// Existing or unreadable authority state latches HA mode. Neither restart
	// nor deletion of the signed deployment can implicitly restore writes.
	if err := executor.latchWriterGate("startup_requires_new_activation"); err != nil {
		shutdown, shutdownCancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer shutdownCancel()
		_, stopErr := writerSystemctl(shutdown, "stop")
		_, killErr := writerSystemctl(shutdown, "kill")
		return errors.Join(err, stopErr, killErr)
	}
	startup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := executor.enforceWriterFence(startup, "startup_requires_new_activation", nil); err != nil {
		shutdown, shutdownCancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer shutdownCancel()
		_, stopErr := writerSystemctl(shutdown, "stop")
		_, killErr := writerSystemctl(shutdown, "kill")
		return errors.Join(err, stopErr, killErr)
	}
	return nil
}

func (executor *LinuxMariaDBExecutor) latchWriterGate(reason string) error {
	executor.writer.mu.Lock()
	executor.writer.managed = true
	executor.writer.open = false
	executor.writer.safe = false
	executor.writer.active = nil
	executor.writer.serial++
	for _, cancel := range executor.writer.running {
		cancel()
	}
	executor.writer.mu.Unlock()
	// A MariaDB restart must also come up read-only before panel-execd polls.
	journalErr := executor.writeNamed("effects", writerGateJournal, writerGateReceipt{State: "closed_pending_observation", Reason: reason, SessionPolicy: "broker-deny; privileged-session-sweep; no-super-read-only", ObservedAt: executor.now().UTC()})
	return errors.Join(journalErr, atomicRootFile(executor.writerFenceConfigPath(), []byte(writerFenceConfiguration), 0644))
}

func (executor *LinuxMariaDBExecutor) writerFenceConfigPath() string {
	if executor != nil && executor.distribution == LinuxMariaDBAlma {
		return writerFenceAlmaConfigPath
	}
	return writerFenceUbuntuConfigPath
}

func verifyWriterFenceConfig(path string) error {
	if path != writerFenceUbuntuConfigPath && path != writerFenceAlmaConfigPath {
		return ErrUnauthorized
	}
	actual, present, err := readManagedConfig(path)
	if err != nil || !present || string(actual) != writerFenceConfiguration {
		return ErrUnauthorized
	}
	return nil
}

// beginWriterMutation guards the entire effect, including host configuration,
// service operations and scoped restore subprocesses, not just root SQL.
func (executor *LinuxMariaDBExecutor) beginWriterMutation(ctx context.Context) (context.Context, func(), error) {
	if executor == nil || ctx == nil {
		return ctx, func() {}, ErrUnauthorized
	}
	executor.writer.mu.Lock()
	managed, active, serial, open := executor.writer.managed, executor.writer.active, executor.writer.serial, executor.writer.open
	executor.writer.mu.Unlock()
	if !managed {
		if _, err := os.Lstat("/etc/cyberpanel/ha/federated-ingress.json"); errors.Is(err, os.ErrNotExist) {
			return ctx, func() {}, nil
		}
		_ = executor.latchWriterGate("new_ha_deployment")
		return ctx, func() {}, ErrUnauthorized
	}
	if !open || active == nil || executor.verifyActiveTransfer(ctx, *active) != nil {
		return ctx, func() {}, ErrUnauthorized
	}
	executor.writer.mu.Lock()
	defer executor.writer.mu.Unlock()
	if !executor.writer.open || executor.writer.serial != serial || !executor.now().Before(active.Certificate.ExpiresAt) {
		return ctx, func() {}, ErrUnauthorized
	}
	bounded, cancel := context.WithDeadline(ctx, active.Certificate.ExpiresAt)
	executor.writer.next++
	id := executor.writer.next
	executor.writer.running[id] = cancel
	return bounded, func() {
		cancel()
		executor.writer.mu.Lock()
		delete(executor.writer.running, id)
		executor.writer.mu.Unlock()
	}, nil
}

func (executor *LinuxMariaDBExecutor) verifyWriterTransferLocal(ctx context.Context, transfer DatabaseWriterTransfer) (json.RawMessage, error) {
	certificate := transfer.Certificate
	if !validSHA256(transfer.PostFenceCommitProof) || !validDatabaseWriterCertificate(certificate, executor.now().UTC()) || verifyWriterFenceConfig(executor.writerFenceConfigPath()) != nil {
		return nil, ErrUnauthorized
	}
	raw, err := databaseWriterTransferJSON(transfer)
	if err != nil {
		return nil, ErrUnauthorized
	}
	bounded, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	if err := executor.verifyWriterSupervisor(bounded); err != nil {
		return nil, ErrUnauthorized
	}
	return raw, nil
}

func (executor *LinuxMariaDBExecutor) verifyActiveTransfer(ctx context.Context, transfer DatabaseWriterTransfer) error {
	if executor.VerifyWriterTransferJSON == nil {
		return ErrUnauthorized
	}
	raw, err := executor.verifyWriterTransferLocal(ctx, transfer)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	if err = executor.VerifyWriterTransferJSON(bounded, raw); err != nil || bounded.Err() != nil {
		return ErrUnauthorized
	}
	return nil
}

// admitWriterTransfer performs the one-shot HA consumption only after every
// local prerequisite and durable activation intent is in place. It is never
// used by the watchdog; ambiguous admission therefore remains closed.
func (executor *LinuxMariaDBExecutor) admitWriterTransfer(ctx context.Context, transfer DatabaseWriterTransfer) error {
	if executor.AdmitWriterTransferJSON == nil {
		return ErrUnauthorized
	}
	raw, err := databaseWriterTransferJSON(transfer)
	if err != nil {
		return ErrUnauthorized
	}
	bounded, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	if err = executor.AdmitWriterTransferJSON(bounded, raw); err != nil || bounded.Err() != nil {
		return ErrUnauthorized
	}
	return nil
}

func (executor *LinuxMariaDBExecutor) guardRootSQL(ctx context.Context, statement mariaDBStatement) (context.Context, func(), error) {
	switch statement {
	case sqlObserveStatus, sqlObserveDatabase, sqlObservePrincipal, sqlObserveGrants, sqlObserveTuning, sqlObserveHA, sqlObserveNativePrincipal:
		return ctx, func() {}, nil
	case sqlWriterSessionAudit, sqlWriterSessions:
		fence, _ := ctx.Value(writerFenceCapability{}).(bool)
		audit, _ := ctx.Value(writerAuditCapability{}).(bool)
		if fence || audit {
			return ctx, func() {}, nil
		}
	case sqlFreezeHA, sqlKillWriterSession:
		if allowed, _ := ctx.Value(writerFenceCapability{}).(bool); allowed {
			return ctx, func() {}, nil
		}
	case sqlObserveReplication, sqlObserveReplicationPrincipal, sqlWaitReplication, sqlStableGTIDCheckpoint, sqlCreateReplicationPrincipal, sqlConfigureReplication, sqlStopWriterReplication:
		if allowed, _ := ctx.Value(sqlMaintenanceCapability{}).(bool); allowed {
			return ctx, func() {}, nil
		}
	case sqlPromoteHA:
		capability, ok := ctx.Value(writerActivationContextKey{}).(writerActivationCapability)
		executor.writer.mu.Lock()
		defer executor.writer.mu.Unlock()
		if !ok || executor.writer.active == nil || executor.writer.serial != capability.Serial || !executor.now().Before(executor.writer.active.Certificate.ExpiresAt) {
			return ctx, func() {}, ErrUnauthorized
		}
		bounded, cancel := context.WithDeadline(ctx, executor.writer.active.Certificate.ExpiresAt)
		executor.writer.next++
		id := executor.writer.next
		executor.writer.running[id] = cancel
		return bounded, func() {
			cancel()
			executor.writer.mu.Lock()
			delete(executor.writer.running, id)
			executor.writer.mu.Unlock()
		}, nil
	}
	return executor.beginWriterMutation(ctx)
}

// StartWriterWatchdog never restores a lease from disk. Failure to reach MariaDB
// is recorded as unsafe, not as a successful fence. The loop is independent of
// the effect mutex so a long-running mutation cannot starve lease enforcement.
func (executor *LinuxMariaDBExecutor) StartWriterWatchdog(ctx context.Context) error {
	if executor == nil || ctx == nil {
		return ErrInvalidCommand
	}
	err := executor.writerWatchdogTick(ctx)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				_ = executor.closeWriterGate(shutdown, "daemon_shutdown")
				cancel()
				return
			case <-ticker.C:
				_ = executor.writerWatchdogTick(ctx)
			}
		}
	}()
	return err
}

// ShutdownWriterGate is synchronous. Merely canceling the watchdog goroutine
// and exiting would leave MariaDB writable until an independent supervisor acts.
func (executor *LinuxMariaDBExecutor) ShutdownWriterGate(ctx context.Context) error {
	return executor.closeWriterGate(ctx, "daemon_shutdown")
}

func (executor *LinuxMariaDBExecutor) writerWatchdogTick(ctx context.Context) error {
	// A transition owns the only bounded window in which read_only may change.
	// Do not refresh its heartbeat: if it hangs, the independent supervisor
	// expires the previous heartbeat and stops MariaDB. Do not race it either.
	if !executor.writer.transition.TryLock() {
		return nil
	}
	defer executor.writer.transition.Unlock()
	executor.writer.mu.Lock()
	managed, active, open := executor.writer.managed, executor.writer.active, executor.writer.open
	executor.writer.mu.Unlock()
	var latchErr error
	if !managed {
		if _, err := os.Lstat("/etc/cyberpanel/ha/federated-ingress.json"); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		latchErr = executor.latchWriterGate("new_ha_deployment")
	}
	if active != nil && open && executor.verifyActiveTransfer(ctx, *active) == nil {
		return executor.publishWriterHeartbeat()
	}
	fenceErr := executor.closeWriterGateUnderTransition(ctx, "lease_expired_revoked_or_authority_unavailable")
	executor.writer.mu.Lock()
	supervised := executor.writer.supervised
	executor.writer.mu.Unlock()
	if !supervised {
		installErr := executor.installWriterSupervisor(ctx)
		if installErr != nil {
			// If the independent dependency cannot be installed or armed, do not
			// rely on the in-process fence surviving this daemon's exit.
			_, stopErr := writerSystemctl(ctx, "stop")
			_, killErr := writerSystemctl(ctx, "kill")
			return errors.Join(latchErr, fenceErr, installErr, stopErr, killErr)
		}
		return errors.Join(latchErr, fenceErr)
	}
	if fenceErr != nil {
		return errors.Join(latchErr, fenceErr)
	}
	return errors.Join(latchErr, executor.publishWriterHeartbeat())
}

func (executor *LinuxMariaDBExecutor) closeWriterGate(ctx context.Context, reason string) error {
	executor.writer.transition.Lock()
	defer executor.writer.transition.Unlock()
	return executor.closeWriterGateUnderTransition(ctx, reason)
}

// closeWriterGateUnderTransition requires transition to be held. Keeping the
// lock from the watchdog's TryLock through the physical fence prevents a new
// activation from slipping between the liveness decision and SET read_only.
func (executor *LinuxMariaDBExecutor) closeWriterGateUnderTransition(ctx context.Context, reason string) error {
	executor.writer.mu.Lock()
	if !executor.writer.managed {
		executor.writer.mu.Unlock()
		return nil
	}
	transfer := executor.writer.active
	executor.writer.open = false
	executor.writer.safe = false
	executor.writer.active = nil
	executor.writer.serial++
	for _, cancel := range executor.writer.running {
		cancel()
	}
	executor.writer.mu.Unlock()
	return executor.enforceWriterFence(ctx, reason, transfer)
}

func (executor *LinuxMariaDBExecutor) enforceWriterFence(ctx context.Context, reason string, transfer *DatabaseWriterTransfer) error {
	receipt := writerGateReceipt{State: "closed_pending_observation", Reason: reason, Transfer: transfer, SessionPolicy: "broker-deny; root-unix-socket-only; privileged-session-sweep; no-super-read-only", ObservedAt: executor.now().UTC()}
	journalErr := executor.writeNamed("effects", writerGateJournal, receipt)
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	fenceContext := context.WithValue(bounded, writerFenceCapability{}, true)
	connection := executor.localWriterConnection()
	// Privileged transactions can block SET GLOBAL read_only. Kill those
	// sessions first, then force the flag and prove absence again below.
	before, beforeErr := connection.query(fenceContext, sqlWriterSessions)
	if beforeErr == nil {
		lines := strings.Fields(string(before))
		if len(lines) > 256 {
			beforeErr = ErrAmbiguous
		} else {
			for _, line := range lines {
				id, parseErr := strconv.ParseUint(line, 10, 64)
				if parseErr != nil || id == 0 {
					beforeErr = ErrInvalidResource
					break
				}
				if _, killErr := connection.query(fenceContext, sqlKillWriterSession, id); killErr != nil {
					beforeErr = killErr
					break
				}
			}
		}
	}
	output, err := connection.query(fenceContext, sqlFreezeHA)
	if err == nil {
		var member ha.DatabaseMember
		member, _, err = parseLocalHAMember(output, executor.now().UTC())
		if err == nil && !member.ReadOnly {
			err = ErrAmbiguous
		}
	}
	var audit []byte
	if err == nil {
		audit, err = connection.query(fenceContext, sqlWriterSessionAudit)
		if err == nil && strings.TrimSpace(string(audit)) != "0" {
			err = ErrUnauthorized
		}
	}
	// Even an unsupported privileged account must have its current sessions
	// killed. It prevents a safe receipt until the operator removes that path.
	sessions, sessionErr := connection.query(fenceContext, sqlWriterSessions)
	if sessionErr == nil {
		lines := strings.Fields(string(sessions))
		if len(lines) > 256 {
			sessionErr = ErrAmbiguous
		} else {
			for _, line := range lines {
				id, parseErr := strconv.ParseUint(line, 10, 64)
				if parseErr != nil || id == 0 {
					sessionErr = ErrInvalidResource
					break
				}
				if _, killErr := connection.query(fenceContext, sqlKillWriterSession, id); killErr != nil {
					sessionErr = killErr
					break
				}
			}
		}
	}
	var remaining []byte
	if sessionErr == nil {
		var checkErr error
		remaining, checkErr = connection.query(fenceContext, sqlWriterSessions)
		if checkErr != nil {
			sessionErr = checkErr
		} else if strings.TrimSpace(string(remaining)) != "" {
			sessionErr = ErrAmbiguous
		}
	}
	err = errors.Join(err, sessionErr, journalErr, beforeErr)
	if err != nil {
		receipt.State = "closed_unsafe_or_unobserved"
	} else {
		receipt.State = "closed_observed"
		proof := append([]byte(nil), before...)
		proof = append(proof, output...)
		proof = append(proof, audit...)
		proof = append(proof, sessions...)
		proof = append(proof, remaining...)
		receipt.ObservationDigest = digestBytes(proof)
	}
	receipt.ObservedAt = executor.now().UTC()
	err = errors.Join(err, executor.writeNamed("effects", writerGateJournal, receipt))
	executor.writer.mu.Lock()
	executor.writer.safe = err == nil
	executor.writer.mu.Unlock()
	return err
}

func (executor *LinuxMariaDBExecutor) localWriterConnection() *mariaDBConnection {
	return &mariaDBConnection{executor: executor, localRoot: true, arguments: []string{"--no-defaults", "--batch", "--skip-column-names", "--raw", "--binary-mode", "--connect-timeout=2", "--protocol=socket", "--socket=" + mariaDBSocket, "--user=root"}}
}

// These statements have no caller-controlled SQL fragments. KILL accepts only
// a parsed, observed connection ID; audit refuses roles and privileged definers
// as well as privileged accounts accessible without the exclusive root socket.
func buildWriterGateStatement(kind mariaDBStatement, values ...any) (string, error) {
	if kind == sqlKillWriterSession {
		id, ok := oneValue[uint64](values)
		if !ok || id == 0 {
			return "", ErrInvalidCommand
		}
		return "KILL CONNECTION " + strconv.FormatUint(id, 10) + ";\n", nil
	}
	if len(values) != 0 {
		return "", ErrInvalidCommand
	}
	switch kind {
	case sqlStopWriterReplication:
		return "STOP SLAVE;\n", nil
	case sqlWriterSessionAudit:
		return `SELECT
(SELECT IF(@@global.skip_grant_tables=0,0,1))+
(SELECT IF(COUNT(*)=1,0,1) FROM mysql.user WHERE User='root' AND Host='localhost' AND plugin='unix_socket' AND authentication_string IN ('','root'))+
(SELECT IF(COUNT(*)>=1,0,1) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(QUOTE('root'),'@',QUOTE('localhost')) AND PRIVILEGE_TYPE IN ('SUPER','READ_ONLY ADMIN'))+
(SELECT IF(COUNT(*)>=1,0,1) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(QUOTE('root'),'@',QUOTE('localhost')) AND PRIVILEGE_TYPE IN ('SUPER','CONNECTION ADMIN'))+
(SELECT IF(COUNT(*)>=1,0,1) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(QUOTE('root'),'@',QUOTE('localhost')) AND PRIVILEGE_TYPE IN ('SUPER','REPLICATION SLAVE ADMIN'))+
(SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES p LEFT JOIN mysql.user u ON p.GRANTEE=CONCAT(QUOTE(u.User),'@',QUOTE(u.Host)) WHERE p.PRIVILEGE_TYPE IN ('SUPER','READ_ONLY ADMIN','CONNECTION ADMIN','BINLOG REPLAY','BINLOG ADMIN','REPLICATION MASTER ADMIN','REPLICATION SLAVE ADMIN','SET USER','CREATE USER','GRANT OPTION','SHUTDOWN','FILE') AND (u.User IS NULL OR u.User<>'root' OR u.Host<>'localhost' OR u.plugin<>'unix_socket' OR u.authentication_string NOT IN ('','root')))+
(SELECT COUNT(*) FROM mysql.global_priv WHERE User='root' AND (Host<>'localhost' OR JSON_CONTAINS_PATH(Priv,'one','$.auth_or')=1))+
(SELECT COUNT(*) FROM mysql.roles_mapping)+
(SELECT COUNT(*) FROM mysql.proxies_priv)+
(SELECT COUNT(*) FROM mysql.func)+
(SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='mysql' AND GRANTEE<>CONCAT(QUOTE('root'),'@',QUOTE('localhost')))+
(SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA='mysql' AND GRANTEE<>CONCAT(QUOTE('root'),'@',QUOTE('localhost')))+
(SELECT COUNT(*) FROM information_schema.COLUMN_PRIVILEGES WHERE TABLE_SCHEMA='mysql' AND GRANTEE<>CONCAT(QUOTE('root'),'@',QUOTE('localhost')))+
(SELECT COUNT(*) FROM information_schema.ROUTINE_PRIVILEGES WHERE ROUTINE_SCHEMA='mysql' AND GRANTEE<>CONCAT(QUOTE('root'),'@',QUOTE('localhost')))+
(SELECT COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA NOT IN ('mysql','sys') AND SECURITY_TYPE='DEFINER')+
(SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA NOT IN ('mysql','sys') AND SECURITY_TYPE='DEFINER')+
(SELECT COUNT(*) FROM information_schema.TRIGGERS)+
(SELECT COUNT(*) FROM information_schema.EVENTS);
`, nil
	case sqlWriterSessions:
		return "SELECT ID FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID() AND COALESCE(USER,'') NOT IN ('system user','event_scheduler') ORDER BY ID LIMIT 257;\n", nil
	default:
		return "", ErrInvalidCommand
	}
}

func (executor *LinuxMariaDBExecutor) sealWriterCertificate(value DatabaseWriterCertificate) (DatabaseWriterCertificate, error) {
	payload := certificatePayload(value)
	value.ID = digestBytes(payload)
	key, err := executor.localHAPermitKey()
	if err != nil {
		return DatabaseWriterCertificate{}, err
	}
	defer wipeBytes(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("cyberpanel-writer-candidate-v1\x00"))
	_, _ = mac.Write(payload)
	value.LocalSeal = hex.EncodeToString(mac.Sum(nil))
	return value, nil
}

func writerCandidateRequestDigest(authority json.RawMessage) string {
	payload := append([]byte("cyberpanel-writer-candidate-authority-v1\x00"), authority...)
	return digestBytes(payload)
}

func writerCandidateEvidenceName(requestDigest string) string {
	return "ha-writer-candidate-" + requestDigest[:48] + ".json"
}

func writerCandidateCertificateName(certificateID string) (string, error) {
	if !validSHA256(certificateID) {
		return "", ErrUnauthorized
	}
	return "ha-writer-certificate-" + certificateID[:48] + ".json", nil
}

func (executor *LinuxMariaDBExecutor) persistWriterCandidateRecord(name string, record writerCandidateEvidenceRecord) error {
	var stored writerCandidateEvidenceRecord
	if err := executor.readNamed("effects", name, &stored); err == nil {
		if !sameWriterValue(stored, record) {
			return ErrIdempotency
		}
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return executor.writeNamed("effects", name, record)
}

func exactMariaDBWriterLease(lease ha.WriterLease, cluster ha.DatabaseCluster, node ha.NodeID, now time.Time) bool {
	return lease.Validate(now) == nil && lease.State == ha.LeaseActive && lease.ResourceID == string(cluster.ID) && lease.GroupID == cluster.GroupID && lease.HolderNodeID == node && len(lease.EnforcedWritePaths) == 1 && lease.EnforcedWritePaths[0] == "mariadb-local" && !lease.IssuedAt.After(now.Add(5*time.Second)) && lease.ExpiresAt.Sub(lease.IssuedAt) <= 30*time.Second
}

// Federated ingress presents the owning executor as "local", while HA's
// certificate deliberately retains the enrolled node identity. The alias is
// accepted only after the current signed target binding resolves to that exact
// certificate candidate; every other lease field remains byte-for-byte equal.
func exactLocalWriterLease(requested, certified ha.WriterLease, requestedNode, boundNode ha.NodeID) bool {
	if certified.HolderNodeID != boundNode || requested.HolderNodeID != requestedNode {
		return false
	}
	if requestedNode == "local" {
		requested.HolderNodeID = boundNode
	} else if requestedNode != boundNode {
		return false
	}
	return sameWriterValue(requested, certified)
}

func (executor *LinuxMariaDBExecutor) observeWriterCandidateBoundary(ctx context.Context, checkpoint ha.ReplicationCheckpoint) (ha.DatabaseMember, string, writerGateReceipt, error) {
	executor.writer.mu.Lock()
	closed := executor.writer.managed && !executor.writer.open && executor.writer.active == nil && executor.writer.safe
	executor.writer.mu.Unlock()
	if !closed {
		return ha.DatabaseMember{}, "", writerGateReceipt{}, ha.ErrFenceRequired
	}
	if err := executor.verifyWriterSupervisor(ctx); err != nil {
		return ha.DatabaseMember{}, "", writerGateReceipt{}, ha.ErrFenceRequired
	}
	member, proof, err := executor.observeLocalHAMember(ctx)
	if err != nil || !member.ReadOnly || member.GTID != checkpoint.Position || member.Sequence != checkpoint.WriteFrontier {
		return ha.DatabaseMember{}, "", writerGateReceipt{}, ha.ErrCheckpointStale
	}
	var sessionFence writerGateReceipt
	if err = executor.readNamed("effects", writerGateJournal, &sessionFence); err != nil || sessionFence.State != "closed_observed" || !validSHA256(sessionFence.ObservationDigest) {
		return ha.DatabaseMember{}, "", writerGateReceipt{}, ha.ErrFenceRequired
	}
	auditContext := context.WithValue(ctx, writerAuditCapability{}, true)
	connection := executor.localWriterConnection()
	audit, err := connection.query(auditContext, sqlWriterSessionAudit)
	if err != nil || strings.TrimSpace(string(audit)) != "0" {
		return ha.DatabaseMember{}, "", writerGateReceipt{}, ErrUnauthorized
	}
	sessions, err := connection.query(auditContext, sqlWriterSessions)
	if err != nil || strings.TrimSpace(string(sessions)) != "" {
		return ha.DatabaseMember{}, "", writerGateReceipt{}, ha.ErrFenceRequired
	}
	return member, proof, sessionFence, nil
}

func (executor *LinuxMariaDBExecutor) validateStoredWriterCertificate(record writerCandidateEvidenceRecord, requestDigest string, authority DatabaseWriterCandidateAuthority, binding ha.StaticReplicationBinding, node ha.NodeID, epoch uint64, replica localReplicaJournal, member ha.DatabaseMember, sessionFence writerGateReceipt) error {
	certificate := record.Certificate
	receipt, receiptErr := decodeDatabaseSourceFenceReceipt(record.SourceFenceReceipt)
	replicaBytes, _ := json.Marshal(replica.Receipt)
	if receiptErr != nil || !bytes.Equal(record.SourceFenceReceipt, authority.SourceFenceReceipt) || record.RequestDigest != requestDigest || !validDatabaseWriterCertificate(certificate, executor.now().UTC()) || !sameWriterValue(certificate.Channel, authority.Channel) || !sameWriterValue(certificate.Checkpoint, authority.Checkpoint) || certificate.ClusterID != authority.Cluster.ID || certificate.ClusterGeneration != authority.Cluster.Generation || certificate.TopologyDigest != authority.TopologyDigest || certificate.DeploymentDigest != binding.DeploymentDigest || certificate.DeploymentDigest != replica.DeploymentDigest || certificate.DeploymentEpoch != binding.DeploymentEpoch || certificate.AuthorityEpoch != epoch || certificate.AuthorityEpoch != authority.Lease.AuthorityEpoch || certificate.OldWriter != authority.SourceNodeID || certificate.Candidate != node || certificate.Candidate != authority.CandidateNodeID || !sameWriterValue(certificate.Lease, authority.Lease) || certificate.FenceEffectID != receipt.EffectID || certificate.FenceDigest != digestBytes(record.SourceFenceReceipt) || certificate.ReplicaDigest != digestBytes(replicaBytes) || certificate.SessionFenceDigest != sessionFence.ObservationDigest || certificate.GTID != member.GTID || certificate.Frontier != member.Sequence || certificate.IssuedAt.Before(receipt.FencedAt) || certificate.IssuedAt.Before(authority.Lease.IssuedAt) {
		return ErrIdempotency
	}
	sealed, err := executor.sealWriterCertificate(certificate)
	if err != nil || !hmac.Equal([]byte(sealed.LocalSeal), []byte(certificate.LocalSeal)) {
		return ErrIdempotency
	}
	return nil
}

// IssueDatabaseWriterCertificate emits only local candidate evidence under
// opaque authenticated HA authority. Activation still requires a separately
// admitted post-fence majority certificate from protected authority storage.
func (executor *LinuxMariaDBExecutor) IssueDatabaseWriterCertificate(ctx context.Context, rawAuthority json.RawMessage) (DatabaseWriterCertificate, error) {
	if executor == nil || ctx == nil {
		return DatabaseWriterCertificate{}, ErrUnauthorized
	}
	authority, err := decodeDatabaseWriterCandidateAuthority(rawAuthority)
	if err != nil || verifyWriterAuthority(ctx, executor.VerifyWriterCandidateAuthorityJSON, rawAuthority) != nil {
		return DatabaseWriterCertificate{}, ErrUnauthorized
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	boundCtx := context.WithValue(ctx, replicationEpochContextKey{}, authority.AuthorityEpoch)
	binding, node, epoch, err := executor.replicationBinding(boundCtx, authority.Channel.ID)
	if err != nil || !bindingMatchesChannel(binding, node, authority.Channel, "target") || authority.CandidateNodeID != node || authority.Lease.HolderNodeID != node || authority.Lease.AuthorityEpoch != epoch || binding.DeploymentEpoch != authority.DeploymentEpoch || binding.DeploymentDigest != authority.DeploymentDigest {
		return DatabaseWriterCertificate{}, ErrUnauthorized
	}
	fence, err := executor.replicationFence()
	if err != nil || fence.FencingToken != authority.FencingToken {
		return DatabaseWriterCertificate{}, ha.ErrFenceRequired
	}
	sourceReceipt, err := candidateSourceFenceReceipt(authority)
	if err != nil {
		return DatabaseWriterCertificate{}, err
	}
	receipt, err := decodeDatabaseSourceFenceReceipt(sourceReceipt)
	if err != nil {
		return DatabaseWriterCertificate{}, err
	}
	var replica localReplicaJournal
	if err = executor.readNamed("effects", "ha-replica-"+digestBytes([]byte(authority.Channel.ID))[:32]+".json", &replica); err != nil {
		return DatabaseWriterCertificate{}, err
	}
	if !sameWriterValue(authority.Channel, replica.Channel) || !sameWriterValue(authority.Checkpoint, replica.Checkpoint) || replica.State != "applied" || replica.Epoch != epoch || replica.FenceToken != authority.FencingToken || replica.DeploymentDigest != binding.DeploymentDigest || replica.Receipt.Position != authority.Checkpoint.Position || replica.Receipt.TargetReceipt == "" {
		return DatabaseWriterCertificate{}, ErrUnauthorized
	}
	requestDigest := writerCandidateRequestDigest(rawAuthority)
	name := writerCandidateEvidenceName(requestDigest)
	var prior writerCandidateEvidenceRecord
	priorErr := executor.readNamed("effects", name, &prior)
	if priorErr != nil && !errors.Is(priorErr, ErrNotFound) {
		return DatabaseWriterCertificate{}, priorErr
	}
	if priorErr == nil {
		member, _, sessionFence, boundaryErr := executor.observeWriterCandidateBoundary(boundCtx, authority.Checkpoint)
		if boundaryErr != nil {
			return DatabaseWriterCertificate{}, boundaryErr
		}
		if executor.VerifyReplicationAuthority == nil || executor.VerifyReplicationAuthority(boundCtx, binding, node, epoch) != nil || verifyWriterAuthority(boundCtx, executor.VerifyWriterCandidateAuthorityJSON, rawAuthority) != nil {
			return DatabaseWriterCertificate{}, ErrUnauthorized
		}
		if err = executor.validateStoredWriterCertificate(prior, requestDigest, authority, binding, node, epoch, replica, member, sessionFence); err != nil {
			return DatabaseWriterCertificate{}, err
		}
		certificateName, nameErr := writerCandidateCertificateName(prior.Certificate.ID)
		if nameErr != nil || executor.persistWriterCandidateRecord(certificateName, prior) != nil {
			return DatabaseWriterCertificate{}, ErrIdempotency
		}
		return prior.Certificate, nil
	}
	var burned writerActivationCursor
	if err = executor.readNamed("effects", "ha-writer-token.json", &burned); err == nil {
		if burned.FencingToken == 0 || !validSHA256(burned.CertificateID) || authority.FencingToken <= burned.FencingToken {
			return DatabaseWriterCertificate{}, ErrUnauthorized
		}
	} else if !errors.Is(err, ErrNotFound) {
		return DatabaseWriterCertificate{}, err
	}
	if err = executor.latchWriterGate("candidate_evidence"); err != nil {
		return DatabaseWriterCertificate{}, err
	}
	executor.writer.transition.Lock()
	defer executor.writer.transition.Unlock()
	if err = executor.enforceWriterFence(boundCtx, "candidate_evidence", nil); err != nil {
		return DatabaseWriterCertificate{}, err
	}
	member, _, sessionFence, err := executor.observeWriterCandidateBoundary(boundCtx, authority.Checkpoint)
	if err != nil {
		return DatabaseWriterCertificate{}, err
	}
	now := executor.now().UTC()
	if now.Before(receipt.FencedAt) || now.Before(authority.Lease.IssuedAt) || !now.Before(authority.ExpiresAt) {
		return DatabaseWriterCertificate{}, ErrUnauthorized
	}
	replicaBytes, _ := json.Marshal(replica.Receipt)
	certificate := DatabaseWriterCertificate{SchemaVersion: databaseWriterEvidenceSchemaVersion, Channel: authority.Channel, Checkpoint: authority.Checkpoint, ClusterID: authority.Cluster.ID, ClusterGeneration: authority.Cluster.Generation, TopologyDigest: authority.TopologyDigest, DeploymentDigest: binding.DeploymentDigest, DeploymentEpoch: binding.DeploymentEpoch, AuthorityEpoch: epoch, OldWriter: authority.SourceNodeID, Candidate: node, Lease: authority.Lease, FenceEffectID: receipt.EffectID, FenceDigest: digestBytes(sourceReceipt), ReplicaDigest: digestBytes(replicaBytes), SessionFenceDigest: sessionFence.ObservationDigest, GTID: member.GTID, Frontier: member.Sequence, IssuedAt: now, ExpiresAt: authority.ExpiresAt}
	certificate, err = executor.sealWriterCertificate(certificate)
	if err != nil {
		return DatabaseWriterCertificate{}, err
	}
	if executor.VerifyReplicationAuthority == nil || executor.VerifyReplicationAuthority(boundCtx, binding, node, epoch) != nil || verifyWriterAuthority(boundCtx, executor.VerifyWriterCandidateAuthorityJSON, rawAuthority) != nil {
		return DatabaseWriterCertificate{}, ErrUnauthorized
	}
	record := writerCandidateEvidenceRecord{RequestDigest: requestDigest, SourceFenceReceipt: append(json.RawMessage(nil), sourceReceipt...), Certificate: certificate}
	if err = executor.persistWriterCandidateRecord(name, record); err != nil {
		return DatabaseWriterCertificate{}, err
	}
	certificateName, err := writerCandidateCertificateName(certificate.ID)
	if err != nil {
		return DatabaseWriterCertificate{}, err
	}
	if err = executor.persistWriterCandidateRecord(certificateName, record); err != nil {
		return DatabaseWriterCertificate{}, err
	}
	return certificate, nil
}

func (executor *LinuxMariaDBExecutor) activateDatabaseWriter(ctx context.Context, cluster ha.DatabaseCluster, node ha.NodeID, lease ha.WriterLease) (string, uint64, error) {
	if executor == nil || ctx == nil || !validLocalHACluster(cluster) || !exactMariaDBWriterLease(lease, cluster, node, executor.now().UTC()) || executor.LoadWriterTransferJSON == nil || executor.AdmitWriterTransferJSON == nil || executor.VerifyWriterTransferJSON == nil {
		return "", 0, ErrUnauthorized
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	raw, err := executor.LoadWriterTransferJSON(ctx, lease)
	if err != nil {
		return "", 0, ErrUnauthorized
	}
	transfer, err := decodeDatabaseWriterTransfer(raw)
	if err != nil {
		return "", 0, ErrUnauthorized
	}
	certificate := transfer.Certificate
	if !validDatabaseWriterCertificate(certificate, executor.now().UTC()) || certificate.ClusterID != cluster.ID || certificate.ClusterGeneration != cluster.Generation {
		return "", 0, ErrUnauthorized
	}
	certificateName, err := writerCandidateCertificateName(certificate.ID)
	if err != nil {
		return "", 0, ErrUnauthorized
	}
	var stored writerCandidateEvidenceRecord
	if err = executor.readNamed("effects", certificateName, &stored); err != nil || !validSHA256(stored.RequestDigest) {
		return "", 0, ErrUnauthorized
	}
	sourceReceipt, receiptErr := decodeDatabaseSourceFenceReceipt(stored.SourceFenceReceipt)
	storedBytes, _ := json.Marshal(stored.Certificate)
	suppliedBytes, _ := json.Marshal(certificate)
	sealed, sealErr := executor.sealWriterCertificate(certificate)
	if receiptErr != nil || sourceReceipt.EffectID != certificate.FenceEffectID || digestBytes(stored.SourceFenceReceipt) != certificate.FenceDigest || string(storedBytes) != string(suppliedBytes) || sealErr != nil || !hmac.Equal([]byte(sealed.LocalSeal), []byte(certificate.LocalSeal)) {
		return "", 0, ErrUnauthorized
	}
	if _, err = executor.verifyWriterTransferLocal(ctx, transfer); err != nil {
		return "", 0, err
	}
	// The signed static binding still has to be the current local target; a
	// valid lease cannot transplant candidate evidence onto another daemon.
	boundCtx := context.WithValue(ctx, replicationEpochContextKey{}, lease.AuthorityEpoch)
	binding, local, epoch, err := executor.replicationBinding(boundCtx, certificate.Channel.ID)
	if err != nil || !bindingMatchesChannel(binding, local, certificate.Channel, "target") || local != certificate.Candidate || !exactLocalWriterLease(lease, certificate.Lease, node, local) || epoch != certificate.AuthorityEpoch || binding.DeploymentDigest != certificate.DeploymentDigest || binding.DeploymentEpoch != certificate.DeploymentEpoch || executor.VerifyReplicationAuthority == nil || executor.VerifyReplicationAuthority(boundCtx, binding, local, epoch) != nil {
		return "", 0, ErrUnauthorized
	}
	executor.writer.transition.Lock()
	defer executor.writer.transition.Unlock()
	name := "ha-writer-activation-" + certificate.ID + ".json"
	var prior writerGateReceipt
	if err = executor.readNamed("effects", name, &prior); err == nil {
		executor.writer.mu.Lock()
		open, active := executor.writer.open, executor.writer.active
		executor.writer.mu.Unlock()
		if prior.State != "active" || prior.Transfer == nil || !sameWriterValue(*prior.Transfer, transfer) || !validSHA256(prior.ObservationDigest) || !open || active == nil || !sameWriterValue(*active, transfer) {
			return "", 0, ErrAmbiguous
		}
		if err = executor.verifyActiveTransfer(ctx, transfer); err != nil {
			return "", 0, err
		}
		encoded, _ := json.Marshal(prior)
		return string(encoded), certificate.Frontier, nil
	} else if !errors.Is(err, ErrNotFound) {
		return "", 0, err
	}
	var burned writerActivationCursor
	if err = executor.readNamed("effects", "ha-writer-token.json", &burned); err == nil {
		if burned.FencingToken == 0 || !validSHA256(burned.CertificateID) || lease.FencingToken <= burned.FencingToken {
			return "", 0, ErrUnauthorized
		}
	} else if !errors.Is(err, ErrNotFound) {
		return "", 0, err
	}
	fence, err := executor.replicationFence()
	if err != nil || fence.FencingToken != lease.FencingToken {
		return "", 0, ha.ErrFenceRequired
	}
	connection := executor.localWriterConnection()
	maintenance := context.WithValue(ctx, sqlMaintenanceCapability{}, true)
	if _, err = connection.query(maintenance, sqlStopWriterReplication); err != nil {
		return "", 0, ErrAmbiguous
	}
	member, _, err := executor.observeLocalHAMember(ctx)
	if err != nil || !member.ReadOnly || member.GTID != certificate.GTID || member.Sequence != certificate.Frontier {
		return "", 0, ha.ErrCheckpointStale
	}
	auditContext := context.WithValue(ctx, writerAuditCapability{}, true)
	audit, err := connection.query(auditContext, sqlWriterSessionAudit)
	if err != nil || strings.TrimSpace(string(audit)) != "0" {
		return "", 0, ErrUnauthorized
	}
	sessions, err := connection.query(auditContext, sqlWriterSessions)
	if err != nil || strings.TrimSpace(string(sessions)) != "" {
		return "", 0, ErrUnauthorized
	}
	receipt := writerGateReceipt{State: "activating", Transfer: &transfer, SessionPolicy: "broker-lease-gate; root-unix-socket-only; watchdog; no-super-read-only", ObservedAt: executor.now().UTC()}
	if err = executor.writeNamed("effects", name, receipt); err != nil {
		return "", 0, err
	}
	if err = executor.writeNamed("effects", "ha-writer-token.json", writerActivationCursor{FencingToken: lease.FencingToken, CertificateID: certificate.ID}); err != nil {
		return "", 0, err
	}
	intentCursor := localMariaDBHAReceipt{EffectID: "ha-writer-" + certificate.ID, Action: MariaDBHAPromote, ClusterID: cluster.ID, NodeID: "local", FencingToken: lease.FencingToken, LeaseID: lease.ID, ReadOnly: false}
	if err = executor.writeNamed("effects", "ha-fence-cursor.json", intentCursor); err != nil {
		return "", 0, err
	}
	if _, err = executor.verifyWriterTransferLocal(ctx, transfer); err != nil {
		return "", 0, err
	}
	if err = executor.admitWriterTransfer(ctx, transfer); err != nil {
		return "", 0, err
	}
	if err = executor.verifyActiveTransfer(ctx, transfer); err != nil {
		return "", 0, err
	}
	executor.writer.mu.Lock()
	executor.writer.managed = true
	executor.writer.open = false
	executor.writer.serial++
	serial := executor.writer.serial
	executor.writer.active = &transfer
	executor.writer.mu.Unlock()
	failed := true
	defer func() {
		if failed {
			executor.writer.mu.Lock()
			executor.writer.open = false
			executor.writer.active = nil
			executor.writer.serial++
			for _, cancel := range executor.writer.running {
				cancel()
			}
			executor.writer.mu.Unlock()
			bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = executor.enforceWriterFence(bounded, "activation_ambiguous", &transfer)
			cancel()
		}
	}()
	activationCtx := context.WithValue(ctx, writerActivationContextKey{}, writerActivationCapability{Serial: serial})
	output, err := connection.query(activationCtx, sqlPromoteHA)
	if err != nil {
		return "", 0, ErrAmbiguous
	}
	member, proof, err := parseLocalHAMember(output, executor.now().UTC())
	if err != nil || member.ReadOnly || member.GTID != certificate.GTID || member.Sequence != certificate.Frontier || executor.verifyActiveTransfer(ctx, transfer) != nil {
		return "", 0, ErrAmbiguous
	}
	receipt.State = "active"
	receipt.ObservationDigest = proof
	receipt.ObservedAt = executor.now().UTC()
	if err = executor.writeNamed("effects", name, receipt); err != nil {
		return "", 0, ErrAmbiguous
	}
	if err = executor.writeNamed("effects", writerGateJournal, receipt); err != nil {
		return "", 0, ErrAmbiguous
	}
	cursor := localMariaDBHAReceipt{EffectID: "ha-writer-" + certificate.ID, Action: MariaDBHAPromote, ClusterID: cluster.ID, NodeID: "local", FencingToken: lease.FencingToken, LeaseID: lease.ID, ReadOnly: false, GTID: member.GTID, Frontier: member.Sequence, ProofDigest: proof, AppliedAt: member.ObservedAt}
	if err = executor.writeNamed("effects", "ha-fence-cursor.json", cursor); err != nil {
		return "", 0, ErrAmbiguous
	}
	executor.writer.mu.Lock()
	if executor.writer.serial != serial || !executor.now().Before(certificate.ExpiresAt) {
		executor.writer.mu.Unlock()
		return "", 0, ErrAmbiguous
	}
	executor.writer.open = true
	executor.writer.mu.Unlock()
	failed = false
	encoded, _ := json.Marshal(receipt)
	return string(encoded), member.Sequence, nil
}
