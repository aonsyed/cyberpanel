# Central PostgreSQL authority

`panel-central` requires a dedicated PostgreSQL database and the fixed schema
`cyberpanel_authority`. Node-local databases remain SQLite. The service never
creates a database/role, changes a database password, or imports SQLite state.

Provision through a DBA-controlled PostgreSQL session (names below are examples;
only the schema name is fixed):

```sql
CREATE ROLE cyberpanel_central LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE DATABASE cyberpanel_central OWNER cyberpanel_central;
```

Set the role password through your secret-management workflow or the interactive
psql `\password cyberpanel_central` prompt, never a shell argument. Connect to
that database as its owner, then provision:

```sql
REVOKE ALL ON DATABASE cyberpanel_central FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cyberpanel_authority AUTHORIZATION cyberpanel_central;
REVOKE ALL ON SCHEMA cyberpanel_authority FROM PUBLIC;
```

Require authenticated TLS in PostgreSQL's connection policy. Install the matching
CA trust bundle at `/etc/cyberpanel/central/postgresql-ca.pem` and a root-owned,
mode-0600 `/etc/cyberpanel/central/postgresql.dsn` through the secret manager. The
DSN is a PostgreSQL URI containing an explicit URL-escaped user/password,
hostname, optional port, database, and `sslmode=verify-full`. For the packaged CA
credential, also set
`sslrootcert=/run/credentials/panel-central.service/postgresql-ca.pem`.
No other URI options are accepted. The systemd unit requires both credential
source files; the application can use system roots if `sslrootcert` is omitted.
Neither file's secret contents belong in panel-central.json, argv, or logs.

The packaged configuration contains only the registered credential path. Startup
pins verified TLS, no plaintext fallback, UTC, serializable transactions,
synchronous commit, a fixed schema search path, bounded query/lock timeouts, and
a bounded pool. Its role must own the schema and must not be a superuser or
BYPASSRLS role. Use a writable primary, not a read replica. Database permissions,
TLS identity, backups, failover fencing and service-role credential rotation
remain deployment responsibilities.

Startup refuses `database_path` configuration, the legacy
`/var/lib/cyberpanel-central/controlplane.db`, and any nonempty authority schema
without the PostgreSQL identity marker. Preserve/export and reconcile legacy
authority under an operator-approved migration plan, then archive it explicitly;
do not delete or silently adopt it. This slice provides no migration tool.

PostgreSQL identity columns provide audit order; predecessor uniqueness prevents
audit-chain forks. Uniqueness conflicts remain HTTP 409; transient PostgreSQL contention and
connection/failover errors return HTTP 503 with Retry-After: 2. Retry the
whole original request with the same idempotency key and request digest. Do not
retry individual failed SQL statements or mint new lifecycle/enrollment requests
after an uncertain commit. Signed JSON and response bytes use BYTEA, not JSONB,
so replay does not reserialize or normalize signed evidence.

Build preparation must resolve `github.com/jackc/pgx/v5 v5.7.6` and its transitive
modules in the authorized dependency environment. No modules were downloaded or
checksums synthesized for this change. PostgreSQL/QEMU behavior, crash replay,
concurrent sequencing, TLS rejection and existing SQLite-based central test
fixtures still require the separately authorized verification phase.

## HA credential and reconnect contract

The same systemd `postgresql.dsn` credential can contain strict version-1 JSON.
Use 2–5 distinct explicit TCP `host:port` endpoints (bracket IPv6 addresses), in
preferred-primary-first order. Every endpoint must belong to the same physically
replicated authority database, with the same service role and private CA.
Endpoints must not name independently initialized authority databases.

```json
{
  "version": 1,
  "endpoints": ["pg-a.internal:5432", "pg-b.internal:5432"],
  "database": "cyberpanel_central",
  "user": "cyberpanel_central",
  "password": "RENDER_BY_SECRET_MANAGER",
  "ca": "/run/credentials/panel-central.service/postgresql-ca.pem"
}
```

This example describes the protected credential, not panel-central.json. Install
its real contents through the secret manager with mode 0600; never pass JSON or
passwords in argv, environment variables, tickets, or logs. The CA file remains
a required systemd credential. HA JSON trusts only that CA bundle. Each DNS
endpoint must match its certificate SAN; IP endpoints require matching IP SANs.
Unknown fields, duplicate endpoints and missing explicit ports are rejected.
The prior one-host URI remains accepted but does not provide host failover.

pgx attempts endpoints in configured order, with verified TLS per host and
`target_session_attrs=read-write`. Each connection attempt is bounded to three
seconds; database statements are limited to 15 seconds, locks to five seconds,
and idle transactions to 15 seconds. Caller context deadlines remain the outer
bound. Before reusing a pooled connection, a two-second probe rejects closed,
unreachable, read-only or recovering backends. database/sql discards that
connection and obtains a writable connection through the configured fallbacks.
An already-running transaction stays on its original connection and cannot
migrate across hosts. Credential or endpoint-list changes require a controlled
service restart to load new systemd credentials.

The application does not retry individual transaction statements or replay an
uncertain commit. Retry an entire request with its original idempotency key and
digest; enrollment retries retain the same token and public keys, and rotation
retries retain the same previous certificate, expected generation and key.
A 503 after submission does not prove that the operation was uncommitted.
Node stream failures use the existing reconnect/outbox replay protocol, with
unchanged frames. This guarantee depends on preservation of acknowledged
PostgreSQL history; asynchronous data-loss promotion invalidates that premise.

## Local readiness

The unit creates mode-0700 `/run/cyberpanel-central`. Its mode-0600
`readiness.sock` accepts only local HTTP GET `/readyz`; no public listener or
node-stream API is added. A host-local operator/health agent with socket access
can use:

```sh
curl --fail --silent --show-error --max-time 25 --unix-socket /run/cyberpanel-central/readiness.sock http://localhost/readyz
```

The response is `{"ready":true}`/HTTP 200 or `{"ready":false}`/HTTP 503,
with no endpoint, credential, SQL error, or authority data exposed. A probe
begins a serializable transaction and locks the schema identity row on the
current primary, verifying identity/version, fixed schema, writable-primary
state and synchronous commit without changing stored data. Missing socket,
timeout, schema mismatch, denied lock rights or unavailable primary means
unready. The probe is bounded to 20 seconds. Readiness is point-in-time evidence,
not proof of replication quorum, split-brain prevention, backup currency, or
application operation success. systemd remains a process supervisor, not a
database-cluster manager or readiness-driven promotion mechanism.

## External PostgreSQL failover and backup/PITR runbook

1. Provision PostgreSQL replication, authenticated inter-node transport,
   synchronous quorum policy and an independent promotion/fencing controller.
   Retain explicit writer authority outside panel-central. A server merely
   reporting read-write does not prove that another primary has been fenced.
2. Before planned promotion, record primary timeline and flush/replay LSNs,
   in-flight authority operations, synchronous standby acknowledgement state,
   and the last retained backup/WAL recovery point. Fence the old writer before
   admitting another. For unplanned failure, prove its fence independently;
   never promote merely because the old address is unreachable.
3. Select a replica containing all acknowledged authority commits under the
   qualified synchronous failure model. `synchronous_commit=on` alone does not
   establish zero data loss: PostgreSQL synchronous standby/quorum configuration
   and its measured acknowledgement evidence are also required. If that proof
   is absent, keep central mutations unavailable and escalate the data-loss
   decision; do not silently serve from a lagging replica.
4. Promote using the external PostgreSQL tooling, observe the new timeline and
   writable role, then observe local readiness and replay an unchanged admitted
   request. Reconcile its exact committed result, node event cursor and audit
   chain before declaring recovery. Repair/reseed the old primary before it can
   rejoin; never restore an old primary as an independent writer.
5. The database owner operates encrypted base backups and continuous WAL
   archiving, retention/immutability, off-host storage and integrity manifests.
   Monitor archive failures, replication lag, storage capacity and the age of
   the latest actually restorable point. The application does not shell out,
   copy WAL, invoke backup tools, hold replication credentials, or own recovery.
6. Rehearse PITR into an isolated environment with no node/operator listeners.
   Restore the selected base backup, uninterrupted WAL and intended timeline;
   verify schema identity, audit chains, enrollment/lifecycle response bytes,
   admission/replay records, revocations and event/snapshot watermarks. Restore
   associated CA/signing keys through their separate protected-secret backup
   contract. Treat a restore older than acknowledged operations as an authority
   rollback: reconcile node epochs, grants, effects and receipts before service,
   under a separately approved recovery plan. Never erase node-local evidence
   or invent a newer epoch just to make a restored central database connect.

## Evidence required before an HA claim

The design target is committed PostgreSQL RPO 0 under the qualified synchronous
failure model and control-service failover RTO ≤60 seconds. These are acceptance
targets, not results demonstrated by this implementation. The later authorized
QEMU campaign must record:

- topology, versions, synchronous quorum/commit policy and exact failure model;
- old-writer fence evidence, old/new timelines and durable/replay LSNs, with every
  externally acknowledged enrollment, intent, receipt, revocation and lifecycle
  result present after promotion (zero lost acknowledged commits);
- fault injection time, first unready observation, promotion completion, first
  ready response and first successful unchanged-request replay; report measured
  RTO to completed service recovery, not merely TCP reconnect;
- primary death, demotion with live pooled connections, all endpoints unavailable,
  wrong-host/expired/untrusted TLS, wrong schema, and failures before/after COMMIT;
- no altered replay acceptance, duplicate admitted effect, audit-chain fork,
  snapshot freshness rollback or node-workload interruption from central loss;
- actual backup age, continuous WAL coverage and isolated PITR restore duration,
  recovered timestamp/LSN, usable-point age (backup RPO), restore throughput and
  completed authority reconciliation (restore RTO).

No regional failover, backup currency, RPO/RTO achievement or runtime behavior
has been verified by this code-only slice.
