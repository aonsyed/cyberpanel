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
audit-chain forks. Transaction conflicts return a conflict error: retry the
whole original request with the same idempotency key and request digest. Do not
retry individual failed SQL statements or mint new lifecycle/enrollment requests
after an uncertain commit. Signed JSON and response bytes use BYTEA, not JSONB,
so replay does not reserialize or normalize signed evidence.

Build preparation must resolve `github.com/jackc/pgx/v5 v5.7.6` and its transitive
modules in the authorized dependency environment. No modules were downloaded or
checksums synthesized for this change. PostgreSQL/QEMU behavior, crash replay,
concurrent sequencing, TLS rejection and existing SQLite-based central test
fixtures still require the separately authorized verification phase.
