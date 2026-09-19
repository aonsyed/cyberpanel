# QEMU verification — 2026-09-19

This is a verification checkpoint, not a parity-release certification.
The scope remains the complete product defined in the existing design spec.

## Source and environment

- Go fixes committed as `961889a1b`; frontend build fixes as `b7bd245d1`,
  with browser-verified navigation and bundle reduction in `6eb51776a`.
- Runs also include the existing uncommitted application database-placement
  changes and application validation/compensation regressions. Those features
  are not certified merely because compilation succeeds.
- Matrix source archive SHA256:
  `5b55dabe810b3bc7f4ca863b6408d2156259fa3806d559ce99aa41c5822195ed`.
- Startup-fix overlay archive SHA256:
  `14baf737c68d19c1a00c8c85e5e208bd237245cc645d21e1e5b49c8f61656bbf`.
- Go 1.26.5; QEMU guests only. ARM64 uses hardware acceleration; AMD64 uses
  CPU emulation. The installed QEMU is 11.1.1; this is not certification of
  the harness's pinned 11.0.3 version.
- Frontend: Node 24.21.0, exact package-lock, strict TypeScript settings kept.
- Evidence root is the parent repository's `.work/qemu/runs/`.

## Results

### Install drawer client identity controls — real QEMU browser

The application install drawer now exposes optional multiline client
certificate/private-key fields with WordPress/mutual-TLS guidance. Private
fields are explicitly marked sensitive: autocomplete/spellcheck are disabled
for the key, password/sensitive values are cleared after completed submission
(including API failure) and unmount, and result rendering redacts client-key
fields. This clears form state; it does not claim secure erasure of immutable
JavaScript strings or already-sent transport buffers.

Chromium inside Ubuntu ARM64 QEMU drove the actual Vue `ActionDrawer` and
current application field definitions at 1366×900 and 390×844. All four
success/failure cases passed: exact multiline PEM submission, cleared key and
administrator password, result redaction, no page errors and no horizontal
overflow. The API boundary was a controlled success/failure fixture; this is
not an authenticated installed-panel HTTP enrollment test. Browser harness:
`application-install-browser.cjs` in the current QEMU run directory; mobile
evidence: `application-install-mobile.png`, visually inspected after copying
it from the guest. The temporary loopback Vite server was stopped afterward.

An initial check found stale guest UI source/dependencies (Vite 7.1.3). The
current UI tree and lockfile were synchronized and `npm ci --ignore-scripts`
installed the locked dependencies in QEMU. With Vite 7.3.6, strict typecheck
and production build passed. Current main bundle: 529.33 kB (138.57 kB gzip);
the existing >500 kB warning remains. No OS images or Go archives were
downloaded. Clone identity controls and full installed enrollment remain open.

### Public application install input — client identity wiring

The `apps.instance.install` handler now accepts optional paired
`database_client_certificate` / `database_client_key` PEM inputs, bounded to
64 KiB each. Partial pairs, NUL bytes, over-limit inputs and unsupported
non-WordPress client-identity requests are rejected. The handler extracts
administrator and client-identity material into non-JSON byte fields, clears
the decoded payload's material strings before calling the edge, and wipes
the byte fields on return. The authenticated transport/canonical request still
necessarily carries the original input for existing request validation and
idempotency; no claim is made that clearing the handler payload erases those
immutable transport copies.

The edge validates its derived install request, enrolls the application client
identity through the existing broker issuer, and passes only its deterministic
reference to the install service. A durable terminal failed/compensated
operation allows enrollment cleanup. An executing, recovery-required or
unreadable operation preserves the lease for recovery rather than risking
revocation of a concurrent original install's identity. Such uncertain pending
leases remain in the local lease journal.

QEMU payload tests passed for paired-field validation, sensitive-field transfer,
non-serialization of the private material struct and byte wiping. The apps and
API package suites and the core binary build passed. This is source wiring and
component validation, not a live HTTP installation claim. Clone input remains
to be connected; install UI controls are now checked above. Full installed material delivery still
awaits the broker privilege choice. No downloads occurred in this phase.

### Client identity lifecycle and truthful purge outcomes — 2026-09-20

Install requests now accept only the deterministic client-identity reference
for their installation. That reference is recorded with the pending
installation, included in install compensation, and retained alongside the
configuration secret when activation succeeds. Shared secret-ID derivation
was moved unchanged out of the Linux adapter so request validation and broker
enrollment use the same rule.

Purge previously ignored database/secret revocation errors and committed a
removed installation. It now attempts all referenced cleanup, with a bounded
context independent of request cancellation, before marking the installation
removed. Failure leaves the installation removing and records a
recovery-required operation; a journal-write failure is also returned rather
than hidden. QEMU coordinator tests cover successful cleanup, database and
secret failures, and request cancellation after filesystem removal. The
install failure test now verifies client-identity revocation as well.

The Linux purge path also removes the installation's fixed private TLS files
outside the document root. A descriptor-anchored QEMU filesystem test verifies
this even after `db.php` has been deleted, including repeated cleanup. Empty
private directories may remain; certificate/key material and client launchers
do not. The apps package suite and both core/execd builds passed inside QEMU.
These are coordinator/filesystem checks, not a complete installed panel purge.

### Application-specific database client identity — backend enrollment

`ApplicationSecretIssuer.EnrollDatabaseClientIdentity` now validates the
certificate/key pair, validity interval and client-auth usage before enrolling
it through the broker's write-only `PutExact` management operation. It uses
the application tenant/installation/release audience and the same
`database_tls` secret identity consumed by the WordPress runtime, never the
external instance administrator's identity. The encoded private payload is
wiped after use. Runtime material validation now also rejects expired or
non-client identities.

The installed Ubuntu ARM64 QEMU broker passed actual enrollment, exact replay,
recovery after deleting only the fixture's local lease row, cross-tenant
rejection, changed-certificate conflict, revocation and refusal to resurrect
the revoked identity. Unit checks reject server-only, expired, not-yet-valid,
mismatched-key and empty-certificate inputs. The focused run passed in 0.096s:
`CYBERPANEL_QEMU_LIVE_APP_SECRETS=1 go test ./internal/apps -run 'TestApplicationDatabaseClientIdentityValidation|TestQEMULiveApplicationSecretLease' -count=1 -v`.
All broker fixture identities were revoked on test exit. No material-consumer
privileges were changed.

This is backend enrollment, not a completed installed public workflow. The install handler
now invokes it as recorded above; clone handling is wired as recorded below. Install UI
controls have passed the component browser checks recorded above.
Installation reference tracking and purge cleanup are now implemented as
recorded above. The existing broker privilege
decision remains pending for installed material delivery. No additional
downloads were performed in this phase.

### Clone target identity wiring and drawer checks — 2026-09-20

The clone edge accepts a separate target database client certificate/key,
validates the pair before site effects, and enrolls it for the target
tenant/site/installation. Clone request validation rejects a source or arbitrary
identity reference. Successful cloning retains the target identity for later
cleanup. A failed edge call revokes it only when its durable application
operation is failed/compensated; executing or uncertain operations retain it
for recovery. This does not prove transactional cleanup of every partial clone.

The site Clone drawer now exposes the optional paired PEM fields and treats the
private key as sensitive. Ubuntu ARM64 QEMU checks passed:

- Fresh apps and API package suites, including target-reference rejection.
- UI typecheck and production build (529.78 kB JS chunk warning remains).
- Real Chromium drawer at 1366×900 and 390×844, each with successful and rejected
  controlled API responses: exact PEM payload, source ID/generation, database-copy
  selection, private-key clearing, result redaction, no page errors or overflow.

The mobile screenshot was visually inspected. Fixture scripts and screenshot
are retained in `.work/qemu/runs/current-ubuntu-arm64-20260919-smoke/`
(`application-install-browser.cjs clone`, `application-install-smoke.html`,
`application-clone-mobile.png`). The temporary Vite process was stopped.
These browser checks exercise the actual component with a controlled API
boundary, not the installed HTTP clone/material-delivery chain. Full installed
clone and partial-failure cleanup qualification remain open. No downloads or
broker privilege changes occurred.

### Partial clone failure reporting — 2026-09-20

A QEMU regression reproduced discarded database-revocation errors, a misleading
failed operation after partial target-file writes, and cancellation suppressing
both revocation and journaling. Clone execution/receipt and probe/receipt failures
now attempt database revocation with a bounded cancellation-independent context
and retain a recovery-required operation. Database cleanup does not prove target
files were removed, so successful revocation alone no longer permits terminal
failure reporting. The edge consequently preserves the target client identity
for recovery instead of revoking it based on a misleading failed journal state.

Recovery journaling uses its own bounded context and returns operation/sync
journal errors alongside the original cause. Seven coordinator regression cases
cover partial execution, database cleanup failure, cancellation, journal failure,
invalid clone receipt, probe failure and invalid probe receipt. Fresh apps/API
package suites and core/execd builds passed in Ubuntu ARM64 QEMU. These checks use
controlled executor/database boundaries; they do not prove cleanup of actual
partial clone files or a completed installed recovery journey.

### Durable staging journal and integrated rerun — 2026-09-20

The SQLite reopen regression now covers application and staging failure/recovery
records under request cancellation. It reproduced staging's early failure record
remaining `executing` after reopening the database. Staging failure journaling now
uses a bounded cancellation-independent context and surfaces write errors rather
than discarding them. Recovery journaling passed the same actual SQLite reopen
check.

After this correction, `go test ./... -count=1` passed as root inside the Ubuntu
ARM64 guest (opt-in integration tests are not implied by that command). A separate
opt-in run passed installed application-secret enrollment/replay, protected-state
connection resolution, and actual WordPress/PHP/WP-CLI/MariaDB TLS and mutual-TLS
checks, including import/export rejection for untrusted identities. These remain
component checks, not a completed installed panel clone or broker material chain.

Logs are retained in `.work/qemu/runs/current-ubuntu-arm64-20260919-smoke/`:
`clone-integrated-check-20260920.log` and `clone-live-components-20260920.log`.
No downloads, signing changes, broker privilege changes, or host tests occurred.

### Committed-source matrix continuation — 2026-09-20

Revision `458fd7876` was exported with `git archive HEAD platform` into the fresh
`/home/harness/revision-458fd7876` directory on the retained AlmaLinux ARM64
overlay. Offline `go mod verify`, `go test ./... -count=1`, and `go build ./...`
all exited zero in the QEMU guest (Go 1.26.5, AlmaLinux 9.8). Command output and
exit are recorded in the task transcript. This is package/build qualification,
not live service qualification. The guest was then asked to shut down cleanly.
Both retained AMD64 overlays subsequently passed the same offline module
verification, uncached full Go suite and build for `458fd7876`, also from fresh
revision directories. Each SSH job exited zero and its saved log ends with
`MATRIX_EXIT=0`. Logs are retained at
`current-ubuntu-amd64-20260919-matrix/matrix-458fd7876.log` and
`current-alma-amd64-20260919-matrix/matrix-458fd7876.log` under the parent
repository's `.work/qemu/runs/`. Both AMD64 guests were asked to shut down after
their logs were copied and checked. These package/build runs do not include
the Ubuntu ARM64 opt-in live service fixtures. No images or toolchains were
downloaded; overlays and evidence were retained.

### Clone-delete private material cleanup — after matrix checkpoint

The production `DeleteClone` path was directly exercised as root in Ubuntu ARM64
QEMU against a unique managed-site filesystem fixture. The regression first
showed six private TLS artifacts left outside the emptied document root. A
second case showed identical source/target site IDs reaching the resolver.

Deletion now rejects identical sites before resolution and removes the target
installation's fixed private TLS files before clearing its public tree. The
runtime test verifies the returned receipt and empty private/public directories
after repeated deletion; the same-site case verifies no resolver call occurs.
The full apps package suite and `panel-execd` build passed in QEMU. Fixture-only
files were removed by test cleanup. This does not implement or qualify the
missing durable coordinator journey for recovering every partial clone.
This small follow-up postdates `458fd7876`; its new runtime checks have run on
Ubuntu ARM64, not the three other guests' completed matrix checkpoint.

### Durable partial-clone installation identity

Clone execution previously began before any target application record existed.
A real SQLite regression in Ubuntu ARM64 QEMU reproduced the missing record
both at executor entry and after a canceled partial clone and database reopen.

The coordinator now persists an `installing` target with its database and secret
references before file execution. Execution/probe failures transition that
record to `recovery_required` with generation advancement, independently of
request cancellation, and preserve state-write errors. Successful execution
updates the existing installation to active instead of creating it only at the
end. SQLite reopen tests cover both committed and recovery outcomes, retained
target identity references and durable replay behavior. The fresh apps suite and
core/execd builds passed in Ubuntu ARM64 QEMU.

The executor/database effects in these coordinator tests are controlled
fixtures. Full installed recovery/purge of an incomplete WordPress tree remains
unqualified, including recovery-point creation when the clone never completed.
An installation persistence failure before execution still requires recovery
of provisioned database resources. No new recovery protocol was introduced.

### Application connection authority and integrated Go check — 2026-09-20

`TestQEMUApplicationConnectionAuthority` exercises the production resolver
against root-owned database/principal/instance records in the disposable
Ubuntu ARM64 guest. It creates unique fixture records and removes them on exit.
The secret-source fixture permits only the exact pinned-CA reference/audience;
administrator credentials, principal passwords and server private-key requests
fail the test. Local resolution requests no material. External resolution
returns only the bound instance, SQL names, endpoint, TLS mode and public CA.

The first run exposed acceptance of disabled principals and quarantined,
deleting or deleted resources. Those states are now rejected before any CA
request. Resolution uses the executor's mutation mutex when joining the three
protected records. Cross-tenant/site requests, mismatched record identities,
principal-instance mismatches and endpoint/server-name disagreement are also
rejected. CA lease failure returns no usable connection profile.

The WordPress caller now verifies the exact instance ID and placement against
that protected result, in addition to SQL names and endpoint. Its focused
QEMU test rejects substituted instance/database/principal/placement/endpoint
values. Both tests passed after the fix (apps 0.007s, database 0.044s).

The existing integrated `go test ./...` run then exited successfully inside
Ubuntu ARM64 QEMU. Its 111 package-result lines include packages without tests
and cached unchanged packages; they are not 111 live product journeys.
Opt-in database/WordPress tests were run separately as recorded here, not
silently counted as exercised by the default suite. Guest evidence:
`/home/harness/application-integration-check-20260920.log`.
No OS image, package or toolchain downloads occurred in this resolver phase.

### Application database provisioning replay — installed broker verified in QEMU

`TestQEMULiveApplicationDatabaseProvisionReplay` now exercises the current
provisioner against the installed Ubuntu ARM64 QEMU management socket and
encrypted secret store, with a real temporary SQLite database repository.
Database command effects are controlled in this test; this is not an additional
MariaDB end-to-end claim. Before the fix, the first provision succeeded and
enrolled both audience-bound credentials. The identical second call failed
with `secrets: conflict` before database commands: the provisioner generated
fresh random material on each invocation, whereas `PutExact` correctly required
the original material. Both fixture credentials are revoked on test exit using
captured metadata only, without reading stored plaintext.

Reproduction (inside QEMU, as an authorized management peer):
`CYBERPANEL_QEMU_LIVE_APP_DATABASE=1 go test ./internal/apps -run TestQEMULiveApplicationDatabaseProvisionReplay -count=1 -v`.
The provisioner now calls the broker's write-only `ProvisionPasswordPair`.
The broker generates one random password, independently encrypts it for the two
existing consumer/tenant bindings, and commits both envelopes plus immutable
pair intent in one SQLite transaction. Exact retries return the original
metadata; they cannot rotate, rebind, adopt unrelated existing secrets, or
resurrect a revoked member. No plaintext or password-derived digest is stored
in the pairing table or returned in management responses. `PutExact` is unchanged.

The regression passes with `CYBERPANEL_QEMU_APP_DATABASE_ISOLATED=1`, which
starts the current real management server over a private Unix socket in QEMU,
using its real UID peer authorizer, FileKEK and encrypted SQLite store. It
injects loss of the first successful response and proves replay proceeds with
the same pair before database commands. After the signed sequence-11 upgrade
below, the default installed-socket mode also passes against the running
`panel-secretd.service`, without the isolated-server override.

`TestPasswordPairAtomicReplay` also passes in QEMU: a forced failure inserting
the second envelope leaves zero pair/head/record rows; both encrypted records
contain the same generated password; concurrent replay after SQLite reopen
preserves both ciphertexts; malformed requests, altered owners/IDs/adapters/
release bindings, unrelated pre-enrolled secrets and revoked members are
rejected. The secrets/apps package suites and panel-secretd/core builds pass
on the current Ubuntu ARM64 source snapshot. No other OS/architecture or
installed full-stack claim is made for this change.

The broker primitive is committed in `a051bccab`; the independently isolated
application call-site and configuration-secret failure cleanup are committed
in `04bb4fd`. The latter's exact staged source (without unfinished external
placement) passed the real-socket lost-response regression, the apps package
suite, and core/broker builds in QEMU at
`/home/harness/pair-commit.DLhDvE/platform`. Pending placement edits were
preserved in the working tree rather than included in that commit.

The installed component fixture is now `qemu-provider-3.1.10`, sequence 11.
Only its broker binary changed; the existing auth/provider binaries and all
service units were retained. A new, disposable QEMU signing authority
`qemu-password-pair-20260919` was explicitly provisioned with sequence range
11–20 and seven-day validity. The original authority and retained releases
remain present for recovery. Before provisioning that trust record, the new
bundle was rejected as untrusted. After normal installation committed, the old
sequence-10 bundle was rejected by the sequence/source frontier; the frontier
remained 11 and the broker remained active. No journal or frontier was edited.

- Manifest: `076578f9d015aa2b064211f23d7f0a52a5ad04ee03331f7307fee9b4372bc366`.
- Bundle: `259c1ef7a6e14083cee4a6d1250066150716fd0db7fe8bcc9356d1f52f01341e`.
- Installed broker/build SHA256: `75595097c10e40d525f3ebf144428e91f6cc051a680a3c7d5ee786c388672e45`.
- Installed-broker checks passed: application database provisioning replay,
  application secret issuance/replay/binding/revocation, and secret management
  enrollment/rotation/revocation. Fixture credentials were revoked on exit.
- `panel-secretd` is active/running, UID `cyberpanel-secrets`, empty capability
  bounding set, zero restarts. Auth and provider services are also active.

The guest-only fixture is under `/home/harness/password-pair-release-20260919`;
its signing seed never left QEMU. This is still a three-daemon component
qualification, **not** installation of the complete panel or verification of
material delivery to other process UIDs. The pending privilege-design choice
and full hosting/application lifecycles remain unresolved. No downloads were
needed for this upgrade.

The same working-tree snapshot passed the focused install-secret-failure and
compensation tests in QEMU (cleanup success/failure, canceled request, and
journal failures). Those checks are separate from the broker replay regression.

### Application secret management through the installed broker

`TestQEMULiveApplicationSecretLease` uses the real installed management socket,
encrypted broker storage and application SQLite lease repository. It reproduced
an issuer authorization bug: an active cached lease was returned for another
tenant without validating its owner. Cached replay now requires the matching
installation, purpose, tenant, secret purpose and complete consumer audience,
including release digest. The live QEMU test passes issuance, exact replay
without rotation, wrong-tenant and changed-release rejection, administrator
site-binding rejection, revocation and revocation replay. Fixtures are revoked
on exit. The exact independently staged source also passes the live checks and
core build, without the unfinished database-placement changes. Evidence:
`current-ubuntu-arm64-20260919-smoke/application-secret-lifecycle.log`.
This ran as an authorized root management peer in QEMU; it makes no claim about
material delivery to consumer processes.

### Packaged recipe loader and node-release layout

Inspection found a concrete startup mismatch: the container recipe loader
accepted only `/opt/cyberpanel/slots/.../components/panel/cyberpanel`, while the
offline signed node installer places the executable at
`/opt/cyberpanel/node-releases/<64-lowercase-hex>/root/usr/lib/cyberpanel/bin/cyberpanel`.
The loader now accepts that exact additional layout. Root ownership, safe
ancestor modes, no-follow recipe reads, strict JSON decoding and signature
verification are unchanged. QEMU tests accept both supported installer layouts
and reject malformed generations, sibling paths, wrong payload locations,
traversal and wrong executable names; the cyberpanel command builds in QEMU.
This removes a source-level prerequisite mismatch, not the need to supply real
signed n8n/Hermes and PHP application release inputs. Installed core startup is
not yet qualified by these path tests.

### Secret material identity privilege decision

Read-only transient systemd probes in the Ubuntu ARM64 guest inspected the
actual installed provider process's `/proc/<pid>/exe`. A root process with an
empty capability bounding set exited 1; the same probe with only
`CAP_SYS_PTRACE` in its bounding set exited 0 and resolved the signed provider
generation. Merely changing the broker UID to root is therefore insufficient.
The installed secret broker remains `User=cyberpanel-secrets`, empty capability
set, same MainPID. No persistent service privilege change was made.
The pending design choice is a constrained root broker with the required
inspection capability versus a dedicated broker with a privileged identity
inspection helper. Neither option permits dropping executable verification.

### Live external MariaDB TLS adapter

`TestQEMULiveMariaDBExternalTLS` passed as root inside Ubuntu ARM64 QEMU.
It starts a separate disposable MariaDB process on a loopback ephemeral TCP
port, with a generated CA/server identity and `require_secure_transport=ON`.
The production external connection builder and query runner accept the trusted
IP certificate, reject a different CA and a hostname missing from the server
certificate, and then accept the valid connection again. Negative cases also
check MariaDB client TLS error 2026, rather than counting arbitrary failures.
Evidence: `current-ubuntu-arm64-20260919-smoke/mariadb-tls.log`.
The fixture process, data directory, keys, and account are removed by cleanup;
the primary local MariaDB configuration is unchanged. The initial fixture setup
needed an explicit mysql-writable TMPDIR rather than inheriting root's TMPDIR.
The same live fixture now also switches the account to `REQUIRE X509`, rejects
the connection without a client certificate, accepts a separate trusted client
key/certificate via the production mutual-TLS adapter, rejects a client identity
signed by an unrelated CA with TLS error 2026, and accepts the trusted identity
again. This qualifies server-authenticated and mutual TLS at the database
adapter only, not secret-broker delivery, external-instance enrollment, or the
still-incomplete application TLS configuration described below.

### Live local MariaDB execution

MariaDB 10.11.14 was installed from the configured Ubuntu guest package
repository (`--no-install-recommends`). Only QEMU was modified; the service is
active and its database listener is `127.0.0.1:3306`. Installation evidence is
`current-ubuntu-arm64-20260919-smoke/mariadb-install.log`.

As root inside this guest, `CYBERPANEL_QEMU_LIVE_MARIADB=1 go test
./internal/database -run TestQEMULiveMariaDBCreateReplayDelete -count=1 -v`
passed. This exercises the actual Linux executor and actual MariaDB, with real
SQLite command persistence: create a uniquely named disposable database, observe
its presence through an independent client query, reopen SQLite and replay,
delete the fixture, observe absence, and replay deletion. The disposable database
was removed by the tested deletion; executor receipts remain for diagnosis.
The live test now additionally creates a managed principal and database-scoped
grants, authenticates through a root-private temporary client option file,
creates/inserts/selects fixture data, rejects a wrong password and access to
`mysql.user`, rotates the password, rejects the old password, confirms the new
password retains access, deletes the account, and rejects subsequent login.
The fixture secret source is in-memory; real secret-broker delivery is not
claimed. Evidence: `current-ubuntu-arm64-20260919-smoke/mariadb-lifecycle.log`.
An initial post-removal assertion expected only error 1045, whereas this server
returned 1698; direct observation confirmed access was denied and the account
absent. The assertion now accepts both authentication-denial codes. The retained
disposable database from that failed assertion was explicitly dropped; final
inventory showed zero `cp_qemu_` databases or users. External TLS, the installed
execd broker endpoint, and other OS/architecture combinations remain unqualified.

### External application database qualification gap

Implementation in progress: `internal/apps/wordpress_db_tls.php` now contains a
managed WordPress database connection implementation that configures the pinned
CA and optional client identity before connecting, enforces the configured TCP
endpoint and peer verification, and checks that the session negotiated a TLS
cipher. It preserves WordPress charset/SQL-mode/database initialization and has
its own connection-initialization state because WordPress's corresponding
property is private. Uncommitted install/clone wiring now invokes this asset,
but that integration is **not ready to activate**.

The current wiring obtains database/principal identity and endpoint/CA settings
from the database executor's protected state, with tenant/site checks. It does
not expose administrator passwords or private keys. Mutual TLS requests a
separate application-audience identity. Explicit TLS arguments are added for
WP-CLI import/export because those commands bypass the WordPress drop-in.

Focused QEMU checks passed for private file modes, replay/partial install,
managed-file removal on a local transition, rejection of TLS flag overrides,
and preserving unrelated drop-ins and symlink targets. On 2026-09-20 the
material files were moved outside the document root into a per-installation
directory under the site generation (`application-db-<installation digest>`),
mode 0700 with 0600 files. Only the executable `db.php` is published in
`wp-content`; its exact managed template carries a base64-encoded private
path. Descriptor-anchored no-follow operations protect material writes.
Additional QEMU checks passed for absence of material in the document root,
clone isolation (including local-transition preservation of source material),
and stable material paths after release-directory promotion. Both package
suites passed as root in QEMU after these changes; `panel-execd` built there.
The real PHP/WordPress/MariaDB TLS test passed again with material outside
its WordPress directory, including all six trusted/untrusted identity cases.
No image or toolchain downloads were performed for this checkpoint.

Outstanding before enabling this wiring: qualify the protected-state resolver
and application-identity enrollment; run full install/clone journeys. The
wiring has not been installed or exercised with production application
credentials. Actual WP-CLI component qualification is recorded below.

### WP-CLI database import/export — real TLS failures corrected

On 2026-09-20, the Ubuntu ARM64 guest ran WP-CLI 2.12.0 with WordPress 7.1,
PHP 8.3.6 and the isolated MariaDB 10.11.14 TLS fixture. WP-CLI's downloaded
PHAR matched the release's published SHA256:
`ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c`.
WordPress core passed `wp core verify-checksums --version=7.1`. These small
test dependencies were downloaded inside QEMU; no OS images or Go archives
were downloaded. They are not enrolled production release artifacts.

Actual import testing exposed two problems invisible to argument-only tests:

- File import opened a preliminary SQL-mode connection without forwarding
  TLS options; mutual TLS failed with database error 1045. Snapshot import now
  streams the verified dump descriptor through stdin, avoiding that connection
  and retaining the SQL modes contained in the exported dump.
- Import's option whitelist silently discarded MariaDB's
  `ssl-verify-server-cert` flag. A wrong-hostname import actually succeeded
  before the correction. A fixed private client launcher now supplies
  `--no-defaults --ssl=1 --ssl-verify-server-cert=1` directly to MariaDB.
  The runtime validates the launcher bytes and selects it only for TLS
  imports. It contains no credentials and is mode 0700 outside the web root.
  CA and application-client identity arguments remain explicit. No ambient
  database option files or certificate-verification bypasses are introduced.

Both trusted TLS and trusted mutual TLS now export real table contents,
delete the fixture row, import the dump, and independently verify restoration
through the server's local administrative socket. Both export and import
reject wrong CA, wrong hostname, absent required client identity and an
untrusted client identity. Rejected imports leave the fixture row unchanged.
The existing PHP/mysqli connection/reconnect checks also pass in the same run.

The fixture subsequently passed a complete WordPress 7.1 bootstrap using the
managed `wp-content/db.php`, not the minimal `wpdb` test bootstrap. `wp core
install` created the installation over server-authenticated TLS; `core
is-installed`, `option get siteurl` and WordPress's `wp_authenticate` plus
`manage_options` capability check passed over both TLS and mutual TLS.
The administrator password was supplied through stdin, never argv. A separate
administrative SQL query confirmed the persisted administrator record. The
same installed WordPress database was reused for the mutual-TLS check; a fresh
mutual-TLS installation is not claimed. The complete updated fixture passed in
4.092s. This validates real WordPress startup and authentication code, not an
OLS-served browser login or the panel's installed provisioning/broker chain.

The production snapshot-import boundary test verifies stdin delivery of the
exact digest-checked dump and rejects a mismatched digest or symlink before
launching the command. That boundary test uses a capture executable; the
database fixture separately executes real WP-CLI. This is not a full installed
panel clone certification.

Reproduction inside QEMU as root:
`CYBERPANEL_QEMU_LIVE_MARIADB=1 CYBERPANEL_QEMU_LIVE_WORDPRESS_TLS=1 CYBERPANEL_QEMU_LIVE_WORDPRESS_CLI=1 go test ./internal/apps ./internal/database -run 'TestWordPressSnapshotImportStreamsVerifiedDump|TestWordPressTLSManagedFiles|TestQEMULiveMariaDBExternalTLS' -count=1 -v`.
All selected checks passed (apps 0.076s, database 2.237s). The complete apps
and database package suites and the execd build were then checked in QEMU.

Driver-level qualification now passes inside QEMU using actual WordPress
`wpdb`, PHP mysqli/mysqlnd and the isolated real MariaDB TLS fixture. Trusted
TLS and mutual TLS both execute queries, select the expected database, apply
utf8mb4 and reconnect successfully. Wrong CA, mismatched identity (`127.1`
versus a certificate for `127.0.0.1`), missing client identity, and a client
certificate signed by an unrelated CA are rejected. Negative TLS cases require
an actual TLS error/warning, not merely any failure. WordPress bootstrap hooks
and constants are minimal test fixtures; this is **not** a full WordPress
installation or browser journey.

The initial connector incorrectly required
`mysqli_options(MYSQLI_OPT_SSL_VERIFY_SERVER_CERT, true)` to succeed. QEMU
proved that mysqlnd 8.3.6 rejects that legacy option. The connector now supplies
the pinned CA and the SSL-only connection flag, never the verification-bypass
flag. This matches the
[mysqlnd TLS implementation](https://raw.githubusercontent.com/php/php-src/PHP-8.3/ext/mysqlnd/mysqlnd_vio.c),
and the live negative-certificate/hostname checks confirm rejection. Temporary
diagnostic logging was removed before the final passing run.

Command inside the Ubuntu ARM64 guest:
`CYBERPANEL_QEMU_LIVE_MARIADB=1 CYBERPANEL_QEMU_LIVE_WORDPRESS_TLS=1 go test ./internal/database -run TestQEMULiveMariaDBExternalTLS -count=1 -v`.
The fixture removes its server, data and keys on exit. Installed MariaDB and
the signed component services were not reconfigured by this test.

PHP 8.3 CLI and its MySQL driver were installed only inside Ubuntu ARM64 QEMU
for those checks (3.3 MB of package downloads, no VM image downloads). Official
WordPress 7.1 `class-wpdb.php` was retrieved into that guest as a test dependency;
this does not select or certify a production WordPress recipe version.
The tested source SHA256 is
`e15403e90032dd0508811301505e491d4212de5152581a98f51b744a1a3903bd`.

The WordPress integration point has been checked against primary documentation:
[`wpdb::db_connect`](https://developer.wordpress.org/reference/classes/wpdb/db_connect/)
uses client flags but does not set the selected instance's pinned CA before
connecting. PHP's [`mysqli::ssl_set`](https://www.php.net/manual/en/mysqli.ssl-set.php)
must be applied before connection, and WordPress's
[`require_wp_db`](https://developer.wordpress.org/reference/functions/require_wp_db/)
supports a managed `db.php` replacement. A flags-only change is insufficient.
The remaining implementation must preserve WordPress connection initialization
and reconnection behavior, fail rather than overwrite an unrelated database
drop-in, and verify real WordPress queries against trusted/untrusted endpoints.
For mutual TLS, a tenant application must receive its own client identity, not
the external instance administrator's private key. These are implementation
requirements, not claims that this application integration exists yet.

Source inspection of the unfinished placement changes found that the selected
instance reaches install/clone requests and the provisioner, but does not yet
establish secure application connectivity. `linux_runtime.go` passes the remote
endpoint to WordPress `config create` without configuring a pinned CA or peer
verification; `linux_staging.go` does the same for cloned WordPress. The binding's
`TLSRequired` boolean is therefore not evidence of enforced transport security.
`applicationDatabaseHost` in `linux_certified_runtime.go` rejects external hosts
for the other certified runtimes. No external application lifecycle is qualified.
Completion requires carrying the selected instance's trust/identity settings
through protected application configuration, enforcing verified TLS in each
supported runtime, and testing valid and wrong-CA/wrong-server cases against a
real QEMU database. Do not commit or advertise the unfinished placement slice
as complete based on binding-validation or controlled-effect tests.

### Installation cancellation cleanup

The real application SQL repository also reproduced lost terminal journal writes:
both failed/recovery-required paths left the persisted operation `executing`
when their request context was canceled. Those writes now have an independent
30-second deadline; ordinary failure reporting also exposes journal-write
errors as recovery-required instead of discarding them. The regression reopens
SQLite and checks the recorded state, stage, and cause. Ubuntu ARM64 QEMU
database/application tests and command builds pass with this correction.

Database cleanup retry qualification additionally exposed an idempotency failure:
after a completed deletion and SQLite reopen, the adapter reused its command ID
with the incremented generation (`database command ID was reused with another
payload`). The adapter now recovers the original expected generation from the
stored deletion request and lets the coordinator validate/replay that command.
QEMU checks exercise real SQLite and coordinator persistence for both completed
and interrupted/ambiguous cleanup, reopen storage, resume cleanup, and confirm
that terminal replays perform no additional effects. Database/application tests
and command builds pass. MariaDB effects remain controlled in these tests.

The current uncommitted application changes also fix canceled-request cleanup.
QEMU first reproduced `TestInstallCompensationSurvivesRequestCancellation`
failing with repeated `context canceled` and `application requires recovery`:
the canceled request prevented both revocation and journal writes. Cleanup now
preserves context values but uses its own two-minute deadline. The regression
checks both secret revocations, database revocation, the compensated journal
state, original cancellation error, and the finite cleanup deadline.
`go test ./internal/apps -count=1 -v` passes in Ubuntu ARM64 QEMU, including
existing cleanup-error/journal-error cases. These are coordinator tests with
controlled adapters, not a live application install or MariaDB certification.

### Database persistence correction

Ubuntu ARM64 QEMU reproduced rejection of valid database-wide grants during
JSON decoding: their intentionally empty object name was rejected by the SQL
identifier decoder. Optional identifiers now round-trip while constructors and
resource validators still reject missing required names and unsafe identifiers.
The associated optional resource-ID correction also preserves local principals
without a network-policy ID.

`TestSQLCoordinatorResourcesAndReplayAfterReopen` exercises the actual SQLite
repository and coordinator: create database, create local principal, assign
database-wide grants, close/reopen storage, replay without repeated effects,
reject changed-payload replay, and exclude another tenant's inventory.
The MariaDB effect boundary is controlled; this is not live MariaDB qualification.
The focused database/application tests and full Go suite/build pass in this
guest. Evidence: `current-ubuntu-arm64-20260919-smoke/database-persistence-suite.log`.
Other matrix guests have not yet run this correction.

| Guest / check | Result | Evidence beneath evidence root |
|---|---|---|
| Ubuntu ARM64 Go suite/build, startup fixes included | Pass | `current-ubuntu-arm64-20260919-smoke/full-startup-fixed.log` |
| AlmaLinux ARM64 Go suite/build, startup fixes included | Pass | `current-alma-arm64-20260919-matrix/full-startup-fixed.log` |
| Ubuntu AMD64 Go suite/build, startup fixes included | Pass | `current-ubuntu-amd64-20260919-matrix/startup-checks.log` |
| AlmaLinux AMD64 Go suite/build, startup fixes included | Pass | `current-alma-amd64-20260919-matrix/startup-checks.log` |
| Frontend strict typecheck and production build in Ubuntu ARM64 | Pass | `current-ubuntu-arm64-20260919-smoke/ui-build-worker-final.log` |
| Updated navigation: strict typecheck/build plus actual Chromium component interaction at 1366x900 and 390x844, all inside Ubuntu ARM64 | Pass | `current-ubuntu-arm64-20260919-smoke/navigation-fixed.log`, `navigation-source.sha256` |
| Application binding and compensation regressions in full Linux package | Pass | Ubuntu ARM64 suite above |
| All 23 command binaries invoked with `--help` in Ubuntu ARM64 | No initialization panics; some reject missing privileges/config/arguments | `current-ubuntu-arm64-20260919-smoke/command-smoke.log`, `command-logs/` |
| Installer status and authority initialization | Not installed; initialization reaches trust checks, rejects missing trusted recipe material | `current-ubuntu-arm64-20260919-smoke/installer-startup-fixed.log` |

Updated suites contain 20 passing packages and 91 packages without tests.
Packages without tests are compilation evidence, not behavioral qualification.
The navigation browser fixture mounts the actual Sidebar, Topbar, CommandPalette,
router and session store. It proves 45 desktop icons, collapse/expand and saved
preference, and mobile palette search/routing. It does not supply or qualify an
authenticated backend. The temporary Vite fixture server was stopped afterward.

## Concrete defects corrected

- API error translation referenced the old n8n-specific type after its rename.
- Mail telemetry and email-marketing regex initialization panicked because Go
  rejects individual bounded repetitions above 1000. Equivalent split bounds
  retain the original maximum lengths and capture groups; boundary tests cover
  accepted maxima and rejected overlong input.
- Application database binding validation accepted inconsistent placement,
  missing external TLS, and an unknown engine.
- Application install compensation discarded durable-journal write failures.
- Frontend icon exports, absent optional values, indexed values, binary buffer
  types and build-tool declarations prevented strict compilation. Source fixes
  and pinned dependencies resolve those failures without disabling checks.
- Actual browser checks exposed a decorative-only mobile menu icon while the
  sidebar is hidden. The accessible button now opens the existing navigation
  palette; mobile route selection passed. Explicit sidebar icon imports remove
  the whole-library namespace import and reduce built JavaScript from 6023.72
  kB to 528.66 kB (gzip: 1300.65 kB to 138.34 kB).

## Remaining release gates

### Follow-up: failed application secret issuance

After the four-guest checkpoint, the real `ApplicationService.Install` path was
exercised with failing secret issuance and controlled store/database/secret
adapters in the Ubuntu ARM64 guest. Both cleanup-success and cleanup-failure
cases initially failed: the administrator bootstrap secret was never revoked.
The call site now uses the existing compensation path, which also exposes
database cleanup failures and records recovery-required state.

`go test ./internal/apps -run TestInstallSecretFailure -count=1` reproduced the
failure before the fix. After the fix, the apps package and then
`go test -count=1 ./... && go build ./...` passed in that guest (exit 0).
This is service-level fault-injection coverage, not a live secret-broker or
MariaDB lifecycle test. The other three guests have not run this later change.
Command output is retained in the task transcript.

Tested SHA256 values:

- `internal/apps/service.go`: `ae89a6832ff0a28d6ae1d146109463dab67e1f68e31957ae84b40d4741d57bd3`
- `internal/apps/install_compensation_test.go`: `74a0cf61071be1a84fcd4a562f1a81b4744f34d6cd95e4bfeff167d26999a20b`

### Follow-up: database resource decoding and cleanup receipts

The next Ubuntu ARM64 check exposed a valid local database principal failing
`EncodeResource`/`DecodeResource` round-trip: the optional empty network-policy
ID was rejected during JSON decoding. Optional resource IDs now round-trip;
tests retain constructor/required-metadata checks and reject malformed IDs.

After fixing decoding, eight fault-injection cases reproduced cleanup falsely
succeeding for accepted, rejected, compensated, or ambiguous command receipts.
The application database adapter now requires `OperationApplied` for both
principal and database deletion, stopping before database deletion when
principal deletion is unconfirmed. Both applied cases remain successful.

The apps regressions, full Go suite, and build pass in Ubuntu ARM64 after these
changes. Evidence: `current-ubuntu-arm64-20260919-smoke/database-cleanup-checks.log`
and the task's exit-zero command result. These checks use the actual resource
codec and cleanup adapter with controlled command responses, not a live MariaDB
server. They are newer than the four-guest matrix above.

Tested SHA256 values:

- `internal/database/model.go`: `9c662c2c1821cda4323915fafbb687a6e2b118122252cec79f54778b0a790122`
- `internal/database/model_test.go`: `d86027e91e89719b40925164c8740004a46be72c166fd4a737c53a1967925cd5`
- `internal/apps/linux_adapters.go`: `75e0a3f98d1131c5e33fc1527126878e7c03c32952129fec9c8517af5fc6df9e`
- `internal/apps/database_cleanup_linux_test.go`: `8a6b699f3e140a8ad35b85ce18761f7ae32fd69404fad93d95b9a1434a749af2`

### Outstanding qualification

### Signed authentication component installation — Ubuntu ARM64

An actual four-artifact, disposable test-authority-signed component release was
assembled and installed through `node-release` and `panel-node-install`: the
real `panel-authd` binary, packaged auth config, packaged hardened systemd unit,
and an already-cached native Ubuntu package. This is **not** the full panel
release or its complete dependency inventory. No additional downloads were
needed. Host-local service identities and random credentials were provisioned
separately in the guest, never included in the signed bundle.

Runtime checks exposed and corrected:

- The manifest rejected `/usr/lib/cyberpanel/bin`, despite core, gateway and
  central units using it. Tests now check the actual packaged unit executables
  and reject sibling/traversal paths.
- Core, gateway, central and auth config readers rejected installer-managed
  symlinks. A shared resolver accepts only the exact root-owned active-release
  chain to a digest-named generation. Root-owned ancestor, payload ownership,
  mode and regular-file checks remain; arbitrary links, writable ancestors,
  symlink payloads and credential destinations are rejected.
- Missing installed-state files were wrapped in a joined error that defeated
  `os.IsNotExist`, preventing fresh installation. Filesystem errors now retain
  their identity; malformed existing files remain rejected.
- Authd rejected systemd's root-owned, root-group `0440` credential files.
  Registered credential paths now accept that protected mount representation;
  config ownership requirements remain unchanged.
- The packaged HTTPS port-8090 WebAuthn origin was rejected by a port-443-only
  configuration validator. Valid HTTPS ports can now be explicitly configured;
  hostname, scheme, userinfo, path and port-boundary checks remain. Runtime
  assertion verification still requires exact membership in configured origins.
- The installer accepted a fleeting systemd `active` state before authd crashed.
  It now requires a continuous activation across observations (up to two seconds
  within the signed timeout). This is startup stability, not application-level
  readiness or long-term health certification.

The failing signed sequence 2 correctly produced `recovery_required` because
both candidate and prior authd crashed. Its complete installer state/releases
and managed links were moved, not deleted, to
`/root/qemu-auth-failed-install-20260919` inside the guest. Only this newly-created
component fixture was reset. Fresh sequence 3 failed on the invalid configured
origin and rolled back. Sequence 4 then installed successfully without another
reset. No signature checks, journals or frontiers were edited to force success.

Installed release: `qemu-authd-3.1.3`, sequence 4.
Manifest: `0942b21b9808fcc279c447344c45e30671e9f115335be2040410fd8df6fc9df2`.
Bundle SHA256: `765a5d8c66f7cfddd5a5cd42f97bc257e6f6f846699d8adc8edc2af43a160401`.

Verified against the installed service, not a fixture server:

- `panel-authd.service` active/running with `NRestarts=0` after subsequent checks.
- Opt-in `TestQEMULiveVerifierPasswordAndAPIKey`, run as the `cyberpanel` account,
  passed enrollment, incorrect/correct password checks, API-key verification,
  revocation and rejection of revoked credentials through the real Unix socket.
  Test credentials were revoked; secret bytes were not printed.
- A signature-corrupted bundle was rejected as untrusted. An older sequence was
  rejected by the source/frontier check. Installed-state SHA256 and daemon PID
  were unchanged across both rejection checks.
- Full current Go suite/build passed in Ubuntu ARM64. Root-owned config-chain
  cases were separately executed as root with `TMPDIR=/root`, rather than
  counting their default non-root skip as a pass.

Evidence beneath `current-ubuntu-arm64-20260919-smoke/`:
`signed-auth-suite.log`, `auth-release-installed-status.json`,
`auth-release-journal.log`; live calls and negative-install results are in the
task transcript. Artifact generator scripts are retained there. The disposable
signing private key stays inside the guest. The service remains running for
the next integration stage. These later changes have not run on the other
three OS/architecture combinations.

### Remaining full-product qualification

### Signed auth + secret-broker upgrade — Ubuntu ARM64

The next component bundle adds the real secret broker and its packaged hardened
unit to the installed auth service. It exposed an absent Docker socket causing
systemd namespace setup to fail, and rollback disabling a newly-added service
only after its unit file disappeared behind the previous-generation link.

Changes and live results:

- Optional absent paths in the secret-broker `InaccessiblePaths` list no longer
  prevent startup; existing paths retain their isolation restriction.
- Removed services are disabled before changing the active generation, on both
  upgrade and rollback. The original failing sequence-5 bundle was replayed and
  now returned `rolled_back`, with the prior sequence-4 auth service running.
- The KEK reader has a separate, exact-path systemd-credential constructor for
  the root-owned/root-group `0400` or `0440` mount. Ordinary key files still
  require their specified owner and `0400`. Reads are bounded and check the
  opened file identity. Root fixture checks and real broker encryption passed.
- The management socket now uses kernel UID/PID peer credentials with the same
  root/control-plane UID allowlist. It does not claim executable verification,
  which management never used. The material socket retains its independent
  executable/process-start verification. No ptrace capability was added.
- Live management calls as `cyberpanel` passed enroll, exact replay, conflicting
  replay rejection, rotation, stale-version rejection and revocation. Calls
  as `cyberpanel-secrets` could open the socket but were rejected as unauthorized
  administrative peers. The auth password/API-key lifecycle also passed again.
- Both installed services report active/running and zero restarts. Full current
  Go tests/build passed in Ubuntu ARM64; root KEK cases were executed explicitly.

Installed component release: `qemu-control-3.1.6`, sequence 7.
Manifest: `5137f236e065ad0f649f5695b711fc53a58da38ba75657bf289c455271f31d0c`.
Bundle SHA256: `28f95fb3a36617597907881c0247cb8d1d4c0956f510739dc9a04314691c6097`.

The original sequence-5 manual-recovery state was preserved by moving this
disposable fixture's installer state, releases and links to
`/root/qemu-control-failed-install-20260919`. The auth-only sequence 4 was then
installed fresh before replaying the same failing sequence 5 with corrected
ordering, followed by sequences 6 and 7. No journals were edited to manufacture
success. This proves the corrected rollback on a new attempt, not automatic
repair of already-existing `recovery_required` journals.

Evidence: `signed-control-suite.log`, `control-rollback-status.json`,
`control-installed-status.json`, `control-secretd-journal.log` under the current
Ubuntu ARM64 evidence directory, plus live test output in the task transcript.
No additional packages/images were downloaded. Both daemons remain running.

**Remaining material-delivery issue:** the isolated secret-service UID cannot
read `/proc/<other-account-PID>/exe`. This was confirmed directly in the guest.
Management no longer depends on that unrelated check, but actual secret delivery
to privileged executors still requires a secure solution and live qualification.
Do not treat management success as proof that material delivery works.

### Outstanding full-product gates

### Provider startup and shared-state permissions — Ubuntu ARM64

The signed component fixture now includes the actual provider worker. Sequence 8
reproduced a Docker-socket namespace failure and rolled back to the healthy
auth/secret-broker release. Sequence 10 contains the final unit: only absent
Docker sockets are optional; private state paths remain mandatory and hidden.
Required private directories were provisioned in the guest before activation.
An intermediate sequence 9 with broader optional paths is not the final fix.

The sandbox check also exposed `/var/lib/cyberpanel` being created as root-only
0700 by the node installer, preventing the control account reaching its own
state. The installer now creates/repairs that root-owned shared parent as 0755,
while its own `node-release` subtree remains root-owned 0700 and `control`
remains control-account-owned 0700. Unsafe ownership, writable modes and symlink
parents are rejected. Root QEMU regression cases passed. After the repair,
`cyberpanel` could list its control directory outside the provider namespace,
but the same UID was denied inside the running provider's mount namespace.

`TestQEMULiveProviderWorkerBoundary`, run as `cyberpanel`, passed a real socket
request returning `unsupported_provider` and rejection of an invalid protocol
version. No external provider request or credential was used. All three daemons
are active/running with zero restarts; full Go suite/build passed in Ubuntu
ARM64. External provider operations are **not** qualified by these checks.

Installed release: `qemu-provider-3.1.9`, sequence 10.
Manifest: `d3720281bf65048fee1e8d53a36172a616b8aff873dd84d58dfe31bedc359703`.
Bundle SHA256: `fc2d4aa12f6ed6fa08765a0da35066667e26db45fb02626459bdfe37870609d5`.
Evidence: `signed-provider-suite.log`, `provider-installed-status.json`,
`provider-journal.log` in the current Ubuntu ARM64 run directory and the task
transcript for socket and namespace checks. No additional downloads occurred.

A user choice is pending for material-consumer verification: constrained root
broker (permitted by the design) versus a separate privileged inspection helper
while retaining the dedicated key UID. No extra privilege, new helper or weakened
material verification has been implemented pending that decision. The disposable
original test signing key's admitted sequence range ends at 10. The later
sequence-11 upgrade documented above explicitly provisions a separate bounded
test authority; frontier checks remain enabled.

### Remaining product gates

- Assemble and install a genuine signed release with its package/artifact
  catalog and trust material in disposable guests. Do not bypass signature
  checks or infer installation from a successful Go build.
- Drive installed authentication/API/browser journeys and actual hosting,
  database, DNS/TLS, mail, application, backup/restore and migration lifecycles.
- Finish secure external application database configuration: the current
  certified runtime still limits host resolution to local MariaDB; clone TLS
  plumbing is not complete.
- Enterprise-engine, recovery/security/performance and full design-spec
  qualification remain unproven.
- Frontend build still emits a 528.66 kB JavaScript chunk warning. The recorded
  npm audit has one low-severity Windows esbuild development-server advisory;
  a complete installed-panel browser pass and a clean dependency audit are not
  claimed. Only the navigation component interactions described above passed.

No project builds, tests, or formatters ran on the macOS host. The host was used
for source edits, virtualization, artifact transport and evidence inspection.
After verification, the AlmaLinux ARM64 and both AMD64 guests were shut down.
Their overlays and logs are retained. Ubuntu ARM64 remains running on loopback
SSH port 22193 for the next installed-release work; its temporary Vite server
is stopped. No base images or evidence were deleted.
