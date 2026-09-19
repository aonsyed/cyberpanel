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
test signing key's admitted sequence range ends at 10; further test releases
will need explicit test-authority provisioning, not disabled frontier checks.

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
