# Platform implementation status

This file is the compact recovery point for ongoing implementation. The normative product design remains in `docs/superpowers/specs/2026-08-12-secure-cyberpanel-parity-platform-design.md`.

## Hard execution rule

Latest candidate checkpoint (2026-09-20): `5b432d144` supports strict managed
release links for signed web catalogs/keys/repositories; all four affected Go
package suites and both binary builds pass in QEMU. Signed sequence 36 is built
at `/var/tmp/panel-web-catalog-3.1.35.tar`, NOT installed: host free space is
about 1.7 GiB, below the 3 GiB install guard. Release 35 remains active. Reclaim
host space before installing; then run the gated native catalog test and finish
initial verified web activation. Guest old bundles 33–35 are preserved together
in `/var/tmp/retained-mail-33-35.tar.zst`, with each extraction hash verified.
Production package-cache provisioning and web bootstrap remain incomplete.

Latest source checkpoint (2026-09-20): fixed web artifact validation rejecting
the actual native OLS `1.9.2-1+noble` package version. Regression reproduced and
full management suite passed in QEMU; signatures and identifier rules unchanged.
Not deployed yet. Next: signed engine catalog and initial verified web activation.
Verified duplicate staging sequences 21–24 removed, installed releases retained.

Latest installed checkpoint (2026-09-20): signed sequence 35 / `6ba18450a` now
passes actual installed SMTPS 465 and STARTTLS 25/587, including AUTH visibility
before/after TLS. All six mail services and their milter startup hooks are healthy.
Creating the new Rspamd link exposed executor /etc being read-only; the native
installer test established it. Source now reconciles fixed bindings in the
installer (replay verified), preserving the runtime sandbox; that final installer
wiring still awaits a signed release. Core gets past mail and fails at the
missing engine catalog/bootstrap configuration. Runtime Restart=no limits core
qualification to one attempt. No mailbox auth/message-delivery/API/UI completion
claim. See RUN-REPORT for signed hashes and exact limits.

Previous candidate checkpoint: Postfix internal services, scoped milter
socket grants and Rspamd Unix milter binding now pass native SMTPS and STARTTLS
on 465/25/587, plaintext AUTH denial, and unprivileged socket-access denial.
Installed edition inspection now accepts only the strict signed-release link.
All five affected package suites pass in QEMU. Candidate changes still await
signed deployment. Further web bootstrap is missing the signed engine catalog
and activated native configuration; OLS remains intentionally held. Removed
only verified duplicate committed staging sequences 25–32, preserving installed
releases/journals/archives; QEMU now has discard, a private QMP control socket and
a low-space build/install guard. Source and exact evidence are in RUN-REPORT.

Previous installed checkpoint: signed sequence 34 includes source `53322d734`:
native mail ACL isolation, ClamAV scan boundary, executor sandbox and OpenDKIM
PID-file fixes. All six native mail services start. Actual TLS IMAP CAPABILITY
and LOGOUT pass; SMTP TLS stalls because generated master.cf lacks proxymap
and other internal services. Core passes mail initialization but fails web-engine
installation inspection (not found); stopped its restart loop. Reboot exposed
PowerDNS cold-start recovery probing an inactive daemon; manually started pdns
and restarted executor, not yet a cold-boot fix. Core/full mail are NOT qualified.
Disk reclamation is enabled on the existing QEMU overlay and trimmed ~2 GiB;
compressing host archives losslessly. Complete sequence-33/34 bundles remain in
the guest. See RUN-REPORT for hashes, native evidence and remaining requirements.

The user's latest direction supersedes the earlier code-first testing deferral.
Close and verify the existing scope now. Run builds and tests only inside QEMU
guests on Ubuntu and AlmaLinux; distinguish package-suite results from live
installed API/UI/service qualification. Fix concrete failures without adding
new feature lanes or expanding the harness. Record the tested revision and
preserve run evidence; historical passes do not qualify newer changes.

## Closure scope freeze

This phase closes known production blockers; it does not discover or add new
product coverage. A worker must stay inside its assigned behavior and existing
interfaces. It may make the smallest compatibility change needed to connect
that behavior, but it must not introduce a new protocol, transport, subsystem,
capability family, or adjacent feature. If an existing interface cannot safely
express the requested behavior, the worker fails closed, reports the exact
residual blocker, commits only the bounded work that is independently correct,
and stops so the coordinator can make the scope decision.

Failure mode to avoid: expanding a replication-lifecycle fix into a federation
receipt redesign or a new cross-node transport. That is a separate architectural
decision, not completion of the assigned blocker.

## Worker lane scope rule

Every delegated coding lane is a bounded slice, not a subsystem rewrite. The
default hard limits are five changed files, 1,100 added lines in total, and 800
added lines in any one file. Reaching 70% of either line limit before the
requested production path is assembled triggers immediate narrowing; reaching
a hard limit triggers correctness-only cleanup and commit. A larger lane needs
an explicit exception from the coordinator before it grows, and splitting code
into fewer files does not bypass the line limits.

## Current position

Current candidates (2026-09-20, not yet signed/deployed) fix native Dovecot syntax,
provision a separate self-signed mail TLS fallback, include ManageSieve/Sieve
prerequisites, repair Redis/ClamAV native validation and generate OpenDKIM's
loopback TrustedHosts file. Native parser/positive-negative tests and four affected
suites pass; core/executor candidates are built. The next confirmed blocker is
daemon access: _rspamd cannot read its config through the root:root mail store.
Keep root-only mutation authority and qualify scoped native config/key access
before another deployment. Sequence 32 is still installed; core/mail are stopped,
DNS and executor admission active. Guest free space is 4.2 GiB. The 100-artifact
draft mail-validation-prereqs-spec.json has the two matching Sieve packages but
still needs the next sequence/version (33 / 3.1.32). See the latest RUN-REPORT.

Sequence 32 (2026-09-20) now deploys verified Ubuntu mail-default adoption and
the dedicated mail Redis config/unit boundary. Real Redis unit/socket and access
checks pass in QEMU; native mail binding reconciliation passes. Core gets as far
as staging mail configuration, then native doveconf rejects the renderer's
one-line blocks (`Garbage after '{'`, line 14). Fix native Dovecot syntax before
another deployment. Core is stopped; mail current link is absent after rollback,
retained generation is mailgen_99e5cb1dd2c2ee5de57928109134ad35-e4b640feb98c2072.
Do not reinstall mail packages over dangling config links without restoring the
verified original defaults first (backups remain). DNS and executor admission
are active. Guest free space is 3.9 GiB; sequence 32 archive remains in /var/tmp.

Newest checkpoint (2026-09-20, sequences 30–31): installed PowerDNS now runs on
normal IPv4/IPv6 TCP/UDP port 53; the real `rping` health probe passes. Executor
mutation admission is ready and survives executor restart. The startup effect
is completed at epoch 0 with three archived attempts, preserving its identity.
Native ACL/config credentials and exact-retained-generation recovery are deployed.
Default Ubuntu resolver handoff/replay preserves outbound DNS and frees port 53;
custom configurations are not overwritten. Core now fails at Dovecot OAuth
activation (`mail resource generation conflict`); its loop is stopped. Native
mail configuration binding is the next concrete blocker. Gateway/API/UI and
managed-zone/full-matrix qualification remain pending. Guest free space is
5.4 GiB after clearing disposable Go build cache; no installed state was deleted.
The chronological checkpoints below describe earlier states, not current readiness.

Latest release checkpoint (2026-09-20): the real ARM64 panel component is
assembled from all five signed PHP inputs and signed n8n/Hermes candidate
recipes. Signed outer node release sequence 15 now installs that component;
the installed binary completed authority/catalog initialization, receipt replay
and secret bootstrap. Sequence 17 now installs core/gateway/execd binaries,
units and configs. Sequence 18 now installs real OLS 1.9.2/LSPHP 8.3.33 after fixing
native package cycles via verified batch installation. dpkg audit is clean and
vendor binaries/modules execute. Real executor startup next requires the missing
container service identity/home, now provisioned through the existing installer.
Sequence 19 installs the engine-edition loader fix. Startup next exposed malware
socket initialization before siteops established shared-directory ownership;
that order is fixed and deployed in sequence 20. Actual startup next required
private native web config permissions; an installer reconciliation hook now
prepares these and passed an actual idempotent QEMU test. Sequence 21 installs
that hook and WP-CLI 2.12.0; actual reconciliation and WP-CLI invocation passed.
Sequence 22 restores /run/user inside the executor's ProtectHome namespace while
keeping home trees hidden; the executor runs, with mutation admission closed
until core schema initialization. Sequence 23 fixes core/gateway sandbox startup
on Podman nodes without a Docker socket. Actual core startup now reaches its
audit credential loader. Sequence 24 fixes that fixed-path check using the exact
root/service-user ACL and read-only tmpfs boundary; real systemd credential and
negative permission checks passed. Actual core now reaches domain assembly and
passes the database executor digest after sequence 25 adds validated managed
release resolution. Sequence 26 shares the verified private credential boundary
with webmail/campaign loaders; actual QEMU credential checks passed. Sequence 27
declares webmail state; actual directories are cyberpanel-owned 0700. Startup
sequence 28 initializes core admission schema before domain startup and makes
executor recovery wait for missing bootstrap tables. QEMU regression checks and
installed startup confirm it passes the former missing-schema blocker. Executor
now remains closed on a PowerDNS native configuration generation conflict.
The native file is verified pristine against dpkg and PowerDNS is inactive.
A new read-only preflight passes the real QEMU startup regression: config
conflicts now reject before acquiring execution leases. Updated executor is
built but not deployed. Installer adoption is now implemented: it checks pristine
package bytes, requires PowerDNS inactive, preserves a root-only SHA-256-named
backup and publishes the fixed managed link. Actual Ubuntu QEMU adoption/replay
and rejection fixtures passed; RPM remains unverified. Candidate panel binary is
built but not deployed. The test prepared the actual QEMU config; PowerDNS stays
inactive after adoption. Sequence 29 now deploys adoption, preflight and narrow
unapplied-startup recovery together. Real recovery archived the prior attempt
without changing request identity and reached native config activation. PowerDNS
then failed reading config as pdns:pdns under the root-only generation store;
rollback leaves no current link, but generation work now exists. Do not reuse
empty-store recovery: fix native service access and reconcile actual generation
state. Native access is now implemented and QEMU-proven: fixed pdns UID gets
traverse-only store access and RW to the live DB/WAL/SHM through exact ACLs,
without directory writes or control.db access. Installer config delivery uses
systemd credentials; native activation restarts to repin the config. A real
pdns-UID service started and answered an unconfigured loopback test query;
native SQLite INSERT/ROLLBACK and isolation checks passed. These changes are
not signed/deployed yet; tests prepared ACLs/drop-in. Do not restart the old
executor, which resets those permissions. Reconcile the retained generation and
ambiguous effect, deploy new binaries, then qualify normal native startup.
Core and PowerDNS restart
loops are stopped. Five older bundle copies were safely offloaded with matching
hashes; installed state was not deleted. Guest now has 3.1 GiB
free; safely recover storage before more bundles. Verified sequence 21–27
archives were moved to host storage, freeing about 1.9 GiB. Executor readiness and
core/gateway startup are not yet proven.
Continue startup and API/browser qualification. OLS remains held stopped until
managed configuration is ready.
The existing guest disk was safely expanded to 40 GiB, removing the repeated
staging-space constraint. Native release sequence 16 installed real
mail/DNS prerequisites installed, dpkg audit clean, external services held stopped
pending configuration. The offline package runner now supplies isolated active
loopback; Postfix setup passed without external networking. Native Ubuntu rootless Podman rejects AppArmor profiles despite
kernel AppArmor being active; preserve the MAC requirement and resolve that
runtime limitation before declaring container integration operational. Exact
artifact hashes, evidence and remaining limits are in `RUN-REPORT.md`.
Fixed-generation inherited AppArmor confinement is now implemented in the
native launcher and admission path. Real QEMU container checks cover identity,
allowed/denied reads and rejected unconfined transitions. Installer policy
provisioning is implemented; persistent publication, kernel-state replay and a
real Ubuntu ARM64 reboot passed. Native AppArmor boot loading retained the exact
enforcing generation and post-reboot container admission/confinement passed.
The signed installed panel's initialization hook also passed. Safe retirement
and complete sandbox qualification remain pending. No unconfined MAC fallback
was enabled. Both component archives were offloaded to checksum-verified host
copies; the guest retains signed node payloads, catalog and source inputs.

Latest executable verification is recorded in `RUN-REPORT.md`: the current
application database/TLS changes passed the full uncached Go suite in Ubuntu
ARM64 QEMU. Revision `458fd7876` then passed offline module verification,
uncached full Go suites and builds on AlmaLinux ARM64 and both AMD64 guests.
Live database/broker component evidence remains Ubuntu ARM64 only.
Frontend strict compilation and desktop/mobile install/clone drawer interactions
passed against controlled API boundaries, not an installed panel. The current
JavaScript bundle is 529.78 kB and retains the size warning.

WordPress now resolves the selected database through protected ownership/state
records, uses a pinned CA and optional separate application client identity,
keeps TLS material outside the document root, and verifies TLS for WP-CLI imports
as well as runtime connections. Real WordPress/PHP/WP-CLI/MariaDB TLS and mTLS
component checks passed; other certified applications' external database runtime
support remains incomplete. Install/clone identity enrollment and private drawer
inputs are wired. Purge cleanup errors and partial clone failures retain recovery
states; staging failure journals survive cancellation and SQLite reopen.

Next gates remain full signed panel installation and live API/service journeys, partial-clone
recovery, and live service qualification across the supported OS/architecture
combinations. Component tests do not establish full product parity.

Later Ubuntu ARM64 work installed a signed **authentication component** release
and exercised the real authd socket as the control-plane account: password and
API-key enrollment/verification/revocation passed. Signature tampering and an
older release were rejected without changing installed state or restarting the
daemon. This closes a component integration gate, not full panel installation.
See RUN-REPORT.md for source changes, failed-install evidence, the disposable
fixture reset, and the precise remaining qualification limits.

The signed component fixture now also runs the secret broker. Its live management
enroll/replay/rotate/revoke checks and unauthorized-peer rejection pass; a failed
signed upgrade now restores the previous auth-only release. Both current
services have zero restarts. The approved peer inspector now resolves cross-user
executable identity while the broker retains its dedicated UID and empty
capability set. Installed material delivery and rejection of a mismatched digest
passed with disposable root and control-account consumers in Ubuntu ARM64.
Production provider/service journeys and full panel testing remain unqualified.

The installed QEMU fixture also runs the provider worker. Its socket boundary
and mount-namespace denial of control.db's directory are verified; external
provider operations are not. The node installer now preserves shared-parent
traversal while retaining private child permissions. The user approved the
recommended separate privileged inspection helper on 2026-09-20. Keep the broker
on its dedicated account; implement socket-descriptor-based inspection and
reverification without arbitrary PID/path input. This decision is settled; do
not ask again. The signed sequence-13 fixture installs and runs this helper;
complete product installer/catalog integration and broader qualification remain.

### Verified checkpoint, 2026-09-19

- Saved QEMU Go-suite exits are zero for Ubuntu/AlmaLinux ARM64 at
  `6348dbf323` and Ubuntu/AlmaLinux AMD64 at `624fd0abd`. Each log has 17
  passing packages and 94 packages without test files. These are not installed
  panel, browser, live API, or full service-lifecycle qualification results.
  Evidence: parent repository `.work/qemu/runs/closure-*-20260919-01/`.
- Upstream stable synchronization (`9be6c087c`, 181 incoming commits) and
  default `v3.0.5-dev` alignment (`17fc2e603`, 21 additional commits) changed
  no `platform/` files. The latter alignment also removed stable-only changes;
  merged Git ancestry is not proof of Go behavioral parity.
- The six platform feature commits after `6348dbf323`, through `da547a90b`,
  and the uncommitted application database-placement slice are not covered by
  the above successful runs. Do not label them verified.
- Application external-database placement is unfinished: certified runtime
  host resolution still accepts only the local sentinel, and cloned WordPress
  configuration does not yet configure pinned remote TLS. Endpoint selection
  alone must not be treated as secure external application DB support.
- Next gates: current-source QEMU compile/tests; close observed failures;
  actual installed API/UI/service journeys; remaining OS/architecture matrix.
  Do not resume broad feature discovery as a substitute for these gates.
- Current Ubuntu ARM64 smoke run: guest boots with Go 1.26.5. The initial
  offline full suite/build was blocked by absent pinned modules; the user then
  authorized downloading them. `go mod download` and `go mod verify` succeeded.
  Full compilation exposed a stale `n8nPrerequisiteError` reference after the
  shared container error type was renamed; that reference is now corrected.
  `full-current-fixed.log` records `go test -count=1 ./...` and `go build ./...`
  both exiting zero: 18 passing packages and 93 without tests. The application
  regression cases now also pass in the full Linux package, not just the
  portable slice. This covers HEAD `da547a90b` plus the current code changes;
  initial source manifest and `fixed-source-sha256.txt` identify the snapshot.
  This does not establish installed UI/API/service qualification or the other
  three OS/architecture combinations. Evidence is in
  parent `.work/qemu/runs/current-ubuntu-arm64-20260919-smoke/`.
  `focused-baseline.log` reproduces four database-binding validation failures;
  `focused-fixed.log` proves all 11 cases pass after the engine/placement/TLS
  guards. This executes the exact portable application sources inside QEMU,
  excluding Linux-tagged adapters, and does not qualify the full apps package.
  Tested `executor.go` SHA256:
  `e6dfc10e78058209c94c38eef9d53ca1311ae8a2d6e7811a85c3fc9d24b57ac9`.
- Verified module downloads are retained outside disposable guests in parent
  `.work/qemu/downloads/go-module-download-cache-20260919.tgz` for reuse.
- The same guest reproduced discarded journal-write errors during install
  compensation. Cleanup now preserves those errors and signals recovery when
  its progress or result cannot be persisted. `compensation-baseline.log`
  records three failing cases; `compensation-fixed.log` records all four
  compensation cases plus the 11 binding cases passing. These use the real
  portable service with injected journal/cleanup failures, not a live database.
  Tested `service.go` SHA256:
  `3d9fc9bd15648ad99d7cc879db0019c151ae1ed29c5d58872a17b732b98ce92f`.

- Implemented production core: tenant/site/domain lifecycle, durable command
  admission, node-wide composition, OpenLiteSpeed and LiteSpeed Enterprise
  renderers, immutable generation storage, activation/probe/rollback, engine
  runtime control, LSAPI/PHP site provisioning, root-owned activation
  attestations, and the local privileged executor daemon.
- Implemented production resource domains: identity/tenancy/RBAC/authentication,
  DNS and certificates, databases, files/FTP/SFTP/SSH/terminal/cron/Git/staging,
  backup/restore/transfer, mail/webmail/marketing models, WordPress and the app
  catalog, containers, secrets, audit, host operations/resource controls,
  provider integrations, and HA/failover.
- Implemented optional federation: outbound node protocol, grants, capability
  negotiation, durable intent/event spools, signed receipts, central
  projections/sagas, revocation-first delivery, and reconnect-safe intent
  replay.
- Implemented executable edges: gateway/core UDS split, immutable SPA serving,
  authenticated versioned API catalog, `panelctl`, recovery claim/trust CLI,
  purpose-bound write-only secret enrollment/rotation, MariaDB broker, and the
  privileged OLS/LSE activation broker. CyberPanel and cPanel extractors now
  produce source-neutral signed migration material with typed cutover fencing.
- Implemented installer/upgrade lifecycle: signed tuple catalog, exact
  Ubuntu/Alma and amd64/arm64 plans, A/B activation, rollback watchdog,
  service/config deployment, protected state initialization, and retained
  uninstall export.
- Concrete Linux brokers are now present and composed for site provisioning,
  web-engine activation, MariaDB, host operations, access/file/Git/cron,
  Postfix/Dovecot configuration and queue control, PowerDNS authority and
  DNSSEC, rootless containers, and certificate deployment. Access helpers are
  packaged as a signed executable bundle with exact Ubuntu/Alma dependencies.
- Certificate issuance now includes protected ACME account/key material,
  Let's Encrypt production/staging endpoints, HTTP-01 and targeted DNS-01,
  immutable certificate generations, and deployment to web, panel, and mail
  consumers. PowerDNS uses a protected local SQLite authority by default.
- Container workloads and signed container applications are composed into
  panel-core with rootless policy, brokered storage/network/exposure, and
  OLS/LSE proxy activation. The named n8n and Hermes Agent products have
  signed, digest-pinned recipes, protected secret slots, durable lifecycle
  state, backed-up volumes, and domain-only exposure; actual release recipes
  and QEMU lifecycle qualification remain external gates. Container command execution now uses an MFA-gated,
  expiring, one-time token exchange whose token is never persisted in
  plaintext; the browser console generates and exchanges that token locally
  and exposes only the bounded execution receipt. Local backup repositories, stable-view capture,
  durable retention, verified restore reading, scratch staging, and guarded
  blue/green promotion are composed through the privileged backup broker.
- Webmail now uses opaque mailbox sessions, active mailbox/domain resolution,
  TLS IMAP, STARTTLS SMTP submission, MIME and attachment handling, contacts,
  Sieve listings, draft persistence, and a conservative HTML sanitizer.
  Dashboard, DNS/DNSSEC, certificates, mail diagnostics/routes, webmail, and
  backup policy/restore-plan console journeys are bound to concrete services.
- The Linux WordPress runtime, signed application catalog, database/secret
  provisioning, lifecycle/update/rollback, LSCache, snapshot recovery, and
  one-time autologin bridge are composed. The application console now binds
  tenant-scoped inventory, signed-recipe install/update, recovery-guarded
  removal, malware scanning, and LSCache purge to those runtimes. Bootstrap
  administrator material is held in a durable broker-lease record and revoked
  after use; the autologin API binding is now present, with its runtime behavior
  still awaiting QEMU verification. Database, access/file/credential,
  container, and host-operations console adapters are also concrete.
- Identity tenancy/entitlement projections and mutations are now connected to
  the authenticated actor context and composed at startup. Migration
  list/create/inventory/plan and security finding/scan/remediation/suppression
  console adapters are concrete; migration sync/cutover are now advertised by
  the concrete migration edge. Their end-to-end behavior is not yet qualified.
- Integration binding list/create/rotate/health/delete now has a concrete,
  tenant-scoped console edge and write-only secret-broker enrollment,
  digest-bound rotation, and revocation plumbing. Cloudflare, AWS S3, Wasabi,
  and Backblaze B2 S3 are executed by a separate non-root provider daemon with
  public-network-only transports and executable-digest-bound secret leases.
  The provider executable and hardened systemd unit are part of the closed,
  signed installer bundle; schema-only provider kinds are not advertised.
- Production runtime code also exists for Joomla, PrestaShop, Magento and
  Mautic. Signed release recipe/artifact packaging and actual lifecycle
  qualification remain outstanding; runtime source alone is not certification.
- In progress: remaining runtime connections, installer provisioning, package
  maintenance outcomes, optional federation lifecycle, migration conversion,
  and signed application release inputs.
- QEMU qualification is active, not deferred. Saved runs are under the parent
  repository's `.work/qemu/runs`; reconcile their revisions before claiming
  current qualification.

## Scope truth

The codebase is now a broad greenfield production implementation, not merely a
first-site slice. It is not yet a completed or qualified parity release:
remaining work is the final concrete-adapter and process composition pass,
frontend journey completion, and the QEMU-only
compile/test/review/hardening program.

## Resumed implementation, 2026-09-07

- The pre-pause integration head was `436e964a`: source extractor packaging,
  signed product-update feed ingestion and protected malware approval issuance
  had been integrated. No QEMU release qualification had been performed.
- Package reboot-requirement publication is now connected to the durable reboot
  repository (`ae6a8534`); this records evidence, not an instruction to reboot.
- Eight bounded workers resumed the saved worktrees: central enrollment and
  lifecycle; HA remote dispatch; legacy backup conversion; package maintenance;
  privileged reboot markers; malware authority bootstrap; offline update import;
  and source container export. Workers commit production changes separately for
  integration. Partial changes remain unqualified until the QEMU phase.
- Earlier percentage figures were rough planning estimates, not measured parity
  coverage. Commits and source line counts do not establish a working release.
