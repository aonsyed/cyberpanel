# Platform implementation status

This file is the compact recovery point for ongoing implementation. The normative product design remains in `docs/superpowers/specs/2026-08-12-secure-cyberpanel-parity-platform-design.md`.

## Hard execution rule

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
that order is fixed and both real listeners passed a QEMU probe, but the new
executor binary still needs signed publication. Its restart loop is stopped.
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
