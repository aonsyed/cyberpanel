# Platform implementation status

This file is the compact recovery point for ongoing implementation. The normative product design remains in `docs/superpowers/specs/2026-08-12-secure-cyberpanel-parity-platform-design.md`.

## Hard execution rule

Production implementation is the only active priority until the full product
surface exists. Do not create test-only slices, run tests, perform review
passes, expand the harness, or build parity-harvesting infrastructure while
production functionality remains unimplemented. Existing tests stay parked.
After the complete production implementation exists, run the full QEMU-only
test, review, hardening, and qualification program on Ubuntu and AlmaLinux.

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
  OLS/LSE proxy activation. Container command execution now uses an MFA-gated,
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
  and application release packaging. The n8n model/coordinator exists but its
  concrete container adapter and product entry points still need implementation.
- QEMU qualification is deliberately deferred until the production surface is
  coded, per the hard execution rule above.

## Scope truth

The codebase is now a broad greenfield production implementation, not merely a
first-site slice. It is not yet a completed or qualified parity release:
remaining work is the final concrete-adapter and process composition pass,
frontend journey completion, and then the deferred QEMU-only
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
