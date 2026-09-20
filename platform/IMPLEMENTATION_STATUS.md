# Platform implementation status

This file is the compact recovery point for ongoing implementation. The normative product design remains in `docs/superpowers/specs/2026-08-12-secure-cyberpanel-parity-platform-design.md`.

## Hard execution rule

## Native dependency ownership boundary — user correction 2026-09-20

Use normal vendor/distribution OLS/LSE and related packages, following the native
CyberPanel installation model. No custom OLS, LSQUIC or ModSecurity builds,
forks, patches or product version pins. Panel configuration/service integration
and QEMU qualification remain our responsibility; inventory is not a version pin.

## Current recovery point — installed export fix, 2026-09-20

Supersedes the installed51/source-only statements in the historical entries below.
Installed53 `qemu-dbexport-3.1.52`, rollback52 retained. Manifest
`a86b11f2e4bec45397b732579379e6f78f7caaf2db1e784fde8e1e8111c57419`;
receipt `99a00d8cccc9c535eabcbce3e14088e3bcf65834a6f6a3dab1fac0387ba3589c`.
Core/gateway/execd process executable paths rechecked against that installed root.

Installed52 exposed export403: root executor records retain applied effect-input
metadata (Provisioning/Pending), while the coordinator separately projects its
confirmed SQL records to Ready/InSync. Export authorization incorrectly required
the coordinator projection in both stores. Corrected the executor check without
removing tenant/site/generation/expiry/principal checks or canonical readiness.
The native regression now models these separate states. QEMU database, apiserver,
cyberpanel and panel-execd suites pass against matching host/guest source hashes.

Installed53 real Chromium workflow previously passed SQL and gzip prepare200,
export201, download200, expected text/binary content and complete SHA256 checking,
plus passkey login, console query, mutation denial and 390px interaction. No mocked
export responses or candidate UI interception were used. See RUN-REPORT.md.
Generated SQL table/artifacts and redundant guest release bundles were removed;
current and rollback releases retained. Latest guest free space: 4.6GiB.

Next: automatic export retention collection, larger asynchronous transfers and
production isolated import. Current console export bounds remain 1MiB/30s/1000
estimated rows; actual streamed row accounting, routines/triggers/events, external
DB transport and full OS/architecture/edition qualification remain open. This is
not completion of database parity or the overall goal.

## Historical checkpoints (newest first)

EXPORT API/UI SOURCE CONNECTED: coordinator prepares sealed jobs from current
workspace/database metadata and derives access again for execution/download.
Added MFA/database:console site-scoped export_prepare, export (mutating with
idempotency), and export_download contracts. Caller cannot supply WorkspaceAccess;
tenant/site/generation/actor come from the authenticated invocation/session.
Console UI offers SQL/gzip, downloads bounded chunks, checks chunk + full SHA256
before saving, and shows progress/errors. QEMU native coordinator→broker→MariaDB
round trip passes; HTTP prepare policy/scope/negative checks pass with explicit
auth/domain fixtures. Candidate Chromium UI SQL/gzip downloads, corrupted-digest
denial and 390px layout pass with MOCK export responses; existing login/console
queries remain live. UI typecheck/build pass (538kB chunk warning remains).
NEXT: install and verify the connected API/UI against real exports; installed51
is unchanged. Workspace caps currently inherit existing console limits (normal
session 1MiB/30s/1000 estimated rows); larger async jobs are still required. Native
row accounting is presently based on preview estimates. Production import,
retention collection, routines/triggers/events and wider matrix remain pending.

DATABASE EXPORT DOWNLOAD PROGRESS: added workspace_export_read broker operation
with <=256KiB chunks, exact descriptor/offset/length/EOF/digest binding, and fresh
protected session/database/principal/instance authorization for EVERY read.
Read-only path neither issues credentials nor journals dump bytes. QEMU private
Unix broker downloads reconstruct both SQL/gzip exports with exact SHA256; EOF,
bad bounds/digest/expiry and revoked-session denial pass. All database/core/execd
package tests pass. Source only, installed51 unchanged. Next is core/API/UI wiring
for these export/download methods, plus production import, async large exports,
retention cleanup and broader qualification. The overall goal remains incomplete.

DATABASE EXPORT BROKER PROGRESS: closed workspace_export client/server operation
now calls the real Linux executor/session credential provider/native dump and
publishes artifacts under protected database/transfers storage. Destination is
derived from the full export specification; request/receipt matching rejects
mixed operations and unrelated artifacts. Reboot admission journals the effect
and replays its original receipt. Executor-level artifact recovery reauthorizes
the session and does not rerun the dump. A preflight preserves 2GiB guest free
space beyond the requested maximum (not an aggregate quota reservation).
QEMU actual private Unix socket → framed broker → SQLite reboot admission →
native scoped account export → plain/gzip import passed, including journal and
artifact replay. Peer authentication and secret delivery are fixtures; native
execution, framing, admission and protected-resource checks are real. Full
database/core/execd suites pass. Installed51 unchanged. Next: authorized artifact
download and user-facing API/UI, production isolated import and larger async
transfer jobs (workspace exports intentionally inherit session size/time bounds).
Full parity, retention collection and the OS/architecture/edition matrix remain
unfinished; no additional native dependency work is needed for this step.

DATABASE EXPORT CREDENTIAL FOLLOW-UP: added LinuxWorkspaceExportConfigs, which
revalidates protected session/database/principal/instance state and resolves the
session credential through the existing purpose-bound secret source. It enforces
tenant/site/generation/name, readiness, session resource/connection bounds and
expiry; native transfer processes inherit credential expiry. Actual QEMU plain
and gzip exports now use a SELECT/SHOW VIEW-only native account. Cross-database
and write denial, stale/disabled/expired/mismatched access and credential-file
cleanup pass. Database, cyberpanel and panel-execd package tests pass in QEMU.
Only secret delivery is mocked for export; import still uses a root fixture.
This is source integration with the native transfer backend, NOT a deployed or
UI/broker-wired feature. External-instance exports, production isolated-import
credentials/catalog/promotion, transfer service wiring and retention cleanup
remain pending. Preserve the full parity scope; do not call this feature done.

DATABASE TRANSFER SOURCE PROGRESS (not deployed): added the missing Linux artifact
store used by the native MariaDB transfer backend. Root-private bounded streaming,
SHA256/size checks, atomic publication, immutable generations, abort cleanup,
expiry checks and persisted retention/legal-hold metadata are implemented. QEMU
Ubuntu ARM64 full database package tests pass, including actual mariadb-dump →
artifact → mariadb round trips for plain SQL and gzip with NULL/binary data.
The live test uses a root client-config fixture: least-privilege credential
provisioning, transfer catalog/promotion, executor/API/UI wiring and retention
collection are STILL PENDING. This is not a finished user-facing import/export
feature. No vendor binaries/packages were changed or downloaded; fixtures clean
up their databases/configs/artifacts. Installed signed51 remains unchanged.

LATEST RECOVERY POINT (supersedes deployment statements below): installed signed51
qemu-recovery-3.1.50, current51/rollback49. Manifest
2d437a4005a10afd8fd085954919dd3da8e11156de38c857d0a54819b3fcfbbb;
receipt6b4428abe69ef69267572963869c1772a555790c892bbe976d6a6fc4b201aaeb.
Core/gateway/execd/broker all verified executing installed51 paths and active.
No candidate broker override or binary;
gateway localhost HTTPS/passkey fixture remains. Real installed UI password and
passkey login200, database.list200, console.issue201, metadata/query200; correct
database rendered, mutation rejected400, recovery query200,390px layout PASS.
Mail manifest unchanged through rollback. This Ubuntu ARM64 upgrade, injected
gateway failure/rollback, rejected retry and next upgrade needed NO manual service
recovery. Full distribution/architecture/edition matrix remains pending.

FAULT/RECOVERY PROOF: signed50 deliberately contained a failing PANEL gateway
ExecStartPre and changed executor6dc26f46... (not a vendor change). Authority moved
forward then restored; gateway failure produced rolled_back receipt5560667132...
and actual services returned to49. UI login/passkey/query all pass after rollback.
Retry50 stayed rolled_back without reactivation. Signed51 with normal gateway and
new executor then committed; same UI checks pass again, credential still version1.
Authority now matches installed executor6dc26f46e3e6cd36078c9bda7bc7ebeba6ca445987b5e5fc744f6dcf620ebeca.
Trying50 after51 rejected the old source frontier without changing active51.

DISK LEAK FIX: completed releases retained ~481MiB duplicate staging EACH. Added
bounded root-owned/digest-matched cleanup after Apply (including admission rejects)
and durable completion/recovery. prune-staging verifies current/previous retained
trees before removing their extraction copies; recovered ~1GiB from48/49. QEMU
tests cover symlink/root/mode/digest/traversal rejection, replay and retained-file
safety. Live50 rollback+retry,51 commit and50-after51 rejection all remove staging.
Current51/rollback49 retained. Fault50 root/bundle archived then removed; bundle51
archived then guest duplicate removed. Guest3.1GiB free. Native dependencies untouched.

Credential fix: root-only signed consumer-release authorization, NOT secret
rewriting during upgrades. Version-sensitive consumers retain original version/
binding; existing principal remains version1, binding1ff23cac..., original anchor
12dd0aad... approved for installed executor6dc26f46.... Root installer pairs exact
binary destinations from verified retained/current manifests; broker atomically
records bounded transitions and rejects stale/conflicting replays. Tenant,
adapter, operation and live process identity checks remain. Broker grants AND
delivery recheck authority; pre-upgrade grants cannot deliver to retired binary.
Tests cover unchanged credential/material, chaining, rollback, stale/non-root and
cross-audience denial, transactional failure without partial authority. Existing
explicit RebindConsumer primitive remains, but is NOT the release upgrade path.

Signed48 committed with frontend failure: repeated provider restarts exhausted
core start limit; recovered manually. Fixed installer: quiesce frontends once,
probe providers in dependency order, authorize after broker readiness, then probe
signed execd/core/gateway even when old manifest service list omitted them. Signed49
verifies that fix without manual starts. QEMU secrets/noderelease/architecture
suites and installer build pass. `/home/harness/bin/panel-node-install-native`
is updated; system bootstrap installer path has NOT been updated/qualified.
Remaining next: broader interruption/failure cases, ordinary native CRS paths,
writable SQL/import/export parity, broader service journeys and current four-target
matrix. Compatibility with incomplete historical development releases is not an
additional product requirement.

Storage: obsolete guest releases28/29/30/45 and47 removed after verified ignored
host archives; redundant48/49 bundles and candidate binaries removed. Current51/
rollback49 retained. Archives under main repo .work/qemu are recoverable; no
downloads, workers, third-party builds or committed binary artifacts.

LATEST INSTALLER FIX (source, not deployed): native offline package phase now
skips EXACT already-configured packages instead of rerunning every postinst on
each panel-only update. All package input metadata/inventories still verified
before any mutation; missing/different/partial packages remain one native batch;
post-state evidence checked for every artifact. Real QEMU dpkg fixture reproduced
postinst counter2 on unchanged replay before fix; passes after fix (counter1).
Upgrade, downgrade, unpacked-package recovery and all-input preflight pass too.
Entire noderelease suite passes. Tiny panel-owned fixture package/counter cleaned;
no vendor package/source rebuilds. This prevents needless conffile changes during
panel-only upgrades, NOT proof of safe actual native-package upgrades. Rebuild
panel-node-install-native with this fix before next signed release. Signed46 still
running; console/WAF changes also await that release. Guest2.5GiB free: reclaim
obsolete artifacts with current46/rollback45 preserved BEFORE another bundle.

LATEST DATABASE CHECK (2026-09-20): installed46 UI created qemu_ui46 and principal
qemu_user46, both201; native MariaDB confirms charset/collation and actual principal
login/create/insert/select. Ungranted UPDATE and mysql.user access denied1142.
Temporary query table dropped. DB/principal remain small guest-only fixtures;
password exists only in guest0600 fixture, never source/Git/tool output.
Found Open console400: UI sent no usable session. Implemented server-derived
session from tenant/database/generation and a ready granted principal; principal
options projected by name, credential reference stays server-side. Added console
UI with schema/query results, expiry, bounded queries, error recovery and mobile.
QEMU candidate core+gateway+UI: console201, metadata200, SELECT DATABASE()200 and
expected name rendered; mutation rejected400, subsequent SELECT200,390px layout
passes. Go affected suites, tenant/site/instance/disabled/no-grant/generation and
replay regression pass; UI typecheck/build pass. Console currently uses existing
read-only workspace API; writable SQL/import/export parity is NOT claimed.
Candidate needed normal slot layout/signed recipe companions and matched gateway
contracts. Removed temporary service overrides after testing; signed46 restored.
These console and prior WAF changes still need a signed release deployment.

CURRENT SOURCE CHANGE (not deployed): removed packaging/native/build-waf-crs.sh.
WAF asset evidence now inventories installed root-owned CRS files directly;
it no longer requires the cyberpanel-waf-crs package's runtime.sha256. Root-owned
rules updates change the recorded digest without a panel rebuild/version lock.
Ownership/mode/symlink/hardlink checks and bounded file/byte counts remain.
QEMU targeted tests and installed asset check pass. Version-specific mapping
reference removed: renders a trusted installed mapping from conventional native
locations or a single discovered installed-release directory. Mapping bytes are
included in activation evidence, even outside the CRS tree. Missing, writable or
ambiguous assets fail closed; no download/build fallback. Actual installed OLS
parser accepted generated policy with both installed and unversioned mapping
paths in private mount namespaces. Installer replay preserves managed policy and
rejects silently replacing an initial policy when installed mapping changes.
Live services remain signed46; guest custom CRS package NOT yet replaced.
Remaining: support/qualify normal native rules configuration paths and replace
the guest package without losing policy.
Do not resume third-party builds or claim native rules installation complete.

LATEST UI CHECK: signed46 actual browser password/passkey login, fresh tenant
site/file listings pass. Trashed qemu-ui-created.php and qemu-ui-upload.txt through
UI: both access.trash.move201, rows removed, both native URLs404. Recoverable trash;
no permanent deletion. Fresh pool s-fe852e1325344b402b32c638-g2 active with NO drop-ins.
All four panel/web services active. Guest2.6GiB free; no new downloads/bundles.

LATEST INSTALLED: signed46 qemu-site-3.1.45, current46/rollback45. Contains core
startup retry/PHP journal fix, UI layout, strict executor sandbox, identity/web
recovery, vendor-service reload, permanent health probe, public/socket ACLs.
Manifest86dd65bef7da361ea0b379448f5db58561d2118d59668069492801a25d9b86f0;
receipt84022b6ceb4a30a215df9a93034cb5f22f4c27f218a8496a9b549541b5073cf5.
Core/executor use installed binaries; executor candidate/strict/diagnostic overrides
removed and three unused candidate binaries deleted after process-map checks.
Gateway localhost HTTPS fixture remains. Existing g2 pool retains runtime drop-in
99-qemu-web-access.conf, now invoking INSTALLED panel-execd helper. Fresh provision
must prove generated unit needs no drop-in. Installed UI real browser login/passkey,
site list,1280/1920/1024/collapsed/390 mobile checks PASS. No candidate static routing.
Unattended upgrade still NOT qualified: needed byte-identical WAF ownership repair,
mail service start and exact ClamAV config metadata repair. I invoked the existing
non-executable mail-restore script without sh; it did not run, while installer
continued and committed. Package installation changed only sealed clamd.conf mode
0440->0644/GID112->0; content hash unchanged. Restored manifest metadata under hash
guard; all mail artifact metadata/hash checks clean, core readiness restored.
Temporary mail diagnostic logging removed from source and guest. Next automate
upgrade conffile protection/reconciliation and test fresh site create/upload/restore.
Obsolete31/32/33/43 archived to ignored host obsolete-releases-31-33-43.tar.gz;
gzip and manifests verified, exact guest roots removed under lock/map checks.
Current/rollback retained. Guest2.7GiB free after bundle install; bundle46 retained.

Latest PHP SERVING checkpoint: actual tenant PHP returns200/expected output, also
after native LSAPI pool restart. Application-created static file returns200 too.
Fixed public-tree access using named cyberpanel-web ACLs: traverse generation/
releases/current/shared; read/traverse plus default inheritance only public/uploads.
Private/session/config trees untouched; QEMU subprocess tests prove web cannot
read private data and unrelated tenant UID cannot read public/private data.
LSAPI socket helper runs as owning site account (NOT root), checks fixed identity/
path/owner/socket, grants only web worker traversal/connect; generated unit invokes
it after every start. O_PATH root traversal is required for0711 runtime root.
Source changes not yet packaged. Candidate helper binary qemu-execd-public-access
is referenced by g2 pool runtime drop-in99-qemu-web-access.conf; installed45 helper
does not support it yet. Main executor still previous qemu-execd-site-recovery.
Existing g2 public ACLs repaired through bounded guest diagnostic --host-public;
future provisions use EnsureDirectories integration. GNU install stripped a static
fixture ACL and it returned403; app-created/inherited ACL file passes. Existing
uploads/restores/imports must preserve/restore ACLs; not broadly qualified yet.
Removed all three temporary public fixtures after checks; ignored host sources
remain reproducible. Next package accumulated panel changes, verify fresh create
without fixture repairs, upload/restore ACL behavior and cross-tenant socket denial.

Latest SITE PERSISTED checkpoint: guarded restored-generation activation recovery
implemented and QEMU candidate executor deployed. Requires exact completed ambiguous
replacement with rollback restored, matching confirmed master/current and live
previous-generation health. SQL old lease preserved; full prior activation receipt
archived in recovery-b4d4db007bede2bb82a9f04535291d4cc1fd88b453b143a7454fefbb6f043118.json.
Original create AND original _active command now applied/confirmed via production
service diagnostic, one hosting_sites row, generation2. No new create request.
Live tenant health returns70d2d2befb8795563b58bfe34730d7779c3d04fc88f3e547b5ad3ace22a52129.
Actual PHP fixture returns403: native cyberpanel-web cannot traverse tenant-owned
0750 roots/releases/current/public; no public ACL exists. Next fix panel-managed
public-tree access without exposing private PHP/session/config trees or weakening
tenant isolation, then rerun real PHP/static/UI workflows. Do NOT call serving done.
Ignored fixture qemu-panel-smoke.php is present in guest site g2 public tree and
host .work/qemu; remove after verification. Candidate overrides remain; signed45
unchanged. Core/gateway explicitly restarted after executor update.

Latest reload/probe checkpoint: candidate executor rebuilt and restarted with
systemd reload mapping. Guest diagnostic --reload invokes actual FixedRunner in
the real executor mount namespace: exit0. Native default.invalid health route
returns exact confirmed98515aa557ad729626e3ec2119b46d0b6e1b6f401cf7184866afc7b5267865b4,
matching .panel-state/current. New tenant health hostname returns404 under that
previous generation, exposing an independent rollback-probe bug: selected first
tenant binding instead of permanent system binding. Source now prefers
binding/system-default; QEMU regression failed before/passes after, four affected
suites pass. Probe change NOT in running candidate yet. Next: guarded replacement
activation recovery using matching restored master/current and live stable health
proof, not stopped-first-install recovery. Site still not finalized.

Latest activation checkpoint: guest diagnostic --complete reconstructs the exact
original CreateSite command (same commandID/scope/input; repository validates
digest) through production service/catalog/controller and native brokers. Create
remains ambiguous: candidate5cef48be... restored previous98515aa5... on disk but
both reload attempts failed. Root cause reproduced in actual executor namespace:
direct lswsctrl cannot write native logs (ro filesystem) and cannot see native PID
(PrivateTmp). Source FixedRunner now maps the closed reload request to systemctl
reload lsws.service, leaving vendor ExecReload/script untouched. Exact systemctl
call from executor namespace succeeds; OLS active, four affected QEMU suites pass.
New mapping NOT yet built into running candidate executor. Next rebuild it and
recover replacement activation only after proving the prior generation is live;
existing recovery supports initial/stopped activation only. Do not delete receipts.
Original activation effect wa-82aa3834aa8e5880bed68672101109eb5a584c5912ebfb8c9fc4210427d2016a.
No successful site-create UI/API or serving-site claim yet.

Latest recovery checkpoint: original site effect is now PREPARED through the real
QEMU executor protocol. Initial identity attempt2 completed, directories and PHP83
LSAPI pool completed atgeneration1; native pool service active/running. Outer
siteops admission rows all completed; original hosting command still ambiguous
and hosting_sites still empty. Next: original command's web activation/final commit,
not another create request. No site-serving success claimed yet.
Executor candidate /usr/local/libexec/cyberpanel/qemu-execd-site-recovery is active
via /run/systemd/system/panel-execd.service.d/99-qemu-site-recovery.conf (strict
filesystem override remains). Signed45 unchanged. Recovery only permits exact
initial identity records: allocated/failed host operation or active/completed,
no roots/pools, matching scope/digest/fence. It reuses the existing admission
recovery transaction, preserving previous attempt and reboot gating. QEMU tests
cover unsafe records, active admission, changed epoch and stale settlement.
The native retry used original accepted request through the guest-only diagnostic,
not UI resubmission or DB/journal reset. Core restarted afterward.
Redundant45 tar moved to ignored host .work/qemu/panel-tenant-3.1.44.tar; both
SHA256 values match a0026d61bc6e05d3bdcb408749244013e598704fe1a1b7c4911f029381b5ee8c.
Guest copy removed under installer lock; current45/rollback44 intact; guest2.5GiB.

Latest site checkpoint: candidate UI fixes shell-main placement in column2.
QEMU browser checks passed at1280/1920/1024, collapsed navigation and390 mobile;
candidate static assets only, real installed45 API/authentication. Site submission
then returned500. File journal omitted PHPProfile; source now retains it, with
real save/reopen/resume regressions forPHP82/83/84. QEMU hosting suites pass.
Actual executor /etc was read-only under ProtectSystem=full despite its allowance.
Source now uses ProtectSystem=strict. Live native unit override
/run/systemd/system/panel-execd.service.d/91-qemu-filesystem.conf proves /etc rw,
/usr/bin ro, active executor and successful bounded identity check. This is our
service sandbox fix, not a vendor change. These fixes are NOT in signed45 yet.
Original site command api_3acd4deffa2846226cbfa3f178446b780642ef6b0db8b3b3 remains
ambiguous, hosting_sites empty. Do NOT repeat --site with a new idempotency key.
Its allocated Unix identity now exists; registry remains allocated and outer
siteops/ensure_identity admission remains ambiguous. Next: evidence-based recovery
of that original effect; no lease/journal deletion or forced reset. One exact
empty-step test receipt was repaired with PHPProfile from its matching accepted
request; installed45 would omit it again on save, so deploy source fix before
resuming full provisioning. Guest2.1GiB free; no new full bundle/downloads.
Executor restart also restarted dependent core; simultaneous admission startup
hit SQLITE_BUSY and core stopped (test override Restart=no). Explicit core start
restored live gateway readiness. Source now retries only SQLITE_BUSY across the
whole rolled-back admission initialization, capped at5s and caller cancellation.
QEMU two-connection WAL test reproduced immediate failure before fix; now waits
for writer release, retains one gate row, and respects caller deadline. Complete
cmd/cyberpanel and rebootcontrol suites pass. Fix not yet packaged/live-qualified.
Earlier checkpoints below are historical and superseded where noted.

Latest: signed45 qemu-tenant-3.1.44 installed; current45/rollback44. Tenant create
503 reproduced as unsupported audit `prepared` outcome and audit SQL write while
holding the same DB transaction. Creation now durably records a PREPARED intent
before opening its mutation transaction; quota/ownership checks and changes remain
atomic. Intents are not reported applied. Other lifecycle precommit audit calls
still require qualification; do not claim all identity mutations repaired.
Role assignment also left reusable credentials on stale authz epochs; now advances
active non-API credentials while leaving old sessions/API keys invalidated.
QEMU tests cover shared single-connection DB, failed audit, quota rejection,
persisted tenant, reusable credential epoch, stale session and unchanged API epoch.
ACTUAL browser tenant create201, fresh password/passkey login200 (including
Chromium extension), customer visible afterward. DB confirms active customer and
prepared audit projection. Guest fixture /home/harness/qemu-created-tenant.json.
DO NOT repeat --tenant: use qemu-passkey.cjs --verify-tenant for read-only verification.
Verifier is now installed45; temporary authd override/candidate REMOVED. Only gateway
localhost HTTPS fixture override remains; core/authd/OLS use installed paths.
Next: site creation blocked BEFORE submission by desktop UI layout. Fixed-position
Sidebar occupies no grid cell, so AppShell .shell-main auto-places in column1 and
sidebar intercepts Create site. Fix grid-column placement, test actual QEMU browser
desktop/collapsed/mobile, then continue qemu-passkey.cjs --site. No site created.
Obsolete41/42 archived to ignored .work/qemu/obsolete-releases-41-42.tar.gz, gzip and
both manifests verified, then removed under installer lock with process-map checks.
Redundant44 tar and candidate executables removed. Guest2.2GiB free, host229GiB;
reclaim obsolete artifacts before next full bundle. QEMU signing maximum45.

Latest authentication checkpoint: signed44 qemu-passkey-3.1.43 installed, previous43
retained. HTTPS port/RP fix deployed in core. Actual Chromium WebAuthn enrollment
returned201/200. Repeated login exposed strict client-data parsing: Chromium's
optional `other_keys_can_be_added_here` caused401. Source now accepts extensible
CollectedClientData while preserving duplicate-key, challenge, origin, cross-origin
and signature checks. Focused QEMU authn/apiserver/identity tests pass uncached.
Actual browser login WITH that extra field now returns200 and assurance3.
IMPORTANT: client-data fix is tested via TEMPORARY native authd unit override,
/run/systemd/system/panel-authd.service.d/99-qemu-clientdata.conf ->
/usr/local/libexec/cyberpanel/qemu-authd-clientdata. It is NOT in signed44 yet.
Gateway has TEMPORARY HTTPS localhost8090 fixture override
/run/systemd/system/panel-gateway.service.d/99-qemu-passkey.conf; config/cert/key
under /run/cyberpanel-qemu-passkey. Browser ignores ONLY this fixture's self-signed
certificate; production TLS provisioning is not qualified. Core runs installed44.
Real UI tenant create with phishing-resistant session returned503 unavailable;
next diagnose that concrete failure, then package accumulated panel fixes.
Guest-only harness /home/harness/qemu-passkey.cjs reuses a saved0600 virtual-key
fixture /home/harness/qemu-virtual-passkey.json. NEVER print/copy test private keys,
passwords or captured assertions into Git. Do not repeat enrollment unnecessarily.
No vendor source builds/patches/downloads. Redundant43 bundle and abandoned core
candidate binaries removed (~594MiB); current44/rollback43 remain. Guest2.3GiB free:
reclaim verified obsolete artifacts BEFORE another full bundle. Trust maximum44.

Latest: signed43 qemu-claim-3.1.42 installed; bootstrap fix is deployed. Actual
root-only local claim returned201 through the protected authentication broker;
consumed-token replay returned401. Actual browser owner login200, authenticated
overview/dashboard200 and identity.tenant.list200. Managed tenant form fields
verified in browser; no tenant submitted yet. Dedicated QEMU account credentials
are guest-only /home/harness/qemu-owner-login.json, mode0600; NEVER print or copy
them into logs/Git. Claim token consumed. Core/gateway/OLS active, no candidate
override. Next: MFA and real tenant/site provisioning workflows, plus remaining
installation replay and cross-platform/native-LSE qualification. Overall parity
remains incomplete. Guest obsolete34–36/40 archived outside Git then removed;
redundant42 tar/candidate binaries removed; installed43/rollback42 retained.
Signing trust currently ends at43.

Latest installed checkpoint: sequence42 qemu-gateway-credential-3.1.41. Temporary
gateway candidate override/binary REMOVED. Core, gateway and OLS active on normal
installed paths; gateway health ready and QEMU desktop/mobile entry/invalid-login
checks pass. Guest releases37–39 archived outside Git to
.work/qemu/obsolete-releases-37-39.tar.gz (verified), then removed under installer
lock after current/rollback and process-map checks. Journals retained. Redundant
sequence41 tar removed after42 committed. Guest approximately2.5GiB free.

Pending source fix BEFORE claiming the real test installation: reproduced initial
claim failure from NULL public credential metadata, then reproduced a second
owner claim being accepted. Normalize absent public metadata to an empty blob;
reserve a singleton installation claim in the SAME transaction as owner state,
reject any existing principal/tenant authority, revoke rejected enrolled refs.
QEMU SQLite regression covers first claim, distinct/repeated-ID second claims,
pre-marker installations, rollback/retry and duplicate reservations. Identity,
apiserver and cyberpanel suites pass uncached. This bootstrap fix is NOT in42;
real one-time claim/authenticated journeys remain pending. Claim token remains
unconsumed in guest. Signing trust currently ends at42.

Latest live checkpoint: sequence41 qemu-gateway-registry-3.1.40 installed.
Consolidated duplicate tenant list/create/suspend contracts onto managed identity;
registry and handler-preservation regressions pass. Core is ACTIVE and its live
health endpoint reports ready/658 operations. UI form now carries manager,
ownership and delegation fields; suspension uses revision. UI typecheck/build pass.
Gateway's systemd credential ACL was rejected by the ordinary secret-file loader.
Source now accepts ONLY the fixed gateway credential path through the existing
read-only tmpfs/exact named-user ACL validator. Native service-sandbox test PASS.
Gateway is currently ACTIVE via TEMPORARY QEMU override:
/run/systemd/system/panel-gateway.service.d/99-qemu-candidate-test.conf
executes /usr/local/libexec/cyberpanel/qemu-paneld-credential. This last credential
fix is NOT yet in signed release41. Gateway /health/ready returns ready; catalog
has658 operations; actual QEMU browser desktop/mobile login renders and nonexistent
login is rejected401. Authenticated tenant workflows remain unqualified.
Next: reclaim obsolete release storage safely, package the credential fix, remove
the candidate override, then authenticated installed-product journeys. Guest
approximately2.1GiB free; storage guard remains enforced. QEMU signing trust ends
at sequence41 (extended from40 only for that release). No downloads/native builds.

Latest checkpoint: sequence39 qemu-preview-3.1.38 installed. Both missing preview
helpers are now in the signed release at /usr/local/libexec/cyberpanel, matching
the installer's existing binary boundary. Helper resolution pins the managed
release; arbitrary links remain rejected. Actual installed constructor tests
PASS as cyberpanel. Startup passes preview and reaches API registration:
`api: conflict: duplicate operation identity.tenant.list`. Identity and console
contracts duplicate list/create/suspend with different payloads; consolidate
without weakening duplicate detection or losing tenant-management requirements.
OLS remains active; core failed with Restart=no. QEMU has approximately3.2GiB
free. Removed redundant sequence37 tar only; installed rollback copies retained.

Latest installed checkpoint: signed sequence38 qemu-web-health-3.1.37 is
committed in QEMU. Persistent root-owned health proofs are keyed by web snapshot,
retain rollback proofs and reject confirmed-generation reuse. Installed vendor
OLS is ACTIVE; live HTTP returns exact proof98515aa557ad729626e3ec2119b46d0b6e1b6f401cf7184866afc7b5267865b4.
Core passed initial web activation and now fails at the site-preview route helper:
`site preview destination denied`. Mail services are active again. Reinstall
required the existing manual reconciliation hook and restoring root ownership
of the byte-identical WAF policy after vendor package ownership repair; automatic
installer replay is NOT qualified. No native source builds or downloads.
Earlier health-provisioning and inactive-OLS notes below are superseded.

Latest routing/storage checkpoint: fixed allowBrowse0 denying health and ACME
files; both renderers now allow files with autoIndex0. Vendor QEMU serves exact
test proof bytes; directory requests404. New vhosts use content-hashed paths so
same-snapshot renderer updates do not collide with earlier sealed vhosts; old
manifests remain readable for recovery. Five affected suites pass. Vendor parser
accepts e8650d...; HTTP18/21 pass (only the known three size cases fail).
Fixture proof files are temporary private binds, NOT production health
provisioning. Next: real generation-safe health writer, signed deploy/activation.

Latest progress: installed rules evidence no longer hardcodes a manifest digest
or release label. Root-owned installed manifests remain recursively verified;
empty/tampered/unsafe assets fail. Custom CRS package/layout replacement remains.
Guarded bootstrap candidate advancement implemented and QEMU-tested for both
edition formats. Actual guest TestQEMUInitialWebParser PASSED for f80079fd...:
old checkpoint advanced without deleting journals, vendor parser accepted new
master, original master restored. OLS remains inactive. Five affected suites
pass; full activation still needs health attestation and updated signed deploy.

Consume vendor/distribution OLS, LiteSpeed Enterprise and ModSecurity packages.
Do not fork, patch, compile or hard-pin these native dependencies (including
LSQUIC). Our responsibility is panel installation/configuration/integration,
using the current CyberPanel reference behavior. Record observed package
versions for test evidence; that is not a product version lock. A native failure
requires checking our integration and reporting the upstream limitation, not
starting a dependency-maintenance project. Removed our ModSecurity compiler
recipe and connector patch. Earlier custom-build checkpoints below are
historical evidence, not the delivery plan. CRS's custom package/manifest pin
still needs replacement with the normal managed rules installation path; do not
silently drop asset-safety checks while correcting it. No OLS/LSQUIC build was
started. Return qualification to vendor packages in the existing QEMU guest.

Restoration done: vendor ols-modsecurity1.9.2-1+noble installed and dpkg-verified.
Compared reference config: explicit required/restrictedPermissionMask000 was
missing from our renderers. Added in OLS/LSE, preserving OS permissions and vhost
isolation. Three QEMU suites pass. Vendor OLS parser accepts f80079fd...; live
HTTP14/17 pass, including every benign request and existing attack fixture.
Three body-size cases still return200 rather than413: retained as evidence,
not justification for another native fork. Native LSE remains unqualified.
Removed obsolete custom native packages/parser/source archive. Next: finish
normal rules-installation integration and bootstrap/health transition.

Latest native body-limit checkpoint (2026-09-20): connector package
1.9.2-1+noble+cpmodsec3.0.16.2 now rejects known-length oversized bodies with
413 instead of disabling inspection. Real QEMU HTTP regression passes this
case. Chunked large bodies remain RED: one large chunk stalls; bounded chunks
receive 200 instead of rejection. Diagnostic decoded-buffer guard did NOT fix
this and was removed, along with instrumentation; packages .3/.4 are not release
candidates. Trace established decoded=13107214, limit=13107200, engine=On,
action=Reject. Investigate native reqBodyDone handler-before-body-hook ordering
and large-chunk read scheduling; do not assume a limit configuration error.
64 KiB late-body chunked XSS is blocked. Static cached requests remain
intermittently403; the same benign query after cache expiry succeeds.
Final 17-case run has 12 passes/5 failures, not product certification. OLS held
inactive; signed release remains37. See RUN-REPORT for evidence and cleanup.

Latest source/native checkpoint (2026-09-20): initial blocking WAF policy and
recursive pinned-asset verification implemented; installer replay preserves later
policies; exact baseline can hand off to the executor's first journaled change.
Fixed CRS package manifest mode (4.29.0-2) and OLS/ModSecurity C++ symbol collision
(module 1.9.2-1+noble+cpmodsec3.0.16.1). Native OLS -t now PASSES for pending
rendered digest 0416df09...; five affected QEMU suites pass.
Live isolated HTTP fixtures reach OLS and block XSS/SQLi/JSON/XML-attribute
attacks, but remain RED: repeated plain GET is intermittent; benign query/JSON/XML receive native static-file
permission-check 403; oversized body returns403 rather than413. Do not suppress
these failures or weaken security masks/WAF. Next: native static-cache/permission
path and connector body-limit behavior, then attestation/bootstrap transition.
OLS held inactive; signed panel release still37; old marker8ad3d376... unchanged.
Detailed evidence and package hashes: newest RUN-REPORT section.

Newest native prerequisite checkpoint (2026-09-20): QEMU Ubuntu ARM64 now has
OLS connector rebuilt against fixed ModSecurity 3.0.16 and complete signed-
upstream CRS 4.29.0. Offline package recipes added; native rule checker loads
840 rules and installed recursive hash checks pass. OLS parser loads the new
module but still fails absent initial managed WAF policy. These prerequisites
are NOT yet included in signed release/catalog (installed panel remains 37).
Next: real WAF body-processing/bootstrap policy, native benign/attack fixtures,
then signed prerequisite inclusion alongside the earlier bootstrap work below.
Keep fixed source archives and small packages outside Git; recipes automatically
clean extracted sources/objects. No new OS/Go image downloads.

Newest source candidate (2026-09-20): dedicated web worker identity, required
MIME/error/access logging in both renderers, root-owned system static roots,
read-only native config mounts and isolated stopped-process observer implemented.
QEMU affected suites + native installer/observer checks pass; candidate binaries
rebuilt. Real pending-plan native parser advances to missing WAF policy
`/usr/local/lsws/conf/modsec/cyberpanel.conf`; keep WAF enforced. Matching
ols-modsecurity ARM64 package is installed and retained for next signed bundle.
Installed release still 37, newest code NOT signed/deployed. Next also needs
health attestation provisioning and safe transition from failed bootstrap marker
8ad3d376... to new renderer digest 0b9c811b... without resetting journals.
OLS/core remain unqualified. Detailed evidence: newest RUN-REPORT section.

Latest installed checkpoint (2026-09-20): signed sequence 37 now includes mail
recovery, initial web activation and scoped broker/admission retry. Same request
advanced after fixing vendor-owned `conf/vhosts` (installer fix native-tested,
not yet signed). Core still fails initial native parser validation; no web
current receipt. Explicit `TestQEMUInitialWebParser` remains red: native log
`/tmp/lshttpd/testconf` reports missing User/Group. Ordinary affected-package
suites pass. Next: provision/render unprivileged server worker identity and
system-default material, prevent OLS startup from
rewriting config ownership, strengthen stopped-process proof beyond systemd.
Do not run `lshttpd -h`: it starts the daemon. Accidental diagnostic startup was
stopped; generated config metadata restored and sealed bytes reverified. OLS
hold restored. Mail/executor active; host 244 GiB free, Git pack ~486 MiB, guest
7 GiB free. Full core/API/UI/mail-delivery and cross-platform qualification
remain incomplete. Detailed evidence is at the top of RUN-REPORT.md.

Latest source candidate (2026-09-20): first web activation is wired from the
SQL node-config journal through verified rendering to a snapshot-one-only
bootstrap. Durable vendor backup, native validation/start, live digest proof,
and stop-before-restore handling are implemented. QEMU workflow/file-store tests
pass (including tamper/reopen/failure cases); both candidate binaries are built
as `cyberpanel-web-bootstrap` / `panel-execd-web-bootstrap` in the guest bin dir.
NOT signed/deployed yet; release 36 remains installed and native web startup is
still unqualified. Next: qualify broker retry behavior and controlled native
bootstrap, then signed deployment including the mail recovery fix.

Latest installed checkpoint (2026-09-20): sequence 36 is committed and its
signed engine catalog, managed links, package hash/native metadata and installed
OLS version pass the explicit QEMU check. Upgrade exposed same-generation mail
restart recovery: fixed and red/green tested against native daemons; recovery
source still awaits the next signed release. Four affected suites pass. Native
mail is healthy again; core reaches web inspection and fails because initial
web activation is absent (OLS held inactive, no current activation receipt).
Next: signed recovery deployment and initial verified web bootstrap. Git pack
size remains ~486 MiB after the checkpoint exclusion fix.

Disk blocker corrected (2026-09-20): automatic Git checkpoint trees had captured
QEMU overlays through the main checkout, growing shared `.git` to ~241 GiB.
Unused temporary packs and obsolete runtime checkpoint objects were reclaimed;
`.git` is now 506 MiB, host free space ~247 GiB. Source branches/reflogs/working
changes are preserved. Shared ignores + forced-add pre-commit artifact rejection
prevent recurrence; QEMU guards now require 10 GiB host free and Git objects
below 5 GiB. Candidate 36 is ready for the previously blocked installation.

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
