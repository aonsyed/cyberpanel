# QEMU verification — 2026-09-19

This is a verification checkpoint, not a parity-release certification.
The scope remains the complete product defined in the existing design spec.

## Source and environment

### Installed76 — native access and encrypted backup batch, 2026-09-22

Signed qemu-workflow-3.1.75, source1156571cd, committed.
Manifest914856ac02ad4216efe394375ba53da60032c676b3b358c715bd49ab1a098072;
receipt600c1f0aa419140ee831117786a4acb4b7ceac1f1840ba37ccbfed205791411f;
bundle84cff647e411ea13cec6d6e183ecfcda69b75bc8f6efa7016908fd3edd0f7ad8.
Operation install-a8255020054bb07f7f47d04c0c08760e76b2edaeb8756e954072df80181a528b.
All seven core/executor/gateway/auth/secrets/provider/peer-inspector live process
hashes match rebuilt artifacts; all services and OLS active. Panel HTML and new
panel-CDFxR6yC.js return200; CSS index-h86HsoAP.css. UI typecheck/build and combined
access/apps/DNS/backup/secrets/webmail/API/core/executor/gateway checks pass in
QEMU. The existing >500kB Vite bundle warning is non-fatal, not a new gate.

Included native source proof, not yet installed workflow qualification:

- SFTP dedicated logins, root-owned descriptor-bound jails, native sandbox
  confinement/read-only/revoke/expiry/remount and pidfd-scoped session termination;
  UI now accepts actual public key/permission/expiry and shows the login. Evidence
  commands/limits in testvm/SFTP-QEMU-2026-09-22.md. No actual reboot proof yet.
- AES-256-GCM local repository objects with purpose-bound secret-broker enrollment,
  authenticated object identity and explicit format. Legacy raw points stay raw
  and readable; new capture requires explicit format. Metadata/spool/scratch are
  not claimed encrypted. Wrong-key/tamper/truncation/substitution rejected.
- Native8MiB chunking and verified reassembly remove the transitional16MiB
  component limit. QEMU encrypted native proof: SQL37,752,634 bytes/5objects and
  files18,880,512 bytes/3objects, exact payload hashes/NULL/BLOB/ACL/rollback and
  invalid-chunk rejection. Off-node key recovery remains unqualified.
- Joomla selected-package PHP CLI and DNSSEC scoped cache invalidation fixes.
- Native attached message/multipart download path; multipart projected size is
  explicitly unknown until the authoritative download literal supplies it, not
  guessed. Ordinary installed75 attachment proof remains below; new container
  UI behavior is not yet installed-qualified.

Installed76 verification queue starts with real SFTP UI/API/native access, then
DNSSEC warmed-cache transitions, Joomla lifecycle, and encrypted backup enrollment
and restore. Public database replacement stays disabled. Internal replacement
worker8010188b2 is not in this release; original ambiguous backup is unrecovered.

Disk: obsolete unreferenced56–59 guest releases were archived to checksum-matching
host .work/qemu/retired-node-releases copies before exact guest removal, preserving
active/previous, receipts, and all application recovery material. Prebuild5.3GiB
free; signed bundle retained on host. No downloads or vendor-source modifications.

### Installed75 — parallel closure batch, 2026-09-22

Follow-up installed proof: webmail attachment read200 projects part2,
proof-bytes.bin/application/octet-stream/31 decoded bytes; actual UI download
retains the filename and exact bytes (including NUL/high bytes). SHA256
047c092c73717c3284501e4dcdcef26f6899a81677c6905452d1a96f42643bcd.
Parent read actual guest /home/harness/webmail-attachment-read-evidence.json:
wrong-tenant404, stale UIDVALIDITY409, oversized upload400, foreign-mailbox403;
exact probeUID4 expunged and subject absent. Native decoded bytes also matched.
No resend. Worker's initial narrative30 was corrected against actual31-byte
fixture/download/metadata. Attached multipart/message containers remain explicitly
unsupported; this is not complete MIME or scale qualification.

Further installed failures: Joomla now passes destination validation but its
LSAPI binary ignored CLI bootstrap flags; selected package PHP CLI correction
c7d477100 is source-tested, not installed75. DNSSEC enable202 and exact DS now
pass, but immediate DNSKEY/SOA responses retained unsigned cache state; scoped
rediscovery/invalidation13d6bcfcf is source-tested, not installed75. Retained DNSSEC
zone remains signed pending a warmed-cache transition verification and cleanup.
Writer-fence primitive03dbed4ce is integrated but public replacement stays disabled
until its full replacement lifecycle is connected and proved.

Signed qemu-workflow-3.1.74, source20fa167b4, committed successfully.
Manifest a66aec2fa18f77b62c0a8361e26e4c7cd2ddd562727371c52ba706efa0a1e9b9;
receipt723f9531b8745a2ec0e97d87573bfa841df0965728c11a04c3010e7c814ba728;
bundle4c3cd189a1f53142e3f1f3e6a74e43f806e84ed96f2d988ddebd653b54d8f78a.
Operation install-72a3be52df5d9077e8c0a93f877881ee9966fe973d3658234023727ca7a680e7.
Actual core/executor/gateway process hashes match all three rebuilt artifacts;
all active, OLS active, panel HTTPS200, installed highest_sequence75.

Included: backup scoped write observation539477d66; webmail attachment metadata
9e8c97d85 and supported raw-size bounds2081c88d2; certified application served-root
admission8d36e4442; exact native DNSSEC DS export20fa167b4. QEMU combined backup,
webmail, API, core, executor and gateway suites pass; apps0.522s; native isolated
DNSSEC0.155s, including multi-key exact DNSKEY digest selection. All builds/tests
remain QEMU-only/offline. Native backup proof is recorded below. UI was unchanged.

Installed74 reproduced Joomla install503 (compensated, current/public rejected)
and DNSSEC configure400 (invalid native export-zone-ds argv). Those source fixes
are now installed, but their full live journeys and webmail attachment download
are pending in the coordinated browser queue. Do not count pending checks as
passed. Database fence, SFTP confinement, and encryption are separate in-flight
worker changes, not included in75. Original ambiguous backup remains unrecovered.

Disk: unreferenced obsolete releases54/55 were copied to host ignored
.work/qemu/retired-node-releases; checksum dry-run matched before exact guest
removal. Neither active/previous nor symlink/process-map references used them.
Guest free space rose from4.5GiB to5.4GiB before build/install; host copies remain
recoverable. No application snapshots, receipts or database data removed.

### Backup write observation — source-only continuation, 2026-09-22

QEMU reproduced three failures before correction: same-size file writes with
preserved mtime were invisible; the server-wide InnoDB marker missed scoped Aria
writes; and a persisted Frozen flag suppressed actual write observation.
Observation now hashes file content and scoped native database dumps, preserves
the first observed write timestamp, and rejects missing baselines as ambiguous.
This is state-change detection, not proof against write-then-revert or a durable
writer fence. The original ambiguous restore is still not recovered.

Fresh Ubuntu ARM64 QEMU command from /home/harness/platform:
`sudo env TMPDIR=/root CYBERPANEL_NATIVE_BACKUP_TEST=1 GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=1 /home/harness/go/bin/go test -count=1 -p 1 ./internal/backup/... -v`.
Exit0: backup0.145s, providers4.591s. Checks cover preserved-mtime bytes,
Aria/InnoDB/MyISAM writes, unchanged/scoped isolation, frozen-state observation,
first-write timestamp retention and missing-baseline denial. Native provider
checks again exercised exact SQL text/NULL/BLOB and files, public/private access,
directory publication/rollback and corrupt-object rejection. Fixtures clean up
their exact generated resources. No native dependencies downloaded or modified.
These source changes are not yet in installed74; installed evidence below remains
the last released behavior. Parallel access, webmail and database lanes resumed.

### Resumed workflow checkpoint67 — 2026-09-22

Latest74 qemu-workflow-3.1.73 (source61e40a55e) committed. Manifest
29875cc903a6bc0aacd1b77b645db886a0fbe4737b23f57459f824af51535940;
receipt d33c8e1de9f0a2fbd365ed43305df000b03163699373f7fb2b1bedd2b965fddf;
bundle bb421c43e1be34984ea35af0901efda6d0f3d31648099e66d9adbd8ce222470a.
All three live hashes equal built artifacts; services/OLS active, HTTPS200.
Directory-to-directory exchange preserves current as a real directory; candidate
and previous inode/device identities are journaled and checked on replay/health.
Restored public ACLs reuse siteops' fd-only named-web-user grants; native proof
checks cyberpanel-web can read public but not private/root files. Real-directory
restore/rollback/corruption and affected combined suites pass. Installed final
UI plan restore_aae5ec78e791664898c70cd9c44c1854fe64951da0feae1f reaches
active/gen14: exact native HTTP200 marker bytes, text/NULL/BLOB SQL values,
real current directory, site UID and cyberpanel-web public reads, web private
read/traverse denial, healthy OLS/core/executor/gateway and panel HTTPS200.
Parent inspected safe guest installed72.json verified74/apply receipts and
independently fetched expected marker bytes HTTP200, checked directory type and
service state. This qualifies explicit fuzzy local files+database normal capture
and same-site restore on Ubuntu ARM64, NOT encryption/full-DR/other components.
Original ambiguous/frozen unpromoted plan is preserved and unrecovered; its
missing scoped pre-write proof remains a release gate. Fixture, verified point
and recovery evidence retained. All six bounded workers have returned; no child
workers or downloads. Matching host bundle retained; guest duplicate
removed and staging pruned. Guest4.5GiB free. Unreferenced old releases52/53 moved
to checksum-verified host copies before exact guest removal; active/previous and
app/backup recovery material retained.

Latest73 qemu-workflow-3.1.72 (source0d43c5857) committed. Manifest
cf03c819822267f9b1b82b78312b0a99b51b13a2df525d08663e8800443432ad;
receipt d4898a807a165657a9ed7275829b9fdb3fb4930a48492ed60397d41794ad2a52;
bundle fdddadc0d88503dcf0b0d9f3b239308ae55c5c62f3290cc51bffc499d1f96b26.
All three live binary hashes equal the rebuilt artifacts; panel services/OLS
active and HTTPS200. Backup directory promotion uses atomic exchange, retains the
old directory at a persisted deterministic identity, and syncs the release parent.
Native actual-directory files/SQL restore, safety rollback and corruption tests
pass, along with affected combined packages. Host bundle checksum verified before
guest duplicate deletion/staging prune. New installed normal restore plan reaches
active/gen14 with exact files and text/NULL/BLOB restored, current site UID can
read, and promoted=true/frozen=false. However native public HTTP remains404:
OLS rejects the new symlink under existing allowSymbolLink0. The public marker
path was confirmed correct. This is a serving regression, not full restore
qualification. Directory-to-directory exchange plus persisted identity/replay
checks is required; do not weaken OLS policy. Earlier ambiguous plan remains
explicitly unresolved, not bypassed.

Latest72 qemu-workflow-3.1.71 (source64c9e54d2) committed using the newly rebuilt
panel-node-install, not the old bootstrap executable. Manifest
644b050c82a1e148be5c79d24f1fbbfab6b6488d9f20621689fddf15c43b4456;
receipt90a501e78d0692442bfda3d3d80d4e939f192fb57e72f403d7207f4b581de44c;
bundle97500247ff843357acb61c2b2ec385aea44298d9e79ea4d8f1b6b2553fb3b278.
Actual backup repository parent is now0700 cyberpanel:cyberpanel, reconciled
through the real signed installer boundary without manual chmod/chown. Shared
helper rejects unsafe ancestry/foreign owners/symlinks; fresh/replay native
sandbox cases and combined affected suites pass. All three actual live binary
hashes match the builds; core/executor/gateway/PowerDNS/OLS active, HTTPS200.
Host bundle checksum matches, guest duplicate removed and staging pruned.

Webmail native UID-first FETCH response parsing fixed: actual delivered probe
failed before the fix, exact body read passed after it. Wrong UID/prefix/duplicate
UID and malformed FETCH regressions pass. Installed72 actual UI account/folders/
list/read/action all200, exact delivered plain text and sanitized iframe match.
No resend: send202 was on71, read completion on72. Only exact probeUID3 expunged,
then subject absence confirmed. Parent inspected guest webmail-installed72-read-
evidence.json operation receipts/cleanup; screenshot retained beside it. This
closes bounded local panel compose/send/list/read, not attachments/drafts/Sieve
or external delivery.

Installed72 backup: disposable qemu-backup72.example.invalid site201, repository
registration200, policy201 and Run now produce verified recovery point
point_ed83625c0ef27740f5279a88ef9f2483b38b78b61500bc4b: real SQL2470B + files5120B.
Restore plan succeeds, apply503. Actual current is a provisioned directory;
promoteFiles attempts symlink-over-directory rename. Native proof shows frozen,
not promoted; coordinator remains ambiguous. OLS failed after freeze while panel
services stayed healthy. Normal service-only start restored OLS to active; no
layout or state journals were manually changed. The old freeze state has no
scoped before-write fingerprint/inode proof; empty TargetGeneration alone cannot
authorize automatic retry. Preserve the ambiguous plan; do not claim it recovered.
Directory-layout correction is in progress. A new explicit normal restore plan
may qualify normal restore separately, only through existing safe admission.
Earlier component restore proof used a symlink layout and does not qualify this
installed flow. Interrupted/ambiguous recovery remains a separate release gate.

Latest71 qemu-workflow-3.1.70 (source ac288b355) committed through the normal
signed installer. Manifest e1f2f31f6100297d1a0c151dce040f4a43b8d4c4fdb769483668a72894b20168;
receipt 16187084cbc307f946eda889efc8616beb4e3d341723d9ea2e487ede23cceed3;
bundle 6cf3b39a761218bf21140ad9fc31a79e66a28bea335108ef24b75cb4fb033839.
Actual core/executor/gateway process hashes equal the three rebuilt artifacts;
all services and PowerDNS/OLS active, panel HTTPS200. Combined apps/catalog/DNS/
webmail/backup/providers/core/executor/gateway suites passed in QEMU. Matching
host bundle retained, guest duplicate removed, staging pruned; guest4.4GiB free.

Installed71 DNS full remaining UI lifecycle passed: update202 immediately serves
A192.0.2.24/TXTdns-final, empty replacement202 removes A/TXT while retainingSOA,
delete200 removesSOA. Parent independently queried the deleted zone: noSOA.
390px editor assertion passed; exact disposable zone cleaned normally. Prior
wrong-tenant read/write404 remains proven; lesser-role denial is not yet qualified.

Installed71 WordPress fresh default-English lifecycle passed site201/install201,
homepage200/login200 and actual generated-credential wp-admin Dashboard, then
normal removal202. Parent read saved safe evidence and independently checked
exact database/principal absence. See WORDPRESS-VERIFICATION-2026-09-22.md.
Webmail folders/list200 and self-send202 now pass; opening the delivered message
still returns500. That single delivered probe is retained pending read-path fix;
no duplicate sends. Safe evidence: guest webmail-installed71-evidence.json.

Installed71 backup directory STILL root:cyberpanel0750 despite migration source
fix. Actual signed node-release lifecycle never invokes the older installer
authority hook; shared backup-only reconciliation is being added to the real
lifecycle. This observed failure is not counted as completed.

Obsolete unreferenced guest releases48/49 also moved to ignored host copies:
rsync checksum dry-run showed no differences before exact guest removal. Active/
previous releases and app snapshots retained; guest free5.3GiB, host206GiB.

Latest70 qemu-workflow-3.1.69 (source9699e7bbd): manifest
ce8428b51ff3fb72279b7257a7aef8c281d572cf75873d1e6d50210fc721b3a7,
receiptcb88e58126a0fa542a36195180eb9c054bd920d8c0ac1a446a13db65c92ef63f,
bundlef94807a6d8ccbc3e60b2dc94d2ce94a8ef9fda0b57d20efdd51c73a1f972db3c.
All three running binaries equal built hashes; HTTPS200 serves combined UI.
Combined API/DNS/webmail/certificates/backup/providers/core/executor/gateway tests
and UI typecheck/build passed in QEMU. Matching bundle retained on host, guest
duplicate removed and verified staging pruned.

Installed70 DNS existing-zone list200, import202 and native A/TXT answers pass;
390px editor and wrong-tenant read/write404 pass. Update202 changed native SQL
but cached query stayed old. Fixed native scoped purge source has actual candidate
purge→new dig A/TXT proof; installed lifecycle rerun awaits71, without replaying
successful mutations. Zero-zone broker/API optional-field codecs were fixed.

Installed70 public TLS mirror is root0444; actual core UID can read only public
identity, not private key. Folder failure moved from503 to403. Separate native
Dovecot fixture proved no-authzid OAuth denies before any introspection, while
canonical authzid succeeds with one request; force_introspection alone does not
fix it. Only trusted-address propagation remains in progress here.

Installed70 backup root still root:service0750: upgrade skips initialize-authority.
Shared backup-only init/migration/replay reconciliation is fixed in source and
real isolated migration-hook regression passes with unchanged claim token.
WordPress installed69 lifecycle/removal evidence is in
WORDPRESS-VERIFICATION-2026-09-22.md; canonical-scheme source fix awaits71.

Known obsolete releases15–17,21–27 were copied to ignored host .work/qemu with
checksum dry-run equality and no filesystem/process references before removal;
retained active/previous releases and app recovery snapshots were not removed.
SSH wrapper now enforces4GiB guest free for assembly/install versus2GiB for builds,
with an observed exit75 reservation rejection and guest shell syntax/pass check.

Latest69 qemu-workflow-3.1.68 from481b6f836 installs all three rebuilt binaries.
Combined apiserver/DNS/webmail/cyberpanel/panel-execd/paneld suites pass in QEMU.
Manifest63d33fb47a39ef9d69db131453e92afaee3690968e77286497d33cb44a6d2f1d;
receipt378873b576db5d50249882c1ef688f5f9760c9287707a5279f641bd2b07c16ad;
bundlef6581bcd9ef3c808f4b8238aa877a46d399ea30e11c514e126e1db982d02837e.
Matching host bundle retained, guest duplicate removed, staging pruned. Obsolete
releases22/23 similarly copied to host with checksum comparison and no live
filesystem/process references before guest removal; active/previous untouched.

Installed69 --scope-only file proof passes legitimate tenant/site200 and wrong
tenant/site404. Underlying real Core HTTP + SQLite authority regression confirmed
the earlier bypass with a tenant-limited credential and now prevents executor
effects. All19 file/transfer/archive handlers use authoritative ownership lookup.

Installed68 WordPress site201/install201/active7.1 nevertheless served404 because
application root differed from provisioned document root;69 uses the validated
relative served path. Original fixture retained for normal application removal.
Installed68 DNS create500 was zero ZoneSpec marshaling an invalid empty DNSName;
69 omits zero reply field, retains populated validation. Actual DNS native CRUD
and new WordPress served-root browser reruns still pending at this checkpoint.

Installed68 Webmail: passkey login200, account discovery200, folders503 on TLS;
Compose self-send202 delivered exact unique subject/body via native strict-TLS
IMAP; only that probe message expunged. Master login/INBOX also passes. Native
responses confirmed preauth capability withholding, CONTEXT=SEARCH positive
PARTIAL support (negative ranges BAD), empty NIL and informational OK behavior.
69 includes protocol fixes, bounded COUNT+positive PARTIAL and mock/native tests.
No unbounded mailbox fetch, TLS bypass, global trust changes or vendor changes.

Follow-up68 installs the rebuilt gateway containing the final DNS contract delta;
source code otherwise unchanged. Manifest58b71157ec6b8d28b12373b3086ebfe88bb452ce6d451304ddeaf7a624d65062,
receipt7a3682ad858eb957b641de7c244adcf561043652fb1cd74021d441492e9bbaf9,
bundle743a1fde143c8db2f1bebf05bc0d6df60b22dc5087d99b16bf4669a9427b7dbd.
Running gateway matches built SHA256a62698f15e1fd8f1caae18760a3bd0558cc1e31319dd0d80ce7b93e1cdc09085;
HTTPS Accept:text/html returns200. Matching host bundle retained; guest duplicate
removed and installer redundant staging pruned.

Installed67 real browser file-manager journey passed: upload/read/download,
rename/trash/restore and second exact-byte download, static/PHP native HTTP,
4MiB boundary upload/download and4MiB+1 rejection before mutation. Test files
removed through API into recoverable trash; no public qemu-access fixtures remain.
The global-owner wrong-tenant/site probe returned200; do not call it a passed
tenant-isolation test. A suspected missing tenant/site ownership binding remains
under bounded investigation. Reusable proof: testvm/qemu-access-flow.cjs.

Obsolete sequence21 release directory e0c15354210502a420c2846b4044b183cbc7d0c14ff2b837dfe100a40e016a45
also moved to ignored host .work/qemu. Checksum comparison had no differences;
no service filesystem symlink or running process mapped it. Active/previous
releases retained. The old directory remains recoverable on the host.

Six bounded source lanes integrated on bfbaf4ab3. QEMU-only combined suites pass:
access, apiserver, apps, backup/providers, database, mail, DNS, cyberpanel and
panel-execd. UI typecheck/build pass. Native lane evidence includes webmail master
authentication/negative credentials, upload ACL/exact bytes, offline WordPress
command boundaries, same-site files+SQL restoration and corrupt-object rejection.
Ordinary dependent-view imports were already implemented (89f46f587); fresh native
three-engine × SQL/gzip checks pass. Replacement remains an unexposed primitive.

Signed qemu-workflow-3.1.66 sequence67 installed successfully, prior66 retained.
Manifest6865fef7cedd803187d9aaac8d092904c14d78884324f6456450faaf1039be7b;
receipt868571b4397fccd8e1f59c84c8af32a6671ddf40d24e5296797e70e54fb199b5;
bundle434f3dccbda5fb053fd9916dd8cfc313a9adb313c16dbf4f8aa1e5712aa17ac2.
Live process binary hashes match assembly, HTTPS returns actual new UI assets.
Gateway was built before the final DNS empty-replacement contract delta; this is
explicitly pending correction in the next signed checkpoint, not DNS qualification.
Browser workflows are in progress, not yet declared passing.

Recovered test environment without recreating disk or downloads. Bare native OLS
configuration test changed managed permissions; restored managed metadata only,
unchanged content hashes. Existing confined product runner avoids that side effect;
testvm/README.md now records the safe diagnostic rule. The separate pdns dependency
fix demonstrated starting execd starts pdns first and restores mutation admission.
Temporary QA HTTPS identity restored with gateway-only private-key permissions.

Moved old panel-web-catalog-3.1.35.tar and retained-mail-33-35.tar.zst from guest
/var/tmp to ignored host .work/qemu after matching SHA256; recoverable host copies
retained. New67 bundle also retained on host with matching digest, guest duplicate
removed and verified redundant staging pruned. No test images/bundles added to Git.

### Installed66 ordinary mailbox browser and delivery — 2026-09-21

Source5f31c57e1, release qemu-mail-delivery-3.1.65 sequence66. Signed installer
committed manifest b4a3983b882d21d8fbbb4adc5f149d2a8afdc92a769c69dd9c509fb33e0609a5,
receipt2abede596eb45d7af6be95475503640ab49e07e00468d0c564200aa0eba1e656.
Actual running binary hashes equal assembly:

- core: 17a323e861deffee62ad152ab24e2855faf582506bb24efc1f8442d7ff4c6236
- gateway: 0b72870e7bfd31873258ee7b05034208fe7a4791a28a19b83f360903c500eb78
- executor: 1c69c8ccbadd99fa322e74ee5c1921d6a80d5e1b6336b8d0e87742efd9727f3d

All active, zero restarts. Native systemd A/B reproduced openat2 ENOSYS with
RestrictSUIDSGID=true and success with false. The installer-managed executor
unit now uses false, retaining NoNewPrivileges and bounded capabilities.
Native doveadm regression reproduced count-quota initialization failure before
quota_vsizes=yes; afterwards native quota and mail/API/core/executor suites pass.

Installed browser passkey login and mailbox qa65 get/update return200/applied
generation3. Independent NEW qa66 installed browser form completes create200,
password enrollment201, activation200/applied. For both mailboxes actual IMAPS
wrong-password rejection, SMTPS authenticated self-delivery, IMAPS retrieval by
unique Message-ID, exact body comparison, and deletion of that message pass.
Native LMTP logs confirm INBOX delivery. No external mail; local bootstrap TLS
certificate verification intentionally disabled in QA clients. No claims for
external acceptance, public certificate trust, DKIM, DNS automation or webmail.

Old qa65 deferred probe delivered and was removed by exact INBOX UID+QA subject;
queue and qa65 INBOX empty. QA credentials remain guest-only. Host-retained
bundle SHA2566addbb5a940b262c5dc188083d46ca7a500de054c7b46e5564e1eaac50a5d36f
verified before duplicate guest removal; staging pruned, guest3.6GiB free.
Remaining concrete error: Dovecot master-auth password file is inaccessible
under root-only /etc/cyberpanel/secrets. Ordinary mailbox auth passes; panel
webmail remains unqualified. No downloads or native dependency builds/patches.

### Installed64 native mail maps and browser regression — 2026-09-21

Source24528b64d. Before fix, TestQEMUPostfixOrdinaryMaps failed ordinary-domain
lookup with postmap exit1. Native texthash rendering now publishes ordinary and
migrated records; no reference to nonexistent socketmap listener. Regression
covers domains, enabled/disabled mailbox, aliases and real native NOTFOUND;
projector tests cover suspended/deleted resources and unsafe record whitespace.
QEMU root/offline with CYBERPANEL_QEMU_MAIL_MAPS=1 ran affected mail/apiserver/
cyberpanel/panel-execd suites successfully (3.671s/0.087s/0.331s/0.028s).

Offline QEMU rebuilt core, gateway, executor and UI. Signed release
qemu-mail-integration-3.1.63 sequence64 committed. Manifest
00df96ae2be0756dfa40b4b784f97471f9955bc02d55361dad5ea705cef9171e; receipt
e40b706306342fc788a63999bab2e6c5d89704f0d1d5d7b2e739c116d17910c4; retained
bundle SHA25664ba36737ef14810ce4c271478444d4d1616256dc288dcaa40dcf2d7a158d270.
Actual running binaries match assembly:
core2d4f49189d76197ee1160b42fc62f298c45a44d508129923f707b0dc92fc637c;
gateway1acc57346fa427393dcc9bd0f50dc64d6b8664a68e525eca05444fcb3509339d;
execd786bfcbb3d3e3ed82aed88ed43cf901af6174c289b2757b5e9727645bdf8fee5.
All active/running with zero restarts at check.

Installed authenticated mail.domain.update returned200 for the known fixture;
harness then mishandled Fetch Response.status. No replay mutation: subsequent
API read proves generation2 active, and native postmap returns OK from installed
texthash-only domain configuration. Installed browser projection and390px form
pass. Actual installed passkey/console issue/query/rejected mutation recovery and
SQL/gzip exports/downloads with text/NULL/BLOB and SHA256 pass. Export table cleaned.

No message-delivery or mailbox-authentication claim. New source does not finish
advanced routing or the missing mail policy helper. Disposable Go build cache
cleared (module cache retained), duplicate bundle removed after host digest+
committed receipt+running binary verification, staging pruned; guest5.5GiB free.

### Mail domain browser/API integration — 2026-09-21

QEMU installed browser with real password/passkey authentication: old generic
mail form reproducibly returned400 invalid_request (flat domain/site_id/
dns_automation). Candidate form sends typed policy and domain through installed
API; both return200. First QA assertion mistakenly expected201; fresh read then
confirmed exactly one active generation1 domain, not a failed provisioning call.
QEMU npm typecheck/build pass. A second authenticated candidate-browser run reads
the actual domain projection and verifies the creation dialog fits390px viewport.
Final domain.ts action metadata-only cleanup also passes QEMU typecheck.

No actual mail delivery success claimed: direct native postmap query against the
configured Unix socket returns missing socket. Postfix/Dovecot remain active;
ordinary domains are not covered by the migration-only static-map path. Next work
is missing lookup integration plus mailbox enrollment and submission/retrieval.
One local-only domain/policy fixture retained for that work, identifiers in
IMPLEMENTATION_STATUS.md; no external mail, downloads or package modifications.

### Whole-source build and installed mail/DNS checkpoint — 2026-09-21

Git archive of 6d76bc266 synchronized into existing Ubuntu ARM64 QEMU guest.
Root/offline Go with TMPDIR=/root and existing guest caches ran
`go test -p 2 ./... -count=1` followed by `go build -p 2 ./...`; combined exit0.
Native opt-in environment flags were absent, so gated native cases skip; packages
without test files establish compilation only.

Then CYBERPANEL_QEMU_INSTALLED_SMTP=1 and CYBERPANEL_QEMU_PDNS_RUNNING=1 enabled
`go test ./internal/mail ./internal/dns -run
'TestQEMU(InstalledSMTP|PowerDNSNativeHealthProbe)$' -count=1 -v`.
Both pass (0.201s and 0.012s). SMTP checks active Postfix/Dovecot/Rspamd/OpenDKIM/
ClamAV/mail-Redis, native TLS465, and STARTTLS25/587 AUTH gating. The fixture
permits the bootstrap certificate; no public trust or message delivery claim.
PowerDNS exercises the native health probe, not a zone provisioning journey.
Installed63 remains unchanged. No downloads or native package changes. Guest
free space after checks3.2GiB; host218GiB before run.

### Native latin1 view import — source, 2026-09-21

New real MariaDB dump fixture failed before loading with unsafe-SQL rejection:
the view SELECT validator required UTF-8 despite the dump setting latin1. Fixed
validation of legacy single-quoted literal bytes without changing the emitted
literal, definer stripping, read-only SELECT checks or isolated loader grants.
Safety regressions cover LOAD_FILE, grant injection, multi-statement view input,
non-UTF-8 identifiers and exact preservation of quotes/semicolons/literal bytes.

QEMU Ubuntu ARM64 offline/root command, CYBERPANEL_QEMU_LIVE_TRANSFER=1:
`go test -p 2 ./internal/database ./internal/apiserver ./cmd/cyberpanel
./cmd/panel-execd -count=1` passed (18.767s/0.189s/0.395s/0.026s).
All three engine × SQL/gzip native round trips verify promoted literal hex
636166E9, latin1 character set, latin1_swedish_ci collation, matching creation
encoding metadata and three INVOKER views. Installed63 remains unchanged.

### Dependent view import promotion — source, 2026-09-21

Ubuntu ARM64 QEMU, existing native MariaDB: root/offline invocation with
`TMPDIR=/root CYBERPANEL_QEMU_LIVE_TRANSFER=1 GOPROXY=off GOTOOLCHAIN=local`
and existing guest caches ran `go test -p 2 ./internal/database
./internal/apiserver ./cmd/cyberpanel ./cmd/panel-execd -count=1` successfully.
Package durations: 15.400s, 0.102s, 0.312s, 0.022s respectively.

The native transfer fixture includes z_view over the table and a_view over z_view,
so alphabetical recreation encounters the dependent view first. All three durable
engines (InnoDB/MyISAM/Aria), plain SQL/gzip, scoped loading, promotion, destination
row values, INVOKER security and existing coordinator recovery checks pass. Table
rename deliberately breaks the source view dependency: verification rejects it
and clears the old proof, then succeeds after explicit fixture repair. The prior
failure was the fixture expecting healthy views after renaming their base table.

No project execution on host, no downloads or native package modifications.
Not an installed UI qualification or proof of safe automatic recovery from a
crash during view recreation. Installed release63 is unchanged.

### Transfer history after promotion — source, 2026-09-21

Real SQLite job/lease/completion test reproduced the transfer service denying
Inspect after a successful import advanced database generation1→2. Split history
read generation checks from mutation checks: reads authorize the current matching
owner/site/database/instance with generation at least the job's source generation;
Run/Cancel/Create retain exact generation matching. Existing readiness/health and
actor-policy checks remain intact.

QEMU regression now reads the completed job and exact stored receipt, denies
old-generation Run/Cancel, unauthorized actor, changed tenant/site/instance, invalid
generation and unhealthy resource. SQLite persistence is real; catalog projection,
actor policy and the completed native-effect receipt are explicit fixtures. This
test does not claim HTTP or native service/catalog wiring. Final offline/root
live-enabled database and panel-execd suites exit0, including native transfers.
Installed55 unchanged; broker/catalog/worker/API/UI integration remains pending.

### Non-replacing native import promotion — source, 2026-09-21

Added private fail-on-conflict promotion for verified InnoDB imports into an empty
destination. It uses the existing writer gate, source generation checks and closed
native SQL commands. Fresh isolated verification is required; one RENAME TABLE
statement moves the tables without changing the destination schema name or grant
namespace. Native destination verification runs afterward, the now-empty staging
schema is removed, and the root source generation advances once with pending
effect metadata. Durable promoting/promoted records prevent blind replay after
uncertain SQL/persistence results; committed promotion returns its original proof.

The native atomic-rename capability check follows MariaDB's documented10.6.1
boundary: [RENAME TABLE reference](https://mariadb.com/docs/server/reference/sql-statements/data-definition/rename-table).
This is a runtime capability check, not a package pin, build or vendor modification.

QEMU live SQL and gzip fixtures each allocate, import and verify into isolation,
then assert a nonempty destination is rejected and its sentinel row77 preserved.
After removing only that synthetic sentinel table, promotion succeeds and native
queries recover the exact text/NULL/binary rows in the destination. Its name stays
unchanged, protected generation becomes2, replay returns the identical promotion,
and the temporary schema is absent. Fixture destination/records are cleaned.
Final QEMU offline/root live-enabled database and panel-execd suites exit0.

Not installed or broker/API/UI exposed; installed55 unchanged. This does not yet
implement replacement imports/restore points, crash recovery, all engines/objects,
core SQL projection synchronization or end-user upload/worker admission. No power
loss or concurrent external DDL qualification is claimed. Ambiguous outcomes remain
fenced pending recovery implementation, not automatically retried or cleaned.

### Streamed native export row accounting — 2026-09-21 local date

Export now counts complete INSERT statements from native mariadb-dump output,
whose fixed arguments include --skip-extended-insert (one statement per row).
Lexical state skips comments and quoted identifiers/data, handles escaped quotes
across chunks, and buffers no row contents. Successful receipts/artifacts use
actual counted rows; checkpoints expose that count. MaximumRows is enforced while
streaming; incomplete output or limit failure aborts private artifact publication.
Preview estimates remain preflight information, not returned exported-row facts.

QEMU native SQL/gzip tests supply an intentionally inaccurate preview of0 rows
for a2-row dump. Both receipts and artifact descriptors report2, and round-trip
imports/isolated verification still recover/check the expected two rows. A second
export with limit1 and estimate0 returns ErrTransferLimit and publishes no artifact.
Counter tests vary every chunk width from1 to the fixture length, preserving all
bytes and ignoring INSERT text in comments, strings and quoted identifiers;
truncated input and explicit row-limit checks pass. Initial test-source escaping
typo was caught by guest gofmt and corrected before tests. Final QEMU offline/root
live-enabled database and panel-execd suites both exit0.

Source only; installed55 unchanged. This relies on the fixed native dump format,
not an arbitrary uploaded-SQL row estimator. Large async export jobs, broader
objects, upload/API/UI integration, import promotion and recovery remain open.

### Isolated import native verification — source, 2026-09-20

Verifier uses the existing protected job/target record, requires loader closure,
and observes actual isolated tables through a closed SQL command set. It hashes
ordered SHOW CREATE definitions, counts actual rows, records server-reported
data/index allocation bytes and requires CHECK TABLE QUICK status OK. Table names
are decoded from HEX metadata and safely backtick-escaped, including embedded
backticks. Unknown object types/engines, malformed output and bounds/declared-row
mismatches fail closed. Successful proofs are persisted in the protected record;
reverification first clears the previous proof so failure cannot leave it usable.

QEMU native SQL and gzip import tests reject verification with an active loader,
then verify the imported two rows and nonzero reported allocation after cleanup.
Renaming to a table containing a backtick still verifies and changes schema digest.
Adding a third row makes verification fail; protected state is closed with no
retained proof. Exact temporary database/account/config cleanup still passes.
Final QEMU offline/root live-enabled database and panel-execd suites exit0.

Not deployed; installed55 unchanged. This proof is health/schema/count evidence,
not source-content equality or promotion authorization. Size is native metadata,
not exact filesystem usage/quota. Promotion needs fencing and fresh revalidation.
Current export descriptors still carry preview-estimated rows; streamed row
accounting must replace that before general export→import qualification. Full
object coverage, upload/API/UI integration and crash recovery remain unfinished.

### Installed literal-grant replacement — 2026-09-20

Installed55 `qemu-grants-3.1.54`, rollback54. Manifest
`73da2a34415c5c379e44475c9bf70c4ee909195520780f07a4b50d8ebaea6e00`, receipt
`2274cfe905433db87b532f722b46998ef135e0048d6e504217900990f5a54226`, committed.
Only panel executor rebuilt inside QEMU; actual core/gateway/execd process paths
checked against55. Credential remains version1/original binding, approved and
installed executor digest `ddccb5ef12354ad747601db601537f1dad2a125fefc2b1a6b6733addc3e15864`.

Before reconciliation native mysql.db stored unescaped `qemu_ui46` for the
existing QA principal. Installed-browser password/passkey authentication followed
by `database.grants.replace` returned applied200. The request preserved the
existing grant list (create/drop/insert/select) and used expected generation1.
Native grant now stores the escaped literal name; protected grant generation2.
The initial harness mistakenly expected201 and stopped after successful mutation;
corrected it to200 and replayed the SAME persisted request/idempotency key. Replay
returned applied200, generation remained2. No duplicate mutation was issued.

Created an absent synthetic neighbor `qemuxui46`, checked the actual qemu_user46
credential cannot SELECT or INSERT there (native privilege-denial errors), then
dropped that exact neighbor in finally cleanup. Original database account still
creates/inserts/reads its generated fixture table; ungranted UPDATE and mysql.user
read remain denied. Its table was removed afterward. Installed console issues201,
metadata/query200, mutation400, recovery query200 and390px interaction all pass.

Removed regenerable1.4GiB Go cache after build to preserve release-install headroom.
Ignored host archive SHA256 `bf2472d01a5c364c14460dc8625fae658d82bf4dc20565ec53a9c4e46fed535f`
matched guest before removing the duplicate guest tar. Completed55 staging absent;
current55/rollback54 retained. No vendor changes/builds/pins/downloads.

Scope: one existing managed QA principal reconciled through the real authorized
API, not an automatic all-principal/fleet upgrade migration. Installed executor
contains recent import primitives, but private isolated-import code remains
unexposed; full import workflow and installed parity remain incomplete.

### Database-wide grant names are literal — source, 2026-09-20

Actual QEMU MariaDB regression demonstrated that generated grants on a synthetic
`qg_scope_<random>` database permitted both SELECT and INSERT on a separate
`qgxscopex<random>` database. Backtick quoting alone did not make underscores
literal. The test failed twice before the fix, once per unauthorized operation.

Changed shared database-scope GRANT generation to escape underscores; table and
routine identifier quoting remains unchanged. Native test now passes: intended
database readable, neighboring database read/write denied. It also seeds the old
broad grant before replacement, proving the existing revoke-all/replace path
removes old wildcard authority rather than retaining it. Account, both databases
and the private credential file are synthetic and cleaned after every run.
Final QEMU root/offline live-enabled database and panel-execd suites both exit0.

Source correction only; installed54 and previously created grants are unchanged.
Deployment alone does not rewrite existing grants: explicit managed-grant
reconciliation and installed verification remain required before release.

### Isolated import allocation and loader — source, 2026-09-20

Added private root executor allocation/config/discard primitives, bound to the
sealed import job and protected source tenant/site/generation/instance. Durable
creating/allocated/loading/closed/discarding records prevent automatic adoption
of unknown databases or concurrent loader replacement. Native database names
contain no grant-pattern wildcards. Disk preflight observes `@@datadir` through
the closed SQL command set and checks its filesystem, not the panel state mount.
This is requested bytes plus2GiB headroom, not aggregate reservations/index quota.

Credentials reuse the native temporary loader implementation: random loopback
account granted only the isolated database, private runtime config, no root SQL
import session. Import subprocess follows the native writer-gate context and
credential expiry. Successful results now require credential cleanup; cleanup
errors produce ambiguous rather than completed imports. Failure cleanup records
closed only after proved account/config removal. Unproven creation remains closed
to automatic reuse/deletion. Crash recovery of loading records is still pending.

Actual QEMU native SQL/gzip tests allocate and replay allocation, reject a forged
target name, issue credentials, reject duplicate issuance and active discard,
deny mysql.user reads and source-database writes, then import into the isolated
database and query exact NULL/text/binary rows. Config file is absent and native
loader account count is0 after import; explicit discard removes the isolated
database. Tests use real native root allocation/loader code; source metadata and
export secret delivery remain fixtures. All generated resources are cleaned.
Final QEMU offline/root live-enabled database and panel-execd suites exit0.

Not deployed; installed54 unchanged. These private primitives still need the
catalog's verification/promotion and broker/service/API/upload/UI integration.
They are not a completed or exposed production import feature. Wider existing
native GRANT database-name underscore escaping needs separate exact-scope proof.

### Ordinary single-database SQL import format — source, 2026-09-20

Removed mandatory CyberPanel export-comment check from the transfer import
backend. SQL is validated statement by statement regardless of provenance;
optional leading UTF-8 BOM is consumed after digest/decompression accounting.
Byte/time bounds, source descriptor/hash checks, constrained reader and native
client safety flags remain intact. Separate migrator canonical-preamble parsing
is unchanged; this does not authorize cross-database or unsupported object SQL.

Extended actual QEMU MariaDB round-trip fixture: remove only the private comment
from a genuine native dump, publish a correctly described private artifact, then
import plain and gzip versions both with and without a BOM through the target-only
account. All four variants failed `invalid database transfer` before the change.
Afterward all pass, verify complete input digest, and query back the exact two
rows with expected text/NULL/binary values. Generated variant artifacts are removed
by exact paths; original fixture cleanup removes its SQL account/config/databases.
QEMU offline/root `go test -p 2 ./internal/database ./cmd/panel-execd -count=1`
with live native transfer enabled exits0 for both packages.

Installed54 remains unchanged. This closes the private-header format restriction,
not production upload/API/UI delivery, isolated import credentials/catalog,
promotion or full object support (views/routines/triggers/events remain limited).

### Import SQL/client boundary hardening — source, 2026-09-20

QEMU regression first reproduced acceptance of a MariaDB executable-comment
`SELECT LOAD_FILE` statement and unquoted client shell/source escapes embedded
in an otherwise allowed SET statement. No such payload was executed: the
regression exercised the actual streaming reader and asserted rejection.
Validator now recognizes MariaDB executable comments, rejects unquoted escapes,
and preserves quoted data and ordinary comments. Native import client uses
`--binary-mode=1 --local-infile=0` as an additional boundary.

The first native round-trip rerun exposed rejection of the vendor's exact
`/*M!999999\- enable the sandbox mode */` protective header. Inspected the
installed mariadb-dump output and recognized only that exact preamble without
exempting adjacent executable comments. No vendor build/patch/pin was involved.

Changed native import fixture from root credentials to a random, local-only
account with privileges solely on its generated target database. Direct native
attempts to read mysql.user or create a table in the source database fail. Plain
SQL and gzip imports still reconstruct the two expected NULL/text/binary rows.
The fixture removes its account, temporary config, databases and artifacts.
This is native privilege qualification with fixture provisioning, not production
isolated-import credential/catalog/promotion or upload/API/UI completion.

Final QEMU offline/root test command, live MariaDB enabled:
`go test -p 2 ./internal/database ./cmd/panel-execd -count=1`, both exit0.
New reader regressions and existing native transfer cases pass. Installed54 is
unchanged; deploying this shared import/migrator-reader change remains pending.

### Installed export retention startup — 2026-09-20

Installed54 `qemu-retention-3.1.53`, rollback53. Manifest
`41d6b4eaa6815dcde6fb524906e7d0280b35309155dc9b3a46073500ca592e50`, receipt
`bba182b090fb51d2e66618c97b21b712ebbce8bf76fd0ca399b38b9f49864f95`, state committed.
Only our executor binary was rebuilt, inside QEMU, from collector source.
Core/gateway/executor processes all resolve into54. Existing credential remains
version1 with binding `1ff23cac43f83986652be2690e9df44d996f04bfa8510619534206a1cda86b38`;
approved/installed executor digest matches
`25a38cd01d936ede55844a5ac1526038752a134c7faf44d2ef7969956be80a06`.

New opt-in `TestQEMURetentionDaemonFixture` seeds four synthetic, root-private
artifacts under the actual executor store before installation: expired, expired
with legal hold, unexpired and expired tombstone with payload already removed.
Only explicit `CYBERPANEL_QEMU_LIVE_TRANSFER=1` plus
`CYBERPANEL_QEMU_RETENTION_PHASE=seed` or `verify` enables it; normal suites skip it.
Seed and verify commands use QEMU root/offline Go, selecting exactly
`-run ^TestQEMURetentionDaemonFixture$ -count=1 -v`. Both exit0.

Actual installed54 daemon journal at18:29:44 reports `collected 2 expired database
exports`. Verify phase confirms expired/tombstone paths absent and held/live
paths present, then removes only its two exact preserved synthetic fixtures.
The actual transfer store is empty afterward. No manual collector invocation
performed between seed and verify: service startup executed the production path.
Hourly timing itself was not observed over a complete hour.

Installed Chromium `qemu-passkey.cjs --console-fresh` passes after upgrade:
password/passkey200, authenticated overview, console201, metadata/query200,
mutation400, valid recovery query200 and390px interaction. No candidate UI mock.
No vendor components changed/rebuilt/downloaded. Bundle archived ignored on host,
SHA256 `0bf7b3e137fb456b4b10c8d1744ff3e4c882d7d0d4563b5c93bcd6e691c7d103`
matched guest before deleting the redundant guest tar. Current/rollback retained;
guest3.8GiB free. Abandoned incoming writes and delete-after-success remain outside
this expiration pass; larger async transfers/import/full parity still incomplete.

### Expired export collector — source verification, 2026-09-20

Added root-daemon startup/hourly collection, at most64 deleted artifacts per
pass with a one-minute context. Uses existing retention/expiry metadata and
hashed artifact identity, validates root ownership/modes and metadata, refuses
symlinks/hardlinks or unexpected files, and preserves legal holds/incoming writes.
Rename to a private tombstone is synced before exact payload/descriptor removal;
retries resume after rename, payload removal or descriptor removal. No recursive
deletion and no vendor changes. Missing stores are not initialized by maintenance.

QEMU Ubuntu ARM64 root-owned filesystem tests passed for expired/live/held
artifacts, all three interrupted-removal states, unknown contents, bad metadata,
identity mismatch, symlink, hardlink, unsafe mode, cancellation, maximum deletion
count, repeat collection and active-writer preservation. Full database and
panel-execd package tests passed with native MariaDB live transfer tests enabled.
Command uses the same offline/root QEMU environment documented below, selecting
`./internal/database ./cmd/panel-execd -count=1`.

This is source verification, NOT installed daemon qualification: installed53
remains unchanged. Startup/hourly execution in the installed release, abandoned
incoming-writer cleanup and explicit delete-after-success workflow remain open.

### Installed native database export — 2026-09-20

Installed53 `qemu-dbexport-3.1.52`, rollback52 retained. Manifest
`a86b11f2e4bec45397b732579379e6f78f7caaf2db1e784fde8e1e8111c57419`, receipt
`99a00d8cccc9c535eabcbce3e14088e3bcf65834a6f6a3dab1fac0387ba3589c`.
Committed receipt and actual core/gateway/execd `/proc/<pid>/exe` paths were
rechecked after resumption; all three resolve into that release.

Installed52 returned403 for export despite successful console access. Protected
executor records preserve applied input metadata, whereas the coordinator's SQL
projection is promoted to Ready/InSync. The export credential provider wrongly
required the latter state in the former store. The native fixture was changed to
reproduce this distinction: plain/gzip tests failed before the provider fix.
Executor authorization now accepts appropriate pending applied-input records;
canonical coordinator readiness and exact resource/session authorization remain.

QEMU Ubuntu ARM64 command (rerun after resumption, all four packages exit0):

```sh
sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root \
  GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath \
  GOPROXY=off GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 \
  ./internal/database ./internal/apiserver ./cmd/cyberpanel ./cmd/panel-execd -count=1
```

Host and guest changed-source SHA256 match: credentials `134383201e89859502f1594ff8dcd7981f65b33e522d4719e409528348d15672`,
native regression `b797c46bee4776fc19864ea23af9ab6af676dbddd9bcc5ca9c69ca5010e81e6e`.

Before resumption, installed Chromium harness `qemu-passkey.cjs --console-fresh
--export-live` passed against53, without candidate UI or export mocking: password
and passkey200, console201, metadata/query200, rejected mutation400, recovered
query200; SQL and gzip each prepare200/export201/download200. Browser downloads
contained the fixture table, expected text and binary `0x0001FF`, correct filename,
and verified complete SHA256. Mobile390px interaction passed. This is the recorded
installed-browser result, not a claim that the browser was rerun on resumption.

Generated fixture table and its two private export artifacts were removed after
checking; original QA database/principal retained. Regenerable guest Go cache was
cleared to recover3.6GiB before the builds. Duplicate guest52/53 bundle files were
removed only after matching ignored host archives; archive53 SHA256
`7da5470091db933ccf255eb65728c6355e2df723525586778df3d8e74004a6f8`.
Current53/rollback52 retained, completed53 staging absent, guest4.6GiB free on
resumption. No third-party component builds, patches, pins or downloads.

Limits: this proves bounded local console export, not full import/export parity.
Automatic retention collection, larger async exports, actual streamed row limits,
production isolated imports and routines/triggers/events remain unfinished, as
do external database exports and the complete installed OS/architecture matrix.

### Actual failure rollback, retry, subsequent upgrade and staging cleanup — 2026-09-20

Installed51 `qemu-recovery-3.1.50`, retained rollback49. Manifest
`2d437a4005a10afd8fd085954919dd3da8e11156de38c857d0a54819b3fcfbbb`, receipt
`6b4428abe69ef69267572963869c1772a555790c892bbe976d6a6fc4b201aaeb`.
All core/gateway/execd/secretd process executable paths resolve into51; all active.

Signed QEMU-only candidate50 deliberately changed the panel executor digest from
0cbfaac2... to6dc26f46... and supplied a panel gateway unit with failing ExecStartPre.
No vendor component changed. Apply failed at the gateway probe and automatically
restored49: receipt state rolled_back, digest
`5560667132313104f8d0cfd37a7e352151d6c9f9318e15e00fa7c11ec7f5fe7c`.
Both authorize_consumers and restore_consumers effects completed. No manual
service starts, password resets or policy edits used for recovery. Real browser
login/passkey200, console201, metadata/query200, rejected mutation400, recovery
query200 and390px interaction passed after rollback. Mail manifest unchanged.
Retrying50 produced rolled_back without activation; later normal51 committed and
passed the same installed UI workflow with executor6dc26f46... actually running.
Original principal remains version1 with unchanged binding1ff23cac... .

Found duplicate extraction directories accumulating after each apply. Added
root-owned, exact-digest staging cleanup when Apply exits and when recovery
completes, without deleting the input bundle or materialized rollback packages.
New prune-staging command first verifies BOTH current/previous signed release
trees, then removes only their redundant extractions. Live command recovered
about1GiB from staging48/49. QEMU noderelease suite passes with root fixtures for
cleanup, absent-target replay, wrong digest, target/root symlink, writable parent,
traversal ID and protection of a file referenced by a symlink inside staging.

Actual staging directories were absent after50 rollback,50 retry and51 commit.
One final older50 admission after51 reproduced source-frontier rejection and
proved rejected extraction cleanup; active51/previous49 unchanged. The first
attempt to replay50 immediately after archiving correctly rejected its temporary
harness group ownership; restored root:root0600 before exercising the replay.
This fixture setup rejection is not claimed as rollback evidence.

Fault50 bundle archived ignored on host with SHA256
`22a16aac48583960054631d05346ed3e1c00213466855cae7d6b68545215c224`;
its failed materialized root and guest bundle were removed after terminal-journal,
current/previous and process-map checks. Normal51 bundle archived SHA256
`f627d1e93d2ddc53772e600cc25b80f688b11c927e235febdbb07748b2e21ed0`;
redundant guest bundle and final replay input removed after verification. Current51/
rollback49 intact; guest3.1GiB free. Fault unit was never committed to product source
and removed from assembly staging. No new downloads/workers or vendor builds/pins.

Limits: this is Ubuntu ARM64 normal upgrade/activation-failure recovery evidence,
not power-loss injection or the complete four-target/OLS+LSE service matrix. The
tested bootstrap executable is still the native harness installer; its system
installation path remains unqualified. Full CyberPanel functional parity remains
open, including writable SQL/import/export and broader native service journeys.

### Signed consumer authority and frontend activation verified — 2026-09-20

Signed49 `qemu-activation-3.1.48` installed, rollback48 retained. Manifest
`26aa0129bda6bf61e0b3e7f072dea7a50d3d30e112625b35ecf3cd4b895dd6ee`;
receipt `cac220e70339346bfaef0ecd5a8fc05d8fa91d85ec1c0944b8f16316dd6da5d4`.
All four core/gateway/execd/secretd process executable paths resolve into49.
Core/gateway/broker active with Result=success,NRestarts=0. Candidate broker
override removed before signed deployment; candidate binaries subsequently removed.
Gateway's guest-only localhost TLS/passkey configuration fixture remains.

Implemented root-only release-authority transitions in the protected broker DB.
Unlike the prior explicit credential-rebinding primitive, panel upgrades do not
rewrite secret versions/bindings/material. The installer verifies retained signed
manifests and artifact trees, pairs binary destinations, durably authorizes the
replacement, and reverses authority on rollback. Broker transition batch is atomic;
changed or stale replays and non-root requests rejected. Delivery rechecks current
authority so an old unconsumed grant cannot bypass executable retirement. Existing
tenant, adapter, purpose, operation and process identity validation retained.
Installed principal remains active version1 and original binding digest
`1ff23cac43f83986652be2690e9df44d996f04bfa8510619534206a1cda86b38`;
old anchor12dd0aad... now authorizes actual executor0cbfaac2.... No password reset.

QEMU candidate and then installed49 real Chromium checks:
password/passkey login200; database.list200; console.issue201; metadata200;
SELECT DATABASE()200 with correct displayed result; mutation400; subsequent
valid query200;390px mobile interaction passes. No candidate static interception.
Mail config manifest check has no mismatches; WAF remains root:root0600.

Signed48 first exposed a separate failure: alphabetical repeated broker restarts
caused core socket-start races and start-limit-hit while an incomplete service
probe list still allowed commit. Recovered48 manually, then fixed installer to
quiesce core/gateway once, order provider probes, authorize after broker readiness,
and include shipped execd/core/gateway probes without changing signed manifests.
Signed49 applied with NO manual recovery and then passed the installed checks.
QEMU `go test -p 2 ./internal/secrets ./internal/noderelease -count=1` and earlier
architecture/installer checks pass. New tests exercise real broker grant/delivery,
unchanged metadata/material, chained upgrades and rollback, denied old/unrelated
consumers, tenant/adapter/operation checks, non-root management, conflict/replay,
SQL-trigger-injected transaction failure, exact signed role pairing and service
ordering. Installed rollback/failure-injection and four-target qualification are
still pending; older brokers lack the new authority table support. The bootstrap
installer at its system path was not replaced; the tested native harness installer
was rebuilt. Do not equate this checkpoint with complete product parity.

Disk cleanup: archived obsolete releases28/29/30/45 to ignored host
`obsolete-releases-28-30-45.tar.gz`, SHA256
`88bdb37dd8bbdd42856d732afa3227e6d0dac32ce9e4d055e399f1d2bf91f664`;
gzip/manifest checks passed before exact locked process-map-checked guest removal.
Obsolete47 removed against verified retained bundle47. Bundles48/49 also archived
with SHA256 verification before redundant guest copies were removed. Current49/
rollback48 preserved. Temporary candidate binaries removed after process checks.
No third-party builds, downloads, native dependency pins or Git binary artifacts.

### Signed47 and credential release-binding regression — 2026-09-20

Installed qemu-console-3.1.46, current47/rollback46. Manifest
`ca9b077af51054c2c147ed1f1930771e07707bbe12bd99bf34df7074c3f018ee`, receipt
`0ad2a5aac192b58452cf6bb7a179f25491bfefd28107427415250422dcedf099`.
Core/gateway/execd executable paths verified in installed47; services and OLS
active. Mail manifest and WAF ownership unchanged. Stale QEMU-only Restart=no
override interfered with core socket startup recovery; removed it and started
core normally. This is not proof of an unattended upgrade.

Installed browser login/passkey/list succeeded; console session creation201,
metadata/query500. Native DB login and allowed/denied grant checks still passed.
Read-only broker metadata probe proves principal bound executable
`12dd0aadbf1b8ed413bd04c4a210150f5427fef5abd2c5272fc75e01b78b1b21`
differs from installed executor
`0cbfaac22858b090d62790b3db24593bccccf24b79a606a7998365e91c77acd5`.
No passwords/ciphertexts exported. Earlier candidate tests used the old executor,
so their success does not qualify installed47 console access.

Implemented source-only root management consumer rebinding. New envelope version
preserves external credential material and all audience fields except explicitly
authorized executable digest. Prior binding/version checked, replay bounded,
revocation serialized with rebinding. Normal non-root management cannot invoke it.
QEMU Ubuntu ARM64: `go test -p 2 ./internal/secrets -count=1` PASS.
`TestConsumerRebindPreservesMaterialAndRejectsOldConsumer` exercises management
frames, SQLite envelopes, denied new-executable delivery before authorization,
unchanged password delivered after authorization, replay, old-consumer denial
for current version, forward-version rollback and stale replay rejection.
`TestConsumerRebindRejectsAuthorityChanges` passes14 negative variants.
These are broker regressions, NOT installed endpoint verification of the fix.
Signed installer integration, generation-coupled consumers, deployment and real
browser upgrade/recovery qualification remain pending. No third-party changes.

Obsolete release44 archive and duplicate bundles46/47 were hash-verified on host
before guest removal; rollback46/current47 remain. Guest2.2GiB free. Archives
are ignored under .work/qemu and recoverable, never added to Git.

### Panel-only upgrade no longer reinstalls unchanged native packages — 2026-09-20

Identified a concrete cause of repeated package-maintainer configuration changes:
`installOfflinePackages` always ran dpkg/rpm over the entire release package set,
including already configured identical versions. It now verifies all supplied
package metadata/inventories as before, selects only packages lacking exact
installed version/architecture/completion evidence, runs the remaining batch
once (if any), then verifies final evidence for every package. Pending cycles
still enter one batch. Dpkg's `installed ok` requirement remains mandatory;
unpacked/broken packages do not count as satisfied.

QEMU-only, real native dpkg regression
`CYBERPANEL_QEMU_PACKAGE_REPLAY=1 go test -p 2 ./internal/noderelease -run TestQEMUOfflinePackageReplay -count=1 -v`:
before fix FAIL `maintainer script ran 2 times, want 1`; after fix PASS. The
test builds a tiny disposable panel-owned text package, not third-party software.
It proves first install, unchanged replay without postinst execution, actual
upgrade, downgrade, recovery after dpkg --unpack, and no mutation when a later
input's metadata fails validation. Package and counter purged on both red/green
runs; filesystem/package-manager checks confirm cleanup. Full noderelease suite
also passes. Existing core/gateway/execd/OLS remain active, guest2.5GiB free.

Not yet in the installed bootstrap installer. Rebuild it before the next signed
release. This addresses panel-only upgrades; safe conffile handling when native
packages genuinely change and full unattended release qualification remain open.
No vendor changes/downloads or product version pin added.

### Database UI/native grants and console repair — 2026-09-20

Installed signed46, actual browser password+passkey session:
`database.database.create_managed`201 for qemu_ui46 (64MiB quota), listing200 and
row visible; native MariaDB confirms utf8mb4/utf8mb4_unicode_ci.
`database.principal.create_managed`201 for qemu_user46 with select/insert/create/drop
only; UI clears password after submit. The secret is random and remains solely in
a guest0600 fixture, not source/Git/log output. Actual socket login as that principal
created a temporary table, inserted and read expected data. UPDATE and SELECT from
mysql.user both failed with native ERROR1142. Temporary table dropped in finally;
database/principal retained for subsequent workflow qualification.

Real Open console reproduced400: generic UI submitted an empty session object.
Replaced that edge with a typed selected-principal request. Server derives tenant,
database/site, generation, existing credential reference, bounded limits and a
15-minute session. Principal selection is restricted to ready grants on that DB;
cross-tenant/site/instance, disabled/missing-grant and stale-generation requests
are rejected. Session replay preserves ID and expiry. Public projection contains
no credential material. The SQL repository closes its cursor before subsequent
loads, supporting the single-connection control database.

New UI opens that session and uses existing scoped workspace metadata/query APIs.
It displays tables/views, escaped tabular results, truncation, expiration and errors.
Changing principal resets the opening idempotency key; retries retain it. Requests
are aborted when closing. Existing workspace API is read-only; this is not a claim
of complete phpMyAdmin-style SQL write/import/export parity.

QEMU-only validation: database/apiserver/cyberpanel Go suites pass; added
TestManagedConsoleBindsDatabasePrincipalAndTenant passes all seven variants plus
expiry-preserving replay using a real single-connection SQLite repository. UI
typecheck/build pass (existing >500kB chunk warning retained). Candidate core and
gateway were built in QEMU, UI served from QEMU dist through the existing browser
fixture. Initial candidate placement outside a supported slot failed packaged
recipe validation; moved to a supported root-owned QEMU slot with unchanged signed
recipe companions, without weakening validation. Updating only core also exposed
the gateway's old request contract; matching candidate gateway resolved it.

Actual browser on matched candidates: console201, metadata200, query200 with
qemu_ui46 rendered. Disallowed DELETE400 and visible error, then successful SELECT200.
390px mobile query/close interactions and no horizontal console overflow pass.
Temporary service overrides removed afterward; installed signed46 restored.
All four services active and gateway readiness200 after restoration. Removed only
the two generated candidate binaries and copied recipe companions after checking
no process executes that slot; empty slot directories removed. These temporary
artifacts are reproducible from source and installed signed recipes.
No release certification/deployment claim. No downloads/vendor builds/new workers.

### Installed mapping discovery and real UI trash — 2026-09-20

Removed the compiled-in ModSecurity release directory from generated initial and
managed WAF policies. Mapping discovery prefers conventional root-owned paths in
`/etc/modsecurity`, `/etc/modsecurity.d`, the native server's `conf/modsec`, or
the CRS root. A single installed-release subdirectory is also accepted without
pinning its name. Missing, empty, writable, unsafe or ambiguous mappings fail;
no source-build/download fallback exists. Mapping bytes join activation evidence
even when the mapping is outside the CRS directory. Exact initial-policy journal
recognition remains valid across layout names. Installer replay preserves later
managed policies and refuses silently replacing an initial policy after a layout
change. The directive's meaning was checked against the upstream
[ModSecurity manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#secunicodemapfile).

QEMU Ubuntu ARM64 only: full operations and cyberpanel package suites passed.
After adding native-parser checks, the focused installed-assets/mapping/installer
tests passed with `CYBERPANEL_QEMU_WAF=1`. Actual installed OLS `lshttpd -t` accepted
both installed and conventional unversioned mapping layouts, each bound only in
a private read-only mount namespace. Live WAF files and server were not replaced.
These source changes are NOT in installed signed46 yet. Normal CRS package/layout
replacement remains pending; no claim that the guest custom package is removed.

Installed signed46 UI: fresh password and real browser passkey login both HTTP200;
fresh tenant site listing and file listing HTTP200. Used file-manager Trash on
ONLY `qemu-ui-created.php` and `qemu-ui-upload.txt`: both `access.trash.move` HTTP201,
both rows disappeared, and native HTTP now returns404 for both fixture URLs.
Files are recoverable through trash, not permanently deleted. Fresh site's PHP
pool remains active with empty DropInPaths; core/gateway/execd/OLS remain active.
Guest free2.6GiB. No downloads, vendor builds, new workers, or release bundles.

### Signed46 installed; native UI verification and upgrade limits — 2026-09-20

QEMU socket regression additionally proves web-worker write permission, unrelated
tenant denial, wrong-owner rejection and symlink rejection on a real Unix socket.
Source socket test formatted in QEMU. Archived obsolete31/32/33/43 to ignored host
obsolete-releases-31-33-43.tar.gz; gzip integrity and all four manifest sequences
verified, then exact roots removed under installer lock and process-map guards.
Free guest space increased2.3->4.2GiB before packaging; current45/rollback44 untouched.

Assembled and installed signed46 qemu-site-3.1.45:
bundle2ef10d084a6191115725055c64a2412bc37bbde61759608f582670c8cc5e3fde,
manifest86dd65bef7da361ea0b379448f5db58561d2118d59668069492801a25d9b86f0,
receipt84022b6ceb4a30a215df9a93034cb5f22f4c27f218a8496a9b549541b5073cf5.
105 artifacts,532456746 artifact bytes. Current46/rollback45. Rebuilt core/executor
in QEMU, included current built UI and strict native executor unit. No downloads.

Upgrade qualification exposed manual requirements. The existing mail-restore
script was non-executable; my direct invocation failed and should have used sh.
Installer nevertheless committed. WAF policy remained byte-identical but package
ownership reverted to lsadm; restored root ownership under exact hash guard and
ran service reconciliation. Core then rejected mail generation integrity. Initial
mail daemon start alone was insufficient. Bounded diagnostic identified sealed
clamav/clamd.conf metadata drift:0440/GID112 became0644/GID0, content and size
unchanged. Restored ONLY its manifest-expected metadata after validating hash;
all mail artifact hashes/metadata then matched and core startup succeeded.
This is NOT proof of unattended upgrade; automate protection/reconciliation.

Removed temporary diagnostic instrumentation from source and guest. Removed
executor candidate/strict/diagnostic unit overrides and three unused candidate
binaries after process-map checks. Executor/core use installed46 paths, strict
sandbox from installed unit. Existing g2 PHP pool's temporary post-start drop-in
now invokes installed panel-execd; fresh generated-unit qualification remains.
Gateway retains only localhost HTTPS fixture; browser ignores only its test cert.

Actual installed UI (NO candidate asset routing): password200, WebAuthn200,
authenticated overview, site-list200 and existing hostname visible; layout checks
pass1280/1920/1024, collapsed navigation and390 mobile. Gateway readiness is ready.
Guest2.7GiB free, release46 bundle retained. Fresh site-create API, ACL-preserving
uploads/restores and unattended upgrades remain outstanding.

### Real tenant PHP/static serving with scoped ACLs — 2026-09-20

Confirmed cyberpanel-web could not read/traverse the public tree; pool socket was
also inaccessible. Added descriptor-relative named-user ACL installation during
EnsureDirectories. Only public/uploads receive read/traverse and inheritable ACLs;
generation/release/shared ancestors receive traversal. No world-readable trees,
shared tenant group, or private/session/config grants. Root-QEMU tests create real
directories/files then run /usr/bin/test under web-worker and unrelated tenant
credentials: public allowed for web only, private denied for both; repeat ensure
preserves expected access.

Added --lsapi-web-access helper to panel-execd, dispatched before daemon startup.
It runs as the site UID, checks UID range/name against the closed site key and
canonical generation, opens fixed runtime directories without following symlinks,
validates socket ownership/type/link count, and grants only cyberpanel-web access.
Generated LSAPI unit invokes it after every start without privilege elevation.
The initial native test exposed O_RDONLY opening a0711 runtime root; switched that
root descriptor to O_PATH, preserving no-follow traversal and no directory listing.

Bounded guest diagnostic repaired only this registered active g2 public layout.
The candidate helper as the actual site user enabled its socket; real native PHP
request returned200 and qemu-site-php-ok. A temporary native pool drop-in invoked
the candidate helper inside the service sandbox; restart succeeded and PHP still
returned200. PHP-created static content inherited its ACL and returned200 with
qemu-site-static-ok. Web account cannot traverse the private directory.

GNU install stripped ACLs from a separately copied static fixture (403); this
does not qualify arbitrary import/upload/restore paths. They must preserve or
restore the public access policy. Existing non-inheriting files are not recursively
rewritten by this change. All three public test files removed as their owning site
account after checks; reproducible fixture sources remain ignored outside Git.
Changes are source/candidate-tested, not yet in signed45. Runtime pool drop-in
99-qemu-web-access.conf uses qemu-execd-public-access; main candidate executor is
still qemu-execd-site-recovery. Fresh signed-install/site-create remains pending.

### Replacement recovery and first persisted active site — 2026-09-20

Added restored-generation recovery for exact ambiguous replacement attempts.
Broker requires rollback-restored evidence, matching request/candidate/previous
digests, confirmed current receipt with verified master, and exact live previous
health response. SQL admission keeps epoch/drain/lease guards and archives the
old lease. Broker rechecks proof before applying and archives the complete prior
receipt to an immutable0600 recovery file before advancing the live journal;
existing journal schema remains compatible. Wrong master, unconfirmed state,
store verification failure, wrong live digest,404, missing restoration, pending
attempt and changed request regressions all reject. QEMU webactivation,
rebootcontrol and panel-execd suites pass.

Rebuilt/deployed QEMU candidate executor containing reload/probe/recovery changes.
Original service diagnostic --complete returned create=applied and
activation=applied. Read-only SQLite verifies both original commands confirmed,
one hosting_sites row, final generation2; native site health HTTP returns digest
70d2d2befb8795563b58bfe34730d7779c3d04fc88f3e547b5ad3ace22a52129.
Full prior receipt is retained in webengine-activation/recovery-b4d4db007bede2bb82a9f04535291d4cc1fd88b453b143a7454fefbb6f043118.json.
This resumed the original production service path, NOT a successful replay of
the browser create API; no second create request, receipt deletion or DB reset.

An actual tenant-owned0640 PHP fixture at g2/releases/current/public/
qemu-panel-smoke.php returns403. Namei shows0750 tenant-group-only traversal from
generation root downward; renderer's web workers use cyberpanel-web and no public
ACL is installed. Native serving is NOT qualified. Fix controlled public-tree
traversal/read access, keeping private/session/config isolation, then recheck.
Fixture remains only in ignored host/guest test locations pending that check.
Signed45 unchanged, temporary candidate executor and gateway fixture remain.
Fresh real browser password/passkey login succeeded; hosting.site.list returned200
and the original customer hostname is visible in the UI (candidate static assets,
real installed backend). This visibility does not qualify the failing PHP request.

### Vendor-context reload verified; rollback probe corrected — 2026-09-20

Rebuilt/restarted the existing QEMU candidate executor with systemd reload mapping.
The ignored diagnostic's --reload calls actual FixedRunner, executed inside the
real executor mount namespace; exit0. No vendor files modified. Core and gateway
were explicitly restarted afterward. Current signed release remains45.

Native HTTP to default.invalid /.well-known/panel-health/activation returned
panel-health-v1 98515aa557ad729626e3ec2119b46d0b6e1b6f401cf7184866afc7b5267865b4,
exactly matching the confirmed on-disk current receipt. The new tenant hostname
returned404 under that previous generation. This exposed the rollback probe's
dependence on a newly added candidate route. Production composition always has
binding/system-default; probe selection now prefers that permanent binding.
Standalone consumers without it retain their prior route selection.

QEMU TestProbePrefersPermanentSystemBindingForRollback failed selecting the new
tenant before the change, then passed with the system binding and fallback case.
Uncached webactivation, lswsruntime, activation and fsstore suites pass. Probe
selection is source-only until the next candidate build. Actual tenant-route
serving remains an independent delivery requirement, not proved by system health.
Replacement activation recovery and final site persistence are still pending.

### Native reload integration failure isolated — 2026-09-20

Extended the ignored guest-only diagnostic to reconstruct the original accepted
CreateSite command through production hosting service, SQL repository, catalog,
controller, provisioner and activation broker. Same command ID/scope/input;
repository validates its digest. It does not bypass receipts or create a new site.
The operation remains ambiguous at web activation: candidate5cef48be... had
ReloadRequested=true, CandidateProbed=false, RollbackRestored=true and
RollbackReloaded=false, previous confirmed digest98515aa5....

Directly reproduced the closed native reload invocation inside the actual executor
mount namespace. Vendor lswsctrl reported read-only lsrestart.log and could not
see its PID file because the executor uses PrivateTmp. This is our integration
error. FixedRunner now asks systemd to reload fixed lsws.service; its vendor
ExecReload runs in the web-server service context. No vendor script, module,
version or package changed. The exact systemctl invocation from the executor
namespace succeeded and lshttpd remained active. Uncached QEMU webactivation,
lswsruntime, activation and fsstore suites passed. Running candidate executor
still needs rebuild with this mapping; full site activation remains unqualified.

Existing activation recovery only handles stopped initial installation. The
recorded replacement failure must be recovered from verified current/master/live
previous-generation evidence, retaining the old attempt. No receipt reset or
relabeling was performed. Hosting command and final site row remain unresolved.

### Original site effect recovered to prepared — 2026-09-20

Implemented a narrow initial-identity recovery path between siteops and execution
admission. Its read-only registry evidence requires exact scope/request digest,
same generation/fence, zero roots/pools, and either allocated/failed host operation
or active/completed identity record. This permits retry of the existing idempotent
identity operation; it does not assert host success. The existing SQL recovery
transaction retains the old attempt, replaces its lease token, and still enforces
ambiguity, epoch and drain guards. Startup wrapper requires executor readiness.
No RPC operation, caller-supplied proof, lease deletion or journal reset added.

Uncached QEMU siteops, rebootcontrol and panel-execd tests pass. Rejections cover
running record, changed digest/fence/operation, wrong failure, existing root and
suspended binding; SQL integration covers active lease, changed epoch, preserved
prior attempt, stale settlement rejection and terminal replay.

Candidate executor built in QEMU and loaded through runtime unit override
99-qemu-site-recovery.conf, retaining strict filesystem confinement. The original
accepted effect through the guest-only provisioning diagnostic reached PREPARED.
Registry confirms identity attempt2 complete, directories complete and pool
complete, generation1. Native cyberpanel-lsapi-s-10983ef8baf3818d87768836-g1.service
is active/running. All three corresponding execution admission rows are completed.
No second site-create request was sent. Hosting command remains ambiguous and
hosting_sites count is0: web activation/final commit are not yet qualified.
Core was stopped during executor restart then explicitly started; the pending
core startup-retry fix has not yet been live-tested in an updated core binary.

Storage guard correctly blocked the first build below2GiB. Copied redundant45
bundle to ignored host .work/qemu/panel-tenant-3.1.44.tar, verified both copies
against a0026d61bc6e05d3bdcb408749244013e598704fe1a1b7c4911f029381b5ee8c,
then removed only the guest tar under installer lock. Recoverable host copy,
current45 and rollback44 preserved. Guest2.5GiB free. No downloads/vendor builds.

### Bounded startup admission contention retry — 2026-09-20

The prior native SQLITE_BUSY startup failure is now reproduced deterministically
using two real SQLite connections to a temporary WAL database in QEMU. A writer
holds the gate row while core initializes; the original implementation immediately
returned database-is-locked before the writer released. Initialization now retries
the complete rolled-back attempt for SQLITE_BUSY and its extended codes only,
within five seconds or the caller's earlier deadline. Other failures are returned
unchanged; no gate state, effect receipt or safety check is bypassed.

The regression now passes after releasing the writer and verifies one gate row.
A second held writer proves caller deadline cancellation. Full uncached QEMU
cmd/cyberpanel and internal/rebootcontrol suites pass. Changes were formatted in
QEMU and retrieved to source. This is source-level regression evidence, NOT a
claim that an updated core binary has passed a native concurrent-service restart;
that remains part of the next accumulated release qualification. No downloads.

### Site creation: layout, persisted PHP profile and executor sandbox — 2026-09-20

Candidate AppShell explicitly places main content in grid column2. The previous
layout blocked the Create site button beneath the fixed sidebar. QEMU-built static
assets, served through the browser harness with real installed45 API/authentication,
passed desktop1280/1920/1024, collapsed navigation and mobile390 form interaction.
This does not claim the candidate UI is installed in the signed release.

The subsequent real site-create request returned500. Its journal lost PHPProfile
across save/reopen; added serialization in both directions. A real FileJournal
regression failed forPHP82/83/84 before the fix and passes afterward, including
resume validation. Offline QEMU `go test -p 2 ./internal/hosting/... -count=1`
passed again; host/guest source hashes match for provisioning.go and AppShell.vue.

Native identity creation failed opening /etc/.pwd.lock with EROFS. Inspection of
the actual executor mount namespace confirmed /etc ro with ProtectSystem=full.
A bounded transient strict-sandbox experiment succeeded. Source changes only
ProtectSystem to strict, retaining explicit ReadWritePaths and other controls.
Applied the same setting to the real QEMU executor through runtime override
91-qemu-filesystem.conf: service active, admission ready, /etc rw, /usr/bin ro;
the bounded identity diagnostic in its mount namespace exits0. No native vendor
builds, patches or downloads. Other executor operations remain to be exercised
under this stricter sandbox before packaging; signed45 is unchanged.

Restarting executor also restarted dependent core, which failed its admission
bootstrap with SQLITE_BUSY. Core's existing QEMU Restart=no override left it down;
an explicit start succeeded and gateway readiness returned ready. First browser
recheck timed out at login while core was down. This startup contention is an
additional unresolved integration issue, not a vendor defect.

Site creation is NOT successful yet. Original command
api_3acd4deffa2846226cbfa3f178446b780642ef6b0db8b3b3 is ambiguous, no hosting_sites
row exists, registry remains allocated, outer ensure_identity admission is fenced.
The exact allocated Unix identity exists following the diagnostic; no site root or
PHP pool success is claimed. A bounded fixture repair restored only its omitted
PHPProfile from the matching accepted request after checking all steps were empty.
No journals or admission rows were reset/deleted. Recover this original effect
with observed evidence rather than submitting another site. Temporary diagnostic
source/binary remain guest-only; no generated artifacts added to Git.

### Managed customer creation and reauthentication — 2026-09-20

Tenant creation503 traced to the real audit boundary. A small identity-only test
passed; adding a SQL-writing audit sink on the same single-connection database
reproduced a deadline. The real audit adapter separately rejected `prepared`.
Prepared is now an explicit audit outcome, not an applied event. Creation writes
its durable intent before opening the control transaction, retaining transactional
quota, ownership, delegation, membership and tenant writes. Unique attempt event
IDs avoid timestamp conflicts between retry intents. Audit failure prevents any
tenant mutation; quota failure leaves no tenant. Other lifecycle audit placements
are not qualified by this fix.

Regression additionally caught manager role assignment leaving reusable credentials
on the old authz epoch. Active non-API credentials now follow the new principal
epoch; old sessions and API credentials remain stale. Tests verify this distinction.
Offline QEMU identity/audit/apiserver/authn suites passed uncached, and core rebuilt.

Signed45 qemu-tenant-3.1.44 contains these changes AND the previous client-data fix:
bundle `a0026d61bc6e05d3bdcb408749244013e598704fe1a1b7c4911f029381b5ee8c`,
manifest `dfa1fd84c73162386b1fe7791055cb743a7c1e034b87b91f4a4cc93f4763d6dc`,
receipt `1750a69b49a3b34a9d64e34cd7d88e61c073c803497e51164d8b07fe675580a8`.
Existing manual install reconciliation remains necessary. Removed temporary authd
override; native authd/core now run installed45. Gateway keeps only the local HTTPS
test fixture. Actual Chromium passkey assertion including its extra member returned
200/assurance3. Actual UI tenant create returned201; subsequent401 reflected the
expected authority-change session invalidation. Fresh password and passkey login
both returned200, and the created customer was visible in Users & tenants. Read-only
SQLite inspection confirmed active customer and `tenant.create` prepared audit row.

Next site-create browser attempt was blocked before submission: fixed sidebar
intercepts the button because shell-main auto-occupies the sidebar grid column.
No site-create API request was sent and no site creation success is claimed.

Archived obsolete41/42 outside Git, validated gzip and both release manifests,
then removed exact directories under installer lock after active/rollback and
process-map checks. Recoverable archive `.work/qemu/obsolete-releases-41-42.tar.gz`.
Removed redundant44 bundle and candidate executables after45 installed; retained
installed45/rollback44. Guest2.2GiB free, host229GiB. No downloads/vendor source builds.

### HTTPS passkeys and first real tenant-create attempt — 2026-09-20

QEMU reproduced rejection of HTTPS8090 and configured localhost by `webAuthnRP`.
The fix permits valid panel ports and localhost, retaining HTTPS, same-host and
configured-origin enforcement, and explicitly rejecting IP RP IDs. Regression
tests include invalid ports, alternate hosts, plaintext, paths and userinfo.

Signed44 qemu-passkey-3.1.43 installed:
bundle `4d494f24b75bd74e9a9b95fd21696a7138863ddb3f7224cfe6c2ea4dd6176c0a`,
manifest `64839c71f265d9b84016eb72cfe545368465e987498c3cadcd52f8d14074a291`,
receipt `62631362f71e7948c8c40937e4ffdc7f59ffaeb0dccdd0775ae98e5b12daf472`.
Existing manual mail/WAF install reconciliation was still necessary. No vendor
source compilation or patches. Current44/rollback43 retained; redundant43 tar and
abandoned core candidates removed. Guest approximately2.3GiB free.

Actual QEMU Chromium virtual-authenticator enrollment returned201/200. Passkey
login was intermittent401: isolated actual failed assertion to rejection of
Chromium's `other_keys_can_be_added_here` client-data member. The
[WebAuthn CollectedClientData specification](https://www.w3.org/TR/webauthn-3/#dictionary-client-data)
requires tolerance of unknown keys. Dedicated client-data decoding now allows
extensions without relaxing our API envelopes, duplicate-key rejection, challenge,
origin or cross-origin validation. Signature verification still uses original bytes.
Regression went red for both registration/assertion extension cases, then green;
negative duplicate/origin/challenge/trailing-data cases remain rejected.

QEMU command `go test -p 2 ./internal/authn ./internal/apiserver ./internal/identity
-count=1` passed offline. The changed verifier was built in QEMU and exercised
under the native authd sandbox via temporary99-qemu-clientdata.conf override.
Actual UI passkey login succeeded repeatedly, including a browser-generated
assertion WITH the extension; HTTP200, assurance3, authenticated overview rendered.
This verifier fix is not yet in signed44. Gateway uses a temporary localhost HTTPS
fixture at8090; browser certificate bypass is limited to that self-signed fixture.
Core uses installed44; authd/core/gateway/OLS all active, HTTPS readiness200.

Next actual UI tenant-create attempt reached the backend but returned503
`unavailable`. No successful tenant creation or site provisioning claimed.
Harness and test credentials remain guest-only/ignored; captured assertion and
virtual-authenticator private key must never be printed or committed. The temporary
diagnostic Go file was removed from guest source after isolating the failure.

### Real installation claim and authenticated UI — 2026-09-20

Signed43 qemu-claim-3.1.42 deployed the bootstrap fixes:
bundle66453e248ac5e8fab9013c2c3659a51ba965cc4d77352aefb28c1db1efbb2d00,
manifest5cbcc9a4ab0132bc39374aaed01e7317d39bde936bf15ac9f4fc2bc7c6b8d84c,
receipt6faf12ecbbbfa71bb0e6f96379e558577358c533b82d8e87a6bcc8b1bad30cf0.
Core built offline in QEMU. QEMU-only signing maximum42→43; key/minimum/expiry
unchanged. Existing documented manual mail/WAF reconciliation still required.

The actual local recovery socket accepted a dedicated QEMU installation owner
claim with201, exercising real protected password enrollment and first-session
authentication. Claim token consumed; replay of that same token returns401.
Random account password stored only in the guest's0600 test credential file;
neither password, claim token nor session/CSRF tokens were printed.

QEMU Playwright exercised real browser login200 and authenticated overview with
no page errors. Observed operations: anonymous session.current401 (expected),
session.login200, observability.dashboard.get200, identity.tenant.list200.
Navigated Users & tenants and opened Create tenant: manager, ownership contacts
and delegation fields visible. No tenant submitted; MFA and tenant/site mutation
journeys remain pending. Screenshots qemu-owner-dashboard.png and
qemu-owner-tenant-form.png reside only in /home/harness. Core/gateway/OLS active
on installed paths; no runtime candidate override.

Before installation, archived obsolete34–36/40 to ignored host file
.work/qemu/obsolete-releases-34-36-40.tar.gz, verified gzip plus four manifests,
then removed exact guest roots under installer lock after active/rollback and
process-map checks. Journals retained and archive is recoverable. After43,
removed redundant42 bundle and three unused candidate executables; installed43
and rollback42 preserved. No downloads, native builds or generated Git artifacts.

### Signed gateway completion and one-time bootstrap guard — 2026-09-20

Archived obsolete guest releases37–39 to the ignored host artifact
`.work/qemu/obsolete-releases-37-39.tar.gz` (1.3GiB). Gzip validation and all three
manifest entries verified. Current41/rollback40, terminal journals and absence
from process maps checked; under installer lock removed only those three exact
guest release directories. Reclaimed about1.4GiB; archives remain recoverable.

Signed sequence42 qemu-gateway-credential-3.1.41 committed:
bundle0a83e48931f4be1e572ec5f6ead5d920fcdc85cb034be0d7892466f8e99a05a5,
manifest2cd210e30717bd3b830c1eba9021bbd02ea2c41f066c2b49f446c43bbd44dd7c,
receiptf21a9bed5913c49292f753f9d3d4eb82cd46d19812059e4a56fdbfcb2009fb96.
Core and gateway were built in QEMU; fixed source destinations checked before
assembly. QEMU-only signing trust maximum extended41→42 without changing its
key/minimum/expiry. Existing manual mail/WAF/reconciliation prerequisites remain.
Removed99-qemu-candidate-test.conf and qemu-paneld-credential. Actual systemd
ExecStart now uses /usr/lib/cyberpanel/bin/paneld. Core/gateway/OLS all active;
HTTP gateway readiness returns ready. Desktop/mobile Playwright checks repeated
against the normal installed gateway: entry renders, no JS errors/overflow,
nonexistent-account submission returns401 with visible error. Redundant41 tar
removed after confirming installed42 and rollback41; guest approximately2.5GiB free.

Before using the actual claim token, a SQLite-backed QEMU regression exposed
two product defects: initial password credential storage passed nil public_data
to a NOT NULL blob column; after correcting that, a second distinct installation
owner claim succeeded. Fixed persistence to represent absent public metadata as
an empty blob. Added a singleton claim reservation in the same transaction as
initial authority creation, plus a guard for existing principals/tenants (including
pre-marker installations). Rejected claims revoke their newly enrolled verifier.
Tests cover successful first claim, distinct/reused-ID rejection, existing state
without a marker, empty-blob storage, rollback allowing retry and committed
reservation denying another claim. Identity/apiserver/cyberpanel suites PASS
uncached in QEMU. Protected authentication is stubbed in this database regression;
it does NOT qualify real credential enrollment or authenticated browser journeys.
The bootstrap correction is source-only pending the next signed deployment;
the actual guest claim token was not consumed and no real owner was created.

### Registry consolidation and live panel entry — 2026-09-20

QEMU regression first reproduced `duplicate operation identity.tenant.list`.
Removed the console's three duplicate tenant registrations AND its handler
overrides. Managed identity owns list/create/suspend, preserving tenant:create,
MFA, manager/ownership contacts, delegated authority and revision concurrency.
Tests prove complete registry assembly, canonical payloads, missing-owner
rejection, duplicate detection and preservation of managed tenant handlers during
console binding. UI creation fields and suspension revision now match that API;
authenticated tenant form interaction is still unqualified.

QEMU apiserver, cyberpanel and paneld suites pass; UI typecheck/build pass.
Signed sequence40 committed registry/core/UI changes (manifest
9911c41bbefebb3e02ef6976a53de34b1996f6ee66c570c9b7a331180546a54f,
receipt8327bbc6ad67174b53e18246bf8f7035d1190748118f4efaafd270a390e40ceb).
Gateway also embeds the registry and required its own rebuild. Signed sequence41
qemu-gateway-registry-3.1.40 committed with bundle
f34c268938ab5d11d19bf81a0552cbba50910c4bd3d74757ae3158cf6c5fec03,
manifest2de4d84479ccafea7b7b1236ff8b9d13c091a3225c368a31df0155adb4f5d74e,
receipt585d6e1cb2e2404b7f0cd748e655217879b5514b76c9857129ee56e4dd9619a9.
QEMU-only trust maximum extended40→41, preserving key/minimum/expiry. Usual
documented mail restore/WAF-owner/reconciliation prerequisites still required.

Core remains active. Actual health over its Unix socket as the gateway UID with
service group returns ready and658 operations; root and a user without the service
group were denied. Gateway then rejected systemd's0440 credential, whose apparent
group bit represents its named-user ACL rather than owning-group permission.
Reused the existing credential validator ONLY for the fixed gateway signer path:
root owner/group, one link, read-only tmpfs, exact caller-only ACL and private
parent ACL. Ordinary group-readable files still fail. No secret bytes printed.
Actual gateway systemd sandbox loaded the signer successfully with the test
binary; temporary test override/binary removed afterward. A separately built
candidate gateway is running via99-qemu-candidate-test.conf with Restart=no,
using the existing sandbox and LoadCredential. This fix awaits signed packaging.

Live candidate gateway /health/ready returns200/ready; /api/v1/catalog returns658
operations. QEMU Playwright drives the installed UI at1366x900 and390x844: login
inputs render, no page errors/horizontal overflow. Submitting a nonexistent user
through the actual form returns401 and displays an error. Screenshots:
/home/harness/installed-ui-41-desktop.png and installed-ui-41-mobile.png.
This proves entry/negative-login, NOT successful authentication or tenant CRUD.

Disk guard stopped a build below2GiB as intended. Removed redundant sequence38,
39 and40 tar bundles plus about600MiB obsolete candidate binaries and temporary
test executables, retaining installed current/rollback releases and journals.
Guest now approximately2.1GiB free. No additional full bundle until safe storage
reclamation. No downloads or native dependency compilation.

### Installed site-preview helpers — 2026-09-20

Reproduced startup failure: route/chromium helper executables absent, while the
route directory had correct service ownership and0700. Package definition also
specified /usr/libexec paths outside the signed installer's allowed destination
boundary. Aligned both helpers to /usr/local/libexec/cyberpanel and added a
package-definition regression covering all executor-bundle member destinations.

Preview validation now resolves only its two fixed installer-managed executable
paths, then checks regular file/root owner/executable bits/non-writability/no
hardlinks/no set-ID. Invocation uses the resolved generation, not the public
activation link. Chromium's self-reexec check matches that resolved path.
Existing release-root/ancestor/link checks remain in force.

QEMU noderelease/sitepreview/cyberpanel suites pass, and all three changed
binaries build offline. Installed signed sequence39 qemu-preview-3.1.38:
bundle `659881ccf665fa8731e79d040a298a53c43aba2e59af5cd6b333fccd06e28eba`,
manifest `04e6744344a9507bbd3f389bb777a4ddd60f8435fd32a70cf9760ccbe822ed55`,
receipt `069b70da1a09c06883a206b1fdefd6e6da21fd84d7ba083966a3c3491f021cd8`.
Same documented mail restore/WAF ownership/reconciliation prerequisites applied.
The installed-helper QEMU test passes as cyberpanel (both managed symlinks and
both constructors). Initial test execution from /home/harness was denied by
directory traversal permissions; rerun from a temporary public executable path
passed and that temporary file was removed. No screenshot execution claim.

Core now passes site-preview assembly and fails at registry construction with
`duplicate operation identity.tenant.list`. Identity and console contracts both
declare list/create/suspend with differing payload types; requires consolidation,
not disabling the duplicate check. OLS is active; core remains failed without a
restart loop. Removed redundant485MiB sequence37 bundle; installed rollback
release remains. Guest free space approximately3.2GiB. No downloads/native builds.

### Installed persistent web health proof — 2026-09-20

Implemented a root-owned, atomically written activation proof for each web
snapshot. Confirmed proofs cannot be replaced by a different candidate at the
same snapshot; earlier proofs survive rollback. Both edition renderers reference
the snapshot-specific path. Installer provisions the tree and an additive
read-only service mount; executor uses the production proof writer.

QEMU tests cover snapshot advancement, rollback retention, conflicting reuse,
unsafe modes and symlinks. Actual vendor HTTP serves the persistent proof, and
the production loopback health client passes. The full WAF fixture remains red
only on three vendor oversized-body cases (19/22 cases pass); no vendor patch.

Installed signed sequence38 `qemu-web-health-3.1.37`, manifest
`62c1c02d06a9bb6337eddd7c8421e3f544f0b46131f981fa8ba1bf93dbe6bf61`, receipt
`4ba75587a8da89857aefca88906c594e7956b70d9322a12f16fd5614329fe8a4`.
The existing QEMU mail-config restore prerequisite was followed by the installed
reconcile-services hook. Vendor package installation had changed the existing
WAF policy owner to lsadm; SHA256 remained
`48bced536ba267183280d79d0afe70b0cc236fd1cf9c82fec15d8ee42106a186`.
Restored root ownership of that exact policy, then reconciliation passed.
This manual step means unattended upgrade replay remains unqualified.

Released the QEMU-only OLS startup hold. Core activated OLS and passed its health
check. Independent HTTP GET to `/.well-known/panel-health/activation` with Host
`default.invalid` returns `panel-health-v1
98515aa557ad729626e3ec2119b46d0b6e1b6f401cf7184866afc7b5267865b4` (one line).
The persistent proof is root-owned0444. OLS, Postfix, Dovecot and Rspamd are active.
Core now exits at `connect exact site-preview route helper: site preview
destination denied`; no UI/API completion claim. Journals preserved. Guest has
4.4GiB free; no images, native source builds or downloads were started.

### Health/ACME contexts and immutable vhost revisions — 2026-09-20

Live vendor QEMU requests reproduced403 for existing health and ACME challenge
files: our static contexts emitted allowBrowse0, which denies file serving, not
merely directory listings. OLS/LSE renderers now use allowBrowse1 with explicit
autoIndex0. Native OLS serves exact proof bytes with200; directory requests
return404 without listings. The fixture binds temporary read-only files into
the private service namespace, leaving live health/challenge trees untouched.
This verifies routing, NOT production attestation provisioning or ACME issuance.

Staging the changed vhost exposed a real same-snapshot renderer-update collision.
New vhost paths include SHA256 of vhost content. Both renderers and fsstore use
that path; earlier manifest layouts remain readable so recovery does not erase
sealed checkpoints. Regression stages two distinct vhosts at snapshot1, verifies
the old sealed generation remains valid, rejects switching while its master is
live, and restores the original vendor master after the updated candidate.

QEMU native/OLS/LSE renderer, fsstore and webactivation suites pass. Vendor OLS
parser accepts digest
`e8650d08836fb242ff7a3a1959ec69e83d91171077f3b3e68560cedb962b8576`.
Live fixture21 cases:18 pass; only the same three oversized-body cases remain
red. Logs `vendor-context-red.log` and `vendor-context-fixed.log` are under
`/home/harness/waf-prerequisites-20260920` in QEMU. No native binary changes,
downloads or release bundles. Production health writer, safe generation-scoped
attestation, updated signed deploy and complete activation remain outstanding.
Enterprise native parsing/HTTP remain unqualified.

### Installed rules evidence and bootstrap checkpoint recovery — 2026-09-20

Removed the compiled-in CRS manifest digest and fixed release label from WAF
activation. The root-owned installed manifest now supplies recorded evidence;
recursive content, owner/mode, hardlink/symlink, extra-file and manifest-change
checks remain enforced. Empty manifests are rejected. QEMU tests prove two
installed rule revisions work without rebuilding the panel, while unmanifested
tampering still fails. This does not yet replace the custom CRS package/layout;
that integration remains outstanding. Removed the obsolete opt-in custom parser
test: asset verification remains, and vendor native parsing is exercised by the
existing webactivation QEMU test.

Bootstrap storage now permits an updated initial candidate only with no current
managed receipt, verified previous sealed candidate/backup and live bytes equal
to the restored vendor master. The activator's existing stopped-engine guard
still precedes this. It preserves the original backup, atomically advances the
candidate marker, and rejects unrestored/stale candidates. QEMU tests cover both
edition formats; activation, fsstore, webactivation, operations and CLI suites
pass.

Actual guest checkpoint recovery also PASSES: ran `TestQEMUInitialWebParser`
with `CYBERPANEL_QEMU_WEB_CANDIDATE=f80079fd4f9e32d8123ed69d51f68391690e4a4c3e63edd54e983e6adf77ce11`.
It proved the engine stopped, advanced the old checkpoint, installed the sealed
master for vendor parser validation, and restored the original master. No
journals were deleted or reset. This is parser/bootstrap preparation evidence,
not confirmed web activation: health attestation and signed updated deployment
remain pending. OLS remains inactive and signed panel release remains37.

### Vendor dependency restoration and reference configuration — 2026-09-20

User corrected the dependency ownership boundary: no local native server/module
forks, patches, compilation or product hard-pins. Removed the custom ModSecurity
compiler recipe and connector patch. Restored the retained vendor
`ols-modsecurity` **1.9.2-1+noble** package, SHA256
`7b99e9ff8806a104021cec860c900cf470ccd8e23696ed6f3d2a6b7f6786ad1f`;
`dpkg -V ols-modsecurity` reports no differences. OLS remains the unchanged
vendor1.9.2-1+noble. These versions identify the test environment, not product
version locks. No OLS/LSQUIC compilation or new dependency installation occurred.

Compared our renderer with `install/litespeed/conf/httpd_config.conf` and
`install/litespeed/httpd_config.xml`: the reference explicitly sets native
required/restricted file permission masks to000; our omission inherited vendor
defaults. Both renderers now emit the reference masks. Unix ownership/mode
enforcement, worker identity, vhost restrictions and symlink policy are unchanged.
This fixes panel-generated configuration instead of modifying the native server.

QEMU OLS/enterprise renderer and webactivation package suites pass. Actual vendor
OLS parser accepts generated digest
`f80079fd4f9e32d8123ed69d51f68391690e4a4c3e63edd54e983e6adf77ce11`.
Live vendor HTTP run now passes all benign and attack fixtures apart from the
three oversized-body expectations: **14/17 pass**, size cases return200 rather
than413. No native patch will be introduced to force those green. Preserve the
failure evidence and assess the panel's advertised capability against reference
behavior. Log: `/home/harness/waf-prerequisites-20260920/vendor-file-access.log`.
The pre-change vendor run (`vendor-integration.log`) still had benign XML403;
post-change all benign cases pass. Enterprise native execution remains untested.

Removed obsolete custom module packages .1/.2, standalone custom parser utility,
OLS source archive and guest copies of the deleted build recipe/patch. These are
rebuildable/downloadable artifacts; source deletion remains recoverable in Git.
Retained vendor package, small evidence logs and active CRS assets. Custom CRS
packaging and hardcoded manifest/version integration remain to be replaced with
normal managed rules installation; asset safety must be preserved. OLS remains
inactive after fixtures. Signed panel release37 is unchanged; no full bootstrap
or installed API/UI completion claim.

### Known-length body rejection and chunked diagnosis — 2026-09-20

Pinned OLS connector previously disabled request-body inspection when declared
Content-Length exceeded the configured limit. The package source patch now
returns413 for positive oversized lengths with engine On and limit action
Reject, preserving inspection for other modes/unknown lengths. Offline QEMU
build installed `ols-modsecurity` **1.9.2-1+noble+cpmodsec3.0.16.2**, SHA256
`ddd1822f899db80d7676397a7f51269af16442cd0e9872b23d70844ebd990c45`.
The source patch is included in the package's documentation.

Final QEMU invocation: `go test -p 2 -count=1 -run
TestQEMURenderedInitialWebParser -v ./internal/executor/webactivation`, with
`CYBERPANEL_QEMU_RENDER_WEB=1`, `CYBERPANEL_QEMU_WAF_HTTP=1`, offline Go settings
and root execution in the existing Ubuntu ARM64 guest. Native parser passes;
HTTP suite deliberately remains RED. Log:
`/home/harness/waf-prerequisites-20260920/http-body-limit-final.log`.
17 HTTP subcases: 12 pass, 5 fail. Known-length oversized413, small chunked XSS,
64 KiB late-body chunked XSS and cache-expired benign query pass. Repeated plain
GET, benign query and benign XML return403 in this run; benign JSON passed,
confirming the static-cache failure is intermittent. Single large chunk times
out after5s; bounded chunks return200 instead of413.

Temporary module builds .3/.4 tested an explicit decoded-buffer size guard.
The guard did not fix the response and is not retained in source. Narrow trace
showed decoded body13107214, limit13107200, engine1 (On), action1 (Reject).
This rules out missing/truncated buffer and incorrect effective limit for the
bounded-chunk case. Pinned native `HttpSession::reqBodyDone` calls
`handlerProcess` before the completed-body hook when waiting for the full body
after URI mapping; this is the next server-side ordering investigation, not a
verified server fix. Large-chunk read scheduling also remains unresolved.
All temporary diagnostic policy/master changes and log instrumentation were
removed. Installed module restored to .2. Build workspaces clean automatically;
diagnostic .3/.4 packages removed, retaining .1 rollback and .2 candidate.
Final cleanup confirmed OLS inactive and guest6.1GiB free. No generated runtime
artifacts are committed. Signed panel release remains37; no full activation or
API/UI qualification claim.

### Initial WAF policy and live native fixtures — 2026-09-20

Root installer now creates a blocking initial policy only after checking the
entire pinned CRS runtime manifest, every referenced file's bytes/ownership and
permissions, and absence of additional wildcard-loaded files. Existing managed
policies are preserved. Added private worker temp/data directories, JSON and
XML body processors, malformed-body/argument/multipart guards, response-body
inspection and metadata-only audit output. The same parser settings apply to
later WAF generations; omitted CRS selects the baseline. Initial executor
handoff accepts only the exact root:root 0600 baseline with an empty journal,
retaining its snapshot for rollback; foreign/ambiguous state remains rejected.

QEMU found and fixed two native prerequisite defects:

- CRS manifest had inherited group-write permission. Package recipe now fixes
  umask/mode. Installed `cyberpanel-waf-crs` **4.29.0-2**, SHA256
  `3f69c012ae977bbfe3cd6a40dff05deb92eddfce5831539dbfbd05e403e058e7`.
- Live OLS startup mixed the server-exported old C++ random-device initializer
  with the module's system C++ getter and aborted. The module now statically
  links its private C++ runtime and exports only its LSI entrypoint. Native
  startup no longer aborts. Installed `ols-modsecurity`
  **1.9.2-1+noble+cpmodsec3.0.16.1**, SHA256
  `308702d46926988633c36f160d960ed6edb874acc24a3319cbecde41b0152c58`.

Static OLS maintenance/suspended vhosts now explicitly select the unprivileged
worker without changing root-owned content. This removes native parser UID/GID
warnings. The actual pending bootstrap generation now **passes OLS -t**:
`0416df09c69c729f8246aa9abd0c82ba83e8b9eeae413c4421e2f9ac80789145`.
Its initial WAF policy loads 847 rules (840 CRS plus seven parser guards).
QEMU operations, webactivation, OLS renderer, installer/CLI and architecture
suites pass, including recursive-tamper, extra-file, symlink/hardlink, ownership,
first-handoff and installer replay checks.

New opt-in native HTTP fixtures start the real installed OLS against that exact
rendered master in a bounded private network, /tmp and /run namespace. Live
master/journals/receipts are untouched. Passing: initial plain/direct-file GET,
query XSS and SQLi blocking, JSON and +json XSS blocking, malformed JSON 400,
and XML-attribute XSS blocking. **Still RED:** repeated plain GET is intermittent
and benign query/JSON/XML get 403;
diagnostic OLS logs identify static-file required/restricted permission checks,
not a CRS intervention. Oversized-body fixture also gets 403 instead of 413;
the connector's request-body-size bypass needs qualification/fixing. Do not
relax file-permission checks or weaken WAF to turn these green. Temporary verbose
diagnostic policy/master overrides were removed from test source.

Test cleanup checks both sealed generation integrity and stopped native process
identity even on failure. OLS remains held inactive afterward. Current fixture
log: `/home/harness/waf-prerequisites-20260920/http-final.log` in the guest.
No full activation, live panel/API/UI, signed-release inclusion or LSE/matrix
qualification is claimed. Next: fix native benign-static/body-limit failures,
then health attestation and safe old-bootstrap-marker transition. Installed panel
release remains 37; old bootstrap marker still binds 8ad3d376..., not the new
rendered digest. No journals were reset.
Final fixture cleanup took 2.43 seconds and confirmed no server remained;
superseded package files and all temporary native build trees were removed.
Guest free space 6.1 GiB after filesystem trim. Initial live baseline file SHA256
is `48bced536ba267183280d79d0afe70b0cc236fd1cf9c82fec15d8ee42106a186`.

### Native WAF dependency repair — 2026-09-20

Added offline QEMU-only native package recipes under `packaging/native/`.
They accept pinned source archives, refuse existing output packages, and remove
temporary extracted sources/objects on exit. Module build retains diagnostic
logs only; CRS package embeds recursive runtime SHA256 evidence and verified
upstream signature status. No generated packages or test artifacts enter Git.

Ubuntu ARM64 QEMU built and installed (native prerequisites, not a signed panel
release):

- `ols-modsecurity` `1.9.2-1+noble+cpmodsec3.0.16`, package SHA256
  `0fcf2dc59e83de826f40ba566d8379a8a420abbf2e1990f1e0c8b6ba889fa9e1`.
  OLS connector from upstream v1.9.2 commit
  `bcd05f4048226cbd0adc75ce6b825527ffe4b6e5`; ModSecurity 3.0.16 source SHA256
  `739be3c71b1939f14e91afe1eeae654acbd440da11bd29790458840bc315b4c0`.
  The old vendor C++11 recipe fails against 3.0.16 headers; C++17 with the same
  old libstdc++ ABI builds successfully. XML, JSON/YAJL and PCRE2 enabled;
  remote rule loading, Lua, GeoIP, ssdeep and LMDB not compiled in.
- `cyberpanel-waf-crs` `4.29.0-1`, package SHA256
  `9c4132cc1ba5ddcc53bc68d49da0d51310fc05059bb9ebff9c1a5bc091bc9748`.
  Full upstream minimal-runtime archive SHA256
  `1aa1c5c8fc29e532d35293bcea36bf72de61db8f6ed4716a0f91ab14552b7fed`;
  detached signature verified against pinned fingerprint
  `36006F0E0BA167832158821138EEACA1AB8A6E72` in an isolated keyring.
  All rule/data files retained, not an empty or reduced ruleset.

Actual native `modsec-rules-check` 3.0.16 loads **840 rules** from installed
`/usr/share/modsecurity-crs/owasp-crs.load` successfully. Installed recursive
runtime manifest verification and `dpkg --audit` pass. Native OLS parser loads
the rebuilt module, then remains RED for the genuinely absent managed WAF policy
`/usr/local/lsws/conf/modsec/cyberpanel.conf`. No live WAF/HTTP protection claim:
body-processing policy provisioning, positive/negative request fixtures, signed
release/catalog inclusion, and remaining platform matrix still required.
OLS stays held inactive; no bootstrap journal or live master was reset.

Upstream security rationale: [ModSecurity 3.0.16](https://github.com/owasp-modsecurity/ModSecurity/releases/tag/v3.0.16)
fixes request-parser issues present in the vendor module's embedded 3.0.15;
[CRS July security release](https://coreruleset.org/20260702/crs-versions-4.28.0-4.25.1-lts-and-3.3.10-released/)
supersedes Ubuntu's older CRS. Downloads were native prerequisites only, no OS
or Go images. Guest inputs/packages/logs live in
`/home/harness/waf-prerequisites-20260920`; parser utility retained at
`/home/harness/bin/modsec-rules-check-3.0.16`.
Both final recipes completed from fresh temporary directories in QEMU; those
directories were absent afterward. Removed the initial 176 MiB debugging
workspaces and duplicate package outputs, keeping the archives, final packages
and logs. Guest free space 6.4 GiB. CRS rebuild is byte-identical; module builds
are not claimed bit-reproducible (the final recipe's package hash is above).

### Native worker identity and config authority candidate — 2026-09-20

Both edition renderers now emit dedicated `cyberpanel-web` user/group,
disabled vendor WebAdmin, required MIME source and bounded error/access logs.
The installer hook provisions the non-root/nologin service identity and fixed
root-owned default/maintenance/suspended content and health directories.
`lshttpd.service` receives read-only config and /etc mounts, no CAP_SYS_ADMIN,
and control-group shutdown. Root installer reconciliation passed twice in QEMU;
the unprivileged worker can read its static page but cannot write the master.

Initial validation now runs the fixed native parser in a bounded transient
systemd service with private /tmp and read-only config. Stopped-service checking
additionally observes kernel executable identities, including processes outside
the unit. Since the main executor deliberately lacks ptrace capability, the
fixed read-only observer receives only CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH for
at most ten seconds; main broker privileges are unchanged. QEMU tested the
observer path, running executable rejection, cancellation, and the built
executor's `--webengine-stopped-proof` dispatch.

`TestQEMURenderedInitialWebParser` reads the real pending bootstrap plan
read-only, composes/renders it, stages sealed artifacts and bind-mounts its
master only into the parser namespace. It re-verifies sealed bytes/metadata
after parsing. Native progression: missing user/group resolved; missing MIME
and access logging resolved; missing system vhost root resolved. OLS attempted
its recursive permission repair, but read-only mounts denied it and generation
verification still passed. No live master/checkpoint was replaced by this test.

Downloaded and installed only the matching native ARM64 `ols-modsecurity`
1.9.2-1+noble prerequisite (2,550,958 bytes, no maintainer scripts), verified
against apt metadata SHA256
`7b99e9ff8806a104021cec860c900cf470ccd8e23696ed6f3d2a6b7f6786ad1f`.
Retained under guest source `web-packages/ols-modsecurity_1.9.2-1+noble_arm64.deb`;
must include it in the next signed bundle/catalog. No OS/Go image downloads.
Native parser now fails loading absent `/usr/local/lsws/conf/modsec/cyberpanel.conf`.
Do not disable WAF or substitute an empty policy to make the parser pass.

Affected QEMU suites passed: both renderers, webactivation, install, cyberpanel
and panel-execd, with native authority check enabled. Both candidate binaries
rebuilt into the existing guest `*-web-bootstrap` paths. Installed release is
still 37; these source changes are not signed/deployed. Native parser remains
RED and no core/OLS health is claimed. Next: provision genuine initial WAF
policy, health attestation material, and safely reconcile the older failed
bootstrap marker when renderer digest changes (do not delete/reset it).
Old marker binds 8ad3d376..., newest rendered candidate 0b9c811b.... OLS hold
remains in place. Guest free 6.8 GiB, host 244 GiB, Git pack 485.74 MiB.

### Sequence 37 and first-activation recovery — 2026-09-20

Installed signed `qemu-web-bootstrap-3.1.36` (sequence 37), manifest
`807b186ab045a2f03d7d1742bbd63eabd6de496f52a034ff35c146ad3b61f637`,
receipt `7641be5a5a2b34c2b94cc02428b3b1d48e23e468995a9ac09f7b993d7a82d587`.
Hook applied; dpkg audit clean. Includes mail recovery, initial web activation
and exact first-request retry. Reboot admission archives the previous ambiguous
attempt; binding, epoch, drain gate and lease fences remain enforced. Ordinary
configuration mutations and successful receipts cannot use this retry path.
Active SQL leases and running unconfirmed candidates still fail closed; this is
not complete arbitrary crash recovery.

Native core startup recovered all five mail services, then failed staging under
the vendor-owned 0755 `conf/vhosts` parent. The installed-authority regression
failed on that exact path. The fix transfers only that parent using a no-follow
directory FD; native regression passed and applied the repair in QEMU. This
installer fix is not yet signed/deployed. Retrying the same installed-core
request then staged the candidate and created the durable vendor backup, without
deleting journals or inventing a fresh operation ID. Native validation still
failed, the original master was restored, and no current receipt was confirmed.

Added explicit native `TestQEMUInitialWebParser`, gated by the sealed candidate
digest in `CYBERPANEL_QEMU_WEB_CANDIDATE`. It verifies/switches a snapshot-one
candidate, runs real `lshttpd -t`, and restores the vendor master. Candidate
`8ad3d376ea58e4300415c4ef80bbe4d4365f48950ec85a829ec8a089a5ff6e2b`
currently fails with exit 1 and no stdout/stderr. The parser's own log at
`/tmp/lshttpd/testconf` identifies the exact failure:
`Invalid User Name((null)) or Group Name((null))!` Both renderers omit the server
worker identity. Next fix must provision/render an appropriate unprivileged
identity, not run workers as root. System-default content/health directories
are also absent and remain a later startup prerequisite, not yet qualified.

Diagnostic incident: `lshttpd -h` unexpectedly started the vendor server (not a
help switch). Stopped with `lswsctrl stop`; checked no OLS processes/listeners
remained. Startup recursively changed config metadata to lsadm:0750/0640.
Restored the three known generated subtrees and fixed parents to their original
root-private metadata, preserving content. The native parser test subsequently
verified the sealed candidate and restored its master. Upstream confirms an
unconditional startup `fixConfDirsPermission()` call:
https://github.com/litespeedtech/openlitespeed/blob/master/src/main/httpserver.cpp
Managed startup must prevent that rewrite, not weaken private-store checks.
Stopped-process proof also needs to cover processes outside the systemd unit.

QEMU suites pass: webactivation, rebootcontrol, activation/fsstore, cyberpanel
and panel-execd. Explicit native parser gate remains RED. Core/OLS remain
unqualified; QEMU service hold restored, executor and mail active. Guest free
7.0 GiB; host free 244 GiB; Git pack 485.74 MiB. No image downloads, binaries or
bundles added to Git. Retained sequence-37 bundle is guest-only (~485 MiB).

### First web activation implementation candidate — 2026-09-20

Reproduced the first-activation gap in QEMU: the activator rejected snapshot one
because there was no previous current receipt. Implemented a separate initial
path under the existing activation locks, restricted to snapshot one and stores
with no current-state file. It requires a stopped native service, durably saves
the vendor master, swaps the independently rendered candidate, runs the native
parser, starts the fixed service and obtains the existing digest-attesting HTTP
proof before confirming. Failure stops the service before restoring the saved
master; it never labels an unverified vendor baseline a healthy rollback.

The file-store checkpoint verifies the immutable candidate and backup digest,
survives reopening, refuses unrelated live-master changes, and cannot reset an
already-adopted node. The control runtime now prepares the first complete node
configuration in the existing SQL journal and finalizes it only after the
privileged activation receipt confirms the exact rendered digest.

QEMU tests went from failing the missing-current path to passing initial
activation and failed-probe restoration. Additional checks pass for parser
rejection without service start, failed stop without overwriting a live master,
later-snapshot rejection, both-edition file-store reopen/restore, and backup/live
tamper rejection. These are workflow tests and real file-store checks, NOT yet
native OLS/LSE startup qualification. Activation/fsstore, lswsruntime, management,
cyberpanel and panel-execd suites pass; the activation broker package compiles
but has no existing package tests. Both candidate binaries were built in QEMU:
`/home/harness/bin/cyberpanel-web-bootstrap` and
`/home/harness/bin/panel-execd-web-bootstrap` (also include the mail recovery fix).

Installed release remains 36. Candidate changes have not been signed/deployed;
native initial startup, SQL finalization and the broker's ambiguous-receipt retry
behavior still need qualification. The QEMU OLS service hold remains in place.
Do not claim the web engine/core is running. Host free space ~246 GiB and Git
packs ~486 MiB remain stable after checkpoint exclusion.

### Sequence 36 installed; native catalog and mail recovery — 2026-09-20

After disk cleanup, QMP reported `io-error` / `nospace`: QEMU had automatically
stopped on the earlier exhausted host disk. Resumed that same VM via QMP (no
image replacement), checked the candidate hash and installed sequence 36.
`qemu-web-catalog-3.1.35` committed with manifest
`818f8aca469212f151a25298fac852e2d2bafbaef2bc6886c8a65d780cda9edc` and receipt
`0aca1e201bd7808c06fb9a179b82f2e30dd64f6fb608b9cf8b6fd19783c68573`.
Installer reconciliation returned applied; dpkg audit was clean. The explicit
installed-engine-catalog test passed against managed catalog/key/repository
links, the real signature, pinned package bytes/native metadata and installed
OLS version. This closes catalog admission, not native web activation.

Core startup then reproduced a same-generation mail recovery bug: retained mail
configuration was valid but package-install service stops left mail inactive;
the unchanged-generation branch only probed and returned an ambiguous outcome.
Added recovery that validates the retained generation before reload/restart and
then probes all services. Healthy replay remains probe-only. The gated native
QEMU test failed before the fix, then passed after it, including refusal to start
an invalid generation, actual SMTP/TLS/STARTTLS recovery, and no restart evidence
on healthy replay. The complete mail, management, cyberpanel and panel-execd
suites passed with installed-SMTP/catalog checks enabled. Recovery source is
NOT yet in a signed release; the native test restored current service health.

The resumed VM clock lagged host UTC by about 63 minutes despite reporting NTP
synchronized; synchronized guest UTC to the host before subsequent checks.
The subsequent installed-core start gets past mail and fails web inspection.
OLS remains held inactive and `/usr/local/lsws/conf/.panel-state/current` is
absent. Next: deploy the recovery fix and implement initial verified web
activation/catalog finalization. Core/API/UI and complete mailbox delivery
remain unqualified. Guest free space is 8.7 GiB; shared Git packs remain ~486 MiB.

### Disk exhaustion root cause corrected — 2026-09-20

The earlier attribution to insufficient user-provided space was wrong. The
repository's shared `.git` had grown to roughly 241 GiB: 128.86 GiB of abandoned
temporary Git files and 110.58 GiB of packs, largely repeated QEMU overlay blobs.
The main checkout lacked runtime ignores even though the development worktree
had them. A Codex turn-diff checkpoint tree included `.work/.../overlay.qcow2`.

Removed 52 confirmed unused Git temporary files. Used `git rm --cached` against
an isolated index of that checkpoint to remove its 117 `.work` runtime entries,
then atomically updated only the checkpoint tree ref. Source branches, reflogs,
the real indexes, working-tree changes and the checkpoint's non-runtime source
entries were preserved. With no Git writers active, garbage collection removed
the now-unreachable old snapshots. Connectivity checks passed before and after;
`.git` is now 506 MiB and host free space is approximately 247 GiB.

Also removed 15 obsolete host-side release bundle archives (3.1.15 through
3.1.29). These obsolete archive files are deleted, not in Trash; current QEMU
state, supplied base images, native package sources, the verified retained
33–35 archive and candidate 36 remain available. No source history was rewritten.

Prevention is structural: shared `.git/info/exclude` covers every worktree,
both main/development ignores exclude `.work`, `.worktrees` and VM image formats,
and the common pre-commit hook rejects runtime paths/images and staged files over
20 MiB even after force-adding. Isolated-index Git-hook checks rejected a runtime
image path and accepted a test-source path. Test source is NOT excluded. The QEMU
build/install preflight now requires 10 GiB host headroom and stops if shared Git
objects exceed 5 GiB. The disk blocker is resolved; release 36 is still uninstalled.

### Signed web catalog candidate; host-space install guard — 2026-09-20

Source `5b432d144` accepts only installer-managed immutable-release links for
engine/PHP catalogs, public trust keys and repository metadata. It uses the
existing release resolver, opens the pinned file no-follow/nonblocking, then
checks ownership, mode, size and read length. Arbitrary links and writable or
oversized catalogs remain rejected; catalog signature verification is unchanged.
QEMU passed the complete management, node-release, cyberpanel and panel-execd
package suites, and built both updated binaries. A gated installed-catalog test
now verifies signed resolution, pinned package hash/native metadata and matching
installed OLS version; it has NOT yet run against the candidate installation.

Assembled sequence 36 `qemu-web-catalog-3.1.35` (103 artifacts, 507857532 bytes)
with the existing native OLS package, signed engine catalog, public key and
repository metadata. Bundle SHA256:
`0e4f0d231672f67349b6fd551f8ca1de78ab211428357ae9d8fd63c10b089888`;
manifest `818f8aca469212f151a25298fac852e2d2bafbaef2bc6886c8a65d780cda9edc`.
Guest bundle: `/var/tmp/panel-web-catalog-3.1.35.tar`.
Spec: `/home/harness/cyberpanel-web-catalog-spec.json`.
The native package cache was explicitly provisioned in QEMU from the retained
package; automatic production package-cache provisioning remains to be wired.

The host-space guard rejected installation BEFORE any service stop, mail-config
restore or installer execution. Installed release remains sequence 35. Initial
web activation/core/API/UI qualification is still incomplete. Host free space
ended near 1.7 GiB, below the existing 3 GiB build/install minimum; guest free
space is 9.7 GiB. Do not bypass the guard or mistake a built candidate for an
installed/qualified release. More host space is needed before deployment.

Removed only verified duplicate staging sequences 4, 6, 7, 9–20, 33 and 34;
every payload was hashed against its manifest and retained installed tree first.
All installed releases/journals remain. Compacted guest bundles 33–35 losslessly
into `/var/tmp/retained-mail-33-35.tar.zst` (440 MiB); extracted SHA256 values
match the previously recorded originals for all three before originals were
removed. Recover using `zstd -dc --long=30` and tar extraction. Candidate 36
remains uncompressed. No OS-image or Go download occurred.

### Native web package version validation — 2026-09-20

QEMU reproduced rejection of the installed OLS version `1.9.2-1+noble`
at `validateArtifactPlan`; epoch and prerelease variants also failed. The
version-only grammar now permits native `+`, `:` and `~` syntax while retaining
the 128-byte bound and rejecting paths, traversal, whitespace, shell delimiters,
NUL and non-ASCII input. Identifier/key/repository token rules and all catalog
signature checks are unchanged. The regression changed from FAIL to PASS in
Ubuntu ARM64 QEMU; the entire management package suite also passed. This is a
source-level prerequisite fix, not an installed web-engine readiness claim.
The signed engine catalog and initial verified configuration activation remain
pending; the installed release is still sequence 35.

Removed only duplicate committed staging sequences 21–24 after checking every
artifact against its manifest and retained installed release under the installer
lock. Installed release trees, journals and archives remain intact. Guest free
space after cleanup was 5.5 GiB; discard reclaimed host blocks. No OS/Go download.

### Signed SMTP protocol qualification and installer-owned bindings — 2026-09-20

Signed sequence 35 (`qemu-mail-smtp-3.1.34`, source `6ba18450a`) committed;
installed reconciliation returned applied and dpkg audit is clean. Bundle SHA256
`cee471150568d519161bd978a56b57cb5dcc538e40bc947a5484b5732c547ead`;
manifest `25a606a2dae61db42f9c37829168ed74c3df6dd10bedc5b4772a7b78957ff03d`;
receipt `74d170a69a527b4a3125c0a87567a8bcb3aa396002647c0f5b2873a77cb21522`.

Installed startup initially failed creating the new Rspamd link. A targeted
syscall trace reproduced `symlinkat(...worker-proxy.inc) = EROFS`; inspecting
the actual executor mount namespace confirmed `/etc` is read-only despite its
broad ReadWritePaths entry. Kept that sandbox intact. Added installer-owned
reconciliation of all fixed native mail bindings and invoked it from the mail
runtime installer setup. The native binding test created the missing fixed link;
the installer setup/replay test then passed twice. Those latest installer-source
changes still await the next signed release; the QEMU binding was established
by the explicit native installer test, not the sequence-35 hook alone.

After that repair, all six installed mail services start and both installed
milter ExecStartPost helpers exit 0. `TestQEMUInstalledSMTP` (no temporary config
or daemon replacement) passes against installed SMTPS 465 and STARTTLS 25/587,
including plaintext AUTH denial and post-TLS AUTH advertisement. Full mail and
installer package suites pass with installed-SMTP/binding checks enabled.
This is protocol startup qualification, NOT successful mailbox authentication,
DKIM/antivirus delivery or end-to-end message delivery.

Core advances past mail and fails web-engine management inspection; the signed
engine catalog and initial activated native web configuration remain missing.
The runtime-only `/run/systemd/system/panel-core.service.d/90-qemu-once.conf`
sets Restart=no during qualification, preventing failure loops. Core is failed/
stopped; do not mistake native mail health for core/API/UI readiness.

The storage guard's first remote preflight consumed a piped source archive.
Corrected it to `ssh -n`, then repeated source transfer with `set -e` and reran
the affected tests. The run that printed a tar error is not source verification.

### Native SMTP and installed-edition regressions — 2026-09-20

The rendered Postfix master.cf omitted internal services, reproducing a native
SMTP TLS timeout in 7.37 seconds. Added the standard internal queue, map, TLS,
rewrite, delivery, logging and connection-management services; immutable panel
paths remain outside chroot. The same native daemon test then completed TLS,
EHLO and QUIT. Extending it to STARTTLS reproduced a 454 response caused by
OpenDKIM socket permission denial and a missing Rspamd milter socket.

Added a managed Rspamd Unix milter override and a fixed root-only executor mode
that grants Postfix named-UID traversal/socket access for exactly OpenDKIM and
Rspamd. It does not add Postfix to signing/config groups or follow final socket
symlinks. Native TLS on 465 and STARTTLS on 25/587 now pass; plaintext AUTH is
absent and AUTH appears after encryption. Installer startup hooks reapply grants
after daemon socket recreation; configuration reload uses restart for these
milters and ClamAV (whose vendor USR2 reload only refreshes signatures).
These candidate changes are not yet in a signed installed release.

The web-engine edition regression reproduced `not found` against the actual
signed installer's engine.edition symlink. Reused the strict node-release config
resolver, pinned the generation, opened no-follow and retained ownership/mode/
size checks. The actual signed-edition test passes. Remaining web startup work:
the QEMU release lacks `/etc/cyberpanel/webengine/catalog.json` and an activated
managed native web configuration; OpenLiteSpeed remains intentionally held.
Do not claim the complete web-engine inspection/startup now passes.

An initial combined package run was interrupted after disk pressure made the VM
unresponsive; only its reported mail package pass counts. Terminated the exact
QEMU process, resumed the same intact overlay, and added a private local QMP
socket. QMP confirmed running, disk I/O status OK, and guest SSH recovered.
Removed the failed partial archive copy, rebuildable Go cache and the identified
21 MiB interrupted Go temporary directory, then trimmed freed guest blocks.
No installed release, journal, source tree, OS image or signing key was removed.

Verified committed staging sequences 25–28 artifact-by-artifact against both
their signed manifest hashes and retained installed releases, then removed only
those four duplicate staging directories under the installer lock. Synced and
trimmed; host free space rose to about 3.5 GiB, guest free to 3.6 GiB. Installed
releases and rollback payloads remain. The harness SSH entry now refuses Go
build/tests and signed assembly/install below 3 GiB host or 2 GiB guest free;
its low-space denial was exercised (exit 75). Completed the same manifest and
retained-payload verification for sequences 29–32 and removed only their staging
duplicates under the installer lock. After sync/trim, host free space was about
4.7 GiB and guest free 5.0 GiB while rebuilding. All installed releases remain.

The restarted full affected check passes in QEMU: internal/mail (including actual
SMTP/STARTTLS and Postfix/nobody socket permission checks), cmd/cyberpanel,
cmd/panel-execd, internal/webengine/management (including signed installed
edition), and internal/noderelease (including unsafe managed-path rejection).
No interrupted or host execution is counted as verification.

All original host tar archives were losslessly gzip-compressed. The gzip copies
of sequences 31/32 are now stored in `retained-mail-pdns-pair.tar.zst` in the
QEMU run directory; extraction hashes exactly match their previous gzip files
(`e236ffe7b0e930d1adc1d1232a334f24625f58729c867d51ec1a3462bab610ed`
and `f1b544aa39afbe2bde40e456ff295d154d13bd38a4b60035a3115eed98d764a9`).
Their separate duplicate gzip files were removed only after verification.

### Signed native mail startup advances to protocol checks — 2026-09-20

Source `53322d734` built and tested entirely inside Ubuntu ARM64 QEMU. Signed
sequence 34 (`qemu-mail-sandbox-3.1.33`) committed and installed reconciliation
returned applied; dpkg audit clean after installation. Bundle SHA256
`fed3126820db37bbeae5d428b1b7f76db86d4464f08d29a188e10a53599dea95`;
manifest `30aea625096a49df72b4b366be5ff457b59c403317598c864512f29846fe9d9a`;
receipt `1e7c98b9059f5c3ced19956d11ccc5d819f2197a9e267a9ae4ca2db1f5cd11b2`.
Installed executor unit includes AF_NETLINK and ambient CAP_SETUID without a
temporary override. All mail validators complete and the six native services
(Postfix, Dovecot, Rspamd, OpenDKIM, ClamAV, dedicated Redis) are active.
Actual listeners include SMTP 25/587/465 and IMAP 143/993 on IPv4 and IPv6.
TLS IMAP CAPABILITY and LOGOUT completed against Dovecot using the explicitly
self-signed fallback certificate. This does not qualify mailbox authentication
or message delivery. SMTP TLS did NOT complete: native journal identifies
missing `private/proxymap`, consistent with missing internal service entries in
the generated Postfix master.cf. Fix that renderer before claiming mail works.

Core now advances past mail initialization and fails at web-engine installation
inspection (`webengine management: not found`). Core is stopped to prevent its
restart loop. The disk-reclamation reboot also exposed a PowerDNS cold-start
gap: executor recovery probes the retained generation while native pdns is
stopped. Starting pdns and restarting executor restored service. This manual
recovery is not a verified cold-boot fix; preserve it as a pending requirement.

Enabled `discard=unmap` in the existing QEMU resume script, powered off cleanly,
confirmed the old VM exited, resumed the same overlay, and trimmed guest free
space. Host available space rose from about 298 MiB to 2.4 GiB without deleting
VM data. Existing signed host tar archives are being losslessly gzip-compressed;
the original `panel-node-d14f9440b.tar` SHA256 after decompression remains
`bf43e24ed7fcece988782fd652a9280eff21bf4ab126e98bf4094b2b00beb41b`.
Sequence-33 and sequence-34 complete bundles remain in the guest. Disk remains
tight; do not add another release before reclaiming safe artifact/cache space.

### Native mail access, scan boundary and executor sandbox — 2026-09-20

Added root-controlled POSIX ACL grants for the six native mail identities:
traverse-only authority roots, read/traverse only each daemon's own role tree,
and narrowly scoped Postfix access to the fallback TLS pair. Native QEMU checks
verify own-config reads, cross-role/list/write denials, preserved generation
digests, replay, and rejection of unsafe ancestors, symlinks and hardlinks.

Installed ClamAV's declared Unix scan socket and scoped supplemental group access
for core/Rspamd, plus an additive local AppArmor rule (not profile disabling).
Actual QEMU native tests passed clean/EICAR INSTREAM scans, both allowed clients,
unprivileged denial, and the running clamd process's enforcing AppArmor label.
Freshclam downloaded and verified daily 28129, main 63 and bytecode 339 in QEMU;
fresh offline signature provisioning remains incomplete.

Signed sequence 33 (`qemu-mail-access-3.1.32`) committed, then its installed
reconciliation hook ran. Bundle SHA256
`02f158ae975a53c199835734aedbe2b83989c8c8ef65957690170e4272abd2b2`;
manifest `c48941551a68889e60e0f36645e23c235a1501970ae913b8e3612f9f231e67d8`;
receipt `68508935baaee450ca26e873fc81382fa7539d9040508f8d7ac92d50e5fe0435`.
This did not qualify core startup: native Postfix validation exposed two executor
sandbox mismatches. A systemd-run negative control reproduces getifaddrs failure
without AF_NETLINK; adding it passes. Under the combined root/mount sandbox,
CAP_SETUID was absent from effective/permitted capabilities despite remaining
bounded. Explicit ambient CAP_SETUID preserves that existing allowed capability;
the complete selected unit security settings now pass native Postfix check.
NoNewPrivileges and the other sandbox settings remain enabled.

Temporary QEMU executor drop-in applies these two source unit changes. All mail
configuration validators then completed and startup reached native services.
OpenDKIM's forking unit stalled because the renderer omitted its required PID
file. Added `/run/opendkim/opendkim.pid`; an isolated actual vendor-unit test now
starts successfully and checks its PID file and milter socket. Runtime test
override is removed afterward. Mail and installer package suites and both Go
binaries build successfully in QEMU. Full installed mail delivery/core startup
remain unqualified; the latest unit/renderer changes await a signed release.

Host disk filled while offloading sequence 33. Removed only the incomplete
168 MiB host copy; the complete guest bundle remains. Preserve previous releases,
journals and VM disks; compress archived bundles losslessly before further builds.

### Native mail configuration checks repaired and verified — 2026-09-20

The installed Dovecot failure was reproduced by a native renderer regression:
doveconf exited 89 with `Garbage after '{'`. Replaced one-line passdb, userdb,
service, protocol and plugin blocks with native multiline syntax. The next
native check exposed missing Sieve/ManageSieve packages. Downloaded only the two
matching Ubuntu ARM64 packages (420 KB total), version
`1:2.3.21+dfsg1-2ubuntu6.5`, and installed them inside QEMU with service restarts
blocked by policy-rc.d. dpkg audit is clean. Ubuntu's Sieve package selection now
names dovecot-managesieved, whose declared dependency includes the exact matching
dovecot-sieve package. The package mapping regression passes.

Mail's configured default TLS paths did not exist. Reused the existing immutable
bootstrap certificate mechanism with a separate mail/default namespace and key,
then installed the fixed mail TLS binding. Actual QEMU tests verify a valid
self-signed key pair, a public key distinct from the web fallback, root-only
0440 key permissions and stable replay. This is an explicitly untrusted local
fallback, not a publicly trusted mail identity. Native doveconf now accepts the
actual rendered configuration with these real mail TLS paths and required TLS.

Fixed two invalid native validation commands. Redis does not accept
`redis-server config --test-memory 2` as a config check; ClamAV has no
`--config-test`. Redis validation now starts a bounded, private, Unix-socket-only
process with persistence disabled and a temporary data directory, checks PONG,
then kills/reaps it and removes only that temporary directory. The installed
mail instance/data are not opened. ClamAV validation uses clamconf and rejects
explicit parse errors even when its exit code is zero. Native QEMU tests accept
valid rendered configs and reject unknown directives for both daemons.

OpenDKIM's native check also exposed an unprovisioned trusted-hosts path. Its
loopback-only TrustedHosts file is now part of the same immutable generation,
with the OpenDKIM artifact ownership, and both config references select it.
Native OpenDKIM parsing with the rendered config/tables passes. Direct Postfix
validation and Rspamd snippet parsing had already completed (with warnings).

Uncached mail/install/core/executor suites passed, and both candidate binaries
built inside QEMU as /home/harness/bin/cyberpanel-mail-validation and
/home/harness/bin/panel-execd-mail-validation. Use sudo for builds against the
shared guest GOCACHE: a non-root compile encountered root-owned cache entries;
the same targeted test passed when run as root. No product code change was
needed for that tooling ownership issue.

No new signed release was deployed: first fix native daemon access. A direct
_rspamd read of its retained redis.conf is denied. Actual mail root and
generations directories are root:root 0750, generation root 0555, and role
directories root:root 0550. Preserve root-only mutation authority while allowing
only each native service to traverse/read its own artifacts; do not make all
mail configuration public. The new fallback TLS key is also root-only, so qualify
native Postfix key access as part of this boundary. Installed sequence 32 remains
active; core and mail remain stopped, while DNS and executor admission are active.

The next draft release spec is
/home/harness/panel-node-d14f9440b/mail-validation-prereqs-spec.json (100 artifacts),
with both downloaded packages copied into source/native-packages. It still has
the old sequence/version: advance to sequence 33 / version 3.1.32 only when the
next candidate is ready. No OS image or Go archive was downloaded.
Sequence 32 archive was checksum-verified on the host before removing only its
guest /var/tmp copy. Installed releases/journals remain intact; guest free space
is 4.2 GiB. Native mail delivery and full core/gateway/API/UI/matrix qualification
remain incomplete.

### Native mail adoption and dedicated Redis qualified — 2026-09-20

Implemented installer-only adoption of five Ubuntu mail defaults. Dovecot and
ClamAV match ucf's stored default hashes; OpenDKIM matches dpkg's conffile record;
Postfix master.cf matches the package's master.cf.dist digest. Generated Postfix
main.cf must match the exact observed stock Ubuntu option set and host identity;
unknown, duplicate or changed options fail closed. All regular files are checked
before adoption, native mail services must be inactive, and originals are retained
as root:root 0600 SHA-256-named backups. Actual native default verification,
edited-Postfix rejection, adoption/replay and backup content/privacy checks passed
in QEMU. This is not generic adoption of customized installations; Alma remains
unqualified and has no new automatic adoption path.

A real binding test then failed at /etc/redis/cyberpanel-mail.conf: Ubuntu ships
/etc/redis as redis:redis 2770. Kept that vendor directory unchanged and moved
the panel binding to /etc/cyberpanel/mail/redis.conf. The dedicated mail Redis
instance now receives its config through a private systemd credential, uses
/var/lib/cyberpanel-mail-redis for private state and
/run/cyberpanel-mail-redis/redis.sock for its Unix-only endpoint. The Ubuntu unit
runs as redis with _rspamd socket-group access; it cannot write the panel config
directory. Rspamd rendering and the native health probe use the same socket.

The actual Ubuntu unit started under its vendor sandbox plus the managed drop-in.
Native redis-cli PING returned PONG as both redis and _rspamd. Negative access
checks rejected Rspamd reading the private input config and Redis writing the
panel config directory. A temporary /run test credential override was removed
and the service stopped after the test; the managed /etc drop-in remains. Actual
mail binding reconciliation now passes. Mail/core/executor package suites and
both binary builds passed in QEMU.

Signed sequence 32 `qemu-mail-native-3.1.31` committed; installed reconciliation
passed and adopted the defaults again. Before package reinstall, restored only
the five test-adopted links to their checksum-verified original bytes, preserving
backups: package scripts must not encounter dangling first-generation links.
This remains an upgrade/failure-recovery ordering concern until managed mail
has a valid current generation.

Bundle SHA-256 `0de6b050e3cf75675266efe1a45281f1ebf77f4e8d3831bfee04b98a1a68e6b9`;
manifest `1f2ad3cbc25820761e0851bc60f0044b6b0da16ba8f14d07baf376de60363acf`;
receipt `d4ba3ee88ef2844155ef1e5241aa70f07438b69998af9fd714e2612449de27ce`.

Core now stages the real mail generation, but native Dovecot validation fails:
`Garbage after '{'` at line 14. The renderer emits one-line semicolon-delimited
passdb/service/plugin blocks, which native doveconf rejects. A direct native
Postfix check completed with warnings; direct doveconf exited 89. Fix the
renderer and validate native configs before another signed deployment. Core
restart loop is stopped; no managed mail current link remains after rollback.
Retained generation: mailgen_99e5cb1dd2c2ee5de57928109134ad35-e4b640feb98c2072.
PowerDNS and executor admission remain active. Mail service delivery, core,
gateway/API/UI and the current-revision four-target matrix are not certified.

Sequence 31 archive was checksum-verified on the host and removed only from
guest /var/tmp; installed releases/journals were untouched. After sequence 32,
guest free space is 3.9 GiB. No OS images or Go archives were downloaded.

### Installed native DNS startup and executor admission verified — 2026-09-20

Sequence 30 `qemu-pdns-access-3.1.29` deployed the scoped database ACL/config
credential work and recovery for the exact retained immutable SQLite generation.
Recovery verifies the desired rendering and every manifest artifact, rejects
other generations/staging/current links/live services, and preserves the original
effect identity and archived attempts. Actual QEMU tests accepted the retained
generation and rejected a different desired generation and a staging marker.

Installer reconciliation now adopts only the default active systemd-resolved
stub setup: preserves the original link target in a root-only backup, switches
clients to the live upstream resolv.conf, and disables only the stub listener.
Custom resolver links/settings are rejected. Actual handoff/replay, outbound
lookup and absence of TCP/UDP stub listeners on port 53 passed in QEMU.
All four affected package suites and both binary builds passed in QEMU.

Sequence 30 started real PowerDNS on IPv4/IPv6 TCP/UDP port 53, but the panel
probe incorrectly called `pdns_control ping` (unsupported). The native health
regression failed before the fix and passed with `rping`, returning PONG.
Sequence 31 `qemu-pdns-health-3.1.30` deploys that executor fix. The installed
reconciliation hook passed, PowerDNS remains active with the intended current
generation, and executor mutation admission is ready, including after an
additional executor restart. Read-only SQL inspection confirms the original
powerdns/startup_configuration effect completed at epoch 0 with three archived
recovery attempts. No journal row was deleted or re-keyed. A real unconfigured
DNS query returns REFUSED; managed-zone/DNSSEC/transfer qualification is pending.

| Sequence | Bundle SHA-256 | Manifest | Receipt |
| --- | --- | --- | --- |
| 30 | 89e97f72ae1404041ee4f6a404f299c23499f06cf363478baad72387a69712ea | 247a4da2f876b9103679c7b611b499f41773d46737fab0f09c2c349cab8e7e7e | e298c5238e5458077bee1b9813df2e37a02f915950165e492dc950ee2e316e36 |
| 31 | 2e9d13a7e738753084d34ec526e2dcd75f0205eb21e383c288fb291a3809f272 | c771681015d2d4b2ebd32c78bc608c6e7570601ad33672bcd9e09b8e6b149e37 | 2a198e540b6301a0561119a1725a03233ffdcdc5ab5d038e8d004674c18271ef |

Sequence 30 archive was checksum-verified on the host before removing its guest
copy. Cleared only the disposable Go build cache, preserving installed releases,
modules, VM disk and journals. Guest free space after sequence 31 is 5.4 GiB.

Core now gets past executor admission and fails at Dovecot OAuth activation with
`mail resource generation conflict`. Its restart loop was stopped. Native mail
configs are still regular files and the managed mail store has no current link;
investigate that binding boundary next. Core/gateway/API/UI, native mail, managed
web and full current-revision OS/architecture matrix remain incomplete.

### Native DNS config and live database access proven together — 2026-09-20

Implemented named-user POSIX ACLs for the fixed pdns UID: execute-only access
to the dedicated PowerDNS store directory, read/write to authority.db and its
existing WAL/SHM files, and no owning-group/other access. Root retains ownership.
The service cannot list or create/replace/unlink directory entries, so a daemon
cannot substitute a symlink for the database opened by the privileged authority.
Validation rejects wrong UID ACLs, world-writable files, symlinks, non-root owners,
hard links and unsafe ancestors. Root-created SQLite sidecars are normalized to
the exact named-user ACL. Authority startup validates existing paths and reapplies
access without resetting it to owner-only on every reopen. No DB copy or backend
substitution is used; native SQLite connections share the live WAL.

Actual root-QEMU tests installed the ACLs, reopened the real authority, and ran
a BEGIN IMMEDIATE / INSERT / ROLLBACK transaction as pdns via native SQLite.
No zone was committed. The same UID could not write the store directory, list
generations or read control.db. Wrong UID, world-write and symlink fixtures were
rejected. Current visible modes are root:root 0710 (store) and 0660 (DB/WAL/SHM):
the apparent group bits are ACL masks, not grants to the owning group.

Installer reconciliation now writes and verifies the fixed pdns systemd drop-in
50-cyberpanel-credentials.conf: LoadCredential copies only the active pdns.conf
into the daemon's private mount; ExecStart selects that config directory. Native
config activation now restarts the unit to repin the selected credential generation.
Actual drop-in installation/replay and systemd unit verification passed in QEMU.

A transient real pdns-UID service using the retained config through LoadCredential
and the live SQLite files started successfully, launched primary/secondary and
UDP/TCP backend threads, and answered a UDP DNS request on 127.0.0.1:15553. The
unconfigured test zone returned REFUSED as expected (not a managed-zone success).
The transient service was stopped. This proves the access boundary, not DNSSEC,
transfers, managed zone lifecycle, or installed product startup.

Affected package suites passed, native access tests passed again after ancestor
validation, and candidate binaries exist as cyberpanel-pdns-access and
panel-execd-pdns-access under /home/harness/bin. New changes are not yet signed
or deployed. The tests prepared the QEMU ACLs and systemd drop-in; do not restart
the old executor which still has the old permission-reset behavior. Core and
native pdns remain inactive, admission closed. Next: reconcile the retained
generation/ambiguous effect and deploy both binaries, then test normal port/service
startup. Guest free space is 3.0 GiB. Alma/SELinux behavior remains unverified.

### Storage recovered; native DNS access failure isolated — 2026-09-20

Offloaded five older native/service/web/executor bundle archives to the same
host run directory and independently matched all guest/host SHA-256 values:

| Guest archive (now removed; host copy retained) | SHA-256 |
| --- | --- |
| panel-native-3.1.15.tar | d705febff5e5f5f6a3915ac2bf16826126b2626e56bd0187f04444596a5bd4a6 |
| panel-services-3.1.16.tar | 6ec81cbe498bb28649b1360cb3e738aee063332ee9c975942cc791a7eed5750e |
| panel-web-3.1.17.tar | 25420a193f549c61c6af1dd77042d29d1b7d2b8c5bbddfe46860d59740ab7e6b |
| panel-executor-3.1.18.tar | 92e0827f628e3fd0ae867b96e5acfcbe90d10d873dfc2bc610f7ea5c4ddbda8f |
| panel-executor-3.1.19.tar | aca74b78ccc945f44abbc2e96f14bf7bbd3d2b2db3812c44950bafd33d96a353 |

Removed only those verified /var/tmp copies. Guest free space rose from 805 MiB
to 3.1 GiB. Retained installed releases and node journals/staging were untouched.
Those installed generations and staging each occupy about 7.3 GiB; do not remove
them manually without the installer's recovery/retention invariants.

Native access probes ran only inside QEMU, as the real pdns UID/GID. The retained
generation is pdns-1-1a42b650351b-1b1cbb355ab4. Its config is root:pdns 0440,
but the generation's pdns directory is root:root 0550 and the store root is
root:root 0700. A systemd read-only file bind into a separate runtime directory
allowed actual pdns_server --config=check to pass. A separate real LoadCredential
probe also passed, without changing private-store permissions.

Then drove the native daemon with that systemd credential, a separate runtime
socket directory, loopback 127.0.0.1:15553 and an 8-second timeout. It read config,
opened its control socket and bound UDP/TCP, then failed opening the SQLite
authority database. The database plus WAL/SHM are root:root 0600 beneath the same
0700 store. Thus config delivery alone does not fix startup: native backend data
access also needs a correctly scoped boundary. The probe exited with failure;
it is not a passing DNS service test. No service UID or config/database modes
were weakened, and no database was moved or rewritten.

Next: solve native config and backend access together, retaining root-only
installer/generation authority and excluding the core database. Account for
SQLite WAL and native secondary-zone writes; do not mount/copy a stale database
snapshot as a live authority. Reconcile the retained generation/ambiguous effect
after the access fix. Core and native PowerDNS remain stopped, executor admission
closed. No new release was assembled during this diagnostic/storage turn.

### Evidence-bound recovery of unapplied PowerDNS startup — 2026-09-20

Read-only inspection of the real control database confirmed one ambiguous
powerdns/startup_configuration effect, epoch 0, with no successful response.
Added recovery only for that fixed local startup boundary after a native probe
proves managed bindings correct, no current generation, empty generations and
staging directories, and inactive PowerDNS. Ordinary ambiguous admission remains
rejected. Recovery retains the exact binding/epoch, rotates the lease token and
archives the old token, status, boot, timestamps and evidence digest atomically.
Core owns creation of the history table; executor waits for it during bootstrap.

All four affected package suites passed in QEMU. Regression tests reject missing
or active effects, changed bindings, wrong boundaries, changed epochs, closed
gates and stale settlement leases; successful recovery preserves the record ID
and prior attempt and permits terminal receipt replay. Actual native QEMU proof
passed for the inactive empty store and rejected an added empty staging marker;
only that test marker was removed afterward. Both binaries built in QEMU.

Signed sequence 29 `qemu-pdns-recovery-3.1.28` committed and its reconciliation
hook passed, deploying config adoption, preflight and recovery together.
Bundle SHA-256 `68cf1d64bf323c2adc1aa2ca96878c59d93cc0f6936311358c409a52710a7469`;
manifest `c3f8ca20f7414ae105d8ba498480791c70945a8de0d4dd035290662baf3eb408`;
receipt `64769688c920b0e1a2f4a54c58b8a560cda90fe862cfe1632826c3f88925db12`.
Actual executor recovered the prior attempt and reached native PowerDNS config
validation/activation. Database inspection confirms one archived attempt and
the same current effect, now ambiguous following the new native failure.

PowerDNS's native service runs as pdns:pdns and failed reading its managed config;
the generation store's root directory is root:root 0700. After rollback the
current link is absent. Core and PowerDNS restart loops were stopped. Do not
retry the empty-store recovery now that generation work exists: qualify native
service access and reconcile the actual staged/activated generation instead.
Admission stays closed and full core/gateway/API/UI qualification is incomplete.

Offloaded the sequence 29 archive to the host run directory, verified SHA-256
against the recorded bundle hash, then removed only its guest /var/tmp copy.
The archive remains recoverable on the host. Installed generations and journals
were not removed. Guest space remains tight; do not stage another full release
until storage is recovered safely.

### Pristine native PowerDNS configuration adoption implemented — 2026-09-20

Installer service reconciliation now adopts only the fixed native PowerDNS
conffile when its bytes match the installed package's local conffile digest.
Ubuntu uses dpkg's record; Alma uses RPM's config-file record. PowerDNS must be
inactive. Root-owned non-writable ancestors, regular singly linked source and
non-writable source permissions are required. Modified files are rejected.
The original bytes are preserved as a root:root 0600 SHA-256-named backup,
verified before atomically installing the managed link and syncing its parent.
An already-correct root-owned managed link replays without rewriting anything.
Adoption runs before installer receipt replay so native reinstalls are checked.

Root QEMU fixture tests passed for valid adoption and rejection of modified
content, unsafe permissions, wrong existing backup and foreign staging link;
rejection leaves original bytes intact. The actual Ubuntu package adoption test
ran twice successfully and verified the backup against the original bytes.
Actual link: /etc/powerdns/pdns.conf ->
/var/lib/cyberpanel/powerdns/current/pdns/pdns.conf.
Backup: /etc/powerdns/pdns.conf.cyberpanel-vendor-3d41154e93c96acee3cf10d5eb9b28f15de5a0a76e4a7273e7632bedfee74bb3,
root:root 0600, SHA-256
`3d41154e93c96acee3cf10d5eb9b28f15de5a0a76e4a7273e7632bedfee74bb3`.
PowerDNS remains inactive; its managed staging/generations directories are empty.
No native config bytes were discarded and no execution receipt was changed.

Command package suite and panel build passed in QEMU. Candidate binary:
/home/harness/bin/cyberpanel-dns-adoption. This hook and the previous executor
preflight are not yet signed/deployed; the actual test prepared this QEMU node.
RPM adoption is implemented but not yet live-Alma verified. Next: recover the
existing ambiguous startup execution with evidence, preserving request identity
and journal history; then deploy both fixes and qualify native DNS activation.
Guest free space remains 2.0 GiB; avoid another oversized staging cycle.

### Reject unmanaged PowerDNS config before execution admission — 2026-09-20

Confirmed /etc/powerdns/pdns.conf is the unmodified native package conffile:
regular root:pdns 0640, MD5 `1143e56f8921c7bd5135569c90600e19` matches dpkg's
conffile record, SHA-256
`3d41154e93c96acee3cf10d5eb9b28f15de5a0a76e4a7273e7632bedfee74bb3`.
PowerDNS is inactive. The existing binding code correctly refuses to overwrite
it, but startup acquired an execution lease before checking that boundary.

Added a strictly read-only binding preflight before startup execution admission.
Existing untrusted/native regular config is rejected before any lease; a missing
file under validated root-owned config ancestors may still be created by the
existing admitted activation path. Arbitrary links remain rejected. No package
config was overwritten, no effect receipt was deleted, and admission stays closed.

Actual root-QEMU regression drove ReconcileStartup against this native conffile,
verified daemoncfg.ErrConflict, zero admission calls, and unchanged config inode
and permissions. DNS/executor package suites passed uncached, and executor built
as /home/harness/bin/panel-execd-pdns-preflight. This binary is not deployed yet.
Next: installer-owned adoption of a verified pristine native config with a
recoverable backup, plus evidence-based reconciliation of the already ambiguous
startup effect. Do not re-key the request or delete its row merely to retry.

Sequence 28 archive was copied to the host run directory and SHA-256 verified
against its signed-release evidence before removing the guest /var/tmp copy.
It remains recoverable on the host; no installed state was removed. Guest free
space is now 2.0 GiB, still requiring care before assembling another full bundle.

### Core admission bootstrap precedes privileged startup effects — 2026-09-20

Core now initializes the reboot repository and execution admission gate with its
other repositories, before domain assembly can request privileged mail effects.
The executor observes the core-owned schema before recovery and retries while
the required bootstrap tables are absent. It never creates or repairs schema;
invalid store ownership and recovery failures still fail closed. Table presence
alone does not mark mutation admission ready: full startup recovery still must
complete. Existing reboot gate closure and recovery logic are retained.

QEMU tests for both command packages passed uncached. The core regression runs
the real repository bootstrap twice and verifies the singleton admission row.
Executor regression verifies repeated absent-schema observations create no
tables, partial schema stays closed, complete schema becomes observable, the
mutation wrapper remains closed before recovery, and invalid store validation
is rejected. Both updated binaries built inside QEMU.

Offloaded sequence 25–27 archives to the existing host run directory; all three
SHA-256 values match recorded release hashes. Removed only those verified guest
/var/tmp copies, recoverable from the host, freeing about 1.4 GiB. Installed
generations, journals, trust and rollback state remain intact.

Signed sequence 28 `qemu-admission-3.1.27` installed both corrected binaries;
reconciliation passed. Bundle SHA-256
`10eac057b8ebe915b776621805260326004e77e358624d46b1add704da224713`;
manifest `fd0d55742ef4e202739d6224f4c22ec867cfa8550232c95655e82b336d38827a`;
receipt `f933e5bcccc685fc189bcc19cc7a0a5ee883bbd3eed32820cb4915c69ac324bc`.
Actual executor first logged admission-bootstrap pending, then retried after
core initialization and progressed past the missing-schema failure. It remains
closed because PowerDNS startup configuration now fails with daemon generation
conflict. Core's mail activation therefore remains blocked; core restart loop
was stopped. Investigate native PowerDNS config adoption and the failed startup
effect's durable recovery before another restart, without deleting receipts or
opening admission. Guest free space is 1.6 GiB; further bundles need safe storage
recovery first. Full startup and product qualification remain incomplete.

### Shared systemd credential boundary for mail keys — 2026-09-20

Moved the proven private credential validator into the existing secrets package,
so audit, webmail-session and campaign-unsubscribe loaders apply the same exact
root/service-user ACL and read-only tmpfs checks. The mail entry points retain
their fixed paths and 32-byte requirement; opened-file identity and bounded reads
now prevent path replacement or oversized reads. Ordinary group-readable files,
arbitrary public loader paths, symlink credentials and wrong-size keys fail.

QEMU command/mail/secrets package suites passed uncached. Actual systemd units
running as cyberpanel loaded both real mail credentials successfully; the shared
validator accepted the actual audit credential and rejected wrong UID/permission
expectations. No secret bytes were printed. All build/test execution was in QEMU.

Signed sequence 26 `qemu-mail-credential-3.1.25` committed; hook reconciliation
passed. Bundle SHA-256
`ef4eb72634f48f985e3f954e5c18b7c532071e761a375ead84ab35f72c5dc1e8`;
manifest `9442dece161377d594b952ed82a3da3060c8c5123e15c7087795fefe98b32954`;
receipt `b3f5a3c90db8e46b21d9b89b12b76cf0cd1371cbb74711c9f1ee62c21a34cddd`.
Installed core passed webmail credential loading and next failed creating
/var/lib/cyberpanel/webmail on its read-only filesystem. The core unit now declares
only that additional StateDirectory (0700) and writable path. Qualification of
that unit follows; this is not yet full startup or product certification.

Signed sequence 27 `qemu-webmail-state-3.1.26` committed and reconciliation
passed. Bundle SHA-256
`b64083293cdde597eff16574e264e478796f9188a5a489af5f7e6dd245258755`;
manifest `2521d08a1fc8e0a5fd63277c06ab08e782e77d340d45758ba7d4922e6081031b`;
receipt `bf95520b170ecd6c6fa5f58ab7435acd056340110adebc1e165862c7f829280b`.
Unit verification passed with the previously recorded vendor OLS warnings.
Installed core created both webmail and blobs directories as UID 999/GID 988,
0700, then failed `activate Dovecot OAuth passdb: mail resource generation conflict`.
Core was stopped. Restarted executor once to check whether core bootstrap had
created its admission schema: it still reports missing reboot_admission_gate
and keeps mutations closed. Code confirms mail activation occurs around line
275 of domain_services_linux.go, before assembleRebootControlLinuxEdge around
line 814 creates the admission gate. Executor startup recovery currently stops
retrying on missing-schema errors. Next fix must resolve this startup ordering
and readiness dependency without allowing pre-recovery mutations. Do not create
schema manually from root or disable admission. Full startup remains unproven.

### Installed executor digest resolved through managed release — 2026-09-20

The real executor path is a root-owned link through node-current into the
immutable release root. The core digest helper previously rejected that link.
Added a fixed executor-path resolver reusing the existing managed-config
activation/ancestor validation, with executable rather than config mode limits.
The digest helper checks opened-file identity and rejects empty/oversize input.
Unrelated symlinks remain rejected; config mode requirements are unchanged.

Root QEMU fixture checks passed for managed config/executable resolution,
writable executable rejection, arbitrary links, wrong generation, writable
ancestors, linked payload and credential rejection. The actual installed
executor digest matched independently read binary bytes. Both affected package
suites passed uncached as harness (root-only cases separately run above).

Signed sequence 25 `qemu-digest-3.1.24` committed; reconciliation passed.
Bundle SHA-256 `5f46c98fb0bb88ef7d62a0e09a0a28dc8a230f78e60d666d11bf58a8f1df5c67`;
manifest `56b3992fc4393b1c5a7cfc22b369162f41466b59864954db9682173486eb0d84`;
receipt `9ff5eb8acd36dadf7a74feef713f1d071e4e4bcb37d657211b1920250a7b7827`.
Actual core now passes database executor digest and fails loading webmail session
authority. Its separate mail loader rejects group mode bits on systemd
credentials, as does the campaign unsubscribe loader immediately downstream.
Apply the already-proven credential boundary consistently to these consumers;
do not relax arbitrary secret files. Core restart loop is stopped.

Offloaded the four sequence 21–24 bundle archives to the host run directory
`current-ubuntu-arm64-20260919-smoke`, verified all four SHA-256 values against
the recorded release evidence, then removed only those four guest /var/tmp
copies (about 1.9 GiB). They are recoverable from those host copies. Retained
installed generations, trust, journals and rollback state are untouched.
Core/gateway readiness, API/UI and full matrix qualification remain incomplete.

### Core systemd audit credential accepted safely — 2026-09-20

The audit loader now recognizes the exact systemd credential boundary only at
its fixed audit credential path. It requires root:root, a singly linked regular
0440 file, read-only tmpfs, and the exact ACL granting read to root and the
current non-root service UID with owning group/other denied. The root-owned
0550 parent must carry the equivalent traversal ACL. Ordinary secrets retain
their owner-only permission requirement. No key bytes were printed.

QEMU command package tests passed uncached. A compiled test run by a real
systemd LoadCredential unit as cyberpanel passed the actual credential check
and rejected a different UID and unexpected permission requirement. An ordinary
0440 secret was rejected and an owner-only fixture accepted. An initial test
launch from private /home/harness was denied execution; the same test binary
was installed root-owned in /var/tmp for the service run.

Signed sequence 24 `qemu-credential-3.1.23` committed and its installed service
reconciliation hook passed. Bundle SHA-256
`59bcb470accb4615dbfd9da1bb7097974c528c784d3040e32e4d6f4cd60bdc05`;
manifest `a30dbb2130ce6e08db35275199cc1591555a5df25ff006963f3630facebecb48`;
receipt `b8f9d364ed3a66f343a19354347ff8ba8aa8fad0eed52b21e34fc1a71cff10a3`.
Actual core startup now passes audit credential loading and reaches domain
assembly, failing `digest database executor: webengine management: invalid value`.
The digest helper currently rejects symlinks at the installed executor path;
investigate its signed-release binding next. Core restart loop is stopped.
Guest root has 4.4 GiB free; avoid unnecessary retained release duplication.
Core/gateway/API/UI and full matrix qualification remain incomplete.

### WP-CLI installed; executor namespace repaired — 2026-09-20

Provisioned a separate QEMU-only release authority `qemu-runtime-20260920`,
bounded to sequences 21–40 and expiry 2026-09-26T18:51:37Z. Existing trust and
retained releases remain intact; private signing material stays inside QEMU.
Sequence 21 `qemu-runtime-3.1.20` installed the native web-authority hook and
WP-CLI package. Actual signed `reconcile-services` passed; installed
`wp --info` reported WP-CLI 2.12.0 and PHP 8.3.6. Bundle SHA-256
`e88e1236ee85db98e6cfe657f101e28189983e047b84c74b9ffc1801544c26b0`;
manifest `e0c15354210502a420c2846b4044b183cbc7d0c14ff2b837dfe100a40e016a45`;
receipt `37dfacc3043542770c8f81faf48342aaea5a43679b49b5bca9603e23b045d11d`.

Executor startup then failed creating `/run/user/992`: ProtectHome hid the
explicitly writable rootless runtime path. Changed to ProtectHome=tmpfs with
BindPaths=/run/user. A real systemd namespace probe confirmed /home/harness and
/root/.ssh remained hidden while creating an empty temporary directory under
/run/user succeeded; that probe directory was removed. Unit verification passed
(vendor OLS unit still warns about legacy PID path and KillMode=none).
Sequence 22 `qemu-namespace-3.1.21` installed this unit and reconciliation passed.
Bundle SHA-256 `6de243c919d89a6c22f950500f1da518821171b24aa2e52b24e3c3af4a5ff94c`;
manifest `3b965c19dacc93f8ab71f1990f57a9b4c4f825879fecf3cba3b599aaa0ab7462`;
receipt `76e6b5a375564b006ba2d60348adb617e97af77d2ee6d638b16e165718cc41c2`.
Executor now runs, but mutation admission remains closed: the not-yet-started
core owns the missing reboot_admission_gate schema. Updater socket remains absent.

First actual core launch failed systemd mount setup (226/NAMESPACE) because
/run/docker.sock does not exist on this Podman node. Core/gateway unit changes
make only Docker socket exclusions optional, matching the provider unit;
existing sockets remain inaccessible. Qualification continues below. No download
occurred; these are Ubuntu ARM64 startup results, not full product certification.

Sequence 23 `qemu-core-3.1.22` committed the optional Docker socket exclusions.
Bundle SHA-256 `5e04d05da169b713f00d1e2f14a506b9af2693f36127b753528109e7209bb299`;
manifest `996fd61d25003ea4bbc3aa31b9630c628fd53a22da0b051af20dba396dc08249`;
receipt `230806f284ae64c3cfe801d3665f0d450e8c532625734b712430f0e913a838cc`.
The installer initially rejected the harness-owned bundle, then accepted it
after root ownership and 0600 were applied. Signed reconciliation passed.
Actual core launch now passes mount namespacing and fails its audit credential
mode check. Root source secret is 0600; a real systemd LoadCredential probe
running as UID 999/GID 988 exposes the credential root:root/0440 in a
root:root/0550 service credential directory, on read-only nosuid/nodev/noexec
tmpfs. Existing readCoreFile rejects all group mode bits, including the ACL mask
used by systemd credentials. No validation weakening was applied. Core restart
loop is stopped. Next: validate the actual credential access boundary and fix
only that loader path, then resume installed core/gateway/API qualification.

### Corrected executor deployed; native web authority bootstrap verified — 2026-09-20

Signed sequence 20 `qemu-executor-3.1.19` committed with the corrected listener
order. Bundle `/var/tmp/panel-executor-3.1.19.tar` SHA-256
`aca74b78ccc945f44abbc2e96f14bf7bbd3d2b2db3812c44950bafd33d96a353`;
manifest `773b9559446032ab506b89ed7a94c0959b246a830b3cd8a09796087648680865`;
receipt `be9efe294f6fcd757f6bca6187c16c501453eb0e960add7cbe974939c2ba49c2`.
Actual startup passed malware/siteops socket setup and then correctly rejected
the vendor web configuration directory's public mode instead of required 0700.

Added root installer service-reconciliation preparation for the fixed native
configuration boundary: selects the master from the installed engine edition,
validates root-owned non-writable ancestors, opens the config directory without
following symlinks, transfers it to root:root/0700, and opens the master relative
to its directory descriptor without following symlinks. The master must be a
single-link regular file; it becomes root:root/0600. Contents are not rewritten.
This runs before reconciliation receipt replay, since package reinstalls can
restore vendor ownership/modes. Runtime private-store checks are unchanged.

The actual root-QEMU test applied this preparation twice, verified ownership and
modes, checked unchanged master SHA-256, and opened the real fsstore successfully.
The panel build passed. The updated hook binary exists at
`/home/harness/bin/cyberpanel-web-authority` but is not yet signed/deployed.
The test prepared the actual QEMU config; restarting the deployed executor then
passed web-store setup and reached application runtime admission, failing because
`/usr/bin/wp` is absent. It also reports the product updater socket unavailable.
Executor was stopped; full startup is not yet achieved.

Reused existing verified WP-CLI 2.12.0 PHAR, SHA-256
`ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c`.
Built a QEMU-native `cyberpanel-wp-cli` 2.12.0-1 architecture-all package carrying
those unchanged bytes at `/usr/bin/wp`. Inspected final archive ownership/modes:
root:root directories 0755 and executable 0755. Candidate
`/home/harness/cyberpanel-wp-cli_2.12.0-1_all.deb`, SHA-256
`815388401cfb99a791ac87b316f1448271d12837ef6eece52d697adb1e3f306c`.
It is not installed yet. No new download occurred. Next signed release must
include this package and the updated panel hook; the current QEMU signing trust
range ends at sequence 20, so provision a new bounded QEMU release authority
before that publication rather than bypassing sequence enforcement.

### Service identities provisioned; executor runtime ordering fixed — 2026-09-20

Invoked the existing installer LinuxHost.EnsureIdentity in QEMU for the missing
gateway/container identities, rather than duplicating user/group allocation.
Gateway is UID 993/GID 984; containers UID 992/GID 983, home
`/var/lib/cyberpanel-containers` (0750), subordinate UID/GID ranges
524288:65536. This is explicit QEMU bootstrap; automatic fresh-node orchestration
of these identities remains part of installation qualification.

Rebuilt the executor at `9089d42fe`, including the signed engine-edition config
resolver, and installed signed sequence 19 `qemu-executor-3.1.18`:
bundle `/var/tmp/panel-executor-3.1.18.tar`, SHA-256
`92e0827f628e3fd0ae867b96e5acfcbe90d10d873dfc2bc610f7ea5c4ddbda8f`;
manifest `f7ca6216861a72f373d37fb2bf0b0e84e8734ac415591125906df17b51b84a0e`;
receipt `25ffce4d18c30299fc0ccfe49b4311d146dd145c44b202a97321721399264a70`.
The signed release committed, but its newly started executor failed at malware
socket admission: systemd creates `/run/cyberpanel` as root:root, while malware
requires root:control ownership. The siteops listener already establishes that
ownership but was initialized later. Stopped the executor restart loop.

Moved malware listener creation immediately after siteops listener creation,
preserving its exact permission check and root executor group. QEMU build and
uncached siteops tests passed (cmd/panel-execd and malwarescan have no package
tests). A guarded QEMU probe using the actual shared-directory and Unix socket
paths successfully opened both real listeners in the corrected order, then
closed them. The ordering fix is built at
`/home/harness/bin/panel-execd-runtime-order` but is NOT installed in sequence 19.
Publish it before the next full startup claim. Core/gateway remain unstarted;
OLS remains under the explicit configuration hold. Further runtime configuration
and complete API/browser/lifecycle qualification remain required.

### Native package transaction fixed; OLS/LSPHP installed — 2026-09-20

The node installer now verifies every pending package before mutation, records
each package's pending effect, and passes the complete pending set to one native
dpkg/rpm invocation inside the existing offline namespace. Completion evidence
is collected for the set before marking per-package effects complete. Replay
still checks completed effects against installed metadata. Retained-package
restoration uses the same batch path so dependency cycles are not reintroduced
during rollback. No force-depends or package rewriting was added.

Debian completion evidence now additionally requires `installed ok`, not only
matching name/version/architecture: unpacked or half-configured packages cannot
be mistaken for completed effects. The real unpacked lsphp83-opcache fixture
passed the rejection regression before recovery. Root-QEMU uncached node-release
tests, including isolated-network and managed-config checks, passed (0.025 s).
The new installer then reconciled the existing staged sequence-18 journal.

The real LSPHP/opcache cycle resolved and `qemu-web-3.1.17` committed at
2026-09-20T04:32:17Z, receipt
`dda8171ee7ce2782b5d1830b19e37340cbabb152b9fe02cb531f5ef354e729a2`.
`dpkg --audit` returned no findings. Executing the real vendor binaries confirmed
OpenLiteSpeed 1.9.2 and LSPHP CLI 8.3.33 with opcache. Module inspection includes
bcmath, curl, gd, intl, mbstring, mysqli/mysqlnd, PDO MySQL/SQLite, soap, sodium,
XML/XSL and zip. This is binary/module evidence, not a managed HTTP site test.
RPM batch execution still requires actual Alma qualification.

OLS is inactive with its QEMU hold condition false. Actual executor startup now
passes the OLS-directory prerequisite but stops at systemd mount setup because
`/var/lib/cyberpanel-containers` is absent. Its restart loop was stopped. Next:
use the existing installer identity provisioner for missing container/gateway
identities (which creates the container home and subordinate ranges), publish the
already-tested engine-config loader fix in a signed executor, then continue real
service startup. Core/gateway and the full API/browser remain unqualified.

### Real OLS/LSPHP inputs admitted; package-cycle blocker identified — 2026-09-20

Verified the vendor's Noble ARM64 repository metadata using only its RSA4096
key `3E892522DB44E1B063D366C5011AA62DEDA1F085`, obtained over HTTPS from the
official repository. The older DSA1024 key was inspected but NOT trusted. A
dedicated deb822 source scopes Signed-By to the vendor key; global apt trust is
unchanged. apt verified Release/Release.gpg and fetched its ARM64 package index.
The vendor setup script remains unexecuted.

Downloaded 15 authenticated packages (22.4 MB) into `/var/tmp/panel-web-packages`,
including OpenLiteSpeed `1.9.2-1+noble`, LSPHP `8.3.33-1+noble`, common/mysql/curl/
intl/sqlite3/opcache and their native dependencies. No Apache or replacement
OS/toolchain images were fetched. Vendor postinst inspection found a direct
systemctl restart bypassing policy-rc.d. A temporary root-owned drop-in at
`/etc/systemd/system/lshttpd.service.d/10-qemu-hold.conf` requires the deliberately
absent `/run/cyberpanel-qemu-web-configured`; remove this fixture only after managed
configuration is ready. Do not claim OLS activation from package installation.

Signed candidate sequence 18, `qemu-web-3.1.17`, contains 97 artifacts and
506,002,559 payload bytes:
bundle `/var/tmp/panel-web-3.1.17.tar`, SHA-256
`25420a193f549c61c6af1dd77042d29d1b7d2b8c5bbddfe46860d59740ab7e6b`;
manifest `8fd38f03117a231006e5def5e6428f72725f56a55e2e7727a60dacf1b189454c`.
Admission succeeded, but one-at-a-time dpkg installation stopped at lsphp83-opcache
because it depends on lsphp83; direct package metadata inspection confirms that
lsphp83 also depends on lsphp83-opcache. Reordering cannot fix this cycle. Next:
run the complete verified package set as a native package transaction, preserving
effect journaling and offline isolation, and retry this same candidate. Do not
use force-depends or alter vendor payloads. opcache is currently unpacked but
unconfigured; the web release has not committed and OLS is not yet installed.

Separately, the actual signed engine.edition symlink reproduced an executor
loader failure (`engine edition file has unsafe metadata`). The loader now uses
the existing generation-pinning config resolver before its regular-file metadata
checks, preserving arbitrary-link rejection. The installed-config QEMU regression
went red then green, and uncached siteops/node-release suites passed. This fix
still needs to be built into the next signed executor binary before activation.

### Service binaries/units installed; web-engine prerequisite identified — 2026-09-20

Expanded the existing Ubuntu ARM64 qcow2 from 24 GiB to 40 GiB after a clean guest
shutdown and confirmed QEMU process exit. Reused the existing backing image,
overlay and resume script. Cloud-init grew the root partition/filesystem at boot;
explicit growpart/resize2fs checks reported already grown. The root filesystem
is now 38 GiB with approximately 15 GiB free after the next release installation.
The installed release and four authority services survived the reboot. No image
or toolchain download occurred. Native mail/DNS/ClamAV units were stopped and
disabled pending configuration, including clamav-daemon.socket; freshclam had
no journal entries in this boot. policy-rc.d alone does not prevent boot activation.

Signed sequence 17, `qemu-services-3.1.16`, committed successfully with 82 artifacts
and 483,614,963 payload bytes. It adds the previously QEMU-built executor/gateway
binaries, packaged executor/core/gateway units, packaged core/loopback-gateway
configs, and installer-owned OpenLiteSpeed edition selection.

- Bundle: `/var/tmp/panel-services-3.1.16.tar`, SHA-256
  `6ec81cbe498bb28649b1360cb3e738aee063332ee9c975942cc791a7eed5750e`.
- Manifest: `045a434c3e63dfabb86eedc371b2ef6e2c46d7e845e13096832ae6dd3169da09`.
- Receipt: `ca6cf58c642390b6e80b224e063f2632bff88cffe50fb7733cf40f4a69a84a67`.

Only the existing four authority services are qualified by this bundle's probes;
the new units were installed for actual startup qualification. Starting the real
executor failed with systemd 226/NAMESPACE: `/usr/local/lsws/conf` is missing.
Stopped its restart loop. OpenLiteSpeed/LSPHP are not installed in this guest and
apt currently has no candidate. Do not hide that dependency with a dummy directory
or weaken the unit's filesystem protections. Core/gateway remain unstarted.

Confirmed the vendor's repository installation path at
https://docs.openlitespeed.org/installation/repo/ and downloaded its setup script
to `/home/harness/litespeed-repository-setup.sh` for inspection only; it was NOT
executed. It identifies the Debian repository and two public signing-key URLs
under `rpms.litespeedtech.com/debian/`. Next: obtain/verify those repository inputs
over HTTPS with scoped apt trust, collect real ARM64 OpenLiteSpeed/LSPHP packages,
then continue the signed installation/startup path. The engine-edition reader's
handling of installer-managed config links also needs qualification at startup.

### Offline loopback fixed; native release sequence 16 committed — 2026-09-20

The package runner now creates its isolated network namespace on a disposable
locked OS thread, enables only its private loopback with an ioctl, and runs the
existing fixed package command there. The locked goroutine exits without
unlocking, so Go destroys that thread rather than returning altered namespace
state to the runtime pool. No external interface, route, shell or new executable
allowlist entry is added. Package subprocesses explicitly use noninteractive
debconf. Non-package commands keep their existing execution path.

The real root-QEMU regression initially failed because the namespace contained
only a down loopback. After the fix, three invocations verified only an active
loopback, external UDP connect returning ENETUNREACH, and unchanged caller-thread
namespace. The observation uses `/proc/thread-self/ns/net` because namespaces
are per-thread; `/proc/self/ns/net` names the thread-group leader, not necessarily
the calling Go task. The uncached node-release suite passed with root-safe
TMPDIR=/root, and the installer was rebuilt in QEMU.

Retrying the actual signed release reconciled the prior staged journal and
successfully installed/configured the native packages, including Postfix's real
newaliases step. Installed sequence is now 16, `qemu-native-3.1.15`; journal
`install-671a5a5b1a126f7bd041a3504b5faf5cda0a4323e8435ff9f678e44b7291fb55`
is committed at 2026-09-20T04:19:40Z. `dpkg --audit` returned no findings; explicit
package queries confirmed Postfix, Dovecot, Rspamd, PowerDNS, OpenDKIM, Redis and
ClamAV daemon installed. All four existing panel authority services are active.
Postfix, PowerDNS, Rspamd and freshclam remain inactive under the QEMU policy-rc.d
fixture pending real configuration. No mail/DNS functional claim is made yet.

The retry command subsequently reported ENOSPC while redundantly staging its
bundle after successful reconciliation. Fresh status inspection, an explicit
reconcile returning no pending operations, and package/service checks established
the committed state; the command's exit code alone was not treated as success.
The old sequence-15 signed bundle was copied to the host run directory, its
SHA-256 matched on both ends, and only the guest duplicate was removed. Installed
and retained generations remain untouched. Guest free space is about 603 MB.
Core/gateway/execd activation and full live API/UI qualification remain pending.

### Native package admission fixed; isolated Postfix setup blocker reproduced — 2026-09-20

Real native bundle assembly exposed rejection of Debian `Architecture: all`.
Added a regression across all four target tuples: it failed in Ubuntu ARM64 QEMU
for all four architecture-independent cases before the fix. Metadata admission
now accepts the target's native architecture or its manager-specific independent
value (`all` for dpkg, `noarch` for rpm), retaining wrong-manager/wrong-CPU
rejections. The uncached node-release suite passed after the change.

The real installer then rejected Ubuntu ssl-cert's empty root-owned 0700
`/etc/ssl/private/` directory as private material. The inventory check now admits
only that exact dpkg directory record (directory type, root/root, zero bytes,
0700). Files, symlinks, descendants, wider permissions, other owners and RPM's
path-only inventory remain rejected; focused regressions and the package suite
passed. Real bundle admission progressed beyond this check.

Candidate sequence 16 `qemu-native-3.1.15` contains 74 artifacts / 441,987,616
payload bytes, including 45 native inputs in apt's configuration order:
bundle SHA-256 `d705febff5e5f5f6a3915ac2bf16826126b2626e56bd0187f04444596a5bd4a6`,
manifest `8f45c8db7724320284c18d91f51104a51c4da475216f5e1d7d010bbc7950d6e4`.
It is retained at `/var/tmp/panel-native-3.1.15.tar`. Assembly used the patched
node-release binary; apply used the patched panel-node-install binary.

Installation is **not complete**. It stopped configuring Postfix: `newaliases:
fatal: could not find any active network interfaces`. Direct reproduction using
`unshare --net /usr/bin/newaliases` produced the same error. The isolated network
namespace has loopback down. Installer child environment also lacks an explicit
noninteractive debconf frontend. Next work is the offline package runner, without
restoring external networking or changing package payloads. Postfix is currently
half-configured; some preceding dependencies installed. The candidate journal
remains staged; installed sequence is still 15, `qemu-apps-d14f9440b`.

A QEMU-only root-owned `/usr/sbin/policy-rc.d` returning 101 was installed after
confirming no previous file existed, to prevent package-script daemon starts.
Postfix, PowerDNS, Rspamd and freshclam were checked inactive. Keep this guard
until native configuration/activation is ready; remove only this known fixture
afterward. Guest free space is approximately 261 MB after staged/retained release
materialization, so offload verified scratch bundles before another build/copy.

### Remaining service binaries and native package inputs prepared — 2026-09-20

Built the current executor and gateway in Ubuntu ARM64 QEMU from the same
`d14f9440b` code used by the installed panel:

- `/home/harness/bin/panel-execd-d14f9440b`: SHA-256
  `73d2f0abe567959960ddbc0eaf9d4f665869b72a80b7786e8c2de30912a335be`.
- `/home/harness/bin/paneld-d14f9440b`: SHA-256
  `86dd676e2cfe3fce271f94c97f944abba6e353fb380a79a50eddf3dacb74f90b`.

Startup inspection confirmed the guest lacks the native mail/DNS packages and
service groups required by the executor. Ubuntu apt downloaded (download-only,
no recommended packages) 45 authenticated native package inputs, 23.8 MB, into
`/var/tmp/panel-native-packages`. These include Postfix/SQLite, Dovecot
core/IMAP/LMTP/SQLite, Rspamd, PowerDNS/SQLite, OpenDKIM, Redis and ClamAV daemon
dependencies. Their actual package/version/architecture metadata was inspected;
no Apache package was downloaded and no new service was installed or activated.
These are inputs for the next signed node bundle, not proof of service operation.
Native package installation ordering, engine edition/configuration and remaining
executor startup prerequisites still need to be connected before activation.

The 801,461,518-byte OpenSearch input archive was offloaded to the host run
directory as `opensearch-3.8.0-verified.tar.gz`; host and guest SHA-256 both matched
`1ed8b6e9e3be799fe08688ea73791cc03d98269d6831646df2905f42c318e05e`
before deleting only its guest duplicate. The extracted OpenSearch installation,
signature evidence and running node release were preserved. Guest free space is
approximately 1.6 GB. No OS image or Go toolchain was downloaded.

### Signed panel/catalog installation and bootstrap verified — 2026-09-20

The existing node-release assembler signed a 29-artifact bundle containing the
current panel component, all five PHP archive/recipe pairs, both container
recipes, and the existing four authority services/UI. The real node installer
committed sequence 15, release `qemu-apps-d14f9440b` (version 3.1.14):

- Bundle SHA-256: `bf43e24ed7fcece988782fd652a9280eff21bf4ab126e98bf4094b2b00beb41b`.
- Manifest: `e44820d671ebcaa3b58d73bc5c2f9dfc505b3abfe5441f2a274858253096d58a`.
- Install receipt: `8d03d1b810b870300c3ac58ca535d4e986653e387ff29859f3b798f02805c163`.
- Payload bytes: 418,157,598. Bundle retained at `/var/tmp/panel-node-d14f9440b.tar`.

The installed panel resolves into that exact immutable generation and its hash
matches the QEMU-built binary. The previously used recipe authority's public key
was separately provisioned as root-owned installer trust (not promoted from an
arbitrary release asset). Running the installed binary's root installer ceremony
completed `initialize-authority`, repeated initialization with receipt/catalog
validation, and `bootstrap-secrets`. This exercised packaged recipe signature
validation, actual catalog publication, persistent AppArmor policy provisioning
and local authority creation, rather than only a helper/test copy. All four
authority services remained active and the exact AppArmor generation enforcing.

The node bundle does not yet contain core/gateway/execd units. No full panel API,
browser, OLS/LSPHP managed application or container lifecycle claim follows from
this checkpoint. Those remain required. Guest space fell to 233 MB during
catalog publication. Both component `.tar.gz` archives were copied to the host
run directory, SHA-256 verified on both ends, then only their duplicate guest
files were removed. They remain recoverable from the host; guest free space is
now approximately 912 MB. Preserve installed generations/receipts and recover
more scratch space before the next large signed bundle.

### Current-code application component rebuilt — 2026-09-20

Rebuilt both panel and assembler from `d14f9440b` inside Ubuntu ARM64 QEMU,
then assembled all five previously verified PHP archives and both signed
container candidate recipes without downloads. New candidate:
`/home/harness/panel-component-d14f9440b.tar.gz`, 355,918,034 bytes,
SHA-256 `59bf9d5bf006e90d104dc96d7cd1696a893177020fa266179ba68d9ef70370ff`.
Gzip integrity and the actual archived manifest were checked. Catalog sequence
2 identifies `qemu-apps-d14f9440b`, content digest
`fb5ed2c5341192bd577517c7e273c1b408abe543aa81f482e72bbdd475a7487a`.
Panel binary SHA-256:
`c8c6350ac103aade3df5cb180ad6f6394afa3ca1a7b351f16bb87fbfe89d40e7`;
assembler SHA-256:
`7251e5535c5cf74b886fde77ebdda377e175ffc8a4a0f25a369e61066154b339`.
This supersedes the older component, not the installed authority-only node.
The outer signed node release and full service/API/browser qualification remain
pending. Guest disk has 2.2 GB free; avoid additional large image pulls until
space is recovered or the existing virtual disk is safely expanded.

### Persistent container policy and real reboot verified — 2026-09-20

The existing initialize/migrate installer hooks now provision the embedded,
versioned AppArmor policy before receipt replay. The root-only provisioner
validates trusted parent/parser metadata, rejects altered, writable or symlinked
generation files, loads only embedded bytes, atomically persists root-owned
0644 policy under `/etc/apparmor.d`, and verifies kernel enforcement. Existing
generations are retained; no rollback unloads live workload confinement.

Ubuntu ARM64 QEMU tests passed for persistent publication, reload after kernel
state loss, unchanged inode on replay and rejection of unsafe files. Uncached
containers/cyberpanel package checks and the panel build passed. The exported
provisioner then installed the policy in the actual guest. A real reboot changed
boot ID from `05b6f627-1117-4dd2-b34c-8e08d5f0d005` to
`7139051b-e1f2-45bc-a7a6-3d0d11f29c9d`; AppArmor's native boot service loaded the
exact enforcing generation without invoking the provisioner again. All four
installed authority services returned active. Native rootless runtime admission
and actual container confinement tests then passed (0.610 seconds), using the
already boot-loaded policy rather than loading a test profile.

This verifies policy persistence, not a full signed node installation: the hook
has not yet been exercised through the outer signed installer. Core/gateway/execd
remain uninstalled. The temporary PHP HTTPS input fixture stopped with reboot;
the verified offline archives and signed recipes remain available. Other OS/arch
qualification and complete workload lifecycle checks remain pending.

### Fixed-profile native container confinement implemented — 2026-09-20

The native rootless launcher now enters a fixed AppArmor profile through the
trusted root-owned `aa-exec` binary before Podman/Skopeo starts. Its name derives
from the embedded policy template; this generation is
`cyberpanel-containers-483cce58be6c2384eb99facad419f8c0`. The caller cannot choose
the profile or an alternative executable. Missing, complain-mode, wrong-generation
or unavailable enforcement fails closed. When AppArmor is unavailable, the
existing Alma path requires SELinux's enforcing flag; disabled/missing MAC is
not an unconfined execution fallback.

The policy forces inherited executable confinement, denies control-plane paths,
selected kernel interfaces and writes to process profile-transition attributes.
The host-side rootless runtime still needs mount/user-namespace operations;
workload capability, seccomp, filesystem, user mapping and network restrictions
remain separately mandatory. This policy is not claimed to replace those layers.
Profile generations may coexist; old generations must not be unloaded while
their workloads remain active.

Runtime inspection recognizes this confinement only for the native runner after
its fixed-profile launch and enforcing-generation check. It does not turn the
kernel-enabled flag alone into a positive MAC verdict. The existing native
executable allowlist and supplementary-group clearing remain enforced.

QEMU verification exercised a real pinned n8n-image process through the native
launcher: confirmed the exact enforced profile inside the container, read an
allowed file, rejected reading an equivalently readable fixture mounted under
`/etc/cyberpanel`, and rejected a transition to `unconfined`. Missing-profile
launch rejection, wrong/complain-generation parsing, rootless Podman inspection
and full runtime capability admission also passed. Tests unloaded only the
profiles they loaded; the container list was empty afterward. Final focused
run: 0.524 seconds. Uncached containers/integrations suites and the panel build
also passed in Ubuntu ARM64 QEMU.

Still pending: signed installer policy publication/loading, boot/reboot and
generation-retirement integration, complete workload/exec/lifecycle checks and
other OS/architecture qualification. The QEMU tests loaded the policy directly;
no installed node release was changed. The old assembled component must be
rebuilt before deployment. These checks do not certify the full sandbox or panel.

### Container privilege-drop group leak fixed — 2026-09-20

While integrating the inherited-confinement path, found that the native
container runner set `NoSetGroups: true` when changing UID/GID. A real root-QEMU
child-process regression confirmed that this preserved the supervisor's root
group: assigned groups 1000 and 1001 produced `1000 0` and `1001 0` respectively.
The runner now clears supplementary groups before changing UID/GID.

The same real-process tests now return only the assigned group in both cases.
Process construction is factored into one private helper used by the native
runner; its public executable allowlist still accepts only Podman/Skopeo, and
a negative regression confirms that the test's `/usr/bin/id` probe was not
added to that allowlist. No new broker operation or arbitrary command entry
point was added.

`TestQEMUContainerRunnerUsesRootlessPodman` also ran the actual installed Podman
through the corrected native runner and verified its rootless result (0.18 s).
The uncached containers/integrations suites and `cmd/cyberpanel` build passed
inside Ubuntu ARM64 QEMU. This proves credential dropping and native startup,
not production MAC policy integration or complete container lifecycle behavior.
The already assembled `panel-component-2c9dfc833.tar.gz` predates this fix and
must be rebuilt before it is promoted as a current release.

### Rootless AppArmor inheritance mechanism verified — 2026-09-20

Checked current upstream containers/common as well as the shipped version:
both still reject named AppArmor profiles from rootless Podman. A runtime
upgrade alone therefore does not remove this limitation.

Tested inherited kernel confinement inside Ubuntu ARM64 QEMU using the already
pinned n8n image. A new diagnostic profile, `qemu-container-inheritance`, was
loaded without modifying any existing profile. `aa-exec` entered it before
launching rootless Podman; the container ran as UID/GID 1000 with no network,
all capabilities dropped, no-new-privileges, read-only root, 256 MiB memory and
64 PIDs. Two read-only fixture files were mounted with equivalent DAC access.
The diagnostic policy allowed one and explicitly denied the other.

The first launch hit a profile D-Bus denial needed by the runtime's cgroup
setup. Kernel audit evidence identified the denied method call; adding D-Bus
permission to this diagnostic profile allowed the same probe to proceed.
The real container then returned:

```text
qemu-container-inheritance (enforce)
cat: can't open '/probe-denied': Permission denied
inherited-denial-passed
```

The allowed file content was checked before the denied read. Thus the denial
was not a missing image/file or failed container startup. The container was
removed by `--rm`, the empty container list was checked, and the diagnostic
profile was unloaded. Only its source and two harmless fixture files remain
in the existing host QEMU run directory and guest harness directory.

This proves a kernel inheritance mechanism, **not** the production sandbox.
The intentionally broad diagnostic profile must not be packaged. Production
work remains: narrowly confine runtime operations, prevent profile escape,
check inherited enforcement rather than trusting a requested profile name,
bind installed policy to the signed release, and verify actual workload/exec
confinement. The existing MAC admission check was not relaxed. Do not replace
it with the kernel-enabled flag or classify this tuple as qualified yet.

### Panel component assembled; rootless container isolation finding — 2026-09-20

Prepared and verified signed ARM64 candidate container recipes using the existing
test authority and the real manifest digests recorded below. n8n 2.39.8 has five
workloads (web, worker, webhook, PostgreSQL 16.15, Redis 7.4.11), three backed-up
volumes, private networking and secret references. Recipe digest:
`abfa08abdaa020fb672b0e79b5f9e6686e9ee488f4dc98341b3b8efa851519ed`.
The owner slot maps to `N8N_INSTANCE_OWNER_PASSWORD_HASH`: enrollment must provide
bcrypt, not plaintext, per the [vendor startup contract](https://raw.githubusercontent.com/n8n-io/n8n-docs/main/docs/deploy/host-n8n/configure-n8n/user-management.md).
The QEMU owner email/name are fixture values, not production account defaults.

Hermes pins image revision `f9524d3f119c672e4a4444f56d582e7475716ba3`, rather
than inventing a product version absent from its metadata. Recipe digest:
`0558fa92fd5d5768fc543541cef8e8da500384cc481b506d93a1f20e6b1f4454`.
Its UID/GID 1000 override and read-only-root startup remain untested. Both
recipes passed the existing signature and integration-contract verifiers;
this is not proof that their containers start or their applications work.

The real assembler now completed successfully:
`/home/harness/panel-component-2c9dfc833.tar.gz`, 355,896,982 bytes, SHA-256
`a1b2bbf50731db717fefea757f7a28a4457c1e575da787ff9b71584993bc215b`.
The resulting gzip integrity check passed. Inspected its complete member list
and actual manifest: five PHP recipes, five archives, the public key, both
container recipes and the panel executable. Catalog content digest:
`2ee04905c3c66b0bfa3256351cdc0aef7603e6834d6fbf7a6ec17b00310bce0c`.
The outer node-release signature/install integration is still pending; this
component is not an installed full panel.

Installed native Podman 4.9.3/Skopeo/uidmap/network helpers inside QEMU (25.3 MB
download, 112 MB installed). Pulled only the pinned n8n ARM64 image into harness's
rootless store and inspected its exact digest/architecture; unpacked size is
1,216,505,242 bytes. No n8n/Hermes containers were started. Guest free space is
now about 2.7 GiB, so the remaining image layers must not all be pulled at once.

The guest kernel has AppArmor enabled with enforced profiles. Rootful Podman
reports AppArmor true; rootless Podman reports false. A bounded `podman create`
probe requesting a named AppArmor profile was rejected before creating the
container. The [shipped containers/common implementation](https://raw.githubusercontent.com/containers/common/v0.57.4/pkg/apparmor/apparmor_linux.go)
explicitly rejects named profiles in rootless mode. This is a real runtime
limitation, not merely a missing kernel switch/profile. The panel's MAC admission
check remains unchanged and correctly prevents claiming this tuple qualified.
Resolving rootless mandatory-access-control enforcement is the next container
integration step; do not replace the requirement with rootful/unconfined execution.

### Complete PHP recipe input set — 2026-09-20

Prepared the four remaining signed version-2 recipes inside Ubuntu ARM64 QEMU
using the existing test authority `qemu-password-pair-20260919`, epoch 1.
The existing WordPress 7.1 envelope remains in
`/home/harness/application-inputs-20260920/wordpress-7.1.recipe.json`.
The new envelopes/public key are in `/home/harness/php-inputs-20260920-v3`:

| Recipe file | Product | Canonical payload SHA-256 |
| --- | --- | --- |
| `joomla.recipe.json` | Joomla 6.1.3 | `081d6fd64e7dcf6e2352c8359a759f216c479f21607fc131edf992161428301e` |
| `mautic.recipe.json` | Mautic 7.2.0 | `5a9eb5475d2ce9c82f93acfa2eb95d24a2e04500a2364a3e213ca459ac992696` |
| `prestashop.recipe.json` | PrestaShop 9.1.5, Classic distribution 9.1.5-5.0 | `e29e330578287fecc77b4fee1deb3ba0c0d02577c28381a92e140d9f2342e54c` |
| `magento_open_source.recipe.json` | Magento 2.4.7-p10, dependency-updated candidate | `3a89a12fa5495246fb4de7d1effb656d2f8e4ea469ea6d92fe8842ae321ed204` |

All four passed the production archive validator, signature verification and
certified-definition contract checks. PHP is narrowed to 8.3; the declared
OS/architecture/engine matrix is not an empirical qualification claim.
Each recipe pins the already-tested rooted archive listed in prior sections.
The new Joomla recipe supersedes both previous envelopes referencing the flat
upstream archive. No private signing material was printed or copied to the host;
the helper wipes its signing bytes after preparation and installs no trust key.

Prepared archives are served by the unprivileged `qemu-php-inputs` fixture at
`https://127.0.0.1:19443/<archive-sha256>.tar.gz`, only inside the guest. Every
response was streamed and digest/size checked with certificate verification
before signing. The exact-path allowlist serves only these four archives.
The TLS certificate is local to the fixture (`fixture-tls.pem`), not a system
trust addition; it expires after 24 hours and the service has a six-hour runtime
cap. These URLs are temporary QEMU release inputs, not published production
download locations. Offline installation consumes catalog bytes, not these URLs.

The full component still requires signed n8n/Hermes recipes and their real image
layers/runtime checks. A complete PHP input set is not a complete panel release.
Built fresh QEMU Linux executables from source `2c9dfc833` with `-trimpath`:
`/home/harness/bin/cyberpanel-2c9dfc833`, SHA-256
`db1a1f9b004f738d7fbfaa146d486632a3348b0411bfe1ec508bfc07eff22800`, and
`/home/harness/bin/application-release-2c9dfc833`, SHA-256
`35d7711e3ecb3622e931ef41fb29342e99e1801efbc6d5cb0fd4520b3d38dc72`.
The actual assembler read `/home/harness/application-release-input.json`,
accepted the five persisted PHP recipes and archive layouts, then stopped at
the absent `oci-inputs-20260920/n8n.recipe.json`. No component was emitted and
assembly success is not claimed. The input JSON retains the real paths/digests
for continuation. Public recipes/certificate/key were also copied to the host's
existing QEMU run directory; the private authority key remains only in the guest.

### Offline WordPress archive path and real OCI metadata — 2026-09-20

Release inspection found WordPress's install path still fetched its archive
with curl despite shipping the same archive in the authenticated offline
catalog. Replaced that duplicate downloader/extractor with the existing pinned
catalog extractor used by the other PHP applications. This requires the
protected catalog, exact digest/size and safe archive layout before extraction;
missing/untrusted inputs cannot fall back to the network. Removed the now-unused
curl field and executable prerequisite from this runtime.

The root-QEMU `TestWordPressInstallRejectsUnpinnedArchiveWithoutNetwork` exercised
the actual `Install` entry point: before the fix it attempted the download
command; after the fix it rejected the missing catalog before commands or
secret retrieval. This is a rejection-path regression, not proof of a complete
offline WordPress lifecycle. Existing language/LSCache plugin operations still
use WP-CLI and are not claimed offline by this change.
The uncached apps suite passed (0.515 seconds), and `cmd/paneld` plus
`cmd/application-release` builds passed in Ubuntu ARM64 QEMU. Other matrix
guests have not yet checked this revision.

Acquired actual registry index, ARM64 manifest and image configuration documents
inside QEMU at `/home/harness/oci-inputs-20260920`. Manifest and configuration
bytes were independently SHA-256 checked against their referenced OCI digests.
No layers were pulled and no containers were started. These are candidate inputs,
not signed application recipes or runtime qualification:

| Official repository / observed tag | ARM64 manifest SHA-256 | Observed version |
| --- | --- | --- |
| `n8nio/n8n:stable` | `24b5c803a1465c524dbe65adb082f00740610d1077d3061063f47a6bb5fe5bba` | 2.39.8 image label |
| `nousresearch/hermes-agent:latest` | `551f53c828267bb7a1c3925338df065114e680a1871eca030a11fc31eb33771f` | revision `f9524d3f119c672e4a4444f56d582e7475716ba3`; no version label |
| `library/postgres:16-alpine` | `2c942175a1255a9abe0366e48c1b401d9f50f835b04dfea13f111609b5530df7` | 16.15 environment metadata |
| `library/redis:7-alpine` | `1f09a89a207d794a8c61d9edfc26e7c58427de10ccef7c5d18d638df79a63b85` | 7.4.11 environment metadata |

Hermes defaults to image user root; the panel's required unprivileged execution
must be tested explicitly, not inferred from metadata. The guest has about
5.1 GiB free: pulling/extracting all images together would risk its headroom.

### Magento supported runtime selection and signed search input — 2026-09-20

Corrected the previous preparation checkpoint: Composer accepts Magento 2.4.9
on PHP 8.3, but the [vendor matrix](https://experienceleague.adobe.com/en/docs/commerce-operations/installation-guide/system-requirements)
does not support that combination. The existing PHP 8.3/MariaDB 10.11 guest uses
2.4.7-p10, which supports those versions and OpenSearch 3. The 2.4.9 candidate
remains unqualified; no shared PHP/database stack was upgraded to accommodate it.

Downloaded Magento 2.4.7-p10 inside QEMU, source SHA-256
`13440995a41fd82ae3f0e95749905438fe972b9931a7c5a7d7b0e992c47a9d8d`.
Composer 2.10.3 passed its published SHA-256 check. Preserved the upstream lock
at `/home/harness/magento-2.4.7-p10-upstream.lock`, SHA-256
`799cfe23a0a6035fbb43313985327d7155c6922a667b544bc07b975e01ce62eb`.
That lock also contained security advisories. Updated within unchanged upstream
constraints without bypassing audit checks. The candidate lock SHA-256 is
`74ffe442a924640e572b7dbe4575806ef66961afda9e2d5f35503d9b8e1ea78b`;
its advisory list is empty, but ten abandoned production Laminas packages remain.
Platform requirements and Magento CLI version checks passed. This is a
dependency-updated candidate, not an unchanged upstream distribution.

Downloaded OpenSearch 3.8.0 ARM64 (801,461,518 bytes) inside QEMU. The detached
signature validates under the [official release key](https://opensearch.org/verify-signatures/)
`A8B2D9E04CD51FEF6AA2DB53BA81D99981191457` in an isolated keyring.
Archive SHA-256: `1ed8b6e9e3be799fe08688ea73791cc03d98269d6831646df2905f42c318e05e`.
A temporary unprivileged service answers its real loopback HTTP endpoint with
version 3.8.0. It has a 512 MiB heap, 1,400 MiB memory ceiling and 30-minute
runtime limit. Authentication is disabled only for this guest-loopback fixture;
this is not production search configuration or a production qualification.

Prepared Magento archive `/home/harness/magento-2.4.7-p10-rooted.tar.gz`, SHA-256
`a08e75ea5b7c0534194328106ee46d4d2dbdbd83ec1e333594d670a99cfa69fd`, uses
one root and explicit preparation timestamp `2026-09-20T03:00:00Z`.
The extension contract now checks both actual Magento source manifests in QEMU;
both passed. `TestQEMURealMagentoInstallation` passed in 13.08 seconds with
native PHP 8.3, MariaDB and real OpenSearch. It uses the production protected
argument bootstrap, checks generated `app/etc/env.php`, consumed argument input
and the active administrator database record, then removes its isolated
database/principal/files. The temporary search service was stopped afterward.
The search journal confirms creation of Magento's product index. Shutdown logged
`stopped` and `closed`; systemd reports exit 143 from the requested SIGTERM, not
an installation failure. No listener remains on 9200. Cleanup queries found no
fixture database/user/tree, and the uncached apps suite passed (0.420 seconds).
This does not certify installed LSPHP/OLS, broker/control API, browser or full
application lifecycle integration; signed recipe/release integration remains.

### Magento source and dependency preparation — 2026-09-20

Fetched [Magento Open Source 2.4.9](https://github.com/magento/magento2/releases/tag/2.4.9)
inside Ubuntu ARM64 QEMU. The annotated tag is
`614a428f70fcef830b02d37f633fedf273eeb667`, targeting commit
`755e34dd689021c5165db9d35ecff74f7dc51527`; GitHub reports the tag unsigned.
Source tar SHA-256: `004020ded235e108f752b93193fb713461eb32e39ae3411681f1a9fe429aa9ad`.
Guest source: `/home/harness/magento-2.4.9-release-source`.
Native Composer/bcmath/soap packages required 1,042 kB; Composer installed 148
production dependencies as the unprivileged harness user without private
repository credentials. These are application dependencies, not OS images or
Go toolchains.

The actual upstream Composer requirements exposed missing FTP, Hash and Iconv
extensions in our Magento contract. Added them and verified the contract against
the real source manifest in QEMU; the focused checks, uncached apps suite and
core/application-release builds passed.

The upstream lock was stale and reported 42 security advisories in 14 packages.
Preserved it at `/home/harness/magento-2.4.9-upstream.lock`, SHA-256
`700cb5371fb0e7f1c5c962b0cf14c21789b8deaec5043b2e38c2c5a9803a79b7`.
Updated dependencies within the unchanged upstream Composer constraints. The
candidate lock SHA-256 is
`5ce48925faebf8bb1236f00e25d17df25ea920083c07bf2c97192298e49d66d6`.
The new audit has an empty advisory list, but exits 4 with four abandoned
packages: laminas-config, laminas-json, laminas-loader and laminas-text.
No audit bypass was enabled, and a clean audit is not claimed.

`composer check-platform-reqs --no-dev`, `bin/magento --version` (2.4.9), and
`setup:install --help` passed. The real CLI exposes the existing adapter's
OpenSearch options. This is a dependency-updated test candidate, not an unchanged
upstream distribution or a certified install; actual search-backed installation,
application lifecycle checks, prepared artifact/recipe and release integration
remain outstanding. Composer logs remain in `/home/harness/magento-2.4.9-*.log`.

### PrestaShop real install and prepared Joomla archive — 2026-09-20

Downloaded the [official PrestaShop Classic 9.1.5-5.0 distribution](https://github.com/PrestaShopCorp/prestashop-classic/releases/tag/9.1.5-5.0)
inside Ubuntu ARM64 QEMU: 121,756,566 bytes, SHA-256
`37140cb77c03acf61b832f76893cd8fe1e304b0fc14fa5485cfea4a7bfaf3a72`, matching
the published GitHub asset digest. Its nested `prestashop.zip` contains the
installable product. `--help` is not a help-only switch in this installer; that
initial probe attempted its default database connection and failed without access.
A fresh extraction was used for packaging, not that probe's modified directory.

The first real install failed because our prepared tar used epoch-zero mtimes.
PrestaShop's `ModuleRepository` requires positive mtimes and rejected all bundled
modules. Rebuilt from pristine input using the official release timestamp
`2026-08-18T09:10:33Z`. The corrected guest artifact
`/home/harness/prestashop-9.1.5-rooted-v2.tar.gz` is 110,050,448 bytes, SHA-256
`ae05affbdcc14d131c678325c664b7bd8f6c136fa6b6dcc0c517910daad10a14`.
The earlier `prestashop-9.1.5-rooted.tar.gz` must not be packaged.

`TestQEMURealPrestaShopInstallation` passed in 40.57 seconds with bundled modules
enabled, native PHP 8.3, MariaDB, and the production argument-bootstrap code.
It checks the prepared digest, generated configuration and administrator record,
then removes the isolated database/principal/files. No module bypass or upstream
code patch was used. The uncached apps suite also passed. This does not certify
the installed panel, LSPHP/OLS/LSE path, browser login or later app lifecycles.

Joomla's prepared single-root archive now passes production archive validation:
guest `/home/harness/joomla-6.1.3-rooted.tar.gz`, 28,938,128 bytes, SHA-256
`af8baac671deb19649f38236f53428d501b69e39e39ac5e23f3010c9623b6320`.
Prepared artifacts still need matching signed recipes and actual release URLs.
Magento and container recipe/image inputs remain outstanding. No OS image or
Go toolchain was downloaded.

### Real Joomla and Mautic installations — 2026-09-20

Ubuntu ARM64 QEMU now passes actual Joomla 6.1.3 and Mautic 7.2.0 installations
against MariaDB using native PHP 8.3 and the production
`certifiedApplicationArgumentBootstrap`. Each opt-in check verifies its archive
digest, extracts into a fresh unprivileged fixture, creates a random isolated
database/principal, passes secrets through the protected argument file rather
than process arguments, runs the real installer and checks its generated
configuration plus the administrator database row. The argument file is consumed.
Temporary files, test databases and principals are removed even on failure.

The first Mautic attempt failed because the test inherited root's `TMPDIR` while
running PHP as the unprivileged harness user. Corrected the fixture environment
and cleared supplementary groups; this was a harness error, not a product fix.
Both live installs then passed, followed by the full uncached apps suite with
both live flags enabled (8.922 seconds). Guest native PHP curl/gd/intl/mbstring/zip
dependencies required an 810 kB download; no OS image or toolchain was fetched.

Flags: `CYBERPANEL_QEMU_INSTALL_JOOMLA=1` and
`CYBERPANEL_QEMU_INSTALL_MAUTIC=1`, run as QEMU root with the existing protected
fixtures. This proves the upstream installer and argument-bootstrap boundary,
not LSPHP/OLS/LSE execution, secret-broker leasing, HTTP login, full panel
installation, application updates or backup/restore. Those gates remain open.

### Real archive admission and Mautic input — 2026-09-20

The actual WordPress archive failed the production pinned-archive validator:
standard directory headers such as `wordpress/` were rejected as noncanonical,
and a top-level directory header was rejected for having no child segment.
Corrected directory-only trailing-slash handling and permitted the single root
directory. QEMU regression tests now accept the real WordPress archive and
reject traversal, absolute paths, repeated separators and mixed roots. The
uncached apps suite and core/application-release builds passed in QEMU.

Downloaded the [official Mautic 7.2.0 full ZIP](https://github.com/mautic/mautic/releases/tag/7.2.0)
inside QEMU: 105,174,048 bytes, SHA-256
`520a4aede649144839e8512d8d046d25dc977d7be5288ab841eecb3ac9378deb`, matching
GitHub's published asset digest. Installed native `unzip` (171 kB download).
The real PHP 8.3 `bin/console mautic:install --help` succeeded and exposed the
adapter's existing install options. No Mautic install or browser workflow is
claimed.

Prepared an offline single-root tar from a fresh extraction, with sorted paths,
zero timestamps and numeric root ownership. Guest
`/home/harness/mautic-7.2.0-rooted.tar.gz` is 89,809,522 bytes, SHA-256
`a4be4794815496fa3ce15ea4b79474b98296d209bb5ce3d32d2f7a819d6134db`; it passes
the real production archive validator. The earlier flat
`mautic-7.2.0-prepared.tar.gz` is not a packageable input. A signed recipe for the
prepared bytes and their release URL remains required; the ZIP URL must not be
misrepresented as serving the prepared tar. Likewise, the earlier Joomla recipe
authenticates the original flat archive but that archive still needs single-root
preparation and a corresponding new recipe before installation. No OS images,
toolchains, host trust changes or dummy product archives were introduced.

### Real Joomla input and missing XML prerequisite — 2026-09-20

Downloaded the [official Joomla 6.1.3 full tar package](https://downloads.joomla.org/cms/joomla6/6-1-3)
inside Ubuntu ARM64 QEMU, 29,126,534 bytes. Its SHA-1 matches the publisher's
`a82d1de02f1b826eacd3d990888f9f75bd49c707`; recorded SHA-256 is
`184f8c582cde5981693de7c28547c6e834c48c50cb377c7b8421bbfd33bbdf6f`.
SHA-1 is recorded as a publisher checksum, not claimed as a strong signature.
The archive remains `/home/harness/joomla-6.1.3.tar.gz`.

Running the real `installation/joomla.php` on PHP 8.3 failed with undefined
`simplexml_load_file`. Added `simplexml` to the Joomla contract so recipe/runtime
prerequisites explicitly include it. Installed the guest's native `php8.3-xml`
package (123 kB download); the real installer then started and its help confirmed
all options currently emitted by our Joomla bootstrap adapter. The opt-in QEMU
CLI check and contract regression passed, as did the uncached apps suite; the
application-release command compiled. This is not a Joomla installation or
OLS/LSE runtime certification.

Re-signed and verified the corrected recipe using the existing QEMU-only key:
`7da747609e4c3d95ecd6a3b1fe7ebdd43df51997e9564658b8c327fe39f0c6be`, in guest
`/home/harness/joomla-inputs-20260920-v2/`. The initial recipe in
`joomla-inputs-20260920/` is superseded and must not be packaged. No private key
was printed or host trust added. No OS image or Go toolchain download occurred.

### Real WordPress release input — 2026-09-20

Prepared a version-2 WordPress 7.1 recipe from the existing QEMU archive
`/home/harness/wordpress-7.1.tar.gz`, after checking its actual 35,356,041 bytes
and SHA-256 `05a5f89138f632b7329f1202f2a0553c5f7fe4daf8e4b9ca7ebae9b9466b9e86`.
The existing QEMU-only signing key signed the canonical payload; the production
`VerifySignedRecipeDocument` verifier accepted the resulting envelope, digest
`30f4a5cda438cf1531ea526f281822e30280091d0a5ab6c6f810345de5543760`.
Inputs are in guest `/home/harness/application-inputs-20260920/`; the preparation
program is retained in the host QEMU run directory. No private key was printed,
no host trust was installed, and no additional download ran. The recipe selects
PHP 8.3; the declared platform/engine matrix is not evidence of certification.
This is one real input, not a complete catalog: the other four PHP artifacts and
their recipes, n8n/Hermes recipes and OCI inputs, and full runtime provisioning
remain unfinished. Existing archive contents were not replaced by dummy files.

### Signed UI assets and gateway loading — 2026-09-20

Added a constrained `release_asset` kind for immutable UI/catalog files (root:
root, mode 0444), retaining per-file signature-bound hashes and the existing
generation activation/rollback path. Destination/mode rejection tests passed
inside Ubuntu ARM64 QEMU. Signed fixture sequence 14, `qemu-ui-assets-3.1.13`,
installed the existing four daemons plus all four files from the already-built
UI. Manifest `355620ec6358c34c3f52423ffa665e2f478da6ca2919b7ff2ac201259758e3da`,
bundle `ffe8ac0606b13e9ab3f788af3efc2ade270e494182d27e773f7ce430b241c2d6`,
receipt `2138c681b5adb241a5f838bf09c4d96b222d1bf38fd054f65c4b42c857cd28f9`.
All installed asset bytes matched their source files, modes/owners matched, and
reconcile returned no pending operations. All four daemons remained active.

The actual gateway static loader initially rejected these managed file symlinks.
Its new entry point pins the UI through the protected managed index to one
immutable generation, then uses the unchanged symlink-rejecting loader.
`TestQEMUInstalledUIAssets` reproduced the failure before the fix and passed
afterward, loading the signed installed tree and checking real loopback HTTP
responses against the installed index/CSS/JavaScript bytes. Uncached paneld and
node-release suites and `go build ./cmd/...` passed offline in QEMU. This is
asset delivery evidence, not a rendered-browser or installed gateway/core claim.
Full core startup still requires the real signed application recipes/catalog,
their already-trusted keys, and bootstrap state; those have not been fabricated
or bypassed. No OS/toolchain/image downloads occurred.

### Peer inspector product-installer integration — 2026-09-20

The closed product catalog now requires the inspector executable in the existing
executor artifact, its root-owned systemd unit, and its required service. Slot
activation starts it before the secret broker; uninstall and failed fresh-install
cleanup stop it. No additional artifact category or broker capability was added.
Ubuntu ARM64 QEMU passed the installer mapping and missing-helper rejection tests,
uncached installer/secrets/node-release suites, and `go build ./cmd/...` with
`GOPROXY=off`. Both installed helper and broker remained active. These checks do
not claim a complete product-catalog fresh install: the installed signed fixture
still contains the four previously recorded daemons rather than the full panel.

### Approved privileged peer inspector — 2026-09-20

The user approved the separate inspection helper while keeping the broker on its
dedicated account. `panel-peer-inspectd` accepts exactly one connected AF_UNIX
stream descriptor through SCM_RIGHTS from the broker UID. It does not accept a
PID, pathname or executable command. Kernel socket credentials select the peer;
process-start and effective-UID checks bracket executable inspection. Executable
hashing checks the current executable inode, size and modification time after
reading. The broker uses the original connection again at grant and delivery,
preserving process/executable/release-audience binding rather than caching an
inspection as authorization.

The helper service runs as root with only `CAP_SYS_PTRACE`, a read-only system,
and inaccessible secret/auth/control stores. The broker remains
`cyberpanel-secrets`, `NoNewPrivileges=yes`, with an empty capability set.
Descriptor tests reject missing/multiple descriptors, regular files and callers
outside the configured broker UID. A real UID-65534 socket process was inspected
successfully in QEMU.

Signed fixture sequence 12 installed the helper but the first end-to-end check
found grant verification still using the old registry. Sequence 13 corrected
that wiring through a normal signed upgrade; no frontier or journal was edited.
Installed sequence 13 (`qemu-inspector-3.1.12`) then passed actual material
delivery for root and unprivileged `cyberpanel` test consumers and rejected
mismatched executable digests. Fixture secrets were revoked on test exit. These
tests pin disposable test executables, not production provider identities.

- Manifest: `5f499b2e9eca772b905237ae8ec6589d8592bf11d252620d1e45380c4deebb16`.
- Bundle: `cf673855b8ecadc613157a4b58eb59ff07c21e4dbc9c04c200d8b744c790b7c2`.
- Helper and broker were active/running with zero restarts after installation.
- Secret and signed-packaging suites passed in Ubuntu ARM64 QEMU.
- The full uncached Go suite also passed; retained log:
  `current-ubuntu-arm64-20260919-smoke/inspector-integrated-20260920.log`.

No new signing authority, base-image download or broker capability was added.
This closes the observed cross-user inspection blocker; it is not full panel
installation. Complete product installer/catalog integration, production
consumer journeys, and other-platform qualification remain.

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

### Clone access-policy admission consistency

The SQLite success-path fixture exposed that `CloneRequest.Validate` accepted
policy IDs later rejected by `StagingRelation.Validate`. A QEMU regression
reproduced five such mismatches. Clone admission now uses the existing shared
policy-ID validator, rejecting malformed IDs before operation admission,
snapshot creation or database provisioning. The valid scoped policy remains
accepted. The fresh apps suite and core/execd builds passed in Ubuntu ARM64 QEMU;
no installed HTTP or other-architecture rerun is implied by this focused fix.

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
# Export coordinator, API and console UI — 2026-09-20

Implemented coordinator preparation from authorized workspace metadata, sealed
job construction, actor-bound execution and freshly authorized downloads. Added
MFA/database:console, site-scoped export_prepare/export/export_download API
contracts; only export is mutating. Access coordinates and actor are derived
server-side, not accepted as WorkspaceAccess payloads. Preparation returns the
complete job so execution retries keep the same specification/timestamps.
Console UI supports SQL/gzip downloads, bounded reads, progress/error states,
chunk and assembled SHA256 validation before save, abort on close and Blob URL
cleanup. It explicitly excludes routines/triggers/events for now.

QEMU Ubuntu ARM64 verification:
- Go: `CYBERPANEL_QEMU_LIVE_TRANSFER=1` with root `TMPDIR=/root`, cached/offline Go,
  `go test -p 2 ./internal/database ./internal/apiserver ./cmd/cyberpanel
  ./cmd/panel-execd -count=1` passed. Native round trip now includes coordinator
  preparation/actor checks/execution/download, real broker and MariaDB. Its domain
  repository reads the protected fixture resources; domain SQL persistence and
  production secret delivery remain separate qualifications.
- Real Core.Handler HTTP preparation endpoint: 200 with correct server-derived
  actor/site/tenant/generation; malformed compression, unknown access/tenant
  payload fields and missing generation give 400; anonymous 401 and authorization
  denial 403. Identity/signature verifier and domain execution are explicit
  fixtures. The other two API contracts' binding/auth/mutation policy is checked;
  installed HTTP export/download have not yet been exercised.
- Guest `npm run typecheck` and `npm run build` passed. Vite reports a 537.99kB
  JavaScript chunk warning, not a build failure.
- Real guest Chromium, candidate compiled UI: both SQL/gzip downloads contain
  expected fixture bytes and filenames; incorrect full-artifact digest produces
  an alert and no download; 390px layout passes. The three export API responses
  are MOCKED, explicitly logged as such. Existing password/passkey login, console
  issue/metadata/query and mutation-denial/recovery calls remain real installed51
  traffic. Harness: ignored `.work/qemu/qemu-passkey.cjs --console-fresh
  --candidate-ui --export-ui-fixture`; no new native resources or packages.

No installed-release claim: signed51 is unchanged. Next required proof is the
connected installed UI/API/native-export flow. Ordinary workspace caps remain
1MiB/30s/1000 estimated rows; native row receipts currently use preview estimates.
Large async transfers, production import, retention collection, full object
parity and the full matrix remain unfinished. No host testing/downloads occurred.

# Authorized export downloads through the broker — 2026-09-20

Added typed `workspace_export_read` client/server/executor support. Each read
reauthorizes current protected session/database/principal/instance state and
acquires a bounded session slot. It accepts only the exact job-bound artifact
descriptor and an in-range offset with 1..256KiB length, seeks the immutable
artifact, and returns exact data length, EOF and a chunk digest. It does not issue
credentials, initialize missing storage or journal download bytes. Consumers
must verify the full assembled artifact digest, not just individual chunks.
Export credential resolution shares the same protected-resource authorization.

QEMU Ubuntu ARM64 actual private Unix broker tests download the plain SQL and
gzip artifacts in 97-byte chunks and match assembled size/SHA256 against the
export receipt. Explicit EOF reads, out-of-range/oversized requests, mismatched
artifact digest, expiry and session revocation are checked. The SQLite admission
store contains zero workspace_export_read rows after download. Existing broker
export/replay, native import and scoped-account denial checks continue to pass.
Peer authentication, export secret delivery and root import credentials retain
the fixture limitations recorded below; production API/UI is not yet connected.

Guest gofmt plus `sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root
GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off
GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/database
./cmd/cyberpanel ./cmd/panel-execd -count=1` passed all three packages, exit 0.
All fixtures clean up. No host tests, downloads, native dependency changes or
deployment. Core/API/UI, large async transfers, production import and retention
collection remain pending; full functional parity is not claimed.

# Native export through the executor broker — 2026-09-20

Added a closed `workspace_export` broker operation, typed client and Linux
executor implementation. It uses the prior session-bound credential provider,
not a root dump account. Job-derived artifact identities prohibit caller-chosen
storage destinations; frames reject mixed operation payloads and receipts must
match the exact destination, format, compression, byte/row counts and retention.
The reboot admission journal records the effect and replays the original result.
The executor can reauthorize and recover an existing immutable artifact without
dumping again; its reconstructed receipt records recovery completion time, while
journal replay preserves the original receipt. New exports check free disk space
for the requested maximum plus 2GiB; this is a preflight, not aggregate quota
reservation. Transfer limit/cancellation/stale errors cross the closed broker
error mapping without exposing subprocess output or credentials.

The QEMU live round-trip test now starts an actual private Unix socket and calls
the real framed client/server, backed by a real SQLite reboot-admission store.
It exports plain and gzip SQL with the scoped native database account, verifies
exact broker receipt replay and executor artifact recovery, then imports through
native MariaDB and checks NULL/binary/text row contents. Negative checks reject
mixed payloads, mismatched receipt artifacts and caller-selected destinations.
Socket peer authorization and secret delivery are explicit fixtures; production
peer-auth integration is not claimed. Import still uses a root test fixture.

QEMU Ubuntu ARM64 only: guest gofmt on new files/test; then
`sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root
GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off
GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/database
./cmd/cyberpanel ./cmd/panel-execd -count=1` passed all three packages, exit 0.
Fixture accounts, databases, state resources, sockets, journal DBs, credentials
and exact job-owned artifact directories are removed by test cleanup. Installed
signed51 and vendor packages are unchanged; no downloads or host tests occurred.

Pending: authorized download delivery, user-facing API/UI, large asynchronous
jobs beyond workspace session bounds, isolated-import authorization/promotion,
retention collection and broader target qualification. This is source-level
broker integration, not a deployed or complete import/export feature.

# Session-bound native export credentials — 2026-09-20

Added `LinuxWorkspaceExportConfigs` for the existing native transfer backend.
It loads root-protected session/database/principal/instance resources, matches
tenant/site/database/name and generations, rejects non-ready/disabled/expired
access, respects session resource and connection limits, and resolves only the
session's credential via the existing purpose-bound secret source. Credentials
stay in transient root0600 client configs, never argv or environment; release
removes their private directory and returns the session slot. Backend subprocess
contexts now honor the optional credential expiry, bounded by job duration.
This provider authorizes local export only: import requires separate isolated
target authority, and remote-instance transport remains to be integrated.

The live plain/gzip SQL round-trip test now exports through this actual provider
using a native database-scoped SELECT/SHOW VIEW account. Only secret delivery
is an in-memory fixture. Native mysql.user reads and source CREATE TABLE are
denied. Different database names, tenant mismatch, stale database/principal
generations, expired sessions, disabled principals, oversized requests and a
second concurrent connection are rejected; credential file deletion and release
replay are checked. Import still explicitly uses a root client fixture.

QEMU Ubuntu ARM64 only: guest gofmt, then
`sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root
GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off
GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/database
./cmd/cyberpanel ./cmd/panel-execd -count=1` passed all three packages (exit 0).
Temporary native users, protected fixture resources, databases and credentials
are cleaned. No downloads, native package changes, host tests or installed-panel
updates occurred. Transfer-service/broker/API/UI wiring is still pending; no
complete or deployed import/export claim is made.

# Database transfer artifact storage and native round trip — 2026-09-20

Implemented `LinuxTransferArtifactStore`: root-private ancestry and files,
bounded streaming writes, streamed SHA256/byte-count verification, fsynced atomic
publication, immutable generations, idempotent commit, abort cleanup, strict
bounded descriptor parsing, expiry and persisted retention/legal-hold metadata.
No tenant authorization is claimed by this storage layer; only the authorized
executor may supply identities. Transfer API/executor/catalog wiring is pending.

Verification ran only in the existing Ubuntu ARM64 QEMU guest. Guest gofmt ran on
the three added files; formatted source was copied back to the worktree.
`sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root
GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off
GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/database -count=1`
exited 0. Focused verbose checks also passed before the final added metadata and
directory validation cases. Storage tests cover publication/reopen/replay,
competing writers, write caps, abort cleanup, wrong digests/generations, expiry,
symlinks/hardlinks, file/directory permissions, mismatched payload size and
oversized metadata.

`TestQEMUTransferNativeRoundTrip` invokes actual native `/usr/bin/mariadb-dump`
and `/usr/bin/mariadb`, exports schema/data through the real artifact store and
imports into a separate fixture database. Plain SQL and gzip both preserve the
expected two rows, NULL fields and binary bytes `0001FF`. Its root socket client
configuration is explicitly a fixture, not production transfer authorization.
Deferred cleanup removes fixture databases, client configs and artifact storage.
No vendor installation, rebuild, pin, download or installed-panel change occurred.
Disk before verification: host 223 GiB available, guest 3.1 GiB available.

Remaining: production least-privilege configs, catalog/isolated promotion,
job/executor/API/UI integration, uploaded SQL handling and retention collection;
views/triggers/routines and the other distribution/architecture targets are not
qualified by this table round trip. Installed signed51 remains the last deployed
panel. Full database import/export parity is not complete.

# Installed CRS evidence without a custom package — 2026-09-20

Removed the custom CRS .deb builder. The operations executor no longer requires
`/usr/share/doc/cyberpanel-waf-crs/runtime.sha256`: it records a deterministic,
bounded inventory of the installed `/usr/share/modsecurity-crs` tree. This is
evidence of installed bytes, not a hard version pin. Regular/root-owned assets,
non-writable ancestors, no symlinks/hardlinks, and a nonempty trusted entrypoint
are still required. Root-owned package updates are accepted with new evidence.

Verification ran only in the existing Ubuntu ARM64 QEMU guest, as root with
`TMPDIR=/root`, cached Go dependencies, `GOPROXY=off`, `GOTOOLCHAIN=local`:
`go test -p 2 ./internal/operations -run 'Test(WAFBaseline|InstalledWAF|InitialWAF|QEMUInitialWAF)' -count=1 -v`
with `CYBERPANEL_QEMU_WAF=1` passed, including inspection of actual installed assets.
Fixtures prove no custom manifest is needed, updates/additions change evidence,
and unsafe files/directories, empty/missing entrypoints, symlinks and hardlinks
are rejected. No vendor builds/downloads or live policy changes occurred.
The full `go test -p 2 ./internal/operations ./cmd/cyberpanel -count=1` also
passed in that guest (both packages exit 0).

Limits: this is a source change, not a deployed release. Existing guest CRS is
still the old custom package. The Unicode mapping path remains version-specific;
normal vendor/distribution rules layouts and package replacement remain pending.
The deleted recipe is recoverable from Git history; live installed assets remain.
# Database import broker integration — 2026-09-21

Added closed core-to-executor allocate/load/verify/promote/discard operations
using the existing authenticated database broker. No SQL commands, filesystem
paths, executable names or credentials are accepted in the command. An import
must reference the full sealed source export, whose derived artifact identity
binds its tenant/site; the stored descriptor is checked before native allocation
and loading. This currently admits same-site panel exports, not arbitrary
uploads. Core-side user authorization and UI integration are still pending.

Native successful stream receipts are persisted in protected isolated-import
records. Broker verification/promotion reject records without that proof.
Load replay returns the persisted receipt without issuing another loader;
promotion/discard also replay through the existing execution journal.

QEMU-only verification, existing Ubuntu ARM64 guest, real MariaDB and Unix
socket broker with real SQLite execution journal (peer authorizer and secret
delivery remain test fixtures):

`sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/database ./cmd/panel-execd ./cmd/cyberpanel ./internal/apiserver -count=1`

All four packages passed. Native SQL and gzip cases prove allocation, verified
load, exact load replay through both broker and executor, verification,
promotion into an empty native destination, native row/text/BLOB contents,
generation advancement, promotion replay, discarded schema/record removal,
and no unsettled import execution-journal entries. Existing-data refusal and
preservation remain exercised against the native promotion function. Forged
source tenant/site/job bindings, modified stored descriptor claims, mixed
operation payloads and mismatched response payloads are rejected.

The initial protocol test used an invalid request ID; corrected to the existing
closed request-ID format. The next run exposed verification being journaled as
a mutation: premature verification left an ambiguous entry which blocked a
later valid verification. Verification now remains a fresh read-only native
observation; its proof persistence does not change native data. Promotion still
revalidates under writer admission. The same premature-verify → successful-load
→ successful-verify regression now passes without an unsettled journal entry.

Not yet installed or user-facing. Existing installed55 is unchanged. Pending:
transfer-service/catalog wiring, core projection after promotion, uploads/API/UI,
replacement/restore points, crash/journal recovery, long-running jobs beyond the
two-minute broker invocation limit, broader SQL objects and OS/architecture
qualification. No vendor builds, pins, patches, downloads or new workers.

QEMU `go build -p 2 ./cmd/cyberpanel ./cmd/panel-execd ./cmd/paneld` also passed
with the same offline environment and root identity as the native tests. An
initial unprivileged invocation could not read root-owned cache entries; no
source change or permission broadening was needed. SHA256 values for all five
changed Go source/test files match between the worktree and the guest. Guest
free space is 3.4 GiB; host 222 GiB. Git objects remain approximately 494 MiB.
# Database import core-state projection — 2026-09-21

Added Coordinator.PromoteDatabaseTransfer and SQLRepository promotion receipt
storage. The coordinator checks current database ownership/site/instance and
generation, calls the existing broker, validates its native proof, then advances
the control.db resource generation/status/proof together with the job-bound
receipt in one transaction. Existing names, quotas and unrelated specifications
are retained. Conflicting receipts and generation jumps are rejected. A failed
projection returns the verified native receipt plus ErrAmbiguous for explicit
recovery, never success.

Extended the existing real MariaDB SQL/gzip QEMU test to use the production
coordinator, broker and real SQLite repository. An injected SQLite trigger
fails receipt insertion AFTER the resource update. The test confirms that
neither the generation update nor receipt survives, retries with the original
durable native proof, checks generation 2/healthy status/matching proof, reopens
SQLite and proves replay does not invoke the executor. Both native data and
exact promotion receipts still match. This is specific failure-window evidence,
not a claim of complete process/power-loss recovery.

QEMU only, existing Ubuntu ARM64 guest:

`sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/database ./cmd/cyberpanel ./cmd/panel-execd ./internal/apiserver -count=1`

All four passed. `go build -p 2 ./cmd/cyberpanel ./cmd/panel-execd ./cmd/paneld`
also passed with the same root/offline environment. Changed source SHA256s match
between host and guest. Guest free space: 3.3 GiB. No downloads, extra guests,
vendor component changes or binary artifacts committed. Installed55 unchanged.
Transfer-service/catalog/authorization, upload/API/UI, replacement and general
crash recovery remain unfinished; this is not installed import qualification.
# Transfer service promotion ambiguity — 2026-09-21

Fixed TransferService.Run's promotion-error branch: SourcePreserved means the
previous data was preserved, not that no promotion occurred. ErrAmbiguous or a
reported promotion now prevents isolated cleanup and persists an ambiguous,
non-restartable receipt with native verification/promotion digests. Definite
pre-promotion failure still permits cleanup.

`TestTransferServicePreservesUncertainPromotion` runs real SQLite job creation,
lease claiming, streaming/verification/promotion checkpoints, terminal receipt
persistence and rejected re-claim. Native effects and authorization/audit are
fixtures here; this test makes no native or UI claim. Before the fix, three
cases reproduced `status=failed discard=1` instead of ambiguous/no-discard.
Afterward all six cases passed: successful-native/failed-projection, explicit
ambiguity despite source preservation, promotion reported alongside an error,
unproven source preservation, definite pre-promotion conflict, and success.

QEMU-only verification in the existing Ubuntu ARM64 guest:

`sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/database ./cmd/cyberpanel ./cmd/panel-execd ./internal/apiserver -count=1`

All four packages passed, including the existing native SQL/gzip broker and
core-projection round trips. Core command build passed with the same offline
QEMU environment; the temporary `/home/harness/platform/cyberpanel` binary was
removed immediately afterward. Both changed Go files have matching host/guest
SHA256 values. Installed55 remains unchanged. Production service wiring,
transfer-job recovery, uploads/API/UI and broader parity remain incomplete.
# TransferService native import execution — 2026-09-21

Added BrokerImportExecution, a job-bound implementation of the existing transfer
catalog/backend. It loads tenant/site-owned core state, obtains a fresh native
destination preview, allocates/loads/verifies/discards through the broker and
promotes through the coordinator's atomic core projection. The import adapter
requires the source export embedded in the immutable job document, so execution
can be reconstructed from a persisted job. Generic uploaded-source jobs remain
representable but are not accepted by this export-backed adapter. No new native
transport or vendor component was introduced.

Added a closed, read-only import-preview broker action. Native table counts,
row counts and allocation metadata describe the destination. Fail-mode rejects
nonempty destinations before job admission and native promotion rechecks them.
Fixed Create's preview comparison to accept a fresh capture timestamp with
identical sealed contents; changed contents, stale/future captures still deny.

Extended existing QEMU native SQL/gzip round trips through TransferService
Create/Run/Inspect/InspectReceipt with real SQLite jobs, broker, native MariaDB,
scoped loader cleanup and core-state projection. Verified authorization denial
at the injected policy seam, nonempty destination preservation, create replay,
source binding reconstruction from persisted job JSON, exact text/NULL/BLOB
data, completed receipts after generation advance and refusal to rerun a
completed import. Missing, nested and altered source-export bindings deny.
Authorization/audit and broker peer policy remain fixtures, not HTTP proof.

QEMU-only command, existing Ubuntu ARM64 guest:

`sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/database ./cmd/cyberpanel ./cmd/panel-execd ./internal/apiserver -count=1`

All four passed. Three production command builds passed in QEMU using the same
offline/root environment: `go build -p 2 ./cmd/cyberpanel ./cmd/panel-execd ./cmd/paneld`.
All nine changed Go files match host/guest SHA256. Guest free space3.0GiB.
No downloads, vendor changes, new workers or committed binaries. Installed55
unchanged. Remaining includes real edge authorization, HTTP/UI/upload wiring,
streaming cancellation/long-job lease handling, replacement and general recovery.
# Database import API and runtime assembly — 2026-09-21

Added prepare/run/inspect API contracts requiring database:manage, MFA and site
scope. Runtime assembly constructs DatabaseTransferOperations using the actual
identity service, active-site store, control.db repositories, coordinator and
audit writer. Transfer authorization rechecks the invocation ActorContext and
owned site/database rather than trusting actor/tenant fields in payloads. Audit
events carry bound actor, database/site/job identifiers, outcome and proof
digests, not dump bytes or credentials.

Preparation derives actor, site, database instance, bounded limits and job
identity; the native destination preview still rejects nonempty databases.
Run admits immutable jobs and uses the joined service/native pipeline. Existing
nonqueued jobs are inspected, never silently rerun. This initial synchronous
surface accepts same-site panel exports with fail-if-not-empty policy and
64MiB/1Mrow/90s limits. Uploads, replacement and larger asynchronous jobs are
still required for parity, not excluded from the goal.

QEMU-only evidence, existing Ubuntu ARM64 guest:

`sudo env CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/database ./internal/apiserver ./cmd/cyberpanel ./cmd/panel-execd -count=1`

All four packages passed. The new test drives a real listening HTTP core for
import inspection and checks handler registration, manage permission/MFA/site
policy, server-derived invocation scope, unknown actor/tenant payload fields,
missing site, anonymous callers, denied callers and insufficient assurance.
Identity/signature/domain execution are explicit fixtures in that HTTP test.
Existing native service SQL/gzip tests also passed; these separate tests do not
establish installed end-to-end identity→HTTP→native import behavior.

Three production command builds passed in QEMU with the same offline/root
environment. All six changed Go files match host/guest SHA256. Guest2.8GiB free.
Installed55 is unchanged; installed API/audit qualification and browser import
UI remain pending. No vendor changes, downloads, extra workers or binaries
committed.

### Installed import identity correction and API qualification — 2026-09-21

Installed56 completed gzip import, then exposed a plain-SQL preparation collision:
read-only prepare requests omit Idempotency-Key, but job identity used commandID,
which depends on it. Derive job identity from tenant, authenticated actor and
request ID instead. Regression checks stable same-request identity and distinct
request/tenant/actor identities. Red/green regression and affected database,
apiserver, cyberpanel and panel-execd suites (including native SQL/gzip) passed
inside QEMU before the signed57 build/install.

Revalidated installed57 committed receipt and actual core/gateway/execd process
executables. Manifest:
`51a8e4fd922ed4a8f1b2ac4b853e4ebf7c99cee0bd919f8c571593387cbfdcc0`.
Receipt: `4d8ac14b73a0760fda98ba0c1814166eb1e3af117a542e387ca454c2f0dedcab`.
Bundle SHA256: `5f829ea64f15b8a17d7b00d7ec45cce7b54506b10239eac5c0b631fb4598280b`.

Guest browser harness qemu-passkey.cjs --console-fresh --export-live --import-live
passed real passkey authentication, console queries/mutation rejection,390px
interaction and gzip/plain browser downloads with full digest verification.
Plain-SQL import prepare/run/inspect returned200; native text/NULL/BLOB rows
matched. Wrong-site inspection403, digest-tampered job400, completed-job replay200.
Disposable destination deletion returned200/applied and native absence checked.
Previously completed gzip fixture was not recreated.

Read-only SQLite audit probe verified both gzip/plain jobs: four scoped audit
events each, create/execute applied and read allowed, authenticated actor/tenant
and site/database bindings, completed job state, durable source-export digest,
promotion job digest, deleted generation3 core database resource. The probe's
first attempt mishandled SQLite BLOB Uint8Array JSON; corrected harness decoding
and reran successfully. This was a probe error, not a product failure.

Source export test table removed. Both temporary destination databases removed.
Existing credential version1/binding retained; approved and installed executor
digests match. Guest archive removed only after host/guest checksums matched and
installed57 was committed; host copy retained in ignored .work/qemu. Guest3.2GiB
free. No downloads, native component changes, new workers or committed binaries.
Import UI/upload, replacement, async jobs and broad parity remain pending.

### Installed export-backed database import UI — 2026-09-21

Added DatabaseExportImport to the SQL console after a fully verified export
download. It lists same-site ready destinations excluding the source, handles
pagination, invokes native destination preparation, requires exact typed target
confirmation and displays durable job ID/status. Submitted errors offer explicit
inspection, not automatic mutation retries. Console query/export/close controls
cannot interrupt an in-flight import request. The UI explicitly identifies the
source as a retained export, not an uploaded SQL file.

Candidate browser qualification found an export identity reuse issue in the UI:
gzip→SQL retained old import controls because the component was keyed by export
ID. Keyed by sealed job digest plus artifact digest instead. Final source hashes
match host and guest: DatabaseConsole179dcf6652b1ad2546ae32d7be8d6bf0f91931c90682d9fa25441fc2dfc55683;
DatabaseExportImportd6e466ca1944e07de5f26d7af30daebec03b2dc6ca175c7a1ddec22e735e590b.

QEMU npm run typecheck and npm run build passed (existing large-chunk warning).
Installed signed58 using unchanged core/gateway/executor binaries plus new UI.
Manifest72d1056e3d3697d6a5990b6edc00cbfcb959851080d413a3a7742651c545b227;
receipt74edddc34d51c5126607d0d864064d7b22b55fbeddb1e6c47343d8401ed36660;
bundle SHA256634dd06d881a2052c605febe8c39d8bef43eaa7400362ddf420a7fbbc08cc402.
Committed receipt and actual core/gateway/execd process executable paths checked.

Installed browser command (no candidate assets or mocked transport):
`node /home/harness/qemu-passkey.cjs --console-fresh --export-live --import-ui`.
Both gzip/plain: real passkey, browser export/digest, destination listing,
source exclusion, disabled blank/wrong confirmation, exact-name confirmation,
prepare200/run200/completed, UI status inspection200, native text/NULL/BLOB rows,
wrong-site403, tampered job400, exact receipt replay200, deletion200 and native
absence. New export reset previous import controls.390px interaction/overflow
checks and SQL mutation denial/recovery passed. Both source and destinations
were deliberately disposable test data; all were removed.

Read-only audit probe --installed58 verified five scoped events per job,
completed state, durable export-source digest, promotion receipt and deleted
generation3 resources. Existing credential version/binding and approved executor
digest unchanged. Guest bundle removed after host/guest SHA256 match; ignored
host bundle retained. Installer prune-staging succeeded for active/previous
releases; older historical staging remains. Guest2.7GiB free. No downloads,
vendor changes, new workers or committed binaries. File-upload ingestion,
replacement, long-running jobs and full parity qualification remain unfinished.

### Uploaded SQL/gzip storage and native import path — 2026-09-21

Implemented sealed TransferUploadIntent and root-private LinuxTransferUploadStore.
Intent includes destination tenant/site/database/generation, actor, compression,
expected bytes/SHA256 and bounded expiry; its digest binds integrity, not API
authorization. Every eventual API request still requires authorization. Chunks
are bounded256KiB; file size64MiB. Flocked storage supports fresh-process resume,
identical replay, offset/gap checks, fsync and final digest publication into the
existing immutable artifact store. Symlinks/hardlinks/unsafe modes are rejected.
Admission preserves2GiB disk reserve, bounds32 pending uploads and reclaims
verified expired pending directories. Discard removes unfinished data only.

Immutable jobs now accept UploadSource separately from ExportSource. Native
import selects the dedicated protected upload artifact store. Uploaded row count
is unknown until native verification; it is measured and limited rather than
trusted from the browser. Existing export row-count equality remains enforced.

Existing QEMU Ubuntu ARM64, offline/root execution:
`CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off GOTOOLCHAIN=local go test -p 2 ./internal/database ./internal/apiserver ./cmd/cyberpanel ./cmd/panel-execd -count=1`
All four packages passed. Storage tests cover SQL/gzip, reconstruct/resume,
partial finish, chunk and finish replay, changed replay, gaps, checksum failure,
tenant/actor/generation changes, expiry, symlink/hardlink/modes, partial-chunk
ambiguity, cancellation, size bounds,32-upload capacity, expiry reclamation and
discard replay. Native suite now uploads ordinary SQL/gzip in31-byte chunks,
loads through the real import broker/service into an isolated MariaDB database,
verifies text/NULL/BLOB data, promotes, persists jobs/projection and cleans up.
Final focused native rerun also verifies mixed export/upload authority rejection,
destination-generation binding and measured progress row count2 versus unknown
source estimate0. Identity/audit authorizers in these native tests remain fixtures;
this is NOT installed browser-upload qualification.

Disk preparation: inspected installed active/previous digests and all journal
states; removed12 individually named obsolete staging trees with committed
journals, excluding active/previous and rolled-back evidence. Reclaimed about
5.8GiB; installed release trees and journals retained. Deleted extractions are
not in trash; original release bundles are retained separately where archived.
Guest8.1GiB free after tests; installed58 services active and unchanged.
No downloads/vendor builds/pins/patches, new workers or host tests.
Remaining: upload broker dispatch/HTTP authorization and per-scope admission,
prepare/run API support, periodic retention and browser file-picker integration.

### Upload broker/API, durable intent retries and retention — 2026-09-21

Added closed transfer_upload broker operation with begin/chunk/status/finish/
discard actions, bounded framing, typed receipts and per-upload mutation
admission. Status is uncached read-only observation; each native operation
rechecks the destination's tenant/site/generation and local-ready instance.
Upload storage now bounds4 pending intents per tenant in addition to32 total.
Daemon startup/hourly maintenance collects expired pending and published bytes;
it does not initialize an unused store and serializes with active uploads.

Added database.upload.begin/chunk/status/finish/discard HTTP contracts, all
database:manage + MFA + site scope. Domain execution rechecks identity, actor,
tenant/site/database generation and target readiness. Begin persists server-issued
intent in database_upload_intents_v1 before allocation; retries retain original
timestamps/expiry/digest and reject changed content under the same identity.
Only metadata/digests/offsets enter upload audit events. Existing import prepare
accepts one of source_export/upload_source and verifies finalized upload status
before constructing its bound import job. No new vendor component or package.

QEMU-only validation:
`CYBERPANEL_QEMU_LIVE_TRANSFER=1 TMPDIR=/root GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off GOTOOLCHAIN=local go test -p 2 ./internal/database ./internal/apiserver ./cmd/cyberpanel ./cmd/panel-execd -count=1`
All four passed. Real broker/native tests cover17-byte chunks, exact chunk and
finish replay, fresh progress per chunk, finalized artifact status, discard and
foreign-tenant refusal, in addition to SQL/gzip isolated import/promotion.
Closed-frame tests reject mixed request/response payloads, excess offsets and
unknown actions. Admission tests cover tenant and global caps. Idle retention
preserves live data and removes expired pending/published data with bounded,
repeatable collection.

HTTP tests drive a real listening core with explicit signature/auth/domain
fixtures: registration/mutation semantics, action binding, actor/site propagation,
unknown actor fields, oversized/beyond-end chunks, anonymous/missing-scope,
denied and password-only requests. SQLite retry tests preserve initial upload
intent and refuse changed byte count; domain scope checks reject different actor,
tenant/site and generation. These are NOT installed identity/upload proof.

Installed58 unchanged and its three services active. Guest7.9GiB free. Remaining
next step is browser file-picker/row-action integration and signed installed
identity→upload→native import/audit qualification. No downloads, new workers,
vendor builds/pins/patches, host project tests or binary artifacts committed.

### Installed SQL/gzip file-picker import — 2026-09-21

Added database row action and DatabaseUploadImport dialog; no SQL principal is
required. The browser checks nonempty/64MiB bound and gzip magic, hashes source
bytes, sends256KiB chunks, resumes from current native offset and verifies the
final descriptor digest/size/compression. Empty-target preparation precedes typed
confirmation and actual import. Submitted outcomes are inspected, not blindly
rerun. Start-over discards unfinished uploads; finalized artifacts retain their
expiry. UI explicitly states unsupported views/routines/triggers/events and no
replacement. APIClient now optionally accepts a stable requestId because core
idempotency binds the entire envelope, including that ID.

QEMU npm run typecheck/build passed; existing large-chunk warning remains.
Core, gateway and executor trimpath builds passed. All4 edited UI source hashes
match host/guest. Signed installed59 is committed:
manifest550cfb5b1837dc60d7539e7d182ac6d448eeb34bd2bc87f77f3d25dc0f190648;
receipt574137b14855fa64795f4dc377ebf518c93b8f2e49ff1501b7b65c262b41d584;
bundle SHA2567fe438e2d344d69232be1eb968973dd2e5ab19dab32ebba1f3232d488edc7a29.
Actual core/gateway/execd process executable paths resolve into that manifest.

Installed browser command, no candidate assets or mocked API data:
`node /home/harness/qemu-passkey.cjs --file-import-live`.
Real passkey login and existing SQL-console regression passed. Disposable target
databases were created through the authenticated API without principals. Ordinary
SQL contained a large inert comment and two text/NULL/BLOB rows; SQL used3 chunks
at1440px, gzip2 chunks at390px. Empty file submission disabled; wrong confirmation
disabled. Begin201, status/chunks/finish/prepare200, wrong-site status403,
run200/completed, persisted inspection200 and native row equality passed.
Dialog overflow checks passed at both viewports.

For SQL, the test deliberately discarded the successful begin response before
the browser received it (real server mutation, no mocked response data), then
clicked retry. Identical request/idempotency identities recovered the original
upload and completed it. SQLite audit shows exactly one begin per upload,3/2
chunk mutations, allowed status and applied finish, plus3 correctly scoped import
events per job. Durable intent digest, immutable job upload source, promotion
receipt and generation3 deleted database resource verified. Audit contains no
SQL payload. Protected artifact descriptors and raw SHA256 matched the original
uploaded file bytes before cleanup.

Both destination databases were removed through the API and native absence
checked. Removed the two individually verified disposable uploaded payload
directories; upload store now contains only .upload-lock. Audit/intents/jobs
remain as evidence. Redundant guest bundle removed after host/guest checksum
match; host ignored copy retained. Guest7.1GiB free. Credential version1/binding
unchanged; approved and installed executor digest9cdeef3c792e89f60f1ba3ad2961fb9b63fe4566ea5d64f0516a8c0f06d6e648
match. No vendor changes, downloads, new workers, host tests or Git binaries.
Remaining import parity: replacement/restorepoints, SQL objects, long-running
jobs and recovery; broader panel journeys/matrix are also unfinished.

## 2026-09-21 — native CRS configuration evidence

Added optional `/etc/modsecurity/crs` and `/etc/modsecurity.d/owasp-crs`
directories to installed WAF asset inventory. No version/package pin introduced.
QEMU Ubuntu ARM64, root with TMPDIR=/root, offline Go toolchain:

- Focused `TestNativeWAFConfigurationInventory`, recursive integrity and
  no-custom-manifest tests passed. Actual filesystem edits change the digest;
  writable configuration and symlinked configuration directories are rejected.
- `CYBERPANEL_QEMU_WAF=1` `TestQEMUInitialWAFAssets` passed, invoking installed
  vendor OLS parser in private systemd mount namespaces for installed/unversioned
  Unicode mapping policies.
- `go test -p 2 ./internal/operations -count=1` passed; formatting was in QEMU.

Native package query confirms ols-modsecurity 1.9.2-1+noble but still custom
cyberpanel-waf-crs 4.29.0-2. No replacement package was found in inspected local
apt archive/harness paths. This is source qualification, not deployment or proof
of distro CRS installation. Installed59 unchanged; no downloads, custom builds,
new workers or binary artifacts. Guest free space remains 7.1GiB.

## 2026-09-21 — durable import outcome after caller disconnect

QEMU regression initially failed: cancellation after successful native-promotion
fixture left no SQLite receipt; cancellation with uncertain promotion returned
context cancelled instead of preserving the ambiguous outcome. Fixed
TransferService.finishTransfer to detach only receipt/audit finalization, with
a 10-second timeout. Existing lease/generation fencing remains enforced.

QEMU Ubuntu ARM64: database/apiserver suites passed with live-transfer flag.
Explicit verbose native round trip passed SQL/gzip ordinary/BOM input, and all
eight promotion outcome cases passed, including both disconnect regressions.
Tests verify actual SQLite receipt persistence, ambiguous job refusal to restart,
and terminal audit with a live bounded context. The disconnect itself is injected
at the catalog seam; installed HTTP disconnect behavior is not yet qualified.
No native operation is retried by this fix. No downloads/vendor changes; source
change is not yet in installed59. Cancellation API, queued cancellation lifecycle,
crash recovery and replacement remain pending.

## 2026-09-21 — queued cancellation and import cancel API

Real SQLite QEMU regression reproduced cancellation returning success while
leaving a job queued/generation1. Queued cancellation now commits cancelled state,
terminal progress and immutable receipt atomically, with no native execution or
mutation. Cancellation finalizes lifecycle attempt1; it does not fabricate a
process receipt. Live jobs still honor cancellation only at safe checkpoints.

QEMU tests passed: queued termination, stale request refusal, cancelled claim
refusal, receipt-insert failure rollback, running-job continuation through an
unsafe checkpoint then cancellation at the safe checkpoint. Database suite with
CYBERPANEL_QEMU_LIVE_TRANSFER=1 passed. Added site-scoped/MFA-required mutating
database.import.cancel using existing service authorization and generation checks.
Actual HTTP test server exercises the contract with fixture auth/domain: valid
invocation, invalid body, missing site, anonymous, denied and low-assurance cases.
API/core/gateway suites passed after correcting the test envelope's idempotency
field location. No installed API cancellation or UI qualification claimed.
Installed59 unchanged; no downloads, vendor changes or binary artifacts.

## 2026-09-21 — installed import cancellation UI, releases60/61

Shared DatabaseImportStatus controls in file/export-backed import dialogs allow
inspection/cancellation while the main run request is busy. Read-before-cancel
uses current job generation. Terminal statuses disable cancellation; requested
does not mean cancelled; ambiguity explicitly prohibits retry. Job checks have
their own busy/close guard. QEMU UI typecheck/build passed (existing large-chunk
warning). Real Chromium component QA at1440/390px covered running cancellation,
generation binding, terminal refusal, stale error, ambiguity and overflow; API
was a fixture for this isolated component check.

Installed60 then exercised the real file-upload flow. Immediate cancellation hit
generation409 as the job advanced; harness disconnection produced a durable
failed receipt with source preserved. Later SQL/gzip cancellation during native
SLEEP streaming succeeded but run returned500. Fixed API handling to return the
validated cancelled receipt only for ErrTransferCancelled, without suppressing
persistence errors. QEMU API/core tests passed and installed61 included the fix.

Installed61 actual passkey/MFA browser, no candidate assets or API fixtures:
SQL1440px and gzip390px uploaded in multiple chunks, SHA verification and typed
confirmation passed; wrong-site status403 and lost-begin response replay retained.
Native streaming was observed before cancel. Cancel200, run200/cancelled, automatic
inspect200 and final cancelled UI passed for both. Native destination schemas
remained empty. Immutable receipts, cancel/execute actor+tenant audit, and absence
of promotion records independently checked in real SQLite. Both cancelled test
destinations and the prior three disposable test databases removed through API;
native schema count for all five is0. Their verified uploaded payload/descriptor
directories removed, retaining audit/jobs/intents. Upload root only .upload-lock.

Installed61 release qemu-import-cancel-3.1.60 committed. Manifest
bae97e346bae9d1ace8b1683c28dcc3961537a2ff28c204c74de41f7f173f584;
receipt24acb7089f68faaaafc79441e26e4db7601b68eb61ff82ecf39c37c532c1e7e5;
bundle SHA4affa38b532e2adbd4d6998ddbaccbe1d6b30127d6c4df3ca98ada1a1eb2e8bd.
Actual core/gateway/execd /proc executables all in that release, services active.
Host ignored bundle checksum matched guest; redundant guest60/61 bundles removed.
Temporary guest Vite server stopped and its two fixture files removed; ignored
host QA harness retained. Guest5.7GiB free. No vendor builds/downloads/new workers.
Source export-backed cancellation wiring is shared but that installed workflow
was not separately driven. Broader recovery and full panel parity remain pending.

## 2026-09-21 — verified native promotion metadata recovery

Added protected promotion-verified checkpoint containing successful promotion
proof and exact before/after native resource records, written after native SQL
move/verification/isolated cleanup but before native resource metadata update.
Re-entry finishes only the matching metadata transition and terminal promotion
record under the existing writer fence. It accepts exactly before/after metadata,
rejects drift/missing proof, and leaves unverified promoting outcomes ambiguous.

QEMU Ubuntu ARM64 real MariaDB SQL/gzip round trips passed. After actual native
promotion and isolated-schema removal, tests inject protected checkpoint states
before/after metadata persistence then call ExecuteTransferImport. Both recover
the identical proof and actual final resource/receipt records; native row count
remains2. Changed metadata, absent proof, and unverified-move states reject with
ErrAmbiguous without overwriting metadata. This simulates durable interruption
states, not a killed-daemon/reboot test. Database/API/panel-execd suites passed
with CYBERPANEL_QEMU_LIVE_TRANSFER=1; targeted real-native test passed after final
assertion tightening. No downloads/dependency changes/new release or workers.
Installed61 unchanged. Job-level reconciliation/operator recovery and earlier
native-move crash windows remain unfinished; this does not claim full recovery.

## 2026-09-21 — job reconciliation from executor-owned promotion proof

Added native recover action (no allocation/load/RENAME/DROP), complete proof tuple,
core projection reconciliation and transactional terminal job receipt/progress.
Original ambiguous receipt remains immutable. Service authorizes stored job and
database ownership, checks generation/expired lease before native recovery, and
rechecks state/lease inside the receipt transaction. Completed replay is exact;
final persistence/audit has bounded detached context. API database.import.recover
requires manage/MFA/site scope and accepts job ID only. Shared UI distinguishes
recovery from rerunning import and refreshes the generation before invoking it.

QEMU real SQLite/socket/native MariaDB SQL+gzip uploaded import tests inject
terminal receipt failure after successful promotion. Live lease/intruder refused;
test clock advances past lease expiry. Gzip first persists ambiguous lease-expiry
receipt, then recovery adds completed receipt without deletion. A second injected
receipt failure leaves job state unchanged; retry after removing fixture trigger
succeeds, stale generation refuses, completed replay digest unchanged, native rows
and core generation verified. Database/API/core/execd suites passed. A test-local
shadowed error initially retained the deliberately injected error; corrected and
reran all affected suites. HTTP server tests cover recovery contract auth/body
refusals with fixture identity/domain. UI typecheck/build and Chromium1440/390px
component checks passed recovery completion and generation binding alongside
prior cancellation checks (fixture API, not installed qualification).

Installed61 unchanged; no bundle/download/vendor change/new workers. Temporary
guest Vite process and fixture files removed; guest5.4GiB free. Still pending:
installed recovery UI/API, killed-daemon/restart proof, and uncertain native move
without durable verified-success evidence. Full panel parity remains incomplete.

## 2026-09-21 — installed62 recovery across actual core SIGKILL/restart

Built all three binaries in QEMU and assembled/installed signed62. Installed
qemu-import-recovery-3.1.61 manifest
c98e86aaea81cc6c00c54664c076d52a02cce02959418024345a7888112c0561;
receipt3fa91805eeaa33b8ac74cfa732dd4656c53bd879b10819d2fa0c9a113840c81a;
bundle SHA5aaca96841038240bf3820052e0e43bfdd86b140f77226c984eeb71bc74ad34c.
Installer state committed. Actual core/gateway/execd executable paths matched
release before and after fault testing; services active. Bundle retained only in
ignored host storage after checksum match; duplicate guest copy removed.

Actual installed browser passkey/MFA, no candidate assets/API fixtures. SQL at
1440px and gzip390px: real multi-chunk upload, lost-begin response replay, typed
confirmation, wrong-site403. Per-job SQLite trigger rejected completed receipt
after native/core promotion; run500 and inspection200/promoting observed. Trigger
removed after checking promotion persisted and terminal receipt absent. Immediate
recovery409 confirmed live-lease protection. SIGKILL sent to panel-core main
process, systemd automatic restart confirmed new PID/NRestarts. Waited actual
119-second remaining lease each time; no timestamp editing/test clock. Recovery
then200/completed and real UI completion rendered; native exact text/NULL/BLOB
values verified, completed receipt and correct actor/tenant recovery audit checked.

Both disposable database deletions applied through API at generation2; control
records deleted generation3 and native schema count0. Each uploaded descriptor and
payload SHA checked before removing its two-file directory; upload store now only
.upload-lock. Both scoped fault triggers removed. Guest4.8GiB free, host220GiB;
Git objects about498MiB. No downloads/new workers/vendor builds or Git binaries.
This establishes receipt-failure/core-restart recovery with verified native proof,
not arbitrary native-operation crashes. Parent dialog's original request error
can remain beside recovered success (UI polish still pending). Other parity work
and broader target matrix remain open.

## 2026-09-21 — recovered dialog status wins over stale request errors

Four-line source correction in upload/export-backed dialogs: confirmed completion
clears prior failure; later rejection of the original run cannot replace it with
an uncertain outcome. QEMU real Chromium drove both full dialogs, not just the
shared status component, through preparation/typed confirmation/run failure and
recovery. Eight fixture-API cases passed (2 dialogs × 2 widths1440/390 × early/late
original failure). Error visible before recovery when applicable, absent after
confirmed completion, no recovery button/overflow/browser errors. QEMU UI
typecheck/build passed; existing chunk-size warning remains. Temporary guest
Vite server and fixture files removed; ignored host harness retained. Installed62
unchanged, no new bundle/download/vendor changes. Include in next grouped release.
# Native WAF mapping preference handoff — 2026-09-21

QEMU Ubuntu ARM64 only: `sudo env TMPDIR=/root
GOCACHE=/home/harness/.cache/go-build GOPATH=/home/harness/gopath GOPROXY=off
GOTOOLCHAIN=local /home/harness/go/bin/go test -p 2 ./internal/operations
./cmd/cyberpanel -count=1` passed both packages. Targeted WAF checks also passed.
New regression verifies preservation of an exact bootstrap policy after a native
mapping preference change and refusal of modified policy, missing old mapping,
and symlink mapping. Existing installer tests preserve managed policy and reject
unsafe files. These are source/package tests inside QEMU, not a live package
upgrade or installed-release qualification. No downloads or third-party changes.
# External workspace export — 2026-09-21 (QEMU source qualification)

Ubuntu ARM64 QEMU: `sudo env TMPDIR=/root CYBERPANEL_QEMU_LIVE_MARIADB=1
CYBERPANEL_QEMU_LIVE_TRANSFER=1 GOCACHE=/home/harness/.cache/go-build
GOPATH=/home/harness/gopath GOPROXY=off GOTOOLCHAIN=local
/home/harness/go/bin/go test -p 2 ./internal/database ./internal/apiserver
./cmd/cyberpanel ./cmd/panel-execd -count=1` passed all four packages.

The existing disposable native TLS server now exercises production workspace
export credential resolution, dump execution, artifact publication and download:
plain SQL/gzip contain the actual remote row; download bytes match the artifact;
wrong CA/hostname fail the native dump and publish nothing; tenant mismatch denies
export and download. Local SQL/gzip round trips pass as well. Native fixture and
artifact cleanup remain scoped to test-created objects. This is not installed
HTTP/browser external-export qualification; mutual TLS for workspace sessions is
still unavailable. No dependencies downloaded/built/pinned and no release deployed.
# External export coordinator/broker qualification — 2026-09-21

QEMU Ubuntu ARM64 targeted `TestQEMULiveMariaDBExternalTLS` passes after moving
successful SQL/gzip cases through production coordinator preparation (real remote
metadata), framed Unix socket, SQL reboot admission, native dump and authorized
download. Wrong actor cannot run the job; stale session cannot download. Existing
negative native TLS and cross-tenant checks still pass. The broker fixture checks
download bytes never enter the mutation journal. Repository reads and peer
identity are fixtures; no installed HTTP/browser qualification is claimed.
# Abandoned incoming transfer retention — 2026-09-21

Ubuntu ARM64 QEMU: targeted `TestTransfer(Incoming|Retention|Artifact)` passed,
including actual child-process SIGKILL and subsequent byte reclamation. Clock
advancement simulates expiry; process liveness is real, not simulated. Live and
closed-but-uncommitted writers retain a directory flock and are not collected.
Legal holds, unexpired data, unknown contents, bad/missing metadata and unsafe
links survive; interrupted tombstone cleanup completes.

With `TMPDIR=/root CYBERPANEL_QEMU_LIVE_MARIADB=1
CYBERPANEL_QEMU_LIVE_TRANSFER=1 GOPROXY=off GOTOOLCHAIN=local` and the existing
guest Go/cache paths, `go test -p 2 ./internal/database ./internal/apiserver
./cmd/cyberpanel ./cmd/panel-execd -count=1` passed all four packages. No installed
daemon upgrade is claimed. Fixtures clean their own temporary data; no user
artifacts or old unidentifiable staging directories were removed.
# Installed63 grouped database release — 2026-09-21

QEMU Ubuntu ARM64 signed release qemu-database-transfer-3.1.62 sequence63 committed.
Source a48a4c83e; core/gateway/execd built offline and UI typecheck/build passed.
Actual process binary hashes match assembly: core
9cbc01c3981d79b03066959cd9b4855ced22fddc536b38fd0c13163269d6fb2a,
gateway99fad41d19b630cd4726e859a22ed64cf19f4aeccf4dd6e7827c435628f05f16,
execdc1015620aa42875e9139ca741bf0859c0c593c753a83c65523ed774d8906d558.
UI index-DGPgYFsL.css/panel-CGMuzc93.js installed. All services running, NRestarts0.

Real Chromium using installed assets/API: passkey login200, console issue201,
metadata/query200, forbidden mutation400, successful follow-up query and390px
layout; SQL/gzip export prepare200/run201/download200, expected fixture bytes and
full SHA256 passed. First attempt had no fixture table after earlier cleanup;
recreated the small native fixture, reran successfully, then dropped that table.
This verifies local installed export; external enrollment/browser remains pending.

Manifest db95ffcb6727508a37e5ea6f57e766bfba2268ac8386dfed5d3e3243ea7a6c55;
receipt8fdc9e4e0c4d9e3cedcdef203040a49bacbf5f75cff63131dba1811d6d7facb1;
bundleSHA256d6b83abce7a6583fd417223dfe1165e9acd0846e0c0c6a8a53af81b6b17769d0.
Retained bundle only in ignored host .work/qemu; exact guest duplicate removed
after matching hashes/committed receipt. Installer prune-staging completed;
guest4.0GiB free. Existing native packages unchanged, no downloads or vendor builds.
# Replacement promotion native lock probe — 2026-09-21

Read/DDL experiment in the existing Ubuntu ARM64 QEMU guest, using unmodified
native MariaDB. Created two disposable schemas and one populated table; on one
connection ran BACKUP STAGE START, BACKUP STAGE BLOCK_DDL, then RENAME TABLE across
the schemas. MariaDB refused the rename with ERROR4145: active BACKUP STAGE.
This invalidates same-connection backup-stage locking as the promotion mechanism.
The process exited, releasing the lock, and both created schemas were dropped.
No panel source behavior, installed package, or release changed in this probe.
# Ordinary INSERT IGNORE / REPLACE imports — 2026-09-21

QEMU Ubuntu ARM64 targeted `Test(TransferSQL|QEMUTransferNativeRoundTrip)` passed.
The native round-trip fixture now imports ordinary, BOM, INSERT IGNORE and REPLACE
forms in both plain SQL/gzip. Native row queries prove duplicate INSERT IGNORE
leaves existing text/BLOB unchanged and REPLACE changes the selected row. SELECT
sources, LOAD_FILE and client escapes remain rejected. The native target fixture
uses a scoped SQL account; this is not installed HTTP/upload qualification.

With the existing guest Go/cache configuration, TMPDIR=/root,
CYBERPANEL_QEMU_LIVE_TRANSFER=1, GOPROXY=off and GOTOOLCHAIN=local, full database,
apiserver, cyberpanel and panel-execd package suites passed. No native package
changes or downloads. Installed63 unchanged; view and live-database replacement
support are not claimed by these tests.
# MyISAM / Aria import promotion — 2026-09-21

Native atomic RENAME support for InnoDB, MyISAM and Aria is documented by MariaDB:
https://mariadb.com/docs/server/reference/sql-statements/data-definition/rename-table
The existing >=10.6.1 server capability check is unchanged. Promotion now allows
these three engines; MEMORY/CSV/FEDERATED/CONNECT/SPIDER/unknown remain refused.

QEMU Ubuntu ARM64 `TestQEMUTransferNativeRoundTrip` passed InnoDB/MyISAM/Aria ×
none/gzip. Each exercises actual native export, import, scoped isolated loader,
broker promotion, exact contents, receipt/projection recovery. Added native
information_schema assertion proves the promoted table retains its source engine.
Ordinary/BOM/INSERT IGNORE/REPLACE subcases also pass for every engine/compression.
No MariaDB process kill during rename was performed; native atomicity guarantee
is sourced above, not claimed as newly reproduced crash evidence.

Full database/apiserver/cyberpanel/panel-execd suites passed inside QEMU using
TMPDIR=/root, CYBERPANEL_QEMU_LIVE_TRANSFER=1 and existing offline Go/cache paths.
No vendor builds, downloads or installed release changes.
# View-dump loading primitive — 2026-09-21 (not complete feature)

QEMU native dump probe established CREATE VIEW placeholder and versioned clauses,
including explicit root definer. Added transfer envelope rewrite strips that
identity, forces SQL SECURITY INVOKER and validates SELECT body through existing
workspace rules. Native SQL/gzip loader checks across InnoDB/MyISAM/Aria confirm
INVOKER and two readable rows. Fixture loader has scoped CREATE VIEW; production
loader authorization and destination verification/promotion are NOT yet changed.
This remains an internal loading primitive, not successful product view import.

Targeted `Test(TransferView|TransferSQL|QEMUTransferNativeRoundTrip)` and full
database/apiserver/cyberpanel/panel-execd suites passed inside Ubuntu ARM64 QEMU
with live transfer flag/offline Go/cache settings. Native probe also verified
SHOW CREATE VIEW after USE emits same-schema table references without the schema
prefix. Probe schemas dropped. No package changes/downloads/release installation.
# Native view definition capture and verification — 2026-09-21

QEMU Ubuntu ARM64: actual root-native observation captures a scoped-loader view,
ordered id/body columns and sanitized invoker definition in its own schema
context. Complete database verification accepts the healthy view and still counts
two base rows, not four. Removing the view changes its schema digest. Captured
character-set/collation are included in canonical view evidence. Existing SQL/gzip
and engine variants pass; no installed view-promotion claim.

Using the established offline QEMU Go/cache configuration and
CYBERPANEL_QEMU_LIVE_TRANSFER=1, full database/apiserver/cyberpanel/panel-execd
suites pass. Production loader grants and destination recreation/promotion remain
unfinished. No native package changes, downloads, or new release deployment.
