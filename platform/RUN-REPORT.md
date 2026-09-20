# QEMU verification — 2026-09-19

This is a verification checkpoint, not a parity-release certification.
The scope remains the complete product defined in the existing design spec.

## Source and environment

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
