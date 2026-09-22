# Installed WordPress lifecycle — 22 September 2026

Ubuntu 24.04 ARM64 QEMU only; installed signed releases 68 and 69. No vendor
downloads, dependency builds, manually moved application files, or credential
output were used. Existing guest-only owner/passkey fixtures authenticated the
actual installed panel. This is a bounded lifecycle result, not full application
or WordPress parity certification.

## Reproduced and corrected

- Release 68: a new isolated site and WordPress 7.1 installation returned HTTP
  201 through the real panel forms. The application was active/healthy, but
  LiteSpeed HTTP `/` and `/index.php` returned 404. The installer targeted
  `releases/current`, while the provisioned document root was
  `releases/current/public`.
- Commit `ebcd65a89` derives the installation scope from the provisioner's
  application/document roots. QEMU regression checks passed for the default
  `public` path and seven invalid/unrelated paths.
- Commit `b803321f2` removes implicit optional downloads from core bootstrap:
  default English needs no language download, requested languages must be
  locally present, and configuration errors are surfaced. Explicit plugin/cache
  controls remain separate. QEMU application-suite and focused command-boundary
  tests passed.

## Release 69 real result

New isolated fixture `qemu-wp-resume22b.example.invalid`:

1. Passkey login 200; site creation 201; application installation 201.
2. Native LiteSpeed HTTP `/` returned 200 containing both the exact site title
   `QEMU WordPress lifecycle22` and WordPress's `Hello world!` content.
3. `wp-config.php` was in `current/public`, owned by site UID/GID
   `200003:200003`, mode 0640. The older fixture's separate site UID could not
   read it.
4. Application database `cp_35090b22e4c52ba421069d88` contained 131 WordPress
   options. Its matching `localhost` principal had grants on its exact escaped
   schema; `Grant_priv=N`.
5. The real panel Remove action, with its impact checkbox, returned 202. Native
   checks confirmed WordPress configuration/files removed and both database and
   principal counts zero. A recovery snapshot manifest remained at
   `application-snapshots/recovery-14fe1327be2ecb4f90d8eceef5aee96eaa611c548ac6f0c7/manifest.json`.
6. The older release-68 fixture was subsequently removed through the same real
   panel action, returning 202. Its application files, database and principal
   were also confirmed absent.

Empty hosting-site resources and retained recovery snapshots were not manually
purged. Snapshot restoration was not exercised, and snapshot existence is not
a disaster-recovery claim.

## Remaining observed limitation

On release 69, HTTP `/wp-login.php` redirects to HTTPS, but this newly created
site has no TLS listener binding; HTTPS returns the default host's 404. The
application edge currently hardcodes its canonical URL to HTTPS. Fixing that
must use current, tenant-owned applied routing state—not a blanket HTTP default
or a fake TLS mapping. Public-page HTTP serving is proven; usable WordPress
admin login is not yet proven.

Guest-only evidence: `/home/harness/qemu-wordpress-resume22*.json`, protected
private bootstrap files, `/home/harness/qemu-wordpress-resume22b-installed.png`,
and `/home/harness/lanes/apps/qemu-wordpress22.cjs`. No credentials are committed.
