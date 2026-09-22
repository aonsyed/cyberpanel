# Installed WordPress lifecycle — 22 September 2026

Ubuntu 24.04 ARM64 QEMU only; installed signed releases 68, 69 and 71. No vendor
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

## Historical release-69 canonical-URL failure

On release 69, HTTP `/wp-login.php` redirects to HTTPS, but this newly created
site has no TLS listener binding; HTTPS returns the default host's 404. The
application edge currently hardcodes its canonical URL to HTTPS. Fixing that
must use current, tenant-owned applied routing state—not a blanket HTTP default
or a fake TLS mapping. Public-page HTTP serving is proven; usable WordPress
admin login was not proven on release 69.

## Release 71: canonical URL and real administrator login verified

The trusted catalog lookup in `2cce4207f` distinguishes a current owned HTTP-only
site from a valid owned TLS binding. Stale, mismatched, unapplied, or missing
listener state fails closed rather than silently downgrading. The installed
retained site's hosting and catalog generations were both 2, confirming the
generation comparison against actual persisted state, not only test fixtures.
Commit `ef3e808f0` completes the runtime path: manifests accept HTTP/default80
and HTTPS/default443, and probes dial only the corresponding fixed loopback
port. Archive input validation remains HTTPS-only and HTTPS certificate
verification remains enabled. The manifest regression failed for HTTP before
the correction and passed after it; focused probe tests and the full apps suite
passed inside QEMU.

Fresh fixture `qemu-wp-resume22c.example.invalid`, on installed signed71:

1. Real passkey login 200, site creation 201, application installation 201.
2. Browser homepage 200 with the expected title; `/wp-login.php` 200 without an
   unprovisioned HTTPS redirect. The actual newly issued WordPress bootstrap
   credential authenticated successfully, and `/wp-admin/` rendered Dashboard
   and its authenticated admin toolbar.
3. The persisted application manifest contained the authoritative
   `http://qemu-wp-resume22c.example.invalid/` URL. No fake TLS mapping or
   certificate-validation bypass was introduced for the application.
4. `wp-config.php` was site-owned `200004:200004`, mode0640; another site's UID
   was denied read access. The guest-only bootstrap credential file was mode0600
   and no credential value was logged or committed.
5. Database `cp_903935f04613af17355ec224` contained 149 options after the real
   admin visit; its localhost principal held its exact escaped-schema grants,
   with `Grant_priv=N`.
6. Real panel Remove returned 202. Native inspection confirmed the application's
   public directory entirely empty, its runtime-state directory absent, and
   exact database and principal counts both zero. The recovery manifest remains
   at `application-snapshots/recovery-5aca7d058a8f5f29b662ba77da6da65a32bb2b6744eb757f/manifest.json`.

Safe guest evidence: `/home/harness/qemu-wordpress-resume22c.json`,
`/home/harness/qemu-wordpress-resume22c-installed.png`,
`/home/harness/qemu-wordpress-resume22c-admin.png`, and the same bounded harness
`/home/harness/lanes/apps/qemu-wordpress22.cjs`. The fixture hosting site and
recovery snapshot remain retained. No service restart or manual application
file relocation was used during this journey.

This closes the fresh default-English WordPress install → public HTTP → actual
administrator login → safe normal removal journey on this target. It does not
certify multilingual installations, WordPress updates/staging/autologin,
restore from the retained snapshot, other applications, other targets, or a
live publicly trusted HTTPS WordPress installation.

Guest-only evidence: `/home/harness/qemu-wordpress-resume22*.json`, protected
private bootstrap files, `/home/harness/qemu-wordpress-resume22b-installed.png`,
and `/home/harness/lanes/apps/qemu-wordpress22.cjs`. No credentials are committed.
