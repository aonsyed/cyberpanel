# Installed Joomla lifecycle verification — 2026-09-22

PASS on installed QEMU release 82, using cached signed Joomla 6.1.3, packaged
PHP 8.3, the real panel UI/API, OpenLiteSpeed, and MariaDB. No vendor downloads,
manual database state changes, permission repairs, or direct service starts were
used to obtain this result. The existing disposable site was reused throughout.

## Verified journey

- Site: `qemu-joomla-resume22j.example.invalid`.
- Site ID: `site-api_17b0664c8fb1a140dbdfd032cce4f3bd0ae098316019c4ab`.
- First normally removed the retained release-81 health-failed installation
  `app-6b15e53ed0fcfc023450619109bfa0c10c16be4850908580` (HTTP 202).
  Its database/principal were removed, both secret leases revoked, public root
  emptied, and runtime state removed; the required snapshot was preserved.
- Fresh installation through the panel returned HTTP 201:
  `app-2da64ac70d35f963464be00945a74d9044a14e9ee5ee6353`.
- The actual HTTP homepage returned 200 and identified Joomla. The administrator
  page returned 200. The guest-only bootstrap credential authenticated the real
  **Home Dashboard** UI.
- Before removal, the installation was active and its database resource matched
  the installation's tenant and site. Database and principal
  `cp_ddd44e6321fecefe7fc8dd06` each existed exactly once.
- Normal panel removal returned HTTP 202. Native verification found zero matching
  databases/principals, both application secret leases revoked, an empty public
  directory, absent application runtime state, and installation state `removed`.

Public root:
`/var/lib/cyberpanel/sites/s-d7f1c5029d08a240c27ea1a0/roots/g2/releases/current/public`.

The original harness expected the site title in homepage body text; Joomla's
default page did not render it there. After the successful installation, only
that assertion was corrected to check the Joomla generator. Verification resumed
against the same installation; it did not reinstall or mutate product state.

## Preserved recovery evidence

Final installation snapshot:

- `/var/lib/cyberpanel/application-snapshots/recovery-caa8f4e3986315f7abca4e148befb0288a81b5ec5dfe9b71/manifest.json`
- Archive SHA-256:
  `3609fad4073fb8f97cb95568c9afbdf306733c987f6af6d2db536e5869c66847`.

The earlier release-81 recovery removal snapshot also remains:

- `/var/lib/cyberpanel/application-snapshots/recovery-b18a3cdddaef5243f40688600932e8d750fae9933353299c/manifest.json`
- Archive SHA-256:
  `770a660bb4e61794d81826a46bde30a03ae6d1287cb58f794b83d4e34dbdb5df`.

Both archives were hashed independently and matched their manifests; each
manifest contains a database digest. The earlier release-78 recovery snapshot
`recovery-ffcfd6437c7c0d324a4cc61b279badd390d185a70f4cd907` was also retained.

Safe guest evidence:

- `/home/harness/qemu-joomla-resume22j.json`: install/removal receipts, login result,
  pre-removal ownership, and computed exact cleanup/snapshot verification.
- `/home/harness/qemu-joomla-resume22j-installed.png`.
- `/home/harness/qemu-joomla-resume22j-admin.png`.

Credentials remain in the guest-only mode-0600 private fixture file and are not
included in this report. The site and recovery snapshots were intentionally
retained. Browser/native lease was released after verification.

## Scope

This proves one complete Joomla install/login/remove journey and normal removal
of retained failed installations. It does not claim other applications, Joomla
updates, multilingual installs, or unrelated application features. The previously
passing WordPress lifecycle was not replayed.
