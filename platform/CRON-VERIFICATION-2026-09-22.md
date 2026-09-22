# Installed cron lifecycle — QEMU release 84

PASS on signed `qemu-workflow-3.1.83`, source `21baf991f`.

Used the existing empty `qemu-joomla-resume22j.example.invalid` site, not another application installation. The normal authenticated API created `public/cron84.php` (200) and cron job `qemu_cron84` (201), with schedule `* * * * *`, timezone UTC, packaged PHP invocation, and the existing site binding.

At **2026-09-22 12:13:00 UTC**, systemd actually dispatched the generated timer service through the installed signed `panel-cron-exec` helper and access broker. PHP wrote the expected marker owned by site UID/GID **200006:200006**, mode **0640**. No run-now request, direct helper invocation, or manual timer start substituted for scheduling.

Normal API disable and delete each returned 200. Final checks found:

- Timer `LoadState=not-found`, `ActiveState=inactive`, no next expiry.
- Generated service/timer files and timer enablement symlink absent.
- Authoritative site cron manifest contains zero jobs.
- Exactly the fixture PHP file and marker removed as the site user; existing public root empty.
- Existing site and application recovery snapshots preserved; no shared service restart.

Durable safe guest evidence: `/home/harness/qemu-cron84.json` includes API responses, marker ownership, actual scheduled journal, and cleanup assertions. Verifier: `/home/harness/lanes/apps/qemu-cron84-proof.cjs`. Harness: `/home/harness/lanes/apps/qemu-cron84.cjs`. Credentials/passkey material remain in separate guest-only files and are not included in evidence.

Before fixture creation, two harness request-shape mistakes returned 400 without mutation (missing generation for file write; forbidden idempotency header on a read). Both were corrected against existing contracts. No additional product defect arose during installed verification.

Source fixes: `7593bbe31` (native calendar/packaged CLI/timer retirement) and `1edec32c5` (day-of-month OR weekday contract). Prior isolated QEMU verification covered native calendar parsing, exact OR next-occurrence agreement with the existing scheduler, site-owned PHP execution, and generated-unit create/disable/delete. This closes one lifecycle, not all cron policy or runtime variants.
