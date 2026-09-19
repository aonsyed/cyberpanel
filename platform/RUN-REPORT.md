# QEMU verification — 2026-09-19

This is a verification checkpoint, not a parity-release certification.
The scope remains the complete product defined in the existing design spec.

## Source and environment

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
