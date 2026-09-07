# Disposable CyberPanel backup conversion

This is an operator-installed, local-only converter. It publishes evidence for
the existing `migration.create` operation; it neither creates target resources
nor grants migration authorization. No runtime validation is claimed by this
runbook. Exercise the complete conversion/admission flow in QEMU before release.

## Provision once for the conversion window

- Install the binary, systemd unit, tmpfiles declaration, and configuration at
  the exact destinations declared in `artifacts/cyberpanel-backup-convert.bundle.json`.
  This declaration does not register a new core-installer component. Apply the
  tmpfiles declaration after the parent `/var/lib/cyberpanel/migration` exists.
- Replace `PROVISION_TARGET_INSTALLATION_ID` in
  `/etc/cyberpanel/cyberpanel-backup-convert.json`. The service deliberately rejects
  the unconfigured example. Keep the configuration root-owned and non-writable
  by group/other, readable by `cyberpanel`.
- Provision a dedicated Ed25519 private key as 128 hex characters at
  `/etc/cyberpanel/secrets/backup-converter-signing.key`, and the target X25519
  public key as 64 hex characters at
  `/etc/cyberpanel/secrets/migration-target-public.key`. A final newline is allowed.
  Root owns these files; systemd exposes private credential copies to the service.
  Do not put keys into JSON, shell arguments, logs, or the raw archive inbox.
- In the existing `/etc/cyberpanel/migration/trust.json`, preserve existing trust
  entries and add the converter's **public** Ed25519 key (64 hex characters) to
  `manifest_keys` under the configured `manifest_signing_key_id`. Its
  `target_installation_id` must exactly match the converter configuration. Add the
  schema hash returned by the existing `CanonicalManifestSchemaHash()` contract to
  `schema_hashes`. Do not trust a key supplied by a backup or automatically copy
  trust from a produced manifest. The independently provisioned target sealing
  key ID must match `target_sealing_key_id`.
- Start `cyberpanel-backup-convert.service` for this window. It runs as
  `cyberpanel`, without IP networking, with a root-peer-only Unix socket, one
  conversion at a time. It is intentionally not enabled at boot.

## Stage and convert

A local root administrator stages an immutable archive named
`<artifact_id>.tar.gz` in
`/var/lib/cyberpanel/migration/cyberpanel-backup-raw/`. The inbox is
`root:cyberpanel 0750`; archives are `root:cyberpanel 0440`, ordinary files with
one link. Symlinks, hardlinks, arbitrary paths, and archive-selected commands are
not accepted. Artifact and request IDs match `[a-z][a-z0-9_-]{2,95}`.

As root, invoke `/usr/local/libexec/cyberpanel/cyberpanel-backup-convert convert`
with one JSON request on stdin. For example, with an actual configured target
and a fresh UTC deadline no more than 15 minutes ahead:

```json
{
  "version": 1,
  "request_id": "backup_request_20260907_001",
  "artifact_id": "backup_example_001",
  "tenant_id": "tenant_example",
  "target_installation_id": "target_example",
  "deadline": "2026-09-07T12:15:00Z"
}
```

The example deadline is illustrative, not a value to replay. Save successful
stdout privately as the operator conversion receipt. It contains the signed
manifest's `migration_id`, `manifest_root`, conversion `evidence_digest`,
`bundle_endpoint`, and a `migration_create` selection object. The bundle has
exactly `source.tar.gz`, `<migration_id>.manifest.json`, and `chunks/` under
`/var/lib/cyberpanel/migration/cyberpanel-backup-intake/<migration_id>/`.

The archive still contains original secrets and must remain private. Only
target-bound encrypted credential envelopes appear in the canonical manifest;
legacy admin hashes/tokens never become target authority. Cron commands and
server configurations remain evidence, not commands executed by this converter.

## Select the result through migration.create

Use `migration_create.operation` (`migration.create`) with
`migration_create.tenant_id`, and submit **only** `migration_create.payload` as
the API payload. Its exact shape is:

```json
{
  "source": "cyberpanel_backup",
  "source_endpoint": "file:///var/lib/cyberpanel/migration/cyberpanel-backup-intake/<migration_id>"
}
```

Do not copy the angle-bracket example literally; use the emitted endpoint.
Do not select `cyberpanel` (the live extractor) or point at the raw `.tar.gz`.
With the existing `panelctl invoke` entry point, supply:

- `--operation migration.create`
- `--tenant` equal to the emitted tenant
- `--idempotency-key` equal to the emitted `suggested_idempotency_key`
- `--payload -`, with only the two-field payload on stdin
- the normal authenticated gateway endpoint and a current MFA-qualified session
  through the existing `--session-file` option, with `migration:manage` authority

Leave `--resource` and `--expected-generation` unset for this create operation.
The complete converter JSON is a receipt, not an API request body. Root access
to conversion does not replace gateway authentication, tenant authorization, or MFA.

The create edge calls `AdmitCyberPanelBackup`, independently checks target trust
and archive/manifest mapping, moves the bundle to
`/var/lib/cyberpanel/migration/cyberpanel-backup-quarantine/<manifest_root>/bundle`,
and binds the signed migration ID and that endpoint to the authenticated tenant.
The returned migration ID should match the converter receipt. Continue through
the existing inventory, plan, synchronization, rehearsal, and guarded cutover
operations; conversion success alone is not import success.

## Retry and recover

- If conversion times out or its stdout is lost, resubmit the same request ID,
  artifact ID, tenant, and target with a fresh deadline. Deadline is not part of
  receipt identity. The raw archive must remain unchanged and available.
- Durable converter receipts live at
  `/var/lib/cyberpanel/migration/cyberpanel-backup-converter/receipts/`
  `<sha256(tenant_id + NUL + request_id)>.json`. They bind the exact request,
  original archive digest, manifest root, and migration ID. Do not edit them.
- Incomplete private jobs are discarded on retry and rebuilt. Completed
  verified private bundles are reused. A rename completed before receipt writing
  is recovered from the published bundle. No partial bundle is published.
- A conversion retry after admission returns the already-quarantined endpoint
  only after checking the same tenant's admission receipt and signed manifest.
  This can be selected through `migration.create` again if creation was
  interrupted after admission. A changed endpoint receives a different suggested
  API idempotency key; never reuse an old key with a changed payload. For an
  uncertain API result, first use normal API idempotency/inspection recovery.
- Conflicting request reuse, changed archives, missing admitted evidence, and
  ambiguous state fail closed. Do not delete receipts, rename quarantined
  evidence back, or invent a new migration ID to bypass a conflict.

## Explicit release limits and cleanup

Input compressed and expanded archives are each limited to 2 TiB; expansion
ratio is at most 512; at most 250,000 archive entries are accepted. Captured
metadata is bounded to 16 MiB per member and 64 MiB aggregate. Every emitted
site-content tar, mail-data tar, SQL dump, or certificate chunk is limited to
64 GiB, and total unique referenced chunk bytes to 2 TiB. A SQL gzip is counted
in its compressed archived form. The entire conversion must finish within its
deadline, at most 15 minutes. Capacity, memory, storage, and schema limits can
reject smaller inputs as well.

There is no multipart support: the shared canonical manifest/import code
currently sorts chunk references by digest, so slicing a tar or SQL stream into
ordered pieces would corrupt its meaning. Inputs exceeding the single-artifact
limit remain blocked until that shared content contract is extended. No shell
split/concatenation workaround is part of the supported flow.

After normal target migration cleanup provides evidence, stop the disposable
service, revoke its trust key, and remove its service/configuration/credentials,
binary, raw evidence and converter-owned private scratch/receipts under the
operator's retention policy. Do not remove admitted quarantine bundles before
the normal migration cleanup path authorizes it. Never print archived secrets
or credential files to diagnose a failed conversion.
