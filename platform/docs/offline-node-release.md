# Signed offline node releases

`platform/cmd/node-release` and `platform/cmd/panel-node-install` are the closed
release-engineering and node-side halves of the initial node release path. They
do not fetch, resolve, or build anything. Release engineering supplies already
built Go/tool binaries, rendered non-secret configs and units, and the complete
set of target-native OS packages. The node consumes only those signed bytes.
Their bootstrap artifact definitions are
`platform/packaging/artifacts/node-release.bundle.json` and
`platform/packaging/artifacts/panel-node-install.bundle.json`.

## Fixed paths and bundle layout

Run `panel-node-install paths` on a node to print the authoritative paths:

| Purpose | Path |
| --- | --- |
| trusted Ed25519 public-key documents | `/etc/cyberpanel/node-release/trust.d/*.json` |
| highest fully verified admission | `/var/lib/cyberpanel/node-release/admission-frontier.json` |
| durable installed frontier | `/var/lib/cyberpanel/node-release/installed.json` |
| effect journals | `/var/lib/cyberpanel/node-release/journal/*.json` |
| private verified staging | `/var/lib/cyberpanel/node-release/staging/<manifest-sha256>` |
| immutable retained releases | `/opt/cyberpanel/node-releases/<manifest-sha256>` |
| atomic active-generation link | `/opt/cyberpanel/node-current` |

The deterministic uncompressed tar has exactly this order and no optional
members:

```text
release.json
payload/<first artifact id in install_order>
payload/<second artifact id in install_order>
...
```

`release.json` contains the canonical manifest, signing key ID, and a raw-base64
Ed25519 signature over the canonical manifest JSON. The manifest binds the
release ID and monotonic sequence, product version and schema, exact target,
fresh-install permission, minimum/maximum source version and schema, every
payload digest/size/owner/mode/destination, install order, required service
probes, validity window, and rollback policy. Package entries additionally bind
the manager, package name, version, and native architecture reported by the
package itself.

The only accepted targets are:

- `ubuntu/24.04/noble/amd64` and `ubuntu/24.04/noble/arm64`
- `almalinux/9/el9/amd64` and `almalinux/9/el9/arm64`

## Assemble from prebuilt local inputs

The spec names files relative to one canonical source root. Modes are four-digit
octal strings. Runtime files are root-owned in this v1 contract: binaries are
`0555` or `0755`, non-secret configs are `0444` or `0644`, systemd units are
`0644`, and package payloads are `0600`. A representative artifact section is:
Package IDs must form the first contiguous part of `install_order`; files follow
in their exact materialization/link order.

```json
{
  "schema_version": 1,
  "signing_key_id": "node-release-2026",
  "release_id": "cyberpanel-3.1.0-ubuntu-noble-amd64",
  "sequence": 42,
  "product_version": {"major": 3, "minor": 1, "patch": 0},
  "product_schema": 17,
  "target": {"distribution": "ubuntu", "release": "24.04", "codename": "noble", "architecture": "amd64"},
  "fresh_install": true,
  "upgrade_source": {"minimum": {"major": 3, "minor": 0, "patch": 0}, "maximum": {"major": 3, "minor": 1, "patch": 0}},
  "source_schema": {"minimum": 15, "maximum": 17},
  "artifacts": [
    {"id": "panel-execd", "kind": "binary", "source": "bin/panel-execd", "destination": "/usr/local/libexec/cyberpanel/panel-execd", "uid": 0, "gid": 0, "mode": "0755"},
    {"id": "panel-core-config", "kind": "config", "source": "config/panel-core.json", "destination": "/etc/cyberpanel/panel-core.json", "uid": 0, "gid": 0, "mode": "0644"},
    {"id": "panel-core-unit", "kind": "systemd_unit", "source": "systemd/panel-core.service", "destination": "/etc/systemd/system/panel-core.service", "uid": 0, "gid": 0, "mode": "0644"},
    {"id": "runtime-deb", "kind": "os_package", "source": "packages/runtime_1.0.0_amd64.deb", "uid": 0, "gid": 0, "mode": "0600", "package": {"manager": "dpkg", "name": "runtime", "version": "1.0.0", "architecture": "amd64"}}
  ],
  "install_order": ["runtime-deb", "panel-execd", "panel-core-config", "panel-core-unit"],
  "services": [{"unit": "panel-core.service", "timeout_seconds": 60}],
  "rollback": {"strategy": "retain_previous_release", "retain_previous": true, "reinstall_packages": true, "minimum_retained": 1, "activation_probe_window_seconds": 300},
  "issued_at": "2026-09-19T00:00:00Z",
  "expires_at": "2026-09-26T00:00:00Z"
}
```

Real release specs contain every required component, not only the four example
entries. For AlmaLinux use manager `rpm` and package architecture `x86_64` or
`aarch64`. Assemble without a network namespace or package repository:

```sh
node-release assemble \
  --spec /srv/releases/cyberpanel-3.1.0/node-release-spec.json \
  --source-root /srv/releases/cyberpanel-3.1.0/ubuntu-noble-amd64 \
  --private-key /srv/release-authority/node-release-2026.hex \
  --output /srv/releases/out/cyberpanel-3.1.0-ubuntu-noble-amd64.tar
```

The private-key file is a mode-0600 hex Ed25519 seed or private key. It is read
separately, is not beneath the runtime release layout, and is never archived.
Config/unit inputs containing private-key, password, token, machine-ID, SSH host
key, node-ID, or host-identity markers are rejected. Destinations beneath secret
or identity paths are also outside the closed manifest grammar. Host-local TLS,
credentials, node enrollment, enterprise licenses, and other secrets must be
provisioned independently after release activation.

## Provision trust and install
Each trust document is root-owned, not group/other writable, and has this strict
shape. `public_key` is 32-byte lowercase Ed25519 hex; the sequence range is an
additional offline signing frontier.

```json
{
  "schema_version": 1,
  "key_id": "node-release-2026",
  "public_key": "<64 lowercase hex characters>",
  "not_before": "2026-01-01T00:00:00Z",
  "not_after": "2027-01-01T00:00:00Z",
  "minimum_sequence": 1,
  "maximum_sequence": 1000
}
```

Copy the bundle to a root-owned, singly linked, regular file with no group/other
write permission, then run:

```sh
/usr/local/sbin/panel-node-install apply --bundle /var/tmp/cyberpanel-node-release.tar
/usr/local/sbin/panel-node-install status
```

Before the first package or active-path mutation, the installer verifies the
signature and expiry, target tuple, installed anti-rollback/source frontier,
tar inventory, every byte digest/size, embedded package metadata, and all future
managed destinations. Ubuntu packages are applied only with local `dpkg`; Alma
packages only with local `rpm`. There is no apt, dnf, curl, HTTP client, mirror,
or download fallback. Package installation and scriptlets run in a new network
namespace, so a signed package cannot silently resolve a runtime dependency.

All active binaries/configs/units are stable symlinks through
`/opt/cyberpanel/node-current`. One atomic rename changes that generation.
Systemd is reloaded, each signed unit is restarted, and a new monotonic start
observation is required. Only then is the installed frontier committed. The
prior immutable generation and its exact packages remain available. A failure
reinstalls prior packages, flips the active link back, reloads systemd, and
probes the prior services before recording `rolled_back`.

Each manifest has the stable operation identity
`install-SHA256("cyberpanel-node-release-operation-v1\n" + manifest_digest)`.
Each package/link/activation/probe effect has a similarly domain-separated ID.
The journal writes `started` before an effect and `completed` after observation,
using fsync plus atomic rename. Re-running `apply` or running `reconcile` resumes
idempotent pre-activation effects; an observed exact candidate is freshly
probed, and an uncertain or failed activation is restored or left explicitly
`recovery_required` with the journal path in the error. Enable the packaged
`panel-node-release-reconcile.service` so incomplete journals are examined on
boot. The reconciler uses the same exclusive installer lock and re-observes the
active generation and service state before continuing any effect.

The bootstrap `panel-node-install` executable and reconcile unit must already be
installed from the trusted node image or an operator-delivered bootstrap
package. They deliberately live outside the active generation link so they
remain executable while a first activation is absent or being rolled back.
Release signing trust, the root-owned bundle, and host-local secrets/identity
enrollment are the remaining operator-provided inputs. Retain historical public
key documents for every retained previous release so its signature can be
reverified during automatic rollback.
