# Offline application release inputs

`platform/cmd/application-release` is a Linux release-engineering command. Its
`--input /absolute/release-input.json --output /absolute/panel.tar.gz` interface
assembles a deterministic panel component without downloading or signing.
The output name must not exist. Files are streamed into a private temporary
archive, fsynced, and published atomically without overwriting another release.
The parent output directory must already exist. Relative input paths resolve
beside the input JSON. Reproducibility requires the same inputs, explicit
whole-second `created_at`, and the same Go toolchain/compression implementation.

The input document has these fields (all required):

| Field | Release-provided value |
| --- | --- |
| `catalog_id`, `release_id` | Actual release/catalog identifiers accepted by the existing catalog contract |
| `sequence`, `minimum_epoch` | Positive monotonic catalog sequence and minimum trusted key epoch |
| `created_at` | Actual RFC3339 UTC release timestamp, without fractional seconds |
| `panel_binary` | Existing Linux `cyberpanel` executable built for the target panel release |
| `panel_binary_sha256` | Actual lowercase SHA-256 of that executable; n8n and Hermes images must match its ELF architecture |
| `keys` | Array of `{id, path, minimum_epoch, maximum_epoch}`; public keys only, Ed25519 PKIX PEM or hex |
| `recipes` | Paths to signed PHP version-2 recipe envelopes |
| `artifacts` | Array of `{sha256, path}` for the exact local `.tar.gz` bytes referenced by those recipes |
| `n8n_recipe` | Path to an existing signed `containers.ApplicationRecipe` JSON document named `n8n` |
| `hermes_recipe` | Path to an existing signed `containers.ApplicationRecipe` JSON document named `hermes` |

No private key is accepted. Input digests, product versions, epochs, and dates
must describe the real release. The assembler computes manifest/file digests
from actual bytes; it does not replace mismatching signed metadata. All five
PHP products are required: WordPress, Joomla, PrestaShop, Magento Open Source,
and Mautic. Each definition must satisfy `CertifiedProductContracts`, including
storage, probes, lifecycle, backed-up stores, runtime minimums, PHP extensions,
and databases. Its declared PHP versions must be a nonempty subset of the
product contract; each must support Ubuntu 24.04 and AlmaLinux 9 on amd64 and
arm64 with both OpenLiteSpeed and LiteSpeed Enterprise. Declaring this matrix
does not prove the product was tested on it.

Prepared PHP archives must contain one top-level directory, since runtime
extraction removes that directory. Preserve file timestamps or normalize them
to the actual release timestamp, not Unix time zero: PrestaShop's module loader
treats zero-mtime module files as absent. Hash and sign the prepared tar bytes,
not the original ZIP; its artifact URL must identify those same prepared bytes.

## PHP envelope version 2

The former self-referential format is rejected, not silently migrated.
Release signing must explicitly produce `schema_version: 2` envelopes:

1. Supply the actual definition, recipe metadata (including publish/expiry
   times), product version, and artifact hash/size/URL. Keep
   `definition.recipe.recipe_digest`, `definition.recipe.signature`, and
   `definition.definition_digest` empty in the signed payload.
2. Serialize using `apps.CanonicalRecipePayload(definition)`. These exact Go
   canonical JSON bytes are the payload to sign with Ed25519. Do not indent,
   reorder, or otherwise rewrite them after signing.
3. The envelope `reference` repeats every signed recipe-reference field.
   Set its `recipe_digest` to the lowercase SHA-256 of those exact bytes and
   its `signature` to standard padded base64 of the Ed25519 signature.
4. Set envelope `canonical_payload` and `signature` to the standard padded
   base64 representations of the payload and signature byte arrays (the JSON
   representation of Go `[]byte`). Set `schema_version` to `2`.

Verification binds every reference field, rejects noncanonical/unknown payload
fields, verifies the signature and digest, then hydrates the three excluded
fields. The hydrated definition digest equals the authenticated payload digest.
The assembler never performs these signing steps or manufactures envelopes.

## n8n, Hermes Agent, and installation

n8n uses its existing independent `SignedRecipeVerifier` format, not the PHP
envelope. Its signing key must be among input `keys` and must already be trusted
on the host by `/etc/cyberpanel/containers/recipe-trust.json` or the existing
installer trust loader. Packaging does **not** install new container trust keys.
Unknown/untrusted keys cause installation and startup to fail closed.

The shared `integrations.ValidateN8NApplicationRecipe` contract checks exact
roles, digest-pinned images, private networking, persistent volumes, rootless
workloads, queue workers/webhooks, health route, and secret placeholders. Actual
product/image versions, image digests, resource limits, backup policy IDs,
signature, and signing key are external release inputs. The recipe's `Name`
must be `n8n`; its ID is release supplied. No arbitrary compose import is added.
Digest-pinned n8n/PostgreSQL/Redis images must already be present in the offline
container store; this package does not pull or bundle OCI images. Per-install
secret material must also be enrolled through the protected container-runtime
broker for the derived resource IDs before deployment.

Hermes uses the same independent signed-recipe format and trust loader. Its
contract permits exactly one rootless `gateway` workload, a digest-pinned image,
one private network, one backed-up `/opt/data` volume, a TCP health probe on port
9119, and the exact `gateway run` command. The dashboard username, password, and
session secret are broker references; the HTTPS public URL is derived from the
admitted route and substituted only into the recipe's signed value slot. The
recipe must reserve at least 2 GiB RAM, expose no arbitrary host port, and must
not include a database. Provider API keys are entered inside Hermes and are not
collected by the panel.

The component contains `cyberpanel`, `application-catalog/manifest.json`,
`application-catalog/keys/*.pub`, `application-catalog/recipes/*.json`,
`application-catalog/artifacts/<sha256>.tar.gz`, `container-recipes/n8n.json`,
and `container-recipes/hermes.json`.
It is intended for the panel component, not extraction directly into `/usr`.
The existing installer must authenticate this component through its signed
outer release manifest, with actual component hash/size and member inventory.
This command does not create or sign that outer release manifest.

The root installer validates n8n and Hermes even when reusing an installer receipt. It
provisions the PHP catalog through the existing generation/rollback path.
Panel startup reads both recipes only beside its resolved executable under the protected
`/opt/cyberpanel/slots/.../components/panel` tree, verifies root ownership and
non-writable ancestors, verifies its existing signature, validates the shared
contract, and calls `RegisterRecipe` before serving. A slot rollback selects
that slot's recipe; prior immutable database recipe versions remain available.

## Inputs still required for QEMU verification

Provide real signed version-2 envelopes and actual upstream/prepared archives
for all five PHP products, their trusted public keys/epochs, signed queue-mode
n8n and Hermes recipes with real image digests and trusted host keys, the target
Linux panel binary, and the outer signed release catalog. No such material is embedded in
source. Compilation, deterministic-output checks, negative signature/archive
checks, installer/rollback/startup execution, and product lifecycle verification
in the supported QEMU guests remain required before any certification claim.
