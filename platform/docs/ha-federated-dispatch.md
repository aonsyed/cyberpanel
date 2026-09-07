# Opt-in HA central dispatch

Without `/etc/cyberpanel/ha/federated-dispatch.json`, domain assembly retains
local-only HA behavior. A present invalid configuration fails assembly closed.
This sender uses the existing central operator mTLS API; it does not enroll
nodes, mint grants, sign approvals, or create a new federation protocol.

Provision the following JSON out of band (values below are illustrative):

```json
{
  "endpoint": "https://control.example.net:9443",
  "server_spki_sha256": "64-lowercase-hex-characters",
  "ca_path": "/etc/cyberpanel/ha/operator-ca.pem",
  "client_certificate_path": "/etc/cyberpanel/ha/operator-client.pem",
  "client_key_path": "/etc/cyberpanel/ha/operator-client.key",
  "tenant_id": "system",
  "principal_id": "ha-controller",
  "peer_id": "central_peer",
  "node_grants": {"database_secondary": "grant_secondary"}
}
```

The endpoint must be an HTTPS origin with no path, query, fragment, or userinfo.
CA verification, hostname verification, the leaf public-key SHA-256 pin, and
TLS 1.3 are all required. Redirects, proxies, compression and mutation replay
are disabled. Requests, headers, response bodies and connection counts are bounded.

All referenced files must be regular, single-link, root-owned files under
`/etc/cyberpanel`, with no group/other write permissions. Parent directories must
also be root-owned, non-writable by group/other, and not symlinks. The client key
must not have any other-user permissions; root-owned group-readable key material
can be provisioned for the panel service group. No secrets belong in environment
variables. The current HA dispatcher has system-owned resources, so this adapter
requires the exact `system` tenant rather than translating tenant identities.

The enrolled operator identity needs `node.intent.create`, `intent.inspect`, and
`grant.inspect`. Each configured grant must be active, belong to the exact tenant,
node and peer, and include the exact resource kind/ID and command operation.
Wildcard selectors are intentionally insufficient for dispatch.

Provision `/etc/cyberpanel/ha/federated-approvals.json` as an array of records with
`tenant_id`, `node_id`, `grant_id`, `purpose` (the exact HA command), and `approval`
(an existing `federation.Approval` JSON object). The independently issued approval
must use policy `cyberpanel.ha.federated-dispatch.v1`; its plan digest is obtained
from `ha.FederatedHAApprovalPlanDigest` for the exact canonical draft and grant.
The plan covers tenant, node, grant, command/schema/payload, resource/generation,
idempotency key and risk. Expired, missing or duplicate matching approvals fail
closed. The sender never invents an authorization ID or signature: it preserves
the provided signed approval; the node's existing authority verifier must verify
that approval according to its configured policy before executing the command.

The panel control database records a durable dispatch claim before the single
POST to `/v1/intents`. Once the returned central intent is saved, re-entry and
reconciliation issue GET requests only. Signed receipts are checked against the
central enrollment evidence record returned by GET `/v1/intents/{id}`, including
node/key identity, key state and validity times, and the Ed25519 signature.

A crash or lost response after the POST claim but before saving the central
intent ID is recovered using GET `/v1/intents/lookup` with the original tenant,
node, grant, idempotency key and request digest. The authenticated operator must
have `intent.inspect` and `grant.inspect`; central checks exact grant ownership
and the signed durable intent's plan digest. Multiple matches or changed semantics
are conflicts, not a choice of which effect to adopt. Lookup remains available
for an expired/revoked grant because it cannot authorize new execution.

If central has no matching durable intent (including a crash before POST), the
claim stays reconciliation-required. Later invocations repeat GET lookup only;
they never retry POST or synthesize a receipt. Do not delete the claim or retry
the mutation to resolve uncertainty. Provisioning
the external signed approvals and node authority verifier remains an explicit
deployment prerequisite. Runtime verification is deferred to the requested QEMU
phase; no tests or builds were performed for this coding slice.

## Owning-node HA ingress

The outbound federation runtime composes the HA ingress only after the domain's
local MariaDB gate/promotion and OLS listener providers exist. Without protected
`/etc/cyberpanel/ha/federated-ingress.json`, the runtime advertises no HA mutation
capabilities. That configuration contains `tenant_id` (`system`), the exact
enrolled `node_id` and `peer_id`, `group_id`, an explicit `grant_ids` array, and
`grant_keys`/`approval_keys` maps from signing key IDs to base64 Ed25519 public
keys. It follows the same root-owned, no-symlink file rules as sender configuration.
Key material is re-read for each authorization; no private authority key is loaded.

The independently provisioned mutation grant must be present in the node's
existing federation store and match the current peer epoch. Compute its digest
with `ha.FederatedHAGrantDigest`, then sign
`ha.FederatedHAGrantSignaturePayload` with the separately held grant authority key.
Purpose approvals use `ha.FederatedHAApprovalSignaturePayload`; their plan digest
remains the exact sender plan described above. These helpers define bytes only:
neither panel nor node manufactures approval, grant, quorum, or fence evidence.

All eight existing HA commands have closed decoders. Arbitrary command types,
unknown payload fields, wildcard grant scope and resource/target substitutions are
denied. The original signed intent is reloaded from the federation acceptance
store before gateway execution. After exact enrolled-target/group membership
checks, only the owning node is mapped to the local executor's fixed `local`
alias; the signed payload and its approval digest are unchanged. OLS observation
digests are projected to that alias internally, then the signed node receipt binds
the original requested result digest after the local provider confirms the effect.

Local HA domain admission remains required: group/member/cluster records,
matching promotion and policy generations, and—before activating writes or
listeners—the exact admitted writer lease and all required proven fences for the
previous writer. The federation transport does not replicate or invent these
records. Missing or stale local domain authority fails closed.

An owning-node file lock serializes HA ingress effects across runtime recomposition
and processes. A per-resource fence high-water/blocked-token record and effect
claim are committed before a local effect; stale or blocked-token activation is
denied. Terminal results are stored only after the existing provider confirms
success. Replay reads that result and never calls a mutation provider again.
A crash after the local effect but before its result is saved remains ambiguous;
the adapter does not infer effect attribution from a generally healthy database
or rerun a write. This coding slice has not been built or runtime-verified.
