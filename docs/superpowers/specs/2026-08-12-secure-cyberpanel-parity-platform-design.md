# Secure CyberPanel-Parity Hosting Platform

## Greenfield architecture, functional specification, security model, federation protocol, migration system, and AI engineering factory

| Metadata | Value |
|---|---|
| Status | Architecture baseline; normative pre-implementation design under review and Gate 0 qualification |
| Baseline | CyberPanel commit `d44f57a3c91834999a0d8b0324eadda5e269e783` (2026-08-10) |
| Date | 2026-08-12 |
| Web engines | OpenLiteSpeed and LiteSpeed Enterprise |
| Primary implementation | Go control plane and host components; Vue 3 strict-TypeScript UI |
| Compatibility policy | Functional parity only; no legacy route, model, schema, file-layout, wire, CLI, or bug compatibility |
| Explicit exclusion | Apache is not a runtime, backend, fallback, migration target, dependency, or qualification cell |
| GridPane policy | CyberPanel defines baseline availability. The adjacent GridPane server-scripts corpus contributes implementation depth and post-parity additions only |

---

## 0. How to read this specification

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

This document is the product and engineering contract for a new hosting control platform. It is not a proposal to refactor CyberPanel. It defines:

1. the complete functional outcome surface that must remain available;
2. a new domain and persistence model;
3. a standalone-first node runtime and narrow privilege boundary;
4. native sibling adapters for OpenLiteSpeed and LiteSpeed Enterprise;
5. safe failure, retry, rollback, reconciliation, and disaster-recovery semantics;
6. optional central federation without a second local writer;
7. one-way disposable migration from CyberPanel and cPanel;
8. an AI-built and AI-maintained engineering factory;
9. an executable definition of parity and general availability;
10. GridPane-derived operational lessons and later enhancements.

Implementation is conformant only when the executable parity ledger described in Section 28 binds every shipped outcome to contracts, permissions, implementation, tests, migration, documentation, telemetry, support-matrix evidence, and a signed release artifact.

### 0.1 Normative hierarchy

When sections appear to conflict, apply this order:

1. security and data-integrity invariants;
2. explicit user decisions in this document;
3. functional-parity requirements;
4. domain and protocol contracts;
5. delivery sequencing and implementation guidance;
6. non-normative rationale and examples.

An implementation MAY change an internal technology when it preserves all normative outcomes and passes the same gates. It MUST NOT weaken an invariant to preserve an internal choice.

### 0.2 Meaning of functional parity

Functional parity means that a user, reseller, administrator, operator, automation client, or optional central controller can achieve every meaningful active CyberPanel outcome that this specification classifies as required or securely redesigned.

Functional parity does not require:

- retaining Django, Python, CyberPanel tables, integer ownership trees, routes, payloads, CLI spelling, file paths, shell scripts, templates, or UI arrangement;
- importing live CyberPanel runtime code;
- reproducing an insecure mechanism when a safer workflow delivers the same legitimate result;
- reproducing dormant, unreachable, promotional, vendor-billing, or telemetry-only behavior;
- retaining defects, false-success responses, unsafe defaults, races, or data-loss behavior.

No active outcome may disappear merely because its existing implementation is insecure, obscure, cloud-only, provider-backed, premium-labelled, or broken. It receives a working implementation, a secure redesign, or an explicit approved disposition.

### 0.3 Document map

- [1. Product mandate and locked decisions](#1-product-mandate-and-locked-decisions)
- [2. Baseline, evidence, and disposition](#2-baseline-evidence-and-disposition-method)
- [3–9. Principles, architecture, resource model, runtime, operations, and surfaces](#3-architectural-principles-and-invariants)
- [10. OLS/LSE, sites, PHP, routing, and deployments](#10-web-engines-sites-php-routing-and-deployments)
- [11–19. DNS/TLS, database, access, backup, mail, apps, containers, security, and operations](#11-dns-and-certificates)
- [20. Optional central federation and HA](#20-optional-central-federation-fleet-operations-and-ha)
- [21. Disposable migration/import](#21-disposable-one-way-migration-and-import)
- [22. Complete functional-parity catalog](#22-complete-functional-parity-catalog)
- [23. Provider and disposition matrices](#23-provider-commitments-and-explicit-disposition-matrix)
- [24. Threat model and formal invariants](#24-threat-model-security-claims-and-trust-boundaries)
- [25. Exact support matrix and Gate 0](#25-support-matrix-and-feasibility-gate-0)
- [26. Performance and capacity](#26-performance-capacity-fairness-and-reliability-budgets)
- [27. AI engineering factory and supply chain](#27-ai-engineering-factory-code-architecture-supply-chain-and-releases)
- [28. Machine-executable parity ledger](#28-machine-executable-parity-and-evidence-ledger)
- [29. Delivery sequence and stage gates](#29-delivery-sequence-and-stage-gates)
- [30. GridPane depth and post-parity roadmap](#30-gridpane-depth-corpus-and-post-parity-roadmap)
- [31. Objective parity-GA evidence](#31-objective-parity-ga-evidence-and-completion-audit)
- [32. Resource/permission/secret/audit/provider schemas, decisions, risks, and glossary](#32-canonical-registries-schemas-decisions-risks-and-glossary)

### 0.4 Executive recommendation

Build a new product, not a CyberPanel rewrite. Use one Go modular-monolith codebase split at runtime into a minimal public `panel-gateway`, local authority/domain `panel-core` (`paneld` package boundary) with one prioritized SQLite writer, and narrowly scoped helpers; use a Vue 3 strict-TypeScript client and generated OpenAPI/Connect/Protobuf contracts. Model user intent as typed resources and durable operations; never expose a generic root command. Run all tenant code as its site UID/cgroup or inside its constrained container. Render complete native configurations from canonical state through separate OpenLiteSpeed and LiteSpeed Enterprise adapters with staged validation, probes, and reboot-safe rollback.

The node remains fully authoritative and useful on its own. An optional self-hostable central plane receives sanitized projections and sends expiring signed intents over an outbound-only node connection; the node reauthorizes and executes them locally. Multi-node HA uses central fleet plans but requires topology-specific fencing and never shares the node SQLite database.

Treat CyberPanel solely as an outcome checklist and prove closure through the executable ledger. Implement one complete site vertical slice on OLS and real licensed LSE early, then expand through data, DR, security, applications, mail, containers, providers, migration, and federation. Treat GridPane as a later operational-depth corpus. Import old systems only through disposable one-way extractors into a signed source-neutral manifest and clean target.

AI agents can author and maintain nearly the entire codebase, tests, documentation, migration logic, and release candidates, but they do not own production credentials, approve their own evidence, or hold release/recovery trust roots. Stable release requires deterministic multi-layer evidence, exact OS × engine qualification, clean restore/migration rehearsals, independent review, reproducible signed artifacts, canaries, and a human threshold ceremony.

---

## 1. Product mandate and locked decisions

### 1.1 Product mandate

The product MUST:

- keep installed local hosting, administration, scheduling, reconciliation, recovery, DNS, database, mail, and security functions usable without a central plane or Internet path; explicitly external functions MUST enter `ExternalDependencyUnavailable` or `WaitingExternal`, and LiteSpeed Enterprise offline behavior is limited to its certified vendor license contract;
- allow optional connection to a central control plane without transferring local state authority;
- provide OpenLiteSpeed and LiteSpeed Enterprise as first-class, separately qualified engines;
- provide the full CyberPanel outcome surface listed in Section 22;
- be secure by construction at its root, tenant, file, terminal, database, container, provider, update, backup, migration, and federation boundaries;
- remain observable, recoverable, idempotent, and honest under partial failure;
- expose common domain operations through consistent local UI, API, and CLI surfaces;
- be buildable and maintainable primarily by AI while retaining non-AI cryptographic trust roots and independent evidence gates;
- use the GridPane corpus to deepen implementation quality after CyberPanel establishes scope;
- produce machine-verifiable evidence for every parity and release claim.

### 1.2 Locked architectural decisions

| Decision | Normative choice |
|---|---|
| Architecture | Standalone modular monolith plus narrow local helpers; no per-host microservice mesh |
| Primary language | Go for panel-gateway, panel-core/paneld, panel-execd, panelctl, federatord, brokers, and initial workers |
| UI | Vue 3 with strict TypeScript and generated clients |
| Contracts | Protobuf plus ConnectRPC for internal typed RPC; versioned JSON/OpenAPI for public HTTP API |
| Local control state | Bundled, pinned SQLite on local ext4/XFS; one prioritized writer |
| Central state | PostgreSQL; central stores projections, intents, sagas, identities, and central audit |
| Privileged execution | Root-owned local Unix-domain services with typed closed operations; no generic command execution |
| Web engines | Native OpenLiteSpeed text renderer and native LiteSpeed Enterprise renderer |
| Apache | Absent everywhere except migration evidence and negative tests |
| Site isolation | Dedicated site UID/GID, cgroup v2, filesystem/project quota, service-specific limits |
| Containers | Admin rootful tier plus measured managed rootless/user-namespace tenant tier |
| Backups | Product manifest/catalog over verified encrypted repository adapters; Restic is the initial object engine |
| Extensions | Signed capability-scoped WASM and rootless OCI tiers; no in-process source patching |
| Migration | Disposable source extractors to a source-neutral signed manifest; no runtime compatibility |
| Federation | One outbound node connection; local node remains sole resource writer |
| AI engineering | AI authors candidates; deterministic evidence and threshold human trust roots authorize stable release |

### 1.3 Explicit exclusions

The following MUST be absent and covered by negative tests:

- Apache installation, runtime, proxy backend, configuration generator, engine switch, migration target, support claim, or fallback;
- Nginx as a baseline runtime or backend;
- browser root shell;
- default administrator credentials;
- password-authenticated automation endpoints;
- static all-powerful user or node tokens;
- generic privileged shell, command, argv, unit, package, path, UID, environment, or configuration-write RPC;
- direct web-process access to Docker or other privileged runtime sockets;
- shared reusable database-administration passwords;
- unauthenticated or query-string deployment webhooks;
- arbitrary global CSS, JavaScript, or remote executable themes;
- source-patching, in-process plugins with root lifecycle scripts;
- mutable-branch self-update and curl-to-shell installation;
- proprietary billing gates around local functionality;
- silent vendor telemetry;
- hidden best-effort downgrade of required features.

### 1.4 Securely preserved administrative outcomes

Dropping an unsafe mechanism does not drop the legitimate outcome:

- Root file administration becomes an expiring step-up HostFilesystemSession with typed descriptor-relative operations.
- Root process administration becomes scoped ProcessAction using PID, boot ID, and process start time or pidfd.
- Package administration becomes planned signed-repository maintenance with impact, receipt, verification, and honest irreversibility.
- Customer-context support becomes an expiring support grant that preserves the real actor; it never forges the customer session.
- Database administration becomes a short-lived scoped database workspace; no permanent phpMyAdmin root bridge is required.
- Application hooks remain possible as site-UID commands inside the site boundary; privileged automation has no shell-string operation.
- Container exec remains possible as an audited short-lived container session; it cannot become a host root session.

---

## 2. Baseline, evidence, and disposition method

### 2.1 Authoritative baseline

CyberPanel commit `d44f57a3c91834999a0d8b0324eadda5e269e783` is the initial availability baseline. Evidence sources include:

- active URL routing and view handlers;
- cloud API dispatch branches;
- CLI command dispatch;
- model-backed UI and persisted resources;
- scheduled jobs and workers;
- installer and upgrade workflows;
- documented operator actions;
- effective daemon-management code;
- provider-specific controllers;
- active site, mail, backup, application, security, and container surfaces.

Route, model, and CLI inventories are traceability evidence, not compatibility requirements.

### 2.2 Disposition classes

Every baseline inventory item MUST map to at least one outcome with exactly one disposition:

- **ga_parity** — same user outcome delivered by the new design;
- **secure_redesign** — same legitimate outcome through a materially safer workflow;
- **drop** — intentionally absent, requiring product and security approval plus negative tests;
- **post_ga** — non-baseline addition committed for later delivery; an active CyberPanel outcome MUST NOT use this disposition;
- **inactive_baseline** — proven unreachable or non-product evidence, with route/job/CLI/documentation reachability evidence.

### 2.3 Provider identity rule

Provider parity is judged as follows:

1. A provider interface without a working implementation is not functionality.
2. A named destination or account explicitly selected by users normally requires that named adapter.
3. A vendor whose identity is incidental MAY be replaced by another working implementation that provides the complete observable journey.
4. Provider-specific policy that cannot be represented exactly MUST fail closed and report the limitation.
5. No optional provider may be required for unrelated standalone operation.

Named GA adapters include Cloudflare DNS, Google Drive backup, SFTP, AWS S3, DigitalOcean Spaces, MinIO, generic S3-compatible storage, LiteSpeed Enterprise licensing, Docker Hub, and Imunify BYOL integration. CyberMail, CyberPanel-hosted backup, and CyberPanel's scanner vendor may be substituted only when a named working equivalent outcome ships.

### 2.4 GridPane scope rule

The adjacent GridPane server-scripts corpus MUST NOT:

- add a prerequisite to CyberPanel parity;
- redefine a CyberPanel outcome;
- turn Nginx or Apache into a baseline engine;
- delay GA through unrelated additional features;
- introduce its command syntax, global state, shell conventions, or file layout.

It MAY:

- reveal hidden operational phases and checks for an already-required outcome;
- improve health, migration, rollback, update, dependency, scheduling, and WordPress semantics;
- contribute separate post-parity provider adapters, policy packs, database engines, storage systems, and automation.

---

## 3. Architectural principles and invariants

### 3.1 Core principles

1. **One local authority.** The node owns its resource state and host mutations.
2. **Intent, not command.** Callers request typed outcomes; only local reconcilers choose host effects.
3. **Least privilege by construction.** Unprivileged components cannot express arbitrary privileged effects.
4. **Desired and observed state are separate.** A successful request means accepted work, not observed completion.
5. **Every side effect is reconcilable.** Timeout is ambiguity, never proof of failure.
6. **Configuration is generated, staged, validated, activated, probed, and recoverable.**
7. **No silent degradation.** Unsupported, constrained, stale, and unavailable are visible states.
8. **Tenant boundaries are resource boundaries.** Accounts do not own host data directly.
9. **Secrets are capabilities.** They are purpose-bound, versioned, encrypted, redacted, and delivered just in time.
10. **Recovery is a feature.** Destructive work has a declared recovery point or irreversible frontier.
11. **Offline is normal.** Local control and scheduled safety work remain functional without central or provider connectivity.
12. **Evidence outranks assertion.** Parity, security, performance, and release claims derive from executable proof.

### 3.2 Non-negotiable security invariants

- panel-gateway and panel-core MUST run under separate dedicated unprivileged UIDs with no sudo, root group, Docker socket, shadow data, host private keys, writable executables, or writable privileged configuration; the gateway has no authority-store/helper access.
- panel-execd MUST listen only on a root-owned local Unix socket and verify peer credentials.
- Privileged request types MUST be closed, versioned structures with unknown-field rejection.
- The executor MUST independently resolve opaque IDs to root-owned registry records and reject caller-supplied host identities and paths.
- Site file operations MUST be descriptor-relative beneath pre-opened roots and use openat2 containment where supported.
- Archive extraction MUST reject traversal, escaping links, devices, FIFOs, capabilities, unsafe ACL/xattr state, duplicate paths, and resource bombs.
- A browser terminal MUST never be a root terminal.
- Container workloads MUST NOT receive privileged mode, host namespaces, host devices, runtime sockets, arbitrary host mounts, or unconfined security profiles through tenant authority.
- Configuration activation MUST retain a reboot-persistent last-known-good generation and rollback lease.
- Durable work MUST use idempotency keys, resource locks, desired-state generations, and monotonic fencing tokens.
- Secret plaintext MUST NOT appear in URLs, argv, environment dumps, logs, audit payloads, crash reports, or API responses after enrollment.
- Updates MUST be pinned, signed, provenance-checked, rollback-protected, and independently verified.
- Cross-tenant resource identifiers MUST reveal neither existence nor content to unauthorized actors.

### 3.3 Honest guarantee language

The product MUST distinguish:

- transactional database acceptance from non-atomic host effects;
- application-binary rollback from OS, package, database-format, or schema irreversibility;
- local tamper evidence from immutability against root;
- a verified backup copy from a successfully restored recovery point;
- pre-exposure automatic rollback from post-write fail-forward recovery;
- an available adapter contract from a configured and tested provider;
- advisory AI classification from independently confirmed security evidence;
- local reachability from externally observed reachability.

---

## 4. System context

~~~mermaid
flowchart TB
    subgraph Clients
        UI["Local web UI"]
        CLI["panelctl CLI"]
        API["Local public API"]
        CPUI["Optional central UI/API"]
    end

    subgraph Node["Autonomous hosting node"]
        GW["panel-gateway<br/>TLS + HTTP/UI parsing only"]
        PD["panel-core<br/>authz + state writer + scheduler + reconciler"]
        DB[("control.db<br/>SQLite")]
        ST["site-taskd<br/>typed site process launcher"]
        SW["site-worker pools<br/>site UID/cgroup"]
        SB["secret-broker<br/>purpose-bound decrypt/JIT delivery"]
        AV["auth-verifier<br/>TOTP/recovery verification + signed assurance"]
        AB["approval-broker<br/>separate high-risk transaction confirmation"]
        AW["audit-writer<br/>prepared append-only segments + checkpoints"]
        PS["provider-supervisor<br/>durable admission + receipt authority"]
        PW["provider-worker pools<br/>one scoped external action"]
        EX["panel-execd<br/>node-critical typed root operations"]
        CB["container-broker"]
        RW["rollback-watchdog"]
        FD["federatord<br/>outbound only"]
        OBS["journald + bounded TSDB + artifacts"]
        ENGINES["OpenLiteSpeed or<br/>LiteSpeed Enterprise"]
        SERVICES["MariaDB, PowerDNS, mail,<br/>FTP, security, optional services"]
    end

    subgraph Central["Optional central plane"]
        CAPI["Central API and identity"]
        PG[("PostgreSQL")]
        ORCH["Fleet saga orchestrator"]
        RELAY["Encrypted interactive relay"]
    end

    EXT["External providers<br/>DNS, ACME, storage, mail, registry, scanner"]

    UI --> GW
    CLI --> GW
    API --> GW
    GW -->|"closed local application protocol"| PD
    PD --> DB
    PD --> ST
    PD --> PS
    PS --> PW
    PD --> SB
    PD --> AV
    PD --> AB
    PD --> AW
    AV --> AB
    SB --> PW
    PW <-->|"bounded authenticated provider protocols"| EXT
    SB --> ST
    SB --> EX
    AB --> EX
    ST --> SW
    PD --> EX
    PD --> CB
    PD --> RW
    PD --> OBS
    SW --> ENGINES
    EX --> ENGINES
    EX --> SERVICES
    CB --> SERVICES
    FD --> PD
    FD <-->|"outbound mTLS stream"| CAPI
    CAPI --> PG
    CAPI --> ORCH
    CPUI --> CAPI
    RELAY <--> FD
    TAC["Separately trusted approval/enrollment client"] -->|"E2E canonical transaction/enrollment channel"| AB
    TAC -->|"E2E TOTP/recovery/WebAuthn enrollment"| AV
~~~

### 4.1 Node components

The recommended implementation remains one Go modular-monolith repository and release, but the network edge and authority core are separate OS processes.

**panel-gateway** is the only normal public panel listener. It terminates TLS, serves immutable UI assets, parses bounded HTTP/WebSocket/API frames, enforces origin/CSRF and coarse unauthenticated rate/size/deadline policy, and forwards a closed canonical request over a peer-verified local channel. It has no control.db, helper/broker socket, signing/wrapping key, provider credential, or site/root file access. It cannot mint a session, grant, TaskEnvelope, resource generation, or audit result.

**panel-core** (the authority component called `paneld` in package/API names) owns local application services, sessions/authentication, authorization, the sole control.db write coordinator, durable operation acceptance, scheduling, desired-state reconciliation, provider coordination, event outbox, and sanitized local projections. It re-parses and validates the canonical request, credential/session, CSRF token, idempotency, resource generation, quota, and policy; it never trusts a gateway allow result. It has no public listener, secret master key, arbitrary provider traffic, raw root shell/systemd/package socket, or container-runtime daemon socket; it can reach only the closed typed helper/broker sockets defined here.

Compromise of panel-gateway exposes and can steal/replay credentials or sessions traversing it and can act with those principals, in addition to attempting malformed requests; it cannot directly rewrite authority state or forge independent high-risk transaction confirmation. Peer IP, TLS-client identity, connection and browser Origin are marked `gateway_attested` after TLS termination and are never the sole authorization factor. Where transport proof is required, the request binds to a passed socket identity or per-connection TLS exporter/channel token that the relevant protected verifier can check. panel-core independently verifies credential/session, CSRF token, and canonical request digest, but source-CIDR/session-IP/origin defenses are honestly considered lost under gateway compromise. Compromise of panel-core is total compromise of control-state/RBAC/application audit and enables product-level cross-tenant operations within typed helper boundaries; it does not by itself create a generic root primitive, bulk secret decrypt, independent high-risk approval, or unrestricted rootful runtime access. The threat model and tests use this honest boundary.

**panel-execd** owns node-critical privileged effects: identity allocation, root-owned configuration generations, service activation, firewall, SSH, panel listener, package transactions, mount and quota setup, and other enumerated handlers.

**site-taskd** is a minimal root-owned launcher. It accepts only a registered TaskEnvelope, resolves the generationed site identity/profile and signed worker binary from its own protected taskd registry projection populated through typed generationed registration, creates the cgroup/namespaces, drops credentials/capabilities, passes validated task data by inherited descriptor, and owns pidfd cancellation/receipts. It never reads or writes execd.db.

**site workers** run file, Git, application, build, cron, scanner, import, and terminal work as the site UID within the site resource envelope. They cannot choose their own UID, root, executable, or isolation profile.

**secret-broker** holds the local wrapping-key capability. It accepts one purpose/resource/operation-bound delivery grant, independently resolves the allowed consumer, unwraps one version, and delivers it by sealed memory/file descriptor or a provider-native channel. It has no Internet listener and no bulk-export operation.

**auth-verifier** owns TOTP seed/recovery-code verification, WebAuthn credentials/counters/challenges/backup/UV state, authenticator policy epochs, a distinct TOTP seed-wrapping key, and its separate protected assurance-signing key. panel-core submits a rate-limited challenge bound to installation, principal, session or transaction, nonce, requested assurance, authorization epoch, RP/origin/channel, and expiry; the verifier returns only a signed yes/no assurance result. It exposes no post-enrollment/admin seed read/list/export and never delivers TOTP material to panel-core. WebAuthn verification enforces exact RP ID/origin, user verification, challenge/purpose binding, signature counter/backup policy, credential state, and replay. Recovery codes are verifier-only hashes and single-use state.

Authenticator enrollment/reset/revocation uses a closed verifier protocol. Initial local installation claim is the only bootstrap exception. Later enrollment requires current independent assurance; reset/recovery or approver/recovery-root change requires the existing independently approved recovery/threshold policy. panel-core cannot select an attacker public key/seed or lower policy without a verifier-issued registration challenge and protected-channel confirmation. Every change increments credential/approver/policy epochs and invalidates outstanding assurances and CommitAuthorizations.

For TOTP enrollment, auth-verifier generates the seed internally and releases it exactly once through the same separately trusted client/protected approval channel used for transaction confirmation, bound to principal, enrollment ID, expected issuer/account label, expiry, and verifier nonce. Normal panel pages may initiate and relay but cannot read the seed in the gateway/core-compromise-resistant mode. The user proves one code before activation; unconfirmed seeds expire and are destroyed. Recovery-code creation similarly returns raw codes once through that channel while authn.db stores only salted verifier state and per-code consumption. A deployment choosing ordinary panel-web delivery declares gateway/core inside the enrollment trust boundary and cannot claim resistance to their compromise.

**approval-broker** is a separately protected transaction-confirmation path for high-risk commits. It owns protected approver identities, trust/policy/recovery epochs, and reads an executor-registered closed plan/digest. A true independent channel—separately signed/pinned panelctl or desktop helper, hardware authenticator with transaction confirmation, or a separately terminated/pinned approval origin whose keys and content are not controlled by panel-gateway/panel-core—retrieves the broker-rendered canonical transaction text/digest end to end. The authenticator signs/confirms that exact digest, target, effect/frontier, and expiry; gateway/core may relay ciphertext but cannot substitute display content. approval-broker then signs one expiring CommitAuthorization that panel-execd consumes in execd.db. A generic TOTP/WebAuthn presence assertion through the normal panel page is authentication assurance, not independent transaction approval. It is not a general authorization service or substitute for panel-core RBAC.

**audit-writer** owns the append-only audit segments and checkpoint-signing key. Before a security-relevant mutation, panel-core sends a canonical body with stable event ID/digest; audit-writer durably records `Prepared`. The control.db transaction then commits the mutation, same ID/digest reference, and outbox state. Audit-writer observes that committed reference and finalizes the event into the hash chain; recovery finalizes prepared+committed pairs and discards/records expired prepared orphans without claiming the mutation occurred. panel-core retains the canonical body in its durable outbox until matching finalize acknowledgement, so either side can reconstruct a crash gap. Safety rollback/recovery uses a preallocated emergency audit lane with the same protocol; there is no unaudited bypass.

**provider supervisor and workers** split durable authority from network parsing. A dedicated no-network supervisor UID owns provider-effects.db, persists one typed action before launch, resolves adapter/destination policy, and validates worker observations; it has no secret plaintext, control.db write, root/helper authority, or external provider socket. Short-lived or tightly pooled unprivileged workers execute one typed provider action against declared endpoints, receive only bounded input and necessary secret versions, cannot read/write provider-effects.db, have no control.db/helper authority, and return untrusted bounded observations. The supervisor correlates, verifies, observes ambiguity where necessary, and persists the authoritative provider receipt.

**container-broker** is the only process permitted to access the selected container runtime API. It applies workload policy independently of panel-core.

Rootful and tenant/rootless brokers are separate processes, UIDs, sockets, registries, journals, and runtime endpoints. The rootful broker is host-root-equivalent; its compromise is host compromise. The tenant broker cannot address the rootful runtime.

Broker RPC is a closed versioned UDS protocol with SO_PEERCRED and bounded frames/deadlines. Requests carry command/operation/grant, opaque workload/image/volume/network/exposure IDs, expected registry generations, image digest and policy result, idempotency/effect ID, fence, expiry, and—where rootful/high-risk—a valid CommitAuthorization. The broker independently resolves all objects in its generationed registry. It accepts no raw Docker/OCI JSON, Compose, host path, daemon method, arbitrary network, or caller-chosen runtime endpoint.

The broker records effect acceptance before the runtime call and stores bounded observations/receipts afterward. Timeout is reconciled by runtime object identity/labels and effect ID; duplicates return the original receipt; stale/replayed generations/fences reject. Rootful mutation without current high-risk approval fails closed. Container deletion/exposure/volume effects use tombstones, observation, and delayed reuse just like executor resources.

**rollback-watchdog** owns the minimal reboot-persistent mechanism needed to restore the previous configuration or access path when activation is not confirmed.

Only panel-execd may arm rollback-watchdog, and only after it independently validates both the current and candidate generations. The arming record is fsynced and contains lease ID, handler/resource and registry generation, prior/candidate generation digests, boot identity, monotonic duration plus wall-time diagnostic, deadline policy, random confirmation nonce, closed restore-step IDs, retry bound, and effect/operation/audit IDs. The watchdog accepts no paths, config bytes, or caller-selected restore commands.

Confirmation is valid only for the exact lease/nonce/candidate generation from the registered validating path after the required probe level. Stale/replayed confirmation is rejected. Reboot recalculates remaining time conservatively from persisted duration/boot state; wall-clock rollback cannot extend authority. On expiry or loss of required heartbeat, the watchdog executes only the prevalidated prior-generation restore steps. Failed bounded restore, invalid prior generation, or repeated boot-loop transitions to `EmergencyRecoveryRequired`, preserves evidence and restores only an already validated prior generation or explicitly pre-enrolled emergency access path. It never invents a permissive firewall rule, enables root/password login, replaces a valid certificate with self-signed material, or opens a new management listener. If no validated recovery path works, it fails closed to local-console recovery rather than alternating or weakening generations.

**federatord** is optional and unprivileged. It opens the outbound central stream, validates central envelopes, submits them through panel-core's closed local command gateway, and exports sanitized projections and receipts.

### 4.2 Persistence separation

The node MUST separate high-value control state from high-volume observations:

| Store | Content | Requirements |
|---|---|---|
| control.db | resources, revisions, commands, operations, locks, leases, quota reservations, minimal audit/outbox | one prioritized writer, local filesystem only, WAL, synchronous FULL for authoritative commits, online backup API |
| execd.db | root registry, fences, privileged effect acceptance and receipts | root-owned, independent recovery, no paneld write access |
| taskd.db | site registry projection, accepted TaskEnvelopes, pidfd/cgroup identities, cancellation and terminal receipts | site-taskd-only writer; FULL commits before launch; no payload/secret plaintext; tombstones prevent stale reuse |
| secrets.db + wrapping key | encrypted secrets, immutable audience bindings, delivery grants/counts/revocation | secret-broker-only writer/key access; encrypted pages/fields; FULL commit; separately escrowed/recoverable master key; no bulk decrypt |
| authn.db + TOTP wrapping key + assurance key | encrypted TOTP seeds, recovery-code verifiers/consumption, WebAuthn credentials/counters/challenges/backup/UV/RP state, authenticator policy/epochs, signed assurance receipts | distinct AEAD wrapping and signing keys; auth-verifier-only access; no post-enrollment seed export; closed independently confirmed enrollment/reset/revoke; FULL consume/result; separately escrowed/rotated |
| approvals.db + signing key | mirrored pending executor plan registration, protected approver identities and trust/policy/recovery epochs, signed/expired/revoked CommitAuthorizations | approval-broker-only writer/signing key; independent end-to-end transaction display/confirmation; execd.db pending plan authoritative and consumption+effect acceptance atomic there |
| provider-effects.db | provider action admission mirror, bounded observations, terminal/ambiguous receipts, adapter/destination digest | provider supervisor-only writer; FULL acceptance before worker launch; workers are stateless and receive one action |
| containers-admin.db | rootful workload/image/volume/network/exposure registry and effect receipts | rootful broker-only writer; host-root trust; FULL acceptance before runtime call; separate from tenant broker |
| containers-tenant.db | rootless tenant registry/receipts | tenant broker-only writer/identity; cannot address rootful runtime or host objects |
| watchdog.db | prevalidated activation leases, nonces, generations, restore steps, retries, terminal recovery state | watchdog-only writer; FULL+fsync before activation; no arbitrary paths/commands |
| audit segments + checkpoint head | append-only canonical AuditEvents, hash-chain segments, signed checkpoints, archive/replication receipts; control.db stores only current durable checkpoint/head/reference | dedicated audit-writer only; preallocated bounded segments, fsync policy, 90-day online baseline plus signed archive policy, no ordinary mutation bypass on silent loss |
| journald/segments | service and diagnostic logs | bounded retention, cursor pagination, tenant filtering, redaction |
| local TSDB | metrics and bounded time series | label cardinality limits, independent failure from control path |
| artifact store | large operation output, evidence, exports, scans, migration reports | checksummed, quota-bound, encrypted by policy |
| backup repositories | recovery objects and signed manifests | separate credentials and retention authority |

Each protected helper store has one owner/writer, peer-authenticated read/registration protocols, explicit N/N-1 schema/protocol compatibility during product rollback, bounded transactions, integrity checks, online backup/export under a typed DR operation, and no shared writable handle. “execd journal” in this document means the appropriate helper-owned store, not one multi-process database. Provider workers themselves are stateless: the supervisor persists acceptance before launch, secrets.db counts delivery, and worker loss returns the action to provider-specific observation or `Ambiguous`, never blind replay.

Boot recovery orders trust and revocation before effects: verify release and helper binaries; mount/verify protected stores; recover wrapping/approval keys; apply revocations/tombstones; reconcile watchdog and privileged receipts; reconcile task/container/provider effects; then allow normal mutation. Corruption fails closed for new effects and enters component-specific recovery; watchdog may execute an already validated safety restore, but cannot arm new work. Full-node DR restores stores and protected keys through an explicit ceremony, rotates session/provider/approval/node credentials where possible, increments epochs, rejects pre-recovery replays, verifies tombstones/receipts, and reconciles host/provider state before readiness.

The product MUST reject SQLite on NFS or another network filesystem. It MUST use the SQLite online backup API rather than copying a live database and WAL pair.

### 4.3 Clean-host contract

Initial installation supports fresh or explicitly certified OS images. It MUST reject or require migration for:

- another hosting control panel;
- an unmanaged conflicting web, mail, DNS, database, firewall, or container stack;
- unsupported kernel, filesystem, quota, systemd, mandatory-access-control, or cgroup configuration;
- insufficient recovery space;
- unsupported web-engine artifact or LiteSpeed Enterprise license state.

Existing CyberPanel hosts migrate to a fresh target. There is no in-place replacement installation.

---

## 5. Canonical resource model

### 5.1 Common resource envelope

All durable domain resources use a common conceptual envelope:

~~~proto
message Resource {
  string id = 1;                 // UUIDv7
  string kind = 2;               // stable catalog name
  ResourceScope scope = 3;       // exactly one instance/tenant/project/site scope
  optional string owner_tenant_id = 4;
  optional ResourceRef parent = 5;
  map<string,string> labels = 6;
  google.protobuf.Any spec = 7;  // schema-qualified kind-specific message
  google.protobuf.Any status = 8;// schema-qualified observed projection
  uint64 generation = 9;         // desired-state revision
  uint64 observed_generation = 10;
  repeated Condition conditions = 11;
  Lifecycle lifecycle = 12;
  repeated string finalizers = 13;
  Timestamp created_at = 14;
  Timestamp updated_at = 15;
}

message Condition {
  string type = 1;
  ConditionStatus status = 2;    // TRUE, FALSE, or UNKNOWN
  string reason_code = 3;
  string message = 4;
  uint64 observed_generation = 5;
  Timestamp last_transition_at = 6;
  Timestamp last_probed_at = 7;
}

message ResourceScope {
  oneof value {
    string instance_id = 1;
    string tenant_id = 2;
    string project_id = 3;
    string site_id = 4;
  }
}

message ResourceRef {
  string id = 1;
  string kind = 2;                // globally unique namespaced wire kind
  ResourceScope scope = 3;
}
~~~

Specifications express desired state. Only the registered reconciler/observer may propose status, and the single control.db write coordinator validates and commits that proposal. Callers MUST use optimistic concurrency for mutations.

Canonical wire kinds are globally unique and context-namespaced, for example `security.scan_run`, `apps.scan_run`, `marketing.delivery_attempt`, `ops.notification_delivery_attempt`, `database.replication_channel`, and `ha.replication_channel`. Short labels in prose/tables are display aliases only. Every reference carries ID, kind, and scope; controllers, permissions, handlers, migrations, events, and provider adapters reject kind or scope mismatch even if the UUID exists. A UUID never selects authority without its expected kind/scope registry entry.

### 5.2 Ownership hierarchy

~~~mermaid
flowchart TD
    I["Hosting instance"] --> T["Provider tenant"]
    T --> R["Reseller tenant"]
    T --> C["Customer tenant"]
    R --> RC["Child customer tenant"]
    C --> P["Project"]
    RC --> RP["Project"]
    P --> S["Site"]
    RP --> RS["Site"]
    S --> A["Web application runtime"]
    S --> AI["Managed application installation"]
    S --> D["Domain bindings"]
    S --> DATA["DB / files / mail / access / schedules"]
~~~

Every tenant-scoped hosted resource MUST derive exactly one tenant ancestry. Instance resources such as Node, WebEngine, DatabaseInstance, ServiceInstance, FirewallPolicy, and ProductRelease are instance-scoped and MAY serve many tenants without being owned by one. Projects group related tenant resources. Site is the primary Unix and resource-isolation boundary. A `WebApplication` is a routable runtime inside a site; an `ApplicationInstallation` is a panel-managed product instance; a `Release` is immutable content; `Deployment` is the operation/resource that produces and promotes a release. Domain bindings route names to web applications; “primary,” “child,” “alias,” “redirect,” and “preview” are relationships, not renderer-specific file concepts.

Resellers are tenants with authority over descendant tenants. They are not special account rows or integer owner pointers.

### 5.3 Lifecycle conventions

Resources use explicit lifecycles and finalizers. Deletion is normally:

~~~mermaid
stateDiagram-v2
    [*] --> Active
    Active --> Deleting: delete accepted
    Deleting --> Quarantined: routing/access revoked
    Quarantined --> Active: restore within retention
    Quarantined --> Purging: retention elapsed + purge authorized
    Purging --> Deleted: effects verified
    Deleting --> NeedsAttention: ambiguous/failed effect
    Purging --> NeedsAttention: incomplete destruction
~~~

Destructive operations MUST leave tombstones long enough to reconcile late effects and audit ownership. Principal deletion never deletes hosted resources. Tenant closure requires an explicit resource disposition plan, quarantine window, recovery point, and separately authorized purge.

### 5.4 Bounded contexts

The canonical contexts are:

1. Identity, Tenancy, Authorization, Plans, and Quotas.
2. Fleet, Nodes, Capabilities, Services, and Product Lifecycle.
3. Web Hosting, Engines, PHP, Routes, and Deployments.
4. DNS, Certificates, and Provider Reconciliation.
5. Databases and Database Workspaces.
6. Mail Server, Webmail, Delivery Providers, and Marketing.
7. Files, FTP, SFTP, SSH, Terminal, Cron, and Git.
8. Backup, Restore, Transfer, and Disaster Recovery.
9. Applications, WordPress, Staging, and Scanning.
10. Containers, Resource Isolation, and CloudLinux.
11. Firewall, WAF, Malware, Security Investigation, and Repair.
12. Observability, Audit, Notifications, and Incidents.
13. Automation, Extensions, Public API, CLI, and UI.
14. Federation, Fleet Orchestration, and Multi-node Availability.
15. Migration and Import.

---

## 6. Identity, tenancy, authorization, plans, and quotas

### 6.1 Identity resources

| Resource | Purpose |
|---|---|
| Principal | human, service, or bounded local-recovery identity |
| LocalCredential | password verifier metadata using Argon2id |
| Authenticator | WebAuthn/passkey public credential or encrypted TOTP secret |
| RecoveryCodeSet | hashed one-use recovery codes |
| ExternalIdentity | immutable OIDC issuer/subject link |
| IdentityProvider | optional OIDC provider policy and health |
| Invitation | expiring tenant/role enrollment |
| Session | assurance, authentication methods, CSRF binding, expiry, and authorization epoch |
| APIClient | service principal, scopes, selectors, source policy, rate policy |
| APIKey | one-time-displayed, verifier-only, expiring and independently revocable secret |
| CredentialEvent | authentication, enrollment, reset, recovery, and revocation event |

### 6.2 First installation and recovery

Fresh installation MUST:

1. generate a high-entropy short-lived claim;
2. permit claim only locally or from an explicitly selected management network;
3. create the instance owner without a default username or password;
4. prefer passkey enrollment and support a strong password fallback;
5. enroll TOTP and one-use recovery codes;
6. confirm two independent recovery methods;
7. consume the installation claim permanently;
8. create the first signed audit checkpoint.

Local authentication and recovery MUST work without Internet, central, vendor, or external IdP connectivity. The final active local instance owner cannot be deleted, suspended, demoted, or made federated-only.

### 6.3 Session and authentication policy

- Session cookies MUST be Secure, HttpOnly, and SameSite.
- Browser state mutations MUST require CSRF protection.
- Authentication and privilege elevation MUST rotate session state.
- Sessions MUST have idle and absolute expiry.
- High-risk actions MUST require recent strong authentication.
- Password, MFA reset, role reduction, suspension, API-key revocation, and authorization-epoch changes MUST invalidate affected sessions and unstarted grants.
- Acceptance records immutable evidence of the authority and policy that admitted an operation; it does not confer unlimited future commit authority. Low-risk work, observation, safety rollback, cleanup, and compensation MAY continue after browser-session loss. Revocation cancels unstarted work and blocks any uncommitted privileged exposure, high-risk mutation, or irreversible frontier until current commit authorization is re-established.
- Authentication errors MUST resist user enumeration.
- Throttling MUST combine account and source signals without enabling trivial permanent lockout.
- Users MUST be able to inspect and revoke their sessions and authenticators.
- SessionPolicy MUST support no network binding, exact-address binding, configurable prefix binding, and risk-based reauthentication. Address change events are audited; a policy cannot silently weaken strong-auth requirements or create an unrecoverable administrator lockout.

### 6.4 OIDC

OIDC is optional and MUST use authorization code, PKCE, state, nonce, exact redirect matching, issuer validation, and immutable issuer/subject identity. Matching email alone MUST NOT link or grant an account.

OIDC claims cannot grant instance-owner authority or exceed a configured mapping ceiling. If the IdP fails, new delegated logins fail closed; local recovery and existing locally authorized sessions follow their normal expiry and authorization epoch.

### 6.5 Tenancy and authorization resources

| Resource | Purpose |
|---|---|
| Tenant | provider, reseller, or customer ownership boundary |
| Membership | principal participation in a tenant |
| Permission | stable verb on a resource kind |
| Role | built-in or tenant-defined permission set |
| RoleBinding | subject, role, scope, optional selector, validity |
| DelegationCeiling | maximum authority and quota a reseller can delegate |
| ResourceOwnership | canonical tenant ownership relation |
| OperationGrant | actor, scope, risk, approval, expiry, and request hash for async work |
| OwnershipTransfer | validated atomic transfer plan |
| SupportAccessGrant | real operator, customer context, scope, consent, banner, and expiry |

Authorization MUST:

1. verify active principal, membership, tenant, session, and target;
2. require the stable permission in the target scope;
3. verify ownership and resource relationships;
4. intersect delegated authority with every ancestor ceiling;
5. evaluate quota, lifecycle, risk, and assurance conditions;
6. apply explicit deny before allow;
7. record the decision and inputs;
8. recheck high-risk authority before privileged commit.

The same decision service governs UI, API, CLI, central intents, schedules, extensions, workers, and support access.

The durable audit unit is a security-relevant admitted request/effect, not every internal row predicate or every hostile edge frame. The audit writer persists every mutation; privileged effect; secret delivery; credential, authenticator, session, role, policy, grant, approval, and trust change; admitted authentication/authorization/security denial; sensitive read/export; and one request/query-level allow decision containing policy/scope/filter/result-set digest and bounded count. Malformed, unauthenticated, pre-admission, and rate-limited flood traffic is aggregated into bounded signed counters/segments by source/category/window with exact drop/coalesce counts and alerts; it cannot consume one essential authority event per packet/request, and security-class counts are never silently lost. Pagination or an internal ownership check does not emit one authority row per object. When per-object proof is required, the operation writes a bounded signed decision-manifest artifact referenced by one AuditEvent.

For mutations, the prepared-body/control-reference/finalize protocol in Section 4.1 bridges the non-atomic stores: stable ID/digest, durable prepared body first, mutation/reference/outbox commit second, hash-chain finalize third, retained body until acknowledgement, and deterministic orphan/gap recovery. For an admitted denial or sensitive read with no control mutation, audit-writer durably appends/finalizes the event before the denial/result is considered auditable; any related access-log request ID/digest is linked asynchronously. A mutation cannot be reported committed until its audit preparation/reference are durable, and exhausted essential-audit reserve blocks new non-safety mutations.

If audit-writer/store is corrupt or unavailable, prevalidated watchdog/executor safety recovery first writes a fixed-schema `EmergencyAuditRecord` to a separately reserved FULL+fsync watchdog.db or execd.db lane containing boot, lease/effect, handler, prior/candidate generation, reason, result, and digest. Only closed prevalidated safety handlers can use this lane. Recovery later links it into a new audit chain with an explicit signed integrity-discontinuity marker; it is not an arbitrary mutation bypass. This preserves accountable list/search behavior without allowing normal authorization fan-out to exhaust control.db.

### 6.6 Reseller and account lifecycle

- Creating a reseller creates a child tenant, manager membership, delegation ceiling, and quota budget.
- Resellers may create descendants, roles, plans, and resources only within their ceiling.
- Principal suspension revokes access but does not stop hosted services.
- Tenant suspension is a separate operation with explicit web, mail, FTP, schedule, deployment, and access effects.
- Principal deletion requires membership and stewardship reassignment.
- Tenant deletion is a staged resource lifecycle.
- Ownership transfer MUST validate destination authority, cycles, plan compatibility, quota, name conflicts, and dependent resources before atomic control-state commit.
- Support access MUST preserve the real operator as actor; it MUST NOT forge or steal a customer session.

### 6.7 Plans and quotas

| Resource | Purpose |
|---|---|
| Plan | tenant-owned reusable offering |
| PlanVersion | immutable entitlements |
| PlanAssignment | desired and applied version |
| Entitlement | typed limit or feature availability |
| QuotaBudget | capacity delegated to a reseller |
| QuotaLedger | allocated, reserved, used, and pending-release values |
| ResourceProfile | requested limits split into explicit enforcement scopes and owners |
| ResourceLimitBinding | dimension, owner scope, adapter, effective value, enforced/accounted_only/unsupported state |

Zero and unlimited are distinct. Editing a plan creates a new version and impact preview. Rollout is explicit, reconciled, and reversible to the prior effective version when enforcement activation fails.

Quotas MUST be reserved before asynchronous creation begins. Checks and allocations MUST occur atomically in control state. Effective enforcement status and the source of each inherited limit MUST be visible.

A “site limit” is not one fictitious kernel envelope. Each dimension binds to an enforcement owner:

- `site_processes`: PHP/LSAPI, cron, Git, terminal, builds, scanners, and native app workers under the site cgroup;
- `filesystem_project`: bytes and inodes under the site project quota;
- `web_engine_vhost`: vhost connections/requests/bandwidth and any engine-qualified CPU/throttle behavior;
- `database_principal`: connections, statement time, result/temp/resource/rate controls supported by MariaDB/proxy; shared server CPU/I/O is accounted-only unless a qualified governor/instance isolates it;
- `mail_domain` or `mailbox`: storage, messages, recipients, send rate, concurrency, and protocol limits; shared filter/service CPU is accounted-only unless qualified otherwise;
- `dns_zone`: update/query/transfer policy and accounting, not a false per-zone daemon CPU cgroup;
- `container_workload`: cgroup, storage, PID, network, and runtime limits;
- `node_shared_service`: reserved host capacity and fairness, not tenant hard isolation.

Every binding reports `enforced`, `accounted_only`, or `unsupported`, its adapter, last observation, and uncertainty. Aggregate site CPU/I/O is usage/accounting unless every relevant path is enforced. A plan may require hard enforcement for named scopes; assignment/creation blocks if the tuple cannot meet it. The UI MUST NOT label shared OLS/LSE static/TLS/WAF/cache, MariaDB, mail, or DNS costs as hard-capped merely because site UID processes are cgrouped.

---

## 7. Standalone runtime and privilege boundary

### 7.1 Process trust table

| Component | UID / privilege | Allowed authority | Forbidden authority |
|---|---|---|---|
| panel-gateway | dedicated unprivileged edge UID | public TLS/HTTP/UI framing and closed local request submission | control DB, sessions/authz decisions, helper/broker sockets, keys/secrets, site/root files |
| panel-core (`paneld` package boundary) | dedicated unprivileged authority UID, local only | control DB, sessions/authz, operation acceptance, reconciliation, provider coordination | public listener, root files, secret master key, direct arbitrary provider clients, sudo, Docker socket, arbitrary services |
| panel-execd | root, local only | enumerated node-critical handlers | generic command/path/unit/package/user operations |
| site-taskd | root, local only, minimal | launch exactly one signed worker under a registry-resolved site identity/cgroup/namespace | caller-supplied UID, path, executable, environment, or arbitrary root work |
| site-worker | site UID, launched by site-taskd | site-root files and site-scoped commands | other sites, host configuration, runtime sockets |
| secret-broker | root or dedicated key UID, local only | unwrap one grant-bound secret for one registered consumer | network access, bulk export, caller-chosen consumer/purpose |
| auth-verifier | dedicated protected UID/key, local only | verify one bound TOTP/recovery/WebAuthn challenge and perform bound one-time enrollment delivery | post-enrollment/admin seed/recovery export, delivery outside enrollment protocol, desired-state writes, generic signing, network listener |
| approval-broker | dedicated protected UID/origin and signing key | render and sign one executor-registered high-risk transaction confirmation | arbitrary commands, desired-state writes, self-approval, reusable approval |
| provider-supervisor | dedicated no-network UID, local only | own provider-effects.db, admit one typed plan, validate observation, persist receipt | external network, secret plaintext, control/root/helper mutation, worker-code loading |
| provider-worker | dedicated unprivileged pool, no journal access | one typed declared external-provider action | control/provider journal writes, ambient secrets, arbitrary destination/redirect, helper authority |
| audit-writer | dedicated protected UID/checkpoint key | prepare/finalize canonical audit events and sign checkpoints | desired-state mutation, helper/provider action, event rewrite/delete, generic signing |
| container-broker | narrowly privileged | typed runtime operations | unrestricted daemon proxy, policy bypass |
| rollback-watchdog | root, minimal | confirm or restore registered activation | new arbitrary configuration |
| federatord | unprivileged | central stream and local command submission | direct host or control-DB mutation |
| extension runtime | sandbox UID/rootless container | granted public APIs and brokered egress | executor, ambient files/network, cross-tenant state |

### 7.2 Executor protocol

The root protocol MUST:

- use a root-owned Unix socket with restrictive group permissions;
- validate SO_PEERCRED identity and protocol handshake;
- impose bounded frames, deadlines, request size, concurrency, and effect rates;
- carry operation ID, request hash, handler version, expected resource generation, fence token, risk class, and grant reference;
- resolve resource IDs through a root-owned append-only, generationed registry with explicit tombstones;
- reject unknown fields and unsupported versions;
- persist effect acceptance before mutation and a typed receipt afterward;
- expose observation/reconciliation handlers for ambiguous effects;
- support N and N-1 protocol versions during product rollback;
- run with clean environment, absolute internal binaries, seccomp, and SELinux/AppArmor policy;
- verify helper digests against the installed signed release manifest.

The executor MUST NOT trust a digest as proof that paneld rendered an authorized configuration. For high-impact managed configuration, it receives a closed typed desired snapshot/reference and either deterministically re-renders with a release-pinned executor-side renderer or verifies an attestation from a separately isolated release-pinned renderer. It then parses the produced native generation and independently validates directive, include graph, path, UID/GID, listener, executable/handler, ownership, schema, and expert-fragment allowlists before staging. A digest binds the verified bytes only after this provenance/policy check. Unknown raw fragments or executable includes are rejected.

The control/executor databases and host state are not one transaction. Identity allocation uses a reconciled saga: paneld reserves an opaque resource and effect ID; panel-execd records effect acceptance; it allocates UID/GID/root/registry generation; paneld records the typed receipt; both sides reconcile missing acknowledgements after crash. Deletion tombstones the registry before reuse, and UID/GID/path reuse is delayed and generation-checked.

The privilege split reduces blast radius; it does not make a malicious panel-core harmless. A panel-core compromise owns product control state and can attempt product-level cross-tenant operations inside typed helper boundaries. The executor prevents arbitrary root primitives, caller-selected identities/paths/units, replay, stale fencing, and cross-registry scope. High-risk approval evidence that the executor enforces MUST be independently signed or derived from a separately protected local approval channel.

For a high-risk handler, panel-execd first records a pending plan digest, target registry generation, effect ID, fence/risk/frontier, and nonce in execd.db. approval-broker obtains that record over a peer-verified local channel and displays its release-pinned canonical transaction text independently of paneld. After the required human/threshold authenticator confirmation, it signs:

~~~proto
message CommitAuthorization {
  string installation_id = 1;
  string approval_id = 2;
  ActorChain approvers = 3;
  uint64 authorization_epoch = 4;
  string command_id = 5;
  string operation_id = 6;
  string effect_id = 7;
  string request_digest = 8;
  string handler_id = 9;
  uint32 handler_version = 10;
  string plan_digest = 11;
  string canonical_display_digest = 12;
  repeated string side_effect_and_frontier_ids = 13;
  string approval_policy_version = 14;
  ResourceRef target = 15;
  uint64 target_generation = 16;
  uint64 fencing_token = 17;
  RiskClass risk = 18;
  Reversibility frontier = 19;
  bytes executor_nonce = 20;
  Timestamp issued_at = 21;
  Timestamp expires_at = 22;
  bytes signature = 23;
}
~~~

panel-execd verifies the protected approval key, handler/version, request/plan/display/side-effect/frontier/policy digests, current approval/authorization epoch, expiry, nonce, target generation, and fence; then consumes the authorization idempotently in execd.db before the commit. Any replan, handler/policy change, changed observed precondition, effect-set change, or display change invalidates the authorization and requires a fresh human confirmation. Revocation/expiry yields `WaitingApproval`, `ApprovalExpired`, or `ApprovalRevoked`; compensation/safety rollback remains available. Offline local approval works without central. A handler lacking this trusted path may validate approval structure only and MUST NOT qualify for an independent high-risk-approval claim.

The pending plan in execd.db is authoritative. approval-broker mirrors only its exact digest/nonce/handler/generation registration into approvals.db and owns the confirmation/signature lifecycle; the two sides reconcile only by that immutable tuple. In one FULL execd.db transaction, panel-execd marks the authorization consumed for the exact effect and records privileged-effect acceptance. After a crash, only that accepted effect may be observed/resumed under the consumed approval; no new effect can reuse it. A consumption record without a matching accepted effect, or a digest/nonce disagreement between stores, becomes `NeedsAttention` and requires recovery/reapproval.

### 7.3 Site worker boundary

Site work that legitimately contains arbitrary tenant commands includes cron, terminal, Git hooks, builds, deployment hooks, WP-CLI, LSAPI, CGI, and native application servers. It MUST run:

- as the site's UID/GID;
- within the site's cgroup and project quota;
- with bounded time, output, process count, memory, CPU, and I/O;
- without host runtime sockets or privileged capabilities;
- with an explicit working directory and bounded environment;
- with purpose-scoped secret delivery;
- with audit metadata and cancellation checkpoints.

panel-core submits only a registered TaskEnvelope and payload digest to site-taskd. site-taskd resolves the site UID/GID, roots, namespace profile, cgroup, quotas, worker digest, and task policy from its protected registry; starts exactly one signed site-worker binary; passes validated task data over an inherited descriptor; drops capabilities and credentials before workload execution; and owns pidfd cancellation, timeout, and process receipts. It never executes a caller-supplied binary or task string as root.

Task launch uses an explicit two-party registration; panel-core never writes taskd.db or execd.db. panel-core submits a closed `TaskEnvelope` over the peer-verified UDS:

~~~proto
message TaskEnvelope {
  string task_id = 1;
  string task_kind = 2;
  ResourceRef site = 3;
  uint64 site_generation = 4;
  string command_id = 5;
  string operation_id = 6;
  string operation_grant_id = 7;
  uint64 authorization_epoch = 8;
  uint64 fencing_token = 9;
  string worker_release_digest = 10;
  string sandbox_profile_id = 11;
  repeated string secret_delivery_grant_ids = 12;
  string resource_limit_profile_id = 13;
  uint64 resource_limit_profile_generation = 14;
  ResourceLimitSnapshot requested_lower_caps = 15;
  WorkEstimate admission_estimate = 16;
  string payload_digest = 17;
  Timestamp expires_at = 18;
}
~~~

`ResourceLimitSnapshot` is resolved from the root-owned site/task profile generation and contains concrete maxima for deadline, output bytes, pids, CPU, memory, I/O, file descriptors, and network policy. panel-core may request only stricter/lower caps; it cannot widen the registry values. `WorkEstimate` remains non-authoritative admission metadata and never becomes an enforcement limit.

site-taskd validates the closed task kind, peer, registry site/generation, grant epoch, fence, worker/sandbox digest from the signed release, secret-grant IDs, limits, expiry, replay, and cancellation state; records acceptance in its root-owned journal; then receives the exact bounded payload over a sealed descriptor and verifies its digest. A separate signature is unnecessary because SO_PEERCRED plus the registered operation/grant/fence and release-pinned schemas bind the local submission; central signatures never reach site-taskd directly. The descriptor is passed only after UID/GID/capability drop.

Duplicate task ID returns the original acceptance/receipt. A stale fence/generation/epoch or expired task is rejected. Cancel is bound to task/operation/fence and uses pidfd. On crash/reboot, site-taskd observes the pidfd/cgroup/effect or records ambiguity, persists one terminal receipt, and paneld reconciles that read-only receipt into control.db; it never blindly launches a second task for the same effect ID.

Every site process uses a qualified `SiteSandboxProfile`, not UID/cgroup alone:

~~~yaml
SiteSandboxProfile:
  filesystem:
    osView: minimal_read_only
    writableRoots: [siteHome, declaredMutableStores]
    privateTmp: true
    privateIPC: true
    proc: hide_other_users_and_sensitive_nodes
    devices: [null, zero, random, urandom, tty_when_terminal]
    hostSockets: deny
  privilege:
    capabilities: []
    noNewPrivileges: true
    securebitsLocked: true
    setuidTransitions: deny
    ptrace: same_sandbox_policy_only
    seccompProfile: versionedProfileRef
    macProfile: appArmorOrSELinuxProfileRef
  network:
    namespace: per_site_or_proven_equivalent
    deny: [hostControl, runtimeSockets, metadata, linkLocal, otherTenant]
    localServices: [brokeredDatabase, brokeredMail, brokeredCache, resolver]
    publicEgress: planGovernedPolicy
  resources:
    cgroupRef: siteResourceProfile
    projectQuotaRef: siteQuota
~~~

The read-only OS view contains only required libraries, runtimes, certificates, timezone/locale, and devices. Site roots are mounted explicitly; `/home` is not globally visible. `/proc`, `/dev`, `/run`, host Unix sockets, kernel interfaces, and control endpoints are minimized/filtered. Landlock MAY add defense in depth but does not replace mount, descriptor, MAC, and network controls.

Per-site database, mail-submission, Redis/cache, and DNS access uses explicitly mounted Unix sockets or policy-owned endpoints with service credentials; other loopback/host/tenant services are not reachable. Public egress may be allowed by plan but metadata, control, runtime, link-local, rebinding, and other-tenant destinations remain denied.

OLS/LSE do not get an isolation exemption. Each site LSAPI pool is launched as a separately managed external application through site-taskd/systemd under the same cgroup and SiteSandboxProfile, and the engine connects to its registry-owned UDS. Gate 0 MUST prove that the exact engine/version supports this lifecycle and cannot respawn an unsandboxed alternative; otherwise that support tuple fails or the adapter architecture changes.

Every engine-triggered executable path—including LSAPI, CGI, FastCGI, or another supported external application—references a registry-owned site-taskd/systemd service and inherits the same sandbox, identity, cgroup, secret, network, and receipt rules. The engine never receives a tenant-selected executable/path/argv to launch directly. A proxy route may target only a broker-issued site or container service endpoint with exact ownership and network policy; it cannot create a process or reach an arbitrary host/loopback socket. Container exec is not a site-taskd operation: it is handled only by the closed container-broker protocol under Section 17.3.

### 7.4 File safety

The privileged and site file layers MUST use file-descriptor-relative resolution. Destructive or create operations use openat2 with RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS, and policy-selected RESOLVE_NO_SYMLINKS. They use O_NOFOLLOW, O_EXCL, renameat2, fsync, and post-open ownership/type checks as appropriate.

Every path a root or shared-service supervisor may open later—engine/service logs, LSAPI and control sockets, cache/temp roots, PID/state files, certificate/key generations, and rotation targets—lives beneath a root/service-owned parent that no site UID can rename or write. Creation and rotation are descriptor-relative with no-follow, expected type/owner/mode/link-count checks, atomic replacement, and directory fsync. Site-writable logs are opened only after dropping to the site identity; otherwise tenants receive brokered read/stream access to service-owned logs. LSAPI UDS parents have registry-owned UID/GID/mode/MAC labels, generation-qualified names, safe stale-socket type/owner checks, and no site-controlled parent component.

Old migration-source kernels MAY use a carefully audited descriptor-walk fallback because they are not part of the target runtime support claim.

### 7.5 Secret and provider worker boundary

control.db stores only an opaque SecretRef and non-sensitive lifecycle/health projection. Ciphertext, wrapped DEKs, authenticated metadata, audience bindings, monotonic versions, delivery grants/counts, and revocation live only in broker-owned secrets.db; the wrapping key is available only to secret-broker. A SecretDeliveryGrant binds secret/version, consumer pidfd/start identity, signed release executable digest, operation/effect, resource, purpose, maximum reads, and deadline. secret-broker verifies caller/consumer peer credentials, live process identity, executable measurement, and registry state, records delivery, and passes a sealed memfd/descriptor to the already running consumer with `CLOEXEC`; it does not return plaintext to panel-core or expose list/decrypt-all.

Provider-worker receives a provider action plan containing adapter/version, target resource, declared origin/redirect policy, idempotency/effect ID, deadlines, byte/request limits, and permitted secret grants. It resolves DNS and redirects under the provider egress policy, performs one bounded action, and emits a typed receipt/observation. Provider code cannot mutate desired state or call panel-execd directly.

First-party secret consumers are single-use or pooled only within the same provider and tenant trust domain; no pool crosses those boundaries. They set `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, no-new-privileges, locked securebits, restrictive seccomp/MAC, and ptrace denial. First-party secret memory uses `MADV_DONTDUMP`, `mlock` where practical, bounded single-use reads, and best-effort zeroization; no secret-bearing child, argv, ordinary environment, crash dump, or inherited descriptor is allowed. Host swap and core-dump policy is explicit and qualified. These controls reduce but do not defeat host-root memory access.

Vendor daemons that must retain TLS, DKIM, DNS, database, backup, or registry material use a `DaemonSecretMaterialization` contract: an immutable root/service-readable non-document-root generation; minimum service UID/group and MAC label; no argv or ordinary environment; systemd/core-dump disablement; exact consumer/version; atomic rotation and reload; active presentation/use probe; previous-generation overlap where protocol requires it; and bounded cleanup after confirmation. `mlock`, non-dump memory, key-agent support, and zeroization are reported as vendor-version capabilities and are never claimed without evidence.

At secret enrollment, secret-broker persists a protected immutable `SecretAudienceBinding` in its root/key-owned journal: provider adapter identity/version family, external account/audience, normalized allowed origin and redirect set, owning resource/generation, permitted operation classes, consumer release digests, and rotation epoch. Both broker and provider-worker compare the action plan to this binding before delivery/use. Endpoint, audience, account, operation-class, or consumer changes require a newly confirmed credential binding and high-risk CommitAuthorization; panel-core cannot retarget an existing AWS, SMTP, backup, DNS, registry, or scanner credential to an arbitrary endpoint.

---

## 8. Durable operations, reconciliation, and schedules

### 8.1 Command and operation model

Every mutation creates an immutable Command and a durable Operation:

~~~proto
message Command {
  string id = 1;
  string kind = 2;
  ActorChain actor = 3;
  Scope scope = 4;
  ResourceRef target = 5;
  uint64 expected_generation = 6;
  string idempotency_key = 7;
  google.protobuf.Any validated_input = 8;
  string operation_grant_id = 9;
  Timestamp accepted_at = 10;
}

message Operation {
  string id = 1;
  string command_id = 2;
  OperationState state = 3;
  uint64 attempt = 4;
  uint64 fencing_token = 5;
  repeated StepReceipt receipts = 6;
  Progress progress = 7;
  optional Failure failure = 8;
  Reversibility reversibility = 9;
}
~~~

Acceptance transactionally records authorization, idempotency, target generation, quota reservation, command, operation, audit event, and outbox event.

control.db has exactly one in-process write coordinator. Reconcilers, API handlers, schedulers, and provider observers submit bounded mutation proposals and hold no writable SQLite handle. The coordinator uses priority queues, admission limits, short transactional batches, and explicit backpressure; safety receipts and rollback state outrank telemetry-derived status. Large artifacts, logs, samples, and time-series data are never authority-database blobs.

Authorization has two checkpoints:

1. **acceptance authorization** freezes actor, assurance, policy, grant, request digest, approvals, and target generation as immutable evidence;
2. **commit authorization** is re-evaluated immediately before privileged exposure, high-risk mutation, secret export, promotion, or an irreversible frontier.

Session loss alone does not prevent observation, compensation, cleanup, or a safety rollback. Principal/tenant suspension, authorization-epoch change, approval withdrawal, or grant revocation blocks unstarted work and uncommitted high-risk effects according to policy.

### 8.2 State machine

~~~mermaid
stateDiagram-v2
    [*] --> Queued
    Queued --> Claimed
    Claimed --> Running
    Running --> Verifying
    Verifying --> Succeeded
    Running --> Reconciling: timeout / worker loss / ambiguous effect
    Verifying --> Reconciling: inconclusive observation
    Reconciling --> Running: safe next action
    Reconciling --> Succeeded: effect observed complete
    Reconciling --> Failed: effect observed absent and terminal
    Reconciling --> NeedsAttention: unsafe ambiguity
    Queued --> Canceled
    Running --> CancelRequested
    CancelRequested --> Canceled: safe checkpoint
    CancelRequested --> NeedsAttention: irreversible frontier crossed
~~~

Operations that may expose traffic or mutate durable data additionally report:

- pre_exposure;
- exposed;
- rollback_in_progress;
- rolled_back;
- manual_intervention_required.

### 8.3 Effect and retry rules

- Every external effect MUST have a stable effect ID.
- A timeout MUST transition to observation/reconciliation, never blind retry.
- Resource locks MUST be bounded leases with monotonic fencing tokens.
- A stale worker MUST be unable to commit.
- Retry MUST mean reconcile desired versus observed state, not replay an entire script.
- Each step MUST declare inputs, outputs, deadline, cancellation boundary, observation, compensation, and irreversible frontier.
- Compensation failure MUST surface exact residual state and an incident; it MUST NOT report atomic success.
- Destruction of recovery state MUST be a later, separately authorized effect.

### 8.4 Scheduling

Schedules create deterministic JobOccurrence records. They do not implement business work.

A schedule defines timezone, parsed expression, missed-run policy, overlap policy, jitter, timeout, priority, resource budget, and notification policy. Occurrence IDs derive from schedule ID and logical time. Reboot, DST, clock jumps, and delayed execution follow explicit skip, latest-only, or bounded-replay policy.

Per-host and per-tenant admission control MUST prevent backups, scans, migrations, builds, marketing, and validations from starving login, firewall recovery, certificate renewal, or other safety-critical work.

### 8.5 Boot recovery

On boot, paneld MUST:

1. verify storage and schema;
2. establish a new boot identity;
3. reconcile executor and watchdog receipts;
4. fence stale workers;
5. recover incomplete configuration activations;
6. validate core identity and authorization state;
7. reconcile service generations and listeners;
8. resume or classify operations;
9. restore schedules according to missed-run policy;
10. expose normal mutations only after the recovery barrier passes.

---

## 9. API, CLI, UI, events, and extensions

### 9.1 Public API

The public API MUST be versioned, documented by OpenAPI, and generated from common application contracts. It covers every GA resource family. It MUST provide:

- opaque IDs;
- pagination, filtering, and stable ordering;
- idempotency keys for mutations;
- expected-generation concurrency;
- asynchronous Operation resources;
- stable problem-detail errors;
- conditional reads and ETags where useful;
- rate and byte limits;
- tenant-confidential authorization failures;
- correlation IDs;
- audit attribution;
- version and capability discovery.

Human passwords and browser session cookies MUST NOT authenticate bearer automation. API clients use scoped service principals and expiring verifier-only keys.

### 9.2 CLI

panelctl is a thin client of the same application contracts. It MUST:

- support interactive local pairing and service-principal automation;
- accept secrets through secure prompt, stdin, or file descriptor, never argv;
- provide human and stable JSON output;
- expose operation watching and cancellation;
- expose dry-run and impact preview where meaningful;
- use predictable exit categories;
- cover all GA outcomes, including users, resellers, plans, sites, child domains, DNS, TLS, databases, mail, FTP, backups, WordPress/apps, containers, security, services, and OLS/LSE management.

A tiny local root recovery surface is separate. It supports identity health, session/key revocation, IdP disablement, local-owner recovery, audit export, and declared break-glass recovery. It is not a generic management API.

### 9.3 Local UI

The UI preserves:

- role-aware navigation;
- object-centric lists and detail hubs;
- permission-filtered command palette and search;
- durable operation pages;
- local notification inbox;
- light, dark, and system modes;
- branding tokens and validated assets;
- per-user locale and timezone;
- responsive and keyboard-accessible workflows;
- reduced-motion and high-contrast support;
- visible degraded, stale, offline, and rollback states.

Search MUST NOT leak unauthorized names, counts, or routes. Security confirmation and break-glass surfaces MUST render outside tenant-customizable styling.

### 9.4 Themes and localization

Themes consist of validated semantic tokens and sanitized assets. Arbitrary CSS, JavaScript, remote imports, external scripts/fonts, overlays, pointer interception, and styling capable of concealing security controls are forbidden.

The GA locale set is English, Chinese, Bulgarian, Portuguese, Brazilian Portuguese, Japanese, Bosnian, Greek, Russian, Turkish, Spanish, French, Polish, Vietnamese, Italian, German, Indonesian, Bangla, Norwegian Bokmål, Serbian, and Urdu. Each locale MUST contain every required key, receive terminology/native-language review, preserve security and destructive meaning without fallback, pass interpolation/plural/format validation, and pass representative layout/overflow/accessibility tests. A locale that fails blocks its parity record or is removed only through an explicit product-scope decision before GA. Tags use BCP 47. Messages use structured pluralization and safe interpolation; translations cannot inject raw HTML.

### 9.5 Events and notifications

Domain changes emit immutable typed events through a transactional outbox. Notification resources include NotificationEvent, NotificationPolicy, NotificationRecipient, InboxItem, NotificationPreference, DeliveryRoute, DeliveryAttempt, and Template.

The local inbox is immediate and independent of external delivery. SMTP and signed webhook routes use bounded retry, deduplication, quiet periods, escalation, and degraded-state reporting. Critical credential, authorization, suspension, backup, certificate, service, and security notifications cannot be globally suppressed from the local inbox.

### 9.6 Extension model

Two extension tiers are supported:

**Tier A — WASM/WASI**

- validators, transformations, event reactions, small provider clients, and admission logic;
- no ambient filesystem, process, network, database, executor, or container access;
- capability-scoped APIs, quotas, deadlines, and deterministic ordering.

**Tier B — rootless OCI service**

- long-running, streaming, or protocol integrations;
- separate storage, network policy, resource profile, health, and lifecycle;
- no privileged host operations.

Bundles MUST be signed and declare identity, publisher, version, API range, digests, provenance, SBOM, capabilities, scopes, subscriptions, UI contributions, jobs, storage, egress destinations, dependencies, and retention policy.

Installation verifies trust and compatibility, displays a human-readable capability diff, creates an extension service principal, applies namespaced migrations, starts in quarantine, probes health, then activates through a durable saga with exact residual state and compensation. New privileges on update require new approval. UI is declarative or a sandboxed separate-origin iframe. New privileged host capabilities can ship only as core signed adapters through normal qualification.

### 9.7 Panel origin, previews, and untrusted artifacts

panel-gateway accepts only the configured canonical SNI/Host/port set and rejects unknown Host, IP-literal mismatch, DNS-rebinding, and alternate-origin requests. `Forwarded` and `X-Forwarded-*` are ignored unless the immediate peer is an explicitly bound authenticated reverse proxy with a closed trusted-hop policy. One canonical external URL drives host-only `Secure`/`HttpOnly`/appropriate `SameSite` cookies, WebAuthn RP ID, OIDC redirects, CSRF origin, WebSocket origin, and absolute links. Management listener/origin changes are make-before-break with both origins explicitly bounded during transition. HSTS and no mixed active content are mandatory after initial claim.

Hostile tenant/application preview bytes are never served under the panel, approval, webmail, or another credential-bearing origin, nor under a cookie Domain that receives their cookies. Browser preview uses a dedicated untrusted registrable domain with random expiring bindings, host-only panel cookies that cannot reach it, no forwarded panel authorization headers, strict CORS/frame/referrer isolation, and the Section 10 SSRF/private-route controls. Internal shadow health probes use authenticated service identities on non-public brokered endpoints; they are not guessable public bypass routes around WAF, access policy, or canonical routing.

All downloads, attachments, log/export artifacts, support bundles, scan evidence, and user-controlled HTML/SVG/XML/PDF follow `UntrustedArtifactDelivery`. Authorization and current resource generation are rechecked immediately before opening a digest-bound descriptor. Content is forced as attachment with a sanitized RFC 6266 filename, product-selected safe Content-Type, `X-Content-Type-Options: nosniff`, no credentialed CORS/referrer, and bounded range/cache policy. Inline preview, when a feature requires it, uses a separate non-cookie origin with CSP sandbox and an isolated renderer. Tenant MIME, filename, disposition, HTML, and headers are never reflected verbatim into panel-origin responses.

---

## 10. Web engines, sites, PHP, routing, and deployments

### 10.1 Canonical engine model

OpenLiteSpeed and LiteSpeed Enterprise are sibling adapters over one engine-neutral desired model. Neither adapter translates the other engine's files.

~~~yaml
WebEngineSpec:
  edition: openlitespeed | litespeed_enterprise
  release:
    channel: stable | pinned
    vendorVersion: opaqueVersion
    normalizedOrder: adapterQualifiedVersion
    artifactDigest: sha256
  listeners:
    - addresses: [ipv4, ipv6]
      port: uint16
      tlsMode: clear | tls
      protocols: [http1, http2, http3]
      defaultBinding: resourceRef
  global:
    workers: boundedInteger
    connectionLimits: typedLimits
    timeouts: typedDurations
    compression: gzipBrotliPolicy
    logging: logPolicy
    security: securityPolicyRef
    cache: globalCachePolicy
  enterpriseLicense:
    secretRef: optional
    expectedState: active | trial

WebApplicationSpec:
  siteRef: resourceRef
  identityRef: siteIdentityRef
  applicationRoot: relativePath
  storageMode: managed_release | mutable_tree
  activeReleaseRef: resourceRef
  documentRoot: relativePath
  indexes: [string]
  autoIndex: bool
  phpProfileRef: optionalResourceRef
  upstreams: [typedUpstream]
  contexts: [typedRouteContext]
  rewrites: [typedRewrite]
  headers: [typedHeaderPolicy]
  errorPages: [typedErrorPage]
  accessPolicyRef: optionalResourceRef
  cachePolicyRef: optionalResourceRef
  resourceProfileRef: resourceRef
  logPolicyRef: resourceRef

WebBindingSpec:
  applicationRef: resourceRef
  hostnames: [fqdn]
  relationship: primary | alias | redirect | preview
  listenerRefs: [resourceRef]
  tlsPolicyRef: optionalResourceRef
  canonicalHostPolicy: preserve | redirect
  routingState: serve | maintenance | suspended
  accessPolicyRef: optionalResourceRef
~~~

Each adapter renders the vendor-native configuration form proven for its exact qualified version in Gate 0; the expected OLS text/per-vhost and Enterprise native configuration families are adapter facts, not an unverified universal format promise. Advanced configuration uses the mandatory versioned `EngineExpertFragment` contract below. There is no live-file editor and no unparsed raw-fragment escape hatch. An unrepresentable expert fragment blocks engine conversion instead of being dropped.

### 10.2 Engine adapter contract

Each adapter implements:

~~~go
type WebEngineAdapter interface {
    Discover(ctx context.Context) (Capabilities, ObservedState, error)
    ValidateSpec(ctx context.Context, spec WebEngineSpec) []Finding
    Render(ctx context.Context, desired DesiredWebState) (ConfigGeneration, error)
    ValidateGeneration(ctx context.Context, generation ConfigGeneration) []Finding
    Stage(ctx context.Context, generation ConfigGeneration) (StageReceipt, error)
    Activate(ctx context.Context, staged StageReceipt, fence Fence) (EffectReceipt, error)
    Probe(ctx context.Context, probeSet ProbeSet) (ProbeReport, error)
    Confirm(ctx context.Context, effect EffectReceipt) error
    Rollback(ctx context.Context, effect EffectReceipt) (RollbackReceipt, error)
    Observe(ctx context.Context) (ObservedState, error)
}
~~~

Validation includes syntax or native validation where available, semantic reference checks, listener conflicts, certificates, LSAPI handlers, WAF loading, file ownership, license capacity, cache policy, and supported directives. Activation uses a guarded generation switch and post-activation probes. OLS and Enterprise results are never substituted for one another.

#### 10.2.1 Advanced engine configuration

`EngineExpertFragment` preserves CyberPanel's advanced site-vhost editing and LiteSpeed Enterprise global pre-main configuration outcome without preserving a live path or arbitrary native-file mutation. It contains:

- scope: exact node-global, listener, or site/application attachment point;
- engine edition, qualified version range, fragment grammar/version, owner, reason, and generation;
- canonical parsed AST plus normalized rendered text and digest;
- declared directive families, include references, path/resource references, and conversion eligibility;
- validation findings, previewed semantic diff, approval, activation receipt, probes, and prior generation.

The engine adapter accepts only a release-owned grammar and an explicit directive catalog for that scope. It rejects unknown directives; arbitrary include paths; executable handlers or scripts; module loading; UID/GID or chroot changes; unmanaged listeners; root-owned document paths; cross-tenant paths; control/runtime sockets; shell substitution; and any directive that bypasses canonical TLS, WAF, firewall, sandbox, logging, or resource policy. Includes, when a qualified directive genuinely requires them, resolve only to immutable product-owned fragment IDs.

The legacy Enterprise `pre_main_global.conf` outcome maps to a node-global Enterprise fragment attachment point; target storage paths are implementation details. Site vhost expert configuration maps to a site/application attachment point. Authorized operators can create, inspect, diff, modify, validate, test, enable, disable, version, roll back, export, and delete fragments. Every candidate is parsed, re-rendered by the isolated release-pinned renderer, staged with the full engine generation, probed on the exact engine, and activated under the rollback watchdog. Fragments, history, and provenance participate in backup, restore, migration, drift detection, and engine-conversion preflight. A fragment that cannot be represented and proven on the target engine is blocking, never silently omitted.

Normal node-global tuning is not forced into an expert fragment. Typed `WebEngineTuning` exposes workers/process capacity, clear and TLS connection limits, connection and request timeouts, keepalive count/duration, in-memory cache/buffer budgets, gzip/brotli policy, and edition-qualified cache/network controls. Inspect, measured recommendation, dry-run diff, apply, native/semantic validation, traffic probes, resource observation, rollback, and drift reconciliation are first-class. Bounds derive from exact engine/version/license and measured host reserve; defaults-only support does not satisfy the tuning outcome.

### 10.3 Site aggregate and lifecycle

A Site aggregate contains:

- owning tenant and project;
- primary hostname and domain relationships;
- allocated Unix identity;
- site home and allowed roots;
- applications and immutable deployments;
- PHP runtime and LSAPI process group;
- resource and quota profiles;
- database, mail, FTP, SFTP, SSH, cron, Git, backup, and security relationships;
- desired lifecycle and observed conditions.

~~~mermaid
stateDiagram-v2
    [*] --> Provisioning
    Provisioning --> Active: all required probes pass
    Provisioning --> Degraded: partial/ambiguous outcome
    Active --> Suspended: operator/policy
    Suspended --> Active: prior generation restored
    Active --> Degraded: drift or service failure
    Degraded --> Active: reconciliation succeeds
    Active --> Deleting: delete accepted
    Suspended --> Deleting
    Deleting --> Quarantined: routes/access/jobs disabled
    Quarantined --> Active: restore before purge
    Quarantined --> Purging: retention + approval
    Purging --> Deleted
~~~

Suspension MUST deny or replace HTTP according to policy, stop new PHP work, disable cron, deployment webhooks, interactive access, and outbound application actions without deleting data, certificates, configuration, or prior desired state. Unsuspension restores the prior effective generation.

Deletion first removes routing and credentials, fences background work, captures the configured recovery point, and quarantines data. Purge is separate and delayed.

### 10.4 Website and domain outcomes

The hosting context MUST support:

- create, inspect, modify, suspend, resume, quarantine, restore, and delete a site;
- primary, child/addon, alias, redirect, and preview domain relationships;
- promote a child application/domain to an independent site;
- attach and remove aliases without data duplication;
- primary-domain change with certificate, DNS, application, mail, Git, backup, and canonical-URL impact preview;
- site-specific document root and application root;
- custom index and error documents;
- redirects, rewrites, headers, access controls, MIME types, contexts, upstreams, and typed environment values;
- safe open-basedir-equivalent containment through process and filesystem boundaries rather than a string-only PHP setting;
- access, error, rewrite, WAF, PHP, and cache observability;
- per-site bandwidth, storage, inode, CPU, memory, process, I/O, and PHP concurrency visibility;
- generated native configuration inspection and semantic diff;
- drift detection and last-known-good restoration;
- OLS and Enterprise-specific capability reporting without Apache fallback.

The canonical HTTP policy layer also provides separately testable resources for:

- `RequestHeaderPolicy` and `ResponseHeaderPolicy`, with typed set/add/remove/append behavior, normalized names, phase/order, route conditions, and protection for security-owned headers;
- `ApplicationEnvironmentPolicy`, with static values, typed conditional predicates equivalent to supported SetEnvIf/BrowserMatch outcomes, and `SecretRef` values delivered only to the selected site runtime;
- `WebNetworkAccessPolicy`, with ordered IPv4/IPv6 allow/deny sets at site, route, or file-pattern scope and an explicit trusted-proxy chain;
- `HTTPAbusePolicy`, with route/method, identity key, attempts/window, concurrency, action (`log`, `throttle`, `challenge`, or expiring block), duration, allowlist, counter scope, evidence, and false-positive recovery.

FilesMatch-style selection maps to typed route/file-pattern predicates; Expires behavior maps to `CachePolicy`; PHP directives map to `PHPProfile`. Header and environment conditions use a closed predicate grammar and cannot read arbitrary files, execute code, select another tenant, or override protected identity/credential variables. Client-address decisions use only the configured trusted-proxy chain and reject spoofed forwarding headers. Counters and blocks are bounded, observable, restart-safe where policy requires, and cannot turn a single request into an unbounded firewall writer. Each policy is rendered and certified separately on OLS and LSE; `.htaccess` is never a target runtime.

`FilesystemAccessPolicy` separates the mandatory site sandbox from an application-level PHP path policy. `strict` limits PHP to declared application/mutable/runtime roots. `compatibility` removes the redundant PHP open_basedir-style list while the mount namespace, site root, MAC, UID, descriptor, and network boundaries remain enforced. Additional roots are typed read/read-write mount grants to approved site/runtime resources. No mode exposes another tenant, host configuration, control state, sockets, proc/sys/dev, or arbitrary host path. Migration maps a disabled legacy open_basedir setting to this compatibility profile and reports any source dependency outside the safe sandbox.

`WebAccessPolicy` provides HTTP password protection for a site, WordPress instance, staging/preview route, or exact path. It contains realm, protected route/method scope, credential principals, state, expiry, and failure policy. Credential verifiers use the strongest format supported by both qualified engines, plaintext is delivered once only when generated, and rendered files live in root-owned non-document-root generations. The policy supports create/inspect/enable/disable/rotate/revoke/delete, login challenge tests, rate limiting, audit, backup/migration with reissue policy, and separate OLS/LSE validation. Staging defaults to protected access unless explicitly public.

`PreviewSession` provides the active pre-DNS preview journey. It binds one site/application generation to a one-use or short-lived opaque preview hostname/token, intended viewer, exact Host/SNI behavior, access policy, expiry, and request budget. The engine routes it through the same PHP, TLS, cache, WAF, and sandbox contracts while preventing hostname confusion, cookie/domain pollution, cache poisoning, open-proxy use, and access to another site. A refreshable screenshot is produced either by a local isolated renderer with metadata/control/private-network denial or by an explicitly consented provider with a declared URL/content-egress policy; it is never fetched by an unrestricted panel process. Preview and screenshot journeys have SSRF, DNS rebinding, redirect, size/time, privacy, stale-generation, OLS, and LSE tests.

### 10.5 PHP and LSAPI

PHP resources include RuntimeVersion, ExtensionCatalogEntry, PHPProfile, RuntimePool, and PHPActivation.

The platform MUST:

- install and remove supported LiteSpeed LSPHP versions from approved signed repositories;
- list installed and available versions and security state;
- select a runtime per application;
- install, enable, disable, and report supported extensions through a signed catalog;
- expose typed basic and advanced INI settings with version-aware validation;
- support bounded expert fragments owned by the PHP adapter;
- configure per-site SuEXEC LSAPI UDS/process groups;
- align max connections with worker/child limits;
- manage memory, request, upload, body, execution, idle, and concurrency limits;
- restart one site's PHP workers without indiscriminate global process killing;
- detect stale workers and configuration drift;
- validate a candidate with real PHP execution before activation;
- preserve the previous profile and worker generation for rollback.

EOL PHP is not automatically supported merely because a source site used it. Migration must select an available version and rehearse the application, or block. Arbitrary PECL compilation is not a normal privileged panel operation; a later build service may emit signed packages.

### 10.6 Cache and performance behavior

LSCache is first-class for both engines. Cache resources include global policy, application policy, exclusion, purge request, and observation.

The platform supports:

- enable/disable by application;
- public/private cache policy;
- path, cookie, query, method, and response exclusions;
- TTL and stale behavior;
- purge by application, path/tag where supported, and full cache;
- WordPress LSCache integration;
- cache hit/miss/bypass observation;
- safe interaction with WAF, authentication, preview, suspension, and deployment generations.

Security-critical routes MUST either be inspected before cache or bypass it. The UI must not imply WAF inspection on a cache path where the engine does not provide it.

### 10.7 Application storage and deployments

Every application declares one storage mode:

- `managed_release` uses immutable releases and an atomic active pointer. Writable uploads, sessions, caches, and other application data live in declared mutable stores outside the release.
- `mutable_tree` permits file-manager, SFTP, Git, WordPress, and application mutation in the active tree. Changes use snapshots/journal, generation checks, recovery points where risk requires, and MUST NOT claim pointer-only rollback.

A mode change is a planned migration. File, deploy, update, staging, restore, Git, and application operations MUST declare which tree and mutable stores they affect. Database writes always have a separate consistency and recovery frontier.

Managed-release deployment uses immutable releases and an atomic active pointer:

1. reserve storage and operation capacity;
2. fetch or assemble content as the site UID;
3. resolve and record immutable source identity;
4. run bounded build/deployment hooks;
5. generate application and runtime configuration;
6. expose the candidate only on a shadow route;
7. probe HTTP, PHP, dependencies, cache, and application health;
8. switch active_release atomically;
9. retain prior releases according to policy;
10. roll back the pointer when post-promotion health fails.

Mutable content such as uploads and application data MUST be explicitly separated from immutable release content. For a mutable-tree application, promotion is a durable saga over a staged copy/snapshot; activation may require a write fence, and rollback claims are limited to the verified snapshot and database/application consistency achieved.

### 10.8 OLS to Enterprise and Enterprise to OLS conversion

Conversion is a durable workflow:

1. verify the exact certified source/target version pair;
2. verify target installation, license, capacity, feature representability, packages, ports, and rollback resources;
3. pin the source desired generation;
4. render target configuration from the canonical model;
5. validate every application and expert fragment;
6. use an isolated shadow process only where vendor behavior supports it;
7. otherwise enter a bounded maintenance handoff;
8. arm a reboot-persistent rollback watchdog;
9. activate target packages, service, listeners, LSAPI, WAF, and cache;
10. probe all bindings and representative application behaviors;
11. confirm or restore the prior engine generation;
12. retain the old engine and configuration through the rollback window.

Zero-downtime conversion is a capability of a certified version pair, not a universal promise. Maintenance conversion is the baseline guarantee.

---

## 11. DNS and certificates

### 11.1 DNS resources

| Resource | Key fields |
|---|---|
| DNSZone | owner, origin, mode primary/secondary/native, SOA policy, nameservers, provider binding |
| DNSRecordSet | relative owner, type, TTL, canonical values, ownership |
| TransferPeer | address, role, zones, notify/transfer policy, TSIG reference |
| TSIGKey | algorithm, encrypted secret, rotation overlap |
| DNSProviderBinding | provider, zone ID, ownership mode, revision |
| DNSChangeSet | expected revision, semantic diff, provider receipts |
| DNSSECPolicy | algorithm, key lifecycle, rollover policy |
| DNSSECKeySet | protected KSK/ZSK or CSK material and state |
| DSPublication | expected DS and externally observed parent state |

An RRset is the mutation unit. The local PowerDNS adapter uses a loopback-only typed API or fixed helper and MUST NOT let arbitrary callers mutate database tables.

### 11.2 Record and zone outcomes

The platform MUST:

- create, adopt, inspect, update, suspend, export, reset/repair, and delete zones;
- manage default and custom nameservers;
- support primary, secondary, and native modes per zone;
- support NOTIFY, AXFR, IXFR, peer ACL, and TSIG rotation;
- reject manual edits to secondary-owned RRsets;
- provide data-driven support for every RR type accepted by the pinned PowerDNS version;
- provide dedicated validation for A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR, NAPTR, TLSA, SSHFP, DS, DNSKEY, SVCB, and HTTPS;
- support RFC 3597 representation for unknown types where PowerDNS supports them;
- increment the SOA serial exactly once per committed batch;
- expose transfer health, lag, provider drift, and authoritative observations;
- import without deleting and prune only after an explicit managed-set preview.

### 11.3 Cloudflare

The Cloudflare adapter MUST use scoped API tokens and support:

- zone discovery and explicit adoption;
- paginated record import;
- semantic dry-run;
- RRset create, update, and delete;
- TTL, priority, and proxied state;
- DNS-01 challenge;
- declared provider concurrency capability (`atomic_cas` or `observe_apply`) and conflict detection;
- rate-limit, timeout, partial-batch, revoked-token, and foreign-edit recovery;
- an explicit writer-ownership policy for every managed RRset.

Initial adoption MUST NOT prune foreign records.

### 11.4 DNS reconciliation

DNS mutation follows:

~~~mermaid
flowchart LR
    P["Plan + authorize"] --> V["Schema/RFC/provider validation"]
    V --> A["Apply under declared provider concurrency mode"]
    A --> O["Query authoritative servers"]
    O --> R["Probe independent recursive resolvers"]
    R --> C["Commit observed state"]
    A --> X["Partial/conflict reconciliation"]
    O --> X
~~~

The adapter never invents CAS from read-then-write. `atomic_cas` is claimed only when the provider gives a real conditional mutation primitive over the affected RRset. Under `observe_apply`, the node serializes only its own writers, snapshots exact before state, applies one effect, re-observes exact after state, and marks concurrent foreign edits `Conflict` or `Ambiguous`. Compensation is permitted only when the currently observed RRset exactly equals this effect's output; otherwise it preserves evidence and intended state for reconciliation. DNS cutover/rollback contracts name this weaker frontier or require an `atomic_cas` provider for an automatic guarantee.

### 11.5 DNSSEC

DNSSEC is a deliberate security enhancement even where CyberPanel only exposes partial schema. It is implemented because secure DNS lifecycle is necessary for safe migration and operation.

Enablement:

1. validate parent and secondary capability;
2. generate protected keys;
3. publish DNSKEY and signatures;
4. prove authoritative and validating-resolver behavior;
5. present exact DS records;
6. mark secure only after the parent DS is observed.

Rollover and disablement use safe overlap. Keys or DS records are never removed solely because a timer elapsed. Migration blocks when a parent DS exists but continuity cannot be proven.

### 11.6 Certificate resources

| Resource | Purpose |
|---|---|
| ACMEAccount | directory, contact, EAB, protected account key |
| CertificatePolicy | names, key algorithm, issuer, challenge order, renewal window, consumers |
| CertificateOrder | durable CA interaction |
| ChallengeAttempt | challenge ownership, presentation, observation, cleanup |
| CertificateGeneration | immutable key, chain, SANs, metadata, verification |
| CertificateDeployment | consumer, active generation, previous generation, probe |

Consumers include sites, child applications, aliases, panel hostname, Postfix, Dovecot, and FTPS.

### 11.7 ACME and deployment workflow

HTTP-01 uses an engine-independent challenge responder inserted above application rewrites, redirects, suspension, and document roots. DNS-01 uses provider adapters and supports wildcard and delegated challenge records.

Issuance:

1. validate names, ownership, CAA, clock, reachability, rate budget, and provider authority;
2. create or resume one ACME order;
3. present challenge with an ownership token;
4. prove propagation externally;
5. finalize and obtain the chain;
6. verify key match, SAN set, validity, chain, and policy;
7. stage an immutable generation;
8. activate consumers in a declared order, recording each per-consumer receipt and partially-applied state;
9. reload and probe each consumer;
10. confirm the saga or compensate each changed consumer to its previous generation;
11. remove only challenge records owned by the order.

Manual certificate import follows the same verification and deployment path. Renewal uses jitter, bounded exponential backoff, CA guidance where available, and expiry escalation. A provider failure MUST NOT replace a valid certificate with an untrusted self-signed certificate.

---

## 12. MariaDB and database workspace

### 12.1 Database resources

| Resource | Purpose |
|---|---|
| DatabaseInstance | node service, version, configuration, health, capacity |
| Database | site-owned logical database, charset, collation, quota |
| DatabasePrincipal | independent identity and host scope |
| GrantSet | typed database/table/routine privileges |
| NetworkAccessPolicy | interfaces, allowed CIDRs, TLS policy |
| DatabaseWorkspaceSession | short-lived scoped browser/API administration |
| TuningProfile | versioned typed settings and validated expert fragment |
| DatabaseUpgrade | supported version edge, snapshot, journal, probes |
| ExternalDatabaseBinding | managed remote instance, TLS identity, admin/service grant, consumers, health |

Site ownership does not imply unrestricted SQL privilege. Principals and grants are explicit. Physical state and control records MUST reconcile; creation and deletion cannot report success when only one side changed.

### 12.2 Lifecycle outcomes

The platform MUST:

- create, list, inspect, rename where safely supported, quarantine, recover, and delete databases;
- create, list, rotate, restrict, and delete database principals;
- manage least-privilege grants;
- enforce tenant and site ownership;
- expose actual MariaDB reconciliation status;
- stream imports and exports with progress, limits, checksum, cancellation, and durable receipts;
- capture a verified recovery point before destructive deletion unless a separately approved policy waives it;
- retain orphan-detection and repair workflows;
- account storage and quota from observed state;
- prevent concurrent quota and identity races.

### 12.3 Remote access

Remote database access is one coherent operation:

1. validate exact CIDRs and risk;
2. create or update account host scopes;
3. configure MariaDB listener and TLS;
4. configure firewall exposure;
5. restart or reload as required;
6. obtain the required verification level: structural, local_end_to_end, client_confirmed, or independent_external; a standalone host does not claim proof from every remote CIDR;
7. persist desired state at acceptance and withhold `Ready` until the policy-required proof level passes;
8. roll back grants, listener, and firewall together on failure.

Wildcard host access requires explicit high-risk approval. Loopback remains default.

### 12.4 Native database workspace

The database workspace provides the outcomes formerly delegated to phpMyAdmin:

- database, schema, table, view, routine, trigger, and event browsing;
- structure, index, constraint, and typed schema changes;
- row browsing and guarded editing;
- SQL editor with timeout, row/byte limits, cancellation, and EXPLAIN;
- streaming import and export;
- site-scoped user and grant management;
- variables, health, status, process list, slow-query insight, and controlled process termination.

The browser never receives a reusable database password. Sessions use an ephemeral scoped grant or backend connection and expire independently. Server-wide administration is a separate step-up capability.

Tenant SQL always executes as a site-scoped MariaDB principal without `FILE`, UDF/plugin installation, global/system privileges, `SET GLOBAL`, filesystem import/export, or administrative process authority. Connections enforce statement deadline, result row/byte limits, cancellation, connection concurrency, and audit. Server-wide tuning, account administration, process termination, physical import, and privileged diagnostics use a separate typed step-up broker.

### 12.5 Tuning and upgrades

Tuning uses version-aware fields and measured capacity. It produces a semantic diff, rejects unsafe combinations, stages configuration, validates syntax, activates under a watchdog, and runs service plus workload probes.

Major upgrades follow a declared graph. Preferred execution creates a side-by-side target from a physical clone or logical stream, validates upgrade tooling and application behavior, catches up changes where supported, briefly fences writes, and switches the local connection target.

Rollback is instant only before incompatible target writes. Beyond that frontier, recovery is a declared restore or reverse-migration workflow; a package downgrade is never advertised as database rollback.

### 12.6 Managed external MariaDB topology

A node MAY place hosted databases and explicitly qualified service schemas on a managed external MariaDB `DatabaseInstance`; control.db and every helper authority/protected store in Section 4.2 always remain local. This preserves CyberPanel's remote-MySQL topology without making an unverified arbitrary server part of the trust root.

Enrollment requires exact endpoint/SNI, pinned CA or certificate identity, TLS policy, capability/version/collation/authentication discovery, network policy, latency/capacity, administrative credential audience binding, and a least-privilege management account. The instance supports create/delete databases and principals, grants, rotation, imports/exports, backup/restore, tuning observations, health, outage, credential rotation, and optional replication only to the extent the adapter proves.

Each consumer binds explicitly. Site databases, PowerDNS schemas, mail metadata, and other services receive separate least-privilege principals and are qualified independently; one remote root credential is never shared across consumers. A remote instance outage creates consumer-specific degraded/unavailable state and does not move data silently to local MariaDB. Backup captures remote data through a database-native verified artifact, and migration can move between local and external instances with final writer fencing and application/service rehearsal.

External endpoint, CA, account, or topology changes are high-risk replans with fresh SecretAudienceBinding and CommitAuthorization. The UI distinguishes managed external database placement from allowing remote client CIDRs into a local instance.

---

## 13. Files, access, cron, Git, deployment, and staging

### 13.1 Site file manager

All site file operations run as the site UID beneath a pre-opened root descriptor. APIs carry relative components, not root-trusted absolute paths.

Required outcomes:

- paginated listing with hidden files and metadata;
- create file and directory;
- upload, resumable upload, range download, and checksum;
- read and edit text/code with encoding handling;
- copy, move, rename, and cross-filesystem verified move;
- soft delete, trash listing, restore, and permanent purge;
- chmod within policy and ownership repair;
- ZIP and tar-family archive creation and extraction;
- large-operation progress, cancellation, resume, and cleanup;
- optimistic edit conflict using inode/mtime/size/content digest;
- Unicode, whitespace, newline, and large filename handling.

Uploads reserve quota, stream to a private temporary inode, enforce limits, compute checksum, fsync, and atomically rename. Downloads stream from an already-authorized descriptor.

Archive operations enforce entry count, expanded bytes, compression ratio, nesting, path depth, and time budgets. They reject absolute paths, traversal, devices, FIFOs, unsafe symlinks/hardlinks, capabilities, and cross-root references.

### 13.2 Host filesystem session

Host-wide file administration is a separate HostFilesystemSession:

- explicit host.filesystem capability;
- recent MFA and recorded reason;
- short absolute and idle expiry;
- read-only default and separately granted write elevation;
- typed descriptor operations, not a shell;
- excluded product trust roots, devices, procfs/sysfs, and secret/executable roots;
- automatic recoverable previous generation for overwrite;
- immutable audit metadata;
- local management network or console restriction by default.

Product-owned configuration MUST be changed through its subsystem API, not this workspace.

### 13.3 FTPS, SFTP, SSH, and terminal

AccessCredential describes protocol, site, confined root, authentication method, quota, bandwidth policy, expiry, and revocation.

FTPS MUST support service enable/disable, reset/repair, account create/list/delete, password rotation, site/subdirectory roots, storage quota, bandwidth policy, status, passive-port firewall reservation, certificate deployment, and immediate revocation. Plain FTP authentication is disabled.

SFTP uses OpenSSH internal-sftp and the same site boundary. SSH shell, SFTP, and browser terminal are independent permissions. Public keys are parsed, policy-checked, fingerprinted, labelled, expirable, source-constrainable, and revocable. Generated keys prefer Ed25519. Host keys are pinned; disabled host-key checking is forbidden.

Terminal sessions use one-time audience-bound grants tied to user, site, origin, node, expiry, and authorization epoch. The PTY runs as the site UID inside its cgroup and namespaces with idle/absolute timeout and revocation. No new public proxy port or root PTY is created.

### 13.4 Cron

CronSchedule contains a parsed expression or supported macro, timezone, command, working directory, bounded environment, enabled state, overlap, timeout, missed-run policy, and notification policy.

Commands are intentionally arbitrary for parity but run only as the site UID in a transient constrained scope. Execution history records deterministic occurrence ID, start, end, exit status, cancellation, resource events, and redacted bounded output.

### 13.5 Git

RepositoryBinding, GitCredential, WebhookEndpoint, Deployment, and Release provide:

- repository initialization;
- attach, replace, and detach remote;
- deploy public-key generation and inspection;
- branches: list, create, switch, and track;
- status, files, commits, log, and per-file diff;
- configure identity and gitignore;
- commit, fetch, pull, and push;
- bounded automatic commit/push;
- signed/HMAC deployment webhooks;
- generic SSH/HTTPS plus supported provider convenience flows;
- bounded site-UID hooks and notifications.

Credentialed Git runs in a sanitized transport phase. `RepositoryBinding` pins the canonical protocol, normalized host/port/path, provider account/audience, host-key or CA policy, permitted refs, and credential SecretAudienceBinding. System/global/repository credential helpers, `core.sshCommand`, `url.*.insteadOf`, proxy/environment transport overrides, askpass, arbitrary CA/known-host paths, and repository hooks/filters are disabled for that phase. The helper/agent releases a credential only for the exact bound origin/account; egress permits only that origin and validated addresses/redirect policy.

Submodules, LFS, filters, recursive dependencies, and alternate object stores are disabled while a credential is present unless each is a separately typed, origin-bound resource with its own credential and limit. Repository-scoped provider keys are preferred. User hooks run later as the site UID with no credential FD, agent socket, helper, or inherited transport environment. Host keys are pinned. Secrets do not persist in repository configuration. Webhooks validate provider signature, timestamp, delivery ID, allowed ref, and replay window, then enqueue one durable deployment. They never run Git synchronously.

### 13.6 Staging, clone, and selective synchronization

StagingRelation links source and target applications. A clone creates a distinct application, bindings, database, secrets, schedules, and backup policy. Outbound mail, production webhooks, marketing, and external integrations are disabled by default.

Synchronization declares direction and components:

- full or selected file paths;
- media;
- full database or selected tables;
- application-aware transforms;
- production promotion policy.

Workflow:

1. validate ownership, direction, target risk, and capacity;
2. snapshot source revision;
3. create a verified target recovery point;
4. build new file/database generations;
5. perform serialization-aware WordPress URL/data replacement;
6. probe on a shadow route;
7. cross the declared activation frontier in dependency order with per-component receipts;
8. compensate to the verified prior target generation where safe, or expose `partially_applied`/`manual_intervention_required` precisely.

Source remains unchanged. Production target data is never mutated in place before rollback material is ready.

---

## 14. Backup, restore, transfer, and disaster recovery

### 14.1 Backup model

| Resource | Purpose |
|---|---|
| BackupPolicy | scope, components, schedule, RPO, consistency, retention, destinations |
| Repository | adapter, credentials, encryption domain, immutability, health |
| BackupRun | durable capture operation |
| RecoveryPoint | atomic logical commit across required artifacts |
| ComponentArtifact | files, DB, mail, DNS, desired config, app, container, metadata |
| Copy | repository-specific verified materialization |
| Hold | legal/operator retention override |
| Lease | active backup/restore/replication/prune protection |
| RestorePlan | mappings, conflicts, secrets, network, target policy |
| RestoreRun | materialize, validate, promote, rollback |
| DRBundle | signed bootstrap/catalog/key-recovery metadata |

The initial content engine MAY use Restic, but the product manifest, catalog, consistency, provider, retention, restore, and evidence contracts are authoritative.

### 14.2 Required components

A site recovery point can include:

- file-tree manifest with metadata and Merkle root;
- MariaDB logical or physical artifact with tool/schema/version and consistency watermark;
- mailboxes, metadata, Sieve, aliases, routes, and signing state;
- DNS zones, RRsets, transfer and DNSSEC metadata;
- certificates and explicitly included encrypted keys;
- canonical desired resources and configuration generations;
- WordPress/application descriptor, plugins/themes, mutable content, and secrets policy;
- Git and schedule definitions;
- container workload definitions and application-aware volume artifacts;
- security, access, and provider-binding metadata according to policy.

Node recovery is a distinct privileged DR product. It includes control.db; execd/taskd/secrets/authn/approvals/provider-effects/container/watchdog stores; audit segments and checkpoint head; secret and TOTP wrapping keys; assurance, approval, audit-checkpoint, node and helper identity keys according to separate escrow policy; protected approver identities/policy/recovery epochs; registries, tombstones, fences, receipts, revocation/epoch state, trust metadata, and bootstrap/restore ordering. Recovery rotates eligible session/provider/assurance/approval/audit/node credentials, advances epochs, prevents pre-recovery replay, verifies audit continuity or records an explicit discontinuity, and reconciles host/provider effects before readiness. It cannot be restored through an ordinary tenant UI.

### 14.3 Consistency and commit

Consistency modes are application-consistent, database-consistent, crash-consistent, and point-in-time capable. The UI MUST label the achieved mode.

Capture:

1. acquire resource and retention leases;
2. reserve measured staging and repository capacity;
3. establish an application-aware write barrier using hooks/LSAPI drain and flush database/mail/filesystem state;
4. while the barrier is held, create stable read views for every captured mutable component: a qualified LVM/filesystem snapshot or immutable release plus snapshot of mutable stores, a database snapshot transaction/native artifact with position, and a Dovecot dsync/snapshot checkpoint;
5. record one barrier ID, source generations, and exact stable-view identities, then release the barrier only after every required view exists;
6. stream artifacts from those stable views to a staging namespace;
7. verify object digests, counts, sizes, decryptability, and manifests;
8. re-read required metadata and configured samples;
9. publish a signed commit marker last;
10. mark the RecoveryPoint restorable only when all required artifacts and destination policy pass.

Partial copies remain non-restorable and reconcilable. Local staging is not removed until a verified remote commit is observed.

If a stable view cannot be created, writers remain fenced through the entire capture or the component is labelled with a precisely defined `fuzzy_crash_consistent` mode and cannot satisfy application-consistent policy. A short barrier ID never blesses bytes read later from a changing live tree. Qualification mutates, renames, truncates, deletes, and appends files/mail/database rows concurrently at every snapshot/capture boundary.

### 14.4 Destinations

GA destination implementations include:

- local repository;
- remote managed node;
- SFTP;
- AWS S3;
- DigitalOcean Spaces;
- MinIO;
- Wasabi S3;
- Backblaze B2 S3;
- generic S3-compatible endpoint;
- Google Drive;
- a working hosted/off-node managed backup journey.

Each named adapter requires conformance tests for authentication, listing, pagination, upload, resume, checksum or equivalent verification, retention, restore, rate limiting, timeout, revoked credentials, partial failure, and provider outage.

Dropbox and other additional GridPane-derived storage adapters are post-parity. Wasabi and Backblaze are named CyberPanel baseline choices and therefore remain independent GA obligations even though they reuse the qualified SigV4 engine.

### 14.5 Retention and immutability

Retention supports GFS, tags, minimum copies, minimum age, legal holds, and repository-native immutability.

Pruning:

1. create and verify a new point before pruning old data when policy requires;
2. scope candidates strictly to the policy namespace;
3. compute dependency reachability;
4. ensure required independent survivors;
5. acquire an exclusive prune lease;
6. mark candidates;
7. delete only unreachable repository objects;
8. verify the catalog afterward.

Prune authority SHOULD be separate from create authority for ransomware resistance. Provider object lock/versioning is used where available. Anomaly detection can freeze retention.

### 14.6 Restore

Restore never writes unverified data directly over the active resource:

1. authorize by tenant-scoped opaque references;
2. verify signature, manifest, encryption, tool compatibility, capacity, and archive safety;
3. optionally scan imported content;
4. allocate new target IDs or validate mappings;
5. restore files to a new release, database to a temporary database, and mail to an isolated namespace;
6. rotate credentials and tokens by default;
7. rewrite only declared application identities;
8. probe the complete restored application;
9. activate routing, pointers, database consumers, mail, and schedules in a declared saga order with per-component receipts;
10. record a `TARGET_WRITE_WATERMARK`, retain old state as recovery evidence, and classify the post-activation recovery frontier.

Blue/green same-site restore is available only when the application adapter can safely switch release, database endpoint/credential, mutable stores, and background writers. Otherwise the workflow fences application writes, captures a verified target recovery point, restores under declared downtime, and exposes its irreversible frontier. New-site restore uses explicit domain/path/identity mappings. Path-level restore uses the same containment and conflict rules as the file manager.

Automatic switch-back to old state is permitted only before the restored target accepts its first persistent write, or when a separately qualified bidirectional write-capture/data contract proves lossless reversal. After `TARGET_WRITE_WATERMARK`, the old generation is not called rollback-ready: failure uses fail-forward repair or a separately rehearsed reverse-reconciliation/restore with measured RPO and explicit data-loss decision. Routing rollback alone must never reactivate a stale database or mutable store.

### 14.7 Cancellation and failure

Backup and restore runs use real operation IDs and process/group receipts, not caller-provided status paths or reused PID files. Cancel requests reach declared safe checkpoints. A stale PID can never kill an unrelated process.

Remote upload result is a typed receipt. Local data is retained until remote verification. A failed upload cannot advance last-success or trigger source deletion. Deadlines, retry, backoff, and provider idempotency are mandatory.

### 14.8 Recovery proof

A backup's evidence states separately:

- `ObjectVerified`: required object hashes/counts/bytes/decryptability passed;
- `ManifestVerified`: the signed manifest and dependency closure passed;
- `RecoveryTested`: an isolated representative or point-specific restore passed under policy.

A backup policy is healthy only when:

- its signed commit and required artifacts verify;
- encryption recovery is available through the declared independent key path;
- retention leaves required survivors;
- a scheduled isolated restore drill for the applicable support tuple, repository, workload class, and risk has passed within policy; a high-value policy MAY require an individual point drill;
- application, database, mail, DNS, and content probes match the declared recovery scope.

GA requires bare-host control-plane recovery and clean-room site, database, mail, DNS, and full-node drills.

---

## 15. Mail server, webmail, delivery providers, and email marketing

Mail is three separately engineered products with independent security, performance, and release gates:

1. managed mail server and delivery policy;
2. complete webmail;
3. consent-aware email marketing.

Full-parity GA requires all three.

### 15.1 Managed mail architecture

The recommended baseline stack is:

- Postfix for SMTP ingress, submission, queueing, and routing;
- Dovecot for IMAP, LMTP, ManageSieve, mailbox quota, and mailbox synchronization;
- OpenDKIM or an equivalent typed signing adapter;
- Rspamd as the primary spam/policy engine;
- Redis for Rspamd and declared mail consumers;
- ClamAV for malware scanning.

SpamAssassin and MailScanner outcomes are preserved through import, diagnostic, and optional legacy profile semantics, but the default installation MUST NOT run multiple competing primary filter planes. The active filter ownership is explicit.

All daemon configuration is rendered from canonical resources into immutable generations and activated as one dependency-aware consistency group.

That group is a generation-pinned multi-service saga, not a fictitious atomic transaction across Postfix, Dovecot, Rspamd, DKIM, Redis, and certificate/firewall consumers. It records a receipt and active generation per consumer, retains the compatible old group, orders activation/deactivation safely, and blocks incompatible traffic until required cross-service probes pass. Failure compensates each changed consumer where safe and otherwise exposes exact `partially_applied`, `degraded`, or `rollback_failed` state.

### 15.2 Mail resources

| Resource | Purpose |
|---|---|
| MailDomain | ownership, state, delivery policy, DNS/signing status |
| Mailbox | address, verifier, quota, state, storage observation |
| MailAlias | alias or forwarding destinations |
| CatchAllPolicy | domain fallback behavior |
| AddressRule | plus, pattern, or other typed address transformation |
| PipeHandler | capability-bound site-UID delivery handler |
| SieveRule | server-side user filtering |
| MailPolicy | domain/mailbox sending limits, authentication, filtering |
| MailLogPolicy | domain/mailbox delivery-event detail, access, retention, and storage budget |
| SigningIdentity | DKIM key lifecycle and selectors |
| RelayBinding | external delivery provider and routing state |
| QueueMessage | normalized queue metadata and controlled content view |
| DeliveryEvent | local or provider delivery outcome |
| MailDiagnosticRun | service, DNS, TLS, routing, queue, reputation evidence |
| MailRepairPlan | typed previewable repair |

### 15.3 Domain and mailbox outcomes

The platform MUST support:

- create, inspect, suspend, resume, repair, and remove mail domains;
- DNS readiness and safe SPF, DKIM, DMARC, MX, and autoconfiguration records;
- create, list, suspend, reactivate, delete, and restore mailboxes;
- password rotation using supported verifiers;
- storage quota and observed usage;
- aliases and multi-destination forwarders;
- catch-all;
- plus addressing;
- pattern forwarding;
- server-side Sieve rules;
- safe pipe delivery;
- domain and mailbox hourly/monthly sending limits;
- policy-server decisions and logs;
- per-domain relay enablement;
- mail certificate deployment and repair;
- DKIM selector generation, rotation, overlap, publication, verification, and retirement.

A PipeHandler is not an arbitrary Postfix command. It references a signed site-owned handler, runs as the site UID in a constrained scope, consumes a bounded spool item, has timeout and retry semantics, and cannot access host secrets or other sites.

### 15.4 SMTP, IMAP, and security

The service supports:

- SMTP port 25 where the environment permits;
- authenticated submission on 587 and optional 465;
- IMAP over TLS on 993;
- LMTP delivery;
- ManageSieve;
- TLS and certificate lifecycle;
- SASL authentication;
- explicit relay policy;
- IPv4 and IPv6;
- inbound/outbound size, recipient, rate, and concurrency limits;
- brute-force and abuse detection;
- per-tenant and per-domain visibility;
- deterministic repair of owned configuration.

Plaintext credentials MUST NOT be accepted without an authenticated encrypted channel. Open relay MUST be impossible under default or partial configuration.

### 15.5 Queue, logs, limits, and diagnostics

Operators with appropriate scope can:

- view queue counts and categorized health;
- search and paginate queue metadata;
- inspect a bounded, redacted message representation under step-up authorization;
- retry, defer, hold, release, or delete selected messages;
- flush a scoped queue;
- inspect delivery logs and per-domain/mailbox statistics;
- diagnose DNS, TLS, authentication, routing, filtering, reputation, storage, quota, and service dependencies;
- preview and run reset/repair plans.

Queue actions use immutable message identity and revalidate current queue state. A UI index or stale queue ID is never authority.

`MailLogPolicy` preserves per-mailbox and per-domain delivery-log control. It defines enabled state, event classes, detail level, retention, access roles, export policy, redaction, storage budget, and purge schedule. The default records envelope/result/timing/queue correlation and diagnostic codes but not message bodies, credentials, authentication material, or unrestricted headers. Disabling detailed logs stops future optional detail; it does not erase mandatory aggregate counters, security events, audit records, active incident evidence, or provider receipts. Purge deletes only policy-owned ordinary delivery events after holds and retention, records the deletion range/count, and cannot wildcard-delete daemon or audit storage.

Usage and expected diagnostic impact are visible before a policy change. Existing data follows its captured policy and legal/incident holds. Backup, restore, and migration preserve policy and, when selected, bounded delivery history with provenance; a destination may require deliberate history exclusion but may not silently enable logging or claim imported history. Tests cover concurrent delivery/purge, disabled logging, storage pressure, tenant isolation, redaction, retention, restore, and migration.

### 15.6 Filtering and malware

Rspamd policy, Redis dependency, ClamAV signatures, rule versions, allow/block lists, scores, actions, and provider ownership are canonical resources. Updates are pinned and health-checked.

The platform MUST expose:

- filter service status and health;
- detection thresholds and actions;
- domain or mailbox policy where supported;
- safe allow/block rules;
- quarantined or rejected-message evidence;
- malware signature health;
- update and rollback state;
- bounded diagnostic logs;
- service reset/repair.

Loss of Redis, Rspamd, ClamAV, or an external filter provider creates a visible degraded state. The product MUST state whether mail is temporarily accepted, deferred, or rejected under the selected fail policy.

### 15.7 Complete webmail

Webmail resources and operations include:

- WebmailProfile and short-lived WebmailSession;
- account discovery, secure SSO, and multi-account switching;
- folders and hierarchy;
- message list, pagination, bounded search, and cancellation;
- read, thread, reply, reply-all, forward, compose, and send;
- drafts and sent mail;
- attachment streaming, upload, download, and malware policy;
- move, copy, delete, expunge, flags, read/unread, starred, and spam actions;
- contacts and contact groups;
- Sieve filters;
- signature, identity, display, timezone, and preference settings;
- remote-image proxy with SSRF, DNS-rebinding, scheme, address-range, type, byte, and time limits.

The implementation MUST use mature IMAP and MIME libraries and real Dovecot interoperability. It MUST NOT implement a casual bespoke IMAP/MIME parser.

Panel SSO uses a short-lived mailbox-scoped OAuth2/OAUTHBEARER or equivalent token. It MUST NOT use a reusable global Dovecot master password. HTML is sanitized and rendered under a dedicated CSP. Message bodies, subjects, addresses, and headers are attacker-controlled output.

Webmail acceptance includes MIME fuzzing, malformed multipart structures, huge headers, Unicode and directionality, HTML/CSS attacks, attachment bombs, slow IMAP, search cancellation, and cross-account/cross-tenant denial.

### 15.8 External delivery provider

Functional parity requires at least one working outbound-delivery integration with:

- provider account connection and health;
- sending-domain enrollment;
- ownership verification;
- SPF, DKIM, and DMARC guidance or managed DNS changes;
- SMTP credential creation, one-time display, rotation overlap, revocation, and expiry;
- per-domain relay enable/disable;
- delivery, bounce, reject, complaint, and suppression logs;
- aggregate and domain statistics;
- provider quota and rate state;
- provider timeout, revoked credential, partial outage, and total-loss behavior.

Resources are DeliveryProviderConnection, VerifiedSendingDomain, SMTPCredential, RelayPolicy, DeliveryStats, DeliveryLog, and SuppressionEvent.

CyberMail vendor identity is not required, but an empty provider SPI is not parity.

### 15.9 Email marketing

Resources:

- MarketingList;
- Subscriber;
- ConsentEvidence;
- Suppression;
- VerificationRun;
- SMTPRoute;
- CampaignTemplate;
- Campaign;
- CampaignAttempt;
- BounceEvent;
- ComplaintEvent;
- UnsubscribeEvent.

Required outcomes:

- list create/list/update/delete;
- subscriber add, bulk import, export, deduplicate, verify, suppress, and remove;
- address-verification runs, progress, and logs;
- local or provider SMTP route configuration;
- versioned templates and preview;
- compose, schedule, start, pause, resume, cancel, and inspect campaign jobs;
- per-recipient attempt history;
- unsubscribe links and immediate suppression;
- bounce and complaint ingestion;
- sending throttles, tenant quota, domain readiness, and abuse policy;
- localized rendering and safe variable substitution.

Marketing runs in a separate bounded queue, not paneld. Sending is disabled until domain verification, consent provenance, suppression, and complaint handling pass. Imported legacy lists without adequate consent do not automatically become sendable.

Suppression reasons have distinct legal state. Unsubscribe, complaint, and global-do-not-contact suppression cannot be overridden by an administrator or campaign; removal requires a separately evidenced, later affirmative opt-in/resubscription event permitted by policy. Hard-bounce, transient/provider, administrative safety, and test suppressions have explicit review/expiry/clear rules but cannot stand in for consent. Every queued attempt rechecks the current immutable suppression generation immediately before provider/local submission; unsubscribe/complaint racing a queued attempt must win before any unsent attempt.

---

## 16. Application catalog, WordPress, staging, and scanning

### 16.1 Application model

| Resource | Purpose |
|---|---|
| ApplicationDefinition | signed pinned recipe, versions, dependencies, support matrix, probes |
| ApplicationInstallation | selected recipe, site, root, runtime, DB, secrets, health |
| ComponentInventory | core, extensions, themes/modules, versions, digests, state |
| UpdatePolicy | scope, channel, schedule, exclusions, maintenance, failure policy |
| Deployment | immutable release and promotion |
| CloneRelationship | source/target lineage |
| ScanRun | scan mode, source snapshot, provider, state |
| Finding | evidence, severity, confidence, affected digest |
| RemediationPlan | reviewed typed mutation with recovery |

Application definitions are content-addressed, signed, and version-pinned. They declare OS/architecture, PHP/extensions, database, ports, storage, engine behavior, install/update/backup/restore probes, and support lifecycle. No recipe executes a remote mutable script as root.

### 16.2 Required application catalog

GA MUST ship working, certified installation and lifecycle recipes for:

- WordPress;
- Joomla;
- PrestaShop;
- Magento Open Source;
- Mautic;
- n8n as a managed container application.

CyberPanel's Magento tile is exposed but its implementation is incomplete. Functional parity means delivering a working supported Magento recipe, not reproducing the broken state.

Each recipe requires clean install, failure cleanup, application login/readiness, update, backup, restore, uninstall/quarantine, OLS, Enterprise, and applicable OS fixtures. A generic future application SDK is not evidence that a named installer exists.

### 16.3 Application discovery and adoption

Discovery MUST:

- operate under the site UID;
- locate canonical roots without following cross-root links;
- validate expected application files and runtime;
- validate database reachability through declared application configuration;
- record version, components, health, and ownership;
- refuse ambiguous or duplicate roots;
- adopt only through an explicit reviewed operation.

Loose filesystem paths are not application records.

### 16.4 WordPress outcomes

The WordPress product MUST provide:

- install, import, discover, adopt, inspect, repair, quarantine, and remove;
- secure one-time administrator login;
- core version and health;
- plugin list, install, activate, deactivate, update, delete, and policy;
- theme list, install, activate, update, delete, and policy;
- configurable certified plugin bundles/catalog;
- general, URL, permalink, search-indexing, debug, maintenance, and update settings;
- core minor, major, and security update policies;
- plugin/theme automatic update selection and exclusions;
- core reinstall and checksum/integrity verification;
- WP-CLI operations as site UID;
- LSCache state and management;
- staging create, inspect, delete, push, pull, and selective synchronization;
- clone and domain change with serialization-aware rewriting;
- local, remote, scheduled, and on-demand WordPress recovery points;
- restore and point-in-time linkage where repository supports it;
- quick, full, custom, and scheduled security scans;
- scan history, live progress, findings, and safe remediation;
- notifications, maintenance windows, and operation history.

### 16.5 Secure WordPress autologin

Autologin uses:

1. a one-use, short-lived, audience/site/user-bound grant;
2. a minimal signed product MU-plugin or equivalent local exchange endpoint;
3. origin and CSRF validation;
4. immediate consumption and expiry;
5. explicit audit and revocation.

It MUST NOT create or reuse a persistent hidden administrator, return a password, or place a bearer token in a durable URL/log.

### 16.6 Updates and rollback

Application updates:

1. create and verify a recovery point;
2. validate runtime, dependencies, signatures/checksums, and policy;
3. create an immutable working release or safe site snapshot;
4. execute as site UID;
5. run component and application probes on a shadow route where possible;
6. switch the release pointer atomically where `managed_release` applies and activate database/mutable/application effects as an explicit saga;
7. retain prior release and verified data recovery material;
8. roll back the pointer and compensate pre-frontier effects on failure, or enter a precise recovery state after an irreversible data frontier;
9. pause future automatic updates after repeated failure.

Fleet-wide canary policy and visual-regression automation are GridPane-derived post-parity enhancements. Per-site update policy, rollback, and health are GA.

### 16.7 Scanner architecture

ScannerProvider may be local signatures/heuristics, a commercial provider, or explicitly consented external AI. Scan modes include upload/event, quick, full, custom path, scheduled, post-restore, and integrity comparison.

Local scanning:

- works on an immutable snapshot or stable manifest;
- runs non-root with site containment;
- has CPU, I/O, memory, time, archive-depth, entry, and expanded-byte budgets;
- does not follow symlinks or mounts outside scope;
- records scanner/rules/model/prompt versions and evidence digests;
- treats content as hostile data, never agent instructions.

Findings include tenant, site, path/resource, hash, first/last seen, engine, version, signature/reason, confidence, severity, and evidence reference.

### 16.8 Remediation

AI or provider output is advisory. Remediation is a distinct operation with:

- reviewed action;
- current-hash precondition;
- recovery point;
- quarantine or replacement artifact;
- exact path/resource scope;
- site-UID execution;
- post-action scan and application probe;
- restoration procedure;
- audit evidence.

High-confidence policy may automatically quarantine when configured. Irreversible deletion based solely on AI classification is forbidden. External content upload requires tenant-visible data-egress consent, provider, purpose, region, retention, and deletion policy.

---

## 17. Containers, native resource isolation, and CloudLinux

### 17.1 Container resources

| Resource | Purpose |
|---|---|
| ContainerRuntime | installed engine, version, ownership tier, health |
| OCIImage | registry, repository, tag, resolved digest, signature/SBOM/vulnerability |
| RegistryCredential | scoped secret reference |
| ContainerWorkload | image, command model, environment, secrets, limits, lifecycle |
| ContainerApplication | multi-workload signed recipe and health |
| ContainerPackage | tenant offering and aggregate limits |
| NetworkAttachment | private network and egress policy |
| Volume | broker-issued storage identity, ownership, backup |
| PortExposure | private port to typed OLS/LSE binding |
| ContainerExecSession | one-use audited scoped exec |
| ContainerExport | OCI/workload/data export manifest |

### 17.2 Required outcomes

The platform MUST support:

- install, verify, update, repair, and remove the runtime;
- registry search, tag listing, and digest-resolved pull;
- local image listing, layer/history inspection, and safe removal;
- create, import/adopt, inspect, and assign ownership;
- configure environment, secret references, volumes, ports, memory, CPU, restart policy, and health;
- start, stop, restart, recreate/rebuild, quarantine, and delete;
- status, logs, stats, top/processes, health, metadata, and resource observation;
- audited exec;
- export/import workload definitions, images, and separately managed data;
- Docker-backed sites/packages and n8n;
- WordPress container application where the supported recipe requires it;
- domain reverse proxy through both web engines;
- failure rollback and persistent-volume recovery.

### 17.3 Trust tiers

**Node-admin rootful tier**

- uses the official rootful runtime;
- only node administrators create or materially reconfigure workloads;
- tenant assignment may grant bounded view, logs, start, stop, restart, and application-specific actions;
- rootful runtime access is treated as host-root-equivalent.

Exec in the rootful tier is node-administrator-only and high risk. container-broker requires a fresh CommitAuthorization bound to workload generation, resolved image/runtime identity, effective container user, mounts, capabilities, namespaces, command/session digest, limits, and expiry. If that workload can act as host root through its effective identity, devices, capabilities, mounts, runtime sockets, or kernel surface, exec is never tenant-delegable and the confirmation states host-compromise authority explicitly.

**Managed tenant tier**

- uses a measured rootless or user-namespace backend;
- accepts only canonical or signed-recipe workload fields;
- isolates namespaces, user mappings, networks, volumes, images, quotas, and secrets;
- exposes application ports privately through a typed web binding;
- denies privileged mode, host PID/IPC/network, devices, runtime sockets, dangerous capabilities, arbitrary sysctls, and unconfined profiles.

Tenant exec is a one-use container-broker session inside the selected workload's own cgroup, namespaces, filesystem, seccomp/MAC profile, and network policy. Its container identity must map to an allowed non-host-root user-namespace identity. The broker rejects a host-root mapping, privilege/profile widening, mount changes, runtime-socket access, and exec into a rootful/admin workload. Neither tier routes exec through site-taskd or exposes a daemon socket to the browser.

The implementation MUST prototype and measure a shared brokered containerd/Podman-style or equivalent backend before selecting one daemon per site. Functional parity does not require a tenant-visible Docker socket.

### 17.4 Mounts, networks, and secrets

Bind mounts resolve only through broker-issued Volume IDs or approved paths beneath the owning site root. Root, /etc, /proc, /sys, device trees, control sockets, runtime sockets, and cross-site paths are unrepresentable.

Workloads receive private networks. Public ingress uses OLS/LSE. Egress has explicit DNS and destination policy. Every resolution and redirect is revalidated; resolved addresses are enforced for a TTL-bounded interval; loopback, link-local, metadata, control, and private ranges are denied unless an exact approved destination requires them; DNS rebinding cannot bypass the address policy; credentials are never forwarded across an origin change.

Container runtimes MUST NOT publish host ports or program host iptables/nftables directly. Runtime firewall programming is disabled on each qualified backend. HTTP/S ingress always terminates through canonical OLS/LSE bindings. A non-HTTP `PortExposure` creates a typed managed port-proxy or canonical NAT generation plus `FirewallPolicy`; panel-execd's firewall adapter is the sole rule writer and owns IPv4/IPv6 filter/NAT ordering, interface/source scope, hairpin behavior, persistence, rollback, and reboot reconciliation. Container creation cannot start public ingress until firewall/listener validation passes, and deletion removes exposure before workload/volume cleanup. If direct daemon rules cannot be disabled or exact reserved-chain ownership/reconciliation cannot be proven for a runtime version, that runtime tuple fails closed.

Ordinary non-secret environment remains supported. Secret values become SecretRefs and are delivered through protected files, tmpfs, or runtime-native secret mechanisms.

### 17.5 Image and recipe policy

Tags resolve to digests at operation acceptance. Policy can require:

- approved registry;
- signature identity;
- SBOM;
- vulnerability threshold and VEX;
- freshness;
- architecture;
- license classification;
- reproducible recipe;
- immutable dependencies.

Compose is an interchange format only. It is parsed, normalized, diffed, and rejected when it requests unsupported or host-escape behavior. It is never passed through as unreviewed runtime instructions.

### 17.6 Container application deployment

Deployment:

1. validate signed recipe and resolved image digests;
2. reserve aggregate tenant/package capacity;
3. create owned private volumes and networks;
4. materialize secrets;
5. start dependencies in declared order;
6. run internal health probes;
7. create a shadow OLS/LSE binding;
8. verify external application behavior;
9. activate routing;
10. record volume/data generation and first-write watermark, then retain the prior workload generation as recovery evidence.

Failed stateless objects are cleaned safely. Pre-existing or newly written persistent volumes remain quarantined with diagnostics until explicit disposition.

Automatic route reversion is valid for a stateless workload, before the new generation's first persistent write, or when both generations share a separately proven backward-compatible data/schema contract. Once a new workload writes incompatible volume/database state, the prior generation is not called rollback-ready and is never restarted against changed storage by default. Both generations and data evidence are quarantined while the operation fails forward or follows a separately rehearsed recovery/reverse-migration path with measured RPO.

### 17.7 Native resource isolation

ResourceProfile and ResourceLimitBinding cover scoped controls:

- CPU weight, quota, and measured throttling;
- memory low/high/max, swap, and OOM behavior;
- pids.max;
- block-device I/O weight, bytes per second, and IOPS;
- disk bytes and inode soft/hard limits;
- LSAPI/PHP entry and concurrency limits;
- network accounting, monthly transfer, and a separately qualified rate backend;
- execution timeout and background-work policy.

The site UID subtree contains PHP, cron, Git, builds, deployments, terminal, scanners, and site helpers. Children cannot escape by daemonizing. These controls do not automatically constrain shared web-engine, MariaDB, mail, or DNS daemon work; those use their separately declared enforcement owners and status from Section 6.7.

Disk and inode enforcement uses project quotas on a certified filesystem. Installation blocks or schedules an explicit remount/reboot when enforcement is unavailable. Network rate limiting is claimed only after the chosen tc/nftables/eBPF or LiteSpeed boundary mechanism passes PHP, cron, terminal, and container tests; cgroup v2 alone is not described as a network controller.

### 17.8 CloudLinux

CloudLinux is a conditional-baseline node platform adapter over the same ResourceProfile: an operator need not install CloudLinux, but a parity release MUST make the CyberPanel-equivalent CloudLinux/CageFS outcomes available and qualify its declared CloudLinux 9 tuples. It MUST support:

- LVE SPEED;
- PMEM and supported VMEM behavior;
- IO and IOPS;
- EP;
- NPROC;
- inode limits;
- package assignment and usage;
- CageFS install, initialize, update, enable/disable per site, status, and drift repair.

Unsupported mappings create explicit conditions. Native and LVE controllers MUST NOT compete; one backend owns each controller. Native equivalent isolation remains available on non-CloudLinux GA platforms.

### 17.9 Container acceptance

GA escape testing includes:

- host paths and runtime sockets;
- devices, capabilities, sysctls, seccomp, and AppArmor/SELinux;
- host PID, IPC, user, mount, and network namespaces;
- user mapping and setuid behavior;
- cgroup/quota escape and fork bombs;
- cross-tenant image, layer, volume, network, log, and secret access;
- procfs/sysfs/kernel interfaces;
- metadata-service access;
- Docker/firewall interaction;
- reboot and runtime upgrade;
- malicious Compose and archive import;
- slow logs and exec backpressure.

---

## 18. Firewall, SSH security, WAF, malware, investigation, and repair

### 18.1 Security resources

| Resource | Purpose |
|---|---|
| SecurityPosture | desired profile, observed compliance, drift, last reconciliation |
| ExposureService | service identity, protocol, port, interfaces, source restrictions |
| FirewallPolicy | one backend, zones/interfaces, defaults, rules, dynamic sets |
| ChangeTransaction | diff, validators, rollback lease, probes, approval, outcome |
| SSHPolicy | listeners, authentication, principals, algorithms, limits |
| SSHKey | public key, fingerprint, owner, constraints, expiry, state |
| LoginEvent | normalized successful/failed authentication evidence |
| HostSession | active SSH/logind session identity |
| ProcessIdentity | PID, boot ID, start time, cgroup, executable, owner |
| WAFPolicy | engine, provider, rule version, mode, thresholds, limits |
| WAFExclusion | exact scope, evidence, owner, reason, expiry |
| ScanRun | malware or posture scan |
| Finding | normalized finding and evidence |
| QuarantineItem | reversible isolated artifact |
| DiagnosticRun | read-only subsystem diagnosis |
| RepairPlan | typed diff, snapshot, validation, activation, rollback |
| Incident | correlated evidence, response, state, timeline |

### 18.2 Firewall

Exactly one backend owns the canonical policy:

- firewalld with its nftables backend on certified configurations; or
- direct nftables where firewalld is intentionally absent.

The panel MUST NOT write direct nftables rules while firewalld owns the firewall.

Baseline:

- default-drop unsolicited inbound traffic;
- established/related traffic and loopback;
- required ICMP and ICMPv6;
- equal IPv4/IPv6 intent;
- explicit interface/zone binding;
- web 80/443 when enabled;
- management ports restricted by policy;
- DNS, mail, FTPS passive range, database, container, monitoring, and provider ports only when declared services require them;
- time-limited rules;
- dynamic threat sets in reserved namespaces;
- runtime firewall programming disabled or an exact version-qualified reserved-chain contract; canonical filter/NAT owns every PortExposure across IPv4/IPv6;
- foreign-rule preservation and drift reporting.

Firewall change:

1. build a semantic diff;
2. reject conflicts, invalid ranges, provider namespace overlap, and loss of all recovery access;
3. install a durable rollback lease with the known-good policy;
4. apply runtime state;
5. validate effective kernel policy;
6. obtain the policy-required structural/local/client/independent proof for intended and denied IPv4/IPv6 paths; unavailable remote vantage points remain explicitly unverified;
7. confirm readiness after the required proof while desired persistent state remains journaled from acceptance;
8. restore automatically on failed probe, lost heartbeat, reboot, or deadline.

Firewall disable remains a parity outcome only as a high-risk local break-glass transaction with impact preview, recent MFA, timed automatic re-enable, and explicit exception for any longer state.

### 18.3 Panel and SSH listener changes

Port/address changes use make-before-break:

1. validate range, conflict, bind capability, certificate, security policy, and firewall;
2. open the new path;
3. start a shadow or dual listener;
4. arm a reboot-persistent rollback deadline;
5. prove local process ownership and protocol;
6. obtain the configured proof level, using the initiating client through the new endpoint as the minimum anti-lockout proof and an independent external probe when available/required;
7. require a fresh authenticated session through the new endpoint;
8. commit and close the old endpoint;
9. roll back on timeout or failure.

An existing session is not proof that the new route works. Existing SSH sessions survive a port change.

### 18.4 SSH policy

Secure default:

- direct network root login disabled;
- public-key authentication enabled;
- password authentication disabled in hardened profile;
- no empty passwords;
- no user-controlled environment/RC;
- agent, X11, TCP, and tunnel forwarding denied unless explicitly granted;
- source CIDR, user, and group restrictions supported;
- approved key algorithms with separate FIPS policy;
- login grace, maximum attempts, idle, and session limits;
- optional key plus MFA through supported OpenSSH mechanisms.

Before disabling the last root or password path, the system MUST prove a sudo-capable administrator and independent recovery route. Temporary migration root access is key-only, source-constrained, and expiring.

Key creation records fingerprint, algorithm, owner, source, options, label, expiry, and revocation. Private keys are not stored by the panel unless a separate purpose-bound product explicitly requires them.

### 18.5 SSH activity and response

The investigation console correlates:

- successful and failed login events;
- source, method, key fingerprint, user, and result;
- brute force, dictionary, root attempts, protocol scans, and floods;
- success following repeated failure;
- active SSH/logind sessions and PTYs;
- process trees, executable, arguments, cwd, resource use, listeners, and peers;
- account/key/policy changes around the event;
- firewall, WAF, malware, and provider findings.

Optional GeoIP uses a locally licensed database or explicit provider.

Response actions are separate:

- terminate one session;
- terminate a selected process tree;
- revoke a key;
- lock an account;
- quarantine a site;
- add an expiring network block.

PID actions verify boot ID and process start time or use pidfd. They protect kernel/init, SSH daemon, panel components, rollback watchdog, and the operator's current recovery session by default. Shell history is available only as an explicit forensic evidence action with scope, reason, recent MFA, policy, and audit.

### 18.6 WAF

Both engine adapters use their native supported ModSecurity/WAF mechanisms. OpenLiteSpeed rejects ModSecurity 2.x-only rules and unsupported directives. LiteSpeed Enterprise uses its separately certified native behavior.

Provider model:

- maintained OWASP CRS is the default baseline;
- commercial/Comodo-equivalent rule lifecycle is a provider;
- Imunify may own rules in Imunify mode;
- GridPane 7G is a later optional signed pack;
- only one primary provider owns a phase/rule namespace unless an exact combination has passed compatibility qualification.

Rule update:

1. download to an inactive quarantine slot;
2. verify signature, digest, version, provenance, and compatibility;
3. parse and detect unsupported directives and duplicate IDs;
4. run positive and negative regression fixtures;
5. replay privacy-reduced traffic where enabled;
6. deploy detection-only canary;
7. switch the validated WAF generation for that engine as one local configuration activation;
8. retain prior rules for rapid rollback.

Custom ModSecurity rules are a separate versioned `CustomWAFRuleSet`, not an edit to a live provider file. Authorized operators can create, import, inspect, modify, validate, test, enable, disable, roll back, export, and delete global or site-scoped custom generations. The parser rejects executable includes, external scripts/Lua, unsafe file access, duplicate/reserved IDs, unsupported phases/actions/directives, and scope escape. Each generation receives per-engine syntax/semantic validation, positive/negative fixtures, detection-only canary, exact provenance/author, and a prior-generation rollback. Migration imports source rules only when the selected OLS/LSE adapter represents them; otherwise they block. Custom rules and activation history are included in backup/restore and drift detection.

### 18.7 WAF exclusions

An exclusion MUST identify:

- tenant and site;
- normalized route;
- HTTP method;
- exact rule IDs;
- exact parameter/header/body target;
- optional source constraint;
- triggering evidence;
- business justification;
- owner and approver;
- creation and expiry;
- observed hit volume.

Wildcards and regex require elevated review. Global request-body disable, whole-engine disable, and broad site/path bypass are separate high-risk actions. Panel, authentication, upload, and administrative routes require additional approval. Exclusions begin in observation mode, survive provider updates through managed ordering, and expire closed.

### 18.8 Imunify and commercial security

Imunify360/ImunifyAV integration covers:

- installation and licensing;
- version, agent, signature, and health;
- scoped SSO where supported;
- users, tenants, and domain ownership;
- WAF ownership mode;
- scan jobs, incidents, malicious files, quarantine, cleanup, restore, and ignore policy;
- WebShield/listener topology where configured;
- normalized findings and events.

The default integration is detect/observe-only. Findings and suggested actions enter canonical state, while quarantine, cleanup, WAF exception, firewall, PHP, and package mutation run only through panel-authorized typed handlers and reconciled provider receipts. Provider absence, expired license, stale signatures, and unsupported capability are visible degraded conditions.

If a product tuple requires an autonomous third-party root agent, it is an explicit `ExternalPrivilegedController` exception rather than pretending INV-004 applies to effects the panel did not mediate. Its contract enumerates the exclusive subsystems and action classes it owns, autonomous-action policy, vendor control/update/network paths, event ingestion, receipt identity, drift/reconciliation, failover/disable behavior, and competing panel writers that are disabled. Its compromise is host compromise, its mutations are distinguished in audit as externally authorized/autonomous, and its exact licensed version receives root-agent network/update/control, conflict, compromise-containment, and recovery Gate 0 tests. No general “explicit owner” label grants implicit root authority.

### 18.9 Built-in security scanner

The baseline scanner combines maintained signatures, integrity comparison, structural/obfuscation heuristics, reputation, and optional model verdicts. It supports upload, targeted, quick, full, scheduled, and post-restore modes.

Low-confidence findings are review-only. High-confidence policy may quarantine, never irreversibly delete. Ignore rules are exact hash/path/signature scopes with owner, reason, and expiry. Broad home-directory exclusions are prohibited.

### 18.10 Diagnostics and repair

Diagnostics are read-only and dependency-aware. They cover engine, PHP, firewall, SSH, MariaDB, PowerDNS, mail, FTP, containers, certificates, storage, scheduler, backups, providers, resource limits, and product components.

A repair recipe declares:

- prerequisites;
- owned fields/files/resources;
- expected semantic diff;
- risk and approval;
- snapshot;
- native validator;
- reload/restart effect;
- local and external probes;
- compensation;
- irreversible frontier.

The workflow is diagnose, propose, snapshot, approve, stage, validate, activate, probe, commit or roll back. Restore-defaults means the last known-good desired state, not uncontrolled package defaults.

---

## 19. Services, observability, packages, onboarding, and product updates

### 19.1 Managed service registry

The fixed registry covers at least:

- OpenLiteSpeed or LiteSpeed Enterprise;
- installed LSPHP runtimes;
- MariaDB;
- PowerDNS;
- Postfix;
- Dovecot;
- Rspamd;
- ClamAV;
- Redis;
- Pure-FTPd;
- container runtime;
- panel components;
- optional Elasticsearch and declared add-ons.

Service status has distinct fields:

- configured;
- systemd active;
- configuration valid;
- dependency ready;
- expected listeners owned;
- internally healthy;
- externally functional;
- desired generation observed.

Status, enable, disable, start, stop, reload, restart, install, remove, and repair use registered service IDs and typed systemd D-Bus/helper operations. Caller-supplied unit names are forbidden.

Critical stop/remove actions require impact preview, scope, recent MFA, and dependency handling. A zero exit status is not service health.

### 19.2 Process actions

Process observation includes PID, boot ID, start time, parent/tree, UID, cgroup, state, CPU, RSS/virtual memory, elapsed CPU, executable, bounded arguments, cwd subject to policy, listeners, and site ownership.

TERM is default. KILL is separate after a visible grace interval. PID reuse is checked. Protected processes cannot be killed through ordinary actions.

### 19.3 Metrics

Host and scoped metrics include:

- CPU utilization, load, frequency, throttling, and pressure;
- memory, swap, OOM, and pressure;
- filesystem bytes, inodes, latency, and quota;
- block throughput, operations, queue, latency, and errors;
- network bytes, packets, connections, loss, errors, and qualified rate enforcement;
- process and cgroup use;
- service health and restart history;
- OLS/LSE listeners, requests, errors, connections, cache, and traffic;
- PHP queue/concurrency and worker health;
- TLS expiry and renewal;
- DNS transfer/provider state;
- mail queue, filters, and delivery;
- backup freshness and restore-drill status;
- scanner and finding state;
- scheduler/operation queue and oldest wait;
- container and workload health.

Metrics MUST use bounded labels. Arbitrary domain, path, IP, user input, and message values are not metric labels. High-cardinality detail belongs in logs or queryable observations.

### 19.4 Logs

Structured streams include:

- product/API/operation;
- audit;
- web access and error;
- PHP/application;
- WAF;
- mail and queue;
- FTP/SFTP/SSH;
- database;
- DNS;
- backup/restore;
- container;
- provider;
- system journal.

Features:

- cursor pagination;
- bounded search;
- follow with backpressure;
- export;
- tenant/site filtering;
- retention and rotation;
- product-boundary fingerprint redaction for product-managed secrets before product log persistence;
- output encoding;
- correlation ID across command, operation, executor, logs, and metrics.

Clear log seals and rotates ordinary diagnostic streams. It cannot erase audit or security evidence. Slow clients cannot produce unbounded memory.

Tenant/application/daemon streams are untrusted and may contain credentials or personal data the product did not deliver. They use least-privilege access, encryption/retention policy, export warnings, known-secret scanning, and safe rendering; the product does not claim perfect redaction of arbitrary tenant-generated content.

### 19.5 Package maintenance

Package outcomes:

- installed inventory;
- signed repository metadata and available updates;
- security advisories;
- package details;
- hold and unhold;
- supported individual update;
- product dependency bundle update;
- planned host security update;
- transaction lock/repair state;
- reboot-required state.

Repository signature authenticates a publisher; it does not make every package or maintainer script safe for panel installation. New package install/removal is limited to the release/support-tuple `ComponentCatalog` with exact package identity, version range, repository snapshot/metadata epoch, digest/signature, dependency policy, expected services/files, and qualification evidence. Caller-supplied package names are unrepresentable.

An isolated release-pinned package planner resolves the complete transaction against the pinned repository snapshot. panel-execd independently re-resolves or verifies the signed plan attestation and checks every NEVRA/version/digest, repository metadata epoch, addition/removal/upgrade/downgrade, maintainer-script risk class, disk/service impact, support compatibility, plan digest, and CommitAuthorization before invoking the package manager. A paneld-authored solver result is not trusted.

Updates of already installed foreign OS packages are allowed only under an explicit host-maintenance policy and full impact approval; they do not expand the product component catalog. Unknown repositories, changed solver closure, unsigned/local packages, unqualified maintainer scripts, and dependency substitutions block. There is no arbitrary package string or shell escape.

MaintenancePlan records solver additions/removals, disk, holds, service impact, compatibility conflicts, snapshot capability, irreversible boundaries, health gates, and rescue path.

Interrupted dpkg/rpm state enters a repair workflow before further package operations. Package downgrade is not represented as safe rollback when formats changed.

OS major upgrades are not a baseline in-place action. They require a later migration-style certified upgrader or fresh-host migration.

### 19.6 Redis and Elasticsearch

Redis and Elasticsearch are typed managed services:

- install, update, configure, start/stop, repair, and remove;
- supported version and health;
- resource profile;
- data path and backup binding;
- loopback-only default;
- authentication and TLS for explicit exposure;
- declared consumers;
- remove separate from data purge.

Mail-owned Redis cannot be removed until dependent policy is changed. Elasticsearch uses a currently supported family; legacy CyberPanel package versions are not compatibility requirements.

### 19.7 Onboarding

Onboarding is resumable:

1. certified OS, architecture, kernel, filesystem, cgroup, MAC, capacity, and conflict preflight;
2. address, hostname, forward DNS, optional reverse DNS, clock, and resolver readiness;
3. OpenLiteSpeed or Enterprise selection, artifact, and licensing;
4. initial owner, passkey/MFA, and independent recovery;
5. panel hostname, certificate, listener, and anti-lockout;
6. firewall and SSH posture;
7. optional DNS, mail, FTPS, containers, and CloudLinux roles;
8. nameserver defaults;
9. backup repository and restore proof;
10. notification transport test;
11. optional federation enrollment;
12. final local and externally observed readiness report.

Panel HTTPS is independent of the web engine.

### 19.8 Product update system

Product updates never pull mutable Git branches or modify a live source checkout.

Release inputs:

- signed deb/rpm repositories and offline bundles;
- threshold-controlled trust roots;
- TUF-style freshness, rollback, freeze, and mix-and-match protection;
- content digests;
- SBOM, VEX, provenance, and license report;
- immutable version directories;
- compatibility manifest;
- schema and executor protocol range;
- release notes and known risk;
- stable, beta, and pinned channels.

Update:

1. verify metadata, signatures, provenance policy, and support tuple;
2. preflight disk, backup, schema, provider, and rollback;
3. fence conflicting operations;
4. snapshot control state and desired generations;
5. install inactive product artifacts;
6. run expand/contract-compatible schema steps;
7. activate the new pointer;
8. run identity, API, scheduler, engine, mail, DNS, DB, backup, and pending-operation probes;
9. confirm or restore prior compatible binaries;
10. contract old schema only in a later release after rollback window.

The updater updates itself last. Power loss resumes from the journal. Forward-only schema or data transitions require explicit approval and demonstrated backup recovery.

### 19.9 Controlled reboot

A managed reboot:

1. blocks new conflicting operations;
2. brings running work to safe checkpoints or records resumable state;
3. runs SQLite online backup/checkpoint policy;
4. drains listeners as policy permits;
5. records current and expected boot identity;
6. arms boot recovery;
7. reboots through a typed operation;
8. reconciles services, configurations, operations, locks, and schedules;
9. reports actual kernel/package rollback capability.

---

## 20. Optional central federation, fleet operations, and HA

### 20.1 Authority model

The node SQLite state is the only resource database and the local reconciler is the only host writer. Central stores:

- central identities and RBAC;
- node registry and capabilities;
- immutable intended remote actions;
- sanitized projections;
- orchestration sagas;
- central audit and operator approvals;
- release and provider metadata.

Central MUST NOT store a writable mirror of node-local resource specs. Authority is split explicitly:

- node-local desired resources are authoritative only in the owning node's control.db;
- central fleet plans, target sets, waves, approvals, and orchestration sagas are authoritative centrally;
- node projections are sanitized revisioned observations and are never centrally writable;
- every host mutation becomes an independently accepted node-local command.

Multi-node HA requires the optional central reference deployment or another separately qualified coordinator that implements the same quorum, fencing, and saga contracts. A standalone node still supports backup/transfer and manually initiated peer workflows but does not pretend to provide automatic multi-node consensus.

~~~mermaid
sequenceDiagram
    participant O as Central operator
    participant C as Central control plane
    participant F as Node federatord
    participant P as Node paneld
    participant R as Node reconciler/executor

    O->>C: Create typed fleet intent
    C->>F: Signed intent over outbound mTLS stream
    F->>P: Submit through ordinary local command gateway
    P->>P: Verify epoch, signature, CAS, local RBAC, policy, capability
    P-->>F: Accepted local operation receipt or exact rejection
    P->>R: Durable local operation
    R-->>P: Observed effects and proof
    P-->>F: Events, status, receipts
    F-->>C: Sanitized projection and terminal result
~~~

### 20.2 Enrollment and grants

Enrollment:

1. local owner initiates;
2. operator verifies central CA fingerprint;
3. one-use bound enrollment token is consumed;
4. node generates identity and HPKE keys; TPM/HSM-backed non-exportability is claimed only on a qualified hardware tuple, while the baseline software keys are encrypted/sealed at rest, root-readable under host compromise, rotatable, and revocable;
5. central issues a short-lived workload certificate;
6. local owner signs CentralAuthorityGrant;
7. grant defines peer, capabilities, resource selectors, maximum risk, approval requirements, expiry, and authority epoch.

Only one central peer may hold mutation authority. Multiple observer peers MAY receive different projections.

Local revoke or break-glass increments the authority epoch and invalidates all queued central work. Central cannot widen its grant.

Each remotely asserted actor MUST map to a locally approved `FederatedPrincipalBinding` keyed by peer plus immutable issuer/subject. The binding defines local role ceiling, selectors, required authentication methods/time, risk maximum, validity, and authorization epoch. Email matching is forbidden, and central cannot create or map an instance-owner identity. Actor assertions contain issuer, subject, audience, authentication time, authentication methods, nonce, expiry, and authorization epoch.

### 20.3 Intent envelope

~~~proto
message FederatedIntent {
  string intent_id = 1;
  string node_id = 2;
  string peer_id = 3;
  uint64 authority_epoch = 4;
  uint32 capability_schema_version = 5;
  CentralActorAssertion actor_assertion = 6;
  string command_kind = 7;
  ResourceRef target = 8;
  uint64 expected_generation = 9;
  string idempotency_key = 10;
  string effect_id = 11;
  Timestamp expires_at = 12;
  repeated Approval approvals = 13;
  google.protobuf.Any validated_payload = 14;
  string signing_key_id = 15;
  string signing_algorithm = 16;
  uint64 signing_key_epoch = 17;
  bytes signature = 18;
}
~~~

Node validation includes peer, certificate, authority epoch, capability version, signature, expiry, replay, actor chain, approvals, local RBAC, selectors, target CAS, node support, current risk policy, quota, and lifecycle.

The application signature covers a versioned canonical `FederatedIntentSigStructure`, not protobuf/YAML presentation bytes: domain separator; schema hash and payload type URL; canonical payload digest; intent/node/peer IDs; authority/capability/signing-key epochs; actor-assertion and approval-set digests; command/target kind+ID+scope/generation; idempotency/effect IDs; issued/expiry; and every policy-relevant envelope field. Only deterministic known-field protobuf (or another release-declared canonical encoding) is accepted; unknown fields, duplicate/noncanonical map keys, unsupported type URLs, unrecognized algorithms, expired/revoked keys, or a payload digest mismatch reject. Key identity, algorithm, validity, rotation overlap, and revocation epoch are local grant state. Acceptance/replay terminal receipt is persisted before execution, independently of mTLS peer authentication.

First accepted generation wins. A stale local or central mutation receives an explicit conflict. Duplicate intents return the original receipt.

### 20.4 Transport and resynchronization

federatord opens one outbound-only mutually authenticated HTTP/2 stream. There is no inbound cloud router.

The stream multiplexes:

- intent delivery and receipt;
- node events;
- projection deltas;
- capability and version negotiation;
- revocation and authority epoch;
- bounded interactive relay frames;
- cursor repair and signed snapshots.

On reconnect:

1. apply peer revocation and epoch changes;
2. exchange terminal command receipts;
3. reconcile event cursors;
4. repair projections with a signed snapshot if deltas no longer join;
5. resume permitted interactive/data flows.

Central projections always show node revision, observed generation, last contact, and stale-since. Central never renders optimistic intent as node reality.

### 20.5 Offline behavior

Without central:

- local UI/API/CLI and recovery remain available;
- hosting, mail, DNS, databases, certificates, reconciliation, cron, deployments, backups, security, and accepted operations continue;
- unaccepted central intents remain central-side and expire;
- central interactive sessions end;
- essential audit-adjacent events and terminal operation receipts use a bounded prioritized durable spool and are never silently discarded; on exhaustion, the node blocks new central-originated mutations and raises a critical condition while local hosting safety work continues;
- high-volume telemetry coalesces;
- local deny/revoke wins;
- assertion and credential expiry are not extended.

### 20.6 Federated secrets and interactive sessions

Node-native secrets never enter central projections.

A secret intentionally delivered through federation uses one of two explicit trust modes. End-to-end mode requires a separately distributed and signed `panelctl`, desktop helper, or qualified extension with pinned release trust and an independently verified node key; a central-served web application cannot make a central-blind claim because a compromised central can replace its JavaScript. The client binds an authenticated transcript containing central actor/assertion, local session grant, node identity/key, purpose, resource, operation, and expiry, then encrypts plaintext directly to the node HPKE key so central stores only ciphertext. In integration-originated or central-hosted-web mode, central can observe/create/transform plaintext and is explicitly part of that secret's trust boundary. In either mode the secret is:

- versioned;
- purpose-bound;
- encrypted to the node HPKE key;
- scoped to resource and operation;
- short-lived where possible;
- redacted from central and local observation.

Node-to-node replication uses source-approved end-to-end ciphertext.

Central file, database, terminal, and support sessions receive a locally issued one-use grant. Central-blind end-to-end interactive traffic likewise requires the separately trusted client and transcript binding above. A central-hosted browser mode is central-in-the-trust-boundary even when transport legs are encrypted. Central receives no reusable node credential. Terminal remains site UID; support context preserves the real actor.

### 20.7 Fleet rollout

A fleet operation freezes:

- target node IDs and their expected capability/support versions;
- desired artifact or command digest;
- canary groups;
- maximum concurrency;
- health gates;
- halt threshold;
- rollback classification;
- maintenance windows;
- expiry.

Nodes lacking required capability are excluded with reasons. Waves advance only on locally observed success. Central cancellation cannot undo an irreversible node frontier and must report exact node states.

### 20.8 Central implementation

Central uses horizontally scalable Go services and PostgreSQL with transactional outbox and one fenced saga lease. Object storage holds signed release/evidence artifacts. Kafka is not required initially.

Central HA requires:

- replicated PostgreSQL with tested failover;
- point-in-time recovery;
- workload certificate and signing-key rotation;
- regional failover where advertised;
- backup/restore rehearsal;
- no impact on already running node workloads when central is lost.

### 20.9 Multi-node resources

| Resource | Purpose |
|---|---|
| PlacementGroup | eligible nodes, failure domains, capacity policy |
| ReplicaSet | workload replicas and desired health |
| ReplicationChannel | data type, direction, encryption, checkpoints |
| TrafficPolicy | DNS/LB/provider routing |
| WriterLease | quorum-backed write authority |
| Fence | topology-specific proof previous writer cannot commit on every protected write path |
| Promotion | candidate, proof, approvals, state |
| FailoverRun | health, fence, promote, route, verify, rejoin |

### 20.10 HA outcomes

Full parity includes redesigned outcomes for:

- manager/node enrollment and detach;
- worker and data-node placement;
- stateless application replicas;
- warm standby site/file synchronization;
- MariaDB Galera with odd voting set or declared primary/replica topology;
- PowerDNS primary/secondary;
- redundant mail ingress and explicit mailbox-writer topology;
- replicated container applications;
- replica, CPU, and memory scaling;
- status, lag, health, uptime, and pending-resource reconciliation;
- DNS or supported load-balancer cutover;
- sync-back/failback;
- verified cross-node backup copies;
- recovery and rejoin.

No raw Swarm token, root rsync key, disabled host verification, public unrestricted database port, pc.ignore_sb, or arbitrary remote command is preserved.

### 20.11 Split-brain rule

No writer is promoted merely because a health check failed. Promotion requires:

- proof the prior writer is fenced; or
- a quorum-backed lease that prevents it from committing.

Loss of quorum freezes unsafe writes. Central cannot override. A rejoining node is rebuilt or resynchronized from the elected generation before receiving traffic; stale state never overwrites elected state.

Fencing is provider- and topology-specific. Certified providers may include power fencing, storage-level fencing, database-enforced quorum for database writes, or mandatory leases enforced by every application/filesystem write path. A database quorum fences only the database. Automatic promotion is unavailable unless every protected writer is enforceably fenced. Manual promotion without such a provider requires independently confirmed physical/administrative fencing and an explicit potential-data-loss acknowledgement.

---

## 21. Disposable one-way migration and import

### 21.1 Components

~~~mermaid
flowchart LR
    CE["cyberpanel-extract<br/>ephemeral source agent"] --> M["Signed canonical MigrationSet"]
    CA["cpanel-archive-extract<br/>networkless sandbox"] --> M
    M --> Q["Encrypted chunks + quarantine"]
    Q --> MI["mig-importd<br/>source-neutral"]
    MI --> G["Normal local command gateway"]
    G --> T["Quarantined target resources"]
    T --> R["Rehearsal"]
    R --> C["Guarded cutover"]
~~~

Components:

- migctl owns inventory, planning, approval, transfer, rehearsal, and cutover;
- cyberpanel-extract is a signed, version-pinned, ephemeral read-only source agent and does not import CyberPanel Python or run CyberPanel scripts;
- cyberpanel-cutover is a separate tiny local-only source helper for pre-approved writer fences, relay changes, and their rollback watchdog;
- cpanel-archive-extract is unprivileged, networkless, non-executable, and resource-bounded;
- mig-receiver accepts one enrolled migration into encrypted quarantine;
- mig-importd understands only the canonical manifest and calls normal target APIs.

After cleanup, source-specific code, certificates, listeners, sandboxes, and keys are removed. paneld never learns legacy schemas.

The source agent opens an outbound pinned mutually authenticated connection and runs with read-only mounts, fixed signed parsers, restrictive seccomp/MAC, no shell, and no generic root file/SQL/service operation. It may emit only manifest resource/chunk IDs discovered by its signed local rules and approved in a source-local plan; the target can request missing approved IDs, never a path, SQL statement, unit, command, arbitrary table, or scope expansion. Resume is content-addressed and bound to migration/plan/source/target epochs, so target compromise or replay cannot turn extraction into a remote root oracle.

Only cyberpanel-cutover can mutate the source. A source-local administrator step-up signs an expiring plan digest enumerating exact fence/relay/restore handlers and resources. The helper independently validates the source generation, arms a source-local reboot-persistent rollback lease, accepts no target-selected command/path/service, and records every effect. Target compromise cannot widen or re-sign the plan. Failed uninstall revokes transport credentials and leaves the helper inert; failed cutover restores only the prevalidated source generation or requires local console recovery. Extractor and cutover helper use distinct keys, sockets, packages, MAC profiles, and removal attestations.

### 21.2 Invariants

- Sources and archives are untrusted.
- No Apache runtime is installed; Apache and .htaccess are translation evidence only.
- Target resources remain dark until verified.
- Source and target are never writable authorities simultaneously.
- Every discovered item is imported, transformed, explicitly excluded, evidence-only, or blocking.
- Legacy IDs, UIDs, GIDs, paths, sessions, tokens, and authorization decisions do not become target authority.
- Central is not required and is not the bulk-data or secret path.
- Timeout never causes blind replay.

### 21.3 Migration manifest

~~~yaml
MigrationSet:
  schemaVersion: integer
  migrationId: uuid
  sourceIdentity:
    kind: cyberpanel_live | cyberpanel_backup | cpanel_archive
    installationFingerprint: digest
    productVersion: string
    os: string
    databaseVersion: string
    daemonVersions: map
    schemaOrLayoutFingerprint: digest
    sourcePublicKey: bytes
  extractorIdentity:
    name: string
    version: string
    binaryDigest: sha256
    publisherSignature: bytes
  targetContract:
    nodeId: uuid
    apiVersion: string
    osTuple: string
    engineEdition: openlitespeed | litespeed_enterprise
    engineVersion: string
  capture:
    start: timestamp
    end: timestamp
    bootId: string
    databaseSnapshots: [watermark]
    filesystemSnapshots: [watermark]
    binlogOrGTID: optional
    mailWatermark: optional
  parentManifestDigest: optionalDigest
  inventorySummary: object
  resources: [ResourceEnvelope]
  blobs: [BlobDescriptor]
  secretEnvelopes: [SecretEnvelope]
  consistencyGroups: [ConsistencyGroup]
  diagnostics: [Finding]
  merkleRoot: digest
  signatures: [signature]
~~~

Each resource contains a stable source key, canonical kind, scope, desired spec, dependencies, content/secret/evidence references, source revision, required capabilities, proposed mapping, support class, field provenance, and expected verification.

Field evidence records origin, redacted locator, capture time, revision, raw digest, extraction-rule version, confidence, and conflicts.

File trees are Merkle DAGs preserving safe files, links, sparse extents, supported ACL/xattr state, mode, and timestamps. Devices, sockets, FIFOs, capabilities, and setuid/setgid state are findings, not restored defaults.

SecretEnvelope is HPKE-encrypted to a migration target key and records purpose, target, source form, rotation policy, and expiry.

MappingLedger maps source keys to reserved target UUIDs without embedding legacy identity into the target.

Extractor/manifest signatures prove extractor identity, artifact integrity, and transport continuity; they do not prove that a compromised source host reported truth. The planner cross-checks control-database intent, effective daemon configuration, filesystem state, service observations, and provider observations. A suspected source-root compromise disables credential continuity, treats all executable content and keys as hostile, and uses an incident-grade migration plan with fresh identities and credentials.

YAML in this section is illustrative only. The signed migration envelope is a versioned deterministic protobuf/CBOR or RFC 8785 JSON structure with domain separation, signing key ID/algorithm/epoch, schema hash, canonical manifest and Merkle-root digest, normalized Unicode/path/string rules, and unknown-field/duplicate-key rejection. The tiny bounded header, schema, signature, target binding, and declared size/count/decompression limits are verified before large allocation, chunk acceptance, archive expansion, or parser dispatch. The same canonical-signature rule applies to DR bundles, backup manifests, provider snapshots, evidence dossiers, recipes, and other signed product manifests.

CyberPanel live state, CyberPanel backup artifacts, and cPanel archives are three independent source adapters and fixture suites. CyberPanel backup parsing has the same hostile archive, secret classification, schema fingerprint, SQL sandbox, completeness, and no-runtime-residue requirements as other sources; a live extractor cannot stand in for it.

### 21.4 CyberPanel source coverage

The extractor inventories both control intent and effective state for:

- node, host, addresses, services, versions, and engine/license;
- PHP runtimes, extensions, global and site settings;
- administrators, owner/reseller graph, ACLs, plans, quotas, and state;
- sites, children, aliases, routes, roots, limits, suspension, logs;
- listeners, vhosts, global/site expert fragments, proxies, redirects, rewrites, request/response headers, conditional environment, network/path access, HTTP abuse/rate policy, preview behavior, cache, access, and includes;
- file trees, metadata, ownership, ACLs, xattrs, links, bytes, and inodes;
- site, alias, panel, mail, and FTPS certificates;
- DNS zones, RRsets, primary/secondary, transfer, TSIG, DNSSEC, and Cloudflare;
- MariaDB databases, principals, host grants, roles, routines, triggers, events, collations, and application links;
- mail domains, mailboxes, verifiers, folders, messages, flags, aliases, catch-all, plus/pattern rules, safe pipes, Sieve, quotas, per-domain/mailbox delivery-log policy and selected bounded history, DKIM, and transports;
- FTP accounts, SFTP/SSH public keys;
- cron, environment, timezone, and ownership;
- Git remotes, branches, deployment/webhook policy, and key fingerprints;
- WordPress, components, staging, updates, cache, scanner, and backups;
- other application installations;
- Docker images, workloads, packages, networks, volumes, ports, environment classification, limits, and health;
- native limits and CloudLinux/CageFS;
- backup destinations, schedules, catalogs, and reachable recovery points;
- firewall, SSH, WAF, rules, exclusions, and providers;
- notification SMTP and routes;
- marketing lists, templates, jobs, suppression, and consent evidence;
- external delivery, scanner, storage, and security providers;
- themes/locales where worth retaining;
- extension declarations and exportable data.

Operational history can be exported as separately signed evidence but never becomes trusted target audit.

Database intent, effective daemon configuration, filesystem payload, and provider observation are independent evidence sources. Conflicts remain explicit. Unknown schema fingerprints block.

### 21.5 cPanel archive coverage and parser safety

Versioned adapters cover:

- account owner/package/quota;
- primary, addon, subdomain, alias, and roots;
- homedir content and safe metadata;
- MultiPHP and per-directory settings;
- Apache/.htaccess evidence;
- DNS, DNSSEC, SPF, DKIM, DMARC;
- TLS keys/chains;
- MariaDB data, grants, routines, triggers, events;
- Maildir/mdbox, verifiers, aliases, forwarders, catch-all, filters, autoresponders;
- cron;
- FTP and SSH public keys;
- application and WordPress detection.

Parser rejects absolute/escaping paths, unsafe links, devices, sockets, FIFOs, duplicates, path/count/depth overflow, compression/sparse bombs, unsafe capabilities/xattrs, truncation ambiguity, and unknown layouts.

Source SQL never runs against production target MariaDB. It enters an ephemeral networkless MariaDB sandbox with no host paths/capabilities. The importer introspects and exports sanitized schema/data. System-schema writes, global statements, UDF/plugin install, filesystem functions, unsafe definers, and unsupported authentication block.

Imported site code is never executed during extraction. It is scanned and first probed as site UID with outbound network denied.

### 21.6 Apache and .htaccess translation

The translator parses an AST and maps:

- redirects and canonical host;
- rewrite conditions/rules and front controllers;
- index and error documents;
- headers;
- access restrictions and supported authentication;
- MIME mappings;
- compression, cache, and expiry;
- supported environment and PHP settings;
- safe typed reverse proxies.

Every construct is `EXACT_BOUNDED_AST`, `TESTED_EQUIVALENCE`, `REQUIRES_OPERATOR_MAPPING`, or `UNSUPPORTED_BLOCKING`. Exactness is reserved for a formally bounded canonical subset. Tested equivalence means equivalent only on the certified generated and operator corpus; residual behavior outside that corpus is disclosed and requires acceptance.

Arbitrary includes, modules, handler tricks, unsafe aliases, executable filters, or unrepresentable merge/order semantics block the affected application. There is no Apache fallback.

Proof runs a generated and operator-supplied request corpus on the selected OLS or Enterprise target and compares status, location, relevant headers, access decisions, cache/PHP routing, and normalized content.

### 21.7 Support classes and blockers

Classes:

- SUPPORTED;
- SUPPORTED_WITH_TRANSFORM;
- REQUIRES_INPUT;
- OPTIONAL_DEGRADED;
- BLOCKING_UNSUPPORTED;
- IGNORED_EPHEMERAL.

Core data and active behavior cannot be optional-degraded.

Blockers include:

- unavailable required runtime/extension;
- unsupported web behavior;
- escaping links or ownership ambiguity;
- database version, collation, authentication, or unsafe SQL;
- unknown application credential rewrite;
- unsupported mail pipe/filter;
- parent DNSSEC DS without continuity;
- identity/name collision;
- privileged or host-mounted container forbidden by policy;
- non-transferable provider without replacement;
- insufficient bytes, inodes, memory, ports, quota, or Enterprise license;
- corrupt/unknown archive;
- source drift after final fencing.

### 21.8 Credential policy

| Source credential | Target behavior |
|---|---|
| Panel sessions, API tokens, recovery codes | never imported |
| Panel password verifier | account activation/reset or new passkey enrollment |
| TOTP | re-enroll by default; explicit encrypted continuity only |
| Mail verifier | preserve only supported strong verifier, else reset |
| DB verifier | preserve supported native verifier and grants, else rotate |
| Known application DB plaintext | rotate and rewrite through application adapter |
| Unknown application DB credential | preserve verifier or block; never guess |
| FTP verifier | preserve supported verifier or reset |
| SSH public key | import after scope/ownership review |
| SSH/Git private key | replace by default |
| TLS private key | encrypted import after verification, then reissue policy |
| DNSSEC/DKIM key | encrypted continuity or coordinated rollover |
| S3/SMTP/backup secret | encrypted import plus rotation policy |
| OAuth/provider token | reauthorize by default |
| Container secret environment | convert to SecretRef and rotate where possible |

### 21.9 Dry run and capacity

Dry run makes no destination public. It produces a signed immutable MigrationPlan containing inventory, scope, mappings, ownership, engine/runtime compatibility, transformations, providers, credentials, conflicts, capacity, quiescence, RPO, DNS patches, probes, exclusions, blockers, and rollback frontier.

Capacity accounts for logical/allocated files, inodes, staging, retained rollback generation, DB data/index/dump/sandbox/rebuild amplification, mail staging, containers, historical backups, chunk store, journals, system reserve, and safety margin. Both physical capacity and tenant quota are reserved.

Changing source state, target capability, mapping, engine, or plan changes the digest and invalidates approval and rehearsal.

### 21.10 Transfer and state machines

Online transfer uses mutually authenticated TLS 1.3, one-use enrollment, target pinning, migration-scoped short certificates, separate control/chunk/secret streams, backpressure, concurrency/I/O limits, content-addressed encrypted chunks, missing-chunk resume, periodic receipts, and end-to-end verification.

Offline bundles use the same signed manifest and encrypted chunks sealed to the target migration key.

~~~mermaid
stateDiagram-v2
    [*] --> Created
    Created --> Enrolled
    Enrolled --> Discovering
    Discovering --> Inventoried
    Inventoried --> Analyzing
    Analyzing --> Blocked
    Analyzing --> PlanReady
    PlanReady --> Approved
    Approved --> BaselineExporting
    BaselineExporting --> BaselineImported
    BaselineImported --> Rehearsing
    Rehearsing --> Rehearsed
    Rehearsed --> DeltaSyncing
    DeltaSyncing --> CutoverReady
    CutoverReady --> Quiescing
    Quiescing --> FinalSync
    FinalSync --> Activating
    Activating --> Verifying
    Verifying --> CutoverCommitted
    CutoverCommitted --> Soaking
    Soaking --> Cleaning
    Cleaning --> Complete
    Blocked --> Analyzing: input/resolution
    state Failure {
      Paused
      Reconciling
      RollingBack
      RolledBack
      FailedNeedsAttention
      Canceled
    }
~~~

Every resource moves discovered, classified, mapped, reserved, staged, materialized, verified, activated, with explicit blocked, excluded, compensating, rolled-back, and needs-attention states.

### 21.11 Baseline rehearsal

Baseline import creates dark resources:

- no public listener or DNS change;
- no production mail;
- schedules, webhooks, deployments, marketing, and backups disabled;
- no unapproved provider calls;
- private container ingress and restricted egress;
- site code under target UID;
- files in new releases;
- DB and mail in isolated namespaces.

Rehearsal uses shadow routes and host overrides for HTTP, PHP, database, TLS, DNS semantics, IMAP/mail, cron parsing, Git dry-run, containers, and application health. Repeating the same approved MappingLedger and plan from an empty namespace MUST reproduce the same semantic graph and content digests; target-assigned UUIDv7 identities are stable because the MappingLedger is reused, not independently regenerated.

### 21.12 Live synchronization tiers

Delivery proceeds in increasing capability tiers:

1. canonical manifest and idempotent importer;
2. offline cPanel archive;
3. cold/quiesced CyberPanel migration;
4. repeated file, database, and mail deltas;
5. GTID/binlog and Dovecot live synchronization;
6. old-IP HTTP and SMTP convergence bridges.

Files use snapshots where available or Merkle baseline plus deltas. Inotify/fanotify accelerates but does not prove completeness. Final sync includes a full comparison after application write fence.

Databases use consistent baseline plus recorded GTID/binlog coordinates where possible. Without usable binlog, final quiescence takes a new logical artifact and advertises the longer outage.

Mail uses Dovecot dsync where compatible or safe Maildir sync. Final mailbox writes are fenced. Source SMTP can relay newly accepted messages through a migration-specific authenticated path during convergence. Deduplication uses Dovecot state/GUID, not Message-ID alone.

Cron, Git webhooks, deploys, marketing, and backups run on source during baseline, then are fenced. Target enables them once after target authority.

### 21.13 Cutover and rollback

TTL preparation begins at least one prior positive and negative TTL before cutover. Changes are verified at authoritative and recursive resolvers. Exact RRset patches use provider CAS. DNSSEC continuity is resolved before activation.

~~~text
SOURCE_WRITER -> SOURCE_FENCING -> NO_WRITER -> TARGET_WRITER
~~~

There is no BOTH_WRITERS state.

Cutover:

1. revalidate plan, target, capacity, source drift, and DNS authority;
2. create verified source and target recovery points;
3. fence source panel mutations, schedules, webhooks, deploys, and app writes;
4. drain or proxy traffic;
5. final-sync control, files, DB, and mail;
6. sign final Merkle/GTID/dump/dsync watermarks;
7. run shadow probes;
8. activate target engine, DB, mail, and applications internally;
9. CAS-switch approved web and mail records;
10. enable target writes;
11. open traffic gradually;
12. run synthetic read/write, mail, and administration probes;
13. enable target schedules and backups once;
14. commit after observed health.

Before TARGET_WRITER, automatic source rollback has RPO 0 only for covered data whose source write fence and final watermark were both verified. External provider side effects, DNS caches, in-flight third-party callbacks, and any subsystem without a proven fence are excluded and receive a measured nonzero RPO or block cutover. Rollback reverts routing and releases the verified fence. After target writes begin, source is stale. Recovery is target-side or a separately rehearsed reverse migration. DNS may direct old traffic to a source forwarder that still reaches target, but it MUST NOT reactivate divergent source writes.

### 21.14 Cleanup and completion

After convergence and the retained-source window:

- create and restore-test a native target recovery point;
- rotate/reissue imported secrets and keys according to policy;
- reauthorize OAuth/providers;
- remove raw archives, SQL sandboxes, chunks, source parsers, listeners, certificates, and migration keys;
- verify no executable CyberPanel/cPanel runtime, active schema/config dependency, parser service/library in the product, disposable credential, listener, package, Apache configuration, or active .htaccess dependency remains; signed historical evidence MAY retain redacted legacy path strings;
- retain a signed mapping, exclusion, verification, and audit report;
- remove the source agent and relay credentials;
- preserve the sealed source until separately authorized decommission.

Migration is complete only after native restore proof and no-legacy attestation.

---

## 22. Complete functional-parity catalog

This catalog is the normative availability checklist. Each identifier represents an independently testable user or operator outcome. Detailed behavior, security constraints, and failure semantics are defined in Sections 6 through 21. The machine ledger in Section 28 expands each identifier by surface, permission, support tuple, test, evidence, migration, backup, documentation, and telemetry.

An outcome is not complete because a page, route, handler, model, or command exists. It is complete only when its end-to-end journey is certified. Duplicate CyberPanel implementations collapse into one outcome. Cloud-only CyberPanel outcomes remain required but are redesigned through the optional federation model. Provider-backed outcomes require working adapters. Apache mechanics are excluded; legitimate hosting outcomes formerly implemented through Apache MUST be expressed by the canonical OLS/LSE model or reported as unrepresentable during migration.

### 22.1 Identity, tenancy, authorization, packages, and preferences

| ID | Required outcome |
|---|---|
| IAM-001 | Claim a new installation locally and create its first owner without a default credential. |
| IAM-002 | Sign in and out; expire, enumerate, and revoke sessions; change passwords; and recover administrative access. |
| IAM-003 | Enroll, challenge, reset, and recover TOTP MFA; support passkeys where qualified; require step-up authentication for high-risk work. |
| IAM-004 | View and edit profile, locale, timezone, appearance, and notification preferences without exposing credentials. |
| IAM-005 | Create, inspect, search, modify, suspend, reactivate, transfer, and delete human users. |
| IAM-006 | Create, scope, rotate, suspend, and delete service principals and expiring API credentials. |
| IAM-007 | Create, inspect, clone, modify, assign, and delete roles and role bindings. |
| IAM-008 | Provide owner, administrator, reseller, customer, service-principal, support, auditor, and read-only operational roles. |
| IAM-009 | Create reseller tenants, delegate child-tenant administration, and enforce a non-escalating delegation ceiling. |
| IAM-010 | Create, version, inspect, clone, assign, retire, and delete hosting plans. |
| IAM-011 | Enforce plan limits for counts, storage, inodes, transfer, processes, runtime concurrency, and each CPU/memory/I/O shared-service dimension only at its declared enforcement scope; reject plans requiring unavailable hard enforcement. |
| IAM-012 | Show current consumption, reservations, measurement time, uncertainty, soft warnings, hard rejections, and quota-reset events. |
| IAM-013 | Transfer site, database, DNS, mail, FTP, backup, application, and schedule ownership without losing authorization or accounting. |
| IAM-014 | Issue a one-use, short-lived, audience-bound support-context grant instead of URL-token autologin or session impersonation. |
| IAM-015 | Reauthenticate and require policy approval for host-file access, firewall or SSH lockout risk, package changes, secret export, destructive restore, promotion, purge, and recovery-key changes. |
| IAM-016 | Apply the same local authorization decision to UI, API, CLI, scheduler, extension, migration, and central-originated operations. |
| IAM-017 | Record real actor, effective actor, assurance, delegation, approval chain, target, request digest, before/after generation, and result for every mutation. |
| IAM-018 | Preserve local owner and break-glass authority while a central peer or external identity provider is unavailable. |
| IAM-019 | Deliver an inbox of durable product/security notifications and optional SMTP/webhook delivery without allowing notification deletion to erase audit evidence. |
| IAM-020 | Create, inspect, resend, accept, expire, revoke, and audit tenant invitations with immutable intended tenant/role ceiling and no email-only account linking. |
| IAM-021 | Configure and enforce session network-binding policy (none, exact address, prefix, or risk-based step-up), expose binding/revocation events, and preserve local recovery. |

### 22.2 Installation, node lifecycle, service administration, and diagnostics

| ID | Required outcome |
|---|---|
| NOD-001 | Preflight and install a fresh node on an exact supported tuple, producing a signed component and configuration report. |
| NOD-002 | Resume or safely compensate an interrupted install; reinstall product code without deleting tenant data; uninstall through an explicit retention plan. |
| NOD-003 | Complete first-run hostname, owner, contact, timezone, engine, service-profile, DNS, firewall, and recovery enrollment. |
| NOD-004 | Report panel, OS, kernel, engine, service, runtime, rule-pack, and adapter versions plus compatibility and available updates. |
| NOD-005 | Download and verify signed releases, stage and switch them, health-check, roll back when valid, and report an irreversible frontier honestly. |
| NOD-006 | Restart or recover control services without unnecessarily restarting hosted workloads. |
| NOD-007 | Configure host identity, public addresses, hostname, timezone, administrative contact, and panel URL. |
| NOD-008 | Change panel or SSH listeners make-before-break with firewall coordination, external confirmation, and reboot-persistent rollback. |
| NOD-009 | Issue, import, inspect, deploy, rotate, and repair the panel-hostname certificate. |
| NOD-010 | Show functional health and start, stop, restart, reload, enable, disable, install, remove, and repair allowlisted services. |
| NOD-011 | Manage OLS, LSE, PowerDNS, MariaDB, Postfix, Dovecot, Rspamd, ClamAV, FTPS, PHP, Redis, search, containers, scheduler, and node agents when installed. |
| NOD-012 | Inventory packages, repositories, versions, advisories, locks, holds, provenance, and pending security updates. |
| NOD-013 | Plan and apply supported package maintenance with dependency impact, snapshots where valid, service probes, recovery instructions, and exact receipts. |
| NOD-014 | Report CPU, load, memory, swap, filesystem, inodes, disk I/O, network, traffic, uptime, pressure, and cgroup state. |
| NOD-015 | List top processes and inspect or signal an authorized process using PID plus start-time/boot identity or pidfd. |
| NOD-016 | Show successful and failed SSH authentication, active sessions, source analysis, risk, related processes, and evidence-preserving response actions. |
| NOD-017 | Read, stream, search, export, rotate, retain, and clear authorized panel, engine, site, database, DNS, mail, FTP, WAF, scanner, container, and audit-adjacent logs. |
| NOD-018 | Configure local SMTP delivery for panel notifications and verify it with a traced test message. |
| NOD-019 | Install, list, preview, activate, roll back, and delete signed static theme assets/design tokens; support scoped reseller branding and user system/light/dark choice without executable CSS/JavaScript or cross-tenant override. |
| NOD-020 | Generate a deterministically redacted support bundle containing versions, health, validation, recent failures, resource conditions, and operation receipts. |
| NOD-021 | Run read-only dependency-aware diagnostics separately from previewable, typed, snapshot-backed repair plans. |
| NOD-022 | Rebuild owned DNS, mail, FTP, web-engine, PHP, firewall, and control configuration from canonical state and reconcile drift. |
| NOD-023 | Expose a node public key only for a purpose-bound migration, repository, backup, or federation trust workflow. |
| NOD-024 | Continue all local lifecycle, repair, certificate, schedule, backup, and security behavior while federation is disabled or offline. |
| NOD-025 | Support clean rescue and credential recovery using a tiny local audited recovery interface, never a browser root shell. |

### 22.3 Websites, domains, routing, PHP, cache, and engine lifecycle

| ID | Required outcome |
|---|---|
| WEB-001 | Create, inspect, list, search, modify, suspend, reactivate, quarantine, restore-before-purge, and delete websites. |
| WEB-002 | Create, inspect, modify, disable, convert, detach, and delete child-domain bindings. |
| WEB-003 | Create, inspect, redirect, attach, detach, and delete aliases and parked domains. |
| WEB-004 | Assign and change tenant, plan, PHP runtime/profile, document root, contact, routing, and lifecycle state. |
| WEB-005 | Provision the site UID/GID, filesystem, runtime sockets, cgroup, quotas, logs, database/DNS/TLS bindings, and access policy transactionally. |
| WEB-006 | Rotate a site-system credential without placing it in logs, argv, reusable responses, or shared configuration. |
| WEB-007 | Enforce descriptor-rooted filesystem containment and an open_basedir-equivalent PHP policy. |
| WEB-008 | Model and manage canonical redirects, rewrites, headers, error pages, indexes, autoindex, and static/PHP/proxy routes. |
| WEB-009 | View rendered managed configuration and submit only typed, engine-qualified extension fields. |
| WEB-010 | Stage, validate, activate, reload, probe, confirm, reconcile, and roll back every engine configuration generation. |
| WEB-011 | View site-scoped access, error, PHP, cache, WAF, deployment, and resource-limit evidence. |
| WEB-012 | Configure disk, inode, monthly transfer, CPU, memory, I/O throughput/IOPS, PID, process, PHP concurrency, timeout, and request-size limits by explicit enforcement scope; show enforced/accounted-only/unsupported state and never claim aggregate hard isolation for shared service work. |
| WEB-013 | Enable or disable SFTP/SSH, terminal, deploy, cron, webhook, FTP, database, and file-workspace access independently. |
| WEB-014 | Provide a unified site workspace linking files, database, logs, DNS, TLS, cron, Git, deployments, terminal, backups, mail, security, applications, and limits. |
| WEB-015 | Restart or recycle one site's PHP/application runtime without restarting unrelated sites. |
| WEB-016 | Clone a site locally with selectable files, database, domains, DNS, TLS, mail, secrets, schedules, and activation policy. |
| WEB-017 | Transfer or clone a site between nodes through a signed, verified, resumable migration artifact. |
| WEB-018 | Preserve application data, including serialized WordPress values, during approved domain or path replacement. |
| WEB-019 | Preview deletion impact, disable routing and credentials first, quarantine owned data, and purge only after retention and final authorization. |
| WEB-020 | Detect and reconcile drift in identity, ownership, routes, listeners, runtime, TLS, DNS, quotas, permissions, and service state. |
| WEB-021 | Install, inspect, activate, refresh, convert between, and remove OpenLiteSpeed and licensed LiteSpeed Enterprise through separate adapters. |
| WEB-022 | Support OLS and LSE listeners, IPv4/IPv6, SNI, TLS, HTTP/1.1, HTTP/2, HTTP/3/QUIC, compression, LSAPI, proxy, CGI where supported, logs, and graceful lifecycle. |
| WEB-023 | Discover, install, inspect, configure, switch, update, and retire currently supported signed LSPHP runtimes and qualified extensions. |
| WEB-024 | Configure per-site PHP settings, OPcache, upload/body limits, process model, children/connections, timeouts, error display/logging, and targeted restart. |
| WEB-025 | Configure LSCache and cache rules per site/application and purge by authorized scope without global cache destruction. |
| WEB-026 | Convert OLS to LSE or LSE to OLS from canonical desired state in a maintenance workflow with target-license/capability preflight, shadow probes, drain, rollback lease, and no config translation. |
| WEB-027 | Create, inspect, enable, disable, rotate, revoke, back up/migrate, and delete HTTP realm/password protection for a site, WordPress, staging/preview route, or exact path with separate OLS/LSE proof. |
| WEB-028 | Switch PHP path policy between strict and compatibility or grant typed additional safe roots inside the mandatory SiteSandboxProfile; never disable the tenant/host boundary or accept an arbitrary host path. |
| WEB-029 | Create, inspect, diff, validate, test, enable, disable, version, roll back, export, back up/migrate, and delete node-global or site-scoped EngineExpertFragments through a closed OLS/LSE grammar; never edit a live engine file. |
| WEB-030 | Create and apply separate request- and response-header policies with route conditions, deterministic phase/order, protected security headers, migration mapping, and OLS/LSE proof. |
| WEB-031 | Create static and conditional application-environment policies, including purpose-bound secret references, without exposing another tenant, host environment, or credentials. |
| WEB-032 | Create site/route/file-pattern IPv4/IPv6 allow/deny policies with exact trusted-proxy/XFF semantics, observable decisions, safe lockout recovery, and both-engine proof. |
| WEB-033 | Configure HTTP/path brute-force and rate policy by route/method/identity/attempt window with log/throttle/challenge/expiring-block actions, allowlists, counters, evidence, and false-positive recovery. |
| WEB-034 | Map file-pattern matching, cache-expiry, and per-route PHP outcomes to typed RouteContext, CachePolicy, and PHPProfile resources while keeping `.htaccess` absent from the target runtime. |
| WEB-035 | Open a short-lived pre-DNS/alternate-host interactive site preview with correct Host/SNI/PHP/TLS/cache/WAF behavior, viewer access policy, expiry, and no open-proxy or cross-site access. |
| WEB-036 | Refresh a site/WordPress screenshot through an isolated local renderer or explicitly consented qualified provider with SSRF, redirect, privacy, byte/time, stale-generation, and egress controls. |
| WEB-037 | Inspect, preview, apply, probe, roll back, and reconcile typed node-global OLS/LSE workers, clear/TLS connection limits, timeouts, keepalive, compression, and cache/buffer budgets within edition/version/license and host-capacity bounds. |

### 22.4 DNS and certificates

| ID | Required outcome |
|---|---|
| DNS-001 | Install and manage PowerDNS Authoritative as the local DNS provider. |
| DNS-002 | Configure default nameservers and create or guide registrar glue records. |
| DNS-003 | Create, inspect, search, import, export, enable, disable, transfer ownership of, and delete zones. |
| DNS-004 | Create, inspect, update, and delete typed RRsets with TTL and record-specific validation. |
| DNS-005 | Support all record types accepted by the qualified PowerDNS release, with first-class A, AAAA, ALIAS, CAA, CNAME, DNSKEY, DS, HTTPS, LOC, MX, NAPTR, NS, OPENPGPKEY, PTR, RP, SOA, SPF, SRV, SSHFP, SVCB, TLSA, TXT, and URI journeys. |
| DNS-006 | Preserve unknown-but-valid provider RDATA through API and import/export without unsafe interpretation. |
| DNS-007 | Manage SOA policy and serials; reject invalid owner names, targets, priorities, weights, ports, TTLs, and RDATA. |
| DNS-008 | Configure primary and secondary zones, NOTIFY, AXFR, IXFR, masters, secondaries, and transfer health. |
| DNS-009 | Create, rotate, assign, revoke, and audit TSIG keys without redisclosing secret material. |
| DNS-010 | Connect, validate, rotate, and disconnect scoped Cloudflare credentials. |
| DNS-011 | List and reconcile Cloudflare zones/records, create/update/delete RRsets, and manage proxy state where supported. |
| DNS-012 | Surface local/provider conflicts; use real conditional RRset CAS only when the provider exposes it, otherwise serialize local writers, capture exact before/after, re-observe, report Conflict/Ambiguous on foreign edits, and compensate only when current state exactly matches this effect's output. |
| DNS-013 | Diagnose delegation, authoritative answers, serial divergence, transfers, DNSSEC, propagation, and provider synchronization. |
| DNS-014 | Rebuild local PowerDNS configuration and owned zones from canonical state without overwriting unmanaged authority. |
| DNS-015 | Enable and disable DNSSEC; create/import/rotate/retire KSK/ZSK or CSK material; sign zones; publish and verify DS guidance. |
| DNS-016 | Keep DNSSEC and TSIG secrets node-local or transfer them only as purpose-bound end-to-end ciphertext. |
| DNS-017 | Automate DNS-01 through local PowerDNS/RFC 2136 and Cloudflare adapters. |
| DNS-018 | Couple site and mail DNS automation through explicit plans while preserving independent DNS administration. |
| DNS-019 | Continue local authoritative service and reconciliation when central is unavailable. |
| DNS-020 | Perform DNS traffic cutover with TTL preparation, DNSSEC continuity, exact preconditions, observation, and rollback/fail-forward policy. |
| DNS-021 | Project sanitized zone health and accept authorized typed central intents without transferring local write authority. |
| DNS-022 | Back up, restore, migrate, and verify zones, records, transfer policy, and protected key references. |
| TLS-001 | Create and manage provider-neutral ACME accounts and terms acceptance. |
| TLS-002 | Issue certificates through HTTP-01 and DNS-01, including wildcard DNS-01. |
| TLS-003 | Issue and deploy certificates for primary sites, child domains, aliases, panel hostname, mail hostname, and configured mail names. |
| TLS-004 | Import custom certificate, chain, and key only after key-match, SAN, chain, algorithm, and lifetime validation. |
| TLS-005 | Generate an explicitly labelled self-signed certificate for development or recovery. |
| TLS-006 | Inspect subject/SANs, issuer, serial, chain, key type, lifetime, renewal method, consumers, and last deployment result. |
| TLS-007 | Renew automatically or on demand, revoke where supported, replace, and retire certificates. |
| TLS-008 | Stage one immutable certificate generation to every chosen OLS/LSE, mail, panel, and application consumer. |
| TLS-009 | Validate configuration and externally presented certificate behavior before confirming deployment. |
| TLS-010 | Roll back consumer generations when reload, handshake, SNI, chain, or application probes fail. |
| TLS-011 | Diagnose HTTP routing, DNS propagation, CAA, authorization, rate limit, time skew, chain, name, permission, and reload failures. |
| TLS-012 | Repair mail or panel certificate deployment without regenerating unrelated configuration. |
| TLS-013 | Protect private keys in the node secret store and omit them from central projections and routine backup metadata. |
| TLS-014 | Rotate ACME and DNS-provider credentials without losing renewal schedules or ownership. |
| TLS-015 | Renew locally while central is disconnected. |
| TLS-016 | Enforce renewal jitter, backoff, provider rate-limit awareness, expiry escalation, and stale-deployment detection. |
| TLS-017 | Back up protected certificate generations and restore/reissue according to declared secret policy. |
| TLS-018 | Expose issue, import, inspect, renew, deploy, revoke, repair, and diagnose consistently through UI, API, CLI, schedules, and optional central intent. |
| TLS-019 | Issue publicly trusted certificates through the named Let's Encrypt staging/production adapter and provide separately qualified ZeroSSL fallback behavior without silently changing CA, account, terms, or trust policy. |

### 22.5 MariaDB and database workspace

| ID | Required outcome |
|---|---|
| DB-001 | Install, initialize, inspect, start, stop, restart, health-check, tune, back up, restore, and upgrade supported MariaDB releases. |
| DB-002 | Create, inspect, list, migrate/rename, transfer ownership of, and delete databases. |
| DB-003 | Create, inspect, rotate, disable, and delete database principals. |
| DB-004 | Grant and revoke database-, table-, and operation-level privileges through a typed grant set. |
| DB-005 | Bind databases and principals to sites and enforce tenant visibility independently of database grants. |
| DB-006 | Return a generated database credential only once through an authorized secret delivery channel. |
| DB-007 | Enable, validate, and disable remote access per principal and allowed source CIDR. |
| DB-008 | Change account host grants, listener bind, firewall exposure, and connection verification as one compensating workflow. |
| DB-009 | Provide a scoped browser database workspace without reusable global/root credentials. |
| DB-010 | List databases, tables, views, columns, indexes, constraints, row estimates, and storage size. |
| DB-011 | Browse, filter, sort, paginate, insert, update, and delete rows under database-scoped authorization and bounds. |
| DB-012 | Create, alter, truncate, and delete schema objects after validation, preview, and destructive confirmation. |
| DB-013 | Run an interactive SQL session with a short-lived scoped grant, statement controls, deadline, result bounds, and audit. |
| DB-014 | Import and export databases with progress, cancellation, integrity validation, and artifact retention. |
| DB-015 | Report configuration, status variables, slow queries, connections, storage, replication, and health. |
| DB-016 | Generate evidence-backed tuning recommendations separately from mutation. |
| DB-017 | Preview and apply typed tuning through candidate configuration, maintenance planning, probes, and recovery. |
| DB-018 | Upgrade through compatibility preflight, recovery point, package transaction, schema tooling, validation, and explicit forward-only boundary. |
| DB-019 | Capture application-consistent database artifacts inside site and standalone backup policies. |
| DB-020 | Restore to a new isolated database first, verify, then optionally promote or remap consumers. |
| DB-021 | Support GTID-aware single-writer replication, lag/checkpoint observation, safe promotion, fencing, and rejoin. |
| DB-022 | Support a qualified Galera topology and orchestration without public unrestricted ports, ignore-split-brain flags, or unsafe bootstrap. |
| DB-023 | Prevent control-plane SQLite from becoming a shared or multi-writer HA database. |
| DB-024 | Reconcile physical database/principal/grant state with canonical resources and report or safely adopt/delete orphans. |
| DB-025 | Enroll, inspect, validate, rotate, suspend, and remove a managed external MariaDB instance using pinned TLS identity, capability/version discovery, protected administrative audience, and health. |
| DB-026 | Place selected site databases and qualified PowerDNS/mail/service schemas on local or external DatabaseInstance bindings with separate least-privilege principals and no shared remote root credential. |
| DB-027 | Back up, restore, migrate, fence, and rehearse consumers across local/external database placement; expose outage/latency/capability state and never fail over implicitly. |

### 22.6 Files, access credentials, FTPS, SFTP, SSH, and terminal

| ID | Required outcome |
|---|---|
| ACC-001 | Browse a site-scoped filesystem from an authorized capability root with stable pagination and metadata. |
| ACC-002 | Create files/directories and rename, copy, move, duplicate, and delete them within the authorized root. |
| ACC-003 | Upload one or many files with streaming, quota, hash, malware, size, timeout, and conflict controls. |
| ACC-004 | Download a file or generated archive by opaque resource/version, never an arbitrary privileged host path. |
| ACC-005 | Create and inspect ZIP, TAR, TAR.GZ, and TAR.ZST archives with bounded work and progress. |
| ACC-006 | Extract archives with traversal, link, device, FIFO, xattr/ACL, duplicate-path, nesting, expansion-ratio, and quota protection. |
| ACC-007 | Edit bounded text files with encoding detection, ETag/generation conflict, atomic replace, and recovery of prior generation. |
| ACC-008 | View and change allowed mode bits without permitting setuid/setgid/capability escape. |
| ACC-009 | View and change ownership only to identities resolved inside the resource's tenant/site boundary. |
| ACC-010 | Trash, list trash, restore, expire, and permanently delete site data under retention policy. |
| ACC-011 | Resist symlink, magic-link, hard-link, mount, rename, and time-of-check/time-of-use escape in every file operation. |
| ACC-012 | Create an expiring MFA-gated HostFilesystemSession for legitimate host administration through typed descriptor-relative operations. |
| ACC-013 | Bind a host-file session to explicit roots, actor, purpose, operation set, deadline, data-volume limit, and complete audit. |
| ACC-014 | Install, enable, disable, inspect, validate, repair, and remove the qualified FTPS service where that parity profile is enabled. |
| ACC-015 | Create, list, modify root/quota, rotate password, suspend, reactivate, and delete virtual FTPS accounts. |
| ACC-016 | Require TLS for FTP authentication/data and prefer SFTP; never offer cleartext FTP credentials. |
| ACC-017 | Create, import, list, fingerprint, label, constrain, expire, rotate, revoke, and delete SSH/SFTP public keys. |
| ACC-018 | Enable or disable site SSH/SFTP access, allowed authentication methods, root, forwarding, command, and expiry. |
| ACC-019 | Open a one-use browser PTY as the site UID in a bounded namespace/cgroup with origin, CSRF, audience, idle, duration, and transcript-metadata controls. |
| ACC-020 | Open an audited container-bound exec session without granting host-root or runtime-socket access. |
| ACC-021 | Provide a restricted local administrator CLI for typed recovery and host operations; explicitly provide no browser root shell. |
| ACC-022 | Enumerate active site terminal/SSH sessions and revoke them by stable session identity. |
| ACC-023 | Inspect per-site processes and working context, and terminate an authorized process by PID/start-time or pidfd with TERM-to-KILL policy. |
| ACC-024 | Enforce access roots and revocation immediately across UI, API, CLI, terminal, FTPS, SFTP, Git, and file workers. |
| ACC-025 | Stream large uploads/downloads without loading whole objects into control-plane memory or creating one timer/thread per transfer. |
| ACC-026 | Record checksums, byte counts, object versions, actor, source, and final outcome for bulk file movement. |
| ACC-027 | Back up and migrate access policy, public keys, virtual-account metadata, roots, quotas, and secret references with secure reissue defaults. |
| ACC-028 | Detect and reconcile filesystem ownership, permission, quota, account-database, and authorized-key drift without recursive global chmod/chown. |
| ACC-029 | Apply cross-tenant existence hiding and consistent permission denial to every path, archive, session, and credential lookup. |

### 22.7 Cron, Git, deployments, staging, and native transfer

| ID | Required outcome |
|---|---|
| DEV-001 | Create, inspect, list, enable, disable, modify, run-now, and delete site cron schedules. |
| DEV-002 | Parse schedules structurally, support timezone and missed-run policy, preview occurrences, and reject ambiguous or invalid schedules. |
| DEV-003 | Run cron as the site UID inside its cgroup/quota with bounded environment, output, timeout, overlap, and occurrence identity. |
| DEV-004 | Show cron history, exit status, duration, truncated output artifact, skipped/overlap reason, and next run. |
| DEV-005 | Initialize a repository, clone/attach a remote, inspect status/config, and detach management while preserving site data. |
| DEV-006 | List branches/tags/remotes/commits, view log/diff/file history, change branch, and inspect working-tree divergence. |
| DEV-007 | Pull, fetch, merge according to policy, push, add/commit, and update ignore/config through site-UID Git processes. |
| DEV-008 | Create, fingerprint, rotate, revoke, and purpose-bind deploy keys and known-hosts entries. |
| DEV-009 | Add, validate, rotate, pause, resume, and delete signed deployment webhooks. |
| DEV-010 | Verify webhook body signature, timestamp, audience, delivery ID, replay window, and repository binding before accepting work. |
| DEV-011 | Deduplicate webhook delivery and serialize deployment per target generation. |
| DEV-012 | Create an immutable deployment release from Git, upload, provider artifact, application recipe, or container digest. |
| DEV-013 | Preflight capacity/runtime/secrets, build as site UID, run declared migrations/hooks, probe, switch a managed-release pointer or execute the declared activation saga, and retain recovery material. |
| DEV-014 | Permit arbitrary application build/deploy commands only as the site UID inside the site boundary; privileged automation remains typed. |
| DEV-015 | Show deployment plan, progress, logs, commit/artifact digest, health, active release, and rollback eligibility. |
| DEV-016 | Cancel only at declared safe points and reconcile uncertain build, migration, promotion, and hook outcomes. |
| DEV-017 | Create a staging site from a production recovery point with isolated routes, database, secrets, schedules, mail, and provider effects. |
| DEV-018 | Compare production and staging files/database/application inventory before synchronization. |
| DEV-019 | Selectively synchronize files and/or database through snapshots, target recovery point, application-aware transform, verification, and an explicit per-component activation frontier. |
| DEV-020 | Require explicit direction, target, conflict policy, domain replacement, schedule/provider behavior, and irreversible frontier for staging sync. |
| DEV-021 | Clone or transfer sites/accounts between new-platform nodes using canonical resources, content-addressed chunks, resumable deltas, provenance, target rehearsal, and writer fencing. |
| DEV-022 | Preserve a safe source until target validation and soak; distinguish pre-target-write rollback from post-write recovery. |
| DEV-023 | Back up, restore, migrate, and reconcile repository bindings, deploy keys, webhook metadata, schedules, deployments, and staging relationships. |
| DEV-024 | Expose cron, Git, deployment, staging, and native-transfer outcomes consistently through local UI/API/CLI and authorized central orchestration. |

### 22.8 Automation, operation control, notifications, and extensions

| ID | Required outcome |
|---|---|
| RUN-001 | Submit any mutation as a durable typed operation and return acceptance separately from observed completion. |
| RUN-002 | Inspect operation plan, actor, approvals, resource locks, steps, attempts, progress, logs, effects, conditions, receipts, and terminal result. |
| RUN-003 | Cancel at declared safe points, retry only retry-safe steps, and reconcile ambiguous timeout or worker loss. |
| RUN-004 | Deduplicate client retries with an idempotency key and return the original operation/effect receipt. |
| RUN-005 | Fence stale workers and stale desired generations from committing later effects. |
| RUN-006 | Prioritize anti-lockout rollback, security recovery, and service restoration over scans, backups, builds, and provider work. |
| RUN-007 | Schedule recurring backups, scans, updates, certificates, campaigns, reports, maintenance, and reconciliation with durable occurrence IDs. |
| RUN-008 | Apply per-host, tenant, subsystem, provider, and resource concurrency and rate limits. |
| RUN-009 | Represent provider outage as waiting/degraded/failed with retry deadline, not as false success or blocked worker threads. |
| RUN-010 | Deliver in-product, SMTP, and signed-webhook notifications with templates, recipient policy, retry, deduplication, and failure visibility. |
| RUN-011 | Acknowledge or dismiss personal notifications without mutating the underlying audit/security event. |
| RUN-012 | Define typed notification rules for operation, health, quota, backup, security, certificate, provider, mail, update, and migration events. |
| RUN-013 | Install, inspect, enable, configure, suspend, update, roll back, disable, uninstall, and purge signed extensions. |
| RUN-014 | Run deterministic extension logic in capability-scoped WASM with fuel, memory, time, host-call, data, and egress bounds. |
| RUN-015 | Run long-lived service extensions in rootless OCI with signed digest, dedicated identity/network/volume, resource caps, health, and no host-control sockets. |
| RUN-016 | Grant extensions only ordinary versioned API permissions; prohibit in-process patching, lifecycle root scripts, generic host access, and permission self-expansion. |
| RUN-017 | Preserve or delete extension-owned data according to explicit uninstall policy and detect orphaned resources. |
| RUN-018 | Provide version/capability compatibility checks, deprecation, crash isolation, audit, telemetry, backup declaration, and migration declaration for extensions. |
| RUN-019 | Generate UI forms, CLI help, API clients, event schemas, and permission documentation from the same contracts to prevent surface drift. |

### 22.9 Application catalog and lifecycle

| ID | Required outcome |
|---|---|
| APP-001 | Discover signed, digest-pinned application definitions with support matrices, requirements, permissions, upgrade policy, and provenance. |
| APP-002 | Install a supported application into a new or existing site through a durable recovery-backed workflow. |
| APP-003 | Provide certified first-party recipes for WordPress, Joomla, PrestaShop, Mautic, and modern Magento Open Source before advertising each tile. |
| APP-004 | Model application instance, version, runtime, root, domains, database, secret references, component inventory, health, and active release. |
| APP-005 | Inspect, configure, start, stop, restart, repair, update, roll back, back up, restore, clone, and remove an application. |
| APP-006 | Detach/unmanage an application while preserving its site files/database and removing only panel automation, credentials, and metadata. |
| APP-007 | Resolve recipes only from signed catalogs and pinned artifacts; prohibit mutable upstream installer execution as root. |
| APP-008 | Run application tools and hooks as the site UID or inside the managed container, with declared secrets, egress, time, and resources. |
| APP-009 | Preflight PHP/database/extension/engine/storage compatibility and block rather than silently substitute unsupported versions. |
| APP-010 | Create a verified recovery point before destructive install, update, repair, or removal. |
| APP-011 | Build/update in an immutable working release, perform application/database health probes, then switch the release pointer and complete or recover the declared data saga. |
| APP-012 | Surface application logs, health, version drift, vulnerable components, pending updates, and failed automation. |
| APP-013 | Route containerized applications through internal-only ports and canonical OLS/LSE bindings. |
| APP-014 | Back up, restore, migrate, and reconcile application definitions, instances, inventory, secrets, database, files, schedules, and routes. |
| APP-015 | Require recipe conformance tests on every declared OS × engine × runtime × database cell before advertisement. |

### 22.10 WordPress management

| ID | Required outcome |
|---|---|
| WPS-001 | Install WordPress securely with generated database credentials, least privilege, selected locale/title/admin identity, HTTPS, and LSCache integration. |
| WPS-002 | Discover and adopt an existing WordPress instance only after validating canonical root, core files, configuration, database, ownership, and route. |
| WPS-003 | Inspect core, PHP, database, multisite, URL, admin users, plugins, themes, cache, cron, debug, health, and file-integrity state. |
| WPS-004 | Detach/unmanage WordPress while preserving site files/database and revoking panel-specific grants. |
| WPS-005 | Issue one-use audience/site/user-bound administrator login grants exchanged by a minimal signed MU-plugin; never reveal or reuse an admin password. |
| WPS-006 | Update core, plugins, themes, and translations through site-UID WP-CLI inside a recovery-backed immutable release workflow. |
| WPS-007 | Distinguish security, minor, major, plugin, theme, translation, and database updates with maintenance windows and exclusions. |
| WPS-008 | Configure per-component automatic-update policy, canary cohort, pause-on-failure, notification, and rollback. |
| WPS-009 | Install, upload, activate, deactivate, update, roll back, and delete plugins and themes with provenance and policy checks. |
| WPS-010 | Create and assign signed plugin/theme bundles and apply them to selected instances. |
| WPS-011 | Manage maintenance mode, search-engine visibility, debug policy, WP-Cron versus system cron, and application passwords. |
| WPS-012 | Manage WordPress users and roles without exposing password hashes or persistent panel credentials. |
| WPS-013 | Create staging from a verified recovery point with isolated domain, database, mail, schedules, webhooks, analytics, and provider effects. |
| WPS-014 | Push or pull selected files/database from staging after comparison, target recovery point, serialized search-replace, and health proof. |
| WPS-015 | Clone locally or remotely with domain/path replacement, database transform, secret rotation, cache purge, and source preservation. |
| WPS-016 | Create on-demand and scheduled WordPress-specific recovery points with files, database, metadata, inventory, and consistency evidence. |
| WPS-017 | Restore into a new isolated instance, verify, then promote; never overwrite production directly from an unverified archive. |
| WPS-018 | Configure and observe LSCache, page/object cache, Redis binding, purge policy, and engine/application cache consistency. |
| WPS-019 | Run integrity, malware, vulnerability, configuration, exposed-secret, and unsafe-user findings against a bounded snapshot. |
| WPS-020 | Support quick, full, custom, scheduled, and provider-assisted scans with progress, history, severity, evidence, and scanner provenance. |
| WPS-021 | Keep remote AI scanning opt-in and content-minimized; treat model output as advisory until deterministic or human confirmation. |
| WPS-022 | Create a separate remediation plan with digest preconditions, recovery point, quarantine/replace/restore, probes, audit, and rollback. |
| WPS-023 | Prevent a scanner or AI provider from receiving arbitrary live mutation authority. |
| WPS-024 | Report core/plugin/theme version vulnerabilities from pinned advisory sources and show remediation eligibility. |
| WPS-025 | Support site health, database optimization, transient/cache cleanup, permission repair, and cron repair as typed reviewed operations. |
| WPS-026 | Preserve application data and serialized values during URL/domain/path changes. |
| WPS-027 | Support Git-managed WordPress and immutable deployment modes without allowing panel automation to overwrite repository-owned files silently. |
| WPS-028 | Back up, restore, migrate, and reconcile all WordPress policies, bundles, inventory, scan/remediation evidence, staging, and login-grant infrastructure. |
| WPS-029 | Provide list/search/filter/fleet views and bounded batch actions locally and through optional central orchestration. |
| WPS-030 | Qualify the complete WordPress lifecycle separately on OLS and licensed LSE, including LSCache behavior and rollback. |
| WPS-031 | Manage WordPress/staging HTTP password protection through the canonical WebAccessPolicy, including credential rotation, login test, backup/migration reissue, and safe default protection for previews. |
| WPS-032 | Search, browse, filter, and paginate the WordPress core/plugin/theme catalog; inspect slug, version, author, compatibility, advisory/provenance and removal state; resolve a checked immutable artifact; and install/update with bounded rate, outage, stale-index, withdrawn-artifact, checksum/signature, and mirror handling. |

### 22.11 Mail domains, mailboxes, routing, filtering, and deliverability

| ID | Required outcome |
|---|---|
| MAIL-001 | Install, initialize, inspect, validate, start, stop, restart, repair, upgrade, and remove the qualified mail profile. |
| MAIL-002 | Create, inspect, suspend, reactivate, transfer, and delete mail domains independently or alongside a site. |
| MAIL-003 | Create, inspect, list, search, suspend, reactivate, rename/migrate, and delete mailboxes. |
| MAIL-004 | Generate/rotate a mailbox password and deliver it once; support policy-governed user self-change. |
| MAIL-005 | Configure mailbox and domain storage/send quotas and report measured use, rejections, and resets. |
| MAIL-006 | Create, inspect, modify, enable, disable, and delete aliases and multi-recipient forwarders. |
| MAIL-007 | Configure catch-all behavior explicitly as reject, discard, quarantine, or deliver to an allowed target. |
| MAIL-008 | Configure plus-addressing, pattern/regex routing where safely supported, and canonical address normalization. |
| MAIL-009 | Configure a mail-to-application pipe only through a signed capability-bound site-UID handler with spool, timeout, cgroup, arguments, and egress policy. |
| MAIL-010 | Create, inspect, enable, schedule, suspend, and delete autoresponder/vacation rules with loop, sender, interval, and date controls. |
| MAIL-011 | Configure SMTP receive on 25, authenticated submission on 587/465, IMAP on 993, LMTP, TLS, SASL, and ManageSieve. |
| MAIL-012 | Generate, rotate, deploy, verify, and retire DKIM keys per domain without exposing private material. |
| MAIL-013 | Generate and optionally apply SPF, DKIM, DMARC, MX, autodiscovery, and mail-host records through explicit DNS plans. |
| MAIL-014 | Verify forward/reverse DNS, HELO, TLS, authentication records, blacklist/provider signals, relay safety, and remote delivery behavior. |
| MAIL-015 | Configure Postfix routing, transports, smart relay, rate/concurrency controls, message limits, TLS policy, and trusted networks through typed models. |
| MAIL-016 | Configure Dovecot mailbox location, quota, authentication, IMAP/LMTP, Sieve, TLS, indexing, and supported compression through generated config. |
| MAIL-017 | Configure Rspamd as the primary spam/policy plane with Redis state and optional ClamAV malware scanning. |
| MAIL-018 | Preserve SpamAssassin/MailScanner operational outcomes through migration/diagnostics or a separately qualified exclusive legacy-filter profile; never run competing primary filters silently. |
| MAIL-019 | Configure global/domain/mailbox spam thresholds, allow/deny lists, actions, Bayes/statistics, and false-positive feedback. |
| MAIL-020 | List, inspect safely, release, deliver, delete, retain, and report false positives for spam/malware quarantine under scoped authorization. |
| MAIL-021 | Inspect mail queue summary and individual metadata/body safely; search, retry, hold, release, delete, and flush selected messages. |
| MAIL-022 | Stream/search structured Postfix, Dovecot, Rspamd, ClamAV, DKIM, policy, delivery, and authentication events. |
| MAIL-023 | Report per-domain/mailbox inbound/outbound volume, delivery result, rejection, deferral, bounce, spam, malware, quota, and authentication statistics. |
| MAIL-024 | Enforce hourly/monthly mailbox and domain sending limits through an atomic policy service that fails according to explicit availability policy, not silently open. |
| MAIL-025 | Detect brute-force and abuse patterns and apply reviewed, expiring, attributable bans without letting external tools become competing firewall owners. |
| MAIL-026 | Issue and rotate panel/mail certificates and verify external SMTP/IMAP presentation and service reload. |
| MAIL-027 | Back up and application-consistently restore domains, mailboxes, Maildir metadata, Sieve, aliases, routing, DKIM, quota, and canonical configuration. |
| MAIL-028 | Restore mail into an isolated namespace, validate ownership/indexes/quota, then activate delivery without erasing another mailbox's data. |
| MAIL-029 | Migrate mail through Dovecot dsync or safe Maildir/Mdbox conversion, final delivery fence, queue/relay convergence, and GUID-aware deduplication. |
| MAIL-030 | Reconcile Postfix/Dovecot/Rspamd/OpenDKIM state, mailbox filesystem, DNS plans, certificates, queue, and canonical resources. |
| MAIL-031 | Continue SMTP/IMAP delivery and local scheduled policy while paneld or central is unavailable; expose degraded administration honestly. |
| MAIL-032 | Prevent open relay, cross-tenant mailbox access, header/body injection, unsafe pipes, plaintext secret disclosure, and unbounded message parsing. |
| MAIL-033 | Qualify server administration, webmail SSO, filtering, deliverability, backup/restore, and migration as separate but integrated products. |
| MAIL-034 | Create, inspect, enable, disable, scope, retain, export, purge, back up/restore, and migrate per-domain/per-mailbox delivery-log policy without erasing audit/security evidence or logging bodies/credentials by default. |

### 22.12 Webmail, contacts, groups, settings, and Sieve

| ID | Required outcome |
|---|---|
| WML-001 | Open webmail through a one-use short-lived mailbox-scoped OAuth/OAUTHBEARER grant without returning the mailbox password. |
| WML-002 | List authorized mail accounts and switch account context without N+1 control queries or cross-account token reuse. |
| WML-003 | List folders with counts, hierarchy, subscription, special-use roles, quotas, and bounded pagination. |
| WML-004 | Create, rename, subscribe, unsubscribe, empty, and delete eligible folders. |
| WML-005 | List messages by folder with cursor pagination, sort, thread/conversation projection, flags, sender, subject, date, size, and attachment state. |
| WML-006 | Search server-side with bounded criteria and return a page of message identities; never expand an unbounded UID set into one response. |
| WML-007 | Read plain text and sanitized HTML safely with CSP, no active content, secure link handling, and explicit remote-image policy. |
| WML-008 | Proxy remote images through SSRF-resistant URL, DNS/IP, redirect, content-type, size, cache, and privacy controls. |
| WML-009 | Download and preview attachments by message/part identity with streaming, safe disposition, malware policy, and no whole-message memory copy. |
| WML-010 | Compose, reply, reply-all, forward, save draft, schedule where supported, and send mail with MIME/address/header validation. |
| WML-011 | Upload compose attachments into bounded temporary storage and stream final MIME submission without unbounded memory amplification. |
| WML-012 | Move, copy, delete, undelete, archive, mark read/unread, flag/unflag, and report spam/not-spam for one or bounded batches. |
| WML-013 | Create, inspect, search, update, import, export, merge, and delete contacts. |
| WML-014 | Create, inspect, update, populate, and delete contact groups/distribution groups with authorization and recipient limits. |
| WML-015 | Configure identities, signatures, reply-to, display, timezone, compose, notification, remote-image, and privacy preferences. |
| WML-016 | Create, validate, order, enable, disable, test, and delete Sieve rules through typed builders plus an expert text editor with parser validation. |
| WML-017 | Provide vacation/autoresponder UI backed by the canonical mail rule rather than an independent conflicting implementation. |
| WML-018 | Preserve draft/send idempotency and show uncertain submission state rather than double-sending after timeout. |
| WML-019 | Meet keyboard, screen-reader, localization, mobile, pagination, timeout, MIME fuzzing, XSS, and attachment-bomb qualification. |
| WML-020 | Back up, restore, migrate, and reconcile user settings, identities, contacts, groups, folder metadata, and Sieve rules. |

### 22.13 Email marketing

| ID | Required outcome |
|---|---|
| MKT-001 | Create, inspect, search, modify, archive, restore, and delete tenant-scoped subscriber lists. |
| MKT-002 | Add, update, tag, verify, suppress, unsubscribe, resubscribe where lawful, and delete subscribers. |
| MKT-003 | Import subscribers from validated CSV with preview, field mapping, deduplication, consent source/time, errors, and bounded batch processing. |
| MKT-004 | Export authorized list/subscriber state with consent and suppression data under privacy policy. |
| MKT-005 | Provide local or selected provider email-verification with explicit data egress, result provenance, rate limit, and uncertainty. |
| MKT-006 | Maintain global and tenant suppression for unsubscribe, complaint, hard bounce, policy, and manual block. |
| MKT-007 | Generate tamper-resistant single-purpose unsubscribe links and honor them immediately without authentication. |
| MKT-008 | Create, inspect, version, preview, test-send, archive, and delete message templates with sanitized variables and safe HTML. |
| MKT-009 | Create, inspect, schedule, approve, pause, resume, cancel, clone, and archive campaigns. |
| MKT-010 | Select list segments, template, subject/from/reply-to, delivery profile, schedule, rate, and tracking/consent policy. |
| MKT-011 | Freeze a recipient snapshot at approval, deduplicate addresses, and recheck suppression immediately before each attempt. |
| MKT-012 | Deliver through a separate bounded campaign queue using local or configured relay capacity without starving transactional mail. |
| MKT-013 | Make every recipient attempt idempotent and expose queued, sent, delivered, deferred, bounced, complained, suppressed, and failed states. |
| MKT-014 | Process provider/local bounce and complaint events with signature, replay, tenant, and recipient correlation. |
| MKT-015 | Report campaign/list statistics with exact denominators, delayed-event status, provider provenance, and privacy-aware tracking. |
| MKT-016 | Enforce tenant/day/hour/concurrency/recipient limits, warm-up policy, abuse controls, and sender-domain verification. |
| MKT-017 | Prevent recipient enumeration, cross-tenant list access, header injection, template code execution, and accidental secret expansion. |
| MKT-018 | Back up and migrate list metadata, subscribers, consent, suppression, templates, campaigns, attempts, and provider references under privacy/retention policy. |
| MKT-019 | Continue locally scheduled campaign safety behavior offline from central; external delivery waits honestly for its provider. |
| MKT-020 | Ship consent, suppression, unsubscribe, bounce, complaint, rate, deliverability, privacy, and restoration acceptance suites before enabling campaigns. |

### 22.14 External mail-delivery integration

| ID | Required outcome |
|---|---|
| EDL-001 | Configure an external delivery provider through a versioned adapter and encrypted credential reference. |
| EDL-002 | Verify domain ownership and required DNS records without falsely marking incomplete provider state active. |
| EDL-003 | Generate/apply and continuously validate SPF, DKIM, return-path, tracking, and provider-specific DNS plans. |
| EDL-004 | Enable, disable, rotate, and revoke relay credentials with overlap and dependent reload. |
| EDL-005 | Route selected domains, mail streams, or campaigns through local or external delivery explicitly. |
| EDL-006 | Configure transactional/campaign rate, retry, bounce, complaint, suppression, and fallback policy. |
| EDL-007 | Verify signed provider webhooks, timestamps, delivery IDs, replay protection, tenant/domain binding, and schema versions. |
| EDL-008 | Import provider delivery, bounce, complaint, suppression, reputation, and usage events into canonical status. |
| EDL-009 | Show provider health, credential state, quota, domain verification, rate limits, usage, cost metadata where available, and last synchronization. |
| EDL-010 | Rotate or change provider without losing message identity, suppression, audit, or pending-work reconciliation. |
| EDL-011 | Treat timeout/partial response as ambiguous and query by provider/idempotency identity before retrying. |
| EDL-012 | Circuit-break provider outage and preserve bounded local queues according to declared retention and backpressure. |
| EDL-013 | Keep provider secrets and raw tenant mail content out of central projection, logs, support bundles, and unrelated workers. |
| EDL-014 | Back up provider configuration and protected references; require reauthorization when provider policy prevents secret portability. |
| EDL-015 | Support one named qualified initial provider and a local SMTP path at GA; substitutable vendor identity does not permit a mock adapter. |
| EDL-016 | Pass sandbox and production conformance for pagination, timeout, rate limit, revoked credential, replay, partial write, event delay, and reconciliation. |

### 22.15 Backup, restore, retention, transfer, and disaster recovery

| ID | Required outcome |
|---|---|
| BAK-001 | Create, inspect, modify, enable, disable, run, clone, and delete backup policies scoped to site, tenant, resource selector, or node. |
| BAK-002 | Select files, database, mail, DNS, certificate/secret policy, canonical configuration, application descriptors, schedules, and provider metadata explicitly. |
| BAK-003 | Configure schedule, timezone, RPO target, consistency class, bandwidth/concurrency, destinations, copy quorum, and retention policy. |
| BAK-004 | Create, validate, rotate, suspend, resume, and delete repositories and encrypted provider credentials. |
| BAK-005 | Provide qualified local, SFTP, AWS S3, DigitalOcean Spaces, MinIO, generic S3-compatible, and Google Drive repository adapters. |
| BAK-006 | Upload under a staging namespace, stream and encrypt client-side, verify object hashes/counts/bytes, and publish a signed commit marker last. |
| BAK-007 | Represent one cross-component capture as a RecoveryPoint with barrier ID, component generations, consistency class, manifest/Merkle root, copies, and verification. |
| BAK-008 | Publish a recovery point as restorable only when all required component artifacts and destination commit evidence exist. |
| BAK-009 | Resume interruption from immutable chunks without overwriting or falsely completing partial work. |
| BAK-010 | Apply short application-aware write barriers, LSAPI drain, database-native dump/checkpoint, and Dovecot flush/sync where available. |
| BAK-011 | Label crash-consistent, application-consistent, quiesced, and mixed consistency per component without overstating atomicity. |
| BAK-012 | Keep local/staging data until remote copy commit and verification succeed; never delete the only artifact after upload ambiguity/failure. |
| BAK-013 | Verify each copy by manifest/object checks and scheduled representative restore drills; track ObjectVerified, ManifestVerified, and RecoveryTested separately. |
| BAK-014 | List/search/filter recovery points by policy, resource, time, tags, consistency, provider, verification, size, and retention. |
| BAK-015 | Add/remove legal holds and leases that prevent retention from touching active backup, restore, replication, investigation, or verification. |
| BAK-016 | Implement GFS/age/count/tag retention within the exact repository/policy prefix and never bucket-wide. |
| BAK-017 | Create and verify a fresh point before pruning where policy requires; retain minimum independent verified survivors and prune only unreachable objects. |
| BAK-018 | Report retention candidates, decisions, freed bytes, preserved dependencies, provider errors, and post-prune catalog verification. |
| BAK-019 | Create a RestorePlan mapping source resources to new/existing targets with conflict, domain, secret, network, schedule, and provider policy. |
| BAK-020 | Validate manifest/signature/decryption, archive safety, capacity, malware, compatibility, ownership, and required secrets in bounded scratch. |
| BAK-021 | Restore files into a new release/tree and databases/mail into isolated namespaces before exposure. |
| BAK-022 | Use blue/green activation only when an application adapter proves endpoint/credential switching; otherwise fence writes and perform declared-downtime restore. |
| BAK-023 | Probe web, PHP, database, DNS, TLS, mail, permissions, quotas, applications, schedules, and provider references appropriate to scope. |
| BAK-024 | Preserve replaced target state for rollback until soak/retention; expose any irreversible database/application frontier. |
| BAK-025 | Restore a full node on a clean supported host using a signed DR bundle, local key-recovery ceremony, canonical render, dark validation, and controlled traffic activation. |
| BAK-026 | Separate control-plane disaster recovery from ordinary tenant restore and prohibit tenant UI from restoring authority databases. |
| BAK-027 | Measure effective backup RPO as age of latest usable point and measured RTO from rehearsals, not configured intent. |
| BAK-028 | Replicate verified copies between nodes or repositories with encryption, checkpoint, resumability, destination verification, and source retention. |
| BAK-029 | Transfer a recovery point to another node/account through a signed scoped grant rather than exchanging root SSH keys. |
| BAK-030 | Export/import a portable signed catalog and content manifest without panel-user hashes, session/API tokens, or plaintext credentials. |
| BAK-031 | Provide progress, throughput, ETA uncertainty, component state, retries, cancellation, logs, receipts, alerts, and last-known-good point. |
| BAK-032 | Bound backup CPU, I/O, memory, bandwidth, file descriptors, temporary disk, provider concurrency, and schedule overlap. |
| BAK-033 | Reconcile missing/orphaned chunks, copies, manifests, catalogs, locks, leases, partial staging, and provider-side drift without unsafe deletion. |
| BAK-034 | Pass clean-room restore, corruption, wrong/missing key, provider outage, partial upload, disk-full, power-loss, concurrent backup/retention/restore, and clean-host DR tests. |

### 22.16 Security posture, firewall, SSH, WAF, malware, and incident response

| ID | Required outcome |
|---|---|
| SEC-001 | Define desired SecurityPosture with singular subsystem ownership, conditions, drift, evidence, and versioned change transactions. |
| SEC-002 | Install and manage exactly one firewall authority: nftables directly or firewalld with detected nftables backend. |
| SEC-003 | Create, inspect, validate, enable, disable, expire, and delete typed IPv4/IPv6 firewall rules and service exposures. |
| SEC-004 | Protect required control, SSH, DNS, web, mail, database, FTPS, and container listeners while preventing self-lockout. |
| SEC-005 | Change listener exposure make-before-break with local proof, optional external proof, client confirmation, rollback lease, and reboot recovery. |
| SEC-006 | Create expiring emergency/incident bans and allowlists with source evidence, actor, reason, owner, false-positive recovery, and automatic unban. |
| SEC-007 | Configure SSH root-login, password/key methods, allow principals, port/listeners, algorithms, forwarding, timeouts, and maximum attempts through validated generations. |
| SEC-008 | Parse, fingerprint, label, constrain, expire, revoke, and reconcile SSH public keys using generated authorized-key fragments. |
| SEC-009 | Ingest structured successful/failed SSH login events, sessions, GeoIP/licensed enrichment, risk, and brute/dictionary/flood/root-attempt findings. |
| SEC-010 | Inspect per-user process tree, cgroup, executable, start time, working context, and open session without exposing shell history by default. |
| SEC-011 | Block a source, revoke a key/session, disable an account, quarantine a site, or terminate a process as separate reviewable actions. |
| SEC-012 | Manage WAF policy per node/site using engine-qualified ModSecurity/native capabilities and pinned signed rule sets. |
| SEC-013 | Provide an always-available OWASP CRS baseline and separately qualified commercial/Imunify rule providers. |
| SEC-014 | Stage WAF updates in inactive slot, validate, replay a corpus, run detect-only canary, promote atomically per engine, and roll back rapidly. |
| SEC-015 | Create narrow, attributable, expiring WAF exclusions by rule/route/method/parameter/source; reject scopes the active engine cannot express exactly. |
| SEC-016 | Search and inspect WAF audit events, rule hits, anomaly scores, blocked requests, false positives, exclusions, and rule-version provenance. |
| SEC-017 | Install/configure/status/update/uninstall a qualified malware/host-security provider such as Imunify only under explicit subsystem ownership. |
| SEC-018 | Run baseline local malware, integrity, vulnerability, secret, and configuration scans even without a commercial provider. |
| SEC-019 | Record canonical findings with evidence, confidence, scanner/model/signature provenance, target digest, lifecycle, assignee, and disposition. |
| SEC-020 | Quarantine reversibly with original digest/metadata, non-executable isolation, tenant separation, expiry, access log, and release/delete approval. |
| SEC-021 | Require reviewed remediation with generation/hash preconditions, recovery point, exact diff, probes, compensation, and no AI-only irreversible deletion. |
| SEC-022 | Separate read-only diagnostics, proposed RepairPlan, approval, mutation, validation, and rollback. |
| SEC-023 | Protect product-managed secrets with envelope encryption, versioned purpose-bound references, JIT delivery, rotation, redaction, and explicit escrow/recovery. |
| SEC-024 | Use a human-controlled key hierarchy for release/recovery roots; qualify TPM/HSM sealing where available but describe software keys honestly as root-readable. |
| SEC-025 | Detect product-managed secret fingerprints at log/export boundaries; treat tenant/daemon logs as hostile potentially secret-bearing data with access/retention/leak controls. |
| SEC-026 | Create evidence-preserving incident cases that link findings, logs, sessions, processes, bans, quarantine, actions, actors, artifacts, and timeline. |
| SEC-027 | Export a redacted signed incident/support bundle and verify audit hash/checkpoint continuity without claiming immutability against root. |
| SEC-028 | Pass command/path/archive/container/terminal isolation, authorization/replay, secret disclosure, firewall lockout, WAF bypass, malware safety, update, and cross-tenant adversarial suites. |
| SEC-029 | Create/import, inspect, edit, validate, test, enable, disable, version, roll back, export, back up/migrate, and delete scoped custom ModSecurity rules with separate OLS/LSE representability and no executable include escape. |

### 22.17 Observability, audit, health, reporting, and capacity

| ID | Required outcome |
|---|---|
| OBS-001 | Provide structured functional health for every managed node, service, site, runtime, provider, repository, certificate, replication channel, and operation. |
| OBS-002 | Collect bounded CPU/load/memory/swap/pressure/disk/inode/I/O/network/process/cgroup/service/queue/backup/TLS/mail/WAF metrics. |
| OBS-003 | Show node dashboards from cached metrics rather than launching fresh top/du/database scans per tab poll. |
| OBS-004 | Show tenant/site usage and limits without unbounded synchronous filesystem traversal or N+1 queries. |
| OBS-005 | Stream, search, filter, tail, export, retain, and redact structured logs with cursor pagination and bounded client memory. |
| OBS-006 | Separate audit, security events, operation events, notifications, metrics, logs, and artifacts according to integrity and retention needs. |
| OBS-007 | Emit an append-only application-level AuditEvent for every security-relevant request-level authorization unit and mutation with real/effective actor and request/result digests; aggregate internal row decisions into bounded signed manifests rather than unbounded per-row events. |
| OBS-008 | Hash-chain audit records, sign periodic checkpoints, verify/export continuity, and optionally replicate checkpoints externally. |
| OBS-009 | State that local audit is tamper-evident, not immutable against host root; expose missing sequence/checkpoint or clock discontinuity. |
| OBS-010 | Configure local inbox, SMTP, and signed-webhook alert delivery with routing, severity, quiet windows, rate, dedupe, retry, and delivery health. |
| OBS-011 | Alert on service health, disk/inode pressure, quota, operation failure/stall, certificate expiry, backup RPO/restore proof, mail queue, security, provider, update, replication, and audit integrity. |
| OBS-012 | Provide historical charts and reports with explicit sample interval, aggregation, retention, missing-data indication, and bounded cardinality. |
| OBS-013 | Calculate capacity forecasts and recommendations from measured evidence while separating observation from mutation. |
| OBS-014 | Generate billing/usage exports for plans, storage, traffic, CPU, mail, backups, provider use, and campaigns without embedding proprietary commerce. |
| OBS-015 | Apply deterministic disk-watermark behavior that preserves audit, recovery, and rollback reserves and never wildcard-deletes tenant data/backups/log classes. |
| OBS-016 | Keep audit and terminal operation receipts in a prioritized bounded durable spool; visibly block new central mutations if essential spool capacity is exhausted. |
| OBS-017 | Protect product logs/support artifacts through deterministic secret scanning, access control, encryption/retention, integrity hashes, and safe downloads. |
| OBS-018 | Qualify dashboards, log/metrics throughput, cardinality, slow clients, disk-full, clock skew, retention, secret redaction, and alert delivery failure. |

### 22.18 Containers, Docker outcomes, and resource isolation

| ID | Required outcome |
|---|---|
| CTR-001 | Detect Docker/rootless backend capability and install, inspect, start, stop, restart, update, repair, and remove the qualified engine profile. |
| CTR-002 | Keep paneld away from privileged runtime sockets; send typed operations through a dedicated broker. |
| CTR-003 | Provide rootful Docker administration only to host administrators and a separately qualified rootless/user-namespace tier for tenant workloads. |
| CTR-004 | Configure, authenticate, rotate, and remove OCI registry credentials; qualify Docker Hub as the initial public registry journey. |
| CTR-005 | Search registry images/tags, inspect manifest/platform/history/SBOM/signature/vulnerabilities, and resolve immutable digest. |
| CTR-006 | Pull, list, inspect, verify, retain, and delete images with progress, deduplication, storage pressure, and in-use protection. |
| CTR-007 | Create, inspect, list, search, start, stop, restart, pause where supported, recreate, and delete container workloads. |
| CTR-008 | Adopt/import an existing administrator-owned container only after normalized inspection, policy validation, ownership assignment, and drift declaration. |
| CTR-009 | Configure image digest, command/arguments, working directory, environment/secret references, user, restart/update policy, and health check structurally. |
| CTR-010 | Configure broker-issued volumes and managed mounts without tenant-chosen host paths or runtime sockets. |
| CTR-011 | Configure per-tenant networks, DNS, internal ports, published exposures, and canonical OLS/LSE reverse-proxy bindings. |
| CTR-012 | Deny tenant privileged mode, host PID/IPC/network/user namespaces, devices, arbitrary host mounts, cap-add, unconfined profiles, sensitive sysctls, and control-plane endpoints. |
| CTR-013 | Apply CPU, memory, PID, I/O, storage, inode, network, process, and restart limits and report effective enforcement/pressure/OOM. |
| CTR-014 | Stream bounded logs with cursor/time/tail controls and no whole-log HttpResponse buffering. |
| CTR-015 | Report metrics, stats, health, processes/top, restart count, image drift, network, volumes, exposures, and security posture. |
| CTR-016 | Open an expiring audited tenant-container exec only with a non-host-root user mapping; treat rootful/admin exec as high-risk host-equivalent authority where mounts/capabilities/runtime identity permit it and confirm the exact impact. |
| CTR-017 | Export a portable signed container/application descriptor and referenced volumes through the backup artifact system, not an unbounded memory response. |
| CTR-018 | Import/restore into an isolated workload, verify digest/config/volume/health, then promote routing. |
| CTR-019 | Recreate or update by producing a new generation, health-gating it, switching traffic, and retaining the prior generation according to policy. |
| CTR-020 | Parse Compose input into a normalized preview and reject unsupported escape/privilege fields; never pass arbitrary Compose directly to root. |
| CTR-021 | Create Docker-backed websites/packages and route only internal application ports through typed OLS/LSE proxy configuration. |
| CTR-022 | Provide certified containerized WordPress and n8n application recipes with secrets, volumes, database, health, backup, update, and rollback. |
| CTR-023 | Assign owner/tenant and enforce cross-tenant visibility, actions, networks, volumes, logs, exec, image, and quota. |
| CTR-024 | Reconcile missing/restarted/orphaned containers, images, networks, volumes, exposures, and route bindings without adopting foreign state silently. |
| CTR-025 | Back up and restore workload specs, encrypted secrets, application-consistent volumes/databases, networks, and route metadata. |
| CTR-026 | Enforce cgroup v2/systemd resource profiles for all site-UID work: PHP, cron, Git, terminal, scanner, build, deploy, and native app processes. |
| CTR-027 | Enforce filesystem project quotas for bytes/inodes and LSAPI/PHP limits for concurrency, request memory, body, upload, and timeout. |
| CTR-028 | Account and enforce network traffic/shaping only through a Gate-0-proven mechanism; never claim a nonexistent cgroup network controller. |
| CTR-029 | Map the same canonical ResourceProfile to conditional-baseline CloudLinux LVE/CageFS capabilities, observe drift, and reject unsupported dimensions. |
| CTR-030 | Install/initialize/update/enable/disable/inspect/repair CageFS and map LVE CPU, PMEM/VMEM, IO/IOPS, EP, NPROC, inodes, and PHP concurrency when CloudLinux is advertised. |
| CTR-031 | Pass hostile-image, runtime-socket, namespace, device, mount, capability, metadata-network, secret, resource-exhaustion, reboot, backup/restore, and cross-tenant tests. |

### 22.19 LiteSpeed Enterprise licensing and administrative control

| ID | Required outcome |
|---|---|
| LSE-001 | Discover supported LiteSpeed Enterprise artifact channels and legal redistribution/BYOL constraints before installation. |
| LSE-002 | Enroll a customer-supplied serial/license or start an eligible trial through a protected one-use secret workflow. |
| LSE-003 | Activate and validate a license against the exact host identity, edition, worker/RAM/domain/options limits, and vendor response. |
| LSE-004 | Show license edition, masked identity, activation state, limits, expiry/grace, refresh time, and actionable failure without projecting the secret centrally. |
| LSE-005 | Refresh/renew license state, back off vendor outage, preserve certified offline behavior, and alert before service-impacting expiry. |
| LSE-006 | Transfer/release or replace a license through an explicit workflow that prevents accidental double activation and preserves recovery. |
| LSE-007 | Handle revoked, invalid, expired, over-limit, hardware-changed, and vendor-unreachable states without silently switching engine or destroying configuration. |
| LSE-008 | Preflight license entitlement/capacity before install, engine conversion, upgrade, worker-count change, or enterprise-only feature activation. |
| LSE-009 | Replace LiteSpeed WebAdmin's legitimate status/configuration/password outcomes with panel RBAC, typed engine resources, step-up control, audit, and local recovery; ship no separately exposed reusable WebAdmin console by default. |
| LSE-010 | Qualify licensing and enterprise-only lifecycle in real licensed CI/labs independently from OLS for every supported OS tuple and release. |

### 22.20 Multi-node placement, replication, high availability, and failover

| ID | Required outcome |
|---|---|
| HA-001 | Enroll, inspect, authorize, label, drain, detach, and retire nodes in a self-hostable optional federation deployment. |
| HA-002 | Discover node engine/service/version/capacity/failure-domain/provider capabilities and keep projections visibly revisioned/stale. |
| HA-003 | Define placement groups by eligible nodes, labels, anti-affinity, capacity reserve, maintenance, and failure domain. |
| HA-004 | Define replica sets for stateless applications and container workloads with desired count, health, rollout, and route policy. |
| HA-005 | Place, scale, update, drain, reschedule, and remove replicas through node-local intents and locally observed receipts. |
| HA-006 | Define warm-standby site/file replication with encrypted channels, checkpoints, lag, consistency, exclusions, and recovery points. |
| HA-007 | Define MariaDB primary/replica GTID or separately qualified Galera topology with health, quorum, lag, fencing, promotion, and rejoin. |
| HA-008 | Define PowerDNS primary/secondary transfer topology, TSIG, notify health, serial convergence, and failover authority. |
| HA-009 | Define redundant mail ingress and an explicit single mailbox-writer or qualified replicated mailbox topology. |
| HA-010 | Define replicated container applications with immutable image, volume/data topology, secrets, health, and routing. |
| HA-011 | Show replica availability, data checkpoint/lag, RPO, last health, pending resources, failures, and estimated RTO. |
| HA-012 | Create TrafficPolicy for exact DNS or qualified load-balancer endpoints, weights, health, TTL, and compare-and-swap preconditions. |
| HA-013 | Create a quorum-backed WriterLease only for write paths that enforce it; never treat a database lease as a filesystem/application fence. |
| HA-014 | Integrate certified power, storage, database, or mandatory-lease fencing providers per topology. |
| HA-015 | Disable automatic promotion when every relevant write path cannot be proven fenced. |
| HA-016 | Require independently confirmed physical/administrative fencing before manual promotion without an enforceable automatic provider. |
| HA-017 | Plan failover with target readiness, latest checkpoint, potential loss, compatibility, secrets, health quorum, fence evidence, route change, approvals, and rollback/fail-forward. |
| HA-018 | Fence the prior writer, promote target, activate internal services, switch traffic, probe, and commit as a durable saga. |
| HA-019 | Freeze unsafe writes on loss of quorum; never use ignore-split-brain flags or unsafe bootstrap as availability shortcuts. |
| HA-020 | Rebuild/resynchronize a returning node from the elected generation before allowing it to write or receive traffic. |
| HA-021 | Fail back/sync back through a separately planned writer transition and never overwrite elected state with a stale source. |
| HA-022 | Preserve old writer/recovery evidence until soak and explicit retirement; expose the post-write irreversible frontier. |
| HA-023 | Schedule and run non-disruptive replication/failover readiness checks and controlled recovery drills. |
| HA-024 | Replicate verified backup copies across nodes/failure domains and demonstrate clean-host recovery independent of live replication. |
| HA-025 | Roll out OLS/LSE/PHP/application/container configuration across replicas with canaries, bounded concurrency, health halt, and per-node rollback eligibility. |
| HA-026 | Scale CPU/memory/resource profiles and replica count without allowing central policy to exceed local plan, support, or capacity. |
| HA-027 | Keep local node management and existing workloads operational during central outage; accepted local HA safety actions continue. |
| HA-028 | Expire unaccepted destructive fleet intents and reconcile already accepted node operations from local receipts after reconnect. |
| HA-029 | Encrypt node-to-node data and purpose-bound secret replication end to end; avoid root SSH keys and disabled host verification. |
| HA-030 | Maintain an immutable central orchestration plan plus authoritative node-local operation/audit evidence; never a writable central resource mirror. |
| HA-031 | Report measured rather than configured RPO/RTO and forbid zero-data-loss claims without synchronous fenced proof. |
| HA-032 | Pass partitions, asymmetric health, stale projection, duplicate intent, central failover, quorum loss, fence failure, DNS/provider lag, source return, and split-brain tests. |
| HA-033 | Support CyberPanel-equivalent site/Galera/DNS cutover and Docker-replica outcomes without Swarm tokens, arbitrary Compose, public unrestricted DB ports, or remote root command execution. |

### 22.21 Optional central control-plane outcomes

| ID | Required outcome |
|---|---|
| FED-001 | Enroll a node only after local-owner initiation, central CA fingerprint verification, one-use token consumption, and explicit authority grant. |
| FED-002 | Rotate/revoke peer certificates, assertion keys, encryption keys, authority grant, and workload identity without losing local ownership. |
| FED-003 | Define one mutation peer and zero or more observer peers with independent projection/resource/risk/expiry scopes. |
| FED-004 | Map immutable central issuer/subject identities to local FederatedPrincipalBindings with role ceiling, selectors, assurance, validity, and risk limits. |
| FED-005 | Forbid email-only identity matching, central-created instance-owner authority, or central widening of a local binding/grant. |
| FED-006 | Project sanitized inventory, desired/observed generation, conditions, capabilities, usage, operation results, alerts, and stale-since. |
| FED-007 | Remotely request every authorized local capability through the same typed local command gateway and policy as UI/API/CLI. |
| FED-008 | Sign intents with peer/node, actor assertion, auth time/methods, authority/authz epoch, target generation, idempotency/effect IDs, approvals, expiry, payload digest, and signature. |
| FED-009 | Recompute local authorization, quota, support, lifecycle, risk, approval, CAS, replay, and capability before acceptance. |
| FED-010 | Return a durable local receipt on acceptance and locally observed terminal proof later; never treat central queueing as host success. |
| FED-011 | Deduplicate retries and reject stale/reordered/expired/revoked/conflicting intents exactly. |
| FED-012 | Increment local authority epoch on revoke/break-glass and invalidate queued central work immediately. |
| FED-013 | Maintain one outbound-only mutually authenticated multiplexed stream; expose no inbound cloud command router or permanent bearer token. |
| FED-014 | Spool prioritized audit-adjacent events/receipts durably and bound telemetry; block new central mutations rather than discard essential receipts on exhaustion. |
| FED-015 | Resynchronize revocations first, then receipts, event cursors, projections, and signed snapshots without duplicate effects. |
| FED-016 | Relay one-use locally issued file/database/site-terminal/support sessions with bounded end-to-end encrypted frames and no reusable node credential. |
| FED-017 | Support client-to-node HPKE secret delivery where central sees ciphertext only; declare central a trust participant when its integration originates/transforms plaintext. |
| FED-018 | Freeze fleet rollout targets, artifact/intent digest, capabilities, waves, concurrency, health gates, halt threshold, maintenance, expiry, and rollback class. |
| FED-019 | Operate central identities/RBAC, node registry, immutable intents, projections, sagas, releases, approvals, and central audit on PostgreSQL with tested backup/failover. |
| FED-020 | Keep local UI/API/CLI, recovery, reconciliation, schedules, hosting, mail, DNS, database, backup, certificates, and security functional during a 72-hour central outage. |
| FED-021 | Expose central unavailability, projection staleness, expired assertions, waiting external work, and per-node partial rollout honestly. |
| FED-022 | Pass central compromise, forged/stale assertion, replay, grant widening, stream partition, spool pressure, key rotation, failover, revocation, and local-deny tests. |

### 22.22 Provider and integration outcomes

| ID | Required outcome |
|---|---|
| INT-001 | Define a versioned provider contract with capability discovery, normalized errors, idempotency, pagination, rate limits, health, drift, secret purpose, and conformance tests. |
| INT-002 | Configure, verify, rotate, suspend, resume, and delete provider bindings without returning reusable secrets. |
| INT-003 | Provide Cloudflare DNS/proxy and DNS-01 as a named GA adapter. |
| INT-004 | Provide AWS S3, DigitalOcean Spaces, MinIO, Wasabi S3, Backblaze B2 S3, generic S3-compatible, SFTP, and Google Drive as independently named GA backup adapters. |
| INT-005 | Provide Docker Hub as the initial named OCI registry journey and allow additional registry adapters later. |
| INT-006 | Provide LiteSpeed Enterprise licensing as a named mandatory adapter for LSE support cells. |
| INT-007 | Provide local Rspamd/ClamAV scanning and an explicitly named remote AI/malware scanning substitute before claiming CyberPanel scanner outcome parity. |
| INT-008 | Provide local SMTP and an explicitly named external outbound-delivery adapter before claiming CyberMail-equivalent relay functionality. |
| INT-009 | Provide native off-host repositories and optional self-hosted central orchestration before claiming CyberPanel-hosted backup-equivalent outcomes. |
| INT-010 | Provide Imunify integration only after real install/license/status/scan/findings/quarantine/remediation/event conformance and singular ownership tests. |
| INT-011 | Provide CloudLinux LVE/CageFS as a separately qualified conditional-baseline adapter; native isolation remains GA on core tuples. |
| INT-012 | Provide Redis as an optional managed service with consumers, version/config/health/backup policy, and lifecycle. |
| INT-013 | Provide Elasticsearch or OpenSearch only for exact advertised product/version tuples with lifecycle, capacity, security, consumers, and recovery. |
| INT-014 | Provide n8n as a certified container application recipe rather than an arbitrary Compose escape hatch. |
| INT-015 | Expose signed outbound webhooks and extension-provider callbacks with timestamp, audience, replay, retry, deduplication, and secret rotation. |
| INT-016 | Require explicit tenant consent, purpose, data class, region, retention, egress, and deletion for providers receiving tenant content. |
| INT-017 | Treat provider state as external observed state with stale/ambiguous/partial conditions and reconciliation, not as a local database assumption. |
| INT-018 | Back up provider configuration and secret references; reauthorize rather than pretend secrets are portable when policy forbids export. |
| INT-019 | Keep provider outage isolated from unrelated local functions and bound threads, sockets, memory, retries, queues, and circuit breakers. |
| INT-020 | Reject advertisement and GA certification for a mock, no-op, unreachable, vendor-billing-only, or happy-path-only adapter. |

---

## 23. Provider commitments and explicit disposition matrix

### 23.1 Provider classes

| Class | Meaning | GA rule |
|---|---|---|
| named_required | Users select this named service or it is inseparable from the required outcome | A real adapter, credentials journey, sandbox/production conformance, fault tests, backup/migration semantics, documentation, and support owner are mandatory |
| substitutable_outcome | CyberPanel used its own vendor, but the valuable outcome is provider-neutral | The selected replacement MUST be named in the release ledger and fully qualified before the record can be certified |
| conditional_baseline | The baseline outcome applies only when the operator selects/licences a platform/provider | The adapter and its applicable support cells are mandatory for parity GA; use remains optional |
| conditional_post_ga | A non-baseline commercial/OS/provider adapter is added later | It MUST remain absent from UI/support claims until its complete independent matrix passes |
| local_native | The platform itself supplies the baseline outcome | No Internet/vendor account may be required for local use |
| post_parity | Added from GridPane or later product scope | It cannot satisfy or block a CyberPanel baseline record |

The provider-class field is a closed enum. Optional deployment and self-hostability are orthogonal fields; compound or free-form class strings are invalid. `operatorOptional=yes` means an operator may omit the capability from one installation, not that parity GA may omit a working baseline adapter.

### 23.2 Provider matrix

| Capability | Class | Operator optional? | Self-hostable? | Initial commitment | Required evidence |
|---|---|---:|---:|---|---|
| OpenLiteSpeed | named_required | yes | yes | Official signed/distribution-qualified packages | Install, engine semantics, lifecycle, failure, upgrade, OLS-specific behavior on both core OS cells |
| LiteSpeed Enterprise | named_required | yes | yes | Official BYOL or written vendor-approved channel | Real license/trial/refresh/expiry/transfer plus Enterprise-only semantics on both core OS cells |
| PowerDNS | local_native | yes | yes | Qualified PowerDNS Authoritative release | Zone/RRset, primary/secondary, TSIG, DNSSEC, backup/restore, failure |
| Cloudflare | named_required | yes | no | Scoped API-token adapter | Zone/RRset/proxy/DNS-01, pagination, conflicts, rate limit, revoke, reconciliation |
| Let's Encrypt ACME | named_required | no | no | Public staging and production directories with qualified account policy | Public trust, account/TOS/EAB where applicable, HTTP-01, DNS-01, wildcard, rate/error handling, renewal, revocation, outage, chain transition |
| ZeroSSL ACME | conditional_baseline | yes | no | Separately qualified fallback adapter/account journey | EAB/account/TOS, HTTP-01/DNS-01 capability, wildcard where supported, rate/error/failover, renewal, revoke, outage, chain validation |
| MariaDB | local_native | no | yes | Pinned supported MariaDB catalog | Install/upgrade, users/grants, backup/restore, remote access, replication |
| Redis | local_native | yes | yes | Pinned managed Redis release | Lifecycle, auth, consumers, bounds, recovery |
| Search service | conditional_baseline | yes | yes | Exact Elasticsearch-compatible product/version selected in Gate 0, not a vague compatibility claim | Lifecycle, security, capacity, consumer, upgrade, backup/rebuild |
| Local mail | local_native | yes | yes | Postfix, Dovecot, Rspamd, optional ClamAV, DKIM adapter | Protocol interoperability, deliverability, filtering, SSO, backup/restore, migration |
| External delivery | substitutable_outcome | yes | yes | Selected provider MUST be named before Stage 5 certification; local SMTP remains available | Domain onboarding, credentials, events, quota/rate, outage, reconciliation, egress/privacy |
| Subscriber verification | substitutable_outcome | yes | yes | Local syntax/DNS verification plus selected optional provider named before advertisement | Consent/egress, batch, retry, rate limit, uncertain result, privacy |
| Local malware scanning | local_native | no | yes | Rspamd/ClamAV for mail plus bounded file integrity/malware engine with signed signatures | Detection corpus, quarantine, false positive, update, resource isolation |
| Remote AI/security scanner | substitutable_outcome | yes | yes | Provider-neutral interface; selected provider named before remote-scanner advertisement | Explicit content egress, bounded snapshot, provenance, timeout, no mutation authority |
| Imunify | conditional_baseline | yes | no | Real licensed/BYOL adapter | Install/license/ownership, scan/findings/quarantine/remediation/events, conflict tests |
| OWASP CRS | local_native | yes | yes | Signed/digest-pinned qualified CRS | Both engines, replay, exclusions, canary, rollback |
| Commercial WAF rules | conditional_baseline | yes | no | Selected CyberPanel-equivalent provider named/licensed before parity certification | Exact scope, signature, update, false positive, rollback, redistribution rights |
| S3-compatible backup | named_required | yes | yes | Generic SigV4 adapter | Write/list/read/delete-prefix, multipart/resume, versioning/object lock where supported, clean restore |
| AWS S3 | named_required | yes | no | Preset over qualified S3 adapter | Regions/endpoints/auth, throttling, pagination, multipart, retention scoping, restore |
| DigitalOcean Spaces | named_required | yes | no | Preset over qualified S3 adapter | Endpoint/region/auth, pagination, failure, restore |
| MinIO | named_required | yes | yes | Self-hosted S3-compatible preset | TLS/CA, path/virtual host style, object locking where supported, outage, restore |
| Wasabi S3 | named_required | yes | no | Named preset over the qualified SigV4 adapter | Endpoint/region/bucket/auth, pagination, multipart/resume, throttling, retention scoping, outage, clean restore |
| Backblaze B2 S3 | named_required | yes | no | Named preset over the qualified SigV4 adapter | Endpoint/region/bucket/key scope, pagination, multipart/resume, throttling, retention scoping, outage, clean restore |
| SFTP backup | named_required | yes | yes | Host-key-pinned SSH/SFTP adapter | Algorithms, timeout, resume, checksum/verification, permission/disk errors, clean restore |
| Google Drive backup | named_required | yes | no | OAuth adapter with app/account policy | Enrollment/refresh/revoke, pagination, resumable upload, rate limit, ambiguity, clean restore |
| Local repository | local_native | no | yes | Encrypted content-addressed repository | Capacity, crash, corruption, retention, restore; MUST NOT be marketed as off-host DR |
| Docker Hub | named_required | yes | no | Initial OCI registry adapter | Anonymous/auth search/pull, tags-to-digest, rate limit, signature/SBOM/vulnerability policy |
| WordPress catalog/artifacts | substitutable_outcome | no | yes | WordPress.org APIs/downloads or a named fully qualified mirror selected before Stage 4 certification | Core/plugin/theme search and pagination, metadata/compatibility/advisories, immutable artifact resolution, checksum/provenance, rate/outage/staleness/removal, mirror consistency |
| Other OCI registries | post_parity | yes | yes | Standards-compatible adapters added only with conformance | Auth variants, digest, pagination, rate, revoke, provenance |
| CloudLinux | conditional_baseline | yes | yes | CloudLinux 9 LVE/CageFS adapter | Separate OLS/LSE matrix; native core isolation remains independent |
| GeoIP/risk data | conditional_baseline | yes | yes | Locally licensed database or declared provider | License/update, uncertainty, privacy, no security decision solely by geography |
| Panel notification SMTP | local_native | yes | yes | Local SMTP client to operator-configured server | TLS/auth, timeout, retry, redaction, traced test |
| Signed notification webhooks | local_native | yes | yes | Generic outbound HTTPS webhook | Signing, replay, retry/dedupe, rotation, SSRF/egress policy |
| Central plane | local_native | yes | yes | Optional self-hosted reference control plane | Enrollment, local-deny, offline, HA, backup, authorization, compromise tests |

Release candidates MUST replace every “selected provider MUST be named” entry with a named adapter and immutable conformance artifact. A placeholder selection blocks certification but does not force a particular commercial vendor into the architecture. `providers.yaml` schema and CI reject unknown or compound classes and require the independent `operatorOptional` and `selfHostable` fields.

### 23.3 Securely redesigned outcomes

| Legacy outcome/mechanism | Disposition | New outcome |
|---|---|---|
| URL token or session impersonation | secure_redesign | Expiring support-context or one-use login grants preserving real actor |
| Default `admin/admin` or default password | secure_redesign | Local one-time installation claim, passkey/MFA, unique fallback credential |
| API password creates normal session and bypasses MFA/state | secure_redesign | Scoped service principals/API keys; interactive auth always enforces state and assurance |
| Web process invokes arbitrary privileged shell | secure_redesign | Closed typed executor operations with independent ID/path/unit resolution and receipts |
| Root web terminal | secure_redesign | Site-UID PTY, container exec, typed host ops, and tiny local recovery CLI |
| Root file manager/download | secure_redesign | Expiring descriptor-relative HostFilesystemSession |
| LiteSpeed WebAdmin reusable console/password | secure_redesign | Panel RBAC, typed engine resources, step-up mutation, audit, local recovery |
| Shared phpMyAdmin/root bridge | secure_redesign | One-use database workspace using least-privileged scoped principal |
| Permanent root SSH keys for backup/transfer/HA | secure_redesign | Purpose-bound transfer grants and signed encrypted artifact/channel protocol |
| Query-string/unauthenticated deploy webhook | secure_redesign | HMAC/body signature, timestamp, audience, replay and delivery dedupe |
| Cron and temp status/PID files | secure_redesign | Durable schedules, operation/step rows, leases, fencing, pidfd/start-time receipts |
| Mutable live daemon config edits | secure_redesign | Canonical desired state, immutable generation, native validator, probes, rollback lease |
| Rootful Docker socket in web process | secure_redesign | Typed broker, admin rootful tier, qualified rootless tenant tier |
| Arbitrary Compose | secure_redesign | Parse/normalize/preview and reject privilege escapes; signed certified recipes |
| Mail pipe to arbitrary command | secure_redesign | Capability-bound site-UID handler with bounded spool/cgroup/egress |
| Password-returning WordPress autologin | secure_redesign | One-use site/user/audience grant exchanged by signed MU-plugin |
| AI provider live file mutation | secure_redesign | Read-only snapshot scanning plus separate digest-bound remediation operation |
| Cloud API all-powerful bearer/router | secure_redesign | Outbound mTLS federation, local grants/RBAC, expiring signed typed intents |
| Swarm/Galera unsafe bootstrap and DNS switch | secure_redesign | Placement/replication resources, enforceable fencing, quorum, CAS routing, recovery |
| Archive SQL/scripts executed against live target | secure_redesign | Hostile extraction, isolated disposable DB, canonical manifest, ordinary target APIs |
| Theme download/global CSS/JS | secure_redesign | Signed static assets and validated design tokens with CSP |
| Source patch plugins/root lifecycle scripts | secure_redesign | Capability-scoped WASM and rootless OCI extensions |
| Bucket-wide or pre-backup retention | secure_redesign | Namespace-scoped leased retention after verified survivor/recovery point |
| Success-shaped response despite failure | secure_redesign | Accepted/observed/ambiguous/degraded/failed states and exact receipts |

### 23.4 Explicit drops and negative requirements

The following are mechanisms or non-functional artifacts, not lost user outcomes. Their absence MUST be tested.

| ID | Explicitly absent |
|---|---|
| DRP-001 | Apache runtime, proxy backend, manager, tuning, configuration, packages, switch, test cell, and migration target |
| DRP-002 | Nginx baseline engine/backend or GridPane Nginx policy compatibility |
| DRP-003 | CyberPanel routes, payloads, Django models, migrations, database schema, file paths, session cookies, token format, and CLI syntax |
| DRP-004 | CyberPanel backup/archive compatibility inside the runtime; parsing exists only in disposable migrators |
| DRP-005 | Browser root shell, root SSH console, and arbitrary privileged command execution |
| DRP-006 | Default/shared credentials and installer-selected known passwords |
| DRP-007 | All-powerful static administrator/node bearer tokens and password-authenticated automation APIs |
| DRP-008 | Generic root argv, shell, script, path, UID, unit, package, environment, or raw-config executor RPC |
| DRP-009 | Direct panel/UI access to Docker, containerd, Podman, systemd, package-manager, database-root, or daemon-control sockets |
| DRP-010 | Plain FTP or cleartext credential authentication |
| DRP-011 | Persistent reusable database-root/phpMyAdmin sign-on |
| DRP-012 | Unauthenticated/query-secret webhooks and unbounded webhook replay |
| DRP-013 | Root rsync keys, disabled SSH host verification, public cluster tokens, and peer-supplied root authorized keys |
| DRP-014 | Arbitrary Compose, privileged tenant containers, host namespaces/devices/mounts, runtime sockets, and unconfined profiles |
| DRP-015 | Live mutable managed config edits and unmanaged source includes used as privileged configuration |
| DRP-016 | In-place replacement of an existing CyberPanel installation |
| DRP-017 | Legacy parser, credential, source agent, active config dependency, listener, package, or compatibility service after migration |
| DRP-018 | Runtime execution of `.htaccess`; it is migration evidence transformed only when safely representable |
| DRP-019 | Magento advertised before a real modern certified recipe exists |
| DRP-020 | Namecheap DNS-01 claim without a real qualified adapter |
| DRP-021 | DNSSEC claimed merely because legacy schema tables existed; new DNSSEC is an explicitly qualified enhancement |
| DRP-022 | No-op WAF disable/exclusion actions, mock providers, happy-path-only providers, and success-on-exception |
| DRP-023 | Dormant/commented CSF, root-terminal, example-plugin, and unreachable installer code treated as functionality |
| DRP-024 | CyberPanel vendor billing, credits, balances, payment method, upsell, hosted VPS commerce, marketplace, and support-ticket business UI |
| DRP-025 | Mandatory CyberPanel/third-party cloud account for local hosting, authentication, recovery, scanner, backup, or mail administration |
| DRP-026 | Mutable-branch/curl-to-shell self-update and unsigned packages/rules/models/extensions/images |
| DRP-027 | Recursive global chmod/chown “repair,” wildcard log deletion, bucket-wide retention, or unverified destructive cleanup |
| DRP-028 | AI self-approval of its own exception, release signature, policy-root change, destructive data purge, or recovery-key destruction |
| DRP-029 | Claims of universal atomic cross-service change, universal rollback, universal zero-downtime migration, or zero data loss without proof |
| DRP-030 | GridPane post-parity features counted as CyberPanel parity or used to postpone a baseline obligation |

### 23.5 Disposition closure rules

1. An active baseline outcome MUST be `ga_parity` or `secure_redesign` before parity GA.
2. `post_ga` is legal only for non-baseline additions; it cannot classify an active CyberPanel outcome.
3. `drop` is legal only for a duplicate implementation path, bug, unsafe mechanism whose legitimate outcome is preserved, inactive/dead surface, compatibility artifact, or explicitly excluded product-business surface.
4. Every active UI action, local/cloud API branch, CLI command, scheduled job, installer option, model-backed lifecycle, template control, provider journey, and documented function MUST map to one or more Section 22 IDs or a signed non-product evidence classification.
5. Every Section 22 ID MUST map back to immutable source evidence or be labelled `security_enhancement`/`operational_correctness` with rationale.
6. No unresolved or unclassified source evidence is permitted at parity GA.

---

## 24. Threat model, security claims, and trust boundaries

### 24.1 Protected assets

- instance ownership, identities, sessions, MFA/recovery, API credentials, policy, approvals, and authorization epochs;
- provider, database, backup, DNS, mail, TLS, extension, federation, and signing secrets;
- tenant isolation, hosted code/data, databases, mail, DNS, certificates, backups, and application state;
- desired state, observed state, quota ledger, operation journal, executor registry/receipts, and audit evidence;
- engine, PHP, firewall, SSH, WAF, container, package, mail, DNS, database, and service configuration;
- recovery points, migration artifacts, quarantine evidence, release artifacts, provenance, SBOMs, and trust metadata;
- availability of local control, hosted sites, mail, DNS, databases, backups, restoration, and anti-lockout recovery.

### 24.2 Adversaries and failures

The design assumes attacks from:

- unauthenticated Internet clients;
- malicious or compromised tenants, site users, resellers, support operators, and service principals;
- compromised WordPress plugins/themes, uploads, Git repositories, hooks, application code, archives, mail, SQL evidence, images, and containers;
- stolen sessions, API keys, SSH keys, mailbox credentials, provider credentials, and recovery material;
- compromised central, identity, DNS, storage, scanner, rules, registry, mail-delivery, notification, or extension providers;
- dependency, build, package, image, ruleset, model, update, or signing supply-chain compromise;
- prompt injection and poisoned code/issues/logs/fixtures/evidence aimed at AI maintainers;
- accidental operator error, duplicate requests, unsafe automation, stale workers, partial effects, and ambiguous timeouts;
- resource exhaustion, disk/inode pressure, slow clients/providers, queue floods, archive bombs, fork bombs, and cardinality attacks;
- crash, reboot, power loss, clock changes, network partition, DNS caching, eventual consistency, and provider outage.

### 24.3 Trust boundaries

~~~mermaid
flowchart LR
    IN["Untrusted Internet"] --> GW["Unprivileged panel-gateway<br/>no authority stores/helper sockets"]
    GW --> CORE["Local-only panel-core<br/>identity + authorization + state writer"]
    CORE --> CW["Single control.db write coordinator"]
    CW --> EX["Root panel-execd"]
    CW --> ST["Root site-taskd"]
    CW --> CB["Container broker(s)"]
    CW --> PS["Provider supervisor<br/>protected effect journal"]
    PS --> PW["Unprivileged provider-worker"]
    SB["Secret-broker<br/>protected key + audience journal"] --> PW
    SB --> ST
    SB --> EX
    AV["Auth-verifier<br/>protected TOTP/recovery + assurance signer"] --> CORE
    AV --> AB
    AB["Approval-broker<br/>protected signer + transaction display"] --> EX
    AW["Audit-writer<br/>prepared segments + checkpoint signer"] --> CORE
    TAC["Separately trusted approval/enrollment client"] -->|"E2E plan/enrollment confirmation"| AB
    TAC --> AV
    ST --> SITE["Hostile site UID workloads"]
    CB --> CONT["Hostile container workloads"]
    EX --> HOST["Kernel + services + managed configuration"]
    PW --> PROV["Untrusted external providers"]
    FED["Optional central plane"] -->|"outbound mTLS, signed intents"| FDR["Unprivileged federatord"]
    FDR --> CORE
    SRC["Untrusted migration source/archive"] --> QUAR["Quarantine + disposable parsers"]
    QUAR --> IMP["Source-neutral importer"]
    IMP --> CORE
    BUILD["Untrusted candidate source + AI output"] --> GATES["Deterministic build/test/policy gates"]
    GATES --> SIGN["Human-controlled release trust root"]
~~~

Boundary rules:

- Internet input is parsed, size/deadline/rate bounded, authorized, and converted to typed commands before durable acceptance.
- panel-gateway compromise exposes credentials/sessions and gateway-attested transport metadata and can act as captured principals, but cannot directly write authority state; independent transaction confirmation still protects qualifying high-risk commits. panel-core compromise means total control-state/RBAC/application-audit and typed cross-tenant product authority, but cannot express generic root primitives, bulk-decrypt secrets, or forge separate approval by itself.
- panel-execd, site-taskd, rollback-watchdog, rootful/tenant container brokers, secret-broker, auth-verifier, provider supervisor/worker, approval-broker, and audit-writer are separate boundaries. Each peer-validates local callers, owns the minimum registry/journal/key material for its decision, and fails closed when that protected state or evidence is unavailable.
- A compromised secret-broker can expose every secret decryptable by key material it can access; audience binding constrains honest execution, not malicious broker code. A compromised auth-verifier can disclose every TOTP seed under its encryption domain, consume recovery state, and forge assurance accepted under its key. A compromised approval-broker can sign any executor-registered pending plan for which its key is trusted, irrespective of its software policy. A compromised provider supervisor can authorize or falsify provider actions/receipts within grants, adapters, destination bindings, and keys independently enforced outside it. A compromised audit-writer can omit/reorder future audit and misuse its checkpoint key but cannot rewrite already externally replicated checkpoints; this becomes a critical integrity discontinuity and blocks non-safety mutations. Separate key domains/processes, external checkpoints, and HSM-enforced policy where qualified narrow these sets; prose policy alone does not. Compromise of panel-execd, site-taskd before credential/capability drop, rollback-watchdog, a rootful container-broker, an ExternalPrivilegedController, or an unavoidable vendor root supervisor is host compromise. Separation narrows reachable input and authority in the non-compromised case; it does not reduce those components' post-compromise privilege. Their keys/journals/processes are isolated from panel-core and from one another, rotated/recoverable, and included explicitly in the threat/incident model.
- provider-worker has network authority but no desired-state or root authority; panel-core cannot send secrets/provider traffic directly.
- tenant code/data is always hostile, even when created by an administrator or AI.
- Shared data-plane daemons are explicit subsystem-wide trust boundaries: compromise of OLS/LSE can affect routing, TLS, cache/WAF behavior, and many LSAPI sockets; compromise of shared MariaDB, Postfix/Dovecot/Rspamd, PowerDNS, or Redis can affect every tenant they serve. Site UID/cgroup isolation protects against hostile tenant workloads, not a compromised shared daemon. Exact daemon privilege, worker/master split, socket/database grants, MAC/systemd confinement, blast radius, recovery, and optional dedicated-instance profile are qualified per component.
- provider state and callbacks are untrusted observations until authenticated, correlated, and reconciled.
- central identity/intent is an input to local policy, never local root authority.
- migration signatures prove source/tool identity and transit integrity, not truth of a compromised source.
- AI output and its tests are candidate artifacts, not approval or release evidence by themselves.

### 24.4 Security assumptions and non-goals

The qualified host kernel, boot chain, root account, systemd, filesystem, and mandatory-access-control policy are trusted for normal operation. A root, kernel, hypervisor, firmware, physical, or malicious package-maintainer compromise can extract secrets, alter binaries, falsify observations, suppress local audit, or destroy data. TPM/HSM-backed protection MAY reduce exposure on certified hardware but is not a universal prevention claim.

External providers can be unavailable, delayed, malicious, inconsistent, rate-limited, or eventually consistent. The product verifies what it can and reports uncertainty otherwise. It does not guarantee availability against upstream/network/provider-wide destruction, volumetric denial of service beyond certified capacity, or loss of every independent recovery copy/key.

The executor boundary prevents arbitrary root mechanisms and cross-registry scope; it does not make a compromised authorization/control plane benign. The release process and independent approval roots protect stable distribution; they cannot prove absence of every defect. Security claims apply only to exact qualified support tuples and feature/provider versions.

### 24.5 Formal security invariants

| ID | Invariant |
|---|---|
| INV-001 | No remotely reachable panel control/management/API process runs as root. Unavoidable qualified vendor daemon supervisors may start as root only to bind/transition privileges; remote parsing runs in unprivileged workers where the daemon supports it, administrative consoles are disabled/private, and systemd/MAC/capability confinement is verified per daemon. |
| INV-002 | No tenant- or caller-controlled string becomes a privileged shell command, executable, UID, path, unit, package, environment, or raw configuration effect. |
| INV-003 | No site workload can access control sockets/storage, signing keys, another tenant, or privileged host paths through a supported operation. |
| INV-004 | Every product-controlled privileged mutation has a closed handler, typed input, target registry generation, current grant/commit authorization, effect ID, fence, deadline, and audit identity. A declared ExternalPrivilegedController is a narrow audited exception with exclusive action classes and threat/gate evidence; its autonomous effects are never mislabelled executor-mediated. |
| INV-005 | Authorization is local, deny-by-default, cross-surface consistent, and rechecked before a high-risk or irreversible commit. |
| INV-006 | Entitlements limit consumption and never grant authority. |
| INV-007 | Central management is optional and subordinate to local policy, revocation, support, quota, and recovery. |
| INV-008 | External failure, ambiguity, partial application, stale observation, and unsupported capability cannot be represented as success. |
| INV-009 | SQLite authority is local; cross-database, host, service, provider, and DNS effects are durable sagas, not fictitious transactions. |
| INV-010 | Status derives from observer evidence with generation/time/proof level, never from the requesting client. |
| INV-011 | Product-managed secrets do not enter URLs, argv, product-emitted logs, normal specs, notifications, crash reports, or routine support bundles. |
| INV-012 | Tenant/daemon logs are treated as potentially secret-bearing hostile content with least access, bounded retention, export warnings, and leak detection. |
| INV-013 | Local audit is append-only and tamper-evident at the application level; it is not marketed as immutable against root. |
| INV-014 | OLS and licensed LSE are separately rendered, validated, activated, observed, rolled back, and certified. |
| INV-015 | Apache and Nginx baseline configuration/runtime/compatibility paths are rejected. |
| INV-016 | One firewall manager owns host policy; anti-lockout changes retain a reboot-persistent confirmed recovery path. |
| INV-017 | WAF exceptions are minimal, attributable, expiring, evidence-backed, and exactly expressible by the active adapter. |
| INV-018 | AI or scanner classification alone cannot irreversibly delete tenant data or authorize its own exception. |
| INV-019 | Automatic repair changes only product-owned managed state and preserves an exact diff, proof, and recovery contract. |
| INV-020 | A backup is not called recoverable until required manifest/object proof and policy-required restore evidence exist. |
| INV-021 | Migration/failover exposes measured RPO, source/target watermarks, writer authority, retained recovery point, and irreversible frontier. |
| INV-022 | Unsupported support tuples and adapter fields block mutation rather than silently degrade. |
| INV-023 | Irreversible deletion, key destruction, schema contraction, and post-soak source purge are delayed separate operations. |
| INV-024 | One tenant's expensive work cannot monopolize admission, workers, provider connections, I/O, storage reserve, or safety recovery. |
| INV-025 | AI/CI/online services do not hold the threshold root or recovery trust keys or approve their own release/security exception. |
| INV-026 | Rootful container runtime authority is never presented as tenant isolation; tenant containers use a separately qualified constrained tier. |
| INV-027 | Every file/archive operation is descriptor-relative and race-safe under the qualified kernel/filesystem semantics. |
| INV-028 | A stale worker, intent, grant, authority epoch, desired generation, PID identity, or provider callback cannot commit a newer effect. |
| INV-029 | No operation deletes its only verified recovery artifact before an independent successor or retention policy proves safety. |
| INV-030 | Secret, audit, recovery, and release trust boundaries remain locally recoverable without a mandatory central account. |

### 24.6 Verification levels

Readiness claims carry one of these levels:

| Level | Meaning |
|---|---|
| structural | schemas/configuration/ownership/policy validate without exercising the data path |
| local_end_to_end | the node exercised the complete local listener/service path |
| client_confirmed | an authenticated client confirmed use through the newly configured endpoint |
| independent_external | a separately located qualified probe observed the public behavior |

Desired state commits when accepted. `Ready` is withheld until the resource's policy-required level passes. A standalone host never claims denial/acceptance from every possible external network. Panel/SSH listener changes require at least client-confirmed reachability through the new path plus a persistent rollback lease; independent probes strengthen but do not replace local ownership.

### 24.7 Security test families

Every applicable feature MUST pass:

- authentication, MFA, recovery, session fixation/revocation, CSRF, origin, and enumeration tests;
- permission, delegation, cross-tenant reference, confused-deputy, stale-grant, replay, and surface-parity matrices;
- shell/argv/environment/template/config/header/SQL/mail/path injection tests;
- symlink/hard-link/magic-link/mount/rename/openat2 and archive traversal/bomb/device/xattr tests;
- UDS peer impersonation, protocol downgrade, unknown field, oversized frame, timeout, crash receipt, fence, and replay tests;
- container namespace/mount/device/capability/socket/metadata/rebinding/resource escape tests;
- file/database/mail/backup/provider streaming and memory/disk/descriptor exhaustion tests;
- webhook/provider signature, timestamp, replay, pagination, rate-limit, revoked credential, partial write, delayed callback, and ambiguity tests;
- update provenance/signature/freeze/rollback/downgrade/dependency-confusion and extension-capability tests;
- firewall/SSH self-lockout, WAF bypass/exclusion, cache interaction, scanner/quarantine, and incident-evidence tests;
- crash, reboot, power loss, disk full, inode full, clock skew, provider outage, network partition, and cancellation at every durable frontier.

---

## 25. Support matrix and Feasibility Gate 0

### 25.1 Exact support policy

A support tuple is exact:

~~~text
OS release/package baseline × architecture × kernel/cgroup/filesystem/quota mode
× mandatory security policy × engine edition/exact vendor version
× install or upgrade path × PHP/database catalog revision × firewall manager
× container mode where enabled × CloudLinux mode where enabled
~~~

“Linux,” “EL-compatible,” “latest LiteSpeed,” and “should work” are not support states. Each release manifest pins exact package/artifact versions and digests. A newer point release remains read-only/unsupported for mutation until automated qualification succeeds. Every unavailable function names the missing predicate, observed evidence, safe remediation, and support timestamp; adapters do not weaken requests silently.

### 25.2 First parity-GA matrix

| OS / architecture / policy | OpenLiteSpeed | LiteSpeed Enterprise |
|---|---|---|
| Ubuntu 24.04 LTS x86_64; systemd; cgroup v2; AppArmor enabled; local ext4/XFS; nftables | Core GA cell | Core GA cell, licensed |
| AlmaLinux 9 x86_64; systemd; cgroup v2; SELinux enforcing; local XFS/ext4; firewalld with nftables backend | Core GA cell | Core GA cell, licensed |
| CloudLinux 9 x86_64; SELinux/systemd/cgroup and qualified LVE/CageFS/filesystem profile | Conditional-baseline parity cell | Conditional-baseline parity cell, licensed |

All six cells are release-blocking for the full-parity release. A passing OLS cell cannot substitute for LSE, and one OS cannot substitute for another. CloudLinux use remains optional for operators, but feature availability is not optional for parity. Native cgroup/quota isolation remains required on core non-CloudLinux hosts. VM platforms such as bare metal, KVM, VMware, Hyper-V, and major-cloud full VMs are supported only after representative runs of the same tuple suite. First-GA unsupported targets include Rocky/Debian/EL10/Ubuntu 26.04, ARM64, cgroup v1, panel-inside-container, OpenVZ/Virtuozzo containers, and network-root/NFS authority storage.

### 25.3 Component policy

- Only security-supported LSPHP lines present in the signed release catalog are installable. EOL PHP is a migration blocker or explicit application-upgrade project, never a silent substitution.
- MariaDB is the baseline SQL service; every catalog revision is separately qualified for install, grants, import/export, backup/restore, migration, and upgrade.
- Redis is optional but managed and consumer-aware. Search support names an exact Elasticsearch/OpenSearch product and version.
- OLS/LSE use separate renderer, capability, validator, activator, observer, licensing, and evidence paths.
- Full mail and local malware scanning require a higher minimum host profile than web-only service selection.
- Rootful Docker is administrator-only. Tenant container claims require the measured constrained backend.
- Absence of project quota disables hard disk/inode entitlement claims and blocks plans that require them.
- SELinux permissive/disabled on AlmaLinux or unexpectedly disabled AppArmor on Ubuntu is an unsupported degraded security posture until repaired.
- FTPS satisfies the FTP-account outcome; SFTP is preferred; plaintext FTP is absent.
- Browser qualification covers the two current stable releases of Chromium, Firefox, and Safari and includes WCAG 2.2 AA keyboard/screen-reader checks.

### 25.4 Gate 0 rules

Gate 0 invalidates unsafe, unavailable, or commercially impossible assumptions before production architecture freezes. It runs only on disposable CI VMs using exact candidate tuples. It MUST NOT run on a developer workstation or production server.

Each result includes immutable inputs, image/package/license/artifact digests, logs, measurements, produced evidence, pass/fail decision, and independent reviewer identity. The author cannot approve the result. Every item blocks: failure changes architecture, provider, scope/support claim, or tuple; it is never converted to a warning.

| ID | Kill test | Passing evidence | Mandatory correction on failure |
|---|---|---|---|
| F0-LSE-01 | LSE can legally and reliably be installed/operated | Vendor terms and BYOL/approved flow; licensed install, activation/refresh, status/logs, graceful lifecycle, recovery, WAF, HTTP/3, LSCache, LSAPI, enterprise-only behavior on Ubuntu and Alma | Obtain vendor-supported channel or customer-supplied certified installation; no LSE parity claim until it passes |
| F0-OLS-01 | OLS is independently supported | Clean install, native render/validation, activation/rollback, TLS, H3, WAF, LSAPI, rewrite, cache, listener, multi-vhost on both OSes | Split/narrow adapter and reject unsupported capabilities |
| F0-ENG-02 | Canonical configuration covers real sites | Representative CyberPanel behavior corpus plus differential redirects/rewrites/request+response headers/environment/network access/HTTP abuse/auth/static/PHP/status/TLS/cache/WAF; LSAPI/CGI/external apps run only as registry-owned sandboxed services and proxy contexts reach only brokered endpoints; malformed/unrepresentable inputs block | Expand canonical AST/migration diagnostics; never add Apache/raw privileged fallback or direct engine-spawned tenant executable |
| F0-EXEC-01 | Privilege boundary is genuinely narrow | Compromised panel-gateway has no authority-store/helper access; unprivileged panel-core cannot mutate host without typed grant or decrypt/bulk-export secrets; executor/site-taskd/secret-broker/auth-verifier/approval-broker/provider supervisor+worker reject unknown/replay/wrong peer/stale fence/path races/hostile env/oversized output/tenant executable/caller-chosen consumer or destination; targeted compromise tests verify the explicit broker key/secret/assurance/approval/provider blast radii and external enforcement limits; crash receipts survive reboot | Split handlers/key domains/components further; generic execution and ambient secret/provider authority remain prohibited |
| F0-STORE-01 | SQLite and protected-store handoffs fit qualified scale | control.db, execd.db, taskd.db, secrets.db, authn.db, approvals.db, provider-effects.db, both container stores, watchdog.db, and audit prepared/finalized segment+checkpoint state each prove one-writer ownership, WAL/FULL/fsync semantics, online backup/integrity/corruption recovery, N/N-1 schema, cross-journal digest/nonce/event prepare-reference-finalize handoff, tombstone/replay/revocation; 100k resources, 10k schedules, 25 accepted mutations/s; p99 authority commit ≤100 ms; kill/reboot/corrupt/backup/restore every boundary with no duplicate effect, lost revocation, or unreconstructible audit body; corruption blocks only affected new effects while prevalidated safety recovery and emergency audit lane remain | Partition high-volume data, reduce certified envelope, change handoff, or replace only the justified store; no untested helper journal |
| F0-HOST-01 | Host primitives work on real VMs | openat2, pidfd, cgroup v2, transient scopes, project quotas, nftables/firewalld, SELinux/AppArmor, atomic replace, directory fsync, reboot rollback, privileged-daemon log/socket path race tests, and sandboxed LSAPI/CGI/external-app lifecycle | Remove tuple or implement separately reviewed safe primitive; no path-string or direct engine-spawn fallback |
| F0-LIMIT-01 | Limits enforce and remain observable without shared-service bypass claims | Per-path noisy-neighbor and restart/escape tests for site-process, web vhost/static/TLS/WAF/cache, database principal/shared MariaDB, mail/domain/filter, DNS, container, disk/inode, LSAPI, and network scopes; every dimension reports enforced/accounted-only/unsupported and control/other tenant reserve holds | Reject unsupported hard dimension/plan or qualify an actual governor/separate instance/proxy; do not fake aggregate or network enforcement |
| F0-PHP-01 | LSPHP supply is sustainable | At least two upstream-supported signed lines, common extension catalog, isolated pools, install/remove/update/recovery, OPcache, both engines | Reduce catalog; no EOL or arbitrary root PECL build |
| F0-MAIL-01 | Mail stack and SSO interoperate | SMTP receive/submission, IMAP, LMTP, quotas, routes, DKIM/SPF/DMARC, TLS, filter/malware, Sieve/autoresponder, backup/restore, Dovecot short-lived OAuth/OAUTHBEARER, major clients | Split/replace components; no superficial inbox substituted for protocol depth |
| F0-CONT-01 | Tenant containers are honestly isolated | Rootless lifecycle/network/volume/secret/log/health/limits/proxy/reboot plus hostile images; no socket/privilege/host namespace/device/mount/control access | Keep rootful admin-only in scoped pre-GA releases and select a different tenant backend; full-parity GA remains blocked until the constrained tenant tier passes |
| F0-CL-01 | CloudLinux parity is implementable without controller conflict | CloudLinux 9 licensed VM, CageFS lifecycle, LVE limit mapping/observation, filesystem/quota, site lifecycle, backup/migration, OLS and LSE, native-controller ownership rules | Adjust mapping or supported CloudLinux tuple; parity remains blocked until active baseline outcomes pass |
| F0-WAF-01 | WAF/rule lifecycle works on both engines | CRS plus one commercial-equivalent provider where advertised, update, shadow/replay, exact exclusion, canary, rollback, false-positive evidence | Reject provider/capability without exact scope or rollback |
| F0-BACKUP-01 | Backup is actually restorable | Encrypted files/DB/mail/DNS/TLS/config/metadata capture; interruption/resume; corruption/wrong key; clean-host full restore; scheduled drill | Change format/provider or narrow claim; write-only destination unsupported |
| F0-MIG-01 | Disposable migration preserves real workloads | Hostile cPanel archive, CyberPanel backup, cold/live CyberPanel; manifest/chunk/provenance, isolated DB, Apache evidence translation, blockers, repeat idempotency, no runtime residue | Expand adapters/diagnostics; never execute archive SQL/scripts in production |
| F0-UPDATE-01 | Signed update and recovery are credible | Offline/repository update, expiry/wrong signature, interruption/disk full/reboot every step, N/N-1, expand/contract, app rollback, rescue, previous release | Narrow update scope; separate OS/kernel/DB/package recovery |
| F0-OBS-01 | Failures are diagnosable without product-secret leakage | Correlated operation/audit/service/engine/security evidence, bounded logs, redaction, cardinality, support bundle, disk-full, clock, checkpoint verification | Redesign schemas/retention; product-secret leakage blocks release |
| F0-SCALE-01 | Reference capacity and fairness hold | All Section 26 latency/resource/fairness budgets under realistic reconciliation, backup, scan, mail, WAF, container, and provider contention | Reduce certified capacity or change architecture before broad delivery |

Gate 0 exits only when every row passes, the four core and two CloudLinux conditional-baseline cells are proven, the support policy is frozen, resulting architecture decisions are recorded, and no unresolved commercial dependency can invalidate LSE, WAF, mail, scanner, provider, or update delivery.

---

## 26. Performance, capacity, fairness, and reliability budgets

These budgets qualify the control product, not arbitrary tenant application speed. Evidence reports p50/p95/p99, error rate, queue lag, resource cost, and interference; a median-only benchmark is invalid.

### 26.1 Reference profiles

| Profile | Hardware | Qualified use |
|---|---|---|
| P-small | 2 vCPU, 4 GiB RAM, local SSD, 1 Gbit/s | Web/DNS control profile without local malware scanning, search, tenant containers, or material mail load |
| P-full | 4 vCPU, 8 GiB RAM, local NVMe/SSD, 1 Gbit/s | Full baseline with light mail and scheduled scanning |
| P-scale | 8 vCPU, 32 GiB RAM, local NVMe, 10 Gbit/s | Control-scale, mixed-workload, fairness, migration, backup, and contention qualification |

The installer computes service-specific memory, disk, inode, port, file-descriptor, rollback, and backup reserves and rejects an impossible topology instead of enabling a guaranteed OOM/swap/disk failure.

### 26.2 Core budgets

| Metric | Qualification budget |
|---|---|
| Mandatory first-party idle RSS | panel-gateway, panel-core, panel-execd, site-taskd, secret-broker, auth-verifier, approval-broker, audit-writer, provider supervisor, rollback-watchdog, and protected-store caches combined ≤384 MiB on P-full, excluding vendor data-plane services, tenant workloads, and OS page cache |
| Optional enabled idle RSS | federatord ≤64 MiB; each enabled container-broker tier ≤64 MiB; any long-running optional provider/helper receives a separately declared ≤32 MiB budget rather than disappearing from the total |
| Core idle CPU | all mandatory always-on first-party processes combined ≤1% of one CPU averaged over 15 minutes; optional enabled-idle budgets are reported separately |
| Authority envelope | 100,000 canonical resources and 10,000 active schedules per node |
| Sessions | 1,000 authenticated sessions and at least 200 active request streams on P-scale |
| Authority commit | p95 ≤50 ms and p99 ≤100 ms at 25 accepted mutations/s on P-scale |
| Cached API reads | p95 ≤150 ms and p99 ≤300 ms at 200 requests/s, excluding external-provider latency |
| Mutation acceptance | p95 ≤150 ms and p99 ≤250 ms through parse, validation, authorization, quota reservation, durable enqueue, audit, and outbox |
| Login | p95 ≤600 ms including deliberately expensive password verification under the qualified concurrency/rate policy |
| Lightweight schedule lag | p95 ≤1 second; safety/rollback priority is higher than backup/scan/build |
| Restart recovery | Read API available within 15 seconds; durable reconciliation starts within 30 seconds; no false-complete operation |
| Full observation sweep | 100,000-resource sweep within 5 minutes under configured CPU/I/O share |
| Engine configuration | 5,000-vhost generation validates and activates within 30 seconds, excluding vendor license outage and external proof |
| UI | Cached shell first content ≤1 second and p75 LCP ≤2.5 seconds on qualification network; no mandatory two-second polling storm |
| Audit ingestion | Dedicated audit store sustained 500/s and burst 2,000/s without losing authority-bearing audit events; benchmark reports encoded bytes/event, fsync latency, storage/day, compression, checkpoint and archive throughput |
| Diagnostic events | Sustained 1,000/s with bounded spool and explicit drop/coalesce counters only for nonessential classes |
| Metrics cardinality | Default ≤20,000 active series/node; bounded label vocabulary; reject/aggregate excess |
| Effect recovery | Transport/worker delivery is at least once with one durable terminal record per effect ID. At-most-once external effect is required only where the local receipt/fence protocol or provider idempotency key proves it; otherwise recovery reports `Ambiguous`, observes/reconciles, and never blindly retries |
| Data-plane isolation | Existing web, DNS, database, mail, and established container data paths continue during panel-core outage |

### 26.3 Storage and retention budgets

- control.db contains only authority, authorization, quota, desired/observed metadata, operations, minimal audit/outbox and is qualified below a 20 GiB ceiling.
- Canonical audit events live in preallocated append-only hash-chain segments, not control.db. The reference envelope reserves at least 50 GiB or 90 measured days online (whichever is larger for the certified workload) plus an independently configured signed archive/replication target; exact bytes/day and archive RPO are release evidence. High watermark blocks new non-safety mutations before audit loss, preserves verification/export/recovery access, and never silently truncates an unarchived segment.
- execd.db contains only registry generations/tombstones and privileged effect/rollback receipts. taskd.db, secrets.db, authn.db, approvals.db, provider-effects.db, container broker stores, and watchdog.db each stay within a declared per-store and combined 5 GiB metadata budget under the certified envelope; secret ciphertext volume is separately measured and quota/retention bounded.
- Gate/load accounting includes write amplification, WAL/page cache, backup bandwidth, integrity-check time, lock contention, and cross-journal handoffs for every protected store, not only control.db.
- Metrics use a bounded local TSDB; logs use structured rotated segments/journald; artifacts use checksummed object storage. None are authority blobs.
- Default operational metrics retention is 30 days, verbose service logs 14 days, security events 90 days, and audit policy-defined. Holds override eligible deletion.
- At disk high watermark, stop optional scans/exports and new space-expanding work, compact eligible telemetry, preserve audit and rollback reserves, and alert. Never delete tenant data, recovery points, mail, or wildcard log classes automatically.
- Upgrade/migration admission reserves at least the greater of 10 GiB or 15% of affected managed data, replaced by a higher measured dry-run requirement when applicable.
- Backup admission measures source, staging, database/mail amplification, chunk/repository need, retained prior generation, inode demand, and safety margin; stale quota metadata is not capacity proof.

### 26.4 Query and UI rules

- Every collection is cursor-paginated with stable ordering and bounded maximum page size.
- Dashboard aggregation reads cached metrics/materialized views; it MUST NOT spawn `top`, `du`, package tools, service tools, or full-table counts per browser poll.
- Site/user/mail/container lists MUST NOT materialize every row or issue per-row queries. Query-count budgets are asserted in tests.
- Webmail search returns bounded server-side result pages and fetches only requested message identities/parts.
- File, attachment, log, export, import, image, backup, and container streams use constant bounded memory, cancellation, backpressure, and deadlines.
- No download creates a long-lived timer/thread per object. Cleanup is durable scheduled state.
- Slow clients cannot pin unbounded buffers, workers, database connections, file descriptors, or external provider streams.
- Structured logs use cursors/tail/time filters and never read an unbounded runtime log into one response.

### 26.5 Heavy-work admission estimates

Before admission, each heavy operation provides an estimate and uncertainty for:

~~~yaml
WorkEstimate:
  cpuMillis: range
  memoryBytesPeak: range
  readBytes: range
  writeBytes: range
  temporaryBytes: range
  inodes: range
  networkBytes: range
  fileDescriptors: integer
  providerRequests: map
  locks: [resourceRef]
  expectedDuration: range
  cancellationLatency: duration
  confidence: measured | modeled | unknown
~~~

Unknown high-impact estimates block or require explicit low-concurrency admission. Backups, restores, migrations, database imports/exports, scans, builds, image pulls, archive work, WAF replay, and mail campaigns run in separate cgroups and queues.

### 26.6 Fairness and backpressure

- Separate host, tenant, subsystem, provider, and resource concurrency pools prevent one tenant or provider from consuming all workers/connections.
- Security rollback, listener recovery, service restoration, identity, and certificate-renewal safety outrank backup, scan, migration, build, campaign, and image work.
- Engine reloads are coalesced by desired generation but never merge incompatible approvals or hide failed resources.
- Provider clients have connect/read/write/overall deadlines, bounded pools, rate-limit feedback, exponential jitter, circuit breakers, and idempotency reconciliation.
- Queue saturation returns a durable accepted state or explicit retryable rejection; it never drops work silently.
- Mail campaign queues are isolated from transactional/submission/receiving paths.
- Backup and retention hold scoped leases; neither can run duplicate traversals or concurrent repository initialization for the same resource generation.
- Reconciliation adapts frequency to health/change and cannot become a busy loop under permanent error.

### 26.7 Subsystem capacity contracts

| Subsystem | Required bound/evidence |
|---|---|
| Sites/engine | 5,000 vhosts qualification; render/reload coalescing; no per-site fork for dashboard observation |
| Identity/tenancy | 100,000 principals/memberships/resources with indexed scoped search and no unpaginated 3N query behavior |
| Mail | Protocol throughput profile stated per hardware; queue, IMAP search, MIME/attachment, mailbox stats, and campaign isolation bounded separately |
| DNS | 100,000 RRsets with indexed zone navigation, transfer, DNSSEC, provider pagination, and bounded reconciliation |
| Files | Streaming constant-memory transfer; archive entry/bytes/depth/time limits; asynchronous recursive operations with checkpoints |
| Databases | Scoped pool/concurrency, result row/byte/deadline limits, streaming import/export, dump/restore I/O admission |
| Backups | No duplicate full transfer; verified destination receipt; measured RPO and restore throughput; retention never competes with active point |
| Containers | Log/export streams bounded; image pulls deduped by digest; per-tenant resource/network/image concurrency |
| Scanning | Snapshot/manifest bounded; archive recursion and content egress controlled; scheduled scans claim work transactionally |
| Federation | Bounded prioritized spool, projection deltas/cursor repair, coalesced telemetry, expired intent rejection, no unbounded reconnect replay |

### 26.8 Central-plane reference envelope

The optional central reference deployment has an independently certified C-scale envelope rather than inheriting node budgets:

| Metric | Initial qualification budget |
|---|---|
| Connected nodes | 5,000 steady outbound streams across at least three service instances |
| Reconnect storm | 1,000 nodes/minute with randomized backoff; revocations and terminal receipts delivered before telemetry catch-up |
| Intent/receipt rate | 500 accepted or terminal intent envelopes/s sustained with per-peer/tenant/risk pools |
| Projection/event rate | 10,000 bounded envelopes/s and 100 MiB/s aggregate ingest without starving control messages |
| Interactive relay | 500 concurrent sessions, per-session byte/rate/time caps, aggregate admission and slow-consumer eviction |
| Snapshot/catch-up | Per-node snapshot and catch-up byte/item ceilings, resumable cursors, no whole-fleet synchronized replay |
| Central API | p95 ≤300 ms for cached inventory/query and ≤500 ms for durable intent acceptance at C-scale |
| Postgres/outbox | p99 committed-event publication lag ≤2 seconds; critical revocation/receipt path prioritized and alarmed |
| HA | Committed Postgres RPO 0 under the qualified synchronous failure model and control-service failover RTO ≤60 seconds |

Each peer and tenant has independent stream, queue, database-work, snapshot, relay, and byte/request admission. A compromised/noisy node cannot consume another node's revocation/intent/receipt capacity. Revocations, epoch changes, terminal receipts, and security events outrank projections and telemetry; coalescing applies only to nonessential observation. Qualification includes asymmetric reconnects, corrupt/oversized frames, one noisy peer, slow consumers, Postgres/outbox lag, leader failover, and regional/network partition.

### 26.9 Reliability objectives

Initial SLOs for a certified P-full/P-scale node, excluding declared maintenance and upstream provider failure:

| Indicator | Objective |
|---|---|
| Local control API availability | 99.95% monthly |
| Operation acceptance durability | No accepted operation lost in qualified crash/power tests |
| Authority integrity | Zero unexplained corruption, duplicate committed effect, or cross-tenant effect |
| Essential audit/receipt retention | Zero silent loss; admission blocks before exhaustion |
| Reconciler convergence | 99% of healthy low-risk desired changes observed ready within 2 minutes, excluding declared external waits |
| Certificate renewal | 99.9% of eligible locally controlled certificates renewed before policy escalation threshold |
| Backup policy | 99% of scheduled occurrences start within declared lag and report a truthful terminal state; recoverability measured separately |
| Recovery proof | Every protected workload class/repository/support tuple has a current policy-compliant drill |

SLO breach never authorizes data deletion, security disablement, or silent downgrade. It produces a condition, incident, and capacity/remediation plan.

---

## 27. AI engineering factory, code architecture, supply chain, and releases

AI-generated work is untrusted supply-chain input. AI can perform nearly all routine engineering and maintenance, but deterministic evidence, independent review, and human-controlled threshold trust roots—not model confidence—authorize a stable release or irreversible production action.

### 27.1 Why Go and a modular monolith

Go is the default because it provides:

- small static binaries and predictable deployment/recovery;
- strong typing, explicit errors, race tooling, fuzzing, profiles, and mature HTTP/2/RPC libraries;
- good system interfaces without defaulting to shell;
- low idle overhead relative to a per-host service mesh;
- a language/toolchain that AI agents can refactor and verify consistently;
- straightforward generated Protobuf/OpenAPI clients and a strict package dependency graph.

Rust remains appropriate for a future parser or primitive only if Gate 0 demonstrates a concrete memory-safety/performance need that cannot be met by process isolation, Go bounds, and fuzzing. A mixed-language privileged core at the start would increase build, review, FFI, packaging, and AI-maintenance complexity without evidence.

The node is a modular monolith: bounded Go packages, one minimal public panel-gateway process, one local authority/domain panel-core process, and separately reviewable privilege/isolation helpers. It avoids a business-domain microservice mesh and cross-service distributed transactions while separating hostile network parsing from the only control-state writer. Package and OS-process boundaries are enforced by architecture tests.

### 27.2 Repository shape

~~~text
/api                 public OpenAPI, Connect, protobuf, generated clients
/cmd                 panel-gateway, panel-core/paneld, panelctl, panel-execd,
                     site-taskd, site-worker, secret-broker, auth-verifier,
                     approval-broker, provider-worker/supervisor, container-broker,
                     rollback-watchdog, federatord, migctl, extractors
/internal/identity   auth, sessions, tenancy, RBAC, plans, quota
/internal/hosting    sites, bindings, engines, PHP, deployments
/internal/dns        zones, DNS providers, DNSSEC
/internal/tls        ACME, certificate generations/deployments
/internal/database   MariaDB resources, workspace, tuning, replication
/internal/access     files, FTPS/SFTP/SSH, terminal, cron, Git
/internal/backup     manifests, repositories, retention, restore, DR
/internal/mail       server, webmail API, delivery, marketing
/internal/apps       catalog, WordPress, staging, scanning
/internal/container  workloads, images, broker contracts, isolation
/internal/security   firewall, SSH posture, WAF, findings, incidents, repair
/internal/ops        operation engine, schedules, reconciliation, notifications
/internal/federation enrollment, intents, projections, HA orchestration contracts
/internal/migration  source-neutral manifest, planning, import, cutover
/internal/platform   storage, secrets, audit, events, capabilities, support tuples
/renderers           OLS, LSE, PHP, DNS, mail, firewall, SSH, WAF native adapters
/providers           separately versioned provider adapters and conformance fixtures
/web                 Vue 3 strict-TypeScript application and generated client
/ledger              parity, permissions, resources, providers, support, evidence
/tests               contracts, property, fuzz, fault, VM, migration, security corpora
/docs                generated reference plus reviewed architecture/runbooks
~~~

Domain packages cannot import host executor implementations. Host helpers cannot import HTTP/session/UI/provider code. Provider adapters cannot write control.db. The UI has no privileged server-rendered action path. Generated dependency policy rejects cycles and forbidden edges.

### 27.3 Factory flow

~~~mermaid
flowchart LR
    E["CyberPanel evidence / issue / advisory"] --> L["Parity or defect ledger record"]
    L --> C["Contract + threat cases + ADR"]
    C --> P["Implementation plan"]
    P --> W["Isolated AI worktree"]
    W --> T["Independent test derivation"]
    T --> S["Static, policy, unit, fuzz, property gates"]
    S --> I["Disposable integration environments"]
    I --> V["Exact VM OS × engine matrix"]
    V --> A["Adversarial + fault + migration review"]
    A --> B["Hermetic reproducible build + SBOM/provenance"]
    B --> R["Signed candidate"]
    R --> K["Canary + soak + halt policy"]
    K --> H["Human threshold stable promotion"]
~~~

Every change starts from ledger IDs and identifies resources, permissions, trust boundaries, data lifecycle, support cells, failure/rollback frontier, telemetry, migration, backup, documentation, and tests. Generated code without this trace is rejected.

### 27.4 Separation of duties

| Role | May do | Must not do |
|---|---|---|
| Product/spec agent | Extract source outcomes, draft contracts and acceptance | Declare its ambiguous/omitted requirement complete |
| Architecture/threat agent | Define boundaries, invariants, abuse cases, ADRs | Approve its own invariant exception |
| Implementation agent | Modify code/tests in an isolated worktree | Hold production, provider, signing, or break-glass credentials |
| Independent test agent | Derive tests from contract and source evidence | Use implementation internals as the sole oracle |
| Adversarial agent | Review data flow, diff, privileges, parsers, failure | Waive its own finding |
| Build service | Produce hermetic artifact, SBOM, provenance | Hold offline root/recovery keys |
| Release evaluator | Verify immutable evidence and policy | Modify the evaluated candidate |
| Human release authority | Approve trust-root, exception, stable promotion, irreversible policy | Bypass absent deterministic evidence without an explicit scope/design change |
| Rollout controller | Deploy one signed approved artifact within bounded policy | Build, sign, widen policy, or generate arbitrary live code |

Two agents using the same model improve review throughput but do not create an independent security boundary. High-risk code requires independently derived tests, deterministic tools, and an authorized reviewer; different model families and conventional human review SHOULD add diversity.

### 27.5 AI context and knowledge system

The repository maintains machine-readable, versioned knowledge:

- resource and command schemas;
- permission and risk catalog;
- parity ledger and source-evidence digests;
- provider capability/conformance manifests;
- support-tuple manifest;
- architecture dependency graph;
- ADRs and invariant registry;
- state-machine definitions;
- operation/executor handler registry;
- migration mappings and fixture provenance;
- threat cases and failure contracts;
- generated API/CLI/UI/docs indexes;
- runbook and diagnostic recipe catalog;
- test/evidence artifact graph.

AI agents retrieve the smallest relevant slice and cite immutable IDs/digests. Generated knowledge is checked against source/schema and cannot silently overwrite reviewed truth. Stale links, undocumented handlers, orphan permissions, missing tests, and source evidence without a ledger mapping fail CI.

### 27.6 Prompt-injection and tool isolation

- Repository text, issues, PR comments, tenant files, code, archives, SQL, mail, logs, provider responses, SBOMs, dependency metadata, scanner findings, and web content are untrusted data, never authority-bearing instructions.
- Agents receive a declared task capability manifest and least-privilege short-lived credentials.
- Builds, parsers, migrations, fuzzers, malware, container images, package installation, engine testing, and VM tests run only in ephemeral restricted CI environments.
- Runners start from signed images, inherit no developer/production credentials, restrict egress, and are destroyed after evidence upload.
- No AI-generated shell string reaches a root executor, production host, or release signer.
- Secrets are redacted and scanned before prompts, logs, artifacts, support bundles, or external model calls leave a boundary.
- Production diagnostics supplied to AI are minimized, purpose-bound, region/retention governed, and tenant-content-free by default.
- Model output that references a nonexistent test, file, result, source, or approval fails evidence validation.

### 27.7 Mandatory engineering gates

1. formatting, compilation/type checking, linting, generated-code freshness, schema/API compatibility, and architecture import rules;
2. dependency, license, secret, malware, binary/provenance, and generated-artifact checks;
3. SAST plus custom rules for raw process/shell use, unsafe path APIs, unbounded parsers, secret logging, missing authz, direct host mutation, SQL privilege, container escape, and network SSRF;
4. unit, table, property, fuzz, race, concurrency, invariant, and model-based state-machine tests;
5. parser corpora for archives, DNS, MIME/mail, engine configuration, rewrites, migration SQL evidence, provider payloads, and signed metadata;
6. contract tests proving UI/API/CLI/central/scheduler/extension authorization equivalence;
7. real VM install/upgrade/reboot/recovery/uninstall on each exact support tuple;
8. licensed LSE and OLS semantic/differential suites independently;
9. crash, kill, power-loss, disk/inode full, clock, provider outage, partition, cancellation, and retry at durable boundaries;
10. tenant isolation, replay, cross-reference, quota-race, stale-worker, listener lockout, and secret disclosure suites;
11. clean-room backup restore and all three source migration fixture families;
12. reproducible build, SBOM, provenance, signature, TUF metadata, and release-manifest validation.

An AI-authored test cannot be the only evidence for the behavior it validates. Critical path behavior needs an independent oracle: protocol conformance, differential fixture, reference implementation, model property, external probe, or reviewer-derived test.

### 27.8 Source and dependency supply chain

- Go modules, npm packages, generated tools, engine/service packages, rules, signatures, models, images, recipes, and build images are version-pinned and digest-locked.
- Builds become networkless after approved dependency acquisition. Dependencies are mirrored, scanned, licensed, and provenance-checked before use.
- Privileged Go binaries avoid CGO unless an audited necessity is recorded.
- Frontend lockfiles/toolchain are pinned; assets are content-addressed; CSP is strict and SRI used where applicable.
- Every first-party artifact includes SPDX/CycloneDX SBOM, vulnerability/VEX, license report, test evidence, and SLSA-style provenance linking source, builder, and invocation. First-party privileged binaries and release metadata MUST be reproducible; unexplained differences block signing.
- Third-party closed/vendor artifacts such as LiteSpeed Enterprise or distro packages are not falsely claimed reproducible or project-SLSA-authored. They require an immutable authorized vendor channel/URL, vendor signature plus pinned digest, acquisition receipt/time, exact component inventory and product-generated SBOM where upstream SBOM/VEX is unavailable, license/redistribution terms, vulnerability disposition, sandbox/conformance evidence, and an explicit provenance-gap risk record. A changed or unverifiable vendor artifact blocks that tuple.
- OCI images are digest-pinned, signed, SBOM-attached, and policy-scanned; tags are display aliases.
- WAF rules, extensions, migration extractors, provider adapters, signature/model databases, and offline bundles follow the same trust policy.

### 27.9 Release trust and packaging

Use a TUF-style hierarchy:

- offline threshold root keys establish and rotate trust;
- bounded targets keys sign named channel/tuple artifacts;
- snapshot/timestamp metadata prevent rollback, freeze, and mix-and-match;
- recovery keys are independently held and rehearsed;
- online signing is hardware-backed or short-lived, scope-limited, monitored, and revocable;
- build, signing, policy-root, and rollout identities are separate.

APT/RPM repositories are normal transport; a signed offline bundle provides equivalent verification. Product releases install in immutable versioned directories; state, secrets, managed configuration, logs, artifacts, and tenant data live outside them. A stable systemd unit selects one release atomically under a reboot-persistent watchdog. N and N-1 binaries/protocols understand the expanded schema through the rollback window; destructive contraction is a later release after verified recovery.

Every release manifest includes hashes, version/channel, provenance, support tuples, engine/package/license constraints, protocol/schema range, disk reserve, preflight, rollback frontier, known limits, required acknowledgements, and the signed evidence dossier.

### 27.10 Update state machine

~~~mermaid
stateDiagram-v2
    [*] --> Discovered
    Discovered --> MetadataVerified
    MetadataVerified --> Downloaded
    Downloaded --> ArtifactVerified
    ArtifactVerified --> Preflighted
    Preflighted --> Staged
    Staged --> SchemaExpanded
    SchemaExpanded --> CanaryRunning
    CanaryRunning --> Switched
    Switched --> HealthVerifying
    HealthVerifying --> Committed
    CanaryRunning --> RolledBack: failed
    Switched --> RolledBack: compatible recovery
    HealthVerifying --> RecoveryRequired: forward-only frontier
    RecoveryRequired --> ManualInterventionRequired
~~~

Expired/unavailable update metadata prevents accepting a new update but never stops the installed verified release. Product code, OLS/LSE, PHP, MariaDB, mail/DNS, WAF rules, container engine, OS package, kernel, provider adapter, and extension updates are separate operations with separate risk and recovery claims. Universal package/kernel/database downgrade is never promised.

### 27.11 Autonomous maintenance envelope

AI MAY autonomously:

- triage redacted telemetry and correlate known failures;
- draft issues, specifications, patches, tests, migrations, documentation, and release candidates;
- run approved CI/VM/fuzz/fault matrices;
- propose diagnostic and repair plans;
- roll a signed pre-approved candidate through bounded canary waves with automatic halt/rollback before an irreversible frontier;
- perform low-risk reversible product-owned reconciliation already authorized by local policy.

AI MUST NOT autonomously:

- sign stable releases or alter root/recovery trust;
- waive failed parity/security/support/restore gates;
- change policy roots, permissions, provider data-egress terms, or support claims;
- deploy unsigned/generated code directly to production;
- cross a post-write migration/failover frontier, purge recovery/source data, destroy keys, or delete tenant data irreversibly;
- disable firewall/WAF/MFA/audit/backup protections to improve a metric;
- approve its own exception or hide an ambiguous outcome.

Emergency status may shorten rollout timing and increase human availability; it does not remove signature, provenance, compatibility, recovery, and evidence requirements.

---

## 28. Machine-executable parity and evidence ledger

The ledger is a versioned, machine-validated release input under `/ledger`, not a narrative checklist or editable percentage. One record represents one independently testable user/operational outcome. A screen containing ten actions creates at least ten records. Scheduled, failure, migration, backup, authorization, and provider semantics are first-class.

### 28.1 Record schema

~~~yaml
ParityRecord:
  schemaVersion: integer
  familyId: stableString           # required Section 22 parent family; never directly certifiable
  atomicChildId: stableString      # required globally unique independently certifiable obligation
  title: string
  domain: enum
  criticality: blocking | high | normal
  origins: [cyberpanel, secure_redesign, operational_correctness, gridpane_post_parity]
  cyberpanelObligation: derivedBool # true when any reachable pinned CyberPanel origin maps here
  gaObligation: derivedBool         # true for every Section 22 child and required secure-redesign dependency unless an enumerated post-GA rule says otherwise
  remoteRequired: derivedBool       # active cloudAPI or ordinary canonical command policy requires central request/projection/receipt coverage
  remoteException: none | bootstrap_physical_presence | local_recovery | trust_root_ceremony | nondelegable_secret_disclosure | provider_reauthorization
  classification: baseline_outcome | security_enhancement | operational_correctness | gridpane_post_parity
  baselineRevision: digest
  sourceEvidence: [EvidenceRef]     # at least one unless non-CyberPanel rationale exists
  rationale: optionalString
  personas: [owner, admin, reseller, customer, service, support, auditor, central]
  scope: instance | tenant | project | site | application | mailbox | provider
  outcome:
    preconditions: [string]
    action: string
    postconditions: [string]
    visibleEffects: [string]
    forbiddenEffects: [string]
  sourceSemantics:
    inputs: [FieldContract]
    outputs: [FieldContract]
    lifecycle: [StateTransition]
    dependencies: [RequirementId]
    editions: openlitespeed | litespeed_enterprise | both | not_applicable
    failureModes: [FailureContract]
  targetContract:
    resources: [ResourceKind]
    apiOperations: [OperationId]
    uiJourneys: [JourneyId]
    cliOperations: [CommandId]
    executorHandlers: [HandlerId]
    permissions: [PermissionId]
    risk: low | medium | high | critical
    quotaDimensions: [QuotaDimension]
    auditEvents: [EventType]
    conditions: [ConditionType]
    verificationLevel: structural | local_end_to_end | client_confirmed | independent_external
    frontier: reversible | delayed_irreversible | irreversible
    rollbackContract: ContractRef
  redesign:
    disposition: exact_outcome | securely_equivalent | remove_nonfunctional_artifact
    differences: [string]
    invariants: [InvariantId]
    threatCases: [ThreatCaseId]
  dataLifecycle:
    backupScope: full | metadata_only | excluded_with_reason
    restoreTests: [TestId]
    migrationMappings: [MappingId]
    deletionContract: ContractRef
  support:
    requiredTupleClasses: [TupleClass]
    capabilityPredicates: [PredicateId]
    providers: [ProviderConformanceId]
    unsupportedBehavior: block | read_only
  acceptance:
    scenarios: [TestId]
    negative: [TestId]
    fault: [TestId]
    performance: [TestId]
    accessibility: [TestId]
    evidenceArtifacts: [ArtifactDigest]
  trace:
    specification: [DocumentRef]
    implementation: [CodeRef]
    documentation: [DocumentRef]
    runbooks: [DocumentRef]
    telemetry: [SchemaRef]
  state: discovered | specified | planned | implemented | qualified | certified | excluded
  certification:
    release: version
    tupleResults: [TupleResult]
    reviewers: [IdentityRef]        # at least two, author excluded where required
    signedEvidence: [ArtifactDigest]
~~~

`EvidenceRef` includes source revision, path, symbol/route/template action/model/CLI/installer/schedule/documentation/observed behavior, line/symbol locator, content digest, reachability class, and notes. Content digests prevent evidence drifting under a record.

### 28.2 Separate registries

The parity graph references generated registries:

| Registry | Required content |
|---|---|
| resources.yaml | resource kinds, schema versions, scope, owner, controller, status writer, backup/migration/deletion behavior |
| commands.yaml | operation IDs, input/output, risk, idempotency, authorization checkpoints, locks, effects, cancellation, frontier |
| permissions.yaml | stable verb, resource kind, scope/inheritance, delegability, assurance, approval, forbidden combinations |
| handlers.yaml | privileged handler, closed input schema, registry lookup, binary/config allowlist, observation, receipt, compensation |
| providers.yaml | adapter/version, capabilities, secret purposes, errors, idempotency, rate, conformance, support cells |
| support.yaml | exact OS/engine/component tuples, status, predicates, evidence, release compatibility |
| events.yaml | audit, security, operation, notification, provider, metric/log schemas and redaction |
| mappings.yaml | source-specific migration evidence to canonical resource/field/transform/blocker |
| tests.yaml | test ID, oracle, environment, fixtures, requirements, threats, support cells, evidence output |
| docs.yaml | journey/reference/runbook ID, target personas, tested procedure, release freshness |

Every code-visible resource, API/CLI action, executor handler, permission, scheduled job, provider, migration mapping, and UI mutation includes one or more parity IDs. Orphans fail CI.

### 28.3 Evidence harvesting and closure

For the pinned CyberPanel baseline, static harvesters inventory:

- URL/view/controller dispatch including cloudAPI;
- template buttons/forms/links and JavaScript API calls;
- local API and CLI dispatch;
- models and lifecycle mutations;
- installer/upgrade flags and service branches;
- schedulers/cron/background workers;
- provider clients and named integrations;
- active documentation/product claims;
- daemon managers and operational entry points.

The harvester output is immutable evidence, not a feature list by itself. Review maps each item to Section 22/parity child records or signs an inactive/non-product classification with reachability proof. Dynamic crawling/behavior capture in disposable fixtures supplements static evidence. Any newly discovered active evidence fails CI until classified.

Harvesting generates mandatory atomic child obligations for each independent verb, lifecycle transition, variant, provider, engine-dependent behavior, scheduler occurrence, and active source surface. Broad Section 22 IDs are parent capability families only; they cannot be certified directly. A many-to-one evidence mapping is legal only when it enumerates a finite child set and every child is independently qualified. Parent state is the worst child state.

`cyberpanelObligation` is derived and immutable: if any reachable evidence origin comes from the pinned CyberPanel baseline, every mapped child is a CyberPanel obligation regardless of an author's `classification`. Authors may add `security_enhancement` or `operational_correctness` rationale but cannot downgrade the derived obligation. Inactive evidence requires signed reachability proof rather than relabeling.

Harvesting is recursive and transitive. A router/controller/dispatcher, downloaded executable or interactive menu, provider-embedded surface, extension/plugin contribution, generated command table, or wrapper is only an edge, not one certifiable action. The harvester must resolve every reachable branch/subcommand/action into digest-pinned atomic evidence. A mutable/unpinned remote artifact or unavailable transitive surface is blocking until captured at an approved immutable digest and behavior fixture; mapping only the wrapper is invalid.

`gaObligation` is independently derived. Every Section 22 atomic child and every security/correctness dependency required to deliver it defaults to true, including a child with no CyberPanel source origin. `cyberpanelObligation=true` unconditionally implies `gaObligation=true`; no classification or approval can override that implication except a separately proven `remove_nonfunctional_artifact`, which is not a missing outcome. Only a closed enumerated `gridpane_post_parity` or `conditional_post_ga` disposition with signed product approval may be false when there is no reachable CyberPanel obligation. `cyberpanelObligation` remains provenance/reporting data and cannot be used to bypass greenfield security obligations.

`remoteRequired` is also generated rather than authored. It is true for active CyberPanel cloudAPI evidence and for every ordinary canonical command/resource policy designated remotely requestable by FED-007. A closed `remoteException` is allowed only for installation bootstrap/physical-presence recovery, trust-root/key ceremony, local break-glass recovery, non-delegable secret disclosure, or provider reauthorization requiring the provider's own user interaction. Ordinary high risk remains remotely requestable and pauses for node-local step-up/CommitAuthorization; risk is not an excuse to omit the surface.

### 28.4 Allowed redesign dispositions

- `exact_outcome`: externally meaningful outcome semantics remain the same, independent of route/schema/UI.
- `securely_equivalent`: the legitimate outcome remains, unsafe/obsolete mechanism changes, differences and proof are explicit.
- `remove_nonfunctional_artifact`: only a defect, duplicate path, inactive code, compatibility form, Apache mechanism, unsafe default, or vendor-business surface is absent.

“Deferred,” “mostly done,” “manual workaround,” “generic executor covers it,” “provider interface exists,” and “covered elsewhere” are not parity-GA dispositions. `remove_nonfunctional_artifact` cannot remove an active user outcome and requires product/security approval.

### 28.5 State gates

| State | Minimum proof |
|---|---|
| discovered | immutable evidence/rationale and unique ID |
| specified | complete outcome, contract, permission, risk, failure, data/support/redesign fields |
| planned | approved implementation/test/migration/docs/telemetry plan and dependency readiness |
| implemented | code references, generated surfaces, unit/property/fuzz tests, no declared completion |
| qualified | semantic, negative, fault, security, performance, backup/migration, provider, and applicable tuple tests pass |
| certified | all required cells and journeys pass; independent reviewers and signed release evidence exist |
| excluded | only valid non-functional artifact with signed evidence/approval and negative test |

The aggregate state of a feature family is the worst applicable child state. A percentage cannot hide a blocking record.

### 28.6 CI validation rules

CI rejects the ledger when any rule fails:

1. Every record is schema-valid, uniquely identified, digest-bound, and has immutable evidence or an approved non-baseline rationale.
2. Every harvested active route/action/API/CLI/model lifecycle/installer option/schedule/provider/documented function maps to at least one record.
3. Every source evidence item maps to a record/classification and every baseline record maps to source evidence.
4. Every target API/UI/CLI command, privileged handler, resource kind, permission, scheduler, provider, and migration mapping maps to records.
5. `implemented` requires code and tests; `qualified` requires applicable scenarios; `certified` requires every support cell/provider and signed evidence.
6. High-risk records require authz/replay/cross-tenant/fault/rollback/audit/secret tests and independent review.
7. Engine-relevant records pass separately on OLS and real licensed LSE; no substitution.
8. Backupable resources have capture plus restore evidence; migratable resources have fixture/provenance/reconciliation evidence.
9. Secure redesign includes source-target differences and a test proving the original legitimate outcome remains.
10. Unsupported capability is deterministic/visible and never a success-shaped downgrade.
11. Referenced code/tests/docs/handlers/schemas/artifacts exist and are not stale relative to digests.
12. New source evidence or target surface fails CI until classified and traced.
13. Removed target code fails CI if it leaves a certified record without implementation.
14. A CyberPanel baseline record cannot depend on a GridPane post-parity record.
15. No baseline record may remain `post_ga`, `planned`, `implemented`, or merely `qualified` at parity GA.
16. GA coverage is exactly certified `gaObligation` atomic children divided by all valid `gaObligation` atomic children = 1.0; exclusions count only when non-functional-artifact approval is valid.
17. Every Section 22 family expands into atomic verb/variant/provider/surface children; parent certification without complete children is invalid.
18. Any reachable CyberPanel EvidenceRef forces `cyberpanelObligation=true`; manual baseline relabeling cannot remove it from closure.
19. Every active CyberPanel UI journey has a certified local UI child unless an approved secure-redesign record explains and tests the replacement; API/CLI-only implementation is insufficient.
20. Every command with derived `remoteRequired=true` has positive central intent, projection, receipt, denial, replay, and outage tests; N/A requires one closed independently approved `remoteException`, never a free-form risk reason.
21. `familyId`, `atomicChildId`, evidence origins, `cyberpanelObligation`, `gaObligation`, `remoteRequired`, and remote-exception validity are generated/recomputed; a supplied value that disagrees fails CI, and parent families cannot hold a certification state.
22. Harvesting recursively expands dispatchers, downloaded/embedded executables, menus, provider/plugin contributions, and generated tables at pinned digests; unresolved or mutable transitive behavior blocks closure.
23. Provider classes use only the Section 23.1 enum and separate optional/self-hostable fields; unknown or compound classes fail schema validation.
24. A reachable CyberPanel origin paired with `post_parity`, `conditional_post_ga`, or `gaObligation=false` fails CI unless the separately valid non-functional-artifact proof removes no legitimate outcome.

### 28.7 Surface and fault matrix

Each record renders this matrix; `N/A` requires a reason:

| Dimension | Cells |
|---|---|
| Surface | local UI, local API, CLI, scheduler, extension, central projection, central intent |
| Actor | owner, admin, reseller, customer, support, service principal, central actor |
| Engine | OLS, licensed LSE, engine-neutral |
| OS | Ubuntu 24.04, AlmaLinux 9, optional qualified tuples |
| Lifecycle | create, inspect, change, suspend, resume, delete/quarantine/purge, reconcile |
| Failure | validation, permission, quota, conflict, cancel, timeout, crash, reboot, disk/inode full, provider outage, partial effect, rollback failure |
| Data | backup, restore, migration, transfer, deletion, secret rotation, retention |
| Quality | semantic, negative, security, performance, accessibility, localization, documentation/runbook |

Generated dashboards show gaps by domain, persona, engine, OS, surface, risk, provider, migration, backup, stage, and failure contract. They are read-only projections of ledger truth.

### 28.8 Completion query

Parity GA is mechanically blocked unless this logical query returns zero rows:

~~~sql
SELECT atomic_child_id
FROM parity_records
WHERE ga_obligation = TRUE
  AND (
    state <> 'certified'
    OR has_unclassified_evidence
    OR missing_required_tuple
    OR missing_surface
    OR missing_required_central_surface
    OR missing_permission_or_audit
    OR missing_restore_or_migration_proof
    OR stale_artifact_digest
  );
~~~

This is conceptual SQL over generated ledger data; SQLite runtime schema is not prescribed by this example.

---

## 29. Delivery sequence and stage gates

Every stage produces an installable, observable, recoverable vertical slice. A model, page, handler, renderer, or API alone is not a feature. Completion includes authorization, quota, durable operation, idempotency, reconciliation, audit, metrics, failure behavior, recovery/irreversibility, backup/migration semantics, docs, and automated evidence.

No release before Stage 10 may be marketed as CyberPanel parity. It may be called foundation, preview, beta, or a scoped hosting release with an explicit certified-capability list.

### 29.1 Dependency spine

~~~mermaid
flowchart LR
    F0["Gate 0 + exact host support"] --> CORE["Identity + local authority + secrets + audit"]
    CORE --> OPS["Durable operations + executor + site launcher + reconciliation"]
    OPS --> ENG["OLS + licensed LSE adapters"]
    ENG --> SITE["Site + PHP + routing + quotas"]
    SITE --> DATA["DNS + TLS + MariaDB + files/access"]
    DATA --> DR["Verified backup + restore"]
    DR --> SEC["Firewall + SSH + WAF + scanner + observability"]
    DATA --> MAIL["Mail server + webmail + campaigns + delivery"]
    DATA --> APPS["Apps + WordPress + Git + staging"]
    SEC --> CONT["Containers + conditional-baseline CloudLinux"]
    MAIL --> PARITY["Remaining providers + extensions + HA outcomes"]
    APPS --> PARITY
    CONT --> PARITY
    PARITY --> MIG["Disposable migrators + cutover rehearsals"]
    MIG --> FED["Optional central plane + fleet/HA qualification"]
    FED --> GA["100% parity certification"]
~~~

Backup/restore appears early because every later destructive operation depends on it. Federation is implemented after local authority is stable; multi-node outcomes use it but never make local operation dependent on it.

### 29.2 Stages

| Stage | Scope | Blocking exit gate |
|---|---|---|
| 0 — Feasibility | All Section 25 kill tests; commercial/legal constraints; ADRs; exact support envelope | Every Gate 0 row green; four core plus two CloudLinux feasibility cells proven; no unresolved LSE/WAF/mail/container/update assumption |
| 1 — Recoverable platform | Signed installer; claim/bootstrap; identity/RBAC/MFA/recovery; tenants/resellers/plans/quota; paneld; write coordinator; executor/site-taskd grants/receipts; secrets; audit; operation engine; service diagnostics; updater/rescue | Clean install/reinstall on four core cells; crash/reboot/N-1 recovery; no remotely reachable root control-plane or generic handler; authz/replay/quota tests; external-effect fault injection |
| 2 — Complete hosting vertical slice | OLS/LSE; UID/site/domain/alias/child lifecycle; listeners; LSPHP; MariaDB/users/grants/workspace; files; cron; PowerDNS; TLS; quotas; native backup/restore; basic firewall exposure | Same create→modify→suspend→backup→restore→delete journey on four cells; engine rollback; quota and hostile path/archive proof; clean restore |
| 3 — Host operations and security | Firewall/SSH; WAF/CRS/provider rules; malware/scanner/Imunify adapter; process/service/log/metrics; packages; Redis/search; limits; notifications; support bundles | Anti-lockout, WAF replay/exclusion/rollback, quarantine/release, PID-safe actions, disk-full/package failure, resource starvation, secret-clean bundle |
| 4 — Applications and developer workflows | Signed app catalog; WordPress/Joomla/PrestaShop/Mautic/Magento when certified; Git/deployments; webhooks; staging/clone; LSCache; app scanning/remediation | Representative WP/non-WP lifecycle/recovery on both engines/OSes; webhook idempotency; no repo/log secrets; staged promotion/rollback |
| 5 — Mail, webmail, delivery, and campaigns | Postfix/Dovecot/Rspamd/ClamAV/DKIM; domains/mailboxes/routes/Sieve/quarantine/queue; SSO webmail; contacts/groups; FTPS/SFTP/SSH; delivery provider; marketing consent/suppression/bounce | Major-client and protocol tests; no open relay; DNS auth; quota; mail restore/migration; MIME/XSS; unsubscribe/suppression invariant; delivery provider conformance |
| 6 — Containers and enhanced isolation | Admin rootful Docker; tenant rootless tier; images/registries/volumes/networks/secrets/logs/exec; Docker sites/recipes; cgroups/quota; conditional-baseline CloudLinux | Hostile-image suite; no tenant socket/host escape; reboot/recreate/export/import/backup; provenance; native limits; both CloudLinux engine cells pass |
| 7 — Extensions and remaining providers | WASM/OCI extension lifecycle; all Section 23 GA adapters; themes/locales; diagnostics/repair and provider ownership | Capability denial/revocation/crash/exhaustion; provider outage/replay/restore; no extension privileged bypass; no placeholder adapter |
| 8 — Migration | CyberPanel live, CyberPanel backup, cPanel archive; manifests/dry run/capacity/conflicts; baseline and deltas; rewrite translation; cutover/reconciliation/cleanup | Fixture corpus and clean-room rehearsals; pre-write rollback; explicit post-write frontier; no executable legacy/Apache residue; idempotent retries; no silent loss |
| 9 — Optional central and multi-node | Enrollment/identity assertions; inventory/projections; remote intents; fleet updates; event spool; file/terminal relay; placements/replication/fencing/failover | 72-hour central outage; local deny/revoke; assertion expiry; no direct executor route; fencing and partition tests; central backup/failover |
| 10 — Parity and GA | Entire executable ledger, support/provider matrices, production soak, independent security review, release ceremony and operator docs | Every Section 31 gate passes on one immutable candidate; no baseline obligation merely implemented/qualified |

### 29.3 Vertical-slice definition of done

For each outcome:

1. stable resource/command/permission/event schemas exist;
2. UI, public API, CLI, scheduler and central applicability are explicit;
3. authorization, assurance, delegation, quota, and risk rules are enforced server-side;
4. accepted work is durable, idempotent, cancel/reconcile aware, and fenced;
5. executor/provider effects are typed, bounded, observable, and have receipts;
6. success, partial, ambiguity, failure, degraded, unsupported, and recovery states are honest;
7. backup/restore, migration, deletion, secrets, retention, and ownership are defined;
8. metrics/logs/audit/notifications and runbook troubleshooting exist;
9. semantic, negative, fault, security, performance, accessibility, and applicable tuple/provider tests pass;
10. the ledger is at least `qualified`; only the release dossier can make it `certified`.

### 29.4 Delivery controls

- Build feature slices behind generated capability discovery, not ad hoc flags.
- Do not create UI before command/resource/permission/failure contracts are reviewable.
- Do not implement all models first; prove the Stage 2 complete site slice on all four cells early.
- Keep LSE in every engine-relevant iteration; postponing it creates a second product and invalidates parity estimates.
- Split mail server, webmail, and campaigns into dedicated teams/agents with shared contracts and independent qualification.
- Treat rootful and tenant containers as separate threat models/products.
- Introduce providers only with conformance fixtures, deadlines, pagination, ambiguity, and recovery.
- Freeze new baseline scope only after evidence closure; security/correctness requirements may still block.
- Stop and redesign when a Gate 0 assumption or invariant fails; do not accumulate compatibility debt.

### 29.5 Milestone artifacts

Every stage publishes:

- signed parity-ledger snapshot and change report;
- supported tuple/provider/capability manifest;
- architecture and threat ADR delta;
- test/fault/security/performance evidence index;
- SBOM/provenance/license/vulnerability reports;
- install/upgrade/recovery artifacts;
- operator/user/API/CLI documentation and tested runbooks;
- known limits, blockers, and irreversibility statements;
- restore/migration evidence appropriate to completed resources.

---

## 30. GridPane depth corpus and post-parity roadmap

CyberPanel alone defines baseline availability. The adjacent `/Users/aon/GitHub/server-scripts` corpus is inspected only after a CyberPanel outcome is identified. Its static repository guide reports approximately 162,000 Bash lines across 116 shell files, 83 function-bearing files, roughly 142,000 library lines, and 1,897 tracked functions. It also describes generated function, dispatch, wrapper, configuration-key, callback, web-server, notification, and global-state maps. Those artifacts are a valuable example of operational knowledge extraction, not target runtime code.

No GridPane script is executed or imported to build this design. Its Nginx/Apache scope, command syntax, file layout, callbacks, and mutable shell architecture are not inherited.

### 30.1 Implementation-depth lessons to adopt

| Lesson | Greenfield realization |
|---|---|
| A feature is an end-to-end workflow, not a button | Every parity record includes preflight, lock/fence, snapshot, diff, effect, semantic probe, recovery, receipt, logs, repair, docs |
| Dependencies must be explicit | Generated capability/dependency graph with versions, conflicts, consumers, lifecycle, support predicates |
| Dynamic command dispatch hides blast radius | Closed generated command/handler registries and compile-time/CI traceability; no string dispatch |
| State reads/writes need provenance | Canonical resources, status writer, effect receipt, provider revision, audit, drift, configuration ownership |
| Deferred work is not inline success | Durable schedules/occurrences/operations with idempotency, cancellation, reconciliation, and deadlines |
| Web-engine branches need a matrix | Exact OLS/LSE capability manifests and separate evidence cells, not scattered conditionals |
| Site changes need application depth | Ownership, runtime/cache, DB, DNS/TLS, cron/webhook, backup, staging, health, traffic activation |
| Host changes need managed ownership | Product-owned immutable generations; observe/conflict with unmanaged state rather than overwrite it |
| Diagnostics and repair are different | Read-only DiagnosticRun followed by exact RepairPlan and separately authorized mutation |
| Operational failures need first-class paths | Missing package, stale lock, disk full, invalid config, provider outage, reboot, already-modified host are tests/states |
| Fleet recipes need resumability | Central plans freeze targets and waves; nodes authorize/execute locally; exact receipts drive progress |
| Knowledge artifacts must stay fresh | Generated registries with source hashes, schema versions, staleness validators, orphan/coverage checks |
| Documentation must trace implementation | Docs reference stable command/resource IDs and are built/validated from registries, not copied line numbers |

### 30.2 Mechanics explicitly not adopted

- monolithic sourced Bash libraries and ambient global variables;
- arbitrary root `gp`/wrapper dispatch or string-composed/deferred commands;
- direct in-place configuration mutation and cross-feature shell side effects;
- `expect` automation containing provider secrets;
- reusable phpMyAdmin sign-on bridges;
- mutable Git checkout/self-update on production hosts;
- overlapping timers/cron and “run on every site” loops without claims/fences;
- central shell callback endpoints as the resource/state API;
- recursive ownership/permission repair over broad trees;
- blind database dump rewrite or replacement;
- Monit/process-text existence as functional health truth;
- Nginx, Apache, or scattered OS/web-server conditionals;
- opaque catch-all fix/repair commands without plan, proof, and recovery.

### 30.3 Post-parity work packages

These use `baseline: gridpane_post_parity` and begin only after Stage 10:

1. **Corpus normalization.** Map the 1,897-function dependency/command/side-effect graph to existing canonical capabilities, implementation-depth improvements, and genuinely new outcomes.
2. **Advanced WordPress operations.** Fleet canaries, visual regression, richer search-replace, maintenance recipes, integrity baselines, compromised-site containment, Object Cache Pro integration, and deeper plugin policy.
3. **Additional data services.** PostgreSQL, Memcached, Supervisord-managed application processes, and exact database/service provider matrices.
4. **Additional backup/storage providers.** Dropbox, remote mounts, recovery analytics, and expanded immutable-destination policy. Backblaze B2 S3 and Wasabi S3 are already CyberPanel-parity GA commitments.
5. **Performance policy packs.** Application profiling, deeper LSAPI tuning, object/page cache strategy, CDN/cache purge adapters, and evidence-based recommendations.
6. **Security policy packs.** GridPane 7G as a signed optional WAF pack, richer incident bundles, credential rotation recipes, and fleet posture reporting.
7. **Fleet automation.** Locally authorized typed runbooks with selectors, canaries, pause/abort, maintenance, and per-node recovery.
8. **Provider/notification depth.** Additional DNS/CDN/storage/mail/security vendors, Slack notifications, and region/residency policies.
9. **Migration forensics.** More source panels/archive versions, application-specific transforms, behavior corpus generation, and data-consistency tooling.
10. **Operational intelligence.** Dependency-aware diagnostics, capacity forecasting, anomaly correlation, and AI-drafted bounded repair plans.

No post-parity package may introduce Apache/Nginx runtime compatibility, arbitrary root scripts, mandatory central authority, or an alternative security model.

### 30.4 Knowledge-graph integration plan

The target takes the concept further through typed source-generated graphs:

~~~mermaid
flowchart TD
    SCHEMA["Resource/command/provider schemas"] --> KG["Versioned engineering graph"]
    CODE["Go registrations + annotations"] --> KG
    UI["Generated UI journeys/client calls"] --> KG
    TEST["Tests + fault cases + evidence"] --> KG
    DOC["Docs + runbooks"] --> KG
    LEDGER["Parity + permissions + support"] --> KG
    KG --> COV["Coverage/orphan/staleness validators"]
    KG --> AGENT["Scoped AI context retrieval"]
    KG --> IMPACT["Change impact + release dossier"]
~~~

Unlike a shell-call graph, the target graph treats effects, permissions, resource ownership, support cells, failure frontiers, backup/migration, and evidence as first-class edges. Dynamic runtime behavior must still emit a declared operation/provider/event identity, so static coverage and runtime traces can be compared.

---

## 31. Objective parity-GA evidence and completion audit

GA certifies one immutable candidate. Evidence from another commit, dependency graph, engine/service version, provider version, rules/model, or support tuple is stale.

### 31.1 Release gates

| Gate | Objective pass bar |
|---|---|
| Baseline closure | 100% CyberPanel baseline ledger records `certified` or validly excluded as non-functional artifacts; zero unclassified active evidence; no baseline `post_ga` |
| Functional surfaces | Every applicable outcome proven in local UI, local API, CLI, scheduler, optional central projection/intent, permission, audit, docs, and operation history |
| Gate 0 | Every Section 25 kill test green with independent evidence and frozen architecture/support decisions |
| Installation | 100 consecutive clean install/bootstrap cycles per core tuple without manual repair; failure leaves working prior or documented resumable state |
| Reinstall/uninstall/rescue | Product reinstall preserves data/state; uninstall follows declared retention; recovery claim restores access without default/root web credential |
| Upgrade | Populated N-1→N on every core cell; crash/reboot/disk-full at every boundary; compatible rollback before contraction; forward-only frontier explicit |
| Engines | OLS and real licensed LSE independently pass install, licensing where relevant, native render/validate/activate/reload/restart/rollback, TLS/H3/PHP/cache/WAF on Ubuntu/Alma |
| Privilege | No remotely reachable panel control/management process runs as root; qualified vendor root supervisors are enumerated/confined with private admin surfaces and unprivileged workers where supported; every privileged mutation maps to a closed handler; path race, peer impersonation, replay, hostile environment, stale fence, crash receipt, and cross-registry tests pass |
| Site launcher | site-taskd cannot run caller-chosen UID/path/binary/profile; site workers/PTY/cron/Git/scans/builds remain in site identity/cgroup/namespace and are pidfd-cancellable |
| Authorization | Role/reseller/delegation/ownership/quota/step-up/session-revocation/central-binding/executor-commit matrix has no allow-on-error or weaker surface |
| Tenant isolation | Hostile PHP/file/archive/Git/mail/container/site command cannot read control secrets/sockets/other tenant or mutate host; exhaustion cannot starve recovery |
| Secrets | Product-managed secrets absent from URL/argv/product logs/crash/support; rotation/revoke/escrow/recovery and known-secret boundary scans pass |
| Audit | Every mutation/decision correlated; sequence/hash/checkpoint verify; clock/disk/replication failures visible; root-compromise limitations documented |
| Independent security | Threat review and penetration test complete; zero unresolved critical/high; every medium has approved owner/disposition; no author self-waiver |
| Supply chain | First-party artifacts have complete SBOM/provenance/license/vulnerability/VEX and reproducibility for privileged binaries; third-party closed artifacts have vendor signature/digest/acquisition/component inventory/generated SBOM/vulnerability disposition/conformance/provenance-gap record; offline TUF verification and key rotation/revocation/recovery pass |
| Operations | Reboot, process kill, disk/inode full, clock, corrupt telemetry, provider outage, firewall mistake, license stale, service crash yield documented durable states/recovery |
| Performance | Every Section 26 budget/fairness/SLO qualification passes under realistic mixed contention with p95/p99 and interference evidence |
| Backup | Full encrypted files/DB/mail/DNS/TLS/config/metadata clean-host restore on each core tuple and enabled subsystem; corruption/missing-key; three consecutive scheduled drills |
| Retention | Concurrent backup/restore/replication/hold/prune, prefix scoping, survivor, object lock/versioning, provider partial failure, and post-prune catalog tests pass |
| Migration | Live CyberPanel, CyberPanel backup, and cPanel fixture suites; at least ten varied clean-room rehearsals/source class; blockers/deltas/cutover/pre-write rollback/post-write frontier verified |
| Clean replacement | Target scan confirms no executable legacy runtime, active schema/config/parser/credential/listener/package, Apache backend/config, or source agent after cleanup |
| DNS | PowerDNS CRUD/all declared RR families/primary-secondary/TSIG/DNSSEC/backup; Cloudflare sync/conflict; provider timeout/rate/revoke/pagination; real-CAS providers pass conditional cutover, observe/apply providers pass exact observation/conflict/ambiguous and no-unsafe-compensation tests; automatic HA DNS promotion requires true CAS or an equivalent qualified traffic provider |
| TLS | HTTP-01, PowerDNS/RFC2136 and Cloudflare DNS-01, wildcard, aliases, hostname, mail, import/self-signed, renew, provider outage, rate/time, failed reload pass both engines |
| MariaDB | Lifecycle/grants/remote access/workspace/stream import-export/tuning/upgrade/restore/GTID and advertised Galera/fencing tests pass |
| Files/access | Descriptor/path/archive races/bombs, streaming/backpressure/quota, FTPS/SFTP/key/revoke, site terminal and host-file step-up pass |
| Mail server | SMTP/IMAP/LMTP/Sieve interoperability, TLS/auth, DKIM/SPF/DMARC, filter/malware/quarantine/routes/quota/queue/backup/restore/migration; no open relay |
| Webmail | SSO/account switch/folders/search/MIME/XSS/SSRF/attachments/compose/idempotency/contacts/groups/settings/Sieve, scale/accessibility pass |
| Marketing/delivery | Consent/suppression/unsubscribe invariants, bounce/complaint signatures, rate/abuse isolation, provider conformance, restore/privacy pass |
| Applications/WP | Every advertised recipe passes clean install/failure/update/backup/restore/detach/remove on every applicable parity cell; WordPress full lifecycle/LSCache/staging/scanning passes |
| Containers | Tenant rootless hostile-image and admin-rootful boundary; runtime socket/namespace/device/mount/capability/metadata/secret/limit/proxy/reboot/backup tests pass |
| CloudLinux | CloudLinux 9 × OLS/LSE LVE/CageFS/resource/backup/migration/conflict matrix passes independently for parity GA |
| Extensions | WASM/OCI signature/capability denial/replay/crash/exhaustion/update/rollback/uninstall/data-retention tests; no implicit privileged mutation |
| Providers | Every named/selected GA provider passes happy path, pagination, deadline, rate, revoked credential, partial write, ambiguity, reconciliation, backup/migration, and documentation |
| Federation | 72-hour central outage preserves local management/recovery; assertions/requests expire; replay is at least once with idempotent durable consumption and one terminal receipt per intent/effect ID; local deny/revoke wins; no executor bypass |
| HA | Quorum/fence/provider/partition/asymmetry/stale projection/promotion/rejoin/failback/DNS lag/source-return tests; no unsupported automatic promotion |
| Reliability soak | At least 30 days production-like mixed workload across all six parity cells with no unexplained authority corruption, cross-tenant effect, essential audit loss, or unrecoverable operation |
| Accessibility/locales | WCAG 2.2 AA automated/manual keyboard/screen-reader; every shipped locale meets completeness/review, interpolation, plural, overflow, and security-meaning gates |
| Observability | Every operation has audit/status/log/metric correlation; support bundles pass secret scan; alert loss and spool exhaustion are visible |
| Documentation | Install, LSE licensing, operations, recovery, backups, migration, mail/DNS deliverability, security, limits, unsupported cases, and break-glass runbooks succeed with unfamiliar operators |
| Legal/commercial | LSE, WAF, Imunify, malware signatures, GeoIP, fonts, packages, images, libraries, models, and providers have approved license/update/redistribution/data terms |
| Release ceremony | Human threshold approval, signed manifest/dossier, recovery artifact, rollback rehearsal, channel criteria, known limits, and support ownership complete |

### 31.2 No-waiver conditions

There is no GA waiver for:

- unresolved critical/high security finding;
- missing real licensed LSE evidence;
- authority corruption, duplicate committed effect, or unexplained state loss;
- cross-tenant/privilege escape or unaudited privileged mutation;
- default credential, generic root command, browser root shell, or permanent all-powerful token;
- silent data loss, false success, false rollback/atomicity, or unverified restore;
- unclassified active parity evidence or missing active outcome;
- unsupported capability silently accepted;
- provider interface without a working qualified implementation;
- backup destination without clean restore;
- automatic HA promotion without enforceable fencing;
- AI self-approved exception or unsigned/unprovenanced release.

A product-scope change can remove an obligation only by updating this design, the evidence/disposition ledger, security analysis, migration/docs, user-facing scope, and release approval. It is not a waiver.

### 31.3 Release dossier

The signed dossier contains:

~~~yaml
ReleaseDossier:
  releaseManifestDigest: sha256
  sourceCommit: digest
  dependencyLockDigest: sha256
  generatedGraphDigest: sha256
  parityLedgerDigest: sha256
  supportManifestDigest: sha256
  providerManifestDigest: sha256
  sbomDigests: [sha256]
  provenanceDigests: [sha256]
  gate0Evidence: [artifactDigest]
  tupleEvidence: [TupleEvidence]
  securityReviews: [artifactDigest]
  performanceEvidence: [artifactDigest]
  restoreEvidence: [artifactDigest]
  migrationEvidence: [artifactDigest]
  soakEvidence: [artifactDigest]
  documentationEvidence: [artifactDigest]
  knownLimitations: [signedStatement]
  recoveryArtifacts: [artifactDigest]
  reviewers: [identity]
  thresholdApproval: signatureSet
~~~

The dossier is verifiable offline from the release trust root. Public claims are generated from it and cannot name a feature, provider, OS, engine, version, capacity, recovery guarantee, or security property absent from certified evidence.

### 31.4 Completion audit

Parity delivery is complete only when:

1. the Section 28 zero-row completion query is empty;
2. every Section 31.1 gate passes for the same candidate;
3. all four core cells, both CloudLinux conditional-baseline cells, and every additional advertised conditional cell are certified;
4. a clean install and a clean migration both restore from native backups;
5. no legacy/Apache compatibility mechanism remains in the target;
6. local standalone operation and optional central outage behavior are demonstrated;
7. user/operator/API/CLI/migration/recovery documentation is current and executable;
8. the signed release and recovery roots are available to authorized humans;
9. known limitations state only bounded unsupported scope, not missing baseline functionality;
10. the product is released through the signed staged rollout with halt/rollback evidence.

---

## 32. Canonical registries, schemas, decisions, risks, and glossary

### 32.1 Resource-kind registry

~~~mermaid
erDiagram
    HOSTING_INSTANCE ||--o{ NODE : contains
    HOSTING_INSTANCE ||--o{ TENANT : serves
    TENANT ||--o{ MEMBERSHIP : grants
    PRINCIPAL ||--o{ MEMBERSHIP : holds
    TENANT ||--o{ PROJECT : owns
    PROJECT ||--o{ SITE : groups
    SITE ||--o{ WEB_APPLICATION : runs
    WEB_APPLICATION ||--o{ RELEASE : versions
    WEB_APPLICATION ||--o{ DOMAIN_BINDING : routes
    SITE ||--o{ DATABASE : owns
    SITE ||--o{ MAIL_DOMAIN : optionally_owns
    SITE ||--o{ ACCESS_CREDENTIAL : authorizes
    SITE ||--o{ SCHEDULE : triggers
    SITE ||--o{ APPLICATION_INSTALLATION : manages
    BACKUP_POLICY ||--o{ RECOVERY_POINT : creates
    RECOVERY_POINT ||--o{ COMPONENT_ARTIFACT : commits
    RESOURCE ||--o{ OPERATION : mutates
    OPERATION ||--o{ STEP_RECEIPT : records
    NODE ||--o{ SERVICE_INSTANCE : hosts
    NODE ||--|| WEB_ENGINE : selects
    CENTRAL_FLEET_PLAN ||--o{ FEDERATED_INTENT : emits
    FEDERATED_INTENT }o--|| NODE : targets
~~~

| Context | Canonical resource kinds |
|---|---|
| Identity | Principal, LocalCredential, Authenticator, RecoveryCodeSet, ExternalIdentity, IdentityProvider, Invitation, Session, APIClient, APIKey, CredentialEvent |
| Tenancy/authz | HostingInstance, Tenant, Membership, Role, RoleBinding, Permission, DelegationCeiling, ResourceOwnership, OwnershipTransfer, SupportAccessGrant, FederatedPrincipalBinding |
| Plans/quota | Plan, PlanVersion, PlanAssignment, Entitlement, QuotaBudget, QuotaReservation, QuotaLedger, UsageObservation, ResourceProfile |
| Node/product | Node, NodeIdentity, NodeAddress, NodeCapability, SupportTuple, ServiceInstance, ServiceGeneration, ProductRelease, UpdatePlan, UpdateRun, RebootRun, DiagnosticRun, RepairPlan, ConfigSnapshot |
| Hosting | WebEngine, EngineCapability, EngineLicense, EngineExpertFragment, Listener, Site, SiteIdentity, WebApplication, DomainBinding, PreviewSession, RouteContext, RewritePolicy, RequestHeaderPolicy, ResponseHeaderPolicy, ApplicationEnvironmentPolicy, WebNetworkAccessPolicy, HTTPAbusePolicy, WebAccessPolicy, FilesystemAccessPolicy, ErrorPagePolicy, PHPVersion, PHPExtension, PHPProfile, RuntimePool, CachePolicy, Release, Deployment |
| DNS | DNSZone, DNSRecordSet, SOAPolicy, TransferPeer, TSIGKey, DNSProviderBinding, DNSChangeSet, DNSSECPolicy, DNSKeySet, DSPublication, DNSProbe |
| TLS | ACMEAccount, CertificatePolicy, CertificateOrder, ChallengeAttempt, CertificateGeneration, CertificateDeployment, CertificateProbe |
| Database | DatabaseInstance, Database, DatabasePrincipal, GrantSet, NetworkAccessPolicy, DatabaseWorkspaceSession, DatabaseArtifact, TuningProfile, DatabaseUpgrade, ReplicationChannel, Promotion |
| Files/access | FileRootCapability, FileOperation, FileTransfer, ArchiveOperation, TrashEntry, HostFilesystemSession, AccessCredential, FTPAccount, SSHKey, SSHPolicy, TerminalSession, ContainerExecSession |
| Developer | CronSchedule, JobOccurrence, RepositoryBinding, GitCredential, WebhookEndpoint, ReleaseSource, Deployment, StagingRelation, SyncPlan, NativeTransferPlan |
| Operations | Command, OperationGrant, CommitAuthorization, Operation, OperationStep, StepReceipt, EffectReceipt, ResourceLease, FenceToken, Schedule, NotificationRule, DeliveryAttempt |
| Backup/DR | BackupPolicy, Repository, RepositoryCredential, BackupRun, RecoveryPoint, ComponentArtifact, Copy, Hold, Lease, RestorePlan, RestoreRun, DRBundle, VerificationRun |
| Mail server | MailDomain, Mailbox, Alias, Forwarder, CatchAllPolicy, AddressRule, PipeHandler, VacationRule, MailPolicy, MailLogPolicy, SigningKey, RelayBinding, QueueMessage, QuarantineItem, DeliveryEvent |
| Webmail | WebmailGrant, MailIdentity, FolderProjection, Draft, Contact, ContactGroup, WebmailProfile, SieveRule |
| Marketing | MarketingList, Subscriber, ConsentRecord, Suppression, Template, Campaign, RecipientSnapshot, DeliveryAttempt, Bounce, Complaint |
| Applications | ApplicationDefinition, ApplicationInstallation, ApplicationHealth, WordPressInstance, ComponentInventory, UpdatePolicy, PluginBundle, CloneRelationship, ScanRun, Finding, RemediationPlan |
| Containers | ContainerRuntime, OCIImage, RegistryCredential, ContainerWorkload, ContainerApplication, ContainerPackage, NetworkAttachment, Volume, PortExposure, ContainerExport |
| Security | SecurityPosture, FirewallPolicy, FirewallRule, EmergencyAccess, SSHLoginEvent, SSHSession, ProcessIdentity, WAFPolicy, WAFRuleSet, WAFExclusion, ScanRun, Finding, QuarantineItem, IncidentCase, EvidenceArtifact |
| Observability | ServiceHealth, MetricSeriesPolicy, LogStream, AuditEvent, AuditCheckpoint, SecurityEvent, Alert, Notification, SupportBundle, CapacityForecast |
| Extensions | ExtensionPackage, ExtensionInstallation, ExtensionGrant, ExtensionState, ExtensionDataStore, ExtensionHealth |
| Federation/HA | FederationEnrollment, CentralAuthorityGrant, FederatedPrincipalBinding, FederatedIntent, ProjectionCursor, FleetPlan, FleetWave, PlacementGroup, ReplicaSet, ReplicationChannel, TrafficPolicy, WriterLease, Fence, Promotion, FailoverRun |
| Migration | MigrationEnrollment, MigrationSet, SourceEvidence, ResourceEnvelope, BlobDescriptor, SecretEnvelope, MappingLedger, MigrationPlan, MigrationRun, CutoverToken, VerificationReport, CleanupAttestation |

Each kind defines scope, ownership ancestry, controller, status writer, lifecycle, finalizers, permission verbs, quota dimensions, secrets, backup/restore, migration, retention, deletion, support predicates, and event schemas in `resources.yaml`.

### 32.2 Permission grammar and risk policy

Permission IDs use `<domain>.<resource>.<verb>`, for example `hosting.site.create`, `database.workspace.query`, `backup.restore.activate`, and `security.firewall.commit`. Stable verbs are generated from the resource registry.

| Domain | Normal verbs | Elevated verbs/frontiers |
|---|---|---|
| identity | inspect, invite, modify_profile, revoke_session, manage_authenticator, manage_api_key | recover_owner, reset_mfa, change_role, suspend_principal |
| tenancy | inspect, create_child, manage_membership, assign_plan, transfer_resource | close_tenant, purge_tenant, widen_delegation |
| hosting | create, inspect, modify, suspend, resume, clone, manage_binding, manage_php, manage_cache | change_primary_domain, change_engine, purge_site, apply_expert_fragment |
| dns/tls | inspect, edit_rrset, issue, renew, import_certificate | change_delegation, disable_dnssec, export_key, revoke_certificate, traffic_cutover |
| database | create, inspect, manage_principal, grant, import, export, workspace_query | remote_expose, server_admin, kill_process, tune, upgrade, promote, destructive_schema |
| access | file_read, file_write, archive, manage_ftp, manage_ssh_key, site_terminal | host_filesystem, cross-owner_repair, permanent_purge |
| developer | manage_cron, manage_repo, deploy, staging_sync, transfer | production_db_push, run_unreviewed_hook, post-write_cutover |
| backup | inspect, run, configure, verify, export_catalog | restore_activate, retention_prune, delete_point, destroy_key, full_node_recover |
| mail | manage_domain, mailbox, route, sieve, queue, quarantine_release | pipe_handler, delete_queue_body, relay_global, mail_server_reconfigure |
| marketing | manage_list, subscriber, template, campaign | approve_campaign, clear_eligible_transient_suppression, record_evidenced_resubscription, export_personal_data |
| apps | install, inspect, update, stage, scan, detach | remediation_apply, production_promote, destructive_remove |
| containers | inspect, start_stop, logs, bounded_exec, manage_tenant_workload | rootful_admin, publish_port, adopt, export_secret, destructive_volume |
| security | inspect, diagnose, create_narrow_rule, investigate | firewall_commit, SSH_lockout_risk, global_WAF_change, delete_quarantine, disable_control |
| product | inspect, plan_update, diagnose | install/update/rollback, package_change, listener_change, trust_root/recovery |
| federation/HA | inspect, project, submit_low_risk, plan_wave | widen_grant, deliver_secret, promote_writer, manual_fence, failback |
| migration | discover, plan, rehearse, sync | approve_cutover, activate_target, post-write_recovery, purge_source |

Risk policy combines permission with resource scope, actor assurance, recency, approval count/independence, local/network origin, support state, recovery readiness, and frontier. A permission alone never bypasses those conditions. Built-in roles are immutable templates; tenant roles reference stable permissions but cannot exceed binding/delegation ceilings.

### 32.3 Secret schema and lifecycle

~~~proto
message SecretMetadata {
  string installation_id = 1;
  string id = 2;
  SecretPurpose purpose = 3;
  ResourceRef owner = 4;
  uint64 version = 5;
  uint64 key_epoch = 6;
  bytes wrapped_dek = 7;
  bytes nonce = 8;
  bytes ciphertext_and_tag = 9;
  string algorithm = 10;
  string key_provider = 11;
  string audience_binding_digest = 12;
  string associated_data_digest = 13;
  Timestamp created_at = 14;
  optional Timestamp expires_at = 15;
  SecretState state = 16; // pending, active, overlapping, revoked, destroyed
  repeated SecretConsumer consumers = 17;
  RotationPolicy rotation = 18;
  string plaintext_fingerprint_hmac = 19;
}

message SecretDeliveryGrant {
  string id = 1;
  string secret_id = 2;
  uint64 version = 3;
  string operation_id = 4;
  ResourceRef consumer = 5;
  SecretPurpose purpose = 6;
  Timestamp expires_at = 7;
  uint32 maximum_reads = 8;
  bytes audience_binding = 9;
}
~~~

SecretMetadata and ciphertext live only in secrets.db; control.db contains an opaque SecretRef and non-sensitive status. AEAD/KMS associated data canonically binds installation ID, secret ID, version, purpose, owner kind/ID/scope, audience-binding digest, key epoch, algorithm, and schema domain. secret-broker compares it with a protected monotonic metadata record before unwrap and rejects ID/purpose/owner substitution, ciphertext/DEK swapping, metadata mismatch, audience mismatch, or version/key-epoch rollback. The plaintext fingerprint is a keyed nonreversible value used only for product-boundary leak detection, never authenticity. Rotation state is pending → overlap → verified active → old revoked → destroyed after retention. Consumers receive plaintext through an inherited FD/memfd/protected file or provider-native channel; not URL, argv, normal environment, or reusable API response. Backup inclusion and escrow are explicit per purpose.

### 32.4 Audit schema

~~~proto
message AuditEvent {
  string event_id = 1;
  uint64 local_sequence = 2;
  string installation_id = 3;
  ResourceScope scope = 4;
  ActorChain actor = 5;
  AuthenticationEvidence authentication = 6;
  string action = 7;
  ResourceRef target = 8;
  string request_digest = 9;
  AuthorizationDecision decision = 10;
  string policy_version = 11;
  repeated string approval_ids = 12;
  optional string command_id = 13;
  optional string operation_id = 14;
  optional string effect_id = 15;
  uint64 before_generation = 16;
  uint64 after_generation = 17;
  string outcome_code = 18;
  RedactedChangeSummary change = 19;
  Timestamp wall_time = 20;
  string boot_id = 21;
  bytes previous_hash = 22;
  bytes event_hash = 23;
}

message AuditCheckpoint {
  string installation_id = 1;
  uint64 first_sequence = 2;
  uint64 last_sequence = 3;
  bytes terminal_hash = 4;
  Timestamp created_at = 5;
  repeated bytes signatures = 6;
  repeated string replication_receipts = 7;
}
~~~

Audit verification checks sequence, chain, checkpoint signatures, clock/boot discontinuity, redaction schema, and optional remote receipt. Export is permissioned and signed. Root can still alter/suppress local evidence; this limitation is part of the claim.

### 32.5 Provider contract

~~~go
type Provider interface {
    Capabilities(context.Context) (CapabilityManifest, error)
    Validate(context.Context, DesiredProviderState) []Finding
    Plan(context.Context, ProviderIntent) (ProviderPlan, error)
    Apply(context.Context, ProviderPlan, IdempotencyKey) (ProviderReceipt, error)
    Observe(context.Context, ExternalRef) (ProviderObservation, error)
    Reconcile(context.Context, ProviderReceipt) (ProviderObservation, error)
    Compensate(context.Context, ProviderReceipt) (ProviderReceipt, error)
}

type ProviderError struct {
    Code       StableErrorCode
    Retry      NeverOrAfter
    Ambiguous  bool
    RateLimit  *RateLimitObservation
    ExternalID string
    SafeDetail RedactedDetail
}
~~~

Provider plans name each external effect, precondition, idempotency support, ambiguity query, pagination cursor, rate budget, deadline, compensator, and irreversible frontier. Raw vendor errors are protected diagnostics, not unredacted user/audit strings.

### 32.6 Adopted decision register

| Decision | Adopted default | Qualification/implication |
|---|---|---|
| Primary implementation | Go modular monolith plus narrow helpers; Vue 3 strict TS | Gate 0 validates scale and host primitives; no premature Rust/microservices |
| LSE distribution | BYOL through official vendor artifact/license flow unless written redistribution agreement exists | Mandatory F0-LSE-01; no parity without real LSE |
| Core OS | Ubuntu 24.04 and AlmaLinux 9 x86_64 | Four engine cells; additional OS/arch after parity |
| CloudLinux | CloudLinux 9 LVE/CageFS conditional-baseline adapter on OLS and LSE | Operators need not use it; both cells are mandatory for full parity certification |
| Local authority stores | Bundled pinned SQLite control coordinator plus separately owned execd, taskd, secrets, authn, approvals, provider-effects, container, watchdog, and audit stores; logs/metrics/artifacts remain non-authority classes | Retained only if every store and cross-journal handoff in F0-STORE-01 passes |
| Tenant containers | Qualified rootless/user-namespace backend; rootful Docker admin-only | Backend selected by F0-CONT-01 evidence |
| Extension model | WASM plus rootless OCI; privileged providers remain signed core adapters | No in-process/root lifecycle plugins |
| Mail | Postfix + Dovecot + Rspamd, optional ClamAV, DKIM adapter, short-lived Dovecot OAuth/OAUTHBEARER | F0-MAIL-01; three separate workstreams |
| Webmail | Focused panel-native client using mature protocol/MIME/sanitization libraries; optional mature external transitional app | Full WML ledger remains GA; no superficial inbox |
| Campaign mail | Separate consent/suppression/rate-controlled subsystem using local/configured relay | Must not starve transactional mail |
| DNS | PowerDNS local authority plus provider interface/Cloudflare | DNSSEC is a securely delivered enhancement |
| Database | MariaDB baseline; PostgreSQL post-parity | Exact catalog/upgrade/restore matrix |
| PHP | Security-supported signed LSPHP lines only | EOL applications upgrade or block |
| File transfer | SFTP preferred, FTPS for FTP parity, no cleartext FTP | Service/profile explicit |
| Backup object engine | Product manifests over initial Restic-compatible content engine if Gate 0 passes | Product catalog/consistency/retention remain authoritative |
| Backup key custody | Local envelope key plus explicit human recovery export/escrow; optional external KMS; central not mandatory | Loss/rotation/destruction ceremonies tested |
| Host updates | Automatic signed product update; service/OS changes planned/orchestrated with honest recovery | No universal kernel/package rollback |
| WAF | OWASP CRS always available; commercial/Imunify separately licensed adapters | Each provider independently conformed |
| Central plane | Optional identity/inventory/templates/bounded orchestration/HA; node owns local resources | No central secret/state authority required |
| Telemetry | Local-first; external product telemetry off by default and schema-limited opt-in | Central rollout evidence cannot require tenant content |
| Migration | Measured downtime/RPO; RPO-0 rollback only before target writes and only for proven fenced data | No in-place or post-divergence one-click rollback claim |
| Full-stack minimum | 4 vCPU, 8 GiB, local SSD/NVMe; smaller web-only profile separate | Installer rejects impossible service mix |
| UI/API | Local static TypeScript app and panelctl consume one versioned application API | No privileged alternate UI path |
| Compatibility | None; one-way disposable migrators only | No old routes/schema/files/plugins/Apache runtime |

Provider choices deliberately marked “selected before certification” in Section 23 are procurement/product decisions, not architecture gaps. A release cannot certify those records until it names and proves them.

### 32.7 Principal risks and controls

| Risk | Why material | Primary controls / decision trigger |
|---|---|---|
| LSE vendor/license constraints | Mandatory engine may be commercially/CI difficult | F0-LSE-01 first; BYOL; official agreement; real lab; parity blocked on failure |
| Scope magnitude | CyberPanel surface includes hosting, mail, apps, containers, providers, HA | Executable granular ledger; vertical stages; no percentage claims; full parity only Stage 10 |
| Privileged control compromise | Typed root ops can still be abused semantically | Unprivileged paneld; narrow helpers; registry resolution; independent commit approval; audit; recovery |
| SQLite contention/corruption | One node has many reconcilers/schedules | One coordinator; short batches; data-store separation; kill/load tests; certified envelope |
| OLS/LSE semantic divergence | Similar features differ by edition/version | Sibling adapters, capability rejection, differential corpus, independent tests |
| Mail/webmail/campaign complexity | Three deep products with abuse/data risks | Separate teams/gates/queues; mature libraries; protocol/security/interoperability fixtures |
| Tenant container isolation | Rootful runtime is host-root equivalent | Admin-only rootful; Gate-0-proven rootless tier; hostile images; no sockets/host resources |
| Provider ambiguity/outage | Timeouts and eventual state cause duplicate/lost effects | Stable effect/idempotency IDs, observation, deadlines, circuit breaker, exact conditions |
| Backup false confidence | Write success does not prove recovery | Signed manifest, independent copies, verification states, scheduled clean restores |
| Migration divergence | Multi-service cutover cannot be atomic | Explicit writer frontier, watermarks, dry run/rehearsal, fencing, measured RPO, retained source |
| AI monoculture/hallucination | Same model may author false code/tests/evidence | Independent derivation/oracles, deterministic gates, artifact verification, human trust root |
| Supply-chain compromise | Product manages root-capable updates/rules/providers | Hermetic/reproducible builds, TUF, SBOM/provenance, threshold keys, staged rollout |
| Support matrix explosion | Every OS/engine/provider multiplies validation | Four core cells first; exact manifest; conditional adapters only after separate proof |
| Performance interference | Backups/scans/mail/builds can harm sites/control | Admission estimates, cgroups, priorities, fairness pools, Section 26 budgets |
| Central compromise/split brain | Remote orchestration can amplify effects | Local binding/RBAC/epoch/CAS; no executor route; enforceable fencing; automatic promotion disabled without proof |

### 32.8 Glossary

| Term | Meaning |
|---|---|
| canonical state | New-platform typed desired/observed resources; never legacy file/database state |
| command | Accepted immutable request to change desired state or invoke a typed action |
| operation | Durable asynchronous realization of a command |
| effect | One externally visible host/provider mutation with stable identity |
| receipt | Durable typed record that an effect was accepted, observed, compensated, or remains ambiguous |
| reconciliation | Converging desired and observed state after request, drift, crash, timeout, or provider change |
| fence | Monotonic or topology-specific authority proof preventing stale/previous writer commit |
| frontier | Point after which automatic rollback cannot restore the stated prior data/behavior guarantee |
| support tuple | Exact OS/architecture/kernel/filesystem/policy/engine/service configuration certified together |
| capability | Discovered, versioned, evidence-backed ability of a node/adapter/provider |
| parity record | Independently testable baseline outcome and all evidence/contract links |
| recovery point | Signed logical commit of required component artifacts and consistency evidence |
| restore-tested | Isolated recovery exercise passed for the declared scope, tuple, repository, and workload class |
| local authority | The node's sole right to persist its desired resource state and mutate its host |
| projection | Sanitized revisioned observation copied to central; not writable resource truth |
| federation | Optional outbound node/central relationship governed by local grants and policy |
| secure redesign | Same legitimate outcome with unsafe legacy mechanism removed |
| managed release | Immutable application content plus active pointer and declared mutable stores |
| mutable tree | Directly editable application tree with snapshots/journal and limited rollback claims |
| proof level | Structural, local end-to-end, client-confirmed, or independent-external readiness evidence |
| AI factory | Isolated multi-role engineering pipeline whose output is gated and signed outside model authority |

### 32.9 Local evidence references

The initial design used static source inspection only; no CyberPanel/GridPane project script, service, test suite, installer, container, or host mutation was executed.

Key local evidence roots:

- CyberPanel baseline: repository at `/Users/aon/GitHub/cyberpanel`, commit `d44f57a3c91834999a0d8b0324eadda5e269e783`;
- active CyberPanel route/view/model/manager/scheduler/installer/provider code under that repository;
- GridPane depth corpus: `/Users/aon/GitHub/server-scripts`;
- GridPane knowledge/dependency design: `/Users/aon/GitHub/server-scripts/AGENTS.md`;
- GridPane command taxonomy: `/Users/aon/GitHub/server-scripts/gp-commands.md` and `/Users/aon/GitHub/server-scripts/gp-commands/`.

Official LiteSpeed, OpenLiteSpeed, PowerDNS, MariaDB, Dovecot/Postfix, kernel/systemd, provider, protocol, and licensing behavior MUST be verified against authoritative current documentation and real disposable environments during Gate 0. Assertions about exact vendor-native formats, commands, licenses, versions, and offline behavior are adapter qualification results, not assumptions inherited from this source review.
