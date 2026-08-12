# Platform implementation status

This file is the compact recovery point for ongoing implementation. The normative product design remains in `docs/superpowers/specs/2026-08-12-secure-cyberpanel-parity-platform-design.md`.

## Hard execution rule

Finish usable end-to-end vertical slices. Do not turn individual abstractions, reviews, test harnesses, or internal boundaries into mini-projects. Use Ubuntu QEMU for the fast RED/GREEN loop, qualify the completed slice on AlmaLinux QEMU, perform one focused review, commit, and move forward.

## Current position

- Complete: QEMU-tested Go foundation and strict QMP client.
- Complete: immutable tenant/site/domain lifecycle aggregate.
- Complete: engine-neutral OpenLiteSpeed/LiteSpeed Enterprise desired-state model.
- Complete: secure native OLS and Enterprise renderers, including collision-safe physical listener identities.
- Complete: durable site-projection command workflow with CAS, idempotency, exact effect correlation, tenant isolation, retryable ambiguity, and explicit withdrawal.
- In progress: compose all site projections into one node-wide desired state and runtime snapshot.
- Next: stage, validate, activate, probe, confirm, and automatically roll back a generated configuration.
- Vertical-slice gate: create one site through the command service, compose it, render it for both engines, activate it in QEMU, and prove HTTP/PHP behavior.

## Scope truth

This is still the first hosting vertical slice, not broad CyberPanel parity. DNS/ACME, databases, mail, files/access, backups, WordPress, containers, security operations, central federation, UI/API/CLI, installer, and migrators remain after this slice.
