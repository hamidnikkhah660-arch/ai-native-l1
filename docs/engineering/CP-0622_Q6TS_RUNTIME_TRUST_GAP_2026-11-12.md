# CP-0622 — Q6TS release/runtime trust-boundary gap

Status: engineering finding; candidate-only. This note does not authorize Mainnet, public mining, Genesis signing, or network exposure.

## Finding

The CP-0620 release artifact gate requires a Q6TS trust bundle, independent trust authorities, and threshold signatures. The candidate package validator also requires the Q6TS artifact as one of six package components.

The permissionless QFP6 launcher inspected for this checkpoint explicitly states that it does not load Q6TS (nor Provider, Q6EA, or QAP1 services). Therefore the current release gate and runtime have different trust boundaries: a Q6TS file may be present and externally checked by a release operator, while the running node itself does not consume or enforce that trust bundle.

This is not evidence that Q6TS is unnecessary. It is an unresolved production-security gap.

## Required resolution — fail closed

Before any production authorization, choose and implement one reviewed architecture:

1. **Runtime-enforced Q6TS (preferred):** define a versioned Q6TS encoding; load it from the permissionless runtime configuration; verify authority keys, threshold signatures, network/profile/Genesis commitments, expiry/revocation policy, and anti-rollback anchor before opening listeners, importing history, or mining. Add negative tests for missing, malformed, wrong-network, insufficient-threshold, revoked, expired, and rollback bundles.
2. **Explicit external trust-verifier architecture:** only acceptable after an independent security review defines a cryptographically verifiable handoff from the release verifier to every node, including how nodes authenticate the verifier result and prevent substitution/rollback. A local “operator checked it” statement is not sufficient.

Do not silently remove Q6TS from the six-artifact release gate, mark it runtime-loaded when it is not, or promote a package merely because all six files exist.

## Additional release blockers remain

- Inbound Noise XX currently does not authenticate remote peer identity.
- Public peer discovery and authenticated peer advertisements are not qualified.
- Existing-history replay needs an independently pinned trusted manifest anchor.
- Public listener qualification and public mining authorization remain false.
- Production Q6CP parameters, canonical Genesis/Q6GD/Q6PN commitments, independent reviews, and independently operated bootstrap peers remain required.

## Acceptance criteria

- Manifest distinguishes `release_trust_bundle_required` from `runtime_q6ts_enforced`; the latter must remain false until actual runtime enforcement and tests land.
- The production release gate rejects any configuration that claims Q6TS enforcement without a runtime verifier implementation and passing tests.
- Documentation names the exact trust boundary and never describes the candidate launcher as Q6TS-authenticated.
- All existing candidate checks remain fail-closed; no fabricated trust roots, signatures, endpoints, or Genesis artifacts.

## Current decision

**NO-GO for production.** Preserve `production_authorized=false`, `mainnet_status=NOT_AUTHORIZED`, and `public_mining_authorized=false`. This checkpoint records the gap; it does not pretend to close it.
