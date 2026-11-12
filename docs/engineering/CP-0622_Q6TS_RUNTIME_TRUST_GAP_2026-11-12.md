# CP-0622 — Q6TS release/runtime trust-boundary finding (clarified)

Status: candidate-only engineering finding. No Mainnet, public mining, Genesis signing, or public network exposure is authorized.

## Clarification

The permissionless full-history base-node architecture intentionally does not require Q6TS, Provider, Q6EA, or QAP1. CP-0588 and CP-0590 explicitly establish this boundary: ordinary nodes validate and replay the complete chain from an independently pinned immutable Genesis/manifest identity. Q6TS remains an optional trust extension for anchored, pruned, or checkpoint operation.

The permissionless launcher therefore not loading Q6TS is not, by itself, a runtime security defect. The actual defect is that CP-0620 and the generic candidate-package validator currently describe a single six-artifact package and do not distinguish the base-chain release from the optional anchored/checkpoint extension. This conflates two different trust models.

## Required resolution — split release profiles

1. **Permissionless full-history Base Mainnet:** require independently pinned network/profile/consensus/Genesis commitments; full-history replay from Genesis; canonical timestamp/MTP and retarget rules; valid PoW and fork choice; anti-rollback protection for retained local history; authenticated/qualified peer admission and public network protections. Q6TS is not a mandatory artifact for this mode.
2. **Anchored/pruned/checkpoint extension:** require Q6TS dual signatures, independently provisioned authority keyset and monotonic trust floor, exact Q6PN/Q6GD/Q6CP/Genesis bindings, expiry/revocation and rollback handling, plus the Q6EA/Provider dependencies required by that mode. This mode must remain separately selected and fail closed.

Do not add Q6TS as a universal base-protocol dependency merely to satisfy a package counter. Do not remove Q6TS from the anchored/checkpoint release requirements. Do not describe a local candidate validator as an independent trust authority.

## Required code/documentation follow-up

- Split candidate/release manifest profiles into `permissionless_full_history` and `anchored_checkpoint` (or an equivalently explicit versioned discriminator).
- Require Q6TS artifacts and trust-floor state only for the anchored/checkpoint profile; reject attempts to claim anchored operation without them.
- For the permissionless profile, require externally pinned immutable Genesis/profile commitments and full-history replay qualification instead of Q6TS.
- Keep `production_authorized=false`, `mainnet_status=NOT_AUTHORIZED`, and `public_mining_authorized=false` until all mode-specific checks and independent reviews pass.
- Add validator tests proving that a base profile does not falsely claim Q6TS enforcement, while an anchored profile cannot pass without valid Q6TS material.

## Current decision

**NO-GO for production.** This clarification corrects the trust-boundary interpretation; it does not qualify either release profile or authorize Mainnet.
