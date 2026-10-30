# CP-0460 — QRun v0.5 strict checkpoint rollover parent links

**Date:** 2026-10-28
**Status:** Strict parent-link validation and restart tests implemented locally; the external CAS path is covered with the in-memory signed-provider fixture. Production checkpoint automation and a live independently administered CAS provider remain open.

## Change

The QRCP codec now offers `decode_anchored_with_parent`. It requires both (1) the independently supplied commitment for the exact checkpoint bytes and (2) the independently supplied expected commitment of that checkpoint's predecessor, in addition to the existing network, Genesis, profile, and minimum-height checks. A checkpoint that has a valid own commitment but links to the wrong parent returns `ParentCheckpointCommitmentMismatch`.

The runtime exposes `open_from_checkpoint_with_parent`; the external-CAS store exposes the corresponding `open_from_checkpoint_with_parent` method. Both validate the expected parent before opening local state. The external-CAS entry point then performs the existing external signed-read / anti-rollback validation; it still requires a pre-provisioned provider pin, signing key, bootstrap record, and retained object-generation floor. The basic single-anchor API remains available for callers that deliberately trust only the latest checkpoint's independent commitment.

## Test evidence

The extended runtime test constructs a Genesis-height checkpoint, then checkpoint heights 1 and 2 with each child's parent set to the preceding checkpoint commitment. It verifies that a wrong parent is rejected before a suffix manifest is created, opens a new suffix from the height-2 checkpoint, appends height 3, and reopens the durable suffix only with the exact retained manifest anchor. The test checks state-root equality and preserves the fixed full-supply invariant at each step.

The external-CAS checkpoint test now uses the strict parent-aware API for both the initial open and restart. Its provider remains an in-memory mock that signs receipts with test keys; this proves code-path behavior and not an external deployment or operator independence.

Local verification for this change:
- `cargo fmt --all -- --check` — passed.
- `cargo test --lib qrun_pow_runtime_mines_persists_and_reopens_full_supply_chain` — passed.
- `cargo test --lib qrun_external_cas_checkpoint_open_submit_and_reopens_qfp5_suffix` — passed.
- `cargo check --all-targets --locked` — passed with existing unused/dead-code warnings.

## Limits and next release gates

This adds explicit parent-link validation to the candidate runtime and CAS entry points. It does not create an automatic background checkpoint scheduler, compress/archive the complete historical store, establish a live provider's atomic-write durability, pin a production receipt key from a second trust domain, or demonstrate recovery against a deployed provider outage. Those still require the independently provisioned service and multi-host integration runs.

Mainnet remains disabled. QZXB's fixed maximum remains 10,000,000,000 coins assigned at Genesis; post-Genesis minting and block subsidy remain zero. The present public-launch path therefore means fee-only production, and must stay closed until production consensus, external anti-rollback infrastructure, public peer operation, and release validation are complete.
