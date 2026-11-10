# CP-0577 - QFP6 checkpoint-segment read-only Store audit

Date: 2026-11-10

## Purpose

CP-0576 introduced a fail-closed audit for a Genesis-rooted QFP6 durable Store and its QAP1 journal. A Store created from a non-Genesis checkpoint is a distinct segment: its archive starts at the checkpoint base and cannot be safely interpreted as a complete Genesis archive. CP-0577 adds a separate read-only audit path for that checkpoint-rooted layout.

## API

- `QRunV06DurableForkStore::audit_existing_checkpoint_segment_with_trust_authorized_profile_pin`
- `QRunV06DurableForkStore::audit_existing_checkpoint_segment_with_trust_authorized_profile_pin_and_quote_asset_authorization`

Both APIs require the caller to provide the exact checkpoint snapshot bytes, an independently retained nonzero checkpoint anchor, an exact externally retained latest Manifest anchor, a Q6TS-authorized Q6PN profile pin, a matching Q6EA anchor pin, a transaction authenticator, and Provider / Anchor signature verifiers. The quote-aware variant additionally takes a Q6TS/Q6QA quote-asset authorization provider for historical replay of external-quote blocks.

## Audit contract

1. Require protocol v0.6 and validated consensus parameters.
2. Validate the Q6TS-authorized profile descriptor and its consensus fingerprint; validate that the supplied Q6EA pin matches the Provider pin.
3. Acquire the Store writer lock and validate the root layout without invoking the mutating Store-open/recovery path.
4. Read the bounded checkpoint file and require byte-for-byte equality with the caller-supplied snapshot. Decode it against the exact externally pinned checkpoint commitment, network, profile, and Genesis descriptor; verify founder and tokenomics-policy bindings.
5. Reconstruct the checkpoint base graph using the checkpoint consensus-tip commitment. Load the Manifest chain, require the latest Manifest anchor to equal the caller's external anchor, and replay all listed post-checkpoint block envelopes. Validate the replayed graph against the latest Manifest.
6. Reconstruct the Q6EA local-state view while preserving the trusted checkpoint anchor, segment base height, and segment base tip.
7. Audit the latest QAP1 journal phase, persisted Provider / Anchor receipt evidence, staged candidate, and next Manifest against the reconstructed Store. Only the exact locally authorized candidate orphan in the AnchorConfirmed / local-manifest-not-yet-published window is tolerated; unrelated orphans and unexpected entries fail closed.
8. Return the reconstructed segment and recovery disposition in `QRunV06DurableStoreAuditReport`. For a checkpoint-rooted segment, `checkpoint_anchor` is `Some(anchor)`; `segment_base_height` and `segment_base_tip` identify the checkpoint base.

## Side effects and non-goals

The audit does **not** create/open the normal Store, clean temporary files, delete or repair branches, reconcile remote services, issue Provider or Q6EA CAS requests, advance Q6TS or Provider trust floors, publish a block, admit a transaction, start P2P, start a node, or mine. It acquires the OS writer lock; as with the Genesis audit, the lock's diagnostic PID file may be created or updated. A successful result is a local integrity/replay finding and does not prove that a remote Provider or Q6EA Anchor is currently reachable or still holds the audited state.

This is a library audit API, not a Mainnet activation or node restart command. It does not qualify the candidate ML-DSA verifier for production, provision production signing keys, establish independent production trust-floor operators, or approve public networking or real-value trading.

## Validation

- Windows, Rust/Cargo 1.82, locked offline dependencies.
- `cargo fmt --all -- --check` - passed.
- `cargo check --all-targets --locked --offline` - passed.
- Focused Q6TS-authorized Genesis + checkpoint Store audit test - passed; includes a height-1 checkpoint, a post-checkpoint block, exact checkpoint and Manifest anchor rejection, segment-base assertions, QAP1 checkpoint-anchor continuity, and preservation of unexpected orphan bytes.
- Full `cargo test --all-targets --locked --offline` with default parallelism: 1,300 passed and 2 existing concurrent Provider / Trust-Floor writer tests failed under parallel load on Windows. Both failed tests passed when rerun individually.
- Full `cargo test --all-targets --locked --offline -- --test-threads=1`: passed with exit code 0; all 1,302 library tests and every binary, integration-test, and example target succeeded. The two concurrency tests above also passed in this serial full-suite run.
- The parallel-only contention remains documented rather than changing lock semantics or masking a possible timing issue. CI should independently validate the pushed commit.
