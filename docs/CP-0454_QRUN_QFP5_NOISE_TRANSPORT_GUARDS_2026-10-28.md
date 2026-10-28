# CP-0454 — QFP5 authenticated transport and legacy-mode downgrade guards

**Date:** 2026-10-28
**Status:** Candidate transport tests and fail-closed mode guards pass locally. No public listener or Mainnet activation.

## Transport candidate

- QRun's bounded Noise XX application-record budget now includes the largest canonical QFP5 envelope plus the bounded sync-response overhead.
- Typed `write_qfp5_block_record` and `read_qfp5_block_record` helpers validate the canonical envelope before sending or after authenticated decryption. A generic record remains available for the separate sync request/response messages, but block helpers refuse to treat PTB2 as QFP5.
- Loopback tests verify a canonical producer-inclusive QFP5 block round-trips inside the pinned Noise session; a legacy payload sent to the QFP5 receiver fails with `UnsupportedBlockEnvelopeMode`.

## Downgrade boundaries

- The existing `QRunV05PowForkRuntime` is explicitly a legacy PTB2 runtime. It rejects QFP5 before calling its legacy PFS2 store and leaves height, retained branches, owner balance, supply, and manifest anchor unchanged.
- The existing loopback-only PoW node refuses QFP5 on block send, receive, archive sync and mined-block routes. The legacy private-testnet node similarly refuses QFP5 during import and archive enumeration.
- The mode-locked QRun QFP5 chain/store introduced in CP-0453 remains a separate candidate path; QFP5 is not silently flattened into the legacy `Block` and accepted by an old node.

## Local checks

- Noise QFP5 typed-record roundtrip and legacy-payload rejection tests pass.
- Legacy runtime QFP5 refusal/atomicity test passes.
- `cargo check --all-targets` and formatting checks pass after these changes.

## Open production gates

These are transport/downgrade guards, not an internet-ready peer system. QFP5 still needs a purpose-built node startup path that uses the profile-locked QRun store/driver, authenticated static-key provisioning and rotation/revocation, bounded peer discovery/admission, transaction relay, and end-to-end QFP5 block propagation across independently operated hosts. The current Noise pattern uses classical X25519 and static-key pins; it is not a claim of post-quantum/hybrid security. Production difficulty/retarget parameters, MTP/timestamp policy, external monotonic anchor provider and automatic verified checkpoint rollover, crash/reorg tests against real nodes, and independent security review remain release gates.

Do not expose the loopback node by changing its bind flag. The QRun balance remains a candidate Genesis commitment, not spendable public Mainnet coins.