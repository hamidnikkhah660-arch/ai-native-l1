# CP-0612 - QAP1-gated pinned-peer history bootstrap and mining handoff

Date: 2026-11-12
Status: QAP1 history client and library-level handoff implemented; CP-0613 adds private-candidate executable wiring. Independent end-to-end peer qualification remains open.

## Implemented

- `sync_history_from_pinned_peer_with_qap1` establishes Noise using the caller's protected local static key and one operator-pinned remote static public key.
- It obtains Q6HR status for the runtime's exact network/profile, rejects a source behind the local anchor, and verifies same-height consensus/execution tips.
- Each Q6HS request is derived from the exact QAP1 committed anchor plus a fresh durable fork-choice snapshot. Every decoded page must match the pinned source snapshot and is passed only to `import_history_page_with_qap1`.
- The importer commits/acknowledges blocks one at a time through Provider/Q6EA. Pending or poisoned anchor state stops synchronization; restart recovery is required before retry.
- Final completion requires source height, consensus tip, execution tip, and QAP1 canonical state root to agree.
- `sync_history_from_pinned_peer_until_complete_with_qap1` bounds reconnect rounds and page totals.
- `run_qfp6_mining_supervisor_with_qap1_bootstrap` validates operator-pinned bootstrap peers, tries only the QAP1 history path, refuses to proceed after an unresolved anchor transition, and hands off to the existing QAP1 mining supervisor only after a complete authenticated snapshot match. It has no non-QAP1 fallback.

## Verification

- `cargo check --all-targets --locked --offline`: passed after adding the QAP1 history client and bootstrap handoff.
- `cargo test --lib qrun_v06_node_supervisor_candidate::tests -- --test-threads=1`: 12 passed, 0 failed.
- `cargo fmt --all`: completed successfully.
- `git diff --check`: passed.
- No end-to-end Q6HR/Q6HS+Provider/Q6EA multi-process sync result is claimed by this change.

## Remaining boundaries

- CP-0613 wires `qrun_v06_node --run` to the QAP1 bootstrap wrapper in private-candidate mode only. It remains fail-closed and requires independently provisioned configuration, Genesis/profile/trust inputs, protected Noise keys, and pinned peers. Public Mainnet execution remains disabled.
- No actual external peer endpoints/Noise keys, Provider/Q6EA transports/verifiers, local protected Noise key, Genesis/profile artifacts or independently authenticated trust pins are provisioned by this code change.
- No public listener, Mainnet activation, public mining, issuance, or exchange trading is enabled.
- Required next qualification: two independently provisioned hosts with real pinned peer keys and Provider/Q6EA test services; interrupt after an acknowledged prefix, restart via `open_qap1`, resume from exact next height, then verify matching snapshot and bounded QAP1 mining handoff.