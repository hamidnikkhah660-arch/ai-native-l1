# CP-0496 - QRun v0.5 committed Genesis-time anchor primitive

Date: 2026-11-02

Status: **Committed Genesis-time anchor primitive and Local/External-CAS runtime/CLI plumbing implemented; focused validation passes. Mainnet identity freeze remains blocked pending selection of the real activation epoch, launch-window policy and cross-layer identity migration.**

## Purpose

CP-0494 reproduced a first-retarget time-warp in live QFP5 admission. CP-0495 added a two-sided local freshness window, but explicitly left the network's deterministic Genesis activation time unresolved.

CP-0496 adds a time-anchored Genesis construction path without silently changing historical candidate identities or choosing an arbitrary Mainnet launch time.

## Implementation

- `LedgerState::genesis_at(network_id, allocations, genesis_timestamp)` creates height-zero state with `last_timestamp` initialized to the supplied activation timestamp.
- The existing `LedgerState::genesis(...)` remains backward-compatible and delegates to `genesis_at(..., 0)`.
- `QRunGenesisV05::new_with_genesis_timestamp(network_id, owner, timestamp)` is the explicit anchored constructor. Timestamp zero is rejected.
- The legacy `QRunGenesisV05::new(...)` constructor remains available for old fixtures and historical candidate identities; it does not claim a Genesis-time anchor.
- The anchored Genesis commitment includes the timestamp under the domain `QUANTUMZXB-QRUN-GENESIS-TIME-ANCHOR-V1\0`. The state root also changes because the existing canonical state root already commits `last_timestamp`.
- The existing Ledger snapshot codec already persists `last_timestamp`; no snapshot format/version bump was needed. A restored anchored Genesis therefore retains its timestamp floor.
- QFP5 live admission uses the normal state-machine monotonic timestamp check. The first accepted block must have a timestamp strictly greater than the committed Genesis timestamp, in addition to satisfying the CP-0495 two-sided local freshness policy.
- `QRunV05PowForkRuntime::open_with_genesis_timestamp(...)` opens the durable local runtime using the anchored Genesis; `from_store_with_genesis(...)` then rechecks the exact same Genesis object before exposing the backend.
- Node startup accepts `--genesis-time-unix-secs`. The value is passed through both Local and External-CAS startup; the External-CAS Genesis pin and ECR1/QCF1 trust tuple are checked against the timestamp-bound commitment.
- QRA1 replay has an exact-Genesis entrypoint; migration and recovery no longer reconstruct an unanchored Genesis while replaying or validating a timestamp-bound archive.
- QRM1 is now version 3: it stores the Genesis timestamp inside the journal and protects it with the v3 checksum domain. Recovery requires the timestamp in QRM1 to equal the timestamp in the independently supplied Genesis state before any provider/floor mutation. The decoder retains explicit v2 compatibility as an unanchored timestamp-zero journal; v1 remains rejected.
- `--public-alpha` now requires a nonzero explicit Genesis timestamp that must be identical on every node in that network. `--local-testnet` retains the legacy unanchored mode for isolated compatibility fixtures and may opt into the timestamp-bound mode.

## Focused validation

- `qrun_genesis_time_anchor_is_committed_and_survives_snapshot_restart`: **PASS**.
- `qrun_genesis_time_anchor_rejects_zero_timestamp`: **PASS**.
- `qrun_v05_live_chain_enforces_the_committed_genesis_time_floor`: **PASS**. A first block equal to Genesis time is rejected atomically; a block at Genesis time + 1 is accepted under a matching test clock.
- `qrun_v05_live_time_window_rejects_backdating_and_bounds_first_retarget_warp`: **PASS**.
- `qrun_checkpoint_restore_preserves_genesis_time_anchor_and_rejects_other_epoch`: **PASS**. The QRCP restore retains the anchored height-zero timestamp and rejects the same checkpoint bytes under a different Genesis-time commitment.
- `time_anchored_runtime_reopens_only_with_the_same_genesis_timestamp`: **PASS**. The local PFS2 runtime reopens under the same epoch and fails closed when the same data directory is opened under a different epoch.
- `genesis_timestamp_cli_requires_nonzero_shared_epoch_for_public_alpha`: **PASS**.
- Runtime candidate module tests: **9/9 PASS**.
- `external_cas_node_startup_uses_pinned_noise_provider_and_advances_floor_before_return`: **PASS end-to-end with a nonzero Genesis timestamp**. QRA1 history replay, QRM1 v3 publication, External-CAS successor commit, QCF1 floor advance, QRCP migration and process restart completed; the test emitted `qrun_v05_genesis_checkpoint_migration_complete height=1`.
- `qrm1_recovery_engine_reconciles_lost_cas_response_advances_floor_and_reopens_checkpoint_store`: **PASS with a nonzero Genesis timestamp**. A deliberately lost CAS response was reconciled from QRM1 v3; the exact Genesis epoch was preserved while QCF1 advanced and the checkpoint store reopened.
- QRM1 migration module tests: **10/10 PASS**, including v3 roundtrip and a reconstructed v2 legacy journal decoded as timestamp-zero Genesis. QRM1 recovery module tests: **1/1 PASS**.
- `qrun_v05_pow_local_node` binary tests, including Gossip/Noise sync and External-CAS startup: **29/29 PASS**.
- Genesis candidate tests: **5/5 PASS**; QRCP checkpoint tests: **2/2 PASS**.
- Historical CP-0450 profile identity compatibility tests: **2/2 PASS**; the legacy unanchored candidate commitment remains byte-for-byte stable.
- Full Rust library suite: **1046/1046 PASS**, 0 failed, 0 ignored.
- `cargo fmt --all -- --check`, `git diff --check`, and `cargo check --all-targets --locked --offline`: **PASS**. Existing unused/dead-code warnings remain; no compilation errors were reported.

## Deliberate non-changes / release boundary

- No real Mainnet activation timestamp has been selected. A build date or the date of this checkpoint must not be substituted for the actual agreed activation epoch.
- The current wallet-bound Mainnet manifest, fixed Genesis/Profile IDs and External-CAS trust pins have not yet been regenerated for an anchored Genesis. The frozen Mainnet identity therefore remains intentionally unchanged.
- `--public-alpha` requires an explicit shared timestamp; `--local-testnet` can still use the compatibility constructor. Mainnet remains blocked by the source-level release gate.
- The `±120-second` CP-0495 check is a node-local live freshness guard that depends on a trusted reference clock; it is not by itself a fully specified cross-node consensus time source. The exact launch activation window and delayed-start policy still need an explicit network-identity decision before Mainnet.
- Historical replay remains clock-free. A timestamp anchor alone does not prove that an untrusted peer's full-history archive was originally admitted live. Bootstrap still requires authenticated checkpoint/anchor provenance.
- No consensus profile JSON, Network ID, wallet identity, External-CAS trust pin, checkpoint version, or Mainnet activation switch is frozen or changed by this checkpoint.

## Required integration before Mainnet

1. Select the real activation epoch and a bounded launch-start policy; specify how delayed activation is handled and whether the first block must fall inside a separately committed activation window.
2. Bind the selected epoch and any launch-window parameters into the wallet-bound Genesis commitment and exact network/profile identity. Retire or explicitly label the historical CP-0450 identity so it cannot be mixed with the current wallet-bound candidate.
3. Before lifting the Mainnet gate, require strict nonzero `--genesis-time-unix-secs` parsing for Mainnet and reject startup when the configured value differs from the frozen identity or External-CAS Genesis pin.
4. Regenerate the wallet-bound manifest, profile/Genesis ID constants, External-CAS ECR1/QCF1 bootstrap/floor pins and checkpoint parent commitments from one agreed anchored Genesis. Update the independent Python/cross-language oracle and vectors together.
5. Test first-block admission, delayed launch, clock skew, 2,016-block retarget boundaries, reorgs, checkpoint capture/restore, process restart and independent-host replay against the same anchored identity.
6. Keep historical replay deterministic and clock-free; prove bootstrap trust through externally authenticated Genesis/checkpoint provenance rather than comparing archived timestamps with today's wall clock.

**Gate 2 remains OPEN.** `QRUN_MAINNET_RELEASE_APPROVED` remains false. This primitive is not approval for Mainnet, public mining, exchange trading or value-bearing QZXB launch.
