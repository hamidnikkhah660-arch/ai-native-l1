# CP-0381 - Bounded Target-History Snapshot Candidate

Date: 2026-10-22
Base: `0cf7ee129e887c9037b5137ffbb19c956ff69eca` (PR #49 merge)
Scope: in-memory target/timestamp-history snapshot and restore in the private-testnet driver. This is a bounded state representation candidate, **not** a canonical PCP4 byte codec, PFM5 manifest, durable checkpoint store, or production fork-choice change.

## Changes in this candidate

- Retains target/timestamp history in bounded `VecDeque` collections and tracks the first retained logical height separately from the current logical chain height. Vector offsets are not treated as block heights after restore.
- Builds a target-history snapshot from the active difficulty-window profile. For a chain below the window length it keeps the prefix starting at genesis. Once logical height `H` reaches or exceeds configured window `W`, the snapshot contains exactly `W` entries covering `H-W+1..=H`.
- Enforces a hard entry ceiling of 65,536 records and validates profile, range/count canonicality, contiguous logical heights, target bounds, the genesis entry, required timestamps, and strictly increasing timestamps.
- For a snapshot that starts at genesis, replays target history and checks recorded targets against the retarget rules. A pruned suffix does **not** prove its own ancestry or trustworthiness; its caller must authenticate the enclosing checkpoint, network/Genesis and consensus/monetary profiles, state root, checkpoint block/tip, cumulative work, issuance accounting, parent commitment, freshness, and an independent anti-rollback trust anchor.
- Keeps live retained target/timestamp history bounded to `W` entries as blocks are recorded; merely limiting snapshot serialization would not bound live memory use.

## Local test evidence

On the Windows development checkout, after rebasing this branch to the PR #49 merge above:

- `cargo fmt --all -- --check` - passed.
- `cargo test --locked --offline --lib target_history_checkpoint_rejects_noncanonical_or_malformed_entries -- --nocapture` - 1 passed.
- `cargo test --locked --offline --lib driver_retargets_from_branch_timestamp_window_deterministically -- --nocapture` - 1 passed. This covers the first default retarget boundary, bounded retained history, continued retarget equivalence after restore, a second snapshot, malformed histories, and a genesis-prefix replay check.
- `cargo test --all-targets --locked --offline -- --test-threads=1` - exited 0 on Windows; the log reports 758 library tests passed, plus the binary, integration/vector, and example targets. The `devnet_node` and `private_testnet_node` targets each reported 36/36 passing. This is local candidate-test evidence only; CI for the PR and other operating systems must be checked separately.
- `git diff --check` - passed before this report was prepared.

These tests establish only behavior covered by this in-memory candidate. They do not constitute independent cross-client consensus vectors, an independent protocol/security review, or a production deployment test.

## Explicit non-goals and open gates

This change does not implement PCP4 encoding/decoding, PFM5 manifest serialization, durable atomic checkpoint publication, checkpoint trust verification, checkpoint-aware archive replay, checkpoint-linked fork choice or reorg recovery, a production CAS provider, or independent receipt-signing trust. It does not change production network parameters or raise the existing PFM4 logical-height ceiling.

- **Gate 2 remains OPEN.** Canonical checkpoint serialization and persistence; integrated replay/reorg; explicit fail-closed cumulative-chainwork overflow semantics; frozen Genesis/consensus/issuance profile; independent difficulty and issuance boundary vectors; and independent protocol/economic review remain outstanding.
- **Gate 8 remains OPEN.** A separately operated production CAS service with atomic generation compare-and-swap; out-of-band pinned receipt trust and monotonic high-water protection; and multi-host disk-loss, crash, race, rollback and recovery qualification remain outstanding.
- **Mainnet and public launch are not enabled or claimed.** No native QZXB Mainnet, public mining, exchange listing, market liquidity, or production value-bearing network is asserted by this candidate.
- **Owner-funded spend remains USD 0.** This patch provisions no paid infrastructure, independent review, public listener, public key ceremony, or liquidity. External costs require real sponsor/customer funding or explicit third-party infrastructure credits.

## Next required implementation steps

1. Specify and implement canonical, bounded PCP4 encoding and strict decoding with independent golden vectors.
2. Resolve cumulative-work overflow as a deterministic fail-closed consensus error before any state mutation; cover individual-block, branch-sum, and cumulative-chain tests.
3. Bind a checkpoint to network ID, canonical Genesis/profile fingerprints, state root, exact block/tip digest, issuance state, chainwork, target/timestamp history, parent commitment and authenticated freshness/high-water state.
4. Integrate checkpoint write/read with crash-safe persistence, bounded replay and reorg rules, and a checkpoint-aware manifest; preserve atomicity under failure.
5. Implement and independently operate production CAS and trust services; test rollback, key rotation, concurrent generation races, host restore and disk loss.
6. Keep Gates 2/8 open until repository evidence and independent review support closure. Mainnet launch requires additional multi-node, wallet/RPC, monitoring, backup/incident-response, release reproducibility and security-review evidence.