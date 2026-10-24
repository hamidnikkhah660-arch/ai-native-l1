# CP-0406 — QZBE persistent branch archive candidate

Date: 2026-10-24

Status: **candidate-level local persistence; not canonical-node integration and not Gate 8 closure**

## Goal

Extend CP-0405's bounded in-memory QZBE/QZB4 v2 branch graph with a disk archive that validates all committed branches on every open. Keep the candidate separate from PMT3/PMT4 and from the canonical node until the profile, monetary transition and production trust boundary have independent approval.

## Implementation

The new monetary_pow_v04_store_candidate.rs module adds a local-only persistent store:

- Uses an OS-backed exclusive writer lock and writes each branch envelope to a filename derived from the validated PoW digest.
- Uses bounded reads and an exact, versioned QZMF manifest containing network ID, Genesis tip, monetary profile fingerprint, PoW profile fingerprint, manifest generation, expected canonical tip/height/state root, and sorted branch digest + envelope-byte-hash records.
- Persists manifests as immutable numbered generations instead of replacing the prior manifest in place. Each new branch file is written and synced before the next manifest generation is published.
- On open, verifies the newest manifest's checksum and profile binding; checks every branch's exact bytes and digest; replays the complete archive from Genesis using the configured authenticator; and rejects a mismatch in the derived canonical tip, height or state root.
- Rejected envelope imports leave the live in-memory graph unchanged. Duplicate accepted payloads are idempotent and do not create a new manifest generation.
- Bounds the branch archive to 4,096 blocks and 64 MiB of encoded envelope data for this candidate.

## Tests

The candidate tests target restart/replay after a reorg, idempotent duplicate submission, fail-closed handling of a corrupt newest manifest, fail-closed handling of a missing referenced branch, and strict manifest framing.

Focused validation on the working tree: `cargo test --locked --offline --lib monetary_pow_v04_store_candidate -- --nocapture` — **7 passed, 0 failed**. This covers replay after a reorg, duplicate idempotency, corrupt-manifest rejection, missing-branch rejection, exact manifest framing/order, and fail-closed handling of a newer manifest-shaped directory and a non-regular branch path. Final local validation on the working tree completed successfully: `cargo test --all-targets --locked --offline` exited 0; the library test harness reported **823 passed, 0 failed**, the `devnet_node` and `private_testnet_node` test harnesses each reported **36 passed, 0 failed**, and all remaining targets completed without failure. `cargo fmt --all -- --check` and `cargo check --all-targets --locked --offline` both passed. The staged release checksum rebuild and public documentation preflight passed with **376 entries** and **47 README-relative links**. This is still local evidence: a committed clean-checkout verification and CI for the exact new SHA remain required. The prior CP-0405 CI result is recorded separately in CP-0405_QZBE_V04_POW_FORK_CHOICE_CANDIDATE_2026-10-24.md.

## Limitations and launch boundary

This module is **not** a production durable-store qualification:

- The manifest and branches are on the same local filesystem; restoring that directory as a whole can roll it back.
- The implementation does not include a separately administered external CAS/monotonic anchor or production receipt-verification key custody.
- Multi-host tests, VM/power-loss and storage-cache fault testing, independent security review, and full node runtime/P2P/import/fork-choice wiring remain open.
- The test authenticator and current subsidy/halving values remain fixtures, not Mainnet policy.
- The module is not wired into chain_import_node, devnet_node, the canonical listener, wallet/RPC, or an externally accessible network.

Therefore **Gate 2 and Gate 8 remain OPEN**. No public Mainnet, minting, sale, exchange listing or real-money market is implied. Keep all runs zero-value and isolated.

## Next required milestone

Implement or select a separately operated CAS provider with challenge-bound exact-successor receipts, bind its verified read/write protocol to this store's manifest generation and digest, add timeout/response-loss/concurrent-writer/replay/stale-restore fault tests, then arrange independent multi-host and security review. Only after that should a separate design review consider canonical runtime integration.
