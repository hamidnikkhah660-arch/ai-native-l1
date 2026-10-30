# CP-0397 — Explicit v0.4 Mining Issuance Schedule Candidate

**Status:** Candidate contract and reference vectors only; no default schedule is approved.
**Code baseline:** ef43ffcd466170945288cb119f858f08d3937c87
**Gate 2:** OPEN. **Gate 8:** OPEN.

## Purpose

CP-0391 defines the v0.4 allocation ceilings, including a 3,000,000,000-coin mining/security bucket. It does not define when or how quickly that bucket may be issued. CP-0397 adds a parameterized arithmetic contract so that any future schedule is explicit, testable and fingerprintable. It is not a policy decision and is not called by a node.

## Implemented candidate contract

File: src/native/pow_bench/src/monetary_issuance_v04_candidate.rs

The constructor requires both initial_subsidy_atoms and blocks_per_halving; it has no implicit default. The candidate pins these arithmetic semantics for schedule version 1:

- Genesis is height 0; reward-eligible block height starts at 1.
- Block height is converted to a zero-based schedule index by subtracting the first eligible height.
- Integer right-shift implements halving, flooring each result in atom units.
- The derived reward is capped at the remaining mining-bucket budget.
- There is no special terminal mint to fill a small residual amount.
- The candidate schedule fingerprint binds the allocation-policy fingerprint, schedule version, eligible height, mining budget, explicit parameter values, and a domain-separated rules tag.

This fingerprint is not yet included in the existing QZGM Genesis manifest or QZL4 snapshot. It therefore cannot yet select or activate v0.4 consensus. Adding it to a live profile requires an explicit versioned Genesis/profile contract rather than a silent mutation of existing bytes.

## Independent reference vectors

Files:
- simulations/quantumzxb_v04_issuance_schedule_vectors.py
- simulations/quantumzxb_v04_issuance_schedule_vectors.txt

The Python script uses only the standard library and independently recomputes the allocation policy fingerprint, reward boundary values, cumulative schedule value, and candidate schedule fingerprint.

For comparison only, the fixture uses the numbers present in the existing legacy schedule: an initial subsidy of 35,673,515,981 atoms and a halving interval of 4,204,800 blocks. This is **not** an implicit v0.4 default or an endorsement to reuse the legacy policy. The values exist in this fixture to provide a concrete, independently checked arithmetic example.

Under those reference-only values, the sum across all eras with a non-zero integer subsidy is:

- Mining bucket budget: 300,000,000,000,000,000 atoms (3 billion coins).
- Sum of non-zero scheduled rewards: 299,999,999,913,926,400 atoms.
- Unissued remainder: 86,073,600 atoms, or 0.860736 coins.

This difference is a consequence of integer halving; the candidate does not invent a special final mint. Whether a future v0.4 schedule should leave such a remainder or choose different parameters is an economic/protocol decision that must be explicitly frozen before activation.

The candidate's Python vector file is a research fixture, not a mainnet Genesis or live-chain state.

## Validation performed before integration

The following checks have passed on the local Windows worktree after adding this candidate:
- cargo fmt --all -- --check
- cargo check --all-targets --locked --offline
- Five targeted Rust tests for monetary_issuance_v04_candidate
- Five existing targeted Rust tests for monetary_ledger_v04_candidate
- python simulations/quantumzxb_v04_issuance_schedule_vectors.py --check
- Full serialized all-target test command: cargo test --all-targets --locked --offline -- --test-threads=1, exit code 0. The library test group completed with 797 passed and 0 failed in 437.28 seconds. The devnet_node and private_testnet_node binary test groups each completed with 36 passed and 0 failed; the other binary/integration/example targets also completed with no failures.

The all-target check retains pre-existing unused-import/dead-code warnings. These are local Windows results for the uncommitted CP-0397 candidate worktree. CI run ef43ffc passed for the prior commit and does not validate this newer code. The CP-0397 commit must receive its own CI result after push.

## Required steps before any runtime use

1. Explicitly freeze the v0.4 mining parameters and the policy for unused rounding remainder. Do not silently reuse the legacy schedule because its bucket size matches.
2. Bind the schedule fingerprint into a separately versioned monetary profile/Genesis contract. Do not reinterpret existing QZGM/QZL4 bytes.
3. Implement a v0.4 block envelope and atomic state transition that changes account balances, mining allocation counters, cumulative mined amount and state root together.
4. Have the producer derive its permitted reward from local parent state/profile. Import must independently derive the same expected reward and reject peer-forged subsidy values.
5. Preserve exact producer/importer parity through fork choice, reorg, replay, restart and durable commit/recovery tests; add independent negative and boundary vectors.
6. Keep Gate 8 open until an independently operated external compare-and-swap/anchor is connected fail-closed and stale-snapshot restore tests pass.

No runtime, Genesis, transaction, block-wire or legacy monetary behavior was changed by CP-0397. No coin issuance, public launch, listing or income activation is implied.
