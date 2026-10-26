# CP-0408 — Offline QZB4 v2 / QZBE persistent-store smoke runner

Date: 2026-10-24

Status: **local-only candidate runner; local test/check validation passes; not canonical node integration, not a public Devnet, not a Mainnet release**

## Goal

Provide a reproducible executable path through the QZGM Genesis manifest, explicit QZCP schedule/profile, transaction-bearing QZB4 v2 candidate blocks, QZBE PoW envelope, persistent branch store, and close/reopen replay. This bridges the gap between module tests and running the actual candidate components in one process without altering the current PMT4 runtime or opening network listeners.

## Executable

Source: src/native/pow_bench/src/bin/qzbe_v04_candidate_smoke.rs

The runner:

- Requires explicit absolute data directory, nonzero network ID, Genesis owner ID, miner ID, initial subsidy in atoms, halving interval, and block count. There is no default monetary schedule.
- Requires a dedicated store directory and rejects unrelated top-level data files or symlinked directory/lock paths, to avoid accidentally co-locating QZBE candidate state with a legacy node data directory.
- Uses a deliberately easy, reduced-memory local PoW parameter set. Each envelope still binds the exact PoW/profile fingerprint, but these parameters are only for offline smoke testing.
- Builds blocks with an empty transaction list. The supplied authenticator rejects every transaction; there is no wallet, transaction submit endpoint, P2P, RPC or market listener.
- Stores candidate blocks through V04ExecutionForkStoreCandidate, closes and reopens the store, then checks that height, tip, state root, manifest generation and archive length match deterministic replay.
- Rejects a reused data store if the explicit network/Genesis/profile/schedule is inconsistent with its committed manifest.

## Example command

The following identifiers and economics are deterministic local test fixtures, not project Mainnet parameters. Choose a new, dedicated absolute data directory on the test machine:

cargo run --locked --offline --bin qzbe_v04_candidate_smoke -- --data-dir "C:\temp\qzbe-v04-smoke" --network-id 3131313131313131313131313131313131313131313131313131313131313131 --owner-id a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7 --miner-id c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4 --initial-subsidy-atoms 1000000 --blocks-per-halving 8 --blocks 3

## Local evidence

- `cargo fmt --all -- --check` — PASS.
- `cargo test --locked --offline --bin qzbe_v04_candidate_smoke -- --nocapture` — **6 passed, 0 failed**.
- Executed the CLI on a dedicated local data directory with the explicit fixture parameters above — **PASS**, height 0 to 3, manifest generation 3, archive length 3, and successful post-close replay.
- Executed again against the same store/profile with --blocks 2 — **PASS**, height 3 to 5, manifest generation 5, archive length 5, and successful replay after reopen.
- The exact observed first-run result included genesis_manifest_hash=099876ace3094b5a7ea761952c665af7a1448f1333ee8beb2bf04925ba1d64dc, profile_fingerprint=0bb3c96aadf1af595ab46a82669a6c699cf35e8dcd6bb10132ad5bfef4a3e333, and replayed state root 8916180b9f97e3c6c0a583febdf693c13b9210d836b7aa382651a9bc64fb96a3. The continuation run advanced from the recorded tip to height 5 without changing the explicit Genesis/profile.
- cargo test --all-targets --locked --offline — PASS, exit 0; the library harness reported **826 passed, 0 failed**, `devnet_node` and `private_testnet_node` each reported **36 passed, 0 failed**, the new smoke binary reported **6 passed, 0 failed**, and all remaining target suites completed without failure.
- cargo check --all-targets --locked --offline — PASS; cargo fmt --all -- --check — PASS.
- Release checksum rebuild and public-docs preflight passed on the prior CP-0408 commit at **379 entries / 49 README-relative links**. The follow-up CP-0407 QZCA/lock-order hardening and the CP-0404 temporary-path isolation fix are now locally validated: focused tests **10/10** and **4/4**, full all-target run **826 library tests** plus both node suites **36/36** and QZBE smoke **6/6**, `cargo check --all-targets --locked --offline` and format check PASS. For source commit `beb531ecd2ef23ba09c5e113bb2cd1e6a4661a03`, GitHub Actions run `40139044429` completed successfully on the exact SHA, with both Rust validation and Windows two-node loopback jobs green. The additional CP-0409 audit-scope document and README/roadmap link are documentation-only follow-ups and will refresh the checksum manifest and trigger fresh CI. These local checks do not replace provider deployment or independent security review.

## Limitations

This is an offline candidate smoke runner, not the canonical node. It does not open peers or RPC endpoints, provide production transaction authentication, implement a real independently administered CAS service, or prove public-network operation. Its locally constructed ledger includes candidate accounting state and must not be advertised as a live/publicly issued asset.

The real node producer/importer still uses the older PMT4/PFM4 research path. QZB4 v2/QZBE remains separate until one monetary Genesis/profile/schedule is explicitly approved and producer/importer, fork choice, persistent storage, recovery and version activation are integrated together. Gate 2 and Gate 8 remain OPEN. No Mainnet issuance, sale, exchange listing or real-money trading is authorized by this runner.
