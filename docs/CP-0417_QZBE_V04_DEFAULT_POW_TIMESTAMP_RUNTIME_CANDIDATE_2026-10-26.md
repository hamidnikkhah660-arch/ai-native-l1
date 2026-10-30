# CP-0417 ? QZBE v0.4 default PoW profile and real monotonic block timestamps

Date: 2026-10-26

Status: **local candidate change; exact-head CI pending; not canonical Mainnet integration or public-launch authorization**

## Changes

- QZBE's default PoW parameters now come from the named candidate consensus profile: Argon2id v1.3, 64 MiB, one iteration, one lane, and the existing 30-second / 2,016-block candidate difficulty policy. The easy 8 MiB target is available only through the explicit test-easy-pow option, and only loopback addresses are accepted by this runtime.
- The local mining attempt bound is increased from 256 to 4,096 hashes per bounded candidate call. This keeps a finite work budget while making the default candidate target practical to mine without changing its target or weakening its memory-hard parameters.
- Block timestamps use current Unix time, with a strictly increasing floor above the canonical parent timestamp. This replaces the earlier runtime behavior that supplied block height as the timestamp and makes the timestamp input relevant to difficulty history.
- The runtime still rejects issuance schedules that do not match the v0.4 pinned subsidy/halving parameters. The startup log distinguishes QZXB_V04_ARGON2ID_64MIB from EXPLICIT_LOCAL_TEST_EASY_POW_8MIB.
- The 2-node integration scripts explicitly request the test-easy-pow mode, and use a future test transaction expiry so the signed transfer remains valid with realistic Unix timestamps. The tokenomics preflight checks the policy constants, default-vs-test PoW split, attempt bound, timestamp path, and loopback fixture flags.

## Local verification

- cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check: passed.
- cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --locked --bin devnet_node -- --test-threads=1: 47 passed, 0 failed, including the new timestamp monotonicity test and default-vs-test PoW profile test.
- simulations/cp0415_devnet_qzbe_dispatch_transaction_loopback.ps1: passed on Windows release binaries; two nodes accepted the signed transfer, rejected a tampered signature atomically, converged at height 2 and matched after replay. Public bind and legacy-profile downgrade remained denied.
- simulations/cp0414_qzbe_authenticated_transaction_loopback.ps1: passed on Windows release binaries with the same signed-transfer, invalid-signature rejection, replay and public-bind assertions.
- simulations/quantumzxb_tokenomics_checker.py: passed after being extended to check the Rust runtime defaults and the explicit test-only profile.
- simulations/public_docs_refresh_checker.py and release checksum preflight are to be run on the staged change.
- Exact-head GitHub Actions run 40371654299 passed for commit 05f71e596c881b5ac2d9a1c312679b0a483ff93d: both Linux all-target validation/tests and the Windows TXN4/PFM4/QZBE loopback job completed successfully. That green result covers CP-0417; it does not cover the subsequent CP-0418 multi-peer patch, whose exact-head CI is pending.

## Still not closed

This candidate still uses the isolated QZBE store and only one pinned loopback peer. It is not wired into the default PTB2/PFS2 or PMT4/PFM4 canonical producer/importer. Peer discovery/fan-out and a multi-operator network are not complete. The store's external CAS remains an interface/test fixture; there is no independently operated production anti-rollback provider. No production owner-key ceremony or founder transfer has taken place, no public network listener is enabled, and no QZXB/USDT market is running.

Gate 2, Gate 8, and the public zero-value devnet/security gates remain open. This checkpoint is a concrete PoW/runtime improvement only, not Mainnet approval.
