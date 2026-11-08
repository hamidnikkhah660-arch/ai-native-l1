# CP-0400 — QZP4 Profile-Bound Monetary Snapshot Candidate

**Date:** 2026-10-24

**Status:** Candidate-only serialization and restore contract. QZP4 is not connected to the live node's producer/importer, fork-choice store, or durable runtime. Gate 2 and Gate 8 remain open.

## Why this step exists

CP-0398 introduced an explicit QZCP consensus profile and QZB4 mining-only candidate transition. QZL4 already serializes the v0.4 ledger and allocation accounting, but QZL4 alone does not commit to the consensus schedule/profile fingerprint. This step adds a separate wrapper instead of changing the bytes or meaning of existing QZL4 snapshots.

## QZP4 v1 wire contract

All integers are unsigned big-endian.

| Field | Size | Validation |
|---|---:|---|
| Magic QZP4 | 4 bytes | Exact match |
| Version | u16 | Must equal 1; unknown versions fail closed |
| Network ID | 32 bytes | Nonzero; must match expected Genesis and configured profile |
| Encoded QZCP v1 profile | 254 bytes | Must decode against the expected Genesis manifest and exactly match the explicitly configured expected profile |
| Nested QZL4 length | u32 | Checked arithmetic and maximum-length enforced |
| Nested QZL4 snapshot | Variable | Existing QZL4 v1 codec; validated and required to re-encode byte-for-byte canonically |
| Profile-bound monetary state root | 32 bytes | Must match the state root recomputed from the restored ledger, accounting, mining counter and profile fingerprint |
| Domain-separated QZP4 checksum | 32 bytes | Covers all preceding QZP4 bytes |

The fixed envelope overhead is 360 bytes, in addition to the nested QZL4 snapshot. The independent genesis fixture is 810 bytes (360-byte QZP4 overhead plus the 450-byte QZL4 snapshot).

The QZP4 checksum domain is QUANTUMZXB-V04-PROFILE-BOUND-SNAPSHOT-CHECK-CANDIDATE-V1 followed by a NUL byte. The format is canonical: the profile, nested snapshot and whole envelope must all be reproduced byte-for-byte during restore.

## Restore invariants

The API decode_snapshot(bytes, expected_manifest, expected_profile) requires the caller to supply both the expected Genesis manifest and the explicitly configured profile. It does not trust a schedule merely because it appears in the saved snapshot.

Restore fails closed for:
- truncated or oversized envelope, incorrect magic, unsupported version, bad outer checksum or inconsistent length;
- zero/wrong network ID, a profile bound to another Genesis, or a schedule/profile that differs from the caller's expected profile;
- invalid or noncanonical nested QZL4 bytes;
- invalid allocation accounting, mismatch between ledger value and live supply, mining counter or schedule inconsistency;
- mismatch between saved and recomputed profile-bound monetary state root;
- any full-envelope re-encoding mismatch.

The crate-private MonetaryLedgerStateV04Candidate::from_transition_parts helper exists solely to provide validated components to this wrapper; it does not expose a public arbitrary-issuance API.

## Independent vector and tests

The standard-library Python oracle in simulations/quantumzxb_v04_transition_profile_vectors.py independently computes QZGM, QZCP, the nested 450-byte QZL4 genesis snapshot and the full QZP4 envelope. simulations/quantumzxb_v04_transition_profile_vectors.txt records the 810-byte canonical envelope, its SHA-256 and the already established profile/block vectors. The Rust test asserts byte-for-byte equality with that independent vector.

New QZP4 tests:
1. Genesis snapshot bytes equal the Python oracle and round-trip to identical state.
2. A snapshot after a candidate mining transition restores the same state root and tip.
3. Wrong Genesis, network and schedule/profile are rejected.
4. Checksum corruption, unknown version and truncation are rejected.

Existing QZL4 behavior and vectors are unchanged. The current local validation for this change:
- cargo fmt --all -- --check: passed.
- Four Python oracle checks (Genesis, QZL4, issuance schedule, QZCP/QZB4/QZP4): passed.
- cargo test --lib monetary_transition_v04_candidate -- --nocapture --test-threads=1: 10 passed, 0 failed.
- cargo test --lib monetary_ledger_v04_candidate -- --nocapture --test-threads=1: 5 passed, 0 failed.
- cargo check --all-targets --locked --offline: passed; pre-existing warnings remain.
- git diff --check: passed.

## Security and integration limits

A checksum detects accidental corruption; it is not a signature, freshness proof or anti-rollback control. QZP4 does not add an external CAS, receipt keys, disk durability, atomic file replacement, runtime recovery hook, fork-choice/reorg persistence, or multi-host restore protection. Those remain separate work.

This step does not change MBK3/MBK4, PMT3/PMT4, QZGM or QZL4 semantics. It does not select production economics, activate QZB4 in a node, close Gate 2 or Gate 8, or make any public-launch claim. The subsidy and halving interval in the golden vector remain small test fixtures, not approved network parameters.

## Next safe step

Before live integration, produce a line-specific runtime call-site/compatibility matrix and obtain explicit approval of the canonical network profile, activation rule and mining schedule. Then integrate profile selection at a single versioned boundary with legacy no-downgrade tests; do not wire QZP4 into the current PMT3/PMT4 stores as if it were already a durable production format.
