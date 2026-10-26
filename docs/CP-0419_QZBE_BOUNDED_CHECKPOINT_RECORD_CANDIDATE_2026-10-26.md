# CP-0419 ? QZBE bounded checkpoint record candidate

Date: 2026-10-26

Status: **checkpoint codec and independent Genesis vector validated locally; exact-head CI pending; not yet integrated with the QZBE archive/store**

## Why this step exists

The existing QZBE fork-choice candidate rejects logical heights above 1,024, but the configured retarget window is 2,016 blocks: the first default retarget for candidate block height 2,017 is therefore unreachable through that fork graph. Removing the height cap or deleting old envelopes without a trusted checkpoint would discard required ancestry and anti-rollback guarantees. CP-0419 creates the versioned record format needed for a later bounded checkpoint-aware store; it does not claim that pruning or long-term mining is enabled yet.

## Record schema and validation

- Magic QZCP, schema version 1, flags fixed to zero, explicit total byte length, and a domain-separated trailing checksum.
- Binds Network ID, exact QZGM Genesis manifest hash, QZCP profile fingerprint, the configured PoW consensus fingerprint, logical height, QZBE body-bound consensus tip digest, the execution ledger tip hash, monetary state root, total mined atoms, cumulative chainwork and parent checkpoint commitment.
- Includes the complete profile-bound QZP4 state snapshot and the exact bounded target/timestamp suffix needed by the configured difficulty window. Target-history count is checked against the configured window before allocating history entries; heights, timestamp markers, and section lengths have canonical encodings.
- Validation decodes and re-encodes the state snapshot against the expected Genesis manifest and profile, checks state height/root/mined counter/ledger tip, restores bounded difficulty history, and enforces Genesis versus non-Genesis chainwork/parent-link shape.
- The independent Python oracle verifies the fixed Genesis vector, nested QZP4 snapshot, length fields, history entry, checksum and domain-separated commitment. A Rust regression compares the encoded record byte-for-byte with the same fixture.
- The boundary test builds the real configured 2,016-entry timestamp/target history, checkpoints at height 2,016, restores it and obtains the same expected target for height 2,017 without substituting a short test window.

## Local evidence

- python simulations/cp0419_qzbe_checkpoint_oracle.py: PASS; 1,231-byte record, 810-byte state snapshot, one Genesis history record; commitment d7c98b7d090179fc7f68b9d808bf59fd0958eb97bf25e9d10c0297be2c7ac600.
- cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check: passed.
- cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --locked --lib monetary_pow_v04_checkpoint_candidate -- --test-threads=1: 6 passed, 0 failed, including Genesis/non-Genesis record round-trips, malformed metadata/length/checksum rejection, parent/chainwork requirements, and the exact height-2,017 retarget-restore test.
- Exact-head CI must be run against the pushed CP-0419 SHA. Previous green CI for CP-0418 does not cover these changes.

## Explicit limits

This is a codec and fixture, not a checkpoint-aware durable archive. It does not prove ancestry or that cumulative chainwork was earned: that requires verified replay from a trusted origin or an independently approved checkpoint certificate. A local checksum/commitment is not authenticity or freshness. The record is not yet integrated with QZBE branch selection, durable manifest transitions, retention/pruning, checkpoint-crossing reorg policy or an external CAS provider. MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT remains 1,024. The first retarget was proved at the TargetHistory checkpoint API level only, not by a running QZBE chain at height 2,017. Gate 2, Gate 8, public multi-operator devnet and independent security/release gates remain open.
