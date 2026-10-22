# CP-0384 - Canonical PCP4 Checkpoint Record Codec Candidate

Date: 2026-10-22
Base: PR #52 merge `9b86eda796e240f858539f4872cbc86d79d0a2e3`.
Scope: candidate-only canonical PCP4 v1 byte encoder/decoder with caller-supplied trusted Genesis, configured consensus profile, and active transaction-manifest validation. This does not add PFM5, durable checkpoint storage, runtime startup integration, fork choice, or reorg support.

## Canonical codec scope

- Implements PCP4 v1 with `PCP4` magic, strict version 1, zero reserved flags, big-endian fixed-width fields, a checked total record length, a bounded embedded monetary snapshot, a bounded target-history list, and a 32-byte domain-separated checksum.
- Computes a consensus-profile fingerprint from the supplied validated PoW/difficulty/issuance settings and the monetary policy constants currently bound to `MonetaryLedgerState`. It does not choose a Mainnet profile.
- Computes a Genesis fingerprint from a caller-supplied trusted height-zero monetary state, network ID, configured profile fingerprint, and active transaction-manifest ID. The checkpoint's Genesis/profile/network/manifest fields must match that independently supplied context.
- Decodes the embedded monetary snapshot and compares its network, logical height, ledger tip, monetary root and total mined atoms with PCP4 metadata.
- Validates target-history ranges using the configured difficulty-window profile. The expected start/count is checked before allocating the entry vector; a count below the global parser ceiling can still be rejected as noncanonical for a given logical height.
- Rejects unknown versions, nonzero reserved flags, bad/truncated/trailing bytes, length mismatches, checksum failures, unsupported count/size, noncanonical timestamp flags, profile/network/manifest/Genesis mismatches, inconsistent Genesis fields, and malformed target histories.
- Computes a distinct domain-separated PCP4 commitment over the complete encoded record. A checksum or commitment is not a signature, an origin proof, a freshness signal, or an anti-rollback anchor.

## Golden-vector evidence

The fixture under `src/native/pow_bench/tests/fixtures/` uses only deterministic synthetic test identifiers and a candidate test Genesis; it contains no private keys or credentials.

- Rust test `private_testnet_checkpoint_candidate::tests::genesis_record_roundtrips_and_has_domain_separated_commitment` compares its encoded bytes byte-for-byte against the checked-in hex fixture.
- `python simulations/verify_cp0384_pcp4_golden_vector.py` independently computes the profile fingerprint, trusted-Genesis fingerprint, record bytes and checksum. The current fixture is 737 bytes; the Python output matches the Rust golden bytes.
- The six focused PCP4 tests cover Genesis and non-Genesis encode/decode round trips, monetary metadata binding to the embedded snapshot, checksum/length/version/flags rejection, network/manifest/profile/Genesis binding, history/genesis consistency, and pre-allocation history range enforcement.
- `cargo fmt --all -- --check` passed on the local Windows checkout.
- `cargo check --lib --locked --offline` passed on the local Windows checkout (with existing unrelated unused/dead-code warnings).
- `cargo test --all-targets --locked --offline -- --test-threads=1` exited 0 on Windows; the library reports 766 passed, 0 failed, in 435.70 seconds. `devnet_node` passed 36/36, `private_testnet_node` passed 36/36, and all other binary, integration/vector and example targets completed successfully. The full process runtime was 626.22 seconds.
- `python simulations/verify_cp0384_pcp4_golden_vector.py` passed: the independent Python encoder reproduced the checked-in 737-byte Rust golden vector exactly.
- The GitHub Actions test matrix for the CP-0384 PR must also pass before merge. Local tests do not constitute independent protocol/security review or production deployment evidence.

## Trust boundary - not a launch feature

PCP4 validation confirms canonical encoding and consistency with the context provided by the caller. It **does not** prove the ancestry or cumulative work of a pruned history suffix. For a non-Genesis checkpoint, nonzero parent commitment and work are only shape constraints; this codec does not authenticate them or reconstruct the missing ancestry. The enclosing system must replay from a trusted origin or verify an explicitly specified, independently provisioned checkpoint authorization and freshness/high-water policy before treating a checkpoint as trusted.

This module is not wired into the existing PFM4 store, a PFM5 store, node startup, branch archive, canonical fork choice, or reorg logic. The checksum is not an independent anti-rollback mechanism. No production CAS provider, signed receipt trust, freshness mechanism, key ceremony, or public listener is added.

- **Gate 2 remains OPEN.** PFM5 and crash-safe durable checkpoint publication; integrated checkpoint-aware archive replay/fork choice/reorg; exact chainwork/ancestry authentication for restored checkpoints; independently reproduced target and issuance boundary vectors; a frozen production Genesis/profile; and independent protocol/economic review remain outstanding.
- **Gate 8 remains OPEN.** Independently operated CAS with server-side atomic generation compare-and-swap, independently pinned receipt signer trust, monotonic rollback protection, and multi-host disk-loss/crash/race/restore qualification remain outstanding.
- **Mainnet and public launch remain unenabled and unclaimed.** This candidate does not raise the existing 1,024 logical-height PFM4 ceiling, so the first default retarget at height 2,017 and halving boundary at 4,204,800 are not made reachable by this change.
- **Owner-funded spend remains USD 0.** No paid hosting, independent review, liquidity, or third-party cost coverage is claimed.