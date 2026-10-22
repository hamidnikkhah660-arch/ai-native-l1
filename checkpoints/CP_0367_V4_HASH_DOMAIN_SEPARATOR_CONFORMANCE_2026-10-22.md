# CP-0367 — V4 Hash-Domain Separator Conformance

Date: 2026-10-22
Base: `main` at `1862dc2144d1a3992681c6de17e8b1be5a317e60`
Scope: candidate-only V4 transaction and monetary block identifier correctness; no production activation.

## Finding

The MBK4 block-ID and TXN4 transaction-ID hash calls used Rust byte-string literals with `\\0` in the source. In Rust this encodes a literal backslash byte followed by ASCII `0`, not a single NUL byte as used by the other versioned domain separators. This was a domain-separation mismatch in the candidate implementation.

## Change

- Both MBK4 block-ID call sites now use the single NUL-terminated `AIN1-MONETARY-BLOCK-ID-V4` domain.
- TXN4 duplicate detection now calls one shared helper using the single NUL-terminated `AIN1-TXN4-ID-V4` domain.
- A regression test independently computes the expected SHA-256 preimages for both IDs, rejects the old literal-backslash-zero encodings, and verifies the applied block's hash equals the canonical MBK4 ID function.

## Qualification boundary

This corrects V4 candidate hash-domain construction only. It changes candidate MBK4 block IDs and TXN4 duplicate-detection IDs relative to the faulty candidate code; it is not an activated chain migration and must not be applied to any assumed production history. No production profile is frozen by this checkpoint.

Gate 2 and Gate 8 remain OPEN. Canonical production Genesis/issuance integration, independent client/operator conformance and review remain required for Gate 2. Gate 8 still requires a deployed independently administered CAS trust service, out-of-band reviewed receipt-key pin, canonical runtime wiring, independent-host and power-loss qualification, and external security review. No paid service, owner spend, Mainnet or public value-bearing deployment is claimed.

## Local validation (Windows owner checkout)

- Focused `v4_block_and_transaction_ids_use_nul_terminated_domains`: PASS, 1/1.
- All `state_machine::` tests: PASS, 49/49, including MBK4 codec/atomicity and the new domain-separator regression.
- `cargo check --all-targets --locked --offline`: PASS.
- `cargo fmt --all -- --check`: PASS.
- CP-0361 independent snapshot oracle: PASS.
- CP-0366 independent integer-issuance oracle: PASS, 17 frozen candidate vectors.
- `git diff --check`: PASS before staging.

PR CI, Windows loopback qualification after the hash change, and the canonical-index checksum rebuild remain to be recorded before merge. This checkpoint is not Mainnet conformance evidence.
