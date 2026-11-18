# CP-0765 — QAR2 QBT1-bound signed Anchor receipt candidate

Date: 2026-11-17
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD observed before this work: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Scope

Introduce a versioned QAR2 envelope without changing the existing QAR1 V1 wire format or verifier. QAR2 carries the exact canonical QAR1 receipt wire and the digest of a previously verified QBT1 bootstrap receipt. The outer QAR2 payload is separately signed with the pinned Anchor ML-DSA-65 receipt key.

## Implementation

- Added `external_cas_offhost_anchor_protocol_v2_candidate.rs` and registered it as a library module.
- `QAR2BootstrapBoundReceipt::new` accepts `VerifiedBootstrapTrust`, not a caller-provided digest, and binds `receipt_digest()`.
- The canonical QAR2 payload contains magic/version/reserved bytes, the nonzero QBT1 receipt digest, and the complete fixed-length QAR1 V1 wire. The outer signature covers the QAR2 domain and complete payload.
- Decode enforces exact length, magic, version, reserved bytes, nested QAR1 canonical decoding, and byte-for-byte canonical re-encoding.
- `verify_read` and `verify_cas` require `VerifiedBootstrapTrust`, compare the embedded digest with its verified receipt digest, verify the outer Anchor signature, then run the existing QAR1 operation-specific verifier.
- QAR1 V1 implementation and wire format were not modified. There is no automatic downgrade path inside the QAR2 verification methods.

## Verification evidence

- QAR2 targeted tests: **4 passed, 0 failed**. Includes canonical round-trip, nested QAR1 byte preservation, outer-signature coverage of both QBT1 digest and inner receipt, zero-digest/header rejection, and successful read verification using an actual test-only `VerifiedBootstrapTrust` capability. A re-signed QAR2 with a substituted QBT1 digest is rejected.
- Existing QAR1 protocol regression tests: **12 passed, 0 failed**.
- Existing QBT1 bootstrap trust tests: **10 passed, 0 failed**.
- `cargo fmt --all -- --check`: passed.
- `cargo check --bins`: passed.
- `git diff --check`: passed.

These are targeted local tests and compile checks, not a full workspace test run. Existing unused/dead-code warnings remain.

## Explicitly not proven / remaining work

- QAR2 is a protocol candidate; no production service, wallet, startup path, or caller has been switched to require QAR2.
- The DynamoDB adapter does not yet persist and return QAR2 receipt envelopes as its authoritative read/CAS response contract. QBT1 binding in the current adapter remains the CP-0762 metadata binding.
- No live AWS account, role, table, KMS key, endpoint, or independent operator was used. No AWS CLI/SDK runtime qualification is claimed.
- The preflight/CLI split and its TOCTOU/effective-IAM limitations from CP-0764 remain.
- The test QBT1 keys and Anchor keys are deterministic fixtures; they do not prove real independent human custody, external root enrollment, or production key isolation.
- No anti-rollback claim is made against whole-machine rollback or a malicious administrator. Independent monotonic witness/CAS deployment and authenticated operator custody remain open.
- QAR1 remains available as a legacy API. Production mode selection must explicitly require QAR2 when QBT1 trust is configured and reject downgrade; this caller-level policy is not implemented here.

## Gate impact

This closes only the local protocol-candidate slice: a QAR2 receipt can cryptographically bind an exact verified QBT1 digest and a complete signed QAR1 operation receipt. It does **not** close Gate 8, does not qualify the AWS deployment, and does not authorize public/mainnet launch.

## Source hash

`external_cas_offhost_anchor_protocol_v2_candidate.rs` SHA-256: `A8FAE84B60635FDE8C643ADBB7ADCCB19ACAC1AB84992A7BDA1A2F7B71E7CFBE`

