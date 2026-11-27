# CP-0767 — QAR2/QBT1 Noise v2 and bounded Anchor daemon
Date: 2026-11-18
Project: QRun / QFP6 / QZXB
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116
Observed HEAD before/after: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3

## Disposition

**QAR2/QBT1 NOISE V2 LOOPBACK AND BOUNDED DAEMON CANDIDATE IMPLEMENTED / TARGETED TESTS PASS / BIN CHECK PASS / NOT YET CONNECTED TO QFP6 STARTUP / GATE 8 OPEN**

This checkpoint extends CP-0765 and CP-0766. It does not change QAR1 V1, does not claim live cloud deployment, and does not authorize Mainnet/public launch.

## Changes

### New versioned transport
Added:
- src/native/pow_bench/src/external_cas_offhost_anchor_noise_v2_candidate.rs

The candidate provides:
1. A QAR2/QBT1-specific Noise profile derivation. The profile binds the exact QBT1 receipt digest, Provider/Anchor/network/Genesis identities, receipt-key IDs and full ML-DSA public-key fingerprints.
2. A separate frame namespace and version: Q2RQ/Q2RS, wire version 2. QAR1's QARQ/QARS version-1 framing is not accepted by this handler.
3. NoiseTcpQar2OffhostAnchorTransport for challenge-bound Read and CAS. It decodes QAR2, checks the exact VerifiedBootstrapTrust capability, verifies the outer Anchor signature, and verifies the operation-specific inner QAR1 receipt before returning.
4. serve_qar2_offhost_anchor_noise_connection, which accepts only Q2RQ version 2 and emits only Q2RS/QAR2 responses.
5. QAR2Qap1AnchorTransport implementing the existing QRunV06Qap1AnchorTransport seam. Its Read/CAS methods verify the QAR2 outer receipt and exact QBT1 binding before exposing the already signed inner QAR1 receipt to the existing QAP1 coordinator.
6. No automatic QAR1 negotiation, fallback, or downgrade path.

### Bounded daemon integration
Updated:
- src/native/pow_bench/src/external_cas_offhost_anchor_noise_daemon_candidate.rs

The existing bounded daemon now has two explicit service variants:
- Qar1: the pre-existing compatibility path, unchanged in behavior.
- Qar2: the QBT1-bound service plus its sealed VerifiedBootstrapTrust capability.

The existing bind constructor remains the QAR1 path. A new explicit bind_qbt1 constructor checks service pins, QBT1 receipt digest, and the QAR2/QBT1 Noise profile before opening the listener. The bounded worker pool selects the handler from the explicit service variant. Worker/queue limits, shutdown and join accounting remain shared with the existing daemon lifecycle.

A wrong pin/service combination is rejected before listener bind. QAR2 is not inferred from the presence of a legacy QAR1 endpoint.

### Module registration and test seam
- Registered external_cas_offhost_anchor_noise_v2_candidate in src/native/pow_bench/src/lib.rs.
- Added a cfg(test)-only QAR2BoundAnchorService::from_test_model constructor for isolated deterministic fixtures. It is not a production constructor and is unavailable outside test builds.

## Verification on heymed

Device: heymed
Device ID: d350fcce-b411-45dd-b2ff-568acbef16dc

Targeted test results:
- external_cas_offhost_anchor_noise_v2_candidate: 5 passed, 0 failed.
  - QAR2 Read with exact QBT1 capability.
  - QAR2 CAS and subsequent QAR2 Read.
  - QAR1 client rejected by QAR2 server.
  - QAR2 client rejected by QAR1 server.
  - QAP1 adapter exposes inner QAR1 only after QAR2/QBT1 verification.
- external_cas_offhost_anchor_noise_daemon_candidate: 20 passed, 0 failed.
  - Includes new QBT1-bound QAR2 daemon loopback, rejection of mismatched service/pins before listener bind, successful QAR2 Read, and shutdown with zero active workers.
  - Existing bounded QAR1 daemon lifecycle, overload, panic, signal, durable restart and shutdown tests also passed.
- cargo check --bins: passed; exit code 0.
- cargo fmt --all -- --check: passed.
- git diff --check: passed.

These are targeted module tests and a binary compile check, not a full project-wide test suite.

Source hashes (SHA-256):
- external_cas_offhost_anchor_noise_v2_candidate.rs: 8D03D3B4AEBB1A6BE8533D6DAFE7F0B2E41286F8968B882F8B52FAF242629A7B
- external_cas_offhost_anchor_noise_daemon_candidate.rs: F823ADA91E497B37C2E19D79696577D2715FF80EB1BE44AADE30D25E607104F1
- external_cas_offhost_anchor_protocol_v2_candidate.rs: E39AD352B85E893AD045681AD993D746DE0A95763FE6302F36B2F994A8C00FD2
- lib.rs: 661756C46C3324EF7C341FD6D9E056CAC3E5D34228F7BBF0227C26C2E632D9B1

Existing warnings remain in older modules/binaries, including unused/dead-code warnings for the AWS CLI runner and unrelated legacy modules. No warning was promoted to an error.

## Startup and trust boundary — intentionally not claimed complete

The existing QFP6 node entry points remain QAR1 callers:
- src/native/pow_bench/src/bin/qrun_v06_node.rs
- src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/mod.rs

They still construct NoiseTcpOffhostAnchorTransport and pass it to QRunV06Qap1ExternalCoordinator. This checkpoint adds a QAR2 transport adapter that can satisfy the coordinator trait, but it does not yet change those production-shaped startup callers to instantiate that adapter.

CP-0761 was re-read before deciding this boundary. It states that BootstrapTrustPin is an independently supplied out-of-band input and is not decoded from QBT1. The verifier also requires:
- the exact generation-zero ECR1 bootstrap record;
- Provider and Anchor pins;
- the expected complete QBT1 receipt digest;
- profile digest and initial ECR1/Anchor-state digests;
- separately pinned owner and independent-custodian identities/public keys.

Therefore a QBT1 capability cannot safely be created by reading QBT1 bytes alone, by deriving pins from the same untrusted config, or by trusting a mutable local directory. The existing qrun_v06_node CLI externally pins the complete config bytes using --config-sha256, which may be part of a future authenticated bundle design, but CP-0767 does not silently assume that the trust-pin provenance problem is solved.

Before changing QFP6 startup, a reviewed, versioned trust-bundle contract must define:
1. Exact serialization and independent pinning of BootstrapTrustPin, Provider/Anchor pins and the generation-zero ECR1 bootstrap record.
2. The precise relationship between QBT1 profile_digest and the current Q6PN/profile identity. Do not assume they are equal without an explicit contract.
3. A separately authenticated delivery path and signer/custodian provenance for the bundle, with no first-read enrollment.
4. Explicit QAP1 mode selection: QBT1-bound mode must construct QAR2Qap1AnchorTransport and must fail closed if only a QAR1 endpoint responds. No automatic fallback.
5. Runtime tests for cold start, wrong trust bundle, wrong Genesis/profile, wrong Anchor/Provider keys, QAR1 downgrade, replay, restart and an independent witness rollback attempt.

The current QAR2 daemon test uses deterministic unit-test keys and an in-memory anchor model. It proves the versioned network contract and bounded lifecycle locally; it does not prove real independent custody or a deployed external Anchor service.

## Cloud, Gate 8 and launch status

No AWS account, role, table, credentials, endpoint, KMS key or cloud resource was accessed or modified. No real independent owner/custodian ceremony occurred. No off-host AWS QAR2 Read/CAS was performed. The existing AWS CLI qualification boundary still has its documented time-of-check/time-of-use limitation.

Gate 8 remains **OPEN**. Still unproven:
- independently authenticated QBT1 pin delivery and real custodian provenance;
- QAR2 caller activation in QFP6 startup;
- a separately administered live Anchor service and real AWS deployment;
- session-bound AWS identity/endpoint assurance;
- independently administered monotonic/CAS witness and whole-host rollback resistance;
- full crash/power-loss/restart and independent recovery qualification;
- external security review.

Mainnet/public launch remains **NO-GO**. This CP does not close consensus/Genesis, complete-node, history/anchor, public multi-operator Devnet, legal/economic or wallet/explorer readiness gates.

## Git safety

- HEAD remained 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3.
- No files were staged.
- No commit, push, merge, reset, clean, stash or checkout was performed.
- Existing modified and untracked worktree contents were preserved.
- This is an untracked checkpoint document, not a release or Gate 8 closure.
