# CP-0739 — Read-Only Anchored Successor Proof Builder

Date: 2026-11-16  
Project: AI-NATIVE L1 / QRun / QZXB / QFP6  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`  
Status: **READ-ONLY C/D + NPI1 + NRT1 + DUAL-ATTESTATION PROOF BUILDER IMPLEMENTED / POSITIVE AND NEGATIVE TESTS PASS / NO RECOVERY WRITER**

## 1. Purpose

CP-0737 classifies the exact C-ACTIVE / D-BEHIND crash window as a typed quarantine state. CP-0738 extracted the pure NRT1 signature/binding verifier. CP-0739 composes the existing verification layers into a single read-only proof builder, without advancing D or authorizing startup.

## 2. Implementation

Added library module `peer_identity_successor_proof` and public API:

`verify_anchored_successor_proof(vault, generation_store, scope, evidence)`

The builder accepts already-open C/D store handles and bounded in-memory artifacts. It uses only read-only store accessors and checks:

1. The supplied anchor scope is exactly the scope used to open C; D's opened store configuration matches network, key, purpose, credential, issuer and trusted issuer public key.
2. C's latest event is a tail `ROTATION_ACTIVE`; D is initialized and still ACTIVE at the exact predecessor generation and KeyRecord digest.
3. C records the exact one-step successor, predecessor digest, successor KeyRecord digest and nonzero event-chain digests.
4. Previous and successor NPI1 envelopes both verify under the trusted issuer key and expected network/issuer; both records match the configured identity scope and ACTIVE lifecycle.
5. The previous NPI1 KeyRecord digest equals D's high-water digest; the successor record and full NPI1 digest equal C's stored bindings; the Noise public-key fingerprint matches C.
6. The NRT1 bytes embedded in successor NPI1 equal the separately supplied NRT1 bytes, match C's NRT1 digest, and verify as the issuer-signed exact D-predecessor-to-C-successor transition.
7. The successor NPI1 is within its validity window at the supplied verification epoch.
8. Both owner and operator signatures verify over the canonical authorization intent; the resulting intent digest, nonce, signer-key fingerprints and profile ID match C's anchored values and the opened anchor scope.

The proof result carries the exact event sequence/digests, predecessor/successor generations and record digests, profile ID, NPI1/NRT1 digests, Noise fingerprint, intent digest, nonce and signer-pin fingerprints.

## 3. Related implementation corrections

- Added `PeerIdentityAnchorVault::matches_scope` and `IdentityGenerationStateStore::matches_identity_scope` as read-only configuration-binding checks.
- `VerifiedDualAttestation` now returns typed intent digest, profile ID, nonce, owner pin fingerprint and operator pin fingerprint instead of discarding those verified values.
- The dual-attestation verifier is exported as one library module. `devnet_trust_provisioner` now imports that canonical module instead of compiling a second path-local copy.
- Corrected the CP-0738 implementation gap: source reinspection found that the stateful `IdentityGenerationStateStore::verify_rotation_statement` still contained its old inline verifier. It now delegates to the pure `verify_signed_rotation_statement` function. The existing stateful high-water behavior is preserved and covered by regression tests.

CP-0738's checkpoint text has been amended to record this chronology accurately.

## 4. Tests and validation

### Proof-builder integration test

`noise_identity_rotation_authorization::tests::anchored_successor_proof_requires_exact_c_d_npi1_nrt1_and_dual_bindings`

Result: **1 passed, 0 failed**.

The test constructs synthetic issuer-signed predecessor/successor NPI1 artifacts, a valid NRT1 transition, an initialized D high-water store, a C anchor event chain and independently signed owner/operator authorization. It confirms:
- the exact composite proof succeeds;
- a tampered NRT1 is rejected as an artifact-digest mismatch;
- a mismatched anchor scope is rejected;
- an expired successor NPI1 is rejected by the explicit validity-window gate.

All artifacts and signing keys are synthetic and test-local.

### Focused regression suites

- `noise_identity_rotation_authorization`: **15 passed, 0 failed**.
- `identity_generation_store`: **6 passed, 0 failed**.
- `peer_identity_reconciliation`: **10 passed, 0 failed** in the preceding focused run after the proof module and NRT1 delegation were integrated.

### Build and hygiene

- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_trust_provisioner`: **PASS**, exit code 0. Existing crate warnings remain; no new proof-module or verifier compile error was reported.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: **PASS**.
- `git diff --check`: **PASS** (Git reports existing LF-to-CRLF working-copy notices).

No full 1,480+ test suite was run.

## 5. Critical limits — proof is not recovery authorization

The builder is read-only and does not:
- write, repair, copy or advance D's high-water store;
- change C's anchor chain;
- create/activate a key, start a node, open a listener or authorize startup;
- independently validate the DPC1/IRG1 deployment and issuer-registry signatures/status, including their binding to the anchor scope's role and genesis root. Their exact bytes are hash-bound by the dual-attestation intent, but their own trust-chain verification remains a separate prerequisite;
- map the numeric anchor-scope role byte to the signed intent's role label. The profile ID is checked, but this role-code mapping is not yet established by the proof builder;
- establish out-of-band provenance for owner/operator pins. It verifies the signatures and requires the resulting fingerprints to equal the already anchored C values;
- protect the local C event chain or D store against full-machine rollback/deletion. The Windows ACL/namespace qualification and an independently monotonic external trust source remain separate requirements.

The resulting `VerifiedAnchoredSuccessorProof` is evidence for a separately designed and reviewed recovery procedure. It is not a recovery capability or production readiness signal.

## 6. Repository and execution boundary

- All tests used isolated temporary directories and synthetic identity/signing material.
- No real C:/D: identity store, private key, wallet, live node, listener, testnet or mainnet was accessed or modified.
- No startup integration, recovery writer, activation, commit, push, merge, PR update or release was performed.
- Work remains in the isolated CP-0704 worktree; protected main checkout remains separate.
- Pre-existing modified and untracked worktree files were preserved; nothing was staged or cleaned.

## 7. Source hashes (SHA-256)

- `peer_identity_successor_proof.rs`: `92355485A78BEE2DF1A0AC1D4370DE417DE8E11C952460B3F62AAD5697165897`
- `noise_identity_rotation_authorization.rs`: `4D9901049649D6C4929B59E639D9537E966D50D416A407075032E1D62ECFB558`
- `identity_generation_store.rs`: `5D7D3D155210FAAF95EB35ACBC8E36EBB6D1D7E6BDB66CA2069C82B3E56C0DCA`
- `peer_identity_anchor_vault.rs`: `10284619CADFB1EC34C3F8D1B6ADE8AA5589FB32B4D15959AED225D23198EAD8`
- `lib.rs`: `655E9065D38F5A13989E5305A2703FAF209B40EF25AE686166B26479EB97B179`
- `bin/devnet_trust_provisioner.rs`: `CCA3CD0ECD6A45CEDBC0E640EA7E6D6D549C50081AABDD42BA8563B5F398CFE9`

## 8. Next bounded engineering step

Audit and expose read-only verification for the deployment-config and issuer-registry artifacts (DPC1/IRG1), including current issuer status, sequence/transition constraints and trust-root binding. Then bind their verified output to the proof object and add tamper, wrong-root, stale-sequence and revoked-issuer tests.

After that, separately assess how owner/operator pin provenance is provisioned and protected, and whether the C anchor needs an independently monotonic external witness. Do not design or wire a D recovery writer until those checks and Windows namespace/path qualification are independently reviewed.

[executed on device: heymed (9d9913e5-d5eb-4a93-8744-5427303647e3)]
