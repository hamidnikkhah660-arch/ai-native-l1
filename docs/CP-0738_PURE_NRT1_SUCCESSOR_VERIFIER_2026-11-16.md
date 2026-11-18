# CP-0738 — Pure NRT1 Exact-Successor Verifier

Date: 2026-11-16  
Project: AI-NATIVE L1 / QRun / QZXB / QFP6  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`  
Status: **PURE NRT1 VERIFIER EXTRACTED / TARGETED REGRESSIONS PASS / NO RECOVERY OR STARTUP INTEGRATION**

## 1. Purpose

CP-0737 made the C-ACTIVE / D-BEHIND state observable as a typed quarantine error, but explicitly did not verify the artifact bytes referenced by the C event. The next prerequisite is a pure verifier for the issuer-signed NRT1 transition, callable without opening or mutating the D high-water store.

## 2. Implementation

Added public pure function:

`identity_generation_store::verify_signed_rotation_statement(...)`

It accepts:
- exact NRT1 wire bytes;
- network, credential, issuer, key and purpose scope;
- exact predecessor generation and KeyRecord digest;
- exact successor generation and KeyRecord digest;
- trusted issuer public key.

It checks:
1. nonzero identity scope and digest inputs;
2. exact one-generation successor using checked arithmetic;
3. NRT1 wire length, magic and version;
4. every encoded scope field and predecessor/successor binding against the supplied values;
5. issuer Ed25519 signature over the existing domain-separated NRT1 wire core.

It performs no filesystem access, state mutation, key generation, or high-water advancement.

Retrospective source correction recorded in CP-0739: the initial CP-0738 extraction did not yet replace the stateful method's inline verifier with a call to this pure function. That delegation is now implemented and regression-tested in CP-0739; this paragraph supersedes the earlier inaccurate statement that delegation was already present at CP-0738.

## 3. Existing NPI1 / dual-attestation verifier audit

The source audit confirms:
- `devnet_signed_peer_identity_candidate::verify_signed_peer_identity` is already public and verifies NPI1's issuer signature, network/issuer binding, and KeyRecord shape. It returns the optional embedded NRT1 bytes, but does not itself verify the NRT1 transition signature.
- At CP-0738, `noise_identity_rotation_authorization::verify_dual_attestation` verified the owner/operator signatures and bound the exact prepared files/evidence/policy/command inputs, but returned `Result<(), String>` and was only `pub(crate)`. CP-0739 exposes a typed result containing intent digest, profile ID, nonce and signer-key fingerprints, and exports the module from the library for one canonical implementation.
- Therefore NPI1, NRT1 and dual attestation are three distinct verification layers. Passing one must not be treated as proof that the other two passed.

## 4. Tests and validation

Commands run:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib identity_generation_store -- --nocapture`

Result: **6 passed, 0 failed**. The new pure-verifier test confirms:
- a valid issuer-signed exact NRT1 predecessor/successor passes;
- changing the expected predecessor digest returns `RotationMismatch`;
- changing the NRT1 signature returns `RotationSignature`.

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_reconciliation -- --nocapture`

Result: **10 passed, 0 failed**. This confirms the stateful store's delegated verifier continues to support the C/D reconciliation and CP-0737 typed quarantine tests.

Also passed:
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all`;
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`;
- `git diff --check` (only existing LF-to-CRLF working-copy notices).

No broad test suite was run.

## 5. Safety and repository boundary

- Tests used synthetic issuer keys and records in isolated temporary directories.
- No real C:/D: store, production identity, private key, wallet, node, listener, testnet or mainnet was accessed or changed.
- No C-to-D recovery write, startup integration, activation, commit, push, merge, PR update or release occurred.
- Work remains in the isolated CP-0704 worktree. The protected main checkout remains separate and untouched.
- CP-0724 through CP-0735 were not rerun.

## 6. Next bounded engineering step

Create a typed, read-only `VerifiedAnchoredSuccessorProof` builder that consumes:
- the CP-0737 C active-event binding;
- D's exact current predecessor binding;
- bounded NPI1 bytes;
- the embedded/external NRT1 bytes;
- trusted network/issuer configuration and verification epoch;
- the complete dual-attestation inputs and independently provisioned owner/operator pins.

It must verify NPI1 signature and record digest, exact NRT1 digest and signature against D's predecessor and C's successor, Noise fingerprint, nonce/intent digest, both signer signatures and pin bindings. It should return a proof object only; no store writes. A separate D recovery writer remains a later, independently reviewed step. Windows namespace/path qualification remains an independent startup blocker.

[executed on device: heymed (9d9913e5-d5eb-4a93-8744-5427303647e3)]
