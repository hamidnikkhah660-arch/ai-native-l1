# CP-0752 — STB1 pure signer-trust-bundle codec and verifier

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: \`feat/cp0704-dual-attestation-rotation-gate-20261116\`
Worktree: \`D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116\`
Baseline HEAD: \`5aba5f69d24fce03af742fd1bebf13ad00e5d9c3\`
Disposition: PURE STB1 SUCCESSOR CODEC/VERIFIER IMPLEMENTED; TARGETED TESTS PASS; NO STORE, ENROLLMENT, PROVISIONER, OR NODE INTEGRATION; NO COMMIT/PUSH.

## 1. Scope and decision

CP-0752 implements a bounded canonical STB1 successor-bundle wire codec, strict verifier, and signer-acceptance receipt verifier.

The implementation consumes a \`VerifiedDeploymentConfig\` that can be used for STB1 only when it carries proof that it came from \`verify_signed_deployment_config_with_floors\` with a nonzero independently supplied Governance-root epoch floor. A result produced through the legacy compatibility verifier is rejected for STB1 verification.

This checkpoint deliberately does not implement:
- first-time signer enrollment or initial trust-root ceremony;
- a persistent STB1 sequence/digest high-water store;
- bundle-history replay, signer-generation monotonicity, or retirement/revocation transition-state comparison against the previous bundle;
- real signer-key generation, custody, provisioning, or enrollment;
- independent human/organizational operator verification;
- changes to the trust provisioner, peer-rotation CLI, PIV2, node startup, or runtime;
- Windows ACL, reparse-point, volume identity, crash/power-loss, or remote-witness qualification.

The source module is library-exported for tests and future review only. It has no production caller.

## 2. Canonical STB1 v1 envelope

All integers use big-endian fixed-width encoding. JSON is not used as signed wire data.

### 2.1 Header (154 bytes)

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic \`STB1\` |
| 4 | 2 | Version = 1 |
| 6 | 2 | Reserved; must be zero |
| 8 | 32 | Network ID |
| 40 | 32 | Profile ID |
| 72 | 8 | Bundle sequence |
| 80 | 32 | Previous bundle SHA-256 digest |
| 112 | 8 | Current Governance-root epoch |
| 120 | 32 | SHA-256 fingerprint of the current GRC1 tip key |
| 152 | 2 | Signer-record count |

The profile ID is checked against a separately supplied expected profile because DPC1 v1 does not carry a profile ID. The verifier never treats the profile named by STB1 as its own trust anchor.

### 2.2 Signer record

Each record is length-bounded and has this canonical field order:
- one-byte signer-ID length, followed by 1–64 ASCII bytes;
- one-byte role;
- one-byte scope;
- 8-byte nonzero signer generation;
- 32-byte Ed25519 public key;
- 32-byte SHA-256 fingerprint of those exact public-key bytes;
- one-byte lifecycle;
- 8-byte activation Governance-root epoch;
- 8-byte activation bundle sequence;
- 8-byte terminal Governance-root epoch;
- 8-byte terminal bundle sequence;
- 64-byte signer-acceptance Ed25519 signature.

Role codes:
- \`1 = OwnerAuthorizer\`
- \`2 = IndependentOperator\`

Scope:
- \`1 = PeerIdentityRotation\`

Lifecycle codes:
- \`1 = Active\`
- \`2 = Retired\`
- \`3 = Revoked\`

Records must be sorted in strictly increasing signer-ID byte order. IDs are lowercase ASCII letters, digits, dot, underscore, or hyphen; the first byte must be a lowercase letter or digit. Unknown role, scope or lifecycle codes, invalid keys, zero generations, malformed lifecycle coordinates, duplicate IDs, duplicate fingerprints, or noncanonical record order reject.

A valid successor bundle must contain exactly one active owner authorizer and at least one active independent-operator record. Fingerprints must be unique across all included records, not only currently active records.

Active records require both terminal coordinates to be zero. Retired/revoked records require both terminal coordinates to be nonzero and not earlier than their activation coordinates. A signer acceptance receipt binds the stable signer assignment and activation coordinates but intentionally excludes lifecycle fields; the Governance-root signature authenticates the full lifecycle state.

### 2.3 Signatures and digest

Bundle signature domain:
\`QFP6-SIGNER-TRUST-BUNDLE\\0v1\`

Signer-acceptance domain:
\`QFP6-SIGNER-TRUST-ACCEPTANCE\\0v1\`

Both use Ed25519 strict verification. The bundle digest is SHA-256 over the complete signed STB1 bytes. The signer fingerprint is SHA-256 over the exact 32-byte Ed25519 public key.

The Governance-root signature is verified against the current key from the verified GRC1 chain inside the strict DPC1 context. The STB1 header's root epoch must exactly equal the verified GRC1 tip epoch, and its root fingerprint must exactly equal the SHA-256 fingerprint of that tip key.

## 3. Trust and sequence binding

The verifier requires all of the following independent inputs:
- a strict \`VerifiedDeploymentConfig\` with a nonzero external minimum root-epoch marker;
- expected profile ID;
- expected previous bundle sequence;
- expected previous bundle digest.

It checks that:
- STB1 Network ID equals the strict DPC1/GRC1 context network;
- profile ID equals the independently supplied expected profile;
- the GRC1 current root meets the strict external root-epoch floor;
- STB1 root epoch and fingerprint exactly match the GRC1 tip;
- new bundle sequence is exactly previous sequence + 1, using checked addition;
- previous digest exactly equals the externally supplied prior digest.

A zero previous sequence, zero prior digest, or zero predecessor in the bundle is rejected as \`InitialEnrollmentRequiresSeparateAuthorization\`. This is intentional: an empty directory or a self-selected first record must not establish trust by itself.

The strict-verifier provenance marker is held in a crate-private field on \`VerifiedDeploymentConfig\`. The legacy compatibility verifier sets it to \`None\`; only the strict external-floor verifier sets it to \`Some(minimum_root_epoch)\`.

## 4. Implementation files

- \`src/native/pow_bench/src/signer_trust_bundle.rs\` — new pure STB1 model, canonical encoder, verifier, acceptance-message builder, and synthetic-key tests.
- \`src/native/pow_bench/src/lib.rs\` — exports the module with an explicit comment that it has no enrollment store or runtime caller.
- \`src/native/pow_bench/src/noise_deployment_config.rs\` — records whether the returned DPC1 context came from the strict external-floor API; compatibility verification leaves the marker unset.

No dependency was added for STB1. The existing Ed25519 and SHA-256 dependencies are reused.

## 5. Test evidence

### 5.1 STB1 tests

Command:
\`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib signer_trust_bundle::tests:: -- --nocapture\`

Final result after the test-fixture and parser-order corrections:
- 12 passed
- 0 failed
- 0 ignored

Coverage includes valid successor round-trip, legacy-context rejection, initial-enrollment refusal, network/profile/root-context mismatches, predecessor digest and sequence enforcement, active-role requirements, duplicate IDs/fingerprints, signer receipts and fingerprints, canonical identifiers/order, lifecycle-coordinate validation, retired-record receipt preservation, reserved bits, malformed/truncated/trailing data, and tampered bundle signatures.

The first run exposed two test/validation-order issues (10 passed, 2 failed). The missing-operator fixture was changed to retain a valid retired operator record, and the verifier now parses exact record framing before signature classification. The final targeted run passed all 12 tests.

### 5.2 DPC1/DCS1 regression

Command:
\`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_deployment_config::tests:: -- --nocapture\`

Result:
- 6 passed
- 0 failed

This includes strict independent root-epoch floor enforcement, DCS1 v2 root-epoch high-water, DCS1 v1 exact-current migration, and existing deployment sequence/digest high-water checks.

### 5.3 Additional checks

- \`cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check\`: PASS.
- \`git diff --check\`: PASS. Git printed existing LF-to-CRLF normalization warnings for modified working-copy files; no whitespace error was reported.
- \`cargo check --manifest-path src/native/pow_bench/Cargo.toml --lib\`: PASS, exit code 0. The library build emitted 10 unused-import/dead-code warnings in existing candidate modules; no compile error occurred.
- The full library test suite was not run as part of CP-0752.

## 6. Security interpretation and remaining gaps

A successful synthetic test proves deterministic codec and signature-verification behavior for the exercised cases. It does not prove the existence or independence of a real owner/operator, production custody, or an external trust ceremony.

The verifier validates a successor against caller-supplied expected predecessor sequence/digest, but there is not yet a persistent STB1 high-water store or a complete previous-bundle transition verifier. In particular, it does not yet prove historical generation monotonicity or prevent a governance-authorized signer lifecycle from being reintroduced incorrectly across a longer bundle history. These are later state/chain responsibilities, not claims of this pure codec checkpoint.

No claim is made that two distinct Ed25519 keys are controlled by different people or organizations. A genuinely separate operator and signed acceptance in an independent custody domain are still required before any real enrollment.

No real private key, owner pin, operator pin, PIV2 directory, production trust directory, node, listener, wallet, asset, liquidity pool, or public service was created or modified by this checkpoint. Test signing keys are deterministic synthetic fixtures only.

## 7. Repository state and gate disposition

- Branch remains \`feat/cp0704-dual-attestation-rotation-gate-20261116\`.
- HEAD remains \`5aba5f69d24fce03af742fd1bebf13ad00e5d9c3\`.
- No files were staged.
- No commit, push, PR update, merge, reset, checkout, clean, stash, or worktree cleanup was performed.
- The primary checkout at \`C:\Users\ASUS\Desktop\AI_NATIVE_L1\` was not changed by CP-0752.
- Existing working-tree changes from prior isolated checkpoints remain in place; the CP-0752 source and document are additions to that cumulative worktree state, not a clean isolated diff against HEAD.

Disposition:
- STB1 bounded canonical successor codec: IMPLEMENTED / TARGETED-TESTED.
- STB1 pure strict verifier against strict DPC1/GRC1 context: IMPLEMENTED / TARGETED-TESTED.
- Signer-acceptance receipt verification: IMPLEMENTED / TARGETED-TESTED.
- Initial trust enrollment policy and ceremony: NOT IMPLEMENTED.
- Persistent STB1 high-water and full history/generation transition verifier: NOT IMPLEMENTED.
- Real independent owner/operator: NOT ENROLLED / NOT VERIFIED.
- Provisioner/PIV2/node runtime integration: NOT IMPLEMENTED.
- Windows ACL/path/reparse/volume/crash qualification: NOT COMPLETE.
- Gate 8: OPEN.

Next safe checkpoint should address the append-only STB1 chain/high-water and exact predecessor transition invariants using synthetic test roots and isolated temporary storage, without enrolling real signers or wiring production runtime. Gate 8, mainnet, public token release, liquidity, trading, and mining remain NO-GO pending their separate evidence gates.

[executed on device: heymed (de0adbe3-6583-4775-a26e-c479a62aa941)]
