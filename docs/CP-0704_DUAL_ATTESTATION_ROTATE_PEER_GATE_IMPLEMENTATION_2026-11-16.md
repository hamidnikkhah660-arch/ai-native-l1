# CP-0704 — Dual Attestation and Mandatory `rotate-peer` Gate

Date: 2026-11-16
Status: IMPLEMENTED IN ISOLATED WORKTREE; TARGETED TESTS PASS; NOT COMMITTED OR PUSHED
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`

## Scope completed

This checkpoint implements the dual-attestation control designed in CP-0703 and wires it into the actual `devnet_trust_provisioner rotate-peer` command. The original active checkout and its uncommitted files were not changed.

### Deterministic signed intent

- Added `src/native/pow_bench/src/noise_identity_rotation_authorization.rs`.
- The authorization intent uses a fixed, versioned, length-delimited binary encoding with domain `QFP6-NOISE-ROTATION-INTENT\0v2`; signatures are not over a reserialized JSON object.
- The independent operator signs the intent digest under `QFP6-ROTATION-OPERATOR-SIGNATURE\0v1`.
- The owner signs the same digest plus the operator public-key fingerprint and operator-signature digest under `QFP6-ROTATION-OWNER-SIGNATURE\0v1`.
- Owner and operator public keys must be different and each must match its independently supplied SHA-256 fingerprint pin.

### Mandatory command integration

`rotate-peer` now requires all of the following inputs before it can write a new NPI1 artifact:
- prepared rotation manifest;
- prepared new identity JSON and prepared previous identity JSON (separate from the binary previous NPI1 file);
- endpoint evidence, fingerprint evidence, and exact rotation-policy files;
- v3 authorization intent JSON;
- independent operator public key, fingerprint pin, and signature;
- owner public key, fingerprint pin, and signature.

The v3 verifier binds the authorization to the actual bytes of DPC1, IRG1, previous NPI1, manifest, both prepared identity JSON files, endpoint evidence, fingerprint evidence, and policy. It also binds the NPI1 `not_before` and `not_after` arguments as explicit unsigned fields in the canonical signed intent, alongside network, issuer, generation successor, role/profile, old and new public-key fingerprints, prepared identity hashes, zero-value Public Testnet scope, endpoint shape, evidence digests, rollback window, nonce format, signer identity distinction, and authorization validity period. Changing either NPI1 validity bound after signing is rejected.

The verified public key in the prepared previous identity must equal the public key verified from the actual previous NPI1. The prepared new identity public key must equal the requested new Noise key. The manifest generation must equal the actual NPI1 successor generation.

All input files are read through the existing bounded regular-file/non-symlink reader. The final output uses the existing `create_new` writer, so an existing output path is never overwritten. Dual-attestation verification occurs before the output write.

### Follow-on parser and output hardening

- Added direct `serde = 1.0.229` dependency, already present in the lockfile.
- Replaced permissive `serde_json::from_slice::<Value>` calls for the four security-sensitive documents (manifest, prepared identity, prepared previous identity, and dual authorization) with a recursive duplicate-key rejecting parser.
- The parser rejects duplicate object keys at any nesting level and rejects trailing data after the JSON document.
- Added tests for top-level duplicate keys, nested duplicate keys, valid nested JSON, and trailing data.
- Added a test proving `write_new_file` refuses to overwrite an existing output and preserves its exact bytes.
- The older standalone v1 verifier is explicitly labeled owner-only preflight and reports that independent operator attestation is not verified; it cannot authorize `rotate-peer`.

## Validation

- `cargo fmt --all -- --check`: PASS.
- `cargo check --bin devnet_trust_provisioner`: PASS.
- `cargo test --bin devnet_trust_provisioner -- --nocapture`: PASS, 20 passed, 0 failed.
- `cargo test --bin noise_identity_rotation_authorization_verify -- --nocapture`: PASS, 6 passed, 0 failed.
- Authorization tests cover valid dual signatures, operator-signature tampering, owner-signature tampering, same signer key rejection, signer pin mismatch, and signed NPI1 validity-window binding, DPC1/command-input digest mismatch, previous prepared identity hash mismatch, old key/NPI1 mismatch, endpoint/policy evidence byte mismatch, expiry, duplicate JSON keys, and trailing JSON data.
- Existing provisioner tests cover bootstrap artifact verification, peer artifact tamper/network/issuer rejection, monotonic terminal issuer status, exact-successor peer rotation/high-water persistence, and no-overwrite output behavior.
- `git diff --check`: PASS.

Warnings from unrelated existing library modules remain; this checkpoint did not modify those modules.

## Explicitly not completed / remaining gates

1. **Replay persistence is not implemented.** The signed intent requires a nonzero nonce, but this code does not maintain a durable replay registry. Safe replay rejection requires the independent monotonic anchor decision and recovery model; a local file alone must not be represented as rollback-resistant.
2. **Independent monotonic identity anchor is not implemented.** The existing QFP6 Anchor Vault is not yet bound to this peer identity generation. Choose and qualify an independently administered remote append-only witness or an appropriate hardware monotonic facility before claiming host-loss/two-disk rollback resistance.
3. **Handler-level `rotate-peer` integration fixture is now implemented.** The test calls the real `rotate_peer` handler, loads synthetic DeploymentAuthority and PeerIssuer seeds from temporary Windows CurrentUser DPAPI ASK1 files, reads signed disposable DPC1/IRG1/NPI1 plus authorization evidence from temporary regular files, and verifies successful successor NPI1 creation. It also proves missing operator signature, invalid operator signature, invalid owner signature, same signer key, changed NPI1 validity after signing, and existing-output overwrite all fail closed. This does not launch the compiled executable as a separate OS process with argv; that outer process dispatch is not separately tested.
4. Evidence and policy files are bounded and their exact bytes are signed by digest, but this implementation does not independently perform external endpoint reachability or fingerprint discovery. Those facts remain operator attestations whose signer must be independently qualified.
5. **Provenance of signer pins remains an external trust requirement.** The verifier checks operator/owner public keys against the supplied SHA-256 fingerprints, but this command does not itself authenticate where those pin values came from or persist them in a separately protected trust store. The executor must obtain and verify both fingerprints through an independent trusted channel; supplying attacker-chosen keys, pins, and signatures together does not establish signer identity.
6. Independent reviewer approval and review of this wire contract remain required.

## Safety boundary

- No production or user private key was read, generated, exported, or rotated. Deterministic synthetic deployment/issuer keys were stored only in unique temporary DPAPI ASK1 test files and loaded through the real handler; synthetic operator/owner keys were used only to sign the disposable test authorization.
- No owner/operator authorization was issued.
- The integration test wrote one synthetic successor NPI1 only inside its unique OS temporary test directory, verified it, then removed the directory. No project, user, production, or deployment NPI1 output path was written.
- No node was started; no listener was opened; no public testnet or mainnet was deployed.
- No commit, push, PR update, or merge was performed.
- Active source checkout `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111` remains untouched by this implementation.

## Next step

Resolve the independent monotonic peer-identity anchor and durable replay-persistence architecture before claiming rollback or replay resistance. The anchor must be independently administered or hardware-backed with a documented recovery model; a local second file or second disk is insufficient against whole-host/two-disk rollback. Add session-drain or bounded-session-lifetime behavior to the rotation rollout design before activation.


## Recovery / superseding status (2026-11-16)

**Historical recovery note (superseded by the verification below):** during a subsequent editing attempt, `src/native/pow_bench/src/bin/devnet_trust_provisioner.rs` was truncated in the CP-0704 isolated workspace. It was restored byte-for-byte from the original active checkout copy (`D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111\src\native\pow_bench\src\bin\devnet_trust_provisioner.rs`). At that intermediate point, the `rotate-peer` CLI was not wired to invoke the verifier. The connection has since been rebuilt and validated as documented in the superseding status below.

The original active checkout was not modified by this recovery. At that intermediate point no production key operation or user NPI1 output occurred; the later synthetic test output is described below. No node start, listener, or deployment occurred. Treat the earlier “implemented mandatory rotate-peer gate” statements above as superseded by the latest verified status below.


## Latest reimplementation and validation (2026-11-16, supersedes prior recovery note)

The `rotate-peer` execution path has now been rebuilt in this isolated worktree. It requires the prepared manifest, prepared new/previous identity JSON, endpoint/fingerprint evidence, exact policy, v3 authorization, separate operator and owner public keys, SHA-256 pins, and both signatures. All evidence inputs are bounded regular non-symlink files. The real handler calls the dual-attestation verifier and writes the NPI1 output only after both independent signatures and all actual input bindings pass. The output writer still uses create-new semantics.

Validation after reimplementation:
- `cargo check --bin devnet_trust_provisioner`: PASS.
- `cargo test --bin devnet_trust_provisioner -- --nocapture`: PASS, 20 passed, 0 failed.
- `cargo test --bin noise_identity_rotation_authorization_verify -- --nocapture`: PASS, 6 passed, 0 failed.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.

The new handler-level integration test stores deterministic synthetic deployment and issuer keys in temporary Windows CurrentUser DPAPI ASK1 files, loads them through the production handler, and uses temporary synthetic DPC1/IRG1/NPI1, evidence and authorization files. It confirms valid rotation generation 1→2; rejection without output for a missing operator signature, invalid operator/owner signatures, a shared signer key, and a changed NPI1 validity bound after signing; and refusal to overwrite an existing output while preserving its exact bytes. The synthetic output is verified and deleted with the test directory. The compiled executable's outer process/argv dispatch is not separately exercised.

No production/user private key, owner authorization, or real rotation was used. No node/listener was started; no testnet/mainnet activation occurred. The original active checkout `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111` was not modified. No commit, push, PR update, or merge occurred.

Still open: durable replay protection; independently administered/hardware monotonic identity anchor with recovery design; out-of-band provenance and protected persistence for signer pins; external qualification of endpoint/fingerprint evidence; session-drain or bounded-session-lifetime rollout policy; and independent review. The nonce is validated but not persisted; no rollback/replay resistance claim is made.
