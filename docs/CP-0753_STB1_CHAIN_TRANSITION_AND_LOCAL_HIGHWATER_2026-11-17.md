# CP-0753 — STB1 successor transitions and local high-water state

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: \`feat/cp0704-dual-attestation-rotation-gate-20261116\`
Worktree: \`D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116\`
Baseline HEAD: \`5aba5f69d24fce03af742fd1bebf13ad00e5d9c3\`
Disposition: STB1 HISTORY-SENSITIVE SUCCESSOR RULES AND LOCAL STH1 HEAD STORE IMPLEMENTED; TARGETED TESTS PASS; NO REAL ENROLLMENT; NO PROVISIONER/NODE INTEGRATION; NO COMMIT/PUSH.

## 1. Scope

CP-0753 extends CP-0752's pure STB1 successor codec/verifier with:
1. A transition verifier comparing a fully verified successor against the exact previously verified bundle.
2. Role-generation uniqueness and monotonic generation rules.
3. A bounded local STH1 high-water state envelope that stores the last accepted signed STB1 wire and digest.
4. Restart, replay, same-sequence conflict, missing-state, corruption, lifecycle, identity-substitution, and generation-transition tests using deterministic synthetic test keys and temporary directories.

The implementation does not perform first-time owner/operator enrollment. The state store requires an already verified checkpoint from its caller. That checkpoint must itself have been authorized through a separate, reviewed initial-enrollment process; CP-0753 does not implement or prove that ceremony.

No real key, signer identity, owner/operator pin, production directory, PIV2 state, node, listener, provisioner operation, wallet, token, liquidity pool, or public service was created or changed by CP-0753.

## 2. History-sensitive STB1 successor policy

New API:
\`validate_signer_trust_bundle_transition(previous, next)\`

Both arguments must already be verified STB1 objects. This function adds checks that cannot be established by verifying each signed bundle independently.

### 2.1 Bundle sequence and predecessor link

- Network ID and Profile ID must remain identical.
- The successor sequence must equal the previous sequence plus exactly one, using checked arithmetic.
- The signed successor predecessor digest must equal the SHA-256 digest of the exact previously verified bundle.
- A lower sequence is a rollback.
- A skipped sequence is a discontinuity.
- Same-sequence/same-digest retry is handled idempotently by the local store; same-sequence/different-bytes is a conflict.

### 2.2 Governance-root context

- The successor Governance-root epoch may not decrease.
- This checkpoint deliberately rejects any root epoch or fingerprint change during an ordinary STB1 transition with \`GovernanceRootContextChangeRequiresMigration\`.
- A root rotation requires a separate, reviewed migration design; it is not silently accepted as an ordinary signer update.
- The STH1 reopen path also compares the persisted root epoch/fingerprint to the currently verified DPC1/GRC1 context. A lower current epoch is reported as root rollback; a changed root context requires migration.

This is intentionally conservative and does not claim that STB1 state migrates safely across GRC1 root rotation yet.

### 2.3 Existing signer records are immutable identities

Every signer ID from the previous bundle must remain in the next bundle. Records cannot disappear to erase history.

For an existing signer ID, the following fields must remain identical:
- role and purpose/scope;
- generation;
- Ed25519 public key and SHA-256 fingerprint;
- activation epoch and activation sequence;
- signer acceptance signature.

Replacing a key under the same ID or rewriting the stable acceptance receipt is rejected. A replacement must use a new signer ID and a higher generation for that role.

### 2.4 Lifecycle is monotonic

Allowed transitions:
- Active → Active, Retired, or Revoked.
- Retired → Retired or Revoked.
- Revoked → Revoked only.

Forbidden transitions include:
- Retired → Active;
- Revoked → Active or Retired.

When an Active signer becomes Retired/Revoked, its terminal epoch and terminal sequence must equal the successor bundle's Governance-root epoch and bundle sequence. Once terminal, those coordinates must remain unchanged in later bundles.

These rules prevent a signed successor from silently reactivating an old generation or rewriting when an old signer was terminated.

### 2.5 Role-generation high-water

Within one bundle, generation numbers must be unique per role, including records that are Retired or Revoked. Owner generations and Independent-Operator generations are separate role namespaces.

For a newly introduced signer:
- it must be Active;
- its activation epoch must equal the successor's Governance-root epoch;
- its activation sequence must equal the successor bundle sequence;
- its generation must be strictly greater than the maximum generation previously present for the same role.

Generation gaps are permitted, but an unused gap cannot later be filled by a new signer. This avoids generation reuse after a higher generation has already been recorded.

These checks establish cryptographic record and history consistency. They do not prove that two different keys are controlled by two different humans or organizations.

## 3. STH1 local high-water store

New API:
\`SignerTrustBundleStateStore\`

State file magic: \`STH1\`
State format version: \`1\`
Fixed header: \`124 bytes\`
Trailing checksum: \`32 bytes\`

### 3.1 Header layout

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic \`STH1\` |
| 4 | 2 | Version = 1 |
| 6 | 2 | Reserved; must be zero |
| 8 | 32 | Network ID |
| 40 | 32 | Profile ID |
| 72 | 8 | Highest accepted STB1 sequence |
| 80 | 8 | Highest accepted Governance-root epoch |
| 88 | 32 | Exact SHA-256 digest of stored signed STB1 |
| 120 | 4 | Stored STB1 wire length |

The header is followed by the complete last accepted signed STB1 wire, then a SHA-256 checksum over the STH1 header and payload.

The state decoder enforces exact total length, version, reserved bytes, nonzero high-water fields, payload bounds, checksum, and equality between the stored digest and SHA-256 of the stored STB1 wire.

On reopen, the stored STB1 wire is strictly reverified against the current strict DPC1/GRC1 trust context. Its sequence, digest, Governance-root epoch, root fingerprint, network, and profile must match the STH1 metadata and configured context.

### 3.2 Writer serialization and atomic persistence

The store uses the existing shared \`SnapshotWriterLock\` and \`atomic_write_bytes_with_hook\` persistence primitive:
- one stable sibling writer-lock file serializes writers;
- a verified successor is encoded into the STH1 envelope;
- the exact bytes are atomically replaced;
- in-memory state advances only after persistence succeeds.

The state store exposes the current highest sequence, digest, and Governance-root epoch, plus an exact-current comparison.

### 3.3 Initial checkpoint handling

The store does not create a trusted initial state merely because the destination directory is empty.

- The caller must supply an already verified initial checkpoint.
- If both state and lock sibling are absent but no checkpoint is supplied, \`BootstrapCheckpointRequired\` is returned before a lock is created.
- If a persistent lock sibling exists but the state file is missing, opening fails with \`StateMissing\`, even if the caller supplies the old checkpoint.
- A malformed or checksum-corrupt state fails closed.
- The state store does not independently prove that the supplied checkpoint was authorized through the project's initial enrollment ceremony. That remains a separate governance/trust requirement.

### 3.4 Successor acceptance and replay checks

\`accept_successor\`:
1. Returns the current digest for an exact byte-for-byte replay of the current accepted bundle.
2. Rejects an older sequence.
3. Rejects same-sequence different bytes.
4. Strictly verifies the candidate against the current sequence/digest and DPC1/GRC1 context.
5. Applies the history-sensitive transition verifier.
6. Persists the new STH1 head atomically.
7. Advances in-memory state only after successful persistence.

The store refuses a lower Governance-root epoch and refuses an unreviewed change in root epoch/fingerprint.

## 4. Important limit: this is a local head store, not an archival append-only log

STH1 stores the exact latest signed bundle and its predecessor digest link. It does **not** retain every prior STB1 wire in a separate append-only archive, nor does CP-0753 implement an independently witnessed history service.

Consequences:
- The signed predecessor link is checked against the previous in-memory verified bundle during successor acceptance.
- On a later process restart, the store re-verifies the persisted latest bundle and its signed predecessor metadata, but it does not reconstruct and independently validate the entire historical sequence of prior bundle bytes.
- The local checksum is for accidental/corrupt state detection, not an independent authenticity root.
- A privileged attacker who can restore an older complete state file and its stable lock sibling, roll back the whole disk/VM snapshot, or alter the launch trust configuration can defeat local high-water state.
- This mechanism is not a TPM monotonic counter, hardware-backed anti-rollback anchor, remote CAS witness, or defense against a hostile Windows Administrator.
- Windows DACL, reparse-point ancestry, retained-handle identity, actual volume identity, power-loss, and physical disk-failure qualification remain separate work.

No claim of full-disk rollback resistance is made.

## 5. Implementation files

Primary file:
- \`src/native/pow_bench/src/signer_trust_bundle.rs\`

The CP-0753 additions include:
- history-sensitive transition verifier;
- role-generation uniqueness;
- STH1 persisted envelope;
- \`SignerTrustBundleStateStore\`;
- strict open/reopen, successor acceptance, replay checks, and high-water accessors;
- synthetic-key and temporary-directory tests.

No new Cargo dependency was added. The implementation reuses the existing Ed25519, SHA-256, snapshot writer-lock, and atomic byte persistence components.

No new production caller was added to:
- \`devnet_trust_provisioner\`;
- \`private_testnet_node\`;
- \`chain_import_node\`;
- PIV2 runtime reconciliation;
- any node startup or listener path.

## 6. Test evidence

### 6.1 STB1 codec, transition, and STH1 store

Command:
\`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib signer_trust_bundle:: -- --nocapture\`

Final result after generation-uniqueness and fixture corrections:
- 18 passed
- 0 failed
- 0 ignored

The tests cover:
- CP-0752 canonical STB1 signing/verification and malformed-wire behavior;
- strict DPC1 provenance marker requirement;
- independent Profile ID and predecessor checks;
- missing/multiple active roles;
- duplicate signer IDs, fingerprints, and per-role generations;
- acceptance receipts and key fingerprint validation;
- lifecycle terminal-coordinate consistency;
- valid retired-record receipt retention;
- role-generation replacement and monotonic transition rules;
- signer removal and key substitution rejection;
- retired/revoked signer reactivation rejection;
- generation gap non-reuse;
- local STH1 checkpoint requirement;
- durable high-water across restart;
- exact replay idempotence;
- old-sequence and same-sequence conflict rejection;
- missing-state-after-lock and corrupt-checksum fail-closed behavior.

The first run after introducing generation uniqueness exposed three existing test fixtures that reused generation 1 within one role. Those fixtures were corrected to use distinct generations and re-signed acceptance receipts. A later fixture was corrected to target the intended \`operator-main\` ID rather than selecting the first operator in canonical record order. The final targeted run passed all 18 tests.

### 6.2 DPC1/DCS1 regression

Command:
\`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_deployment_config::tests:: -- --nocapture\`

Final result:
- 6 passed
- 0 failed

This rechecks strict external Governance-root epoch enforcement, DCS1 v2 root-epoch high-water, exact-current DCS1 v1 migration, and existing DPC1 sequence/digest replay protections.

### 6.3 Additional checks

Final validation command also ran:
- \`cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check\`: PASS.
- \`git diff --check\`: PASS. Git emitted existing LF-to-CRLF normalization warnings for modified working-copy files; no whitespace error was reported.
- \`cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins\`: PASS, exit code 0. Existing unused-import/dead-code warnings remain in various candidate modules and binaries.
- The full library test suite was not run for CP-0753.

## 7. Repository state and safety

- Branch remains \`feat/cp0704-dual-attestation-rotation-gate-20261116\`.
- Expected HEAD remains \`5aba5f69d24fce03af742fd1bebf13ad00e5d9c3\`.
- The active worktree is the isolated \`QRUN_CP0704_DUAL_ATTESTATION_20261116\` worktree.
- The primary checkout at \`C:\Users\ASUS\Desktop\AI_NATIVE_L1\` was not used for these changes.
- No real owner/operator identity, pin, signing key, or independent custodian was enrolled or generated.
- No production trust directory, live C/D path, PIV2 anchor, node, listener, provisioner, wallet, token, liquidity pool, or public service was created or changed.
- No commit, push, PR update, merge, reset, checkout, clean, stash, or worktree cleanup was performed.
- Existing tracked/untracked work from earlier isolated checkpoints remains cumulative in this worktree; CP-0753 is not a clean diff against the baseline HEAD.

## 8. Gate disposition and next safe step

Implemented and focused-tested:
- STB1 canonical successor verification (CP-0752).
- Strict predecessor-link and lifecycle/generation transition verification.
- STH1 local head/high-water state persistence and restart/replay checks.

Still incomplete:
- Independent owner/operator human or organizational custody and initial enrollment ceremony.
- Full persistent archival history or external witness for STB1 sequence/digest high-water.
- Root-rotation migration path for STB1 state.
- Windows DACL, reparse-point ancestry, handle/file identity, actual volume identity, power-loss and physical disk failure qualification.
- TPM/off-host anti-rollback protection.
- PIV2 production caller and C/D reconciliation.
- Provisioner and node runtime integration.
- Full library test suite.

Gate 8 remains OPEN.

Next safe checkpoint CP-0754 should qualify the STH1 storage boundary on Windows using only isolated temporary paths: inspect DACL and reparse-point ancestry, retained file-handle identity, volume identity, lock/state replacement behavior, process termination and restart recovery. Do not use live production C/D paths, enroll real signers, or wire node startup.

Mainnet, public token release, public trading, liquidity, and mining remain NO-GO until their separate technical, security, legal, and operational evidence gates pass.

[executed on device: heymed (de0adbe3-6583-4775-a26e-c479a62aa941)]
