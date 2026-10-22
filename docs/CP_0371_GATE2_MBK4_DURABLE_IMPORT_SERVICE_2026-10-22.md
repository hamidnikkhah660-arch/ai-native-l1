# CP-0371 — Candidate MBK4 Durable Import Service

Date: 2026-10-22
Project: QuantumZXB / AI-Native L1
Base commit: `47155b9925f8a7e9fa7b0ca8405b67ae0713dc0b`
Branch: `feat/gate2-monetary-import-service`
Scope: candidate-only MBK4/TXN4 state admission and profile-bound persistence; no node activation.

## Finding

The existing `ChainImportService` and `chain_import_node` accept legacy BLK2 and persist only `LedgerState`. Separately, `ChainAdmissionBoundary` already exposes the MBK4/TXN4 monetary state transition APIs, and `MonetaryLedgerState` has a versioned snapshot that includes cumulative mined issuance. These pieces lacked a durable importer that joins them under one explicit network/Genesis/manifest profile.

## Change

Added `V4HybridMonetaryImportService` as a separate candidate service in `chain_import.rs` without changing legacy importer behavior or dispatching the live TCP node to it.

- Validates non-zero network and manifest IDs and requires the supplied starting Genesis state at height zero.
- Persists the nested monetary snapshot in a bounded `MCS4` wrapper binding the network ID, caller-supplied manifest ID, and fingerprint of the exact canonical Genesis snapshot.
- Uses a domain-separated SHA-256 checksum for corruption detection; the checksum is not an authentication signature and provides no anti-rollback security.
- Applies decoded MBK4 blocks through the existing MBK4/TXN4 admission APIs into a staged clone. It writes the profile-bound snapshot via the existing atomic byte-write primitive, and publishes in-memory state only after that write succeeds.
- On open, rejects network, manifest, Genesis, version, length and checksum mismatches; it never silently migrates a legacy `STV2` snapshot.
- Keeps live timestamp admission and historical replay distinct. ML-DSA verification and expected manifest identity are explicit service inputs.

## Local Windows validation

- `cargo fmt --all -- --check` — PASS.
- `cargo test --lib --locked --offline chain_import::tests::` — PASS (10 passed, 0 failed); includes both the existing legacy import regressions and new MBK4 durable reopen / manifest mismatch / Genesis mismatch / corrupted snapshot / rejected-block atomicity tests.
- `cargo check --all-targets --locked --offline` — PASS (exit code 0); pre-existing diagnostic/dead-code warnings remain elsewhere in the repository.
- `cargo test --lib --locked --offline` — PASS (751 passed, 0 failed, 0 ignored; test runtime 186.55s). The new MBK4 importer tests are included in this exact suite.

## Explicit limitations — Gate 2 remains OPEN

This class only performs monetary state decode/admission/persistence. It does **not** verify `PowHeader`, proof-of-work, target/difficulty transition, cumulative chainwork, canonical fork selection, reorg/undo, independent archive replay, or a public peer/runtime callsite. The canonical TCP node continues to instantiate legacy `ChainImportService`. MBK4/TXN4 and PMT4/PFM4 have not been frozen as one production protocol, and the supplied manifest is an explicit caller input rather than an independently pinned production governance trust root. The checksum protects against accidental corruption, not an adversary who can rewrite both data and checksum; external anti-rollback/independent recovery trust is still a separate Gate 8 requirement. Independent cross-client conformance, external protocol/cryptographic review, final monetary/fee/reward/migration parameters, and legal review are not done.

Do not market this as Mainnet-ready, do not enable production issuance or value transfers, and do not connect a public listener on the basis of this candidate service. No owner-funded spending, production keys, transactions, public endpoints or liquidity were created. Owner budget remains USD 0.
