# CP-0768 — Canonical QBTB1 Bootstrap Bundle and Explicit QAR2 Runtime Selection
**Date:** 2026-11-18
**Branch:** `feat/cp0704-dual-attestation-rotation-gate-20261116`
**Base HEAD observed:** `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
**Status:** implementation candidate + targeted local verification; not a production enrollment or deployment qualification

## 1. Objective

CP-0767 supplied a separately domain-separated QAR2/QBT1 Noise v2 transport and bounded daemon entry point. The node startup path still selected the historical QAR1 transport. This checkpoint adds a canonical, externally digest-pinned container for the QBT1 bootstrap trust material and makes the node's Anchor transport selection explicit.

This work does not provision a real owner/custodian ceremony, create cloud resources, enroll production keys, publish a network endpoint, or close Gate 8.

## 2. Trust semantics

The QBT1 `profile_digest` is defined for QFP6 as the exact Q6PN profile-pin commitment returned by `QRunV06VerifiedProfilePin::profile_pin_commitment()`. It is **not** the Q6GD `profile_id`, nor a locally synthesized config hash.

The Q6PN commitment is domain-separated over the complete canonical Q6PN bytes. Q6PN binds the immutable Q6GD descriptor and Provider identity/key/network/Genesis values (and Q6QA v2 trust fields when present). The Q6TS signed profile-trust envelope already authorizes the exact Q6PN commitment. At startup:
- the complete JSON deployment config is checked against the digest supplied to the process out of band (`--config-sha256`);
- the Q6PN bytes are decoded only against `profile_pin_commitment` from that independently digest-pinned config;
- QBTB1's full-file SHA-256 is supplied in that same independently digest-pinned config;
- QBT1's `profile_digest` must equal that verified Q6PN commitment;
- Provider pin is taken from the verified Q6PN; Anchor pin is built from the independently digest-pinned configuration inputs;
- only then is the existing pure QBT1 verifier called with the exact generation-zero ECR1 record and receipt bytes.

QBTB1 never derives an expected pin from its own contents. It is a transport container, not a self-authenticating root. Its expected digest must be obtained independently of the bundle file.

## 3. QBTB1 v1 codec

New module: `src/native/pow_bench/src/external_cas_bootstrap_trust_bundle_candidate.rs`.

Fixed-width wire form:
1. 8-byte header: `QBTB`, big-endian version 1, zero reserved field;
2. canonical ECR1 generation-zero bootstrap record (existing 272-byte ECR1 format);
3. the QBT1 `BootstrapTrustPin` fields in a fixed order: expected receipt digest, Q6PN profile commitment, initial record digest, initial Anchor-state digest, owner signer ID and ML-DSA-65 public key, independent-custodian signer ID and ML-DSA-65 public key;
4. exact fixed-size QBT1 receipt wire bytes.

The total size is computed from the existing ECR1/QBT1/ML-DSA constants and enforced before field parsing. Decoder rejects wrong length, magic, version, nonzero reserved bytes, noncanonical ECR1 and trailing bytes. Encoder re-encodes the decoded value to ensure canonical representation.

`verify_qbt1_bootstrap_trust_bundle` returns a sealed `VerifiedQbt1BootstrapTrustBundle` only after:
- a nonzero externally supplied whole-bundle SHA-256 matches;
- a nonzero independently supplied Q6PN commitment matches the embedded QBT1 profile digest;
- the ECR1 record, Provider and Anchor pins match the QBT1 receipt/pin;
- the existing QBT1 verifier validates both role-specific ML-DSA-65 signatures and generation-zero state bindings.

The module performs no filesystem/network operations, enrollment, CAS, or mutable state writes.

## 4. Node preflight and runtime selection

Updated:
- `src/native/pow_bench/src/bin/qrun_v06_node.rs`
- `src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/mod.rs`

Top-level config fields:
- `qbt1_bundle_path`
- `qbt1_bundle_sha256`

They must appear together. Preflight reads the bounded, fixed-size bundle and verifies it against the externally pinned digest, Q6PN commitment, Provider pin and independently configured Anchor pin. A verified bundle is retained in the preflight summary for runtime construction.

Runtime selector:
- `runtime.q6ea_anchor_transport = "qar2-qbt1-v2"` requires both QBTB1 fields and constructs `NoiseTcpQar2OffhostAnchorTransport` plus `QAR2Qap1AnchorTransport` using the verified QBT1 capability;
- `runtime.q6ea_anchor_transport = "qar1-v1"` is the explicit compatibility choice and is accepted only when no QBTB1 fields are configured;
- missing, unknown, incomplete, or contradictory selection is rejected.

There is no automatic QAR1 fallback when QBTB1 inputs are present or when the selector is absent. The same selected transport type is used by both QAP1 recovery and steady-state coordinator construction. QAR2 transport retains its CP-0767 Q2 wire/profile separation and validates the outer QAR2/QBT1 receipt before the QAP1 adapter exposes the inner QAR1-shaped receipt to the existing coordinator.

The QAR2 server must separately be started with the CP-0767 explicit `bind_qbt1` path and the same verified bootstrap trust. This checkpoint does not deploy or remotely exercise that server.

## 5. Verification performed on heymed

All commands were run in the existing Windows worktree. No staged files or commits were created.

| Verification | Result |
|---|---:|
| `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check` | PASS |
| `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib external_cas_bootstrap_trust_bundle_candidate::tests -- --nocapture` | 4 passed, 0 failed |
| `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node qrun_v06_node_runtime_launch::tests -- --nocapture` | 6 passed, 0 failed |
| `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins` | PASS, exit code 0 |
| `git diff --check` | PASS, only Git's LF/CRLF informational warnings |

The four QBTB1 tests cover canonical round-trip and trust verification, wrong whole-file digest, wrong Q6PN profile commitment, header/version/reserved/trailing-byte rejection, wrong Provider domain, and altered ECR1 even when an attacker recomputes the outer bundle hash.

The six node runtime tests include the new explicit transport selector matrix: explicit QAR1 with no QBTB1, explicit QAR2 with the complete pair, missing selector, QAR1 plus QBTB1, QAR2 without QBTB1, incomplete QBTB1 pair, and an unknown selector. Existing private-candidate listener, directory-separation and restart-manifest tests also passed.

This is targeted test coverage and a bins check, not the full crate test suite. Existing unrelated unused/dead-code warnings remain.

## 6. Source SHA-256

Hashes were computed after source formatting and successful targeted tests/build:

| File | SHA-256 |
|---|---|
| `external_cas_bootstrap_trust_bundle_candidate.rs` | `10A71A24C20C64F6668AEF31F1EC1D347269E9794FBB13866903D34E47D0B836` |
| `external_cas_bootstrap_trust_candidate.rs` | `7FBC5FC6230964AA8C2B49893A5527A49A67D0EA53AC8D50BEFF7B43AEA52DF5` |
| `lib.rs` | `C9265959F516AE98E8BA095DF3CDF66AD684C0D90EB6816CD751E39D2C82B69C` |
| `bin/qrun_v06_node.rs` | `F7B61F60BE9B9FA4E895E55841AED6017B6B0CF814C40285C421B82898F5C9E7` |
| `bin/qrun_v06_node_runtime_launch/mod.rs` | `C7EA64C4719F6C65D240EFEBEFA6B5A1E6E87EF217D919A97BDB7E0981B6B788` |

## 7. Explicitly unresolved / no-go items

- No real independent owner + custodian enrollment ceremony or provenance evidence exists yet. Unit-test keys are synthetic.
- No production QBTB1 bundle has been generated from authorized real public keys and a real generation-zero ECR1 bootstrap record.
- No end-to-end node-to-live-QAR2-daemon read/CAS, restart, reorg or downgrade test has been performed. CP-0767 daemon tests remain synthetic localhost tests.
- No live AWS account/role/table/IAM/session-bound endpoint or production DynamoDB CAS deployment was qualified here.
- No separately administered, rollback-resistant independent witness has been exercised against whole-host snapshot rollback.
- Existing OS/TPM/Windows ACL/AccessCheck qualification limitations remain.
- No independent security audit or public multi-operator network test is evidenced by this checkpoint.

**Gate 8 remains OPEN. Public/Mainnet release remains NO-GO.** CP-0768 advances the code and local test evidence; it does not convert local hashes, test fixtures, or a local config into an independent custodian or rollback-resistant trust root.

## 8. Git preservation

Observed HEAD remains `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`. The existing branch and all pre-existing modified/untracked CP work were preserved. No stage, commit, push, merge, reset, clean, stash or checkout was performed.
