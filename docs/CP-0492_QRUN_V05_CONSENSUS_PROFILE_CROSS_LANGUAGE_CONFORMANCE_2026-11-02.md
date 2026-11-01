# CP-0492 — QRun v0.5 consensus profile cross-language conformance

Date: 2026-11-02

Status: **Independent profile serialization check added; the calibrated profile remains a candidate, not a frozen production consensus profile. Mainnet remains disabled.**

## Purpose

The QRun v0.5 node derives a consensus profile ID from the actual runtime parameters. Before this checkpoint, the measured PoW calibration oracle checked the calibration JSON and its initial-target arithmetic, while the node's Rust tests separately checked hard-coded parameters and the current profile ID. There was no independent script proving that the exact calibration JSON, wallet-bound Genesis identity and runtime profile fingerprint all described the same bytes.

CP-0492 adds that missing cross-language consistency check without changing any consensus, Genesis, network, supply or activation parameter.

## Candidate values checked

The oracle checks the current recorded candidate values:

- Protocol version: 5.
- PoW: Argon2id v1.3, 64 MiB, one iteration, one lane and 32-byte output.
- Target interval: 30 seconds.
- Difficulty window: 2,016 blocks.
- Retarget clamp: minimum 1/4 and maximum 4x.
- PoW limit: 256-bit maximum.
- Initial target: independently derived from the conservative 64 MiB measured throughput of 11.186 hashes/second.
- Issuance: fixed maximum supply 1,000,000,000,000,000,000 atoms, fee-only, zero post-Genesis subsidy, and canonical nonzero interval of one.
- Wallet-bound Network ID and Genesis commitment from the current identity manifest.

The profile fingerprint is serialized independently in Python using explicit big-endian widths and the same domain-separated field order used by the node's runtime fingerprint function. The resulting SHA-256 must equal the wallet-bound identity manifest's profile ID:

75596fa188dc308088efc6b138e9fcd50be6de82ec2bc117c13e81d7eebfdb09.

## New checks

- simulations/qrun_v05_consensus_profile_conformance.py independently derives the initial target and complete runtime profile fingerprint from the candidate JSON and wallet-bound identity manifest.
- simulations/test_qrun_v05_consensus_profile_conformance.py runs the checker under Python optimization and mutates PoW memory, initial target, wallet Network ID, fee-only issuance interval and Mainnet activation state to prove those mismatches fail closed.
- The Rust calibrated-candidate test now also explicitly checks the fee-only interval is one.
- GitHub Actions runs the independent fingerprint oracle and its mutation suite before Rust validation.

## Local validation

- The independent Python fingerprint oracle: PASS.
- Mutation tests under python -O: 6/6 PASS.
- Existing measured calibration oracle: PASS.
- Existing wallet-bound identity manifest parity checker: PASS.
- Rust calibrated-consensus test: **1/1 PASS**; confirms the current candidate parameters including the fee-only interval.
- Rust node profile parity test: **1/1 PASS**; Public-alpha and Mainnet candidate modes derive the same recorded candidate profile ID.
- Rust Mainnet guard test: **1/1 PASS**; Mainnet remains fail-closed while concrete blockers are present.
- `cargo check --all-targets --locked --offline`: **PASS**.
- `cargo fmt --all -- --check` and `git diff --check`: **PASS**.
- Full `cargo test --all-targets --locked --offline -- --test-threads=4`: **PASS**, exit code 0; library **1,037/1,037**, `devnet_node` **68/68**, `private_testnet_node` **41/41**, `qrun_v05_pow_local_node` **28/28**, `qrun_v05_local_node` **5/5**, QZBE smoke **6/6**, QZBE peer node **26/26**, and all other binary, integration and example targets passed.

## What this does not prove

The source profile still identifies itself as candidate_multi_runner_calibrated_not_frozen. Historical benchmark evidence contains four hosts (one owner development host and three hosted OS runners) and two independent operators; CPU models and power consumption were not measured. The measured target is a reproducible candidate calibration, not a complete production difficulty/security determination.

This checkpoint does not add real-world independent mining operators, long-duration difficulty manipulation tests, adversarial timestamp/reorg tests, multi-host network qualification, independent protocol review, or a public Devnet. It does not change the 10B owner-Genesis allocation, turn candidate balances into live QZXB, enable Mainnet, enable minting or create a market.

**Gate 2 remains OPEN.** The QRUN_MAINNET_RELEASE_APPROVED guard remains false. Public deployment remains blocked until the full production profile, full-history/repeated-checkpoint recovery, authenticated peer operations and adversarial multi-host behavior have separate reproducible evidence.
