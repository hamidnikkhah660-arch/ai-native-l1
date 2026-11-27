# CP-0634 — Cryptographic Security Test Pass and Threat-Gap Reconciliation
Date: 2026-11-13
Project: QRun Blockchain / QZXB / QFP6
Repository: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Branch: feat/cp0600-bootstrap-sync-startup
HEAD: df673d07050688a64b26822d97e6ea609b68ce88
Status: LOCAL SECURITY VALIDATION NOTE — NOT AN EXTERNAL AUDIT OR RELEASE APPROVAL

## 1. Scope
This checkpoint records focused cryptographic and protocol-security tests executed against the current Windows worktree. It does not repeat the already recorded listener-rate-limiter or peer-book Sybil test families.

## 2. Executed tests

All commands used the locked offline Cargo dependency set and the pow_bench manifest.

| Test filter | Result | Coverage represented by the matching tests |
|---|---:|---|
| `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib mldsa65 --locked --offline -- --nocapture` | PASS — 5 passed, 0 failed | Real ML-DSA-65 verification, wrong-digest and tampering rejection, pinned Wycheproof vectors, TXN4 identity/signature verification, trust-floor path |
| `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qfp6_noise --locked --offline -- --nocapture` | PASS — 9 passed, 0 failed | QFP6 Noise XX pinned-peer handshake, wrong network/profile context rejection, duplicate/unpinned key rejection, record-size bounds, unpinned-mode identity boundary, two-process transport qualification |
| `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib hybrid_ --locked --offline -- --nocapture` | PASS — 40 passed, 0 failed | Hybrid TXN4 authentication, signature tampering, sender/transaction replay binding, legacy/downgrade rejection, fork-choice and archive replay, PFM4 crash-window recovery and manifest-commit consistency |

These are three targeted test filters (54 reported test executions in total). They are not a formal cryptographic certification, external penetration test, or proof of whole-network quantum resistance.

## 3. Security boundaries confirmed from implementation
- TXN4 is an Ed25519 + ML-DSA-65 hybrid candidate path. The tests above establish behavior of the implemented verification and transaction-binding paths only.
- QFP6 P2P Noise currently uses `Noise_XX_25519_ChaChaPoly_SHA256`. X25519 is classical; the P2P transport is not post-quantum.
- Public inbound Noise XX mode is anonymous. Encryption alone does not authenticate the remote peer's real-world/network identity; a remote static key is not a trusted identity unless pinned through the separate trust path.
- The listener's current accept/handshake path remains serial. Source-prefix and global admission buckets mitigate bursts, but one slow handshake can still occupy the serial handshake path until its deadline (currently eight seconds). Rate limiting alone does not prove resistance to distributed multi-source slow-handshake DoS or head-of-line exhaustion.
- The repository's current candidate manifest remains non-authorized; cryptography review is still marked pending. Local test success must not be represented as independent security approval.

## 4. Previously recorded work not repeated
- CP-0632 already records source-prefix/global rate limiting, bounded limiter state, established-session accounting, and the focused listener regression family.
- CP-0631 records Q6PA V3 peer-book migration and operator approval controls, including the Sybil candidate-capacity tests.
- Prior CP-0571/0572 and later history-sync tests are not rerun here.

## 5. Multi-host / listener-resilience evidence reconciliation
The owner reports that independent multi-host testing and listener-resilience testing were already completed and instructs that these not be repeated.

The available 587-page `QRUN 5 (1).docx` handoff and current local CP-0632/0633 checkpoint material do not contain an independently reproducible report proving the claimed external multi-host qualification. They instead distinguish local two-process/loopback tests from independent physical-host qualification. CP-0632 also explicitly records the remaining serial-handshake/head-of-line limitation.

Accordingly:
- No multi-host test was rerun in this checkpoint.
- No public endpoint, firewall rule, router forwarding, or public listener was activated.
- The reported completion is preserved as owner-reported, but the supporting report/CI run/host identities/commit SHA were not found in the currently available project evidence.
- The serial handshake limitation is a direct property of the current local source and remains a technical finding independent of whether separate external tests were run.

## 6. Remaining security work identified by this pass
1. **P2P transport PQC:** design and qualify a hybrid/PQ transport migration (including key establishment, peer authentication, downgrade resistance, key rotation, recovery, and interoperability). Do not label the current X25519 Noise transport quantum-safe.
2. **Serial-handshake DoS:** replace or otherwise safely bound the serial handshake critical path; test slowloris/slow-handshake, multi-prefix distributed floods, worker/queue exhaustion, shutdown under load, and recovery. Do not weaken the existing global/prefix budgets.
3. **Public inbound identity:** specify and enforce an explicit identity/authentication policy for anonymous Noise XX sessions; test MITM/key-substitution and trust transitions.
4. **Independent cryptography review:** review exact code, dependency versions, parameter sets, key generation/storage, signature verification, and migration/downgrade behavior. This cannot be self-certified by local unit tests.
5. **Consensus adversarial suite:** after the canonical production consensus profile is frozen, verify timestamp/timejacking, difficulty manipulation, branch-locality, deep reorg, selfish-mining assumptions, invalid-target and network/profile substitution scenarios against the exact profile.
6. **Supply-chain/release integrity:** reproducible builds, dependency provenance/advisories, signing-key lifecycle and artifact verification on the exact release SHA.

## 7. CBI terminology
No definition or test framework named `CBI` was located in the available core-source and documentation search. The acronym is therefore left unresolved rather than guessing its expansion or claiming a CBI test was run.

## 8. Safety and worktree
- No source code was modified by this checkpoint.
- No commit or push was created.
- No node process, public listener, or external attack traffic was launched.
- Existing CP-0631/0632/0633 local changes remain preserved.
- Release manifest remains unchanged and not authorized.
