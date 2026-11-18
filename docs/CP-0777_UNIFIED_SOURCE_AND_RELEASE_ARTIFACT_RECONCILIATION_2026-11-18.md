# CP-0777 — Unified Source and Release-Artifact Reconciliation
Date: 2026-11-19
Worktree: D:\Temp\ASUS\QRUN_QFP6_UNIFIED_20261118
Branch: integration/qfp6-unified-20261118
Parent checkpoint: CP-0776-UNIFIED-INTEGRATION-CANDIDATE
Parent commit: 02c7946123c6861947d29ade87acc7154a7acedf

## 1. Purpose

This checkpoint reconciles the unified candidate against both preserved source worktrees, the current owner-directed monetary policy, and the actual Genesis/release-artifact inventory. It distinguishes source integration and local candidate tests from a deployable public network package. No production key, live cloud resource, network endpoint, or active node was mutated.

## 2. Source reconciliation

The unified worktree contains every Rust source path found in each source worktree under src/native/pow_bench/src; no Rust source path is missing. Final SHA-256 comparison after the CP-0651 policy-gate correction: CP-0704 has 243 byte-identical files, 36 differing integrated files and 0 missing; CP-0596 has 227 byte-identical files, 39 differing integrated files and 0 missing.

- CP-0704 provides the newer QAR2/QBT1, session-bound AWS/KMS, PIS2/PIV2, and standalone Anchor components.
- CP-0596 provides the owner-directed CP-0651 fixed-supply/fee-only launcher integration and related Genesis execution path.
- The unified branch retains the CP-0704 QAR2/QBT1 components while the Permissionless launcher is bound to CP-0651.
- The CP-0651 gate checks the 7B maximum, 1B owner Genesis, six 1B accounting labels, zero subsidy, height-zero state, owner identity and policy fingerprint before opening stores or listeners.
- The read-only Genesis auditor is CP-0651-specific; it rejects legacy CP-0528 and CP-0604 Genesis.
- The package validator now enforces CP-0651 economics and rejects the superseded 10B/3B-mining policy and nonzero subsidy.
- CP-0775 PMT4/PFM4/TXN4/MTA4 reorg/restart tests remain loopback diagnostics, not a public authenticated peer-network qualification.

Both source worktrees remain preserved. No wholesale overwrite or destructive Git operation was used.

## 3. Candidate package validation

Commands:
- python tools/qfp6_candidate_package.py self-test
- python tools/qfp6_candidate_package.py validate release/qfp6-candidate

Results:
- Self-test: PASS, exit 0. It verifies CP-0651 economics, rejects 10B/nonzero-subsidy substitutions, separates release profiles, fails closed on Q6TS claims, verifies founder public-key binding and keeps incomplete packages non-production.
- Candidate validation: exit 2 / INCOMPLETE, as intended.
- Five release inputs are absent from this package directory: CP-0651 Genesis snapshot, Q6GD descriptor, Q6CP consensus profile, Q6PN network profile and approved bootstrap peer set.
- Founder identity: PUBLIC_KEYS_BOUND_CANDIDATE_ONLY; no Genesis signature is present in this candidate manifest.
- Runtime wiring: true; this does not mean public deployment is authorized.
- Mainnet authorization: false.
- Public mining authorization: false.
- For permissionless_full_history, Q6TS is not a package requirement. An anchored_checkpoint release profile separately requires Q6TS signatures and an independently provisioned trust floor.

No placeholder artifact was created to satisfy the validator.

## 4. Existing local CP-0651 artifacts — valid local provenance, not public deployment inputs

A local CP-0651 single-operator package exists at:
release/qfp6-local-single-operator-devnet-2026-11-15

It contains a Genesis snapshot, Q6GD, Q6CP, Q6PN, local owner Q6GA, and a zero-value testnet authorization. Its monetary policy is CP-0651 (7B maximum, 1B owner Genesis, six 1B accounting labels, zero subsidy/fee-only producers), so it is not an obsolete 10B/3B-mining artifact set.

However, this package is explicitly local single-operator / Loopback-only:
- Its Q6PN and Q6GA authorization bind the old local configuration and its loopback scope.
- Its bootstrap peer file contains exactly [] (zero approved peers).
- It does not provide independent public Seed endpoints, external pinned Noise identities, or independently administered operator attestations.
- Its Q6GA signatures cannot be reused after changing Network ID, Profile ID, Genesis/Q6GD/Q6CP/Q6PN/config hashes or authorization scope.

Therefore, these files may be retained for their original local-only scope and regression provenance, but must not be relabelled as a public release or silently copied into a different network/profile package. A public package needs a new, internally consistent CP-0651 artifact set and fresh owner authorization over the exact frozen hashes.

## 5. Gate and deployment disposition

- Gate 2: OPEN. CP-0775 proves two-process PMT4/PFM4/TXN4/MTA4 reorg/restart diagnostics on one Windows host and loopback only. Earlier CP-0566C NetBird cross-host evidence remains valid for its private-overlay scope; neither test scope by itself proves the current candidate has authenticated public ingress, independent public hosts, stable public bootstrap endpoints or production PoW calibration.
- Gate 8: OPEN. CP-0774 is code-level Q6TS integration; CP-0771 through CP-0773 are session-bound AWS/KMS composition code. No live independent Anchor service, authenticated external CAS receipt, QBTB1 owner/custodian enrollment, independent monotonic witness or whole-host rollback test is evidenced.
- Public seed/network: NOT LAUNCHED. No approved public bootstrap peer set or independently qualified public Seed endpoint is in the release package.
- Mainnet, public mining, real-value transfers, exchange listing and trading: NOT AUTHORIZED.

## 6. Verification completed on 2026-11-19

- Full serial Rust library suite: 1,684 passed / 1 failed in 2,264.56s. The only first-pass failure was qap1_peer_ingress_qualifies_separate_qfp6_process, which saw Windows socket error 10053. The exact test was rerun alone and passed (1/1). All 1,685 unique library test cases therefore passed across the serial run plus the isolated retry; the transient first-run failure is retained in the evidence rather than suppressed.
- Full qrun_v06_node binary suite: 46 passed / 0 failed.
- Full qrun_v06_anchor_daemon binary suite: 4 passed / 0 failed.
- CP-0651 Genesis auditor suite: 2 passed / 0 failed; accepts exact 1B-owner CP-0651 Genesis and rejects CP-0528/CP-0604.
- cargo check --all-targets: PASS; compiler warnings only.
- cargo fmt --all -- --check, git diff --check, and manifest JSON parse: PASS.
- Package validator self-test: PASS, exit 0. Actual candidate validation: exit 2 / INCOMPLETE as expected because five release inputs remain missing.
- cargo build --release --bins: PASS, exit 0, 11m24s. Help probes for node, wallet and auditor all exit 0.
- Refreshed Release SHA-256 values:
  - qrun_v06_node.exe — DC62A700E7C339447C82D01E53248B29B73BB0337B1F73E78EE50003426BFE5E (3,370,496 bytes)
  - qrun_v06_anchor_daemon.exe — 9E98990FFB29E107DEA33273A57665335EA314EFABABBD5740E050C138E72454 (1,458,688 bytes)
  - qzxb_wallet.exe — 6553369C133C4F81AAB49CB3AE01477E77FE59B3DCAAA5F9F6F08EA8792F9184 (1,385,472 bytes)
  - qfp6_genesis_audit.exe — A3AD3F2283498138E580F5BE07C2CF501E6592165ED3D2425F0F59353F5DA307 (509,440 bytes)
- Hashes are recorded in docs/UNIFIED_RELEASE_BUILD_SHA256SUMS_2026-11-18.txt. The older CP-0776 node and auditor hashes are superseded.
- AWS CLI is not installed on heymed, so no live AWS STS identity/session was available for QAR2/QBT1. NetBird reports NeedsLogin; historical CP-0566C NetBird results remain valid for their previous private-overlay test scope.
- GitHub issue #72 remains OPEN: no accepted independent operators and no qualified public Seed host/endpoint. PR #196 and PR #197 remain OPEN with no submitted reviews at the time of inspection.

## 7. Safe next dependencies

1. Freeze and independently review the CP-0651 production Q6CP parameters and exact Network ID, Profile ID, Genesis timestamp, owner account and Q6GD commitment.
2. Generate or explicitly approve one canonical CP-0651 Genesis/Q6GD/Q6CP/Q6PN package; complete owner authorization locally with the protected signer over exact artifact hashes. Never export private keys.
3. Qualify the selected anti-rollback release profile: for anchored/checkpoint mode, provision Q6TS/QBTB1 through an independent ceremony and live separately administered Anchor service, then exercise authenticated reads/CAS and whole-host rollback against the real witness. Do not claim Q6TS is required for the full-history profile.
4. Qualify authenticated PMT4 transport and archive synchronization across independently administered hosts using the exact frozen release profile; preserve existing CP-0566C/NetBird evidence for its already validated private-overlay scope.
5. Only after those gates pass, authorize and publish the zero-value Public Testnet, wallet/explorer/site and independent security-review package. Exchange outreach follows a verified running network and a truthful listing dossier.

This checkpoint is an evidence reconciliation, not a production release, Genesis signature, public launch authorization, or Gate 2/Gate 8 closure.