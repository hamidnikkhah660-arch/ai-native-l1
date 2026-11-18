# QFP6 Unified Integration Handoff — 2026-11-18

## Purpose and source preservation

This is the isolated integration worktree combining the latest CP-0704 dual-attestation/Q6TS work with the CP-0596 QFP6 runtime, wallet, PMT4/PFM4 and market-ingress work. The original worktrees remain untouched:

- CP-0704 source: QRUN_CP0704_DUAL_ATTESTATION_20261116, base 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
- CP-0596 source: QRUN_QFP6_CP0596_20261111
- Unified branch: integration/qfp6-unified-20261118
- Unified worktree: QRUN_QFP6_UNIFIED_20261118

All tracked diffs were imported with three-way application. Untracked source and documentation were copied into the unified worktree without overwriting existing files. The colliding CP-0596 verifier was preserved under a _cp0596_legacy filename. Protected identity folders, local runtime state and private key material were not copied.

## Canonical economic policy

The unified permissionless launcher is bound to the later owner-requested CP-0651 policy (CP-0650/CP-0651), superseding CP-0566D/CP-0566E for the active candidate:

- 7,000,000,000 QZXB maximum gross issuance
- 1,000,000,000 QZXB owner Genesis allocation
- block subsidy and mining issuance are exactly zero at every height
- six accounting labels of 1,000,000,000 QZXB each (6,000,000,000 total)
- six labels are accounting ceilings only, not Genesis balances, spendable accounts or automatic mint authority
- producers receive canonical transaction fees only; fees transfer existing value and do not mint. The CP-0422 mining schedule is historical under CP-0651.

CP-0566D/CP-0566E remain preserved as the prior 10B/3B-mining policy; CP-0651 is the later owner-requested and active 7B/fee-only policy. The CP-0651 permissionless Genesis gate accepts only the version-7 CP-0651 fixed-supply snapshot with matching owner and policy fingerprint; CP-0528 and CP-0604 Genesis are rejected.

## Integration changes

- Combined CP-0596 QFP6 node/runtime and wallet/market modules with CP-0704 identity rotation and QAR2/QBT1/Q6TS anchor work.
- Resolved permissionless launcher integration while retaining CP-0704 QAR2/QBT1 trust components and binding Genesis admission to CP-0651.
- Preserved CP-0528 and CP-0604 as historical compatibility paths; the permissionless launcher accepts only CP-0651.
- Updated release/qfp6-candidate/manifest.json to remain a non-production scaffold for the CP-0651 permissionless full-history profile.
- Candidate package remains a structural scaffold. Genesis snapshot, Q6GD descriptor, Q6CP, Q6PN, and approved bootstrap peer artifacts are still missing in this candidate directory. Do not substitute CP-0528/CP-0604 or local research artifacts.

## Validation observed on 2026-11-19

- cargo fmt --all -- --check: PASS; git diff --check: PASS.
- cargo check --all-targets after CP-0651 gate/auditor/package-validator correction: PASS (warnings only; no compile errors).
- Full qrun_v06_node binary suite: 46 passed, 0 failed (serial).
- Full qrun_v06_anchor_daemon binary suite: 4 passed, 0 failed (serial).
- CP-0651 permissionless Genesis gate on the corrected unified source: 1 passed / 0 failed. CP-0651 read-only Genesis auditor tests: 2 passed / 0 failed; verifies exact 1B owner issuance and rejects CP-0528/CP-0604.
- Full library suite: serial run completed with 1,684 passed / 1 failed in 2,264.56s. The sole failure was qap1_peer_ingress_qualifies_separate_qfp6_process with Windows socket error 10053. Isolated rerun of that exact test passed (1 passed / 0 failed in 4.14s). All 1,685 unique library tests therefore passed across the full run plus isolated rerun; retain the first-run socket interruption in the record as a transient test-environment failure, not a suppressed result. The library source itself was not changed by the CP-0651 binary-gate correction.
- cargo build --release --bins: PASS, exit 0 (11m24s). New hashes: qrun_v06_node.exe DC62A700E7C339447C82D01E53248B29B73BB0337B1F73E78EE50003426BFE5E; qrun_v06_anchor_daemon.exe 9E98990FFB29E107DEA33273A57665335EA314EFABABBD5740E050C138E72454; qzxb_wallet.exe 6553369C133C4F81AAB49CB3AE01477E77FE59B3DCAAA5F9F6F08EA8792F9184; qfp6_genesis_audit.exe A3AD3F2283498138E580F5BE07C2CF501E6592165ED3D2425F0F59353F5DA307. Full byte sizes in docs/UNIFIED_RELEASE_BUILD_SHA256SUMS_2026-11-18.txt. Older CP-0776 node/auditor hashes are superseded.
- Package validator self-test after CP-0651 hardening: PASS, exit 0. Actual candidate package validation: exit 2 / INCOMPLETE as intended, with five missing release inputs. Full node/wallet/auditor help probes pass. Anchor daemon requires an absolute config path and SHA-256 positional arguments; it was not started without a provisioned QAR2/QBT1 configuration.


## Runtime and release boundary

The pre-existing local process PID 20244 on port 30333 was not stopped or replaced. It runs the older CP-0596 local zero-value config, with an empty bootstrap list, outbound peer sync disabled and anonymous Noise XX ingress. It is not evidence that this unified build is deployed or that secure public P2P is live.

CP-0775 provides two-process PMT4/PFM4/TXN4/MTA4 loopback diagnostics, not public Internet or independent physical-host qualification. CP-0774 integrates Q6TS into the standalone Anchor daemon at code level, but no live independent AWS trust-floor deployment was performed. Gate 2 and Gate 8 remain OPEN in the latest qualification records.

AWS CLI is not installed on heymed, so no live AWS STS identity/session or QAR2/QBT1 external integration was verified. NetBird currently reports NeedsLogin. This does not invalidate the historical CP-0566C NetBird cross-host evidence for its already-qualified private-overlay scope; it means there is no current overlay session for qualifying the unified candidate.

No production keys were read or rotated. No external AWS/NetBird services were changed. No public listener was enabled, no Genesis was promoted, and no exchange/market listing or liquidity action was initiated.

## Next safe actions

1. Obtain the independently reviewed CP-0651 public Genesis/Q6GD/Q6CP/Q6PN values and complete owner authorization locally over exact hashes. The existing local CP-0651 package and its Q6GA/config authorization are loopback-only and cannot be reused for a public profile.
2. Make a real AWS CLI/SDK deployment session available on an independently administered Anchor host, then qualify QAR2/QBT1 authenticated reads/CAS and whole-host rollback. Current heymed cannot establish AWS STS because AWS CLI is absent.
3. Restore an approved private overlay or provision independently operated public Seed infrastructure. Preserve CP-0566C/NetBird historical qualification, but qualify the current candidate on the exact frozen profile and genuinely independent hosts.
4. Recruit and verify at least three independent operators. Issue #72 remains open; GitHub PRs #196 and #197 also remain open and need independent review.
5. After Gate 2/Gate 8 and release authorization pass, publish the zero-value Public Testnet, wallet/explorer/site and independent security-review package. Exchange outreach follows a verified live network and a truthful listing dossier.

This handoff records an integration candidate, not a public release, production authorization, Mainnet activation, or trading readiness.