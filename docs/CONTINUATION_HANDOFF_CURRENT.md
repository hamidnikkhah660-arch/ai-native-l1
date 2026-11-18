# QFP6 Unified Integration Handoff — 2026-11-18

## Purpose and source preservation

This is the isolated integration worktree combining the latest CP-0704 dual-attestation/Q6TS work with the CP-0596 QFP6 runtime, wallet, PMT4/PFM4 and market-ingress work. The original worktrees remain untouched:

- CP-0704 source: QRUN_CP0704_DUAL_ATTESTATION_20261116, base 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
- CP-0596 source: QRUN_QFP6_CP0596_20261111
- Unified branch: integration/qfp6-unified-20261118
- Unified worktree: QRUN_QFP6_UNIFIED_20261118

All tracked diffs were imported with three-way application. Untracked source and documentation were copied into the unified worktree without overwriting existing files. The colliding CP-0596 verifier was preserved under a _cp0596_legacy filename. Protected identity folders, local runtime state and private key material were not copied.

## Canonical economic policy

The unified permissionless launcher is bound to the owner-confirmed CP-0566D/CP-0566E direction, as reaffirmed by the latest CP-0775 handoff:

- 10,000,000,000 QZXB maximum gross issuance
- 1,000,000,000 QZXB Founder Genesis allocation
- up to 3,000,000,000 QZXB deterministic PoW mining/security issuance
- six additional 1B QZXB category ceilings, not pre-issued Genesis balances
- CP-0566E one-way retirement of unissued ProtocolBurnReserve capacity
- CP-0422 initial subsidy 35,673,515,981 atoms; halving interval 4,204,800 blocks; 0.860736 QZXB remains permanently unissued; no terminal top-up

CP-0650/CP-0651 remain preserved as historical records of the later 7B/fee-only proposal, but are not the selected permissionless policy in this integration. The CP-0566D permissionless Genesis gate accepts the CP-0528 snapshot encoding only when the embedded tokenomics and policy fingerprint match; CP-0604 is rejected.

## Integration changes

- Combined CP-0596 QFP6 node/runtime and wallet/market modules with CP-0704 identity rotation and QAR2/QBT1/Q6TS anchor work.
- Resolved permissionless launcher conflicts to retain Q6AR/Q6TS trust checks while binding Genesis admission to CP-0566D.
- Preserved CP-0651 and CP-0604 modules/tests as historical compatibility code; they are not the selected launcher policy.
- Updated release/qfp6-candidate/manifest.json to reflect CP-0566D/CP-0566E economics and mining schedule.
- Candidate package remains a structural scaffold. Genesis snapshot, Q6GD descriptor, Q6CP, Q6PN, and approved bootstrap peer artifacts are still missing in this candidate directory. Do not substitute CP-0651/CP-0604 or local research artifacts.

## Validation observed on 2026-11-18

- cargo fmt --all: PASS.
- cargo check --all-targets: PASS.
- cargo test --bin qrun_v06_node: 46 passed, 0 failed.
- cargo test --bin qrun_v06_anchor_daemon: 4 passed, 0 failed.
- CP-0566D permissionless Genesis targeted test: 1 passed, 0 failed.`r`n- qfp6_genesis_audit binary tests: 2 passed, 0 failed.
- Full library suite: 1,685 tests were exercised. The first parallel run showed four timing/resource-sensitive failures (two QAP1 child-process/record-timeout tests, one supervisor idle-deadline test, and one CP-0604 mining-supervisor test). All four were rerun individually with one test thread and passed. Treat the parallel-run failures as resource-contention flakes; a single clean serial run of all 1,685 tests has not been performed.
- qfp6_genesis_audit binary tests: 2 passed, 0 failed.
- Release build: qrun_v06_node, qrun_v06_anchor_daemon, qzxb_wallet, qfp6_genesis_audit all built successfully in optimized release mode. SHA-256 values are recorded in docs/UNIFIED_RELEASE_BUILD_SHA256SUMS_2026-11-18.txt.
- Safe CLI probes: node, wallet and Genesis-audit help/usage returned successfully. Anchor daemon requires an absolute config path and SHA-256 positional arguments; it was not started without a provisioned QAR2/QBT1 configuration.
- git diff --check: PASS after manifest and handoff edits.

## Runtime and release boundary

The pre-existing local process PID 20244 on port 30333 was not stopped or replaced. It runs the older CP-0596 local zero-value config, with an empty bootstrap list, outbound peer sync disabled and anonymous Noise XX ingress. It is not evidence that this unified build is deployed or that secure public P2P is live.

CP-0775 provides real two-process PMT4/PFM4/TXN4/MTA4 loopback diagnostics, but explicitly not public Internet or independent physical-host qualification. CP-0774 integrates Q6TS into the standalone Anchor daemon at code level, but no live independent AWS trust-floor deployment was performed. Gate 2 and Gate 8 remain OPEN in the latest qualification records.

No production keys were read or rotated. No external AWS/NetBird services were changed. No public listener was enabled, no Genesis was promoted, and no exchange/market listing or liquidity action was initiated.

## Next safe actions

1. Finish the full library test run and rerun any timing-sensitive failures in isolation.
2. Reconcile all candidate manifest component hashes against independently approved CP-0566D Genesis/Q6GD/Q6CP/Q6PN/bootstrap artifacts; do not fabricate missing inputs.
3. Qualify the separately administered QAR2/QBT1 Anchor and Q6TS floor with live external evidence.
4. Build the final candidate binaries and run a clean two-or-more-host authenticated P2P qualification on the exact frozen profile.
5. Only after those gates pass, stage public seed operations, wallet/explorer/site deployment and exchange-facing documentation.

This handoff records an integration candidate, not a public release, production authorization, Mainnet activation, or trading readiness.