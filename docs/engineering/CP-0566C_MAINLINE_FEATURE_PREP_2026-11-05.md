# CP-0566C mainline-based feature preparation report

Date: 2026-11-05

## Base and isolation
- GitHub repository: hamidnikkhah660-arch/ai-native-l1
- Base main SHA after security PR #134: 8de9812e7d1a49020f1a7fc169c40d4b8a72a144
- Security PR #134 merged; follow-redirects is 1.16.2 in package-lock and CycloneDX SBOM.
- Local-only preparation branch: prep/qrun-feature-mainline-20261105
- Worktree: D:\Temp\ASUS\QRUN_CP0566C_FEATURE_MAINLINE_PREP_20261105
- The older release feature overlay was applied as exactly 114 source files; the status path set matched with zero unexpected paths.
- The expected remote feature branch feat/qzxb-usdt-trading-gate-20261104 was absent at the last read-only check. No remote feature branch has been created by this preparation.

## Validation on this exact mainline-based worktree
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check: PASS.
- cargo test --offline --manifest-path src/native/pow_bench/Cargo.toml --lib qap1_ -- --nocapture: 24 passed, 0 failed, 1244 filtered.
- cargo test --offline --manifest-path src/native/pow_bench/Cargo.toml --lib qfp6_ -- --nocapture: 37 passed, 0 failed, 1231 filtered.
- Controller and Runner PowerShell AST parse: PASS.
- Workflow YAML parse: PASS.
- Workflow policy markers: PASS (manual-only dispatch, exact feature-branch guard, immutable actions/checkout pin, pinned NetBird MSI SHA, Authenticode verification, always cleanup).
- Full crate all-target test suite on this worktree: not yet run at report creation.

## GitHub release and security PR status at report creation
- Security PR #134 merged at 8de9812e7d1a49020f1a7fc169c40d4b8a72a144.
- Workflow PR #133 head 9f1cfb2b380cf037b017a699b094db45bb61558b is still Draft.
- PR #133 is exactly one commit ahead of current main, zero behind, and changes only .github/workflows/qfp6-qap1-netbird-cross-host.yml.
- GitHub Actions Run #482 (42001964642) on that workflow-only PR head completed successfully: Format/check/test PASS, EVM/dependency audit PASS, Windows PMT4/TXN4 loopback PASS.
- No PR merge approval, workflow_dispatch, Actions secret creation, NetBird enrollment, ACL/firewall change, or real-money action is recorded here.

## Evidence boundary
These results do not establish CP-0566C two-physical-host NetBird PASS. That still requires the authenticated Node A remote admission and replay rejection plus Node B second-process restart-continuity evidence from a real two-host run. Mainnet, public Devnet, public RPC, QZXB listing, QZXB/USDT liquidity, bridging and real trades remain separate gates.## Full all-target test completion (2026-11-05)

Command: cargo test --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline
Result: exit code 0 in 510.33 seconds.
- Library tests: 1,268 passed; 0 failed; 0 ignored.
- Every binary/unit-test target and integration target completed successfully.
- Notable suites: devnet_node 68/68; private_testnet_node 41/41; qrun_v05_pow_local_node 43/43; qzbe_v04_peer_node 26/26.
- Existing rustc warnings concerned unused imports, unused mutability and dead code; they were warnings only.
- This is local single-host evidence, not the CP-0566C two-physical-host NetBird result.

## Final worktree integrity
- HEAD remains 8de9812e7d1a49020f1a7fc169c40d4b8a72a144.
- The 114-file overlay plus this report should be exactly 115 changed paths.
- No commit or push was performed from this worktree.