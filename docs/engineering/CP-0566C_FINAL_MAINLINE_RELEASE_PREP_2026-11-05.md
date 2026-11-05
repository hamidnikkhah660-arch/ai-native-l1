# CP-0566C final mainline release preparation

Date: 2026-11-05
Current main base: c536caec696217234d6b35582663c0aa58652b9c
Local-only branch: prep/qrun-final-mainline-20261105
Expected technical ref for the manual workflow: feat/qzxb-usdt-trading-gate-20261104

## Release source reconciliation
- Feature overlay paths: 114.
- Exactly matched against the previously full-tested mainline worktree after line-ending normalization: 114/114.
- 29 paths were transplanted from the tested worktree; 85 were already byte-equivalent after newline normalization, including the merged Workflow.
- The only GitHub mainline change after the full all-target test was the Workflow merge; the Rust crate had zero changed paths between base 8de9812e7d1a49020f1a7fc169c40d4b8a72a144 and current main c536caec696217234d6b35582663c0aa58652b9c.
- The merged main Workflow was never overwritten.
- The final worktree is local-only, uncommitted and unpushed.

## Test evidence
On the same 1,268-test Rust source:
- cargo test --all-targets --locked --offline: exit 0; 1,268 library tests passed, zero failed; all binary/integration targets completed.
- cargo fmt --check: to be validated on this final worktree below.
- Focused QAP1: 24/24 PASS; focused QFP6: 37/37 PASS.
- Workflow YAML and policy checks, Controller and Runner PowerShell AST checks passed on the tested source.
- GitHub Actions PR #133 Run #482: all three jobs passed (Format/Check/Test, EVM/Audit, Windows PMT4/TXN4 two-node loopback).

## Current gates
- Workflow exists on main but is manual-only; no workflow_dispatch run has occurred.
- The required technical branch does not yet exist on origin.
- CP-0566C remains NOT RUN until Node A is remotely admitted, replay is rejected, and Node B second-process restart continuity is proven using two physical hosts.
- No public Devnet/Mainnet, public RPC, real USDT liquidity, cross-chain bridge or real QZXB trade is claimed.