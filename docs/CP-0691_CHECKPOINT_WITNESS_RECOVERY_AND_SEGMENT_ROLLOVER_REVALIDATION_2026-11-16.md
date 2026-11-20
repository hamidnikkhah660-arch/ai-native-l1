# CP-0691 — Checkpoint Witness Recovery and Segment Rollover Revalidation — 2026-11-16

## Scope and source of truth
- Active worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`
- Package manifest: `src/native/pow_bench/Cargo.toml` (the repository root does not contain a Cargo.toml).
- Branch: `feat/cp0600-bootstrap-sync-startup`
- HEAD before and after validation: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
- This checkpoint records two previously interrupted/unconfirmed tests rerun individually. It supplements CP-0689 and CP-0690; it does not replace them.

## Validation results — PASS

### 1. Checkpoint witness recovery and global segment-generation mapping
Command:
```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib checkpoint_witness_recovers_root_publication_and_maps_segment_generations_globally -- --nocapture
```
Exact result:
- Test: `qrun_v06_local_anchor_vault_candidate::tests::checkpoint_witness_recovers_root_publication_and_maps_segment_generations_globally`
- `1 passed; 0 failed; 0 ignored; 1475 filtered out`
- Test duration: 0.21 seconds.
- Process exit code: 0.

Raw log:
- `docs/CP0691_checkpoint_witness_recovery_rerun.log`
- SHA-256: `743A20C4F37A923AC3AFC5F57A321209235F3C74ADB27C13F25950A480990C0B`

### 2. Automatic checkpoint segment rollover at 1,024 and recovery of an unanchored commit
Command:
```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib checkpoint_segment_runtime_automatically_rolls_at_1024_and_recovers_unanchored_commit -- --nocapture
```
Exact result:
- Test: `qrun_v06_permissionless_runtime_candidate::tests::checkpoint_segment_runtime_automatically_rolls_at_1024_and_recovers_unanchored_commit`
- `1 passed; 0 failed; 0 ignored; 1475 filtered out`
- Test duration: 774.54 seconds.
- Process exit code: 0.
- The test completed its 1,024-block durable-store setup, exercised automatic rollover, then exercised recovery after simulating a crash between the segment-manifest commit and the Anchor Vault append. The test ended with `ok`.
- The temporary test directory was confirmed absent after completion.

Raw log:
- `docs/CP0692_checkpoint_segment_rollover_rerun.log`
- SHA-256: `DDD6986806E78801C404225B935C51FBAE019F0AE52CD75017A0767ACA6B606F`

## Post-test integrity checks
- `git diff --check`: exit code 0. Git emitted existing LF/CRLF normalization notices only.
- No Cargo or test executable remained active after completion.
- The test's temporary runtime directory was removed.
- HEAD remained unchanged at `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- Git status contained 112 modified/untracked entries at the post-test inspection. The worktree already contained extensive project work; preserve all of it.
- No reset, clean, stash, commit, push, merge, rebase, or source-code rewrite was performed as part of this rerun.
- No node was started, no network listener was opened, and no firewall/router/VPN/DNS configuration was changed.

## Interpretation and limits
These two tests now have confirmed passing results, replacing the previous unknown/incomplete status for these exact test cases. They provide local test evidence for checkpoint witness recovery, generation mapping, the 1,024-block rollover boundary, and recovery from the tested interrupted-commit point.

They do not establish external Seed reachability, independent operator administration, public Internet synchronization, a public soak, production-grade storage failure tolerance, or readiness for Mainnet. Public Testnet remains blocked on the external endpoint, independent operator, inbound reachability, and independent review gates recorded in CP-0690.

## Next engineering step
With these two tests confirmed, continue with a code-level audit and targeted process-level tests for Joining identity/config binding and Anchor Vault rotation/reload. Do not generate a real Joining deployment configuration until a stable owner-approved Seed endpoint and independently verified Seed fingerprint are available. Keep all work local and preserve the existing dirty worktree.
