# CP-0690 — Joining Topology and Loopback Noise History-Sync Regression

Date: 2026-11-16  
Project: AI-NATIVE L1 / QRun / QFP6  
Active worktree: local candidate checkout  
Branch at verification: `feat/cp0600-bootstrap-sync-startup`  
Observed HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`  
Status: **focused local regression suites passed; no public network launch**

## Objective

Re-qualify the next safe boundary after Windows DPAPI process-restart reload: public-Testnet role/topology validation, storage-path separation, pinned Noise history synchronization, restart recovery, and independent-source agreement.

## Verification results

Run from `src/native/pow_bench`:

1. `cargo test --bin qrun_v06_node public_testnet_ -- --nocapture`  
   **PASS — 2 passed, 0 failed.** Covers explicit public-testnet mode acknowledgements/role and Seed-versus-Joining topology requirements.

2. `cargo test --bin qrun_v06_node anchor_vault_path_must_not_overlap_data_or_mempool -- --nocapture`  
   **PASS — 1 passed, 0 failed.** Covers lexical path overlap and nesting rejection. This does not prove distinct physical disks or defeat Windows junction/reparse-point aliasing.

3. `cargo test --lib pinned_noise_sync_imports_a_heavier_competing_branch_and_recovers_after_restart -- --nocapture`  
   **PASS — 1 passed, 0 failed.** Pinned Noise history sync, competing-branch selection and recovery after restart.

4. `cargo test --lib two_independent_noise_sources_ -- --nocapture`  
   **PASS — 2 passed, 0 failed.** Same-history independent-source agreement passes; divergent histories fail bootstrap agreement.

5. Windows DPAPI process-reload test recorded in CP-0689:  
   **PASS — 1 passed, 0 failed.** A fresh child test process reopens the protected synthetic identity under the same Windows user context.

6. `cargo fmt --check` and `git diff --check`: **PASS**. Git emitted only LF/CRLF working-copy notices. Existing compiler warnings remain; no aggregate all-target test pass is claimed.

## Security and operational boundary

- The peer and topology tests use controlled test fixtures/loopback paths; they do not prove public Internet reachability or independent public operators.
- The path-separation test is lexical only. Physical-volume separation and reparse-point/junction alias detection remain separate hardening work.
- No external Seed endpoint was fabricated or used.
- No production key, wallet key, seed phrase, DPAPI plaintext or private endpoint was read or emitted.
- No QRun node was launched; no listener, firewall, VPN, router, DNS or port-forward setting was changed.
- No commit, push, merge, reset, clean or stash was performed. All pre-existing dirty/untracked work remains preserved.

## Remaining gates

1. Strengthen Joining configuration construction so the actual public Seed endpoint and pinned identity are mandatory, independently verified inputs.
2. Add process-level identity rotation/reload and checkpoint rollover tests around the local Anchor Vault.
3. Qualify external reachability and independently administered Seed/Joining hosts before any zero-value Public Testnet launch.
4. Obtain independent protocol, cryptography and economics review. Mainnet and real-value operations remain unauthorized.
