# CP-0692 — Anchor Vault Runtime Revalidation — 2026-11-16

## Scope and source of truth
- Active worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`
- Cargo manifest: `src/native/pow_bench/Cargo.toml`
- Branch: `feat/cp0600-bootstrap-sync-startup`
- HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
- This checkpoint supplements CP-0689, CP-0690 and CP-0691. No production code was changed during these test reruns.

## Validation results — PASS

### 1. Complete local Anchor Vault unit-test module
Command:
```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qrun_v06_local_anchor_vault_candidate::tests -- --nocapture
```
Result:
- 7 passed; 0 failed; 0 ignored; 1469 filtered out.
- Includes fresh Genesis root creation/reopen, refusal to repair partial roots, network/checksum tamper rejection, checkpoint-witness tamper rejection, one-commit catch-up/rollback rejection, chained idempotent append, and witness/root recovery with global generation mapping.
- Exit code: 0.

Raw log:
- `docs/CP0693_anchor_vault_unit_suite.log`
- SHA-256: `DE3A46D61C814B96EDE18F52EBF4CEA699C91A0FEDDB2455B09764BCC662978C`

### 2. Fresh Genesis Anchor Vault runtime restart recovery
Command:
```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib fresh_genesis_anchor_vault_persists_first_commit_and_recovers_one_commit_after_restart -- --nocapture
```
Result:
- 1 passed; 0 failed; 0 ignored; 1475 filtered out.
- Test duration: 1.06 seconds.
- Exit code: 0.

Raw log:
- `docs/CP0694_fresh_genesis_anchor_restart_rerun.log`
- SHA-256: `BB918CBADD6F1EAFA5763C448FCC0864213325B964A129D429E0E99292990D52`

### 3. Runtime recovery from one unanchored generation
Command:
```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib local_dual_disk_runtime_persists_each_commit_and_recovers_one_unanchored_generation -- --nocapture
```
Result:
- 1 passed; 0 failed; 0 ignored; 1475 filtered out.
- Test duration: 0.51 seconds.
- Exit code: 0.

Raw log:
- `docs/CP0695_anchor_vault_unanchored_commit_recovery_rerun.log`
- SHA-256: `5D1733759C96805A98DBB3F4B28E1213825B8D54B1BB10CFE962E7F0D6A3BD61`

## Post-test validation and limitations
- `git diff --check`: exit code 0; existing LF/CRLF normalization notices only.
- The test named `local_dual_disk_runtime...` uses separate logical directories under the same temporary host path. It validates runtime persistence/recovery ordering; it does not prove actual physical-disk separation. Physical-disk qualification remains separate and must be measured on each deployment host.
- These tests do not prove cross-account DPAPI portability, external Seed connectivity, independently administered Joining operation, public inbound reachability, full Internet sync, or public soak.
- No node was launched and no listener, firewall, router, VPN, DNS or adapter setting was changed.
- No reset, clean, stash, commit, push, merge, rebase or destructive worktree operation was performed.
- Preserve the existing dirty/untracked worktree and all user/project artifacts.

## Next step
Continue with the process-level Joining identity/config binding and Anchor Vault rotation/reload audit. A real Joining configuration remains blocked until the owner supplies a stable Seed endpoint and the Seed Noise fingerprint is independently verified out of band. No Public Testnet launch or Mainnet/market authorization is implied.
