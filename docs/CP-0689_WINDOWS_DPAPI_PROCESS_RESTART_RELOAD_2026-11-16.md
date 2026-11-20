# CP-0689 — Windows DPAPI Process-Restart Reload Qualification

Date: 2026-11-16  
Project: AI-NATIVE L1 / QRun / QFP6  
Active worktree: local candidate checkout  
Branch at verification: `feat/cp0600-bootstrap-sync-startup`  
Observed HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`  
Status: **implemented as a focused test and passed locally; candidate engineering evidence only**

## Objective

Verify that a protected Noise static identity can be reopened by a fresh process under the same Windows user context, rather than relying only on an in-process protect/unprotect round trip.

## Change

Added a Windows-only unit test, `dpapi_protected_noise_key_survives_process_restart`, in the Noise key provisioning module.

- The parent test process stores a synthetic test key in the existing CurrentUser DPAPI-protected envelope.
- It launches the same Rust test executable as a child process.
- The child process independently reopens the protected file and verifies the expected test key.
- The child also verifies that loading the same envelope under a different network identifier fails closed.
- The synthetic key is compiled into the test; it is not passed in command-line arguments or environment variables. The environment variable carries only the temporary protected-file path.
- The temporary protected file is removed after the child exits.

No production identity, Seed key, Joining key, wallet key, seed phrase or DPAPI plaintext was read or emitted.

## Verification

Command, run from the `src/native/pow_bench` package:

```powershell
cargo test --lib dpapi_protected_noise_key_survives_process_restart -- --nocapture
```

Result: **PASS — 1 passed, 0 failed**. The parent and fresh child test processes both reported success.

Additional checks:
- `rustfmt` on the touched source file: PASS.
- `cargo fmt --check`: PASS.
- `git diff --check`: PASS (Git emitted only existing LF/CRLF working-copy notices).

## Scope and limitations

This proves process-to-process DPAPI reload under the same logged-in Windows user on the development workstation. It does not prove service-account isolation, another Windows profile, machine migration, backup/restore, OS recovery, TPM-backed custody, compromise resistance while the process is running, or public-network operation.

No node process was launched. No listener, firewall, VPN, router, DNS or port-forward setting was changed. No commit, push, merge, reset, clean or stash was performed. Pre-existing dirty and untracked project work was preserved.

## Next gate

Continue with strict Joining configuration and loopback-only Noise XX synchronization/restart/identity-rollover tests. A real public Seed endpoint and independently operated hosts remain prerequisites for any public Testnet launch.
