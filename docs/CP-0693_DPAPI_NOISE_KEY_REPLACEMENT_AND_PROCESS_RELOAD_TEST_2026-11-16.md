# CP-0693 — DPAPI Protected Noise-Key Replacement and Process Reload Test — 2026-11-16

## Scope and source of truth
- Active worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`
- Cargo manifest: `src/native/pow_bench/Cargo.toml`
- Branch: `feat/cp0600-bootstrap-sync-startup`
- HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
- This checkpoint records a new Windows-only regression test. The production key-provisioning behavior was not changed; one test was added to the existing module.

## Change
Added test:
`noise_key_provisioning::tests::dpapi_protected_noise_key_rotation_reloads_new_key_in_child_process`

File:
`src/native/pow_bench/src/noise_key_provisioning.rs`

SHA-256 after the test-only addition:
`F4AFD54282065BA7F7DD7077A691E5B036C54E4E90B5F67688DC88973BCB6EBA`

The test uses synthetic, compile-time test keys only. It verifies:
1. An initial protected key can be stored and loaded under its expected network ID.
2. The protected envelope does not contain the synthetic plaintext key bytes.
3. An invalid all-zero replacement is rejected and leaves the previously stored key loadable.
4. A valid new key replaces the old protected envelope through the existing atomic persistence path.
5. The new protected key is loadable in the parent process and then independently reopened by a fresh child test process.
6. A different network ID is rejected in the child process.
7. The temporary protected key file is removed after the test.

No private-key bytes or plaintext DPAPI material are passed through process arguments/environment variables or printed.

## Validation — PASS
- `rustfmt --edition 2021 --check src/native/pow_bench/src/noise_key_provisioning.rs`: exit code 0.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib dpapi_protected_noise_key_rotation_reloads_new_key_in_child_process -- --nocapture`: 1 passed, 0 failed; exit code 0.
- The child-process invocation also reported the exact test as passed.
- Temporary test key cleanup check: 0 matching files remained.
- `git diff --check`: exit code 0; existing LF/CRLF normalization notices only.
- Raw log: `docs/CP0696_dpapi_noise_key_rotation_process_reload_test.log`
- Raw log SHA-256: `78F7C54815A1B0B460B783C15D6213280CB09939DFE5D014EDE87B63EDEC6479`

## Critical scope limitation
This is a low-level protected-file replacement and process-reload regression test, not a complete operational Noise identity rotation protocol. It does not update or atomically coordinate:
- the Seed/Joining public identity JSON and its fingerprint;
- config/bootstrap peer pins and their hashes;
- a remote peer's trust pin or trust-registry approval;
- live-session draining, old-key overlap, rollback policy, or multi-operator authorization.

Therefore, do not use the provisioner's `--replace-existing` option against a real Seed or Joining key as a substitute for a coordinated identity rotation. Existing production identity files were not touched by this test.

## Safety and Git state
- HEAD remains `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- No node was started and no network listener was opened.
- No firewall/router/VPN/DNS/adapter settings were changed.
- No reset, clean, stash, commit, push, merge or rebase was performed.
- Preserve all pre-existing modified and untracked project artifacts.

## Next engineering step
Audit and implement only a staged, versioned identity-rotation workflow that binds the newly protected key, public identity record, config/bootstrap pins and restart boundary together. Keep the current Seed/Joining keys untouched until that workflow has explicit tests and a separately approved maintenance window. External Seed endpoint and independent operator gates remain unchanged.
