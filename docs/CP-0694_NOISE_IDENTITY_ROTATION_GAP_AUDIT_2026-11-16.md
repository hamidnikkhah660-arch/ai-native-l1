# CP-0694 — Noise Identity Rotation Gap Audit and Provisioning Regression Suite — 2026-11-16

## Scope and repository state
- Active worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`
- Branch: `feat/cp0600-bootstrap-sync-startup`
- HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
- Reviewed existing Noise key provisioning, Seed/Joining identity records, Seed runtime config, bootstrap peer file, and the fail-closed Joining config builder.
- No production identity, protected key, Seed config, Joining config, bootstrap peer file, or deployment package was changed.

## Audit finding — protected-key replacement is not full identity rotation
The existing provisioner:
- Generates a fresh Noise static key internally; raw key input is rejected.
- Supports `--replace-existing` and persists the protected envelope through a temporary file plus atomic replacement.
- Prints the new public key and basic protection metadata.
- Does not coordinate the related identity JSON, public fingerprint, config hash, bootstrap peer pin, trust registry, peer rollout, or restart/rollback procedure.

The current Seed identity record binds its public static key/fingerprint and Seed-config hash. The Joining identity record binds its public key/fingerprint, protected-key file path/hash, and the Seed fingerprint/endpoint. The Joining config builder validates these bindings and generates the exact pinned Seed peer/config artifacts.

Consequently, replacing an active protected key file by itself can leave the public identity and config pins stale. Do not treat `--replace-existing` as a complete or safe production rotation workflow.

## Safe rotation requirements identified
A production-ready rotation must be staged and versioned, not an in-place overwrite:
1. Generate a new protected key at a new versioned path while preserving the active key.
2. Derive and verify its public key and fingerprint without exporting private material.
3. Produce a versioned identity/config/bootstrap bundle with exact network/profile, protected-file hash, and peer-pin bindings.
4. Obtain explicit owner authorization and independent out-of-band verification of the new fingerprint.
5. Define the old/new trust overlap, activation boundary, restart/reload behavior, and rollback floor.
6. Activate the new bundle as one reviewed deployment generation; retain the prior protected key until the new process and peer connectivity are independently verified.
7. Test rejection of stale pins, wrong network/profile, mismatched protected-file hashes, partial bundle writes, and rollback to an older identity generation.

The Seed and Joining roles have different propagation requirements; a single generic replace operation is insufficient.

## New Windows regression test
Added test-only coverage in:
`src/native/pow_bench/src/noise_key_provisioning.rs`

Test:
`dpapi_protected_noise_key_rotation_reloads_new_key_in_child_process`

Source SHA-256:
`F4AFD54282065BA7F7DD7077A691E5B036C54E4E90B5F67688DC88973BCB6EBA`

The test uses synthetic keys and verifies invalid replacement leaves the prior key usable, valid replacement changes the protected envelope, plaintext key bytes are absent from the envelope, the new key reloads in a fresh child process, and a wrong network ID is rejected. No actual Seed/Joining key was rotated.

## Validation — PASS
- Targeted rotation/process-reload test: 1 passed, 0 failed; exit code 0.
- Full `noise_key_provisioning::tests` module: 9 passed, 0 failed; exit code 0.
- `rustfmt --edition 2021 --check src/native/pow_bench/src/noise_key_provisioning.rs`: exit code 0.
- `git diff --check`: exit code 0; existing LF/CRLF normalization notices only.
- Targeted raw log: `docs/CP0696_dpapi_noise_key_rotation_process_reload_test.log`
- Targeted log SHA-256: `78F7C54815A1B0B460B783C15D6213280CB09939DFE5D014EDE87B63EDEC6479`
- Full module raw log: `docs/CP0697_noise_key_provisioning_test_suite.log`
- Full module log SHA-256: `7B2F043190F3D62AE1F3B2EB3AB20B448ABD3872F3A3C16F365FDAC61FE68DB4`
- Temporary rotation test key files remaining: 0.

## Safety and release boundary
- No production Seed/Joining key was read as plaintext, replaced, or rotated.
- No node was started and no listener was opened.
- No firewall/router/VPN/DNS/adapter settings were changed.
- No reset, clean, stash, commit, push, merge or rebase was performed.
- HEAD remains `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`; preserve the existing dirty/untracked worktree.
- The actual Seed endpoint remains a separately supplied/out-of-band gate. Public Testnet remains NOT LAUNCHED; Mainnet and market authorization remain NOT GRANTED.

## Next engineering step
Implement a prepare-only, versioned identity-rotation bundle builder and its negative tests. It must never overwrite active keys or activate a rotation. Only after independent review and explicit authorization should a separate activation step be considered.
