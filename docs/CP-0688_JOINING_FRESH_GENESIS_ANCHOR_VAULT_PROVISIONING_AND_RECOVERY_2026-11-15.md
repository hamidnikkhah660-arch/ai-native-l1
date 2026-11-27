# CP-0688 — Joining Fresh Genesis Anchor Vault Provisioning and Recovery

Date: 2026-11-15

## Scope

Complete the production CreateNew-only Anchor Vault bootstrap required for a fresh Public Testnet Joining node. This checkpoint records local engineering and test evidence only; it does not authorize or claim a Public Testnet launch.

## Implementation present in the active working tree

- Added QRunV06LocalAnchorVault::provision_genesis_root for a new generation-zero Genesis anchor root.
- Provisioning requires an absolute path, a real parent directory, and a nonzero independently pinned Genesis manifest anchor.
- Root and first record creation use create-new semantics. An existing or partial root is rejected; the routine does not truncate, repair, or overwrite it.
- The runtime entry point open_with_fresh_genesis_anchor_vault verifies a fresh height-zero/generation-zero store, matches its manifest anchor against the independently supplied Genesis pin, provisions the local Vault, reopens it, and checks the exact root.
- The Public Testnet Joining launch branch now invokes that path and enables automatic checkpoint rollover. The node binary compiles with this branch.
- Joining data, mempool, and Anchor Vault remain distinct paths by policy. The tests below use separate temporary directories on the test host; they do not prove physical cross-disk independence or external operator independence.

## Validation performed on 2026-11-15

1. cargo test --lib fresh_genesis_anchor_vault_persists_first_commit_and_recovers_one_commit_after_restart -- --nocapture
   - PASS: 1 passed, 0 failed.
   - Exercises fresh Genesis root creation, first block commit and anchor persistence, an intentionally lagging Vault after a second Store commit, recovery/reconciliation on restart, and rejection of re-provisioning over an existing Vault.
2. cargo test --lib qrun_v06_local_anchor_vault_candidate::tests -- --nocapture
   - PASS: 7 passed, 0 failed.
   - Covers CreateNew/reopen, refusal of partial existing roots, network/checksum tampering, catch-up/rollback handling, chained append, witness tampering, and checkpoint witness recovery/global-generation mapping.
3. cargo fmt --check
   - PASS after applying rustfmt only to the three affected Rust source files.
4. cargo check --bin qrun_v06_node
   - PASS; finished successfully. Existing library warnings were emitted (unused imports/dead code); no compile errors.
5. git diff --check
   - PASS (exit code 0). Git emitted LF/CRLF conversion notices only.

## Runtime and custody safety check

- qrun_v06_node process count: 0.
- TCP listeners on 30333 and 30334: 0.
- No Seed or Joining node was started by these tests.
- The tests use isolated temporary directories and do not open network listeners.
- No key material, private key, seed phrase, or DPAPI plaintext was read or emitted.
- No firewall, VPN, router, DNS, or port-forwarding changes were made.

## Git and source-of-truth state

- Active checkout: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111.
- Branch: feat/cp0600-bootstrap-sync-startup.
- HEAD at start of this work: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3.
- Working tree already contained extensive modified and untracked work before this checkpoint. Those changes were preserved.
- No reset, clean, stash, commit, push, or merge was performed.
- This checkpoint is a new untracked local document and is not committed.

## Remaining gates

- Perform a process-level protected-key reload test for the generated Joining DPAPI artifact without exposing plaintext key material.
- Complete and validate the dedicated Joining configuration against the exact Seed endpoint and independently verified Seed fingerprint.
- Confirm non-overlapping fresh data, mempool, and Anchor Vault paths; separately establish whether the intended Vault placement satisfies the required physical-volume failure model.
- Exercise Joining startup, pinned Noise XX responder authentication, history synchronization, restart, and automatic checkpoint rollover in isolated local fixtures.
- Obtain a genuinely independent operator and independent review before any public launch.
- Public Testnet remains NOT LAUNCHED. Mainnet, real-value transfers, and market authorization remain out of scope.

