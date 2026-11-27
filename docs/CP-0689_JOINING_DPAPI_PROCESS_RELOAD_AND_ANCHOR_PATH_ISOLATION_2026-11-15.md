# CP-0689 — Joining DPAPI Process Reload and Anchor Vault Path Isolation — 2026-11-15

## Scope and source of truth
- Active repository: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
- Branch: feat/cp0600-bootstrap-sync-startup
- HEAD: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
- This checkpoint supplements CP-0687 and CP-0688. It does not replace them.
- The working tree already contained extensive user/project changes. The preexisting status count was 90; after the temporary test helper was removed, it remained 90. No reset, clean, stash, commit, push, merge, or rebase was performed.

## Process-level Joining protected-key reload — PASS
A disposable temporary Rust binary was compiled and executed from the existing ai_native_l1_pow_bench package using its own Cargo.lock, --locked, and --offline. It loaded the actual existing Joining protected-key file in a newly started process under the current Windows user context.

Observed program output:
- dpapi_reload=PASS
- network_binding=PASS
- noise_xx_static_identity_match=PASS
- network_io=NONE

The check used the expected network ID and recorded Joining public identity. A complete three-message in-memory Noise XX handshake confirmed that the loaded static key corresponds to the public key recorded in the Joining identity document. Secret buffers were zeroed by the temporary helper's Drop implementation; neither private key bytes nor plaintext DPAPI material were printed.

The first external temporary Cargo project was abandoned because its dependency resolution selected base64ct v1.8.3, which requires Cargo's not-yet-stabilized edition-2024 feature and is incompatible with the project's Cargo 1.82. That external temporary directory was removed. The successful check used the repository's locked dependencies instead.

The temporary source src/native/pow_bench/src/bin/z_tmp_noise_key_reload.rs and both output/error logs were removed. No helper source remains. The existing Joining key and identity files retained their prior SHA-256 hashes:
- Joining protected key: 2d4023202541ba8534768aa23386b1229f96e387e8197d92068c3d98ddc23c6c
- Joining identity JSON: 120f3d89d07febe29670ed82319f63348db5ef1e7c64c99754f9565c7ee05b1a

This proves local same-user DPAPI reload and the key-to-public-identity binding. It does not prove remote Seed reachability, independent operator identity, or successful network synchronization.

## New Anchor Vault path isolation guard
Code inspection found that data_directory and mempool_directory were already required to be separate and non-nested, while the configured Anchor Vault path was not checked against either tree.

Updated:
src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/permissionless.rs

The launcher now validates the resolved trusted_manifest_anchor_vault_path against both runtime directories before store initialization or listener startup. The guard:
- requires absolute paths;
- compares path components rather than raw string prefixes;
- uses case-folded comparison for Windows filesystem semantics;
- rejects identical paths and either direction of nesting;
- rejects any .. parent-directory traversal component.

A unit test covers a separate sibling Vault path, equality with data/mempool, Vault nested inside data/mempool, Vault as their parent, case-only path differences, and parent traversal.

Important limit: this is a lexical path-isolation guard. It does not resolve all junctions, symbolic links, reparse-point aliases, 8.3 aliases, or prove distinct physical disks. Physical volume/storage independence remains a separate qualification gate and must not be inferred from this check.

Patched source SHA-256:
b914fe42c429108404928eff5143ce3c981b98fdaf1b35aa289015eb8e680d7d

## Validation — PASS
- cargo test --locked --offline -j 1 --bin qrun_v06_node -- --nocapture: 45 passed, 0 failed.
- cargo test --locked --offline -j 1 --bin qrun_v06_node qrun_v06_node_runtime_launch::permissionless::tests -- --nocapture: 16 passed, 0 failed.
- cargo check --locked --offline -j 1 --bin qrun_v06_node: passed.
- rustfmt --edition 2021 --check src/bin/qrun_v06_node_runtime_launch/permissionless.rs: passed.
- git diff --check: exit code 0.
- Existing non-fatal unused-import/dead-code warnings remain; no new compilation error was observed.

## Physical storage and network observation on 2026-11-15
Read-only Windows storage inspection mapped the currently configured Seed-side paths:
- C: is Kingston RBUSNS8154P3256GJ3, about 238.5 GiB, Disk 1.
- D: is TOSHIBA MQ04ABF100, about 931.5 GiB, Disk 0.
- The existing C:-side Anchor Vault, D:-side data directory, and D:-side mempool directory all exist and were not marked as reparse points at inspection time.

This confirms that the existing local Seed package's current C: Anchor Vault and D: runtime data are on different physical disks. It does not automatically qualify a future Joining configuration; its actual configured paths and volume mapping must be independently checked.

A fresh read-only network snapshot found an active Wi-Fi IPv6 default route, preferred global IPv6 address(es), and successful outbound IPv6 TCP 443. The observed preferred-address lifetime was about 55 minutes at the time of the check; one address used a randomized suffix. This is transient network evidence, not a stable advertised Seed endpoint. No inbound TCP 30333 reachability from an independent external host was verified. No address was written into the Joining identity/config.

## Runtime safety / Git state
- qrun_v06_node process count: 0.
- TCP listeners: 30333 = 0; 30334 = 0.
- No node was launched.
- No firewall, router, VPN, DNS, adapter, or port-forward setting was changed in this work.
- No private-key material, recovery phrase, or DPAPI plaintext was emitted.
- Branch and HEAD remain the values recorded above.
- Working tree status count after temporary-helper cleanup and before creating this checkpoint: 90; after CP-0689 was created: 91 (the additional item is this document).
- No Git commit or push was made.

## Remaining gates
1. Establish a stable, owner-approved Seed endpoint and independently verify it out-of-band against the Seed Noise fingerprint. Current Joining identity still contains NOT_EMBEDDED_REQUIRES_CURRENT_OUT_OF_BAND_ENDPOINT.
2. Verify inbound TCP 30333 from an independent external network/operator; outbound IPv6 alone is insufficient.
3. Build a Joining-specific, independently pinned bootstrap peer file and configuration only after the endpoint is stable. Enforce zero-value Public Testnet scope and exact network/profile/Genesis pins.
4. Verify the proposed Joining data, mempool, and Anchor Vault paths; prove volume and physical-storage separation for that host. The new source guard only prevents lexical path overlap.
5. Run isolated Seed/Joining Noise XX, history sync, restart, catch-up, checkpoint rollover and recovery tests before any public listener is enabled.
6. Obtain independent operator participation and external security/consensus/economics review before public launch.
7. The public website change (PR #195) remains a separate publication gate; this checkpoint does not claim merge, deployment, or reviewer approval.

## Authorization boundary
Current owner authorization remains limited to the zero-value Public Testnet candidate scope. It does not authorize Mainnet, a market, real-value transfers, token sale, exchange listing, or any financial outcome. Public Testnet has not launched.