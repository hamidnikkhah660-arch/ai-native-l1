# CP-0687 — Public Testnet Joining Noise Identity and Fresh-Vault Gap

Date: 2026-11-15

## Separate Joining identity provisioned

- Protected key: `release/qfp6-local-single-operator-devnet-2026-11-15/protected/joining-node-noise-static-key.npk`
- Protection: Windows CurrentUser DPAPI NPK1; network-bound to the AI-NATIVE L1 network ID.
- Noise pattern: `Noise_XX_25519_ChaChaPoly_SHA256`.
- Joining public static key: `fd175c81c74851b136cbc6ed649fcdc6a8d132f718dc3acbd2de44717c2e513d`.
- Joining public-key SHA-256 fingerprint: `05fcc7dd125894d8503559d6a9ebd727cb15d256404a6640d67e4280dabbbc25`.
- Protected-key file SHA-256: `2d4023202541ba8534768aa23386b1229f96e387e8197d92068c3d98ddc23c6c`.
- Identity artifact: `release/qfp6-local-single-operator-devnet-2026-11-15/joining-noise-identity.json`.
- Identity artifact SHA-256: `120f3d89d07febe29670ed82319f63348db5ef1e7c64c99754f9565c7ee05b1a`.
- Seed key remains separate; Seed fingerprint: `9407504ce70ddf91478a82143195fffa6fd3375c52c0776ef223dff1a559ec48`.
- Joining private material was not printed, exported, or read back into a plaintext file.

## Runtime source audit — blocking issue before Joining config

- `validate_public_testnet_topology` accepts `node_role=joining` only with at least one publicly routable pinned bootstrap peer.
- `load_peers` requires each peer's numeric `address` and 32-byte `noise_static_public_key`; the runtime verifies the peer-set SHA-256.
- `QRunV06HistorySyncClient` uses the pinned Noise XX initiator path, so the Joining node authenticates the Seed responder against the supplied static-key pin.
- `data_directory` and `mempool_directory` must be distinct, non-nested paths. A Joining node must use fresh, separate directories and must not share Seed's data, mempool, or Anchor Vault.
- Fresh Genesis-only startup currently returns `None` from `trusted_manifest_anchor` when there are no manifests and no configured root pin, then uses the ordinary `QRunV06PermissionlessNodeRuntime::open` path. That path does not attach `QRunV06LocalAnchorVault` and therefore does not provide the CP-0683 per-commit dual-disk anchor persistence needed for safe restart after the Joining node has written history.
- The existing `open_with_local_anchor_vault` constructor requires an already provisioned Vault root and exact manifest anchor/generation. The production Vault API has no public genesis-root provisioning method; the only `provision_test_root` helper is test-only.
- Therefore, a naive Joining config that merely omits `trusted_manifest_anchor` would be unsafe for durable restart. No such config was created.

## Next engineering task

Add a production, CreateNew-only Genesis-root Vault provisioning path for a fresh Joining data directory, then open the runtime through `open_with_local_anchor_vault`, enable checkpoint rollover, and test first-commit persistence, interrupted-commit recovery, restart, and checkpoint rollover. Only after those tests should a dedicated Joining config builder be written. It must pin the current Seed endpoint and fingerprint out of band, use the independent Joining DPAPI key, and create separate data/mempool/Vault paths.

## Safety and release state

- No Seed or Joining node started.
- No listener or firewall rule created; no router, VPN, DNS, adapter, or port-forwarding changes.
- Seed key and Seed identity artifact were not modified.
- No Git commit, push, merge, reset, or clean operation performed.
- CP-0652 independent operator/reviewer gates remain outstanding. Public Testnet is not launched.
## Execution addendum — identity and custody checks

- `noise_key_provisioner --release` completed successfully and generated a fresh random Joining Noise XX key; the provisioner emitted only the public static key and DPAPI protection status.
- Joining public key differs from the existing Seed public key.
- The protected Joining key file is a regular non-reparse file; its contents were not read or printed.
- Joining identity JSON parsed successfully and its public key/fingerprint fields were rechecked.
- `cargo test --lib noise_key_provisioning -- --nocapture`: 7 passed, 0 failed, including DPAPI envelope roundtrip and network-binding tests.
- This unit-test run validates the protection implementation; it is not represented as a separate process-level re-load test of the newly generated Joining file.
- Runtime safety check: qrun node process count, TCP 30333/30334 listener count, and temporary diagnostic firewall-rule count are recorded below.
- qrun_v06_node processes: 0; TCP 30333/30334 listeners: 0; temporary diagnostic firewall rules: 0.
