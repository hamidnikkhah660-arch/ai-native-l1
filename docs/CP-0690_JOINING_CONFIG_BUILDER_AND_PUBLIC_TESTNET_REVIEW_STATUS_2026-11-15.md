# CP-0690 — Joining Config Builder and Public Testnet Review Status — 2026-11-15

## Repository and preservation state
- Active worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
- Branch: feat/cp0600-bootstrap-sync-startup
- HEAD: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
- CP-0690 supplements CP-0687, CP-0688 and CP-0689; it does not replace them.
- The status count immediately before adding the Joining builder was 91. After adding the one new tool it is 92. This is one additional untracked project file; other pre-existing changes remain untouched.
- No reset, clean, stash, rebase, commit, push or merge was performed.

## Release build and Q6GA v2 runtime verification
The active package Release node binary was rebuilt from the repository lockfile:
- Command: cargo build --release --locked --offline -j 1 --bin qrun_v06_node
- Result: PASS.
- Release binary: src/native/pow_bench/target/release/qrun_v06_node.exe
- SHA-256: 6e1481e80599fd3448a34d200284072309f5044c66b92a312d2165bbc3bb6b22
- Release --help returned exit code 0.

A disposable negative topology probe used exact copies of the real Q6GD, Q6CP, Q6PN, Genesis, bootstrap and Q6GA v2 artifacts. Only the listen address was changed to the documentation-only address 192.0.2.10:30333 and the disposable config hash was recomputed.

Observed Release launcher output:
- owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED
- owner_genesis_approval_scope=ZERO_VALUE_PUBLIC_TESTNET_ONLY
- mainnet_authorization=NOT_GRANTED
- market_authorization=NOT_GRANTED

The launcher then refused the documentation-only listen address with:
- QFP6 PREFLIGHT REFUSED: a non-wildcard public-testnet listen address must be globally routable unicast

The process exited with code 1 as expected. This confirms the real Q6GA v2 Ed25519 + ML-DSA-65 signatures and Q6GD/Q6CP/Q6PN/Genesis/economics bindings are accepted, while the non-public topology is rejected before Seed-key loading, durable-store open or listener bind. The disposable directory was removed. This was not a node startup.

## Seed and Joining protected Noise key reload — PASS
Two separate process-level Windows CurrentUser DPAPI checks were run using the actual protected key files and the repository's locked Cargo dependencies.

Seed:
- protected key SHA-256: a7743aa6c17b7cfeb008d8ef568a4a813fe218bd80f529c327b65284c1a5b584
- seed_dpapi_reload=PASS
- seed_network_binding=PASS
- seed_noise_xx_identity_match=PASS
- network_io=NONE

Joining:
- protected key SHA-256: 2d4023202541ba8534768aa23386b1229f96e387e8197d92068c3d98ddc23c6c
- dpapi_reload=PASS
- network_binding=PASS
- noise_xx_static_identity_match=PASS
- network_io=NONE

Each temporary helper loaded the actual protected key in a newly started process, completed an in-memory three-message Noise XX handshake, and compared the resulting remote static public key against the recorded public identity. No private key bytes or DPAPI plaintext were printed. All temporary helper source files and output/error logs were removed.

Joining identity JSON SHA-256 remained:
120f3d89d07febe29670ed82319f63348db5ef1e7c64c99754f9565c7ee05b1a

Seed/Joining public identity binding remains:
- Seed fingerprint: 9407504ce70ddf91478a82143195fffa6fd3375c52c0776ef223dff1a559ec48
- Joining's independently pinned Seed fingerprint: exact match.
- Network/profile identifiers: exact match.

## Seed package artifact verification — PASS
Read-only verification confirmed that the IPv6 Seed config hash matches the Seed identity's config pin and that the Q6GD, Q6CP, Q6PN, Genesis snapshot, Seed bootstrap set, and Q6GA v2 authorization file match their configured SHA-256 pins.

- IPv6 Seed config SHA-256: dab3e9df70125888710b3a60b22981f62efcb65f1b60a3b38fcd7bbe501f5747
- Q6GA v2 authorization SHA-256: 72d58ef455d9b6f6ab9a5514f5f0fb40f333d347af288363b3897b5584c2f169
- Q6GA authorization artifact size: 5,685 bytes.

The actual public static key bytes were independently re-hashed and matched the Seed identity fingerprint. No key plaintext was read.

## New fail-closed Joining config builder
New tool:
tools/qfp6-public-testnet-joining-config.ps1

SHA-256:
7b2f3647316d78e1a4f2c7ac3b58bc2fabf7216479dcc6a791b8549a9411de9a

Size: 19,583 bytes.

PowerShell parser result: 0 errors.

The builder is prepare-only. It never starts qrun_v06_node, opens a socket, changes firewall/router/VPN/DNS settings, creates the Anchor Vault, or reads/prints DPAPI plaintext. It requires explicit flags confirming out-of-band Seed fingerprint verification and approval to prepare a public-listener Joining configuration.

Before writing any output, the builder verifies:
- numeric Seed and Joining SocketAddr syntax and P2P port 30333;
- Seed endpoint is a specific globally routable unicast address, not a hostname, wildcard, private, documentation, reserved or special-use address;
- Seed public-key fingerprint computed from the Seed identity equals both the explicitly supplied fingerprint and the fingerprint pinned by Joining;
- Seed/Joining roles, Noise transport, network ID and profile ID match;
- Seed config hash is pinned by the Seed identity;
- Q6GD, Q6CP, Q6PN, Genesis and Seed bootstrap artifact hashes match the Seed config;
- Q6GA file is a Q6GA v2 / scope-2 envelope and its SHA-256 matches the Seed config (the actual full dual-signature verification remains the Release launcher's responsibility and was independently tested above);
- Joining DPAPI key file is a regular non-reparse file and its SHA-256 matches the Joining identity;
- output paths are new, distinct and directly inside the package directory;
- Joining data/mempool directories are new, pairwise separate and non-nested with the Anchor Vault;
- no path ancestor traverses a reparse point;
- the proposed Anchor Vault does not already exist and is on a different physical disk from the Joining data directory;
- no qrun node process or existing TCP 30333 socket is active.

When all gates are satisfied, the tool is designed to create three CreateNew artifacts: a Joining bootstrap peer set with one exact Seed endpoint/public-key pin, a Joining-specific Public Testnet config, and a deployment record with hashes, network/profile IDs, physical disk mapping and the explicit no-Mainnet/no-market boundary. Any partial output files are removed if a later CreateNew write fails. The existing joining-noise-identity.json is deliberately not modified; its seed_endpoint placeholder remains unchanged. The actual endpoint and out-of-band verification are recorded in the generated peer/config/deployment artifacts instead.

### Negative builder tests — PASS
No production config was generated. Tests used only disposable arguments and stopped before CreateNew writes:
- Placeholder Seed endpoint: rejected as non-numeric.
- Documentation-only Seed IP 192.0.2.10:30333: rejected as non-routable.
- Valid-format test address with an incorrect Seed fingerprint: rejected by exact fingerprint binding.
- Private Joining listen address: rejected.
- Output path nested below PackageDirectory rather than directly in the package root: rejected.
- Anchor Vault path on the same physical D: disk as the data directory: rejected with "Joining data and Anchor Vault must be on different physical disks."

After all negative tests:
- No Joining config/bootstrap/deployment outputs existed.
- No test Anchor Vault was created.
- Joining identity JSON SHA-256 remained unchanged.
- No node process or listener was created.

The 1.1.1.1:30333 address used in the fingerprint and same-disk negative tests was only a syntactically public test input; the incorrect fingerprint or same-disk path caused refusal before any output was written. It is not a configured or advertised Seed endpoint.

## Current Seed endpoint and independence gate
The actual Joining identity still contains:
NOT_EMBEDDED_REQUIRES_CURRENT_OUT_OF_BAND_ENDPOINT

No stable, owner-approved current Seed endpoint has been supplied to the builder. The transient Wi-Fi IPv6 address observed earlier is not promoted to a permanent endpoint. No Joining config has been generated and no Joining node has started.

The builder's disk check proves only that the proposed Joining data and Joining Anchor Vault paths are on different physical disks on the host where it runs. It does not prove the Joining host is physically, administratively or network-independent from the Seed. A genuine public topology still requires at least one independently operated Joining host/operator and independent verification of the actual Seed endpoint and fingerprint.

## Public website PR #195 — current GitHub status
Repository: hamidnikkhah660-arch/ai-native-l1
PR: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/195

The previous PR description contained an obsolete statement that Q6GA v2 had not yet been owner-signed. That statement was corrected through the GitHub PR metadata update. The updated body now records the owner-signed Q6GA v2, Release signature/binding verification, and the expected negative topology refusal.

Current observed state:
- PR #195: OPEN, not merged, mergeable.
- CI workflow run 43641340965 (Rust validation): completed successfully.
- Jobs: Format/check/test, EVM contract/wallet/dependency audit, and Windows PMT4/TXN4 two-node loopback — all successful.
- Requested reviewers: none.
- Submitted reviews: 0.
- Inline review threads: 0.

The PR remains site/documentation-only. Updating its description does not merge or deploy the public website. An independent reviewer is still required. The Public Testnet has not launched; no live Seed node, independent public seed set, market, listing, market cap or trading volume is claimed.

## Final safety and Git state
- Branch remains feat/cp0600-bootstrap-sync-startup.
- HEAD remains 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3.
- Working-tree status count after creating this tool: 92.
- git diff --check: exit code 0 (existing LF/CRLF normalization notices only).
- qrun_v06_node process count: 0.
- TCP listeners: 30333 = 0; 30334 = 0.
- No firewall, router, NAT, VPN, adapter or DNS settings changed.
- No private key, seed phrase or DPAPI plaintext was emitted.
- No commit, push, merge, rebase, reset, clean or stash was performed.

## Next gates
1. Obtain a stable, owner-approved Seed public endpoint and independently verify its Noise fingerprint over a separate trusted channel.
2. Independently test current inbound TCP 30333 reachability from an external network/operator; outbound IPv6 alone is insufficient.
3. Only after those checks, generate a real Joining config with the new builder and verify its SHA-256/peer file against the final operator-reviewed values.
4. Use an independently operated Joining host. Then run pinned Noise XX, wrong-key rejection, full-history synchronization, restart/catch-up, checkpoint rollover and recovery tests.
5. Keep Public Testnet launch blocked until independent operators and external security/consensus/economics review are in place.
6. Continue tracking PR #195 until an independent reviewer has actually reviewed it and the protected site deployment is confirmed.

## Authorization boundary
Q6GA v2 authorizes only the zero-value Public Testnet scope. Mainnet, public mining as production, real-value transfers, market activity, token sale and exchange listing remain unauthorized. Public Testnet remains NOT LAUNCHED.