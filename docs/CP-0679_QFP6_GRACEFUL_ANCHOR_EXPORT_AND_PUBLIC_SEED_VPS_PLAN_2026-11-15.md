# CP-0679 - QFP6 Graceful Anchor Export and Public Seed VPS Plan

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: feat/cp0600-bootstrap-sync-startup
Worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Depends on: CP-0678
Status: LOCAL RELEASE CODE BUILDS; 38/38 LAUNCHER TESTS PASS; ANCHOR EXPORT ON CLEAN STOP ADDED; PUBLIC SEED HOSTS NOT PROVISIONED.

## 1. Owner question: second laptop

A second physical laptop is not required for public seed infrastructure. The proposed topology is:
- existing Windows laptop remains the development/management workstation;
- two rented public VPS hosts run the seed nodes;
- each VPS gets its own locally generated protected Noise private key;
- only public IP:port and public-key fingerprint leave that VPS.

Two VPSs on different providers / ASNs improve infrastructure diversity, but they do not automatically prove independent administration. The two trust domains must be backed by actual separate control/administration evidence. Two VMs, two IPs, or two provider accounts controlled by the same operator must not be described as independently administered without evidence.

The prior CP-0655 host profile remains the baseline:
- Ubuntu 24.04 LTS, x86_64
- 4 vCPU, 8 GiB RAM, 60-80 GiB SSD/NVMe
- stable public IPv4 or globally routable IPv6
- public P2P TCP reachability only after all launch gates pass
- different providers and ASNs preferred.

## 2. Local QFP6 graceful anchor export

Source changed:
`src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/permissionless.rs`

After the permissionless supervisor returns successfully on controlled shutdown, the launcher now calls `runtime.status()` and prints:
- `final_manifest_generation`
- `final_manifest_anchor`
- `final_canonical_height`
- `final_canonical_tip`
- `final_canonical_state_root`
- `anchor_rotation_status=EXPORT_ONLY_REQUIRES_OUT_OF_BAND_OWNER_PIN`

Security property:
- this is a diagnostic/export value from the verified runtime status API;
- the launcher does NOT rewrite `trusted_manifest_anchor`;
- local state is never silently promoted into future trust;
- if final status cannot be read, the launcher returns an error rather than claiming a completed anchor export.

This supports a clean-stop operator workflow: stop the node using its OS shutdown handler, inspect the final generation/anchor/state identity, independently validate/pin the successor out of band, then update the config digest through the approved procedure before restart.

Crash recovery and continuous production-grade anchor witnessing remain a separate design requirement. A local exported anchor alone is not independent consensus or a third-party witness. A continuously running public seed cannot rely on manual per-block Google Docs updates; the public profile still needs a robust external/witnessed monotonic anchor mechanism and qualified operator process.

## 3. Validation

Completed:
- `cargo fmt --all -- --check`: PASS
- `cargo test --bin qrun_v06_node --locked --offline -j 1`: 38 passed, 0 failed
- `cargo build --release --bin qrun_v06_node --locked --offline -j 1`: PASS
- Release binary `--help` smoke check: exit 0
- `git diff --check`: exit 0 (only existing LF/CRLF conversion warnings)

Existing unrelated unused-import/dead-code warnings remain in the library. No test failure was observed.

Pre-change source backup:
`D:\Temp\QFP6_CP0679_source_backup\permissionless.rs.pre-anchor-export.bak`
SHA-256:
`fda41b1ff8179bbb6dd8b14730ae30a27d40b382658ef61d820c314f5a114e98`

## 4. Deployment decision

- No second laptop purchase.
- Do not provision public ports or publish seed endpoints yet.
- Do not use the existing local Windows laptop as one public seed and a same-home second VM as the other.
- Do not launch public Testnet merely because rented VPSs exist.
- Preserve CP-0655 and CP-0670 external gate requirements: independent operator/trust domains, owner Genesis signing, protected node keys, public reachability, security acknowledgement, external full-history tests and independent reviews.
- Public Testnet and Mainnet remain NO-GO.

## 5. Next controlled sequence

1. Complete and test clean-shutdown anchor export on a disposable data copy when a genuine OS Ctrl-C/SIGTERM can be delivered to the node process; do not force-kill and call it graceful.
2. Design a crash-safe, monotonic external anchor/witness mechanism suitable for continuously advancing public seed stores. Do not use manual local config rewriting as a substitute.
3. Provision the two VPS hosts only after choosing two genuinely independent administrators/trust domains and confirming provider network diversity.
4. Inspect hosts, OS versions, routes, storage, ports and resource limits before generating each host's Noise key locally.
5. Keep public listener and firewall changes closed until Genesis/profile/config pins, operator acknowledgements, and independent review gates are satisfied.

CP-0679 records an engineering improvement and a low-friction infrastructure route. It does not claim clean-shutdown output was integration-tested, public seed readiness, public reachability or a Testnet launch.
