# CP-0844 — QFP6 CP-0843 Single-Seed Automatic Peer Discovery and Operator Bundle
Date: 2026-11-23
Scope: ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY
Status: CP-0843 live on the primary Seed and same-host Joiner; optimized Release binary built; Windows operator bundle staged and verified; first independent external peer NOT YET PRESENT.

## 1. Operator constraint and topology
The project owner operates one Windows x64 laptop and one Internet connection. This is sufficient to host the first public bootstrap Seed; additional Seed machines are not required from the owner. Tailscale Funnel is currently active:
- Public TCP endpoint: heymed.tail2a756d.ts.net:443
- TLS-terminated TCP forwarded to localhost:30336
- Primary Seed listener: 0.0.0.0:30336
Joining clients can use outbound-only mode and do not need public IP, inbound port-forward, firewall rule, router change, or tunnel of their own.

## 2. Live processes last verified 2026-11-23
- Primary Seed PID 10092: CP-0843 debug executable; config hash a7fc3639e7b9a1eed4eac5c3b9af5a9ccc2e459ace3d8de09ac1e6096798255b; listener 0.0.0.0:30336.
- Local QA Joiner PID 10084: same CP-0843 debug executable; config hash a9483651505c3806855c6c637bd0ea611e742309da92b26c6e017b0873a1984b; listener 127.0.0.1:31434 only.
- Backup Seed PID 5800: older CP0817 executable; config hash 66d34df369370af6161aa8266c451cf7cd9eafc465646c96cfcef4fead8dc0d8; listener 0.0.0.0:30337; left untouched.
No node keys, TPM bindings, live configs, or listeners were changed during package staging.

## 3. Verified live discovery behavior
The CP-0843 Joiner successfully resolved the pinned Seed hostname through multiple DNS routes, established TLS with SNI heymed.tail2a756d.ts.net, completed the three-message Noise handshake, pulled and refreshed signed Q6PD peer records, and exercised Q6PX/Q6PY bidirectional gossip. The Seed logs confirmed signed-record pull response and gossip acceptance.

The current Q6PD record set still contains only the Seed peer identity. Different resolved IP addresses are different network routes to the same hostname/key, not independent nodes. The Joiner is on the same physical laptop and does not count as an independent operator. No live multi-host mesh or independent external identity is claimed.

## 4. Bitcoin-inspired peer discovery implementation
CP-0834 provides DNS-seed route failover and pinned bootstrap transport.
CP-0839 provides:
- Q6PX bounded third-party signed-record push and Q6PY acknowledgement over an established Noise session;
- Ed25519 signature, exact Network ID/Profile ID, endpoint, TTL, peer-ID, sequence/replay and batch-bound checks;
- a durable Q6PD Address Manager with new/tried pools, randomized selection, IPv4 /16 and IPv6 /32 diversity groups, attempt/success/failure history, exponential failure backoff (30s to 6h), successful-peer cooldown (5 min), bounded capacity (256 entries);
- third-party records remain untrusted route hints; no auto-trust. Auto-dial occurs only when the live Noise static key matches the exact key from the verified signed record.
This is a QFP6-native Bitcoin-inspired implementation, not Bitcoin wire protocol compatibility and not a byte-for-byte clone of Bitcoin Core''s complete AddrMan policies. Bitcoin nodes are not QFP6 peers.

## 5. CP-0843 optimized Release binary
Built successfully using:
cargo build --locked --offline --release --bin qrun_v06_node -j 1
Path:
D:\Temp\ASUS\QRUN_QFP6_UNIFIED_20261118\src\native\pow_bench\target\release\qrun_v06_node.exe
SHA-256:
519e695aed1a0b68195f841c167c06e4fe23176eb50cd96476a34113233c0470
Size: 5,823,488 bytes.

The separate optimized Release-profile test-target compilation exceeded 1 GiB Rust compiler working memory and was stopped before test execution. No Release-profile test result is claimed. The dated CP-0839 engineering note records focused test PASS evidence: 3 Address Manager tests, 1 signed-record push/ack round-trip including tamper rejection, and 1 bidirectional pinned Noise integration test. The prior engineering note remains the source of that evidence.

## 6. Operator bundle staged locally
Folder:
D:\QJ6\QFP6_PUBLIC_ALPHA_NODE_CP0843_20261123
ZIP:
D:\QJ6\QFP6_PUBLIC_ALPHA_NODE_CP0843_20261123.zip
Sidecar:
D:\QJ6\QFP6_PUBLIC_ALPHA_NODE_CP0843_20261123.zip.sha256
ZIP size: 53,689,703 bytes
ZIP SHA-256:
f54b0b811f443a42ceb0aaab2bf56d167ed30cf4b721a223fd493057b07bdfa9

Node binary in package SHA-256:
519e695aed1a0b68195f841c167c06e4fe23176eb50cd96476a34113233c0470

Standard package verifier PASS:
- expected executable / identity utility / bootstrap / Genesis / profile / Q6PN / authorization hashes match;
- Anchor Vault baseline count 20,501;
- checkpoint base hash matches;
- no node-local private key, TPM metadata or generated local config material;
- SHA256SUMS coverage = 22,637 files;
- QFP6_PUBLIC_ALPHA_PACKAGE_VERIFY=PASS.
The full 22,637-file rehash mode was not run.

The ZIP was independently checked after packaging: 22,638 archive entries; inner ZIP hashes for qrun_v06_node.exe, README.md, PACKAGE-METADATA.md and verify-package.ps1 match the embedded SHA256SUMS manifest; .sha256 sidecar matches the final ZIP bytes.

## 7. Distribution and recruitment
- Public operator intake Issue #204 updated with the outbound-only onboarding path and request for separately administered operators.
- Issue #204: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/204
- PR #205 remains Draft. The old CP-0834 draft Release only has its checksum sidecar uploaded; it does not have the ZIP and must not be treated as the CP-0843 package.
- The CP-0843 source worktree was dirty and includes local uncommitted engineering changes. The exact binary/package hashes are recorded, but the public branch HEAD alone is not claimed to reproduce the package. The CP-0843 bundle is a review candidate, not a public audited installer. Do not silently publish or advertise it as code-reviewed/reproducible.

## 8. Next action
1. Keep primary Seed and Funnel running.
2. Review and publish the exact CP-0843 source changes and bundle only after the source/provenance and inbound Noise XX security boundaries are clearly reviewed.
3. Onboard the first genuinely independent QFP6 host. Outbound-only mode works behind NAT; no public relay is required to participate as a joining node.
4. Observe its fresh locally generated Noise and Ed25519 Q6PD identity, verify signed record at the Seed, verify pull/gossip and chain state convergence, restart/reconnect, then observe genuine peer diversity.
5. A true peer count increase only happens after such an independent host joins; never count multiple local processes or DNS routes as external nodes.

Security boundaries remain:
- ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY;
- no Mainnet, real-value transfers, issuance/rewards, or market authorization;
- inbound Noise XX is anonymous before application-layer Q6PD identity checks;
- transport is classical X25519, not post-quantum;
- no independent security audit or full Internet multi-host soak is claimed.
