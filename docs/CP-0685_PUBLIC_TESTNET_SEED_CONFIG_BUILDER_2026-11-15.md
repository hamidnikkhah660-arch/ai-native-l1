# CP-0685 — Public Testnet Seed Configuration Builder

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Scope: prepare-only; no Public Testnet authorization signed, no listener started.

## 1. Purpose

After CP-0684 introduced Q6GA v2, the next operational friction was converting the exact owner-signed local candidate package into a separate Public Testnet seed configuration without overwriting the local Devnet config or its history.

New script:
`tools/qfp6-public-testnet-seed-config.ps1`

It creates a separate `permissionless-public-testnet-seed.json` only after an actual Q6GA v2 file exists and the operator explicitly supplies `-ConfirmPublicExposure`.

## 2. Seed configuration behavior

- Requires absolute package, listen-address, protected Noise key and output-config paths.
- Requires the output config to be a new file inside the package; never overwrites the local config.
- Requires a Q6GA v2 / scope-2 envelope header. Full dual-signature and artifact binding verification remains mandatory in the Rust node launcher at startup.
- Requires the source manifest to remain local-only, non-public and non-Mainnet, with an already-present local Q6GA v1 owner signature and exact CP-0651 economics.
- Requires an empty bootstrap peer list, because this builder creates a seed role only. Joining-node configuration is intentionally separate.
- Requires the existing canonical data history, checkpoint-segment directory and actual local anchor Vault. It runs `qfp6_anchor_vault.py verify` before producing any config.
- Reuses the exact current Genesis-rooted history and witnessed checkpoint segment. It does not create a fresh chain or reset the Vault; the Public Testnet seed would continue the same network history from the current anchored tip (global generation 1,188 at this checkpoint).
- Sets the exact Public Testnet mode and acknowledgements, public-listener opt-in, seed role, supplied listen address, Q6GA v2 path/hash, supplied protected Noise key path and explicit Vault path.
- Removes local-only Q6GA config references from the generated runtime object and adds a Public Testnet notice.
- Prints the config SHA-256 and exact `--public-testnet-run` command. It never starts the node, opens a firewall, changes router settings or performs port forwarding.

## 3. Guard rails

- `-ConfirmPublicExposure` is required even though the script only writes a config.
- A live `qrun_v06_node` process or occupied TCP 30333 prevents config generation.
- A local Q6GA v1 file is not accepted as a Public Testnet authorization.
- The source package, local Devnet config, local manifest, Genesis files, existing history and actual C: Vault are not rewritten.
- The script does not create or reveal Noise private keys and does not read wallet secrets.

## 4. Verification

- PowerShell parser check: PASS.
- Negative scope test using the existing local Q6GA v1 as a deliberately invalid public authorization: rejected with the expected Q6GA v2/scope error.
- Negative test output config created: false.
- After the negative test: qrun process count 0; TCP 30333 listener count 0.

The script has NOT yet been run against a genuine Q6GA v2 authorization because the owner-signing command has not been executed. Therefore no actual Public Testnet seed config has been generated yet.

## 5. Remaining launch dependencies

- Owner must separately approve and locally sign the Q6GA v2 authorization after reviewing the explicit anonymous Noise XX inbound limitation.
- A real public listen endpoint must be reachable from outside the laptop/network; this script does not prove Internet inbound reachability.
- At least one public seed is required to start; additional independent seed hosts/operators are needed for resilience and credible decentralization.
- Each joining operator needs its own protected Noise key and pinned bootstrap peer set; this seed builder does not generate joining-node configs.
- Public Testnet remains NOT LAUNCHED. Mainnet, public mining and value-bearing transfers remain unauthorized.
- Website PR #195 remains a separate publication gate.
- No commit, push, merge, firewall change, port-forward change or node startup was performed.

Decision: the Windows single-seed config preparation path is now scripted and safely rejects local-only Q6GA. It is ready to consume the genuine Q6GA v2 authorization once the owner signs it; it does not itself make the laptop publicly reachable.

## Execution addendum — 2026-11-15

- Owner explicitly supplied the exact Q6GA v2 confirmation phrase for scope ZERO_VALUE_PUBLIC_TESTNET_ONLY and acknowledged the anonymous, unauthenticated Noise XX inbound MITM limitation.
- Owner signer completed successfully: Q6GA_V2_ED25519_MLDSA65_SIGNED_AND_SELF_VERIFIED.
- Authorization artifact: release/qfp6-local-single-operator-devnet-2026-11-15/public-testnet-authorization.q6ga
- Authorization SHA-256: 72d58ef455d9b6f6ab9a5514f5f0fb40f333d347af288363b3897b5584c2f169 (5685 bytes; matched signer output).
- Seed builder first execution exposed a PowerShell PSCustomObject issue: the source JSON did not predeclare node_role and other new properties. The builder now uses Set-JsonProperty to add missing properties safely; PowerShell parser check passed.
- Re-executed builder successfully after validating the existing local Anchor Vault:
  - Vault sequence 165; manifest generation 1188.
  - Anchor: b4dd74d78094995675ebf16b73db1c0eb40cfa13ae8ef6bf6fd3275ba10ede64
  - Record SHA-256: d6176a2730542d48b1a703c2954dacc4a7ddd580826b9674012e4a8a9e83096d
- Created release/qfp6-local-single-operator-devnet-2026-11-15/public-testnet-seed-config.json using wildcard bind 0.0.0.0:30333, role seed, and empty bootstrap peer set.
- Seed config SHA-256: 4315cef3393edc3d2448a51b3e8945c7dd1c2b0e2d7011215f4c2d23708684b6 (3162 bytes).
- The local source package and local-only manifest were not overwritten. Config creation used the existing canonical history and Vault; it did not initialize a new history.
- No node was started; TCP 30333 had zero listeners after config creation. No Windows Firewall, router, NAT, VPN, or other network setting was changed.
- Remaining external launch gates: qualify a real public inbound route and host reachability; establish independently operated seed peers/operators; resolve the documented Noise XX unauthenticated inbound MITM limitation or explicitly accept it as the initial zero-value testnet threat posture. Mainnet, market, and value-bearing transfers remain unauthorized.

## External route assessment addendum — 2026-11-15

Read-only Windows network inspection after seed-config creation:

- Active Wi-Fi has a router-advertised IPv6 /64 and preferred global-unicast-candidate addresses, but this alone does not establish inbound reachability.
- The active default IPv4 egress selected for a real outbound TCP 443 test was Ethernet 2, identified as TAP-Windows Adapter V9, with a private tunnel source address. The outbound IPv4 test succeeded through that adapter.
- The outbound IPv6 TCP 443 test to ipv6.google.com failed (no remote address selected); direct IPv6 egress is therefore not established in the current routing state.
- The Wi-Fi and TAP adapter profiles are Public. Windows Firewall profiles are enabled.
- No enabled inbound Allow rule was found for TCP/UDP local port 30333, and no inbound application rule was found for the current qrun_v06_node.exe release path.
- No node process or TCP 30333 listener exists.
- No adapter, VPN, firewall, router, NAT, port-forwarding, or DNS setting was changed. The VPN was deliberately left connected to preserve Desktop Commander access.
- Conclusion: the present session has not established a public inbound route to this laptop. The successful outbound IPv4 test is through the VPN/TAP interface and is not evidence of inbound P2P reachability. The Wi-Fi global IPv6 address classification is not enough to claim routability or reachability; a direct test would require deliberately routing a probe outside the VPN and would expose the home/ISP IPv6 address to the test endpoint. That probe was not performed.
- Do not start the public seed yet. Next safe options are (a) use an independently hosted public seed endpoint, or (b) with explicit user approval and a safe reconnection plan, test direct Wi-Fi IPv6 reachability while accounting for the VPN/remote-session dependency. No network changes are authorized by this assessment.
## Zero-cost direct IPv6 qualification addendum - 2026-11-15

This addendum supersedes the earlier statement that direct Wi-Fi IPv6 egress had not been established; it does not supersede the finding that inbound reachability remains unproven.

- Wi-Fi interface index 18 was Up and had a Preferred IPv6 address plus an active IPv6 default route through its router.
- A direct IPv6 HTTPS request was successfully bound to that Wi-Fi IPv6 source address using curl.exe -6 --interface; Cloudflare returned HTTP 200. The test did not print or persist the public source address. This proves direct outbound IPv6 from Wi-Fi, not inbound reachability.
- Source inspection confirms the public-testnet listener parses a Rust SocketAddr and binds with TcpListener::bind; IPv6 SocketAddr is supported by the implementation. Public-testnet topology validation accepts an unspecified IPv6 bind address, and joining peers must use publicly routable unicast IPs.
- Created a separate, non-overwriting IPv6 seed candidate config: release/qfp6-local-single-operator-devnet-2026-11-15/public-testnet-seed-config-ipv6.json
- IPv6 candidate config SHA-256: dab3e9df70125888710b3a60b22981f62efcb65f1b60a3b38fcd7bbe501f5747; listen address [::]:30333; role seed; empty bootstrap set.
- Canonical Anchor Vault verification passed during creation: sequence 165, generation 1188, anchor b4dd74d78094995675ebf16b73db1c0eb40cfa13ae8ef6bf6fd3275ba10ede64.
- The original IPv4 seed config was not overwritten. The new config was created with CreateNew semantics.
- No node was started; TCP 30333 listener count remained zero. No firewall, router, NAT, VPN, adapter, or DNS setting was changed.
- Remaining gate: inbound IPv6 reachability through both the Windows Firewall and home router must be proven with a temporary diagnostic listener before considering the actual node. The existing Noise XX inbound MITM limitation also remains unresolved.
## Confirmed zero-cost inbound IPv6 diagnostic - 2026-11-15

- The earlier TCPData API probe was treated as inconclusive: it returned status=open with HTTP 403, but the local diagnostic listener did not record an accepted connection.
- A second independent check used the IPv6 port-check API on Port.Tools against the Wi-Fi IPv6 address and TCP 30333 while the temporary diagnostic listener was active.
- Port.Tools returned result=True.
- The local diagnostic listener independently logged INBOUND_CONNECTION=ACCEPTED with remote address family InterNetworkV6. This is the decisive confirmation that an external IPv6 host reached the laptop's Wi-Fi IPv6 TCP listener on port 30333.
- The temporary Windows Firewall Allow rule was restricted to the selected Wi-Fi IPv6 local address, TCP local port 30333, and Public profile. It was removed automatically after the test.
- The diagnostic TcpListener was stopped automatically. Post-test verification: temporary firewall rule count 0; TCP 30333 listening sockets 0; qrun_v06_node process count 0.
- No router, NAT, port-forwarding, VPN, adapter, or DNS setting was changed. The VPN remained connected.
- The test did not start the QFP6 node and did not expose any private key or seed material.
- No IP address was written into this checkpoint.
- Conclusion: this laptop currently has a proven inbound IPv6 path to TCP 30333. The IPv4 route remains VPN/TAP-based; IPv6 is the zero-cost candidate route for the seed.
- Remaining launch gates are independent of basic network reachability: resolve or explicitly accept the already-disclosed anonymous unauthenticated Noise XX inbound MITM limitation, verify the final runtime configuration and node startup gates, and obtain explicit launch authorization before starting the actual public seed. Mainnet, market, and value-bearing transfers remain unauthorized.
## VPN adapter cross-check clarification - 2026-11-15

- A post-test status query initially selected the first TAP adapter, which belongs to the separate OpenVPN Connect virtual adapter and is Disconnected.
- The active VPN/TAP path is the distinct "Ethernet 2" adapter (TAP-Windows Adapter V9), which remains Up. A fresh outbound TCP 443 route check succeeded via Ethernet 2 (interface index 10).
- Therefore the active VPN route remained connected throughout the diagnostic; the disconnected OpenVPN Connect adapter was not the active route. No VPN setting or adapter state was changed.
## Active public-runtime Noise identity audit - 2026-11-15

Read-only source inspection after IPv6 reachability qualification:

- The active public-testnet launcher selects run_qfp6_permissionless_mining_supervisor_open when no outbound pinned bootstrap peers are configured.
- That open supervisor calls the generic permissionless supervisor with an empty trusted_remote_static_public_keys slice.
- The QRun V06 peer listener distinguishes pinned sessions from unverified sessions; an unpinned remote static key increments unverified_peer_sessions, not authenticated_sessions.
- A separate DevnetNoiseSession candidate supports explicit remote static-key pinning, but source search did not find it wired into the active qrun_v06_node public-testnet launch path.
- Therefore the current public seed path accepts anonymous/unpinned inbound peer identities. The owner-signed Q6GA v2 authorizes the zero-value testnet scope but does not by itself establish an authenticated seed Noise identity for joining operators.
- Before launch, provide an authenticated out-of-band seed identity and a joining-node config that pins it, or explicitly decide to retain the acknowledged MITM risk after reviewing the exact threat boundary. Required tests: wrong seed key rejection, active MITM relay rejection, network/profile mismatch rejection, and restart/rotation behavior.
- No code was modified in this audit. No node was started. Public Testnet remains NO-GO pending the README/CP-0652 independent launch gates, including independent operator/reviewer readiness.
## Noise XX directionality and pinned-joining clarification - 2026-11-15

A deeper call-path audit refines the earlier generic MITM warning:

- The public Seed is the Noise responder for inbound connections. Its permissionless listener may accept anonymous initiators and therefore does not authenticate every joining client's static identity. This is an explicit server-side peer-admission property, not proof that the Seed identity is unverified to clients.
- The Joining side is the Noise initiator. `QRunV06NoiseSession::connect` receives the operator-supplied Seed static public-key pin, completes the first two XX messages, compares the responder static key to the exact pin, and rejects a mismatch before sending message three or exposing an application transport session.
- `load_peers` parses both the numeric `address` and `noise_static_public_key` for each bootstrap peer. The configured bootstrap-peer file is SHA-256 pinned by the runtime config.
- The active pinned history-sync client calls `QRunV06NoiseSession::connect` with `peer.noise_static_public_key`; it does not rely on the anonymous responder-side identity of the joining node.
- Consequently, an out-of-band-pinned Joining client authenticates the Seed and protects the end-to-end Noise session against a network MITM that attempts to impersonate the Seed or decrypt/re-encrypt the session. A byte-forwarding TCP relay remains possible, but it cannot terminate the pinned session without failing the key check. The Seed still does not authenticate the joining client's identity unless a separate inbound trust policy is configured; open permissionless ingress intentionally allows anonymous peers.
- Earlier generic comments describing active MITM termination/re-encryption apply to a genuinely unpinned session. They must not be generalized to a Joining client that uses the pinned `connect` path above.
- This clarification does not waive the need for an independently verified fingerprint, a correct bootstrap peer-set hash, application-level admission controls, independent operators/reviewers, or explicit launch authorization.

No node was started and no network settings were changed during this audit.