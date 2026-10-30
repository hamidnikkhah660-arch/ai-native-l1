# CP-0461 — QRun v0.5 Bitcoin-style public-alpha peer mode

**Date:** 2026-10-28
**Status (historical, 2026-10-28):** Public-alpha mode was implemented and locally tested. That earlier seed process used a prior candidate identity; it is not a claim that a node is running now.

> **Supersession and safety warning (2026-10-29):** The launch command below uses the historical `70fd…` network identity and must not be used for the current wallet-bound candidate. The current source identity is documented in [CP-0468](CP-0468_QRUN_WALLET_BOUND_IDENTITY_RECONCILIATION_2026-10-29.md) and the [current candidate manifest](../profiles/qrun_v05_wallet_bound_mainnet_identity_candidate.json) (network `8b5d…`). Keep this runbook's old identity/data directory separate. Do not expose either candidate as a public service until a reviewed current onboarding bundle, independent operator verification, and explicit zero-value configuration are approved. A live host check on 2026-10-29 found no node listening on TCP 49339–49341; external reachability is not verified.

## Why this mode exists

Bitcoin v0.1 did not require a hosted external CAS, a three-operator benchmark sign-off, or a formal enterprise release gate before software could be released. QRun should likewise distinguish *running an experimental public network* from *declaring a production Mainnet frozen*. CAS is therefore an optional rollback-protection add-on in this mode, not a prerequisite to execute the chain.

The explicit --public-alpha mode is separate from --local-testnet:
- It selects ConsensusParameters::qrun_v05_calibrated_candidate() instead of the trivial smoke target.
- It defaults the P2P block listener to 0.0.0.0:49341 and permits numeric IP peer addresses outside loopback.
- It continues to bind RPC and transaction ingress to loopback by default, so unauthenticated administrative APIs are not exposed to the Internet.
- It requires a network-bound Noise static private key stored in a Windows CurrentUser DPAPI NPK1 file. The Noise session encrypts records and binds both network ID and consensus-profile fingerprint. Remote peer keys can be pinned for known seeds, but are not mandatory for ordinary public P2P. With no pin, the session is encrypted but the remote peer identity is not independently authenticated; a peer may also choose to pin trusted seed keys.
- It allows bounded encrypted startup sync from configured peers. The current seed list is manually supplied through --peer IP:PORT; pin a seed's static key when independent peer identity is needed. Automatic DNS seed discovery, peer address exchange, transaction mempool gossip and broad DoS/rate limiting are not implemented yet.
- The normal QFP5 block importer, PoW verification, state transition, fork choice and durable PFS2 store remain responsible for accepting received blocks; an encrypted connection alone never makes a block valid.

## Local checks

The following local tests pass:
- cargo test --bin qrun_v05_pow_local_node listener_bind_policy_separates_loopback_and_public_alpha_modes
- cargo test --lib public_inbound_noise_accepts_unpinned_peer_but_binds_network_and_profile
- cargo test --bin qrun_v05_pow_local_node public_alpha_nodes_gossip_unpinned_qfp5_blocks_and_converge
- cargo test --bin qrun_v05_pow_local_node qrun_fee_only_qfp5_authenticated_gossip_and_sync_converge
- cargo test --bin qrun_v05_pow_local_node authenticated_mode_refuses_unpinned_peer_instead_of_plaintext_fallback
- cargo fmt --all -- --check
- cargo check --all-targets --locked

The public-alpha gossip test transfers an actual QFP5 envelope over Noise without pre-pinning the other node, then verifies both nodes agree on tip, height and state root.

## Starting an experimental seed

Build the release binaries from src/native/pow_bench:

    cargo build --release --locked --bin qrun_v05_pow_local_node --bin qrun_v05_noise_keygen

Provision a network-bound Noise identity. The command stores a DPAPI-protected key file; the private key is not printed:

    New-Item -ItemType Directory -Force -Path "C:\QRun" | Out-Null
    $network = "70fdcdbe6f0afa1edb0c4fb4a85252831376f7b9ecf2a13a86dcf61979cdcad7"
    cargo run --release --locked --bin qrun_v05_noise_keygen -- --network-id-hex $network --output-key-file "C:\QRun\node.npk1"

Use the QZXB wallet's verified public account ID and public key for the Genesis owner. Do not put a private wallet key or recovery material into the node command line. A seed node with no outbound peers can start as follows:

    cargo run --release --locked --bin qrun_v05_pow_local_node -- --public-alpha --network-id-hex 70fdcdbe6f0afa1edb0c4fb4a85252831376f7b9ecf2a13a86dcf61979cdcad7 --owner-account-id-hex eee2e72882d770ab6fd7815c905b49e39650c74e8f121b26cbd49e333a3715c8 --owner-public-key-hex 42a45fd22f7483fc75f6c30fc25f156ab958e6eaec7eb683b5badcc90f4f5131 --data-dir "C:\QRun\public-alpha-data" --noise-private-key-file "C:\QRun\node.npk1" --block-listen 0.0.0.0:49341

The example is a command template, not proof of public reachability. A remote peer still needs a reachable public address and port-forward/firewall configuration for TCP 49341 if the host sits behind NAT. The node logs mainnet=false and network_class=public_alpha_experimental_not_mainnet. Do not reuse the same data directory between local-testnet and public-alpha modes.

## Remaining product differences (not launch paperwork)

This candidate preserves the project's already-selected **10-billion QZXB full-supply Genesis allocation** and **zero post-Genesis block subsidy**. That is economically different from Bitcoin v0.1, which issued new BTC through block rewards rather than preminting its entire cap to one Genesis owner. If “exactly Bitcoin” is also intended to mean Bitcoin-style issuance, the next protocol version needs a newly committed Genesis with no full-supply owner premine, a deterministic halving/subsidy schedule, block-committed or consensus-derived rewards, and updated wire/profile vectors; that is a consensus/economics change, not a reason to block public P2P behind a cloud CAS service.

The current mode also lacks automatic peer discovery and transaction-pool gossip. Transactions can be submitted by a local wallet to the node's loopback transaction ingress, then propagated as valid QFP5 blocks. This is a public-alpha path, not yet a complete Bitcoin-equivalent wallet/P2P experience.

## First seed launch on the development host

On 2026-10-28, the release binary was built, a network-bound DPAPI-protected NPK1 key was created at `C:\QRun\node.npk1`, and the seed process was started using the command above. The process reported:
- `mainnet=false`, `network_class=public_alpha_experimental_not_mainnet`
- Genesis height `0`, full supply `10,000,000,000 QZXB`, subsidy `0`
- P2P listener `0.0.0.0:49341`; RPC `127.0.0.1:49339`; transaction ingress `127.0.0.1:49340`
- Local TCP probes to all three ports succeeded; no external peer had connected at the time of verification.

The current remote shell is not elevated. Attempting to install a narrowly scoped Windows Firewall rule returned `Access is denied`, so external Internet reachability is **not verified**. In an elevated PowerShell session, the host operator can allow only the QRun P2P executable/port with:

```powershell
New-NetFirewallRule -DisplayName "QRun Public Alpha P2P 49341" -Direction Inbound -Action Allow -Enabled True -Profile Any -Program "C:\Users\ASUS\Desktop\AI_NATIVE_L1_G2_G8_20261024\src\native\pow_bench\target\release\qrun_v05_pow_local_node.exe" -Protocol TCP -LocalPort 49341 -EdgeTraversalPolicy Block
```

If the host is behind NAT, TCP 49341 also needs forwarding to the host's private LAN address. Do not expose ports 49339 or 49340; those remain local-only.
