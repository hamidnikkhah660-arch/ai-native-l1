# CP-0461 — QRun v0.5 Bitcoin-style public-alpha peer mode

**Date:** 2026-10-28
**Status:** Public-alpha mode implemented and locally tested. This is a runnable public-P2P candidate, not a claim that an internet-reachable network has already been started.

## Why this mode exists

Bitcoin v0.1 did not require a hosted external CAS, a three-operator benchmark sign-off, or a formal enterprise release gate before software could be released. QRun should likewise distinguish *running an experimental public network* from *declaring a production Mainnet frozen*. CAS is therefore an optional rollback-protection add-on in this mode, not a prerequisite to execute the chain.

The explicit --public-alpha mode is separate from --local-testnet:
- It selects ConsensusParameters::qrun_v05_calibrated_candidate() instead of the trivial smoke target.
- It defaults the P2P block listener to 0.0.0.0:49341 and permits numeric IP peer addresses outside loopback.
- It continues to bind RPC and transaction ingress to loopback by default, so unauthenticated administrative APIs are not exposed to the Internet.
- It requires a network-bound Noise static private key stored in a Windows CurrentUser DPAPI NPK1 file. The Noise session encrypts records and binds both network ID and consensus-profile fingerprint. Remote peer keys can be pinned for known seeds, but are not mandatory for ordinary inbound/outbound public P2P.
- It allows bounded authenticated startup sync from configured peers. The current seed list is manually supplied through --peer IP:PORT; automatic DNS seed discovery, peer address exchange, transaction mempool gossip and broad DoS/rate limiting are not implemented yet.
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

The current mode also lacks automatic peer discovery and transaction-pool gossip. Transactions can be submitted by a local wallet to the node's loopback transaction ingress, then propagated as valid QFP5 blocks. This is a public-alpha path, not yet a complete Bitcoin-equivalent wallet/P2P experience. The public listener has not been started from this change, and remote Internet reachability has not been verified.
