# CP-0418 ? QZBE static multi-peer support and three-node loopback

Date: 2026-10-26

Status: **local three-node integration passed; exact-head CI pending; loopback-only candidate**

## What changed

- QZBE now accepts repeated --peer entries and repeated --trusted-peer-key-hex entries. Each outbound peer address is paired by order with one pinned static public key; additional trusted pins authorize inbound Noise sessions.
- The runtime rejects duplicate peer addresses, duplicate or zero trust keys, non-loopback peers, a peer equal to the local listener, more than 16 configured outbound peers, more than 32 trusted identities, and any outbound peer without its corresponding pin.
- Mining sends each locally produced block to every configured outbound peer and requires each peer ACK to bind the expected block digest and the same canonical snapshot. Inbound Noise authentication accepts only the configured trust set. No automatic discovery or unpinned peer fallback was added.
- Existing two-node tests remain explicitly --test-easy-pow; the node's default profile stays the v0.4 64 MiB Argon2id candidate profile. Public binds remain prohibited.

## Local verification

simulations/cp0418_qzbe_three_node_multi_peer_loopback.ps1 passed on Windows release binaries, exit code 0. It creates three independent temporary data stores, provisions three separate protected Noise identities, configures a static peer mesh and has node A mine two blocks. A sends each block to both B and C; both receivers validate the signed 2,500-atom transaction and QZBE PoW, independently persist and accept both blocks, and each store is closed/reopened for replay. The script asserts that all three nodes have the same height-2 state root and tip, that A sent four peer deliveries, that B and C accepted two blocks each, that the tampered-signature probe was rejected atomically, and that public bind was denied.

Observed local run:
CP-0418 QZBE_THREE_NODE_MULTI_PEER_PASS height=2 state_root=4bda54c832097f399f0bd71d477b0bdde587e199befc4fd45caf3a9929560101 tip=9679bb66d2a4dc858c8af85917964b974b2864733d051af90b8d1b25e4936c75 nodes=3 sent_peer_blocks=4 accepted_each=2 balance_atoms=2500 invalid_signature=atomically_rejected replay=matched public_bind=denied.

The focused Rust parser test also passed. A fresh CI run including the three-node scenario is required for this checkpoint; the preceding commit's green CI is not substituted.

## Limits and next step

These are three processes on one Windows host using loopback addresses and a test-only easy-PoW flag. This demonstrates static multi-peer delivery to independent stores, not public network reachability, independent operators, peer discovery, dynamic membership, gossip/flood control, production difficulty tuning, or network-wide reorg convergence under concurrent competing miners. QZBE remains isolated from the default canonical node lifecycle. The external CAS provider is still only an interface/test fixture; no independently administered production rollback anchor is deployed. Gate 2, Gate 8, the public zero-value-devnet gate, and the independent security/release gates remain open. This checkpoint does not authorize a public value-bearing network, founder mint/transfer, or a QZXB/USDT market.
