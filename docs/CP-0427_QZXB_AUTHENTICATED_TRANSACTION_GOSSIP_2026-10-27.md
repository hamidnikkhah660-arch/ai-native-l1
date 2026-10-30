# CP-0427 ? Authenticated QZTG/1 transaction gossip (2026-10-27)

## Scope

Add transaction gossip over the existing statically pinned, Noise-authenticated QZBE v0.4 peer listener. Wallet ingress uses QZTS/1; peer-relayed transactions use a distinct QZTG/1 frame on the authenticated Noise record layer. The transaction pool remains bounded and process-local, and the ingress endpoint remains loopback-only.

## Wire framing and admission

QZTG/1 frames are `QZTG` magic, a big-endian protocol version, the 32-byte QZBE profile fingerprint, a big-endian u32 payload length, and exactly one canonical TXN2 payload. The Noise prologue binds the network ID; the frame explicitly binds the profile fingerprint. The decoder validates magic/version/profile/exact framing and the same transaction payload byte cap before transaction decoding.

An authenticated peer transaction is decoded and admitted using the same `BoundedMempool` admission rules used by wallet ingress. Signature, sender/account binding, network, nonce, expiry, fee, and balance checks remain in the existing transaction/mempool validation path. A first-seen valid transaction receives an encrypted QZTA/1 ACK and is relayed to all statically pinned outbound peers except its immediate source. Duplicate ACKs suppress relay loops. Invalid frames and invalid transactions receive rejection ACKs without modifying the pool. Peer failure is logged and isolated per destination, not allowed to falsely advertise a successful ACK for the failed peer.

Wallet-origin transactions are acknowledged at local admission and then relayed to the pinned peer set. The ACK denotes pool admission at the destination; it is not itself a block confirmation.

## Mining responsiveness

PoW candidate search now polls the optional QZTS listener at each nonce-attempt cancellation point. The first newly accepted TCP connection interrupts that search, queues the bounded connection, and returns control to the runtime. The node then decodes/validates/adopts or rejects the transaction outside the fork-choice borrow, reconciles the pool, and resumes mining with the updated deterministic transaction set. Ingress-triggered mining cancellations do not consume the configured number of successfully mined blocks.

## Local integration target

`simulations/cp0427_qzxb_three_node_transaction_gossip.ps1` provisions three independent DPAPI-protected Noise identities and three separate QZBE data directories. Node B is the miner and wallet ingress point, with statically pinned peers A and C. The scenario:

1. submits a tampered TXN2 and expects atomic rejection with mempool count zero;
2. submits the valid self-contained Ed25519 transfer using QZTS/1;
3. expects successful QZTG/1 delivery/ACK and admission at both peer nodes;
4. mines the transaction into a canonical candidate block and relays the block to both peers;
5. checks exact recipient atoms, height, state root, tip and restart replay convergence on all three stores.

The local Windows Release integration passed on 2026-10-27 with exit code 0 (runtime 171.92 seconds). It printed `CP-0427 INVALID_SIGNATURE_REJECTED_ATOMICALLY_PASS`, `CP-0427 WALLET_TO_NODE_QZTS_TRANSACTION_ADMISSION_PASS`, `CP-0427 TRANSACTION_GOSSIP_REACHED_BOTH_PINNED_PEERS_PASS`, and `CP-0427 THREE_NODE_BLOCK_STATE_ROOT_TIP_REPLAY_CONVERGENCE_PASS`. The tested transaction ID was `2cf46b14835e22e4801234db8d22056dcf90f0b2f3c43c2db725d98630e339e2`; the disposable receiver balance was `10000000000000000` atoms. Before the integration, `cargo +stable fmt --all -- --check`, `cargo +stable check --all-targets --locked`, all three QZTS/QZTG/QZTA codec tests, public-docs, tokenomics, and the independent CP-0419 checkpoint oracle passed. The exact-head CI for this new source SHA is still required before this checkpoint is CI-verified.

## Deliberate boundaries

- This remains an opt-in QZBE candidate. Legacy PTB2/PFS2 default runtime behavior is not silently migrated.
- All configured peer listeners and transaction ingress listeners remain loopback-only; there is no Internet-reachable public node.
- Peer identities are provisioned out of band and peers are statically pinned; no untrusted peer discovery, signed dynamic trust registry or robust peer rotation is provided by QZTG/1.
- Transactions in the mempool are not yet durable; process restart loses pending transactions. Mempool synchronization, late-join state bootstrap, and archive-based catch-up for a new node remain separate work.
- An authenticated peer's QZTG request shares the existing sequential Noise peer server with block delivery. Mining now yields for local QZTS ingress; peer acceptance during long mining remains a separate responsiveness test and must be addressed before any external deployment.
- No Mainnet balance, market listing, trading pair, liquidity or independent security audit is created by this work.

This is a local protocol/runtime experiment, not an instruction to expose a node to untrusted Internet traffic.
