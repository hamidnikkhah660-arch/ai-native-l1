# CP-0426 ? QZXB live TXN2 ingress and bounded mempool (2026-10-27)

## Purpose

Move the QZBE v0.4 candidate one concrete step beyond transactions supplied as process-start arguments: a wallet can send a signed TXN2 payload to a running node, receive an admission acknowledgement, and have an admitted transaction selected for the next candidate block. The work remains an opt-in, loopback-only runtime candidate; it does not activate the canonical default node or claim Mainnet readiness.

## Protocol added

- `QZTS/1` request: 10-byte header (`QZTS`, version `1`, big-endian u32 payload length), followed by exactly one canonical TXN2 byte string. Both the advertised length and payload are bounded by the existing TXN2 parser limit before admission.
- `QZTA/1` acknowledgement: fixed-width 43-byte response carrying version, `accepted` / `duplicate` / `rejected`, current pending-pool count, and transaction ID (zero ID on rejected input).
- The optional `--tx-listen` endpoint is required to be loopback and cannot reuse the authenticated block-peer listener. It is disabled unless explicitly configured. Per-connection read/write timeouts, an eight-request-per-poll limit, a process-local submission budget, and existing pool count/byte limits bound ingress work.
- The existing wallet defaults to a self-contained Ed25519 signature envelope: 32-byte public key followed by the 64-byte Ed25519 signature. The node derives the account identifier from the embedded key and verifies it strictly against the transaction signing digest. The legacy 64-byte signature remains available for registry-bound fixtures. This is an additive validation rule within the existing TXN2 signature field, but it is consensus-affecting behavior and must be frozen/versioned and reviewed before any public production network.

## Runtime behavior

1. The node decodes TXN2 only after validating a bounded request header.
2. Admission checks the existing canonical ledger preview for network, signature, nonce, amount/fee, expiry and account-balance validity; rejected attempts do not mutate the pool.
3. The process-local `BoundedMempool` revalidates against the latest canonical state before selection, uses its deterministic sender/nonce ordering, and removes transactions only after the corresponding block is accepted locally.
4. The wallet can use `--submit-to IP:PORT`; an `accepted` acknowledgement means pending-pool admission, not confirmation. It is not proof of block inclusion, external-node reachability or Mainnet existence.
5. The new CP-0426 Windows Release loopback scenario passed locally on 2026-10-27. It submitted a tampered self-contained signature first and received `rejected` with pool count 0; the wallet then submitted the valid TXN2 and received `accepted` with pool count 1. The candidate miner included it by height 3, the recipient balance matched the exact atom amount, and two independent local stores converged on state-root/tip with `replay=matched`. The script exits 0 and prints `CP-0426 TWO_NODE_STATE_ROOT_TIP_REPLAY_CONVERGENCE_PASS`.

## Validation and runbook

- Formatter: `cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`
- Compile every target: `cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked`
- The ingress framing, self-contained-signature, QZBE parser/runtime, and wallet tests are exercised directly by `simulations/cp0426_qzxb_live_tx_ingress_mempool.ps1`.
- The local Windows Release script, QZTS/1 codec tests, self-contained-auth regression, wallet tests, full `devnet_node` test suite, explicit loopback-binding guard test, and `cargo +stable check --all-targets --locked` passed on this worktree.
- That script is wired into the Windows job of `.github/workflows/rust-ci.yml`. The exact-head GitHub Actions run is still required before this checkpoint is considered CI-verified.

## Boundaries still open after CP-0426

- The QZBE store/consensus remains explicitly dispatched and isolated; legacy PTB2/PFS2 is not silently reinterpreted or migrated.
- Ingress still binds only to loopback. There is no public RPC or Internet-reachable transaction endpoint in this checkpoint.
- Pending transactions are in-memory and not relayed to peers. Authenticated peer transport currently carries candidate blocks, not a production transaction gossip protocol.
- Fresh-node bootstrap/chain synchronization across independent hosts, robust reorg/recovery under production load, independent security review, external anti-rollback/CAS anchoring, release deployment, and operational monitoring are not established here.
- Founder allocation/balance shown by these runs exists only in disposable candidate genesis/state. No Mainnet balance, exchange listing, trading pair or liquidity is created.

This checkpoint is engineering progress and test evidence, not an independent security audit or permission to expose a node to untrusted Internet traffic.
