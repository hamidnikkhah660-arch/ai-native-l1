# CP-0440 â€” Explicit Public Zero-Value Testnet Transaction Ingress

**Date:** 2026-10-27
**Status:** Candidate implementation and same-host integration exercise; no production approval.

## Purpose

CP-0434 enabled explicitly opted-in public P2P binding for the QZBE candidate. This packet adds an equally explicit, separately gated option for public **transaction ingress** so a testnet participant can submit a signed TXN2 through QZTS/1. This is strictly an easy-PoW zero-value testnet feature, not a way to enable value-bearing Mainnet traffic.

## Operator configuration

The qzbe_v04_peer_node candidate requires all of these before a non-loopback transaction listener is accepted:

- --tx-listen 0.0.0.0:PORT (or another concrete non-multicast bind)
- --test-easy-pow
- --public-testnet-p2p
- --public-testnet-tx-ingress

The flag is rejected if duplicated, without --tx-listen, or unless both test-only flags are also present. Without the new explicit ingress flag, the transaction listener still rejects non-loopback bind addresses. The public-read-only RPC flag does not exist: --rpc-listen and RPC clients remain loopback-only.

The transaction framing, size limits, transaction decoding, network binding, signature authentication, mempool limits, admission ACK, and peer relay continue to apply. The listener exposes no unauthenticated administrative commands; its only application request is a signed, bounded TXN2 via QZTS/1. This does not replace an Internet firewall, upstream rate limiting, DDoS mitigation, key custody, monitoring or incident response.

## Validation

The source adds policy tests for the negative/default cases and the exact allowed flag combination. The integration runner simulations/cp0440_public_zero_value_testnet_tx_ingress.ps1 is derived from the existing signed-wallet/ingress scenario and exercises a QZBE node binding transaction ingress to 0.0.0.0, invalid-signature atomic rejection, valid wallet submission, mining, replay, and two-node state convergence. The script connects through localhost to the wildcard-bound listener because both test processes are on the same host.

A successful same-host run proves the listener's explicit opt-in path and transaction flow, not external Internet reachability or independent-operator operation. To qualify a public devnet, a genuinely separate operator/host must submit a signed zero-value test transaction through its public endpoint, and both independent nodes must verify the same canonical receipt/state root after replay and recovery. The runtime telemetry now distinguishes a wildcard P2P bind from a loopback P2P listener with public zero-value TX ingress; a CLI opt-in flag alone is not reported as proof that the P2P socket itself is publicly bound.

## Security boundary and remaining gates

- Startup and RPC telemetry continue to report mainnet=false and public_launch_approved=false.
- --public-testnet-tx-ingress has no effect unless test easy-PoW and public-testnet P2P mode are explicitly selected.
- The public ingress option is unaudited and must not receive real-value transactions, seed phrases, private keys or production treasury credentials.
- Gate 2 remains open: the canonical production monetary/Genesis profile is not activated end-to-end.
- Gate 8 remains open: recovery history is bounded; stale-restore, full-history, deep-reorg and independent anti-rollback qualification remain incomplete.
- Gate 13 remains open: a same-host simulation is not a qualified public multi-operator devnet. Public wallet/RPC/explorer, monitoring, backups and incident response are not yet production-qualified.
- No native QZXB Mainnet, deployed native DEX, verified QZXB/USDT pool, real reserves, or authentic live price candles are created by this change.

**Decision:** enable this opt-in ingress only to help recruit and test external zero-value devnet participants. Do not describe it as Mainnet readiness or invite real deposits.
