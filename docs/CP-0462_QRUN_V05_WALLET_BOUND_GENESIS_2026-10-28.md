# QRun v0.5 wallet-bound Genesis setup - 2026-10-28

## Status

The QZXB wallet file was created locally and the node binary was rebuilt with support for a wallet-specific public-alpha Genesis owner. The node binary build succeeded and the `qrun_v05_pow_local_node` test target passed 11/11 tests. Runtime startup and the balance query were subsequently verified against the wallet-specific network identity. The wallet CLI reported `wallet_rpc_balance_status=ok`, `balance_atoms=1000000000000000000`, `height=0`, and `network_class=candidate_not_mainnet`. This verifies the local node genesis state and read-only balance path; it does not verify an Internet-connected peer or activate Mainnet. Mainnet remains disabled.

## Local wallet identity

- Wallet file: `C:\QRun\owner.qzkw`
- Format: `QZKW1_Windows_CurrentUser_DPAPI` (bound to this Windows user context)
- Account ID: `a14d67bd195c6a0044bedac8532e742811f92501630764d73a98b2f0cc335fdd`
- Public key: `fca65e26f596fa60674f5ec35808ec80b317a701e97feee343d85007713bd93f`
- Recovery phrase is not recorded in this repository or chat; it is displayed in the local wallet-creation console. Write it down offline and do not share it.

## Wallet-bound chain identity

To avoid reusing the prior proposed Genesis identity with a different owner, the wallet-specific network ID is derived as:

`SHA256("QUANTUMZXB-QRUN-PUBLIC-ALPHA-WALLET-GENESIS-V1\0" || proposed_network_id_bytes || wallet_account_id_bytes)`

- Proposed base network ID: `70fdcdbe6f0afa1edb0c4fb4a85252831376f7b9ecf2a13a86dcf61979cdcad7`
- Wallet-bound network ID: `8b5d169205ac49cb9866a9d27ff1a6c3c2571fca65f634854c41c112e506aebb`
- Original proposed Genesis ID (different owner): `613bb4f36c8e57e73dd04308809b9decdd1b4411e0838f948ee2aa7eaacbab97`

Because the owner/network values differ, this wallet-bound network has a different Genesis and consensus profile ID. It must not be presented as the original frozen identity. All peers joining this alpha chain must use the exact same network ID, Genesis owner account/public key, Genesis and profile.

## Monetary state

The QRun v0.5 Genesis runtime credits the fixed total supply of `1,000,000,000,000,000,000` atoms (10 billion QZXB at 8 decimals) to the configured Genesis owner. There is no subsequent issuance and the block subsidy is zero. This is an owner pre-allocation model, not Bitcoin's miner-reward issuance schedule. Even after local balance verification, this is experimental public-alpha state, not a live Mainnet or a claim of market value.

## Local verification completed

1. A rebuilt public-alpha node was launched with the wallet-derived account/public key, this wallet-bound network ID, a matching DPAPI-protected Noise key, and fresh data directory `C:\QRun\wallet-bound-genesis-data-v3`.
2. Verified from the node startup output: Genesis owner equals the wallet account, owner balance and total supply are `1000000000000000000` atoms, and height is zero. The `qzxb_wallet balance` command against `127.0.0.1:49339` returned the same balance, account ID, and state root.
3. Observed listeners: RPC `127.0.0.1:49339`, transaction ingress `127.0.0.1:49340`, and P2P `0.0.0.0:49341`. No independent peer is connected (`block_peer_count=0`); inbound Internet reachability remains unverified. Keep RPC and transaction ingress loopback-only.