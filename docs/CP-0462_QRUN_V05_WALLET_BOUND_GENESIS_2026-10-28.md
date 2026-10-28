# QRun v0.5 wallet-bound Genesis setup - 2026-10-28

## Status

The QZXB wallet file was created locally and the node binary was rebuilt with support for a wallet-specific public-alpha Genesis owner. The node binary build succeeded and the `qrun_v05_pow_local_node` test target passed 11/11 tests. Runtime startup against this newly generated wallet and its balance query remain unverified in this run; do not describe this wallet balance as independently verified yet. Mainnet remains disabled.

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

## Verification still required

1. Launch the rebuilt public-alpha node with the wallet-derived account/public key, this wallet-bound network ID, and a fresh data directory.
2. Verify the emitted Genesis owner and total supply, then run `qzxb_wallet balance` against `127.0.0.1:49339` for the wallet account ID.
3. Keep RPC (`49339`) and transaction ingress (`49340`) on loopback. Only P2P (`49341`) may be exposed.