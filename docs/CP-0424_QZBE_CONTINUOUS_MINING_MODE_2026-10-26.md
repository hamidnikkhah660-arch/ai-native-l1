# CP-0424 â€” QZBE continuous mining mode

Date: 2026-10-26

Status: local Windows two-node release integration passed; exact-head GitHub Actions run is pending after commit.

## Change

The explicit QZBE v0.4 loopback candidate now supports `--mine-forever`. Instead of stopping after the bounded `--mine-blocks` count and a timer, the miner continues producing blocks and requiring an acknowledgement from each statically pinned peer. It exits when `--stop-after-height` is reached; without that option it runs until the process is stopped.

The option is deliberately exclusive with `--mine-blocks`, `--run-seconds`, and `--exit-after-mining`. At least one statically pinned outbound peer is required so a miner cannot silently build an isolated branch without peer acknowledgement. The existing loopback-only bind and peer-address checks remain unchanged. The existing test-easy-PoW switch remains explicit and cannot be treated as production work.

## Verification

Run on Windows from the checkout root:

```powershell
.\simulations\cp0424_qzbe_continuous_mining_loopback.ps1
```

The script starts two independent `devnet_node` processes with separate DPAPI-protected Noise keys and separate durable stores. The miner uses `--mine-forever --stop-after-height 2`; the receiver accepts both produced blocks. The test passed and reported:

- `CP-0424 CONTINUOUS_MINING_HEIGHT_2_PASS`
- `CP-0424 TWO_NODE_RESTART_REPLAY_CONVERGENCE_PASS`

Both nodes reopened their stores, replayed the persisted suffix, and agreed on the height-2 canonical state root and tip.

## Boundary that remains

This closes the process-lifetime/block-count limitation for the existing diagnostic candidate only. It does **not** make the node publicly reachable or permissionless. QZBE still requires statically pinned peers, retains the loopback-only address guard, and does not yet provide the public transaction-ingress/mempool, automatic peer discovery, or late-join block synchronization needed for a Bitcoin-like public network. The test explicitly uses easy PoW on loopback and is not evidence of mainnet activation, public mining, owner-key custody, or market liquidity.

The exact-head GitHub Actions run 40390573762 (https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40390573762) completed successfully for commit 2ef7d151722b8a357e02a82e3650dfb2739eb075. Gate 2, Gate 8, public-network operation, and production-release qualification remain open.
