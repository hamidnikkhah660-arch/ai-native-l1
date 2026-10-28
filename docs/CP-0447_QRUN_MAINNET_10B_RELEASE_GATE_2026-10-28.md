# CP-0447 — QRun Mainnet and 10B QZXB Release Gate

Date: 2026-10-28

Status: Standing owner objective; production launch remains blocked by concrete protocol and operations defects below. This is an execution gate, not a claim that coins already have market value.

## Owner objective (persistent project requirement)

The target is a native, permissionless QRun L1 whose fixed Genesis supply is exactly 10,000,000,000 QZXB allocated according to the current CP-0437 direction, with no later minting or miner subsidy. The intended use is Bitcoin-like peer-to-peer transfer and direct trade. Do not make exchange listing, coin trackers, a sponsor, or third-party platform approval a protocol-launch prerequisite.

Do not call the supply "real Mainnet", publicly tradable, priced, or valuable merely because a local Genesis ledger credits 10B units. State ownership and market value are different facts; value requires counterparties willing to exchange goods, fiat, or another asset. Do not invent a buyer, trade, reserve, price, or public endpoint.

## Verified source facts at branch head 1f428594fe829ff3223508a0231a2f0b60ca447d

- `qrun_v05_pow_local_node.rs` is explicitly a test-only local-loopback binary. It requires `--local-testnet`, rejects non-loopback listeners and peers, sets `initial_target` and `pow_limit` to `Uint256::MAX`, and reduces Argon2 memory to 8 MiB. Never change those controls to expose this binary publicly.
- The local smoke network ID was randomly generated for one run; it is not a frozen production network ID and must not be reused as Mainnet identity.
- `QRunV05PowForkRuntime` and PTB2/PFS2 are documented candidate components, not a frozen production consensus/network protocol.
- `private_testnet_fork_choice.rs` limits each retained segment to 1,024 block heights and 4,096 archived branches. The default candidate difficulty window is 2,016 blocks. Segmented checkpoints and external manifest anchoring exist, but the production full-history validation/sync or an independently verifiable automatic rollover path is not yet integrated into a public QRun node.
- The QRun candidate block peer path is raw TCP, not integrated with authenticated peer sessions or robust missing-history synchronization. A local two-node block-gossip test does not prove public network security or convergence after arbitrary partitions/restarts.
- QRun candidate signed transaction-ingress and loopback transaction tests passed, but those fixture tests did not submit a transaction from the owner's persistent wallet to public Mainnet.
- The current Windows CI run for this head has its format/check/test job successful; its second Windows integration job was still running when this status was recorded. Neither job, by itself, certifies Mainnet.

## Mandatory engineering work before any public value-bearing node

1. Freeze one canonical production identity: network ID, owner public identity, exact 10B Genesis commitment, consensus/profile version, transaction domain, monetary transition and wire formats. Never reuse a generated test network ID.
2. Integrate one production consensus path for both mining and block import: deterministic target derivation/retargeting, timestamp bounds, valid PoW, cumulative-work fork choice, transaction signatures/replay/expiry/fee checks, atomic state changes, and exact lifetime supply cap. Every node must enforce the same rules.
3. Replace the candidate-only bounded-history approach with full-history validation and replay/sync from Genesis, or ship a clearly specified recovery/checkpoint model with explicit trust assumptions and verifiable rollover. Do not raise archive caps as a shortcut.
4. Integrate authenticated, bounded peer transport with peer churn/reconnect handling, synchronization of missing blocks, bounded transaction relay and anti-replay/DoS controls. The local smoke binary must remain loopback-only.
5. Prove reproducible builds and independent multi-host startup, restart, fork/reorg recovery, transaction relay, inclusion and independent receipt/balance reads using the locked production identity. Publish artifacts, hashes, node/wallet setup, endpoints and known risks.
6. Only then activate a production network and describe its on-chain transfers as Mainnet. For a direct trade, the buyer and seller separately agree payment terms and verify the canonical transfer. A native QZXB/USDT pool is a separate feature requiring an authentic quote asset, actual reserves and real swaps; never fabricate it.

## Decision rule

Do not flip a flag or expose the current test binary to the Internet. If any mandatory gate is unresolved, keep that specific deployment blocked while implementing the next engineering item; do not reinterpret passing candidate tests as a production security assessment. Do not ask for or print private keys or seed phrases. No new owner-funded spend is implied by this project goal.
