# CP-0447 — QRun Mainnet and 10B QZXB Release Gate

Date: 2026-10-28

Status: Standing owner objective; production launch remains blocked by concrete protocol and operations defects below. This is an execution gate, not a claim that coins already have market value.

## Owner objective (persistent project requirement)

The target is a native, permissionless QRun L1 whose fixed Genesis supply is exactly 10,000,000,000 QZXB allocated according to the current CP-0437 direction, with no later minting or miner subsidy. The intended use is Bitcoin-like peer-to-peer transfer and direct trade. Do not make exchange listing, coin trackers, a sponsor, or third-party platform approval a protocol-launch prerequisite.

Do not call the supply "real Mainnet", publicly tradable, priced, or valuable merely because a local Genesis ledger credits 10B units. State ownership and market value are different facts; value requires counterparties willing to exchange goods, fiat, or another asset. Do not invent a buyer, trade, reserve, price, or public endpoint.

## Verified source facts at branch head 848fb24a8d9d7c3ae88ac199a0fefaff5a19b8a9

- `qrun_v05_pow_local_node.rs` is explicitly a test-only local-loopback binary. It requires `--local-testnet`, rejects non-loopback listeners and peers, sets `initial_target` and `pow_limit` to `Uint256::MAX`, and reduces Argon2 memory to 8 MiB. Never change those controls to expose this binary publicly.
- The local smoke network ID was randomly generated for one run; it is not a frozen production network ID and must not be reused as Mainnet identity.
- `QRunV05PowForkRuntime` and PTB2/PFS2 are documented candidate components, not a frozen production consensus/network protocol.
- `private_testnet_fork_choice.rs` limits each retained segment to 1,024 block heights and 4,096 archived branches. The default candidate difficulty window is 2,016 blocks. Segmented checkpoints and external manifest anchoring exist, but the production full-history validation/sync or an independently verifiable automatic rollover path is not yet integrated into a public QRun node.
- The local-only candidate binary now has a QRun-domain-separated Noise XX transport with peer static-key pins, a handshake bound to network ID + Genesis commitment + consensus fingerprint, encrypted bounded block/ACK records, and an explicit `--sync-on-start true` option. Startup sync runs before listener binds and requires a DPAPI-protected key plus pins for peers; it fails closed if the peers fail.
- An isolated live CLI smoke test used two separate DPAPI-protected Noise keys and two fresh data directories. The receiver authenticated its pinned loopback peer, completed startup sync, and only then bound its RPC/TX/block listeners; its read-only RPC reported `mainnet=false`. The temporary keys and both smoke-node processes were removed afterwards. This validated startup sequencing only, not public reachability or a real trade.
- Bounded canonical range service and multi-page authenticated catch-up are integrated in the candidate path. Local tests verify an 18-block chain catches up over three authenticated pages with an independently validated signed transfer and matching canonical state root. This is still a bounded segment (1,024-block height window), not full-history public sync; there is no independently verifiable automatic checkpoint rollover or public peer bootstrap. A local test does not prove convergence under arbitrary real-world partitions, adversarial peers, or multi-host restart scenarios.
- QRun candidate signed transaction-ingress and loopback transaction tests passed, but those fixture tests did not submit a transaction from the owner's persistent wallet to public Mainnet.
- Commit `848fb24a8d9d7c3ae88ac199a0fefaff5a19b8a9` adds bounded authenticated candidate sync. Local formatting, locked all-target compilation, eight QRun Noise tests, bounded wire/range/checkpoint tests, and the 18-block three-page catch-up test have passed. GitHub Actions run `40671373505` is the release candidate's CI run; its live conclusion must be checked before treating CI as complete. Neither passing tests nor CI certifies Mainnet.

## Mandatory engineering work before any public value-bearing node

1. Freeze one canonical production identity: network ID, owner public identity, exact 10B Genesis commitment, consensus/profile version, transaction domain, monetary transition and wire formats. Never reuse a generated test network ID.
2. Integrate one production consensus path for both mining and block import: deterministic target derivation/retargeting, timestamp bounds, valid PoW, cumulative-work fork choice, transaction signatures/replay/expiry/fee checks, atomic state changes, and exact lifetime supply cap. Every node must enforce the same rules.
3. Replace the candidate-only bounded-history approach with full-history validation and replay/sync from Genesis, or ship a clearly specified recovery/checkpoint model with explicit trust assumptions and verifiable rollover. Do not raise archive caps as a shortcut.
4. Extend the integrated pinned Noise transport and bounded sync path with reviewed peer churn/reconnect handling, full-history/bootstrap checkpoint trust, bounded transaction relay, and anti-replay/DoS controls. The local smoke binary must remain loopback-only.
5. Prove reproducible builds and independent multi-host startup, restart, fork/reorg recovery, transaction relay, inclusion and independent receipt/balance reads using the locked production identity. Publish artifacts, hashes, node/wallet setup, endpoints and known risks.
6. Only then activate a production network and describe its on-chain transfers as Mainnet. For a direct trade, the buyer and seller separately agree payment terms and verify the canonical transfer. A native QZXB/USDT pool is a separate feature requiring an authentic quote asset, actual reserves and real swaps; never fabricate it.

## Decision rule

Do not flip a flag or expose the current test binary to the Internet. If any mandatory gate is unresolved, keep that specific deployment blocked while implementing the next engineering item; do not reinterpret passing candidate tests as a production security assessment. Do not ask for or print private keys or seed phrases. No new owner-funded spend is implied by this project goal.
