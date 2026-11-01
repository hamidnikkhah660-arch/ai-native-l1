# CP-0490 ? QRun Permissionless-First Release-Gate Alignment

Date: 2026-11-01

Status: **Policy/code alignment and fail-closed regression tests implemented on a development branch. Mainnet remains disabled. This checkpoint does not complete the remaining technical release gates or launch a public network.**

## Decision

Apply the standing project rule in CP-0443 consistently to the QRun v0.5 node's source-level release gate:

- A minimum count of independent operators is not a permission token for publishing a permissionless protocol.
- The availability of a third-party auditor is not, by itself, a protocol launch permission gate. Review status and residual risk must be disclosed truthfully; an audit must never be claimed unless one was actually delivered.
- Exchange listing, market-data indexing, sponsor funding and liquidity targets are not prerequisites for publishing a technically valid permissionless protocol.

This does **not** waive genuine protocol or operational requirements. Multiple real hosts are still required to demonstrate peer interoperability, external reachability, transaction relay, independent receipt/balance reads and recovery. The distinction is between evidence of real operation and an arbitrary minimum number of people or an outside approval certificate.

## Concrete technical gates retained in code

`QRUN_MAINNET_RELEASE_APPROVED` remains `false`. The node continues to reject `--mainnet` before reading protected keys, creating its data directory or opening sockets. The fail-closed message now retains the following blockers:

1. The production consensus profile and difficulty/retarget policy are not frozen and reproducibly validated.
2. Full-history validation/recovery and safe checkpoint rollover/rebase are not integrated.
3. Multi-host restart/reorg/partition/transaction-relay and independently queried receipt/balance behavior are incomplete.
4. External Mainnet P2P reachability, authenticated bootstrap and monitored recovery have not been verified.

These are capabilities/evidence, not a request for a fixed number of external approvals. The node still requires an explicitly configured non-loopback pinned peer and startup sync before a future Mainnet mode could be considered; RPC and transaction ingress remain loopback-only.

## Current source evidence and remaining engineering gap

The current development ancestry contains QRun v0.5 signed TXN2/QZTS ingress, QFP5 block production/receipt indexing, authenticated Noise block transport, and bounded authenticated startup sync. Exact-head CI on the preceding Anchor/lifecycle source `1b8687edf49cbda241b3fd3879b897ca92ae06af` passed both push and PR workflows. Focused local tests on that source also revalidated signed transaction admission, two-node loopback transfer/replay and shutdown.

However, the active fork-choice/store is still bounded: `MAX_FORK_ARCHIVE_HEIGHT` is 1,024 and `MAX_FORK_ARCHIVE_BLOCKS` is 4,096. The authenticated sync path is paged, but the current catch-up budget is sized to that 1,024-height branch window. The QRA1/QRM1 checkpoint-history and migration pieces are candidate components; the full repeated checkpoint-rollover/full-history recovery lifecycle is not yet integrated as an ordinary production operation. This remains a real release blocker, not an auditor/operator-count blocker.

A single-host loopback test is not external network evidence. No public P2P port, firewall rule, public RPC/TX listener, cloud resource, production Anchor service or Mainnet setting was changed by this checkpoint.

## Market is a separate gate

Publishing a permissionless native protocol does not itself create a QZXB/USDT market. A genuine quote-asset route, such as an authentic supported USDT representation with verifiable issuance/redemption or a reviewed bridge, two-sided reserves and real counterparties, is still required before claiming a QZXB/USDT trade. The repository's QZBE v0.4 AMM/candle candidate is not an activated QRun v0.5 market; Sepolia QX is a different test asset.

## Validation performed on this branch

- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check` ? PASS.
- QRun node Mainnet guard tests: **5 passed, 0 failed**.
- Permissionless operator/auditor policy regression: **1 passed, 0 failed**.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline` ? PASS.
- `git diff --cached --check` ? PASS.
- `python simulations/public_docs_refresh_checker.py` ? PASS: 14 HTML IDs, 89 README-relative links, 527 canonical Git-blob checksums; candidate-emission arithmetic unchanged and verified.
- Compilation emitted existing unused-import/dead-code/unused-mut warnings in unrelated candidate modules; no new warning was attributed to this policy change.
- Exact-head GitHub CI must complete successfully before this change is described as CI-verified.

## Release decision

This change only aligns policy text and fail-closed error reporting with CP-0443. It does not set `QRUN_MAINNET_RELEASE_APPROVED` to true, remove full-history or peer-network blockers, change consensus/PoW/Genesis/Network ID/wallet identity/supply, expose listeners, provision infrastructure, or claim a security audit or real market.
