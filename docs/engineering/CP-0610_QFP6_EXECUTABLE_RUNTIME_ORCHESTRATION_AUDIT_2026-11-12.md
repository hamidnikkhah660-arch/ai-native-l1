# CP-0610 - QFP6 executable/runtime orchestration boundary audit

Date: 2026-11-12
Status: implementation-boundary audit; no runtime activation, network listener, mining, or Genesis signing.

## Finding

The QFP6 executable `src/native/pow_bench/src/bin/qrun_v06_node.rs` is a bootstrap preflight and read-only QAP1 service probe. Its `run()` rejects `--run` before parsing configuration. That fail-closed behavior is correct and must remain until the following runtime wiring is complete.

The underlying libraries expose substantial pieces, but there are two distinct orchestration tracks that are not yet joined:

1. QAP1/recovery track: `QRunV06PermissionlessNodeRuntime::open_qap1(...)` opens the durable store and returns `QRunV06NodeRuntime<A>` after Provider/Q6EA pin checks and QAP1 restart recovery. The QAP1-aware supervisor `run_qfp6_mining_supervisor(...)` consumes this `QRunV06NodeRuntime<A>`, the QAP1 coordinator, quote-asset authorizer, trusted peer Noise keys, and transaction journal.
2. Permissionless-history/mining track: `run_qfp6_permissionless_mining_supervisor_with_bootstrap(...)` performs authenticated Q6HS history synchronization and then mining/listener service, but it consumes `QRunV06PermissionlessNodeRuntime`, which is opened through the non-QAP1 `open(...)` path. It does not accept the QAP1 Provider/Q6EA coordinator or QAP1 anchor gate.

These runtime types are not interchangeable. The current QAP1 constructor returns `QRunV06NodeRuntime<A>`; the permissionless bootstrap/mining supervisor requires `QRunV06PermissionlessNodeRuntime`. Simply calling one after the other would either fail to compile or bypass the intended QAP1/anchor guarantees. The executable currently does neither, and must not be changed to claim it does.

## Executable inputs already handled by preflight

The existing signed/pinned preflight validates:
- independently pinned config digest;
- Q6GD identity through verified Q6PN profile pin;
- Q6CP bytes/hash/fingerprint and consensus parameters;
- full Genesis snapshot hash, descriptor and founder balance;
- Q6TS authority keys and trust envelope;
- external Provider/Q6EA identity, endpoints, Noise server keys and read-only trust-floor/service probes.

## Additional node-runtime inputs not represented by the current Config

Before a real process can start, a separately versioned and independently pinned runtime deployment schema must provide and validate:
- node data directory and durable store/recovery policy;
- node-local network-bound protected Noise static private-key file (never raw key bytes in JSON/argv);
- authenticated bootstrap peer addresses and their pinned Noise static public keys;
- producer/miner account identity, independently bound to the intended public QFP6 account;
- bounded listener and history-sync configuration;
- durable transaction/mempool journal path and safe restart semantics;
- QAP1-compatible history import/peer admission, or an explicit, reviewed protocol decision that defines when imported history is externally anchored.

No such complete deployment config or bootstrap peer set is present in the current candidate package. The package still lacks the six canonical release artifacts recorded by CP-0609. No peer endpoint, key, account, network identifier, or Genesis value is fabricated here.

## Required engineering sequence

1. Define one QAP1-aware permissionless runtime interface. Preserve Provider/Q6EA recovery and pending-anchor gating while supporting authenticated parent-first Q6HS history import. Do not reuse the non-QAP1 `open()` path for a Mainnet node.
2. Add integration tests for restart with pending QAP1 intent, imported-history anchor reconciliation, wrong-peer-key rejection, partial sync/retry, canonical reorg, and durable mempool recovery.
3. Add a versioned runtime config parser with independent config digest pinning and protected local Noise key loading; reject missing/duplicate/unpinned bootstrap peers and zero/duplicate producer identities.
4. Wire the executable only after the full Genesis/Q6CP/Q6PN/Q6TS/Q6EA package and independently provisioned peer set exist. Keep `--run` fail-closed until the integration tests and two-host restart/history qualification pass.
5. Start on a separately authorized isolated qualification network first. Mainnet activation requires a separate explicit release decision.

## Validation / scope

This change is documentation-only. It does not modify the executable, consensus rules, Genesis artifacts, wallet, keys, or network state. `--run` remains blocked. No public listener, mining, Mainnet issuance, or QZXB/USDT market is activated.