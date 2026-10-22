# CP-0373 — PMT4/PFM4 Runtime Boundary and Mainnet Prerequisites

Date: 2026-10-22
Project: QuantumZXB / AI-Native L1
Verified base: `a0fe9a4a7cb2daba100ff50300fb16d8c5ada6bf`
Purpose: distinguish the strongest existing candidate implementation from a production launch path.

## Existing paths verified from source

### 1. Legacy TCP importer

`src/native/pow_bench/src/bin/chain_import_node.rs` imports the legacy `ChainImportService` and `LedgerState`, accepts BLK2 bodies, and persists the legacy snapshot format. It is not an MBK4/TXN4 production monetary runtime.

### 2. Default node runtime

`devnet_node` normally enters `NodeRuntimeProfile::ZeroValueDevnet`, whose named profile is `PTB2_PFS2_LOOPBACK_ZERO_VALUE_DEVNET_CANDIDATE`. That path is deliberately distinct from a value-bearing PMT4/PFM4 monetary network. Existing data-directory profile guards reject silently mixing MGN4/PMT4 state with the default PTB2/PFS2 path.

### 3. PMT4/PFM4 local smoke mode

`--monetary-v4-hybrid-local-smoke` is an offline-only candidate path. Source forces `initial_target = Uint256::MAX` and reduces Argon2 memory to 8 MiB for speed. Genesis can use deterministic placeholder founder/public-goods/miner accounts unless both founder Ed25519 and ML-DSA-65 public keys are explicitly supplied. The mode has no peer listeners or production authorization, and the source labels it `public_launch_approved=false`.

### 4. PMT4/PFM4 peer smoke mode

`--monetary-v4-hybrid-peer-smoke` contains real candidate wiring across the PMT4 header/body codec, `pow_digest`, the `PrivateTestnetV4HybridForkStore`, MBK4 state admission, PFM4 multi-branch persistence, fork-choice, Noise XX peer authentication, transaction/mempool plumbing, and paged archive sync. This is the strongest existing end-to-end monetary candidate path in source.

However, its validation explicitly requires loopback-only listen/status/transaction addresses and loopback-only peers. It also overrides the PoW target to `Uint256::MAX` and memory to 8 MiB. The store opens through the local-only `PrivateTestnetV4HybridForkStore::open` and commits through `store.submit`; the node does not instantiate a real external HTTPS CAS provider or call `submit_with_external_anchor`. This proves bounded local/loopback protocol integration, not a public network, production mining economics, remote-operator trust, or whole-disk anti-rollback.

### 5. External CAS building blocks

The PFM4 library has `open_with_external_cas` / `submit_with_external_anchor` candidate APIs and fail-closed regression tests. Gate 8 still lacks a real independently operated HTTPS provider, provider-side atomic generation CAS, independent operator/trust domain, production-pinned receipt-signing key, and real multi-host race/rollback/power-loss/restore/key-rotation qualification. The current local-only smoke path does not supply those properties.

## Architecture decision on PR #37

PR #37's tests are green, but it has been returned to Draft. Its `V4HybridMonetaryImportService` is a second linear MCS4 state store with an API accepting raw MBK4 body bytes and an unenforced caller precondition that PoW/header verification and canonical branch selection happened elsewhere. It is not currently node-wired and does not do PoW, chainwork, fork choice, or reorg itself. Since the existing PFM4 candidate path already has the richer fork-choice/store integration, do not introduce a parallel import/state machine unless a concrete requirement needs it. Future work should extend/reuse the PMT4/PFM4 path, or first introduce a type that can only be produced after header, target, PoW, body/profile binding and fork-selection checks.

## Minimum technical work before any public value-bearing devnet or Mainnet

1. Freeze one reviewed production protocol profile: network ID, canonical Genesis and founder identity, MGN4/manifest, wire format, fee rules, subsidy/halving and lifetime caps, resource limits, difficulty/retarget rules, snapshot/replay rules, migration plan, trust roots, and versioning policy. Do not base this on the local MAX-target profile.
2. Provide a separately configured non-loopback devnet profile only after profile review, with real target/difficulty, explicit operator identity, pinned peer trust, bounded RPC/explorer access controls, and multi-host recovery; retain local-smoke loopback restrictions.
3. Wire one canonical production submit path through PMT4 header verification, PoW/expected target and chainwork, MBK4 state admission, deterministic fork choice/reorg, durable PFM4 storage/replay, and an explicit externally anchored recovery protocol where required. Prove there is no legacy fallback or protocol downgrade.
4. Run independent cross-client golden vectors and divergent-history/reorg/restart tests, obtain independent cryptographic/consensus/economic security review, and resolve every Critical/High finding before any public value transfer.
5. Separately complete legal classification, MiCAR/white-paper/marketing and service-permission analysis, owner-side wallet/payout/tax checks, and market-data listing prerequisites. A CI run is not legal clearance.

## Current gate status

- Gate 2: **OPEN** — candidate monetary logic and end-to-end loopback path exist, but a single production profile and production runtime wiring are not frozen/qualified.
- Gate 8: **OPEN** — a safe local PFM4 branch store and CAS contract/tests exist, but real independent external anchor operations and whole-disk rollback qualification do not.
- G0: **OPEN** — a public checklist exists, but owner wallet control, donation receipt/payout/tax and legal status are not independently verified; the specific Giveth campaign could not be opened by the verification tool on 2026-10-22.
- G1: **OPEN** — a fixed-scope paid engineering offer is public, but no client, signed engagement, payment or revenue is claimed.

Owner-funded spend remains USD 0. No public listener, production private key, public value transfer, liquidity operation, token offer, or Mainnet network was enabled by this checkpoint.
