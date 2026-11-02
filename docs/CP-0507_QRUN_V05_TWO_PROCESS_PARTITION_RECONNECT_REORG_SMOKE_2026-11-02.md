# CP-0507 — QRun v0.5 two-process Public Alpha partition / reconnect / durable reorg smoke

Date: 2026-11-02

Status: **PASS — two independent OS node processes diverged under an enforced bidirectional TCP partition, then authenticated startup sync selected the greater-cumulative-work QFP5 branch, corrected receipts and balances, and survived a second restart without resync.** This remains same-host loopback qualification, not multi-host certification. Mainnet remains disabled.

## Purpose

CP-0506 proved reorg-aware authenticated canonical sync using two independent durable runtime instances in a single test process. This test raises the boundary to two independent QRun node OS processes with separate data directories, separate DPAPI-bound Noise XX static keys, separate reference-time high-water stores and independent RPC/transaction/block listeners.

The test deliberately creates a network partition, not merely a delay:
- both nodes are configured with a peer address and an exact static Noise public-key pin;
- each peer address points through a separate transparent TCP proxy;
- each proxy denies accepted connections while its gate file is absent;
- opening the two gate files makes each proxy relay the original encrypted TCP stream to the other node's real block listener. The proxy does not terminate or inspect Noise.

## Test-only support

New files:
- `src/native/pow_bench/src/bin/qrun_v05_partition_proxy.rs`
- `tools/qrun-v05-public-alpha-partition-reorg-multiprocess-smoke.ps1`

Updated file:
- `src/native/pow_bench/src/bin/qrun_v05_public_alpha_process_smoke.rs`

The process smoke signer remains a deterministic **test-only** Ed25519 identity for freshly generated ephemeral networks. It now supports:
- `submit`: nonce 1, recipient byte `0x78`, amount 1,000 atoms;
- `submit-conflict`: nonce 1, recipient byte `0x79`, amount 2,000 atoms;
- `submit-next`: nonce 2, recipient byte `0x7A`, amount 3,000 atoms.

All three are separately signed QZTS/1 requests from the same test identity. The conflicting nonce-1 transactions are valid on separate partitions because they are never imported into one ledger before reconnection.

The proxy listener is nonblocking to accept new connections, but every accepted/target stream is explicitly changed to blocking mode before its two-way relay starts. This matters on Windows: the first end-to-end attempt showed the accepted socket's inherited mode could terminate the byte-copy relay during Noise handshake. The corrected relay records both directional byte counts. This change is test-harness-only.

## Scenario and observed results

Command:

```powershell
.\tools\qrun-v05-public-alpha-partition-reorg-multiprocess-smoke.ps1 -Release
```

The script generated a fresh ephemeral Network ID, shared Genesis epoch, signed RTP1 reference-time policy and Authority, a disposable signer identity, and two independent NPK1 Noise static keys. Both nodes opened the same Genesis/profile at height 0 with independent durable directories.

### Phase A — enforced partition and competing branches

The two transparent proxy gates were initially closed in both directions.

1. Node A accepted and mined its own signed nonce-1 transaction:
   - txid: `ba7cdbdc725e7b360113aa796cd39b571363ce3d9db03714babc693420a1df27`
   - Node A reached canonical height 1.
   - Node B remained at height 0 and reported the transaction as `not_found_in_canonical_chain`.

2. Node B accepted and mined a different signed nonce-1 transaction from the same owner:
   - txid: `f329308f9fe195762a7b3f17a67c299052ab2f9f68297672265dc5a7b6d6f864`
   - Node B reached its own height 1 with a different tip.
   - Node A did not import it and reported its receipt as not found.

3. Node B accepted a valid nonce-2 transaction and extended its branch to height 2:
   - txid: `e8bbf0b02c3f4c5cc65a504d23c4c7e7449552ea43a2f3b7b415952b613c4280`
   - Node B reached height 2; Node A remained at height 1.
   - Both directional proxy logs recorded denied connections while partitioned.

Observed partition state:
- Node A: height 1, branch-A receipt only.
- Node B: height 2, branch-B nonce-1 and nonce-2 receipts only.
- The nodes had different canonical tips while gates were closed.
- Test marker: `TWO_PROCESS_PARTITION_DIVERGENCE=PASS`.

### Phase B — heal partition and authenticated reorg on process restart

Both gate files were created. Node A was stopped and restarted with:
- the same original data directory;
- the same original reference-time high-water file;
- the same network-bound Noise key;
- the same peer proxy address and exact peer static-key pin;
- `--sync-on-start true`.

The restarted Node A completed pinned Noise XX canonical sync before opening its application listeners. It fetched the peer's canonical path from the shared Genesis base, imported the competing height-1 block and height-2 descendant into its local fork graph, then selected Node B's branch because it had greater cumulative work.

After sync:
- both nodes were at height **2**;
- both had the same canonical tip and state root;
- Node A no longer reported branch-A's losing nonce-1 receipt;
- Node A confirmed Node B's nonce-1 and nonce-2 receipts;
- the owner nonce was **2** on both nodes;
- owner balance matched;
- recipient `0x79…79` held **2,000 atoms**;
- recipient `0x7A…7A` held **3,000 atoms**.

Test markers:
- `AUTHENTICATED_STARTUP_SYNC_REORG=PASS`
- `CANONICAL_RECEIPTS_AND_BALANCES_CORRECTED=PASS`

### Phase C — durable reopen without resync

Node A was stopped a second time and restarted against the same data directory, but **without** `--sync-on-start`.

The reopened process retained:
- height **2**;
- the selected Node B canonical tip and state root;
- owner nonce 2 and matching owner balance;
- absence of the orphaned branch-A transaction from the canonical receipt index;
- confirmed branch-B nonce-1 and nonce-2 receipts;
- the expected recipient balances.

Test markers:
- `MULTIPROCESS_PARTITION_RECONNECT_REORG=PASS`
- `DURABLE_REOPEN_AFTER_NETWORK_REORG=PASS`
- `QRun_PUBLIC_ALPHA_PARTITION_REORG_MULTIPROCESS_SMOKE=PASS`

Total smoke runtime: **69.49 seconds**, Release profile, process exit code **0**.

Final canonical values:
- tip: `0072b2132e1f5dea6aac9bc8dcc1bf2a1f19c47111d363e1af53bf16c8545210`
- state root: `c449ed4a0aeb69974d412ceaf98089b5cacb14004a4abbb734ab8bb0d68353d7`

The successful script removed its disposable root and stopped both nodes, both proxies and the Authority.

## Regression and quality validation

After the successful Release smoke:

- `cargo test --bin qrun_v05_pow_local_node --locked --offline`: **34 passed, 0 failed**.
- `cargo test --lib reorg --locked --offline`: **20 passed, 0 failed**.
- `cargo check --all-targets --locked --offline`: **PASS**.
- `rustfmt --edition 2021 --check` on the modified QRun node/runtime, partition proxy and process-smoke helper: **PASS**.
- PowerShell parser for the new smoke script: **0 errors**.
- `git diff --check`: **PASS** (Git emits its existing LF-to-CRLF conversion notices only).

Build output still contains unrelated existing unused-import/dead-code and unused-mut warnings. There are no compiler errors.

## Scope boundaries

- This test uses **two independent QRun OS processes**, distinct stores and keys, but both run on the same Windows host over loopback TCP.
- It verifies process isolation, actual P2P partition enforcement, transparent reconnection, authenticated startup sync, reorg receipt correction and durable reopen. It does not prove separate-host firewall/NAT traversal, internet reachability, clock diversity, independent operator deployment or production uptime.
- The signer and network are disposable Public Alpha test fixtures. They do not use live QZXB private keys or represent public token transfers or value.
- The reference-time Authority remains a single configured Ed25519 time attester; it is not BFT time consensus.
- Mainnet genesis/identity freeze, checkpoint rollover/recovery, External-CAS failure injection, adversarial multi-host networking and independent security review remain release gates.
- `QRUN_MAINNET_RELEASE_APPROVED = false` remains unchanged.

**Decision:** retain the process-level partition/reorg smoke as a reproducible QRun v0.5 Public Alpha regression. The next qualification must run the same scenario across two genuinely independent hosts and controlled firewall/network conditions. No commit or push was made.
