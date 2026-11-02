# CP-0504 — QRun v0.5 bounded PoW time refresh and independent block ingress

Date: 2026-11-02

Status: **Candidate operational hardening implemented and validated by Rust regression tests plus a successful two-process Public Alpha loopback smoke. Mainnet remains disabled.**

## Triggering evidence

A disposable Public Alpha smoke started two independent QRun node processes with separate data directories, Noise NPK1 keys and reference-time high-water stores. Both opened the same ephemeral Network ID, Genesis and signed reference-time profile.

Node A accepted a real Ed25519-signed TXN2 request and mined a QFP5 candidate. A live retest exposed that a single timestamp captured before a long 64 MiB Argon2id search could become stale before the peer received it. Node B correctly rejected the candidate under the existing local live-admission policy:

```
TimestampTooFarInPast {
  earliest_allowed: 1793608361,
  actual: 1793608356
}
```

The prior candidate was approximately 305 seconds old, just outside the existing 300-second past bound. This was a correct fail-closed rejection. The policy was not relaxed to force convergence.

The same investigation found that the transaction/PoW loop also polled the inbound block listener. Although the RPC server already ran in a separate read-only thread, a long synchronous PoW operation could delay acceptance of incoming P2P blocks.

## Bounded changes

### 1. Independent authenticated block listener

`src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs` now runs the inbound block listener on a dedicated named worker:

- The worker polls authenticated Noise XX / block ingress independently of transaction mining.
- It handles one accepted connection at a time, preserving bounded back-pressure.
- Canonical runtime writes still pass through the same `Arc<Mutex<NodeState>>`; this does not create parallel store writers or move the OS writer lock between threads.
- Worker failures are sent to the main loop and propagated during shutdown.
- Shutdown signals and joins the block worker and the existing read-only RPC worker before NodeState is dropped.

### 2. Authenticated time refresh between bounded PoW slices

Public Alpha previously ran one uninterrupted candidate search of at most 10,000 nonce attempts with a timestamp sampled before mining. It now divides that same total attempt budget into slices of at most 1,000 attempts.

After a slice exhausts its nonce range:

1. The node reacquires NodeState and checks that the canonical parent tip and height have not changed.
2. It obtains a new sample from the configured authenticated reference-time provider.
3. It advances the candidate timestamp monotonically with `next_live_block_timestamp`.
4. It resumes candidate search against the same immutable branch snapshot using the refreshed timestamp.

A successful candidate therefore carries a timestamp refreshed during the mining operation rather than inheriting a potentially several-minute-old start timestamp. Total attempts remain capped at the existing 10,000 in Public Alpha (and one attempt in the local smoke profile). No difficulty target, Argon2id parameters, retarget formula, issuance, Genesis, network identity, or timestamp-admission bound was weakened.

The existing candidate live-admission window remains unchanged: **300 seconds maximum past drift and 120 seconds maximum future drift**. This is still a provisional node-local operational policy, not a frozen Mainnet consensus time rule.

## Validation

- `cargo test --bin qrun_v05_pow_local_node --locked --offline`: **33 passed, 0 failed** after the sliced-PoW change.
- `cargo check --all-targets --locked --offline`: **PASS**.
- `rustfmt --edition 2021 --check src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs`: **PASS**.
- `git diff --check`: **PASS** (Git emitted line-ending conversion notices only).
- `tools/qrun-v05-public-alpha-two-process-smoke.ps1`: **PASS**, total runtime **127.50 seconds**.
- Two independent node processes used separate data directories and separate Noise keys while sharing the disposable network, Genesis and authenticated time policy.
- A real signed TXN2 transfer was admitted by Node A; its QFP5 block was propagated to Node B over Noise XX.
- Both nodes reached height **1**, with matching canonical tip `002d610dff5ad971cd548ebd3d7cae4205c85b3201b6928684f2b2adc60be1f8`, matching state root `1533cad0ad3a16add77fe5add097ed7e3d4c9242da5fd4d148cf28ecbf3bc12d`, and a confirmed receipt for transaction `dde1b788abd0752ddd25ae77550a94aaa1a77e7aa7ad94f2c3acc991a9dc6ea6`.
- Owner balance and nonce matched on both nodes.
- The smoke returned exit code 0. Its disposable successful root was removed by its own cleanup path; no QRun node, Authority or smoke-client processes and no test listeners remained afterwards.

## Scope and remaining limitations

- The end-to-end test used two processes on one Windows host over loopback TCP. It is not evidence of independent-host routing, firewall/NAT reachability, multi-operator deployment or production uptime.
- The Authority remains one trusted Ed25519 time attester using its host clock; this does not constitute BFT time consensus.
- The dedicated block worker still serializes inbound block handling and canonical mutations. A larger bounded connection pool / explicit admission queue remains future work if throughput testing justifies it.
- Partition/reorg/fork-choice stress, adversarial restart, full-history recovery, checkpoint rollover, External-CAS failure injection, multi-host tests and independent security review remain release gates.
- `QRUN_MAINNET_RELEASE_APPROVED = false` remains unchanged. This is not a Mainnet approval, public token launch, trading/liquidity claim or exchange-readiness claim.

**Decision:** retain the change as a QRun v0.5 Public Alpha operational candidate, proceed to multi-host and partition/reorg validation, and keep Mainnet fail-closed.


## Optimized Release profile measurement and end-to-end validation

The existing disposable two-process smoke script now accepts an optional `-Release` switch. Omitting it preserves the previous debug-profile behavior. With `-Release`, it builds and runs the exact Release-profile node, Authority, Noise-key provisioner and test-only transaction client.

The Cargo Release profile is configured with `opt-level = 3`, thin LTO and one codegen unit. The same 12-attempt rate probe was run five times against the optimized executable:

| Sample | Attempts | Elapsed | Hashes/sec |
|---:|---:|---:|---:|
| 1 | 12 | 641 ms | 18.7136 |
| 2 | 12 | 636 ms | 18.8402 |
| 3 | 12 | 650 ms | 18.4600 |
| 4 | 12 | 631 ms | 19.0115 |
| 5 | 12 | 657 ms | 18.2606 |
| **Mean** | **12 each** | **643 ms** | **18.6572** |

Theoretical success probability for the measured candidate target remains **0.002979915370 per hash**. The reciprocal gives approximately **335.58 expected attempts**; dividing by the five-run mean rate gives a rough one-host expected solve time of **17.99 seconds**. This is a mathematical expectation from a short 60-hash timing sample, not an observed long-run block interval, percentile, throughput guarantee or multi-host benchmark. The 64 MiB Argon2id parameters and target were not changed.

The complete optimized two-process smoke was then run using:

```powershell
.\tools\qrun-v05-public-alpha-two-process-smoke.ps1 -Release
```

Result: **PASS**, process exit code 0, total runtime **93.88 seconds**, including the optimized build/startup and the full end-to-end test. Node A and Node B each used separate data directories, distinct Noise keys and separate reference-time state.

- Signed QZTS/1 transfer: **PASS**.
- Noise XX block broadcast: **PASS**.
- Canonical convergence: **PASS**.
- Receipt on both nodes: **PASS**.
- Owner balance and nonce match: **PASS**.
- Both nodes reached height **1** with tip `0046b353950244790b87da289495bbefdeb491e534d999b95b4cce47dab5fbac` and state root `994b57a183fb0d03f233fb483f13388330cca05a1d883f92ec75430ce36096ed`.
- Transaction ID: `86aef4580dedff93c1261c11bfcf79952ac4166700b4573af1bda526ab372262`.

The script's PowerShell parser reports zero errors. Its successful cleanup removed the disposable test root and all QRun process children. The same-host/loopback and experimental Public Alpha limitations above continue to apply.
