# CP-0503 — QRun v0.5 Public Alpha mining-latency timestamp window

Date: 2026-11-02

Status: **Candidate operational adjustment implemented; focused regressions and same-host two-process Public Alpha smoke pass. Mining still blocks Node A's RPC event loop while work is synchronous. This is not a canonical Mainnet timestamp rule.**

## Triggering evidence

A process-level Public Alpha test launched two independent QRun node processes on Windows. The processes used separate data directories, Noise NPK1 keys and reference-time RTS1 high-water stores, while sharing one disposable Network ID, Genesis epoch, signed RTP1 policy and consensus profile.

Both nodes initialized successfully and reported identical Genesis ID, Profile ID, initial tip and state root. A real Ed25519-signed TXN2 transaction was submitted to Node A through QZTS/1. The transaction was decoded and assigned its expected transaction ID. Node A performed the calibrated Argon2id candidate-mining path, but rejected the resulting candidate at live admission:

```
TimestampTooFarInPast {
  earliest_allowed: 1793600923,
  actual: 1793600892
}
```

The block timestamp was 151 seconds behind the authenticated reference time by the time mining and local submission completed. The previous QRun v0.5 local past-freshness bound was 120 seconds. The rejection was correct under that policy; no signature, network, Noise or state-transition failure was observed.

The Public Alpha candidate uses 64 MiB Argon2id, one iteration and one lane. On this host, real candidate generation and submission crossed the existing 120-second past bound. This is a production-like operational condition that the previous unit tests did not measure end-to-end.

## Bounded adjustment

The live QRun v0.5 *local admission* policy is now asymmetric:

- maximum future drift: **120 seconds** (unchanged);
- maximum past drift: **300 seconds** (raised from 120 seconds);
- zero timestamps and timestamps not strictly greater than their parent remain rejected;
- arithmetic remains saturating/overflow-safe;
- historical replay remains independent of the current wall clock.

The 300-second past allowance is a provisional operational budget based on the observed 151-second local mining/admission delay, with additional margin for host and local transport variability. It does not make a timestamp canonical, does not authenticate an arbitrary peer's historical chain and does not replace an activation-time/Genesis floor.

The asymmetric choice deliberately keeps the forward-time guard narrow. The adjustment does not change Argon2id parameters, target, retarget formula, Network ID, Genesis commitment, profile ID, issuance, supply, ECR1/QCF1/QRCP pins or Mainnet identity.

## Time-warp regression impact

The actual QFP5 live first-retarget regression now exercises the 300-second past edge together with the unchanged 120-second future edge. In its eight-block fixture:

- nominal window duration: 240 seconds;
- earliest first-block timestamp: reference time −300 seconds;
- latest final-block timestamp: reference time +120 seconds;
- maximum derived observation, including one target interval: 660 seconds;
- ratio against nominal window: 2.75x, below the configured 4x retarget clamp.

The test still rejects a severely backdated first block atomically and verifies the ledger, target history, cumulative work and consensus tip do not advance on rejection. This bounded result is useful regression evidence, not proof that local admission windows can safely become consensus parameters. Each node still has a local reference clock and may disagree with another node whose clock or mining latency differs.

## Files

- `src/native/pow_bench/src/timestamp_policy.rs`: QRun v0.5 past limit is now a distinct 300-second constant; future drift remains 120 seconds.
- `src/native/pow_bench/src/private_testnet_driver.rs`: stale-time atomicity and first-window retarget regression updated for the asymmetric bounds.
- `tools/qrun-v05-public-alpha-two-process-smoke.ps1`: launches two isolated Public Alpha node processes, provisions independent Noise/time state, submits a signed TXN2 request and checks both RPC views for the same canonical tip, state root, receipt, balance and nonce.

## Validation

Focused Rust validation after the policy adjustment:

- `timestamp_policy::tests::qrun_v05_live_timestamp_window_bounds_mining_latency_and_keeps_future_guard_strict`: **1/1 PASS**.
- `private_testnet_driver::tests::qrun_v05_live_time_window_rejects_backdating_and_bounds_first_retarget_warp`: **1/1 PASS**.
- Public Alpha two-process end-to-end retest after the asymmetric 300s/120s policy: **PASS**, total smoke runtime **291.16 seconds**.
- Node A and Node B used separate data directories, separate DPAPI-protected NPK1 Noise keys and separate RTS1 reference-time state; both opened the same disposable Network ID, Genesis ID and profile.
- A real Ed25519-signed TXN2 transfer entered Node A through QZTS/1. Node A completed calibrated Argon2id PoW and successfully broadcast the QFP5 block to Node B over Noise XX.
- Both nodes reported height **1**, identical canonical tip `00831ee4744c5dd9aa2f5ab1396bdececab2941d6f0f4ef50e69af084ee762ed`, identical state root `eba295ec228d7719c7c8961895afa2d38f27d9a399a91413d3b2cb620ab74749`, and confirmed the same transaction receipt. Owner balance and nonce matched.
- The test helper read timeout was raised to 360 seconds for this disposable end-to-end test only; the production Authority two-second deadline and signed RTP1 freshness rules were not relaxed.
- While Node A was mining, its RPC handler temporarily did not respond within a five-second probe; Node B's RPC remained responsive. After mining, Node A's RPC returned and the script verified convergence. This exposes synchronous mining/event-loop starvation, tracked as a separate operational hardening issue.

An earlier two-process run failed before this policy adjustment: Node A correctly rejected a block that was 151 seconds behind the authenticated clock under the former 120-second past limit. That failed run is retained under `E:\QRUN_TEST_TMP\qrun-public-alpha-2proc-339263583e1b4e41be6b610bf5f20ae4` as diagnostic evidence, not counted as a success. A later intermediate run reached node startup but hit a Windows accepted-socket nonblocking RPC issue; the accepted RPC/TX/Block streams now explicitly switch to blocking mode before synchronous reads.

## Remaining limits and release boundary

- The adjusted window is node-local operational freshness, not a deterministic cross-node consensus clock policy.
- The Authority remains one trusted Ed25519 time attester using its host OS clock; it is not BFT time consensus.
- The two-process smoke uses one physical Windows host and loopback TCP. It does not qualify two independent hosts or operators.
- Genesis activation epoch must still be selected and frozen before any Mainnet identity/profile finalization.
- Full-history provenance, repeated checkpoint/External-CAS recovery, remote-host Noise reachability, partitions, adversarial reorg/restart and independent security review remain open.
- `QRUN_MAINNET_RELEASE_APPROVED = false` remains unchanged.
- No Mainnet launch, public value-bearing QZXB trading, exchange listing, adoption or liquidity is claimed.

**Decision:** keep Public Alpha experimental. Use the 300-second past allowance only as a disclosed candidate live-admission latency budget. Do not promote it to a Mainnet consensus parameter without a separate time-policy design, adversarial first-window analysis and independent review.
