# CP-0459 — QRun v0.5 single-host PoW calibration candidate

**Date:** 2026-10-28
**Status:** Local benchmark completed; a reproducible initial-target candidate is derived, but the production consensus profile remains **not frozen** and Mainnet remains **not activated**.

## Measured throughput

Executed from `src/native/pow_bench`:

```powershell
cargo run --release --bin cpw_argon2id_pow_benchmark
```

The executable completed successfully with seven trials per memory case, eight hashes per trial, and two warm-up hashes. The results were:

| Argon2id memory | Median time per 8 hashes | Median hashes/s | Median absolute deviation |
|---:|---:|---:|---:|
| 16 MiB | 0.116017 s | 68.955 | 2.245 |
| 32 MiB | 0.270532 s | 29.571 | 2.363 |
| 64 MiB | 0.715189 s | 11.186 | 1.105 |

The selected candidate uses Argon2id v1.3, 64 MiB, time cost 1, one lane, and 32 output bytes. Power consumption, energy per hash, and cross-hardware variance were not measured.

## Derived difficulty candidate

For a 30-second target interval and the measured 64 MiB median throughput of 11.186 hashes/s, the candidate expects 335.58 hash attempts per block. The deterministic integer calculation is:

```text
initial_target = floor((2^256 - 1) * 1000 / (11186 * 30))
```

The resulting 32-byte big-endian initial target is:

```text
00c34aaf0f8c0ba80ec4d914373b1f1bff34e587607897b79eb865eaf9c2837c
```

The machine-readable candidate is `profiles/qrun_v05_consensus_calibration_candidate.json`. The independent oracle `simulations/qrun_v05_consensus_calibration_oracle.py` reproduces the integer calculation and verifies that the profile is still marked as unfrozen.

## What this does and does not establish

This is a real measurement and a reproducible local calibration—not a production-ready difficulty decision. It is based on one host, and so cannot establish a fair target for weaker supported miners or a stable expected block interval across the network. Before freezing, collect the same benchmark from at least three independently operated hardware classes, preserve raw outputs, compare lower-percentile throughput, and stress the retarget rule under sudden hashrate changes, delayed blocks, timestamp manipulation, and branch reorganizations. The exact profile fingerprint must then be applied consistently by block production, import, replay, fork choice, and restart.

The benchmark binary still deliberately uses an easy target for local smoke tests. This candidate profile does **not** change that binary's listen policy or imply public-network readiness. External-CAS deployment, independently retained anti-rollback state, production peer bootstrap/churn, multi-host QFP5 tests, and independent release verification remain open. Post-Genesis minting and miner subsidy remain disabled.
