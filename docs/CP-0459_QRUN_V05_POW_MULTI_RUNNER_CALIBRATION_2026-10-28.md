# CP-0459 — QRun v0.5 PoW multi-runner calibration candidate

**Date:** 2026-10-28
**Status:** Four-host benchmark evidence recorded; conservative initial-target candidate is reproducible. The production consensus profile remains **not frozen** and Mainnet remains **not activated**.

## Benchmark design

The benchmark executable measures the project's Argon2id PoW path with 16, 32, and 64 MiB memory settings. Each case runs seven trials of eight hashes, after two warm-up hashes. The local development host and three separate GitHub-hosted OS runners executed the same release command:

```powershell
cargo run --release --locked --bin cpw_argon2id_pow_benchmark
```

The three runner jobs all completed successfully in CI run [40744185485](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40744185485), commit `188faee3034dd46f41a285b377483083c22b685e`.

## Observed median throughput

Values are median hashes per second; MAD is the median absolute deviation for the 64 MiB case.

| Benchmark environment | 16 MiB | 32 MiB | 64 MiB | 64 MiB MAD |
|---|---:|---:|---:|---:|
| Local Windows development host | 68.955 | 29.571 | 11.186 | 1.105 |
| GitHub-hosted Ubuntu runner | 146.391 | 30.997 | 15.556 | 0.041 |
| GitHub-hosted Windows runner | 93.823 | 45.641 | 21.601 | 0.193 |
| GitHub-hosted macOS runner | 94.012 | 41.532 | 19.058 | 2.437 |

This is four separately executed benchmark hosts and three CI OS environments, across two operators (the local environment and GitHub-hosted runners). The benchmark does not record exact CPU models or power consumption; the macOS runner's higher variance is visible in its MAD. This is better evidence than a single-host number, but does not establish an independent-operator count of three or characterize all hardware that public miners may use.

## Candidate difficulty

The lowest observed 64 MiB median was 11.186 hashes/s on the local Windows host. The candidate therefore retains that conservative lower throughput rather than using a faster CI runner result. For a 30-second target interval, this corresponds to 335.58 expected hash attempts per block under the simplified initial-target derivation:

```text
initial_target = floor((2^256 - 1) * 1000 / (11186 * 30))
```

The resulting 32-byte big-endian target is:

```text
00c34aaf0f8c0ba80ec4d914373b1f1bff34e587607897b79eb865eaf9c2837c
```

The machine-readable candidate is `profiles/qrun_v05_consensus_calibration_candidate.json`; `simulations/qrun_v05_consensus_calibration_oracle.py` verifies the captured measurements, conservative selection, integer target derivation, fixed-supply constraints, and unfrozen/not-activated flags.

The Rust consensus module now exposes `ConsensusParameters::qrun_v05_calibrated_candidate()` using this exact initial target, 64 MiB Argon2id parameters, a 30-second target interval, a 2,016-block retarget window, and bounded 4x adjustment. A dedicated fee-only issuance parameter constructor yields zero subsidy at every height while retaining the 10-billion-coin maximum. Unit tests compare those values to the calibration artifact and check bounded retarget behavior. This creates one explicit, testable parameter candidate; it does not yet replace the deliberately easy profile in loopback node fixtures or freeze public consensus.

## Remaining consensus and launch gates

This is not a frozen production difficulty profile. Before freezing it, run measurements under at least three independently operated infrastructure operators, capture CPU architecture/model and power/energy where practical, and stress the actual target-adjustment implementation against sudden hashrate changes, slow/fast timestamps, timestamp manipulation, long gaps, fork reorganizations, and restart/replay. The exact profile fingerprint must be bound and enforced consistently by production block production, import, replay, fork choice, and restart.

The local node still uses an intentionally easy test-only PoW target for loopback tests; the measured candidate does not change its listener policy. Public peer bootstrap/churn and independent multi-host network tests remain open. The external CAS transport is still only a contract/interface plus mock-provider tests: no independently administered provider, durable provider-side atomic-CAS service, pinned production receipt key, or external anti-rollback record has been deployed from this environment. Full-history replay tests and checkpoint-rooted suffix tests are useful evidence, but are not equivalent to production-scale automatic checkpoint rollover backed by that external anchor.

The fixed supply remains 10,000,000,000 QZXB assigned at Genesis, with post-Genesis minting disabled and block subsidy zero. Public mining, if/when activated, is fee-only. Mainnet and public listeners remain disabled until the outstanding production gates are verified.
