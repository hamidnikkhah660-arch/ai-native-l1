# CP-0621 — QFP6 SHA-256d Host Throughput Measurement

Date: 2026-11-12
Branch: `feat/cp0600-bootstrap-sync-startup`

## Scope

Measured the existing canonical QFP6 SHA-256d header digest path using the repository's `qrun_v06_sha256d_rate_probe` release binary. The probe performs 100,000 warm-up digests, then five two-second samples. This measures one CPU host only; it is not a network hashrate, miner fleet estimate, production difficulty recommendation, or security assessment.

## Host

- CPU: Intel Core i7-8565U @ 1.80 GHz
- Cores / logical processors: 4 / 8
- OS: Windows (x64)
- Build: Cargo release profile

## Results

| Sample | Digests | Elapsed seconds | Digests/second |
|---:|---:|---:|---:|
| 1 | 1,323,714 | 2.000000 | 661,856.934 |
| 2 | 1,015,123 | 2.000002 | 507,561.119 |
| 3 | 923,898 | 2.000001 | 461,948.723 |
| 4 | 939,923 | 2.000002 | 469,961.007 |
| 5 | 914,861 | 2.000002 | 457,430.157 |

- Median: **469,961.007 digests/second**
- Minimum: **457,430.157 digests/second**
- Maximum: **661,856.934 digests/second**

The first sample is materially higher than the remaining four; the median is retained as the robust summary rather than selecting the peak.

## Release implications

1. `qrun_v06_sha256d_candidate()` still inherits the intentionally easy candidate/testnet target. This measurement does not justify carrying that target into Mainnet.
2. A single laptop's digest rate cannot establish expected public-network hashrate, attacker cost, or safe initial difficulty. Mainnet difficulty must be set from an explicit security model and independently reviewed assumptions about participating mining capacity and concentration.
3. The result does not qualify public mining, consensus security, or a production Q6CP profile. It is retained as one reproducible host baseline only.
4. No Genesis, network identity, issuance schedule, trust root, peer endpoint, or production parameter was changed by this measurement.

## Reproduction

```powershell
cargo run --release --manifest-path src\native\pow_bench\Cargo.toml --bin qrun_v06_sha256d_rate_probe
```

Expected output includes `measurement_scope=single_host_cpu_only_not_network_hashrate`.
