# Mining, Halving, Throughput and Performance Evidence - v0.1

Date: 2026-10-20
Status: Candidate-profile and benchmark record. This is not a frozen production consensus specification.

## 1. Current monetary design

The current public direction is a 10,000,000,000 native-coin lifetime design cap with the following allocation envelopes:

| Envelope | Amount | Share of total cap | Current meaning |
|---|---:|---:|---|
| Founder | 4,000,000,000 | 40% | Founder-controlled; no protocol lock or time vesting under current owner direction |
| Mining / network security | 3,000,000,000 | 30% | Maximum design budget envelope, not a statement that these coins are already mined or issued |
| Public goods / ecosystem | 3,000,000,000 | 30% | Design envelope; detailed release/authorisation accounting remains to be frozen |
| Total | 10,000,000,000 | 100% | One inclusive proposed lifetime cap |

The sponsor proposal of up to 1B coins and the contributor/professional pool of 0.1B-1B are carved from the founder's existing 4B envelope. They do not increase the cap. No sponsor award or coin transfer under that proposal is established.

## 2. Existing candidate mining and halving profile

CP-0338 and the current working-tree checkpoints record an internally shared monetary-policy candidate that reconciles the proposed 10B total cap and 4/3/3 allocation envelopes at the arithmetic level:

| Parameter | Current candidate value | Status / caveat |
|---|---|---|
| Coin precision | 8 decimal places (100,000,000 atomic units per coin) | Candidate profile; confirm in canonical production schema |
| Total maximum supply | 10,000,000,000 coins | High-level design direction; not yet an active production mint rule |
| Mining/security budget | 3,000,000,000 coins | Design envelope |
| Target block interval | 30 seconds | Candidate target, not an observed production block interval |
| Halving interval | 4,204,800 blocks | Four years only if the 30-second average target is achieved; not ratified as production consensus |
| Initial block subsidy | 35,673,515,981 atomic units = 356.73515981 coins | Candidate arithmetic, not a canonical reward |
| Modelled total subsidy across integer-halving eras | 299,999,999,913,926,400 atomic units = 2,999,999,999.139264 coins | Matches the independent integer schedule calculation |
| Unused remainder within the 3B candidate budget | 86,073,600 atomic units = 0.860736 coins | Due to integer rounding; no extra terminal mint is silently assumed |

The schedule candidate halves the base subsidy by block height using integer arithmetic. The epoch number is floor(block_height / 4,204,800); the candidate subsidy in atomic units is the initial subsidy shifted right by the epoch number, with explicit integer behaviour. A block-height schedule is more deterministic than a calendar-date rule, but the real-world date of each halving depends on observed block production.

**Important:** this profile is not integrated through the canonical production block admission/producer, Genesis, import, fork-choice/reorg, persistence, replay, snapshot and state-root paths. Gate 2 remains open. These values are useful design/test inputs, not a promise that production mining is running.

## 3. Proof-of-work and difficulty parameters in research

The working-tree research describes the following Argon2id candidate:

- Argon2id v1.3, memory cost 64 MiB, one iteration, one lane, 32-byte output.
- Candidate target interval: 30 seconds.
- Candidate retarget window: 2,016 blocks, nominally 16 hours 48 minutes at the target interval.
- Candidate retarget clamp: from one-quarter to four times the previous target difficulty per adjustment window.
- Candidate work/target comparisons use integer target arithmetic and candidate cumulative-work/fork-choice logic.

This is not a guarantee of ASIC resistance, fairness, attack cost or launch security. The parameter selection, timestamp rules, consensus activation, miner protocol and canonical node integration require independent review. Difficulty adjustment and subsidy halving solve different problems: retargeting attempts to regulate block cadence; halving changes the issuance rate.

## 4. Measured mining-candidate screens

A local Release-mode Rust screen dated 2026-10-10 on one Intel Core i7-8565U Windows host reported median candidate hash rates:

| Memory parameter | Median measured rate | Trials |
|---|---:|---|
| 16 MiB | 65.910 H/s | 7 trials, 8 headers per trial |
| 32 MiB | 37.837 H/s | 7 trials, 8 headers per trial |
| 64 MiB | 13.395 H/s | 7 trials, 8 headers per trial |

A separate Python screen on an AMD64 host reported 67.813 H/s, 29.895 H/s and 15.956 H/s for the same respective memory settings. These are small, single-host or non-identical implementation samples. They are not total network hashrate, mining profitability, joules/hash, GPU/ASIC results or evidence of ASIC resistance. Power consumption, sustained thermal behaviour, device diversity and cloud/rented-hash cost were not established.

## 5. Measured state-scale candidate baseline

A separate candidate asset-state benchmark ran on one Windows host with an Intel Core i7-8565U. At 16,384 candidate assets and 32,768 holdings it reported a 6,280,432-byte snapshot and about 12.07 seconds for the repeated candidate block-plus-full-state-root metric as described by that benchmark report. The full-state commitment path is O(state); this result is an architectural warning and motivates evaluating authenticated incremental state commitments.

This is not a whole-node TPS figure. The candidate asset-state format is not integrated into the canonical P2P block/snapshot wire path, only one host was tested, and this baseline does not represent a public network or production consensus limit.

## 6. What has and has not been measured

| Metric | Current evidence | Current public claim boundary |
|---|---|---|
| Rust regression | 736/736 library tests passed in the reviewed maintainer checkout; other test targets had no failures | Test count is not throughput or independent security certification |
| ML-DSA-65 vectors | 53 selected cases (48 expected-valid, 5 expected-invalid) | Verifier/fixture conformance only; not whole-network post-quantum security |
| Candidate PoW hash rate | Single-host/limited comparison screens at explicit memory costs | Not total network hash rate or profitability |
| State growth | Candidate asset-state workload up to 16,384 assets / 32,768 holdings | Not canonical L1 execution throughput |
| Native transaction TPS | No comparable end-to-end canonical multi-node benchmark in current evidence | Do not publish a TPS claim yet |
| Inclusion/confirmation latency | No public multi-operator production-like measurement in current evidence | Do not promise a fixed finality time |
| Mainnet uptime / scale | No native production Mainnet | Do not claim uptime, live network scale or active miners |
| AI/LLM inference | No measured in-project production service established in current evidence | Describe AI/LLM/compute as roadmap and collaboration opportunities, not live utility |

## 7. Required mining and emission acceptance tests

Before numeric mining economics can be called production rules, freeze a versioned profile with all of these details:

1. Network ID, Genesis hash, block/transaction/snapshot schemas and activation/migration rules.
2. Exact header bytes hashed by PoW, digest/algorithm parameters, target encoding and canonical integer comparisons.
3. Timestamp bounds, future-time checks, retarget formula, window size, clamp, minimum difficulty and rules for missing/abnormal timestamps.
4. Initial subsidy in atomic units, halving interval in block height, rounding, terminal/tail-emission decision, beneficiary binding and fee distribution.
5. One canonical rule for founder, miner/security and public-goods buckets, including how sponsor/contributor awards remain within the founder envelope.
6. A lifetime 10B supply invariant enforced through every value-creation path: block producer, validator/importer, fork-choice/reorg, persistence, restart/replay, snapshot restore and state root.
7. Independent cross-language vectors for Genesis, every halving boundary, integer truncation, zero subsidy, overflow, cap-minus-one, exact cap, cap-plus-one, wrong network, replay, reorg and restart.
8. Independently built clients that derive identical balances, issuance counters, canonical tip and state roots from the same chain.

Every accepted block's subsidy must be computed inside the canonical validator from the frozen schedule. Do not trust a peer-supplied reward. The 3B mining/security envelope must not be interpreted as a claim that all 3B coins exist at Genesis.

## 8. Performance, accuracy and scale methodology

Consensus accuracy means deterministic agreement, not an approximate statistical score. For identical accepted input, independent clients must agree exactly on transaction validity, balances, issuance counters, canonical chain tip, state roots and execution receipts. A single disagreement is a correctness defect.

For network performance, publish a dated benchmark bundle identifying commit, build profile, hardware, operating system, node count, configuration, workload, duration and raw logs. At minimum measure:

- **TPS:** valid committed transactions per second, transaction sizes/types, workload mix, duration, rejected transactions, peak and sustained rates.
- **Latency:** p50/p95/p99 submission-to-inclusion and confirmation/reorg behaviour with sample count and clock method.
- **Block cadence:** inter-block time distribution, missed/empty blocks and reorg depth vs target.
- **Resource scaling:** CPU, RAM, disk I/O, network bandwidth, queue depth and state size per node.
- **Sync and recovery:** initial sync rate, snapshot size/restore time, replay time, restart time and rollback correctness.
- **Mining:** H/s, joules/hash, memory bandwidth, sustained thermal behaviour, hardware type and transparent electricity-cost assumptions.
- **EVM:** exact VM revision, gas schedule, fixture bytecode, execution latency and matching receipts/state roots across nodes.
- **AI/compute service:** model/runtime version, hardware, task duration, success/error rate, input/output volume and independent verification overhead.

Separate single-node microbenchmarks, localhost tests, multi-process tests, multi-host devnet runs and public soak measurements. Do not blend them into one marketing TPS figure.

## 9. Halving options and economic modelling

A four-year macro-halving is the current arithmetic candidate in CP-0338, but it remains unratified for production. Shorter bootstrap halvings, smooth emission and other profiles have been studied as alternatives in older research. Older internal research also contains incompatible caps, founder splits and initial subsidies that are superseded by the current 10B / 4B-3B-3B design direction. Do not combine values from those older profiles or describe them as simultaneously active.

Before selecting the production curve, simulate and publish:
- cumulative issuance by month, year and exact boundary height;
- miner-budget use and integer-rounding remainder;
- low/zero-fee scenarios and subsidy decline;
- hash-rate exits/spikes, retarget lag, rented-hash sensitivity and pool concentration;
- demand/price sensitivity without assuming any market price is guaranteed;
- independent reference implementation output and a written owner decision.

A larger nominal reward does not mean larger real-world earnings. Miner profitability depends on actual token value and liquidity, fees, electricity, hardware efficiency, difficulty, uptime and competition. No profitability or future coin price is promised.

## 10. Next engineering priorities

1. Freeze one canonical Genesis and monetary profile, then close Gate 2 with end-to-end invariants and independent vectors.
2. Close Gate 8 through a separately administered monotonic trust provider and multi-host durability/recovery qualification.
3. Integrate the chosen EVM execution path into canonical state and RPC, with matching receipts/state roots across independent nodes.
4. Operate a zero-value multi-operator devnet and publish reproducible TPS, latency, CPU/RAM, sync and uptime measurements.
5. Complete independent protocol/cryptography review before describing any of the above as production-qualified.

## 11. Reproducible candidate curve chart

The public site now includes two clearly labelled, modelled SVG charts: per-block subsidy across halving eras (log2-scale steps) and cumulative mining-budget emission. These charts are not live telemetry, a price chart, a circulating-supply series, or a production consensus guarantee.

Regenerate the per-era data and SVG section from the integer candidate profile:

    python simulations/candidate_halving_curve.py --write

Check that the committed CSV and rendered HTML match the arithmetic:

    python simulations/candidate_halving_curve.py

The script writes simulations/candidate_halving_curve.csv with every nonzero subsidy epoch, inclusive height boundaries, per-block subsidy, per-era issuance and cumulative modeled issuance. Decimal values are formatted from integer atomic units, not floating-point calculations. The data remains a candidate simulation until Gate 2 closes.
