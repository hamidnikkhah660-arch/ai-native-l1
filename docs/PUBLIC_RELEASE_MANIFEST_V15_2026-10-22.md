# QuantumZXB Public Documentation Release Manifest v1.5

Prepared: 2026-10-22
Validated source baseline: `1bc600803ffeab378450abb8b984bebba4a56942` (PR #48 merge)
Release type: documentation and engineering-design checkpoint only; no runtime, consensus, issuance or production-profile changes.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## What changed from v1.4

Version 1.5 adds CP-0380, a source-grounded checkpoint schema and trust-boundary proposal for the next Gate 2 implementation phase. It specifies a versioned PCP4 checkpoint record, a separately versioned checkpoint-aware PFM5 manifest proposal, exact default retarget-history coverage, rollback/freshness assumptions, crash-safe publication transitions and adversarial acceptance tests. It also flags the current saturating cumulative-work update for explicit resolution before checkpoint trust can rely on chainwork. **The document is a design proposal, not an implemented format or runtime capability.** Existing PFM4 behavior and configured bounds are unchanged.

Version 1.4's CP-0379 finding and PR #48 regression remain the current source baseline: an over-height PMT4 candidate fails closed without publishing a branch/manifest mutation; no logical-height ceiling is relaxed.

## Key public files

- `README.md` and `index.html`: project overview, candidate halving visualization, engineering offer, compliance disclosures, current Gate 2/Gate 8 limits and non-launch status.
- `docs/CP_0380_GATE2_CHECKPOINT_SCHEMA_THREAT_MODEL_2026-10-22.md`: proposed PCP4 record layout and trust model; no source implementation added.
- `docs/CP_0379_GATE2_PFM4_BOUNDED_CHECKPOINT_DESIGN_2026-10-22.md`: verified logical-height/archive-cap distinction, default retarget/halving reachability gap, and checkpoint/reorg requirements.
- `docs/CP_0378_GATE2_BRANCH_DERIVED_RETARGET_2026-10-22.md`: branch-derived retarget timestamps and their atomic validation requirement.
- `docs/CP_0373_GATE2_PFM4_RUNTIME_PRODUCTION_BOUNDARY_2026-10-22.md`: PFM4 candidate/runtime boundaries and why loopback smoke tests are not a production node.
- `docs/CP_0372_G0_PUBLIC_LAUNCH_COMPLIANCE_CHECKLIST_2026-10-22.md`: source-linked AFM/MiCAR, donation status, owner-wallet and payout checks; not legal advice or a compliance determination.
- `docs/ENGINEERING_SERVICE_OFFER_V01.md`: fixed-scope Rust/protocol reproducibility and AI/ML feasibility engagement; no customer, contract, payment or revenue is claimed.
- `docs/LIQUIDITY_MARKET_DATA_AND_PUBLIC_LAUNCH_READINESS_V01.md`: real-market, market-data and cash-flow prerequisites.
- `docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V02.md` and `docs/QUANTUMZXB_MASTER_ROADMAP_V02.md`: proposed project scope and roadmap, not proof of deployed future functionality.
- `docs/CP_0349_REPRODUCIBLE_CANDIDATE_HALVING_VISUALIZATION_2026-10-21.md`, `simulations/candidate_halving_curve.py` and `simulations/candidate_halving_curve.csv`: reproducible integer-only candidate emission chart/data.

## Candidate halving arithmetic

The candidate chart models 36 eras using integer atomic units, 35,673,515,981 atoms initial subsidy, 4,204,800 blocks per halving, eight decimals and a 30-second target-time equivalent. Modelled total mining subsidy is 299,999,999,913,926,400 atoms (2,999,999,999.139264 coins), leaving 86,073,600 atoms (0.860736 coins) unused from the 3B mining/security allocation envelope due to integer halving. The remainder is not topped up.

This is candidate arithmetic only. A target interval is not observed cadence; this does not prove issued or mined supply, miner profitability, price, liquidity or investment returns.

## Current Gate and launch status

- **Gate 2: OPEN.** A frozen production network/Genesis/fee/reward/retarget/migration/trust profile, an integrated checkpoint/replay/reorg path, independently reproducible cross-client vectors and independent protocol/economic review remain outstanding. The candidate height ceiling remains 1,024, below the first default 2,017 retarget; the halving boundary is 4,204,800. CP-0380 does not implement the proposed checkpoint format.
- **Gate 8: OPEN.** External-CAS contracts/test fixtures exist, but a deployed independent HTTPS/cloud transport, server-side atomic generation CAS, independently pinned receipt-signing trust, multi-host/restore/rollback qualification and key lifecycle remain outstanding.
- **G0: OPEN.** Current Giveth campaign status, wallet control, actual receipt, payout/conversion route and tax treatment are not independently verified here. Check the live campaign directly.
- **G1: OPEN.** A fixed-scope engineering offer is public, but no signed client engagement or paid milestone is claimed.
- Native QZXB Mainnet, public mining, a native trading pair, tracked exchange volume, listing or market-data symbol are not claimed as live.
- Owner-funded spend: **USD 0**. This change introduces no paid service, production key ceremony, public listener or value-bearing deployment.

## Validation provenance

**Exact merged source baseline:** `1bc600803ffeab378450abb8b984bebba4a56942`. GitHub Actions Rust run https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39766468103 succeeded; the Ubuntu `Test every target` log reports 754 library tests passed, zero failed/ignored, in 346.91 seconds. The Windows PMT4/TXN4 two-node integration job in that workflow passed. GitHub Pages build and deployment on the same source baseline succeeded at https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39766467441.

The pre-merge Windows checkout validation for the same PR #48 code reports 757 library tests passed, zero failed/ignored; `devnet_node` 36/36, `private_testnet_node` 36/36 and all remaining binary, integration-vector and example targets passed. These Windows counts are not the Ubuntu Actions count. The CP-0380 branch changes documentation only; its documentation preflight/checksum and PR workflows must pass separately before this manifest can describe the documentation branch as validated.

Regression tests and CI establish behavior only for the current candidate code and configured targets. They do not constitute an independent security audit, a production consensus specification, a deployed checkpoint format or Mainnet approval. `RELEASE_SHA256SUMS.txt` is generated from canonical Git-index blob bytes and does not hash itself.
