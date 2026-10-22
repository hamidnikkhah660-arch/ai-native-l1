# QuantumZXB Public Documentation Release Manifest v0.8

Prepared: 2026-10-22
Release type: public site refresh, reproducible candidate halving charts, paid engineering offer and current launch-readiness disclosures. No production consensus/runtime profile is changed by the chart/site additions.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## Public baseline and new material

This manifest supersedes the v0.7 halving-chart snapshot as the current curated public-documentation index. It combines the reproducible candidate emission visualization with the latest launch-readiness boundaries and zero-owner-spend funding route.

Key files and evidence:

- `README.md` and `index.html` — current project overview, chart/source links, public-benefit donation disclosure, fixed-scope engineering offer, current launch-compliance checklist, and explicit statement that native QZXB Mainnet/native-market price or liquidity is not live.
- `docs/ENGINEERING_SERVICE_OFFER_V01.md` — a bounded Rust/protocol reproducibility or AI/ML feasibility engagement with deliverables, measurable acceptance conditions, written commercial terms and no-token/no-revenue-claim language. No client, contract, payment or revenue is claimed.
- `docs/CP_0372_G0_PUBLIC_LAUNCH_COMPLIANCE_CHECKLIST_2026-10-22.md` — source-linked AFM/MiCAR, donation status, payout, and owner-side verification checklist; not legal advice or a compliance determination.
- `docs/CP_0373_GATE2_PFM4_RUNTIME_PRODUCTION_BOUNDARY_2026-10-22.md` — the current PMT4/PFM4 candidate runtime and its local-only, loopback, easy-target smoke limitations; production prerequisites for Gate 2 and Gate 8.
- `docs/CP_0374_GATE2_PFM4_INVALID_POW_ATOMICITY_2026-10-22.md` — PFM4 store regression evidence for rejecting over-target PoW without changing branch/archive/tip and for the Windows PFM4 stale-cursor test-harness deadline correction.
- `docs/CP_0349_REPRODUCIBLE_CANDIDATE_HALVING_VISUALIZATION_2026-10-21.md`, `simulations/candidate_halving_curve.py`, and `simulations/candidate_halving_curve.csv` — reproducible integer-only candidate subsidy/emission visualization data.
- `docs/MINING_HALVING_PERFORMANCE_AND_SCALING_V01.md` — mining parameters, benchmark method and constraints on interpreting single-host results.
- `docs/LIQUIDITY_MARKET_DATA_AND_PUBLIC_LAUNCH_READINESS_V01.md` — real-market, market-data and cash-flow prerequisites.
- `docs/FOUNDER_PROFILE_AND_COLLABORATION.md` and `docs/FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V03.md` — collaboration contact and conditional proposed allocation terms.
- `docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V02.md` and `docs/QUANTUMZXB_MASTER_ROADMAP_V02.md` — public project concept and proposed engineering roadmap, not proof that future integrations are deployed.

The older `docs/PUBLIC_RELEASE_MANIFEST_V07_2026-10-21.md` remains a historical manifest for the halving chart increment and is not the current comprehensive public baseline.

## Candidate halving chart and arithmetic boundary

The chart/CSV is generated and checked by `simulations/candidate_halving_curve.py` using integer atomic units. The candidate inputs include an initial subsidy of 35,673,515,981 atoms, 4,204,800 blocks per halving, eight decimal places and a 30-second target-time equivalent. The modelled total mining subsidy is 299,999,999,913,926,400 atoms (2,999,999,999.139264 coins), leaving 86,073,600 atoms (0.860736 coins) from the 3B mining/security allocation envelope due to integer halving. The remainder is not silently topped up.

These values are candidate arithmetic only: the 30-second interval is a target, not observed cadence; this does not prove native supply has been issued or mined, does not establish miner profitability, and is not price or investment-return guidance. Gate 2 remains open until a single production profile and canonical production path are frozen, integrated and independently reviewed.

## Public status and claim boundaries

- Native QZXB Mainnet and a liquid native-coin market have not launched.
- The default `devnet_node` profile remains a zero-value PTB2/PFS2 loopback candidate. The current PMT4/PFM4 peer smoke is also loopback-only and uses `Uint256::MAX` target with 8 MiB Argon2 for fast integration tests; it is not a production mining profile.
- The legacy `chain_import_node` still uses BLK2/`LedgerState`. The separate MCS4 importer PR remains Draft because it duplicates a parallel linear state store without an enforced verified-PoW/fork-choice input.
- Gate 2 is **OPEN** pending a frozen network/Genesis/fee/reward/retarget/migration/trust profile, canonical production runtime wiring, independent cross-client conformance and independent protocol/economic review.
- Gate 8 is **OPEN** pending a real independently operated HTTPS CAS provider, provider-side atomic generation CAS, a reviewed out-of-band receipt-signing-key pin, separate trust domain and whole-disk anti-rollback recovery qualification. Current CAS implementation is a contract/test fixture, not a production HTTP transport.
- G0 is **OPEN**. The Giveth campaign's current status, owner wallet control, actual donation receipt, practical payout/conversion and tax treatment are not certified by this repo. Verify the live project page directly.
- G1 is **OPEN**. A fixed-scope engineering offer is published, but no signed customer engagement or paid milestone is claimed.
- Gate 4/brand and market-data work is also **OPEN**. Official exchange/data-provider eligibility must be satisfied with a real market; charts/listings must not be simulated with fabricated candles, volume or liquidity.

The Dutch AFM's public guidance on MiCAR white papers and crypto-asset services is linked in CP-0372. This manifest is not legal advice, not a claim of MiCAR compliance, not a security audit, not a Mainnet approval and not an offer to sell an investment.

## Validation provenance

The parent `main` baseline `f2acc9eca2bda4929418879017902b20a9f8b4bb` passed the Rust validation and Pages workflows after PR #40; the CI run records both test completion and the PFM4 page-2 stale-cursor/reorg smoke. The chart increment must pass its own exact-head CI and Pages deployment before this documentation release is treated as published. `RELEASE_SHA256SUMS.txt` is regenerated from canonical Git-index blob bytes and excludes its own hash.

No public listener, production key, native issuance, public value transfer, liquidity operation, paid service or owner-funded spending is created by this release. Owner spend remains USD 0.
