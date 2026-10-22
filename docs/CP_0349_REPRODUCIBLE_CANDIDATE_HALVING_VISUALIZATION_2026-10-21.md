# CP-0349 - Reproducible Candidate Halving Visualization

Date: 2026-10-21
Parent public docs baseline: v0.4.0-docs / commit 446c609
Change type: Documentation, chart rendering and arithmetic validation only; no consensus/runtime source changes.

## Purpose

Make the current mining/emission candidate easier for miners, developers, sponsors and reviewers to understand while avoiding the false impression that a native network is already issuing coins or publishing live price data.

## Changes prepared

- Added a responsive two-panel SVG chart to the public website: per-block subsidy by four-target-year halving era (log2 steps) and cumulative modelled mining-budget emission.
- Added the Python script simulations/candidate_halving_curve.py, a deterministic offline generator/checker that derives the chart and per-era CSV from integer atomic-unit calculations.
- Added simulations/candidate_halving_curve.csv, listing all 36 non-zero subsidy epochs, start/end heights, block subsidy, per-era issuance and cumulative modelled issuance.
- Extended the public documentation preflight to run the candidate-curve checker and require matching CSV and generated HTML.
- Linked the chart source/data from README and the mining/halving report.
- Reworked decimal formatting in the CSV generator to use integer atomic units, not floating-point rounding.

## Arithmetic and model

Candidate inputs: 10,000,000,000-coin total design cap; 3,000,000,000-coin mining/security envelope; 100,000,000 atomic units per coin; initial candidate subsidy 35,673,515,981 atoms (356.73515981 coins); 4,204,800 blocks per halving; 30-second target block interval. The 30-second interval is a design target, not observed production cadence. The candidate schedule is height-based; wall-clock estimates are not guarantees.

- Candidate total subsidy across the integer-shift eras: 299,999,999,913,926,400 atoms = 2,999,999,999.139264 coins.
- Remainder from the 3B design envelope due to integer halving: 86,073,600 atoms = 0.860736 coins; no terminal top-up is silently added.
- Modelled cumulative emission is approximately 50% of the 3B mining budget after four target-years, 75% after eight, 87.5% after twelve, and 93.75% after sixteen. This illustrates the proposed curve's front-loading and helps support an explicit economic/security decision.
- These values are candidate arithmetic only. Gate 2 remains open; no production Genesis, canonical active mining reward, native Mainnet supply, real miner revenue or native price series is established.

## Validation

- python simulations/candidate_halving_curve.py --write - PASS; regenerated the 36-epoch CSV and SVG block.
- python simulations/candidate_halving_curve.py - PASS; generated CSV and HTML match the canonical integer calculation.
- python simulations/public_docs_refresh_checker.py - PASS; HTML structure/anchors, README links, contact/credential/platform text, emission arithmetic, candidate chart and Git-blob checksums all validated.
- The latest full curated Rust regression is recorded separately in [CP-0347](CP_0347_PUBLIC_CURATED_CHECKOUT_VALIDATION_2026-10-21.md): 735/735 library tests; all targets completed without failure. This documentation increment does not rerun or change the runtime test scope.
- Live page, final GitHub Pages build, PR merge, release tag and checksum manifest are to be rechecked after merge.

## Publication and claim boundary

The graphic is a modelled emission curve, not a market-price candle chart, live circulating supply, an active block reward or a forecast of USD returns. Real market charts remain dependent on a real supported market/data source; public network telemetry remains dependent on authenticated devnet/mainnet records. No fake candles, synthetic volume or QX/QZXB asset substitution is introduced.
