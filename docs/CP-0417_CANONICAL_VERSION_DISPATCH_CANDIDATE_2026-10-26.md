# CP-0417 — Canonical version-dispatch contract candidate

Date: 2026-10-26
Project: QuantumZXB
Status: candidate implementation; runtime integration and Gate 2 remain OPEN.

## Objective

Add a small, auditable dispatch seam that encodes the most important Gate 2 rule: choose exactly one protocol family from an explicit height activation schedule and the input's leading magic, and never try another decoder after a mismatch or decode error.

The implementation is in `src/native/pow_bench/src/canonical_version_dispatch_candidate.rs`. It is intentionally not wired to the current Devnet entrypoint, `ChainImportService`, PMT3/PMT4 store paths, or QZBE candidate node. This keeps this change from silently changing current network behavior or turning an unapproved profile into an activated consensus rule.

## Contract

- Every schedule entry explicitly pins an inclusive activation height, one protocol family, and a nonzero network ID, Genesis hash, and monetary-policy/profile fingerprint.
- The first epoch must begin at height zero. Later activation heights must strictly increase; adjacent epochs cannot repeat the same family. No fallback profile or implicit default exists.
- Recognized network block envelopes are BLK2, PMT3, PMT4, and QZBE. A PMT3/PMT4/BLK2 envelope supplied after a QZBE activation is rejected as the wrong family, not re-tried through a different decoder.
- Raw QZB4 is a block body, not the QZBE PoW network envelope; QZP4 is a snapshot, and QZGM/QZCP are profile objects. These are rejected by this block-envelope dispatch entrypoint.
- After selection, the chosen decoder must still check canonical encoding and return the decoded network/Genesis/profile identity. The caller must compare that identity to the dispatch decision. This module deliberately does not decode or validate family-specific fields itself.

## Test coverage

The focused tests cover exact inclusive activation boundaries, old-family rejection after activation, post-decode identity mismatch, empty/default schedule rejection, invalid/non-increasing/redundant epochs, zero identity pins, truncated input, unknown magic, and confusion between an inner block/snapshot/profile object and a network block envelope.

## Explicit non-goals and remaining blockers

This checkpoint does not set an actual mainnet activation height or approve token economics. It does not connect the QZBE producer/importer/state transition to the canonical node, and it does not solve historical migration/reorg, producer-importer differential conformance, full durable replay or RPC/explorer integration. The current legacy, PMT3, PMT4 and QZBE runtimes still use separate state/store paths.

Before this candidate can be wired as a production dispatcher, the project must ratify the canonical Genesis and allocation manifest, subsidy/halving schedule, owner/miner/treasury key binding, fee/burn policy, and explicit activation/migration rule; each family adapter then needs a single-decoder call path with network/Genesis/profile verification and end-to-end producer/importer/fork-choice/store/replay tests. The profile pins here are an interface contract, not evidence that these owner decisions have been made.

Gate 8 remains separate and open until an independently administered anti-rollback provider is deployed and bound to the frozen canonical state commit/reopen/reorg path. A local marker, in-memory CAS test fixture, or this dispatch module cannot prove independent anti-rollback.

## Acceptance boundary

A passing unit test can validate dispatch logic only. It does not close Gate 2 or Gate 8, authorize public listeners or value-bearing transfers, establish Mainnet activation, or authorize a token sale, listing, or liquidity pool. Public zero-value multi-operator Devnet and independent review remain downstream requirements.
