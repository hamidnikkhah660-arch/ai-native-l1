# QuantumZXB Public Documentation Release Manifest v0.4
Prepared: 2026-10-20
Release type: Founder/contact, mining/halving research and performance-method refresh; no consensus/runtime source changes.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## Purpose

This release layer improves professional discoverability and technical transparency. It adds a founder research profile with a direct email route, brings the candidate mining/halving arithmetic into the public description, records the scope and limitations of existing single-host benchmarks, and fixes stale publication-status/link references. It does not activate a new coin, mining network, native Mainnet, or any production consensus parameters.

## Added and updated public files

- docs/FOUNDER_PROFILE_AND_COLLABORATION.md - founder research background, education as listed in the current CV, selected technical areas, collaboration types, and direct email contact.
- docs/MINING_HALVING_PERFORMANCE_AND_SCALING_V01.md - candidate 10B/4B-3B-3B design, shared monetary-policy candidate values, PoW/difficulty profile, limited hash-rate/state-scale screens, benchmark methodology and outstanding gates.
- README.md - direct founder contact, profile/mining links, candidate parameter summary, corrected current-manifest references.
- index.html - new mining/halving/performance and founder/contact sections with mailto link.
- docs/CP_0344_PUBLIC_DOCUMENTATION_REFRESH_2026-10-20.md - clarified as historical planning checkpoint, superseded by subsequent publication evidence.
- simulations/public_docs_refresh_checker.py - offline HTML nesting, in-page-anchor, README relative-link, candidate emission-arithmetic and Git-blob checksum preflight.
- simulations/rebuild_release_checksums.py - reproducible SHA-256 regeneration from staged canonical Git blob bytes.
- RELEASE_SHA256SUMS.txt - recomputed Git-blob SHA-256 manifest over the curated tracked and included source tree, excluding the checksum file itself.
- docs/CP_0346_FOUNDER_CONTACT_MINING_PERFORMANCE_REFRESH_2026-10-20.md - scope, test evidence and boundary notes for this update.

## Founder profile boundaries

The profile is based on the current CV in the owner's workspace and the public repository engineering record. It lists an M.Sc. in Artificial Intelligence (2020), a B.Sc. in Computer Science (2015), and documented research interests in machine learning, quantum machine learning, fuzzy/evolutionary optimisation, pattern recognition, cognitive science and post-quantum blockchain security. It does not invent prior employers, a production LLM deployment, a peer-reviewed publication status, or a degree not reflected in the source CV. Individual research-paper links can be added when their public publication records are available.

Contact email: hamidnikkhah660@gmail.com. The mailto link routes prospective collaborators directly to the founder's mailbox. The assistant does not operate that mailbox.

## Candidate mining profile disclosed

The shared working-tree arithmetic recorded in CP-0338 uses 8 decimals, a 10B total design cap, a 4B founder / 3B mining-security / 3B public-goods envelope, a candidate 30-second block target, a 2,016-block difficulty window, and a 4,204,800-block four-year halving candidate. Candidate initial subsidy is 35,673,515,981 atomic units (356.73515981 coins); modeled integer subsidy totals 2,999,999,999.139264 coins and leaves 0.860736 coins in the mining/security envelope.

These parameters remain candidate arithmetic. Gate 2 is open: Genesis, canonical block rewards, import, reorg, persistence, replay, snapshot and state-root paths do not yet form a frozen production monetary profile. The 3B mining/security envelope does not mean that those coins have already been mined or issued.

## Benchmark evidence and limitations

- Maintainer-checkout regression recorded 736/736 Rust library tests passing, with no failed remaining targets; locked/offline all-target check and format check passed.
- Local launch-asset test suites passed for the separate QX testnet experiment.
- Single-host Argon2id candidate screens recorded 13.395 H/s at 64 MiB on an Intel Core i7-8565U host, with a separate host/implementation reporting 15.956 H/s for the same nominal memory setting. These are small screening samples, not network hashrate or profitability.
- A candidate asset-state workload of 16,384 assets / 32,768 holdings reported a 6,280,432-byte snapshot and about 12.07 seconds for its repeated candidate block-plus-full-state-root metric on one Intel Core i7-8565U host. It is not canonical L1 TPS.
- No comparable end-to-end native multi-node TPS, public-network latency, live block-time, native Mainnet uptime, mining profitability or independent external audit is claimed.

## Verification requirements retained

All supply/reward rules, halving boundaries and difficulty/time rules must be validated through a single canonical Genesis and runtime, with independent cross-language vectors and exact supply/state-root agreement. Gate 8 still requires an independently administered anti-rollback trust provider and multi-host durability/recovery qualification. Native EVM integration, a zero-value multi-operator devnet and independent protocol/cryptography review remain open.

No consensus/runtime source code was changed. This is a documentation and public-site refresh, not a Mainnet activation or an independent security certification.
