# QRun — Next AI Session Handoff

Last recorded: 2026-10-30

**Global product scope:** QRun is intended for worldwide use. Do not treat the founder's present/future location, Europe, the United States, Iran or any one region as the product's default market or architectural center. Apply local legal/operational analysis only to the specific issuer, asset, user group, venue, custodian and service activity involved. Keep jurisdiction-specific policy modular and separate from base consensus wherever possible.

**Read first:** [CP-0473 — Quantum-Resilient Multi-Domain Platform Vision](docs/CP-0473_QRUN_QUANTUM_RESILIENT_MULTIDOMAIN_VISION_2026-10-30.md)

## Founder direction

Build QRun as a modular, secure, evidence-led Layer-1 settlement platform. Strategic product combination:
- Quantum-resilient cryptography and crypto-agility.
- Verifiable privacy / selective disclosure.
- High performance and elastic scaling measured under realistic multi-host conditions.
- Real-world asset tokenization with legally valid rights, verified issuer/custody/oracles, lifecycle and redemption.
- Payments, multi-assets, smart contracts, DeFi, interoperability and developer tooling.
- Optional AI-agent / machine-to-machine payments with strict spending limits and scoped keys.
- Flagship proposed capability: **QRun Verifiable Asset Passport (QVAP)** — evidence-linked asset identity and rights commitments, independently signed attestations, lifecycle events, revocation/expiry, selective disclosure, and programmable settlement. An isolated non-consensus Rust candidate now exists; it is not a live feature. See [CP-0474](docs/CP-0474_QRUN_VERIFIABLE_ASSET_PASSPORT_DESIGN_2026-10-30.md).
- AI product direction: **QRun Verifiable Agentic Asset Commerce (QVAAC)** — compose QVAP with interoperable agent identity, owner-approved capability grants, deterministic evidence checks and conditional settlement. See [CP-0475](docs/CP-0475_QRUN_VERIFIABLE_AGENTIC_ASSET_COMMERCE_2026-10-30.md). Novelty is a hypothesis; no first-in-world claim is approved.

Preferred positioning: **Quantum-Resilient. Privacy-Preserving. Asset-Ready. Performance-Verified.**

Do not claim infinite scalability, impossible-to-break security, total untraceability, guaranteed price, listing or liquidity. "Infinite scale" means the founder's ambition; engineering translation is safe horizontal/elastic scaling with explicit compute, bandwidth, data-availability, verification and consensus limits.

## Current baseline and PR stack

Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Local Windows checkout: C:\Users\ASUS\Desktop\AI_NATIVE_L1_G2_G8_20261024

At last verification:
- Branch: work/qrun-v05-cas-kms-signer-20261030
- HEAD: 7f736565ccddbf2eee5a9f17583848c23d4e0789
- Working tree clean.
- PR #90 OPEN / Draft / CLEAN. Base: work/qrun-v05-cas-floor-20261030; head: work/qrun-v05-cas-node-wiring-20261030; SHA: 627d901e94f630fa19e6dbfbc080e0bc8acf0c60. CI checks green. https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/90
- PR #91 OPEN / Draft / CLEAN. Base is PR90 head branch work/qrun-v05-cas-node-wiring-20261030; head: work/qrun-v05-cas-kms-signer-20261030; SHA: 7f736565ccddbf2eee5a9f17583848c23d4e0789. CI checks green on Ubuntu, Windows, macOS, and Windows loopback. https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/91
- Keep stack order: PR90 before PR91. Neither is merged. Re-query GitHub before acting.

## Current work in progress — 2026-10-30

- Working feature branch: feat/qrun-qvap-offline-prototype-20261030, created from docs branch head 9f7b9bb4804a3db0f7d26c56be07cf93c16edbf3. Candidate implementation commit 9810bfbf224b9de5e5180f60c95865764272d69a is pushed to origin; the subsequent handoff-only commit may advance HEAD, so verify the exact SHA and working tree before acting.
- New isolated offline candidate modules:
  - src/native/pow_bench/src/qrun_verifiable_asset_passport_candidate.rs
  - src/native/pow_bench/src/qrun_verifiable_agentic_settlement_candidate.rs
  Both are exposed from lib.rs for test purposes only. Neither is wired into the production node, TXN2/TXN4, QFP5, block/state roots, Genesis or monetary supply.
- Focused verification on current code: QVAP 15/15 tests passed; QVAAC 16/16 passed; cargo +stable check --all-targets --locked --offline passed; git diff --check passed. Existing unrelated repository warnings remain.
- A previous full library test run yielded 962 passed / 1 failed due to a Windows multi-process reward-pool writer file-I/O error (Access Denied / path not found); the one test passed when rerun in isolation. Do not claim the full library suite is entirely green.
- QVAAC also enforces distinct buyer/agent/seller/evaluator identities and rejects future-dated delivery attestations. Both test suites use deliberately non-cryptographic test-only verifiers. No production AAP, ERC-8004, QVAP attestor, evaluator or ML-DSA agent-commerce verifier is connected. No trusted clock, persisted global grant revocation/sequence registry, real escrow, real payments, production API/explorer, independent-node replay or deployment exists.
- PR #92 remains a documentation-only Draft PR, all 5 observed CI checks passed: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/92. It is stacked on PR #91.
- PR #93 is OPEN / Draft: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/93. Head: feat/qrun-qvap-offline-prototype-20261030 at 9810bfbf224b9de5e5180f60c95865764272d69a. Its base is work/qrun-qvap-ci-base-20261030, a CI-filter alias branch pointing exactly to docs commit 9f7b9bb4804a3db0f7d26c56be07cf93c16edbf3. The alias exists because .github/workflows/rust-ci.yml only runs pull_request checks for base branches main/work/**; it has the same tree as docs/qrun-quantum-resilient-vision-20261030 and is not a feature/integration branch. Before any eventual merge, retarget/rebase PR93 to the intended parent after PR92's docs commit is integrated. Do not merge the alias branch itself.
- The feature work is a separate experiment and must not block QRun v0.5 public release work. Keep it Draft, isolated and reversible. Before commit/push, rerun format, both focused test suites, all-target check and git diff --check on the exact HEAD.

## Current technical truth

- PR90 wires QRun node startup to external CAS.
- PR91 adds a candidate separate CAS provider daemon and AWS KMS-backed ML-DSA-65 receipt signer.
- Full local all-target suite passed before the final CLI parser hardening (951 library tests); after that small final edit, targeted provider tests passed 5/5, and format, all-target check and diff check passed.
- AWS KMS adapter has not been tested against a real AWS account/key. AWS CLI and local AWS config/credentials were absent.
- CAS storage is durable local filesystem, not independent cloud object storage. KMS receipt signing does not stop a common rollback of provider state, floor and host backups.
- Current Noise XX transport is classical X25519/ChaChaPoly, not post-quantum/hybrid.
- External-CAS node path is QFP5 fee-only only.
- No provider or QRun node daemon was running in the last process-list check.
- The source gate QRUN_MAINNET_RELEASE_APPROVED remains false. There is no verified public QRun Mainnet, public mint, real QZXB/USDT market or market price.

## Immediate priorities

1. Re-check git and PR #90/#91. Review diffs, dependency chain and exact-head CI. Preserve Draft state until review is complete.
2. Complete independent anti-rollback design and deployment evidence. A separate process on the same host or common backup is not an independent trust domain.
3. Plan a real off-host provider/monotonic floor, separate operator/credentials, backup isolation, monitoring, key rotation and crash/failure/recovery drills. Do not provision paid cloud resources without explicit owner approval.
4. Test separate-host peer sync, restart, partition, reorg, transaction relay and exact Network ID / Genesis / profile agreement.
5. Complete consensus/profile, full-history replay/recovery and wallet/supply checks. Never bypass the closed Mainnet gate.
6. After the base network gates: PQ cryptographic inventory/migration, performance baseline, payments/developer tooling, RWA testnet model, privacy/ZK prototype, then contracts/DeFi/interoperability and AI-agent payments.

## Key current protocol/product constraints

- Founder-directed target: 10,000,000,000 QZXB at wallet-bound Genesis, zero post-Genesis minting and zero block subsidy. This remains a candidate until production integration and release validation; do not change Network ID, Genesis or supply unilaterally.
- Current RWA direction is a future modular asset framework. A token is not automatically legal title to an off-chain asset. No real RWA issuance without authorized issuer, enforceable rights, custody/attestation, redemption and jurisdiction-specific review.
- The 0.01–0.90 USD QZXB price is an aspiration only; never promise it. Real trading needs authentic assets, actual liquidity and independently verified market access.

## Useful project records

- CP-0443 permissionless-first launch policy.
- CP-0463 repository audit and release decision.
- CP-0464 brand identity.
- CP-0465 Mainnet/public trading NO-GO.
- CP-0466 real-liquidity path.
- CP-0470 durable provider backend.
- CP-0471 separate QCF1 floor.
- CP-0472 node startup wiring.
- CP-0473 product vision and phased roadmap.
- CP-0474 QRun Verifiable Asset Passport (QVAP) design and isolated offline Rust candidate; no production cryptography or consensus wiring.
- CP-0475 QRun Verifiable Agentic Asset Commerce (QVAAC); research-backed design proposal, interoperate with existing agent standards, no first claim.

## Safety / collaboration rules

Continue from actual repository state; do not make the founder repeat known details. Do not ask for seed phrases, private keys, passwords or cloud secrets. Explain proposed costs before any paid deployment and obtain explicit approval. Distinguish implemented, candidate/test-only, designed and future capabilities in all public claims.
