# QuantumZXB - Master Engineering and Ecosystem Roadmap v0.2
Date: 2026-10-20
Status: Public engineering roadmap aligned with the repository review. Milestones are evidence-based; no public-network launch date is promised.

## North-star

Build an independently operable native Layer-1 with predictable coin economics, verifiable state, resilient peer networking, post-quantum-ready authentication and an integrated programmable application layer. The long-term AI-native ecosystem should connect native payments, developer applications and verifiable computation services without placing unverified AI-work claims into the consensus layer prematurely.

The plan below separates completed research evidence from acceptance work needed for a production network.

## Phase 0 - Research base and reproducibility (substantial progress)

**Existing assets**
- Public curated source repository, versioned documentation and release checksum manifest.
- Native Rust research/runtime candidate with transaction, state, PoW, chain-selection, fork/reorg, snapshot and persistence experiments.
- Reproducible vectors, strict parsers, adversarial mutation tests and independent language oracles.
- EVM feasibility lab using revm, with selected cross-client calls/creation/storage/rollback/gas fixtures.
- ML-DSA-65 real verifier candidate, selected hash-pinned C2SP/Wycheproof vectors and hybrid-identity transaction research.
- Separate fixed-supply QX ERC-20 testnet experiment plus local wallet/deployment console.

**Recorded current regression:** the local working checkout passed 736/736 library tests and the remaining Rust test targets, locked/offline check and format check. The separate EVM asset suite passed local contract, console and loopback-server tests. No live native market or revenue is implied by those test results.

## Phase 1 - Canonical native protocol and monetary accounting

**Goal:** one unambiguous implementation of the native coin rules.

Deliverables:
1. Freeze the production block/transaction/Genesis/snapshot schemas, network identifier, activation/migration rules and version compatibility.
2. Ratify the 10B coin cap and the 4B founder / 3B mining-security / 3B public-goods envelope; the sponsor/contributor proposal is carved from the founder 4B and does not increase total supply.
3. Retain the owner-directed fully transferable founder allocation with no protocol lock or time vesting. A potential sponsor's up-to-1B allocation and a 0.1B-1B contributor/professional pool remain conditional proposals until milestones, agreements and award decisions exist. The owner retains at least 2B direct discretionary coins plus any unawarded remainder of the original founder tranche.
4. Integrate issuance, transfer, fee and treasury accounting through the canonical producer, validator/importer, fork-choice/reorg, durable store, replay, snapshots and state root.
5. Add an independent reference implementation/vector oracle for Genesis, issuance schedule, rewards, reorg and exact-cap boundaries.
6. Define the true circulating-supply calculation and make node/RPC/explorer/disclosures use one consistent rule.

**Exit evidence:** reproducible clean-checkout all-target tests, independent vectors, multi-client agreement and reviewed state transitions. Do not call the proposed supply schedule active until that evidence is attached to the selected production profile.

## Phase 2 - Hybrid identity, quantum readiness and recovery

**Existing foundation:** Ed25519, ML-DSA-65 verifier candidate, V4 hybrid account/transaction candidates, key-generation/rotation/revocation policies, domain separation and test vectors.

Deliverables:
1. Freeze the account/address and signature-suite model and the exact classic/hybrid migration boundary.
2. Integrate real ML-DSA verification into the selected transaction-admission and account-state path; ensure all accepted nodes derive identical outcomes.
3. Define public key sizes, wire formats, canonical signable messages, network/manifest binding, key rotation, revocation and recovery.
4. Test against pinned external vectors plus an independent implementation, add fuzzing and malformed-input campaigns, and review timing/memory behaviour.
5. Close Gate 8 by deploying an independent monotonic trust anchor/CAS service outside the node's restore boundary, integrating exact-successor commits into the canonical store lifecycle and testing multi-host/device-failure recovery.
6. Publish a truthful cryptography profile. Claim only the portions actually migrated to hybrid/post-quantum operation; do not describe the existing classical Noise transport or all production paths as quantum-resistant.

**Exit evidence:** canonical-path integration, reproducible cross-implementation tests, independent storage/recovery evidence and external cryptography review.

## Phase 3 - Native smart-contract execution

**Existing foundation:** isolated revm 19.5.0 VM lab, typed-transaction parsing and mapping candidates, state-diff codec/decoder, selected cross-client execution fixtures, fixed-supply Solidity testnet contract and EVM wallet console.

Deliverables:
1. Pin the selected revm release and a separate reviewed toolchain; verify dependency provenance, licence and advisories.
2. Freeze the EVM hardfork, gas schedule, transaction types, chain ID, signature admission, nonce/balance/fee policy, native-coin funding model and block gas ceiling.
3. Define deterministic EVM code/storage/account representation inside the canonical native state and block-linked EVM state root; freeze receipts, logs/bloom and receipts-root rules.
4. Integrate execution, fee settlement, receipts, state commits, restart/replay and fork/reorg rollback into the canonical node.
5. Expose production-compatible JSON-RPC for read calls, deployment, transaction submission, balances, nonce, code, storage, receipts and logs.
6. Cross-check actual deployed sample applications against independent clients on a zero-value native devnet, then run adversarial contract and resource-exhaustion tests.

**Exit evidence:** sample Solidity contract deployed and executed across at least two independently built nodes, matching receipts/state roots after restart and reorg; independent VM/protocol review. Until this phase closes, the EVM lab is a strong engineering asset but not the native production VM.

## Phase 4 - Public zero-value devnet and operator qualification

Deliverables:
1. Freeze signed deployment manifests, node/network IDs and public peer identity provisioning.
2. Run multiple independently operated nodes on different hosts and networks.
3. Exercise peer churn, stale peers, missing ancestors, competing forks, archive sync, restart/recovery, key rotation, network partition and malicious/oversized input.
4. Publish native wallet, RPC, block explorer/indexer and minimal developer SDK with reproducible example scripts.
5. Provide metrics, logs that exclude secrets, issue/security reporting, incident response and backup/recovery procedures.
6. Run a public soak period and publish authentic throughput, latency, resource and uptime measurements with methods and hardware details.

**Exit evidence:** no dependence on a single local test host, consistent chain/state roots across operators, known recovery procedures and reviewed exposure boundaries.

## Phase 5 - Independent release qualification

Deliverables:
- Independent protocol and cryptography audit; critical/high findings fixed and recorded.
- Clean reproducible build and source/license/provenance/SBOM review.
- Production key ceremony rehearsal with disposable keys and restore/revocation tests.
- Genesis/consensus parameter manifest, checksums, release signing and rollback/incident runbooks.
- Independent testnet operators sign off on sync, upgrade, rollback and restart scenarios.
- A release packet links every material public claim to a test, code location, deployment record or dated decision.

## Phase 6 - Developer ecosystem and sustainable revenue

The revenue plan should start with services that can be delivered transparently using existing engineering expertise, rather than claiming the chain already has market demand:

1. Scoped sponsor-funded protocol/security/developer deliverables under written milestone agreements.
2. Contracted systems integration, wallet tooling, node deployment, reproducible-build and custom developer tooling work.
3. Paid integration support, training, technical documentation and enterprise node operations when the relevant software is stable.
4. Grants or research collaborations with public deliverables and conflict-of-interest disclosures.
5. After verifiable workloads and network accounting exist, pilot an AI/compute service coordination market, with provider measurement, service-level evidence, dispute rules and abuse resistance.

Open-source core development remains reproducible and independently operable. A service is not sold as production-ready until it has an actual deployment and support boundary. The project should not depend on fake volumes, synthetic prices, paid listing promises or speculative appreciation as a business model.

## Phase 7 - Market and production decision

Before considering a value-bearing Mainnet or publicly marketed coin:
- Freeze the production genesis/coin rules and disclose allocations, sponsor/contributor conditions and circulating-supply methodology.
- Confirm the native identity, network explorer, wallet, RPC and support channels.
- Publish independent security evidence, operating/incident practices and real testnet metrics.
- Check the requirements applicable to the actual activity and target audiences before conducting transactions that require prior steps.
- Establish real liquidity only with actual assets and honest counterparty/risk disclosures; apply to market-data platforms only when their technical criteria are met.

This phase is a decision gate, not an automatic step triggered by hitting a chosen dollar valuation.

## Release gate summary

| Track | Current state | Next verifiable milestone |
|---|---|---|
| Public source / reproducibility | Public curated release exists; latest local changes are not published | Publish a reviewed versioned release from the authorized repository remote |
| Native monetary path (Gate 2) | Candidate modules and tests; canonical integration incomplete | One frozen profile with independent end-to-end state/issuance vectors |
| Anti-rollback / recovery (Gate 8) | Extensive models and local process-crash evidence | Independent trust provider, canonical integration and multi-host storage tests |
| ML-DSA / hybrid signatures | Real ML-DSA-65 verifier tests and hybrid candidates | Production-selected transaction path and key lifecycle review |
| Native smart contracts | Isolated EVM lab and candidate adapters | Canonical VM/state/receipts/RPC integration with cross-client agreement |
| Public devnet | Loopback/private zero-value harnesses | Multiple external operators with signed identities and operational controls |
| Wallet / explorer / RPC | EVM testnet console exists; native production tooling not complete | Native toolchain connected to actual native devnet state |
| External security audit | Not completed | Independent engagement and remediation report |
| Sponsor / contributor allocation | Proposal only; no confirmed sponsor/award | Milestone agreement and versioned allocation record, if a sponsor is secured |
| Revenue | No verified project revenue in current evidence | First contracted deliverable or service revenue, separately evidenced |

## Status convention

"Built" means source/tests or a verified deployment artefact exist for the scope stated. "Integrated" means the selected component participates in the canonical node path. "Qualified" means independent, reproducible evidence is recorded. "Production" means a frozen release and operational evidence exist. These terms keep the roadmap ambitious without confusing research output with live service.
