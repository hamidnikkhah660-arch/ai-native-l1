# QRun Project Start Here — Continuity and Operating Charter

**Document ID:** QRUN-CONTINUITY-001  
**Established:** 2026-11-06  
**Project:** QRun Blockchain  
**Native asset:** QZXB  
**Canonical repository:** https://github.com/hamidnikkhah660-arch/ai-native-l1  
**Public website:** https://hamidnikkhah660-arch.github.io/ai-native-l1/

> This file is the first-read handoff for every new developer, AI assistant, browser session, workstation, or project collaborator. It is deliberately stored in the repository so continuity does not depend on chat history.

## 1. Read these documents first

1. **[Master roadmap — ten-layer coverage map and competitive thesis](docs/QRUN_MASTER_ROADMAP_VERIFIABLE_AI_NATIVE_INFRASTRUCTURE_2026-11-06.md)** — canonical strategy, ten permanent layers, evidence vocabulary, release discipline and priorities.
2. **[CP-0567 A0 decision record](docs/CP-0567_A0_DECISION_RECORD_AI_AGENT_PAYMENT_AUTHORIZATION_2026-11-06.md)** — initial design decisions and constraints for bounded AI-agent payments.
3. **[CP-0567 A1 implementation dependency audit](docs/CP-0567_A1_IMPLEMENTATION_DEPENDENCY_AUDIT_2026-11-06.md)** — initial read-only source inspection; read together with the later correction below.
4. **[CP-0567 A1B PMT4 source-path reconciliation](docs/CP-0567_A1B_SOURCE_PATH_RECONCILIATION_2026-11-06.md)** — corrected, source-pinned description of the actual loopback PMT4/PFM4/TXN4 peer-smoke runtime and its production boundary.
5. **[CP-0567 A1C atomic capability-state proposal](docs/CP-0567_A1C_PMT4_CAPABILITY_STATE_ATOMIC_EXECUTION_PROPOSAL_2026-11-06.md)** — proposed state model, atomic execution invariants, reorg/persistence requirements and adversarial test matrix. Design only; not implemented.
6. **[QZXB economics and trading gate — PR #135](https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/135)** — draft economics/trading gate; do not merge or change draft state without explicit owner approval.
7. **[Public website update — PR #137](https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/137)** — candidate public copy and wallet/economics/technology pages; not live until approved and merged.
8. **[Master roadmap and CP-0567 documents — PR #138](https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/138)** — current documentation branch containing this roadmap and subsequent design/audit documents.
9. **[Brand identity candidate — PR #139](https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/139)** — candidate visual identity; not final or published.

## 2. Identity and strategic direction

**Public product:** QRun Blockchain  
**Native asset ticker:** QZXB (spoken as the individual letters Q-Z-X-B)  
**Strategic identity:** **Verifiable AI-Native Blockchain Infrastructure**

Build QRun around verifiable ledger state/history/recovery, open independently operated PoW nodes, carefully governed cryptographic migration, privacy-aware proofs, programmable assets and settlement, and bounded AI-agent payment authorization. PoW, low fees, speed, scalability, or quantum-related language alone are not a defensible differentiator. Publish only reproducible measurements and independently checkable evidence.

The central long-term differentiator to engineer is **AI-Agent Payment Authorization**: an owner-authorized, cryptographically bound capability that limits an agent by budget, fee, asset/network, recipient/service scope, validity window, nonce/replay rules and revocation policy. The ledger must enforce aggregate limits atomically and preserve correct behavior across concurrency, reorg, restart and recovery. This is a design priority, not a shipped feature or current marketing claim.

## 3. Permanent ten-layer map

All work must be mapped to the master roadmap's ten layers:

1. Core L1 protocol and network.
2. Security, cryptography and post-quantum transition.
3. Privacy, confidentiality and verifiable disclosure.
4. Performance, scalability and reliability.
5. Developer platform and programmability.
6. QZXB monetary policy, issuance and mining economy.
7. Payments and merchant settlement.
8. DeFi, tokenization and real-world assets.
9. AI-agent economy and bounded payment authorization.
10. Ecosystem, governance, operations and adoption.

This list is a coverage taxonomy, not a statement that all capabilities are implemented. A new major feature needs a layer, specification/issue, acceptance criteria, tests and evidence status.

## 4. Evidence-state rules

Use the exact states defined in the master roadmap: Proposed, Designed, In progress, Implemented, Tested, Independently verified, Production deployed, Released. Always name the tested environment and scope. CI success means only that the named jobs passed. Loopback and private-overlay tests do not prove public-mainnet readiness. Never convert a design document into a claim of implementation.

## 5. Snapshot of known project state (2026-11-06; re-verify before acting)

- Current documentation branch: `docs/qrun-master-roadmap-20261106`.
- Latest recorded branch commit at this snapshot: `0ad82887f486cc6bc54b72796e1081d84b974ac5` (CP-0567 A1C design proposal).
- PR #138 is OPEN and unmerged. Its latest CI run at the time of this snapshot was `42225422770`, with Rust validation and Windows PMT4/TXN4 loopback checks in progress and EVM/dependency audit queued. Re-check GitHub; do not infer the current state from this snapshot.
- PR #137 is OPEN and unmerged; its last known head was `eed9786df4fd9dea3560cc8adf7154740bb96472`. The live GitHub Pages site was still serving the older version at the last check.
- PR #139 is OPEN and unmerged; its last known head was `faa54e23f9c5840a4f69c94b8dd0f12cfabb5616`. Brand assets are candidates, not approved production assets.
- PR #135 is a Draft economics/trading-gate PR; preserve Draft and do not merge without explicit approval.
- QFP6/QAP1 private-overlay two-host admission/restart qualification passed, but it was not public-internet qualification and did not establish replay rejection or mainnet readiness.
- PMT4/PFM4/TXN4 peer-smoke runtime exists in a loopback-only diagnostic harness. It is not a public production monetary runtime. The current peer-smoke path uses local PFM4 storage; external-CAS APIs exist separately and were not found wired into that runtime path in the cited source audit.
- CP-0567 bounded AI-agent authorization is not implemented. TXN4 hybrid authentication is not equivalent to delegated agent capability enforcement.
- The whole network is not post-quantum: classical Ed25519 transaction paths and X25519/ChaChaPoly Noise P2P remain in the current inventory; ML-DSA-65 is present only in specific experimental/candidate or receipt-verification paths.
- No verified public QZXB/USDT market, exchange listing, or public trading route is established by this snapshot.

## 6. Non-negotiable operating guardrails

- Do not merge PRs, publish a new live website, change Draft status, deploy, or change release gates without explicit owner approval.
- Do not change Genesis, consensus, monetary issuance, balances, wallet custody, network/firewall/VPN settings, or production listeners as part of documentation-only work.
- Never ask for private keys, passwords, seed phrases, setup keys or tokens in chat. Use secure local prompts and least-privilege access.
- Preserve historical decisions; mark superseded decisions rather than deleting history.
- Keep user-facing claims aligned with the strongest verified evidence. No guaranteed price, exchange listing, CMC listing, or universal regulatory approval.
- For any new assistant/developer: verify current Git branch/status, fetch latest refs, inspect PR heads and CI for the exact head SHA, read this file and the master roadmap, then continue. Do not assume this snapshot remains current.

## 7. Next engineering sequence

1. Re-check CI and review feedback for PR #138 at its exact current head.
2. Continue CP-0567 design only after source-path and production-boundary assumptions are verified; next safe coding step is an isolated, pure Rust policy/state-transition module with typed errors and deterministic adversarial vectors, not node/consensus wiring.
3. Resolve atomic capability state, fork/reorg rollback, persistence and external-CAS integration semantics before selecting a wire format or changing consensus.
4. Separately validate the website update and brand candidate; publish only after explicit approval.
5. Maintain independent launch gates: durable storage/CAS and anti-rollback; full history/checkpoint recovery; independent providers/operators; production PoW calibration; restart/reorg/fork-choice and attack testing; wallet/Genesis/economics reconciliation; independent security review; public network operation; and a separately verified market/liquidity route.

**Continuity rule:** if a later decision changes any item here, update this file and the relevant detailed source document in the same reviewed change. This document is a durable handoff index, not a substitute for live GitHub/CI verification.
