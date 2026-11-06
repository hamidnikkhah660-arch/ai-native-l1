# QRun Living Continuation Handoff

- **Document ID:** QRUN-CONTINUATION-CONTROL-001
- **Purpose:** durable, repository-resident handoff for the next ChatGPT session, developer, or reviewer.
- **Last verified:** 2026-11-06 (UTC; see exact commit and CI run below).
- **Canonical project:** QRun Blockchain; native asset ticker `QZXB`.
- **Repository:** https://github.com/hamidnikkhah660-arch/ai-native-l1
- **Canonical strategy map:** [`QRUN_MASTER_ROADMAP_VERIFIABLE_AI_NATIVE_INFRASTRUCTURE_2026-11-06.md`](QRUN_MASTER_ROADMAP_VERIFIABLE_AI_NATIVE_INFRASTRUCTURE_2026-11-06.md)
- **Current detailed CP-0567 engineering record:** [`CP-0567_A1C_PMT4_CAPABILITY_STATE_ATOMIC_EXECUTION_PROPOSAL_2026-11-06.md`](CP-0567_A1C_PMT4_CAPABILITY_STATE_ATOMIC_EXECUTION_PROPOSAL_2026-11-06.md)

> **Mandatory first action on every continuation:** fetch and inspect the current repository state; verify the checked-out branch, clean/dirty worktree, remote HEADs, open PRs, exact head SHAs, CI conclusions, and dependency/base relationships. This file is a dated handoff, not live telemetry. Never treat a status below as current without rechecking it.

## 1. Current continuation point

- Working checkout last verified at `D:\Temp\ASUS\QRUN_CP0566C_FINAL_MAINLINE_PREP_20261105` on authorized machine `heymed`.
- Branch: `docs/qrun-master-roadmap-20261106`.
- Last verified HEAD: `8d3b8c46bef530d0a9faae52fcffbcf71865e123` (`docs(qrun): define PFM5 checkpoint authenticity gate`).
- Worktree was clean and branch matched its origin tracking branch at that check.
- Active documentation PR: [#138](https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/138), open and unmerged. Do not merge without explicit owner approval.
- CI run [42233317891](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42233317891), for exact HEAD `8d3b8c46bef530d0a9faae52fcffbcf71865e123`, was **in progress** at last check. Formatting, target checks, independent monetary Genesis oracle, issuance schedule oracle, TXN4 submit/signature-rejection/peer-propagation/replay step, and EVM/wallet/dependency job had passed; Rust all-target tests and Windows PFM4 paged archive sync/reorg/stale-cursor step were still running. Recheck; do not infer final CI success.

## 2. What this PR #138 documentation set records

- Master strategy: **Verifiable AI-Native Blockchain Infrastructure**, organized into ten layers (L1/network; cryptography/PQ transition; privacy; performance/reliability; developer platform; monetary policy/mining; payments; DeFi/tokenization/RWA; bounded AI-agent economy; ecosystem/operations).
- Evidence vocabulary is mandatory: Proposed → Designed → In progress → Implemented → Tested → Independently verified → Production deployed → Released. A feature must not be described at a stronger state than its evidence supports.
- CP-0567 A0/A1/A1B/A1C records cover AI-agent payment authorization, dependency/source audit, PMT4 runtime boundary, and proposed atomic capability-state execution. These are design/audit records, not a shipped capability.
- A1C sections 11.12–11.14 document PR #60 PFM5 checkpoint replay review, the PMT4 node-to-store startup gap, and checkpoint authenticity as distinct from anti-rollback.

## 3. Critical engineering findings — do not regress these distinctions

### 3.1 PFM5 checkpoint replay and authenticity

- PR [#60](https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/60), branch `work/cp0390-pfm5-checkpoint-fork-choice`, head reviewed as `9206f545926d6c752060d50bb78e85421a492490`, adds replay/restore logic by extending the already-registered candidate fork-choice/store path; it is not a new independent fork-choice engine.
- Its bounded replay checks, manifest binding, branch-digest completeness, PoW/network checks, and canonical tip/work comparison are useful candidate primitives. Its tests use an intentionally easy candidate test profile; they do not establish production difficulty or mining resistance.
- **A valid signed External-CAS record proves the provider attested to a manifest commitment. It does not prove that a pruned PCP4/PFM5 checkpoint is historically valid from trusted Genesis.** Checksums, roots, metadata, and signed commitments are not substitutes for validation of omitted ancestry.
- Before a pruned checkpoint can become canonical, define and test a separate authenticity policy: independent full-history validation and/or appropriately independent threshold attestations, including signer independence, equivocation, expiry, key rotation, and recovery. Keep full history available for independent validation until this policy is accepted.
- Keep checkpoint restore candidate-only until authenticity and production recovery requirements are met.

### 3.2 PMT4 live-node External-CAS integration gap

- `src/native/pow_bench/src/bin/private_testnet_node.rs` is the node entrypoint under review.
- The PMT4 peer-smoke runtime currently opens the local fork store via local `open(...)`; it does not require a fresh independently verified remote anchor through `open_with_external_cas(...)` before serving PMT4 state.
- External-CAS APIs and unit tests exist, but they do not prove that the live PMT4 peer-smoke node is externally anchored.
- Remaining work: provider transport and independent-floor adapters; protected configuration/credentials; fresh remote read and reconciliation at startup; fail-closed behavior; and crash/restart/reorg/recovery tests through the actual node entrypoint. The independent monotonic floor must not be rollbackable with the same node disk or controlled solely by the same provider/operator.

### 3.3 QVAAC / CP-0567 reuse rule

- Existing QVAAC candidate code is in PR #93 (stacked on #92; dependency chain #90 → #91 → #92 → #93). Reuse and extend its grant/escrow work; do not create a parallel agent-grant or escrow module.
- Existing candidate escrow includes useful deterministic checks and injected verifier boundaries, but injected test verifiers are not proof of production cryptographic verification. Candidate spend counters are not yet a canonical global ledger registry.
- CP-0567 still needs a canonical QZXB capability registry, owner-authorized register/revoke transitions, per-capability nonce/replay protection, fee and aggregate spend accounting, atomic execution, state-root/snapshot commitment, and fork/reorg/recovery semantics. Do not alter fixed-width TXN4 casually; evaluate a separate TXN5 or versioned block-action envelope. No consensus change without explicit approval and decision record.

## 4. Other important evidence and project constraints

- **QFP6/QAP1:** workflow run [42205440686](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42205440686) passed a private NetBird cross-host admission/restart qualification. State root, height, and generation matched across restart. It used a private overlay; it is not public-Internet convergence or Mainnet proof. Do not claim replay rejection passed unless a specific passing marker/test is verified.
- **PQC:** the whole network is not post-quantum. Current inventory includes classical Ed25519 transaction paths and X25519/ChaChaPoly Noise P2P. ML-DSA-65 appears in limited experimental/candidate or External-CAS receipt-verification paths. Never describe the entire network as quantum-resistant.
- **Economics (CP-0566D selected policy):** 10B QZXB gross maximum-supply target; 1B founder Genesis allocation target; up to 3B PoW mining; six conditional 1B ceilings for community, exchange/liquidity partnerships, marketing, developers/security contributors, financial/strategic supporters, and burn reserve. Conditional ceilings are not automatically minted/credited; unused amounts remain unissued. Distinguish gross issuance, circulating supply, restricted balances, and actual burns. Earlier CP-0437 (10B all-owner Genesis/no subsidy) is historical/superseded.
- Initial mining subsidy correction: `35,673,515,981` base units at 8 decimals = `356.73515981 QZXB`. Inherited integer-halving schedule totals `2,999,999,999.139264 QZXB`, leaving `0.860736 QZXB` below the 3B ceiling; document dust or resolve with independent vectors before consensus freeze.
- No verified QZXB/USDT public market, exchange listing, liquidity, CMC listing, price, or universal regulatory approval is established. A PR branch name containing `usdt-trading` is not evidence of a market.
- Website update PR #137 is open and not live until merged/deployed. Brand candidate PR #139 is open and not final/approved. Do not merge, deploy, publish, or approve either without explicit permission.

## 5. PR / dependency map to verify before acting

| PR | Last known purpose/status | Rule |
|---|---|---|
| #138 | Master roadmap + CP-0567 audit/design docs; open, unmerged | Current documentation continuation branch; verify exact head/CI |
| #139 | Candidate QRun brand identity assets; open | Candidate only; no final brand approval |
| #137 | Public website/economics/wallet/PQC status update; open | Not live until approved merge/deploy |
| #135 | Draft QFP6/QAP1 runtime and cross-host qualification (despite branch name, not a live USDT market) | Preserve Draft; verify dependencies |
| #132 | Draft older v0.5 private NetBird qualification | Keep separate from QFP6/QAP1 evidence |
| #93 | Draft QVAAC; stacked #90 → #91 → #92 → #93 | Do not merge out of order; reuse candidate semantics |
| #60 | PFM5 checkpoint replay candidate | Review evidence; no blind merge |
| #124–#128 | PFM5 store/CAS candidate stack | Inspect base/head/dependencies and test evidence before any action |

This table is intentionally selective, not a complete PR inventory. Always query GitHub for the live list and dependency graph before work.

## 6. Mandatory continuation protocol

1. Read this file and the canonical master roadmap, then read the latest relevant CP-0567 A1C/A1B/A1/A0 records.
2. Verify `git status --short --branch`, `git log -1`, remote tracking, `gh pr view`, exact PR head SHA, and `gh run view` for the exact commit. Record timestamps and links.
3. Inspect source and tests on the actual base/head commits before proposing code. Do not infer integration from module existence or unit tests.
4. Label every result by scope: unit test, local node, loopback, private overlay, independent operator, public network, production deployment.
5. Update this handoff and the relevant canonical technical record in the same documentation PR when a material decision/status changes. Include exact commit, test command, environment, result, limitations, next blocker, and rollback/safety notes.
6. Keep superseded decisions as history and mark them superseded; do not silently erase them or maintain competing “current” summaries.
7. Do not invent success. If a process is still running, poll it; if CI is pending, say pending; if a step was not run, say not tested.
8. Do not merge PRs, change Draft state, deploy, publish the website, approve brand/economics/release policy, change Genesis/consensus/economics/cryptographic trust, or enable public minting without explicit owner approval.
9. Do not alter VPN, NetBird policy, routes, firewall, adapters, DNS, or network services absent concrete evidence and explicit approval. Connectivity was previously restored; preserve it.
10. Never request or expose passwords, private keys, seed phrases, signing secrets, or credentials in chat or committed docs.

## 7. Next engineering sequence (not authorization to bypass gates)

1. Recheck PR #138 CI for exact HEAD `8d3b8c46...`; record final result.
2. Inspect existing PFM5 PR stack #124–#128 and External-CAS client/store APIs against PR #60 replay; map what is implemented, tested, integrated, and missing. Do not create a second fork-choice engine.
3. Produce a precise PFM5 integration sequence covering remote anchor read, local/remote generation reconciliation, independent anti-rollback floor, checkpoint authenticity, bounded suffix replay, atomic publication, crash recovery, and actual PMT4 node startup.
4. Define the checkpoint-authenticity policy separately from provider CAS anti-rollback.
5. Continue CP-0567 only after the QVAAC gap matrix and canonical state-transition design are reconciled; no consensus code until explicit design approval.
6. Keep public website language, PQ claims, economic claims, and release readiness synchronized with evidence.

## 8. Safe verification commands

```powershell
# Always start by confirming repository and branch
 git status --short --branch
 git log -1 --format='%H %s'
 git remote -v

# Verify the current PR and exact head
 gh pr view 138 --repo hamidnikkhah660-arch/ai-native-l1 --json state,isDraft,headRefName,headRefOid,baseRefName,url

# Verify the exact CI run; substitute the current run ID after checking the head SHA
 gh run view 42233317891 --repo hamidnikkhah660-arch/ai-native-l1 --json status,conclusion,headSha,jobs
```

---

**Operating principle:** the repository is the durable project memory; chat is an interface, not the source of truth. When evidence conflicts, source code + reproducible tests + exact GitHub commit/run take precedence over old chat summaries or this dated handoff. Update the handoff after verifying the new truth.
