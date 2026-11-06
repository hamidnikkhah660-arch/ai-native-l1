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

## 3.4 PFM5 stack source review (2026-11-06)

Exact fetched PR heads establish this dependency chain: `main` -> #60 / CP-0390 -> #123 / CP-0391 -> #124 / CP-0392 -> #125 / CP-0393 -> #126 / CP-0394 -> #127 / CP-0395 -> #128 / CP-0396.

- #60 `9206f545926d6c752060d50bb78e85421a492490`: open, non-Draft; two GitHub CI jobs pass (run `40048033364`). Provides the PFM5 checkpoint replay primitive; test profile is deliberately easy.
- #123 `39d64b7743582a0c0cd5bd9c3330fbefcc358f80`: open Draft; no GitHub checks reported. Adds `next_pfm5_manifest_after_replay`; no provider I/O, signed receipt, durable write or CAS.
- #124 `c4ece0e46375d1cdc59337c453095b2be6f33b9d`: open Draft; no GitHub checks reported. Local PFM5/PCP4 durable store; `open_with_manifest_anchor` compares a caller-supplied commitment but performs no remote provider read or receipt verification.
- #125 `cc563c7fb98974de546a568f77c2f1304cc9f51b`: open Draft; no GitHub checks reported. Immutable-object transport with in-memory test provider; no concrete provider adapter or independent two-host test.
- #126 `16d1c3063c565cc0bdb1b88f593b9b2571b94345`: open Draft; no GitHub checks reported. `execute_intent` composes fresh signed ECR1 read, immutable object publication, exact CAS and ambiguous-result reread, but depends on external durable intent/floors.
- #127 `786a531897e262e9f1c073bef1f582ffa33ca56f`: open Draft; no GitHub checks reported. PFJ1 crash-safe local intent journal; explicitly not an independent anti-rollback root.
- #128 `91560bfcaf8d73cc1b703efb00e02316c7e7c455`: open Draft; no GitHub checks reported. High-water provider interface and gate functions; only in-memory test implementation, no production authority adapter.

PR #123-#128 descriptions report Windows/offline local validation (778, 786, 791, 799, 807 and 816 library tests respectively, with additional target checks stated in each body). `gh pr checks` reported no GitHub checks for those heads at audit time; do not call these GitHub CI or independent security verification.

**Critical composition finding:** in the PR #128 tree there is no production caller composing PFJ1 stage -> independent high-water advance -> CP-0394 execute -> PFJ1 finalize -> high-water finalize. High-water functions are only referenced outside their module by documentation; journal store has no production caller outside its own module. Exported candidate modules do not prove runtime integration.

**Current node boundary:** on `origin/main`, `run_monetary_v4_hybrid_peer_smoke` in `src/native/pow_bench/src/bin/private_testnet_node.rs` opens the PFM4 store with local `open(...)` (audited source line 5687). It does not call `open_with_external_cas(...)` or the PFM5 store. PFM5 remains unintegrated with the actual PMT4 startup path.

Next: write one mainline-compatible end-to-end integration design, not another isolated module. It must combine checkpoint authenticity (separate from CAS anti-rollback), fresh pinned ECR1 read, PFJ1 durable intent, independent high-water ordering, immutable object publication, exact CAS and ambiguous recovery, PFM5 bounded replay, and crash/restart/partition/reorg tests through the real PMT4 node using independently administered production adapters.

## 9.1 Documentation validation checkpoint

Commit `b4758e0cf1a6eb19cde63ed880109c96e4c7922a` on PR #138 completed GitHub Actions run [42234319470](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42234319470) successfully across all three jobs: Rust format/check/test; Windows PMT4/TXN4 two-node loopback (including signed TXN4 rejection/propagation/replay and PFM4 paged archive reorg/stale-cursor checks); and EVM/wallet/dependency audit. This is CI evidence for that exact commit only, not PFM5 integration or public Mainnet readiness.
