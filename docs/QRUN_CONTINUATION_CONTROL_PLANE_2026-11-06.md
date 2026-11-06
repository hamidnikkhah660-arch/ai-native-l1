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
- Last pre-continuity-documentation baseline: `b4758e0cf1a6eb19cde63ed880109c96e4c7922a`. The PFM5 stack source review and integration-gap update are recorded in commit `9265479bb5666cc195132db98cd6aa69cf8abe85`; this handoff metadata is subsequently refreshed in a documentation-only commit. Always query the live PR head before continuing.
- Worktree was clean and branch matched its origin tracking branch at that check.
- Active documentation PR: [#138](https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/138), open and unmerged. Do not merge without explicit owner approval.
- CI run [42234319470](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42234319470), for exact HEAD `b4758e0cf1a6eb19cde63ed880109c96e4c7922a`, completed successfully across all three jobs. The subsequent PFM5 review commit `9265479bb5666cc195132db98cd6aa69cf8abe85` triggered run [42235844835](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42235844835), which was queued at the time of the check. This handoff metadata refresh itself is another documentation-only commit; always query PR #138 and CI for its exact live head before continuing.

## 2. What this PR #138 documentation set records

- Master strategy: **Verifiable AI-Native Blockchain Infrastructure**, organized into ten layers (L1/network; cryptography/PQ transition; privacy; performance/reliability; developer platform; monetary policy/mining; payments; DeFi/tokenization/RWA; bounded AI-agent economy; ecosystem/operations).
- Evidence vocabulary is mandatory: Proposed â†’ Designed â†’ In progress â†’ Implemented â†’ Tested â†’ Independently verified â†’ Production deployed â†’ Released. A feature must not be described at a stronger state than its evidence supports.
- CP-0567 A0/A1/A1B/A1C records cover AI-agent payment authorization, dependency/source audit, PMT4 runtime boundary, and proposed atomic capability-state execution. These are design/audit records, not a shipped capability.
- A1C sections 11.12â€“11.14 document PR #60 PFM5 checkpoint replay review, the PMT4 node-to-store startup gap, and checkpoint authenticity as distinct from anti-rollback.

## 3. Critical engineering findings â€” do not regress these distinctions

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

- Existing QVAAC candidate code is in PR #93 (stacked on #92; dependency chain #90 â†’ #91 â†’ #92 â†’ #93). Reuse and extend its grant/escrow work; do not create a parallel agent-grant or escrow module.
- Existing candidate escrow includes useful deterministic checks and injected verifier boundaries, but injected test verifiers are not proof of production cryptographic verification. Candidate spend counters are not yet a canonical global ledger registry.
- CP-0567 still needs a canonical QZXB capability registry, owner-authorized register/revoke transitions, per-capability nonce/replay protection, fee and aggregate spend accounting, atomic execution, state-root/snapshot commitment, and fork/reorg/recovery semantics. Do not alter fixed-width TXN4 casually; evaluate a separate TXN5 or versioned block-action envelope. No consensus change without explicit approval and decision record.

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

## 3.5 PFM5 PR stack composition audit (2026-11-06)

Live GitHub review of PRs #123-#128 confirms a strict six-branch Draft stack; each branch targets the immediately preceding branch. All six are OPEN and Draft. Do not merge them independently or reorder them. Their exact head/base SHAs are available from GitHub and must be rechecked before any review/merge decision.

- **#123 / CP-0391 ? deterministic stale-writer rebase:** `next_pfm5_manifest_after_replay` derives a complete retained branch set from a fork-choice archive already replayed from PCP4; preserves all branches in the observed manifest; binds parent commitment and canonical cumulative-work tip. It deliberately does not perform provider I/O, signed receipt verification, persistence or CAS. Its competing-writer convergence is modeled with two fork-choice instances in one process, not two hosts.
- **#124 / CP-0392 ? local durable checkpoint-rooted fork store:** persists PCP4, content-addressed envelopes and PFM5 manifest; validates/replays retained branches on reopen; has crash-retry/corruption/lock tests. It remains local-only and not wired into `private_testnet_node`. No remote immutable-object provider or signed External-CAS transaction. It also changes README and `RELEASE_SHA256SUMS.txt`; checksum/README refreshes across stacked branches must be reconciled against the final composed tree, not cherry-picked as independent snapshots.
- **#125 / CP-0393 ? immutable object transport:** defines typed domain-separated immutable object keys and create-if-absent publication order (checkpoint, branches, manifest), read-back and bundle replay. Provider tests are in-memory doubles only; no real provider atomicity, authentication, two-host consistency or node wiring.
- **#126 / CP-0394 ? signed ECR1 publication orchestration:** reconstructs exact intent, requires a fresh signed predecessor read, publishes/read-backs immutable objects, then performs exact ECR1 CAS; classifies ambiguous replies by fresh signed reread. Still uses test doubles/local ML-DSA test keys; no concrete object store/ECR1 service, production identity/TLS/key provisioning, independent two-host campaign, or node startup wiring.
- **#127 / CP-0395 ? durable intent journal:** PFJ1 persists exact intent and predecessor/object-generation observation; crash tests cover process termination around atomic replacement. It is explicitly not an independent rollback root. Caller must advance a separately protected monotonic high-water authority after staging and before remote side effects.
- **#128 / CP-0396 ? independent high-water contract:** binds authority/provider/network/Genesis, journal sequence, ECR1 predecessor/successor and object generation; defines Prepared/Finalized and rollback/ambiguous-CAS gates. Its conformance tests use an in-memory double; no actual external authority, independently provisioned trust key or production adapter exists.

**Composition conclusion:** the stack contains valuable candidate primitives and tests, but it is not yet one production transaction. The missing production seam is the caller that composes a real independently authenticated immutable-object provider, real signed ECR1 CAS, PFJ1 durable journal and an actually independent monotonic high-water authority, then reconciles crash/ambiguous outcomes and invokes the PFM5 replay/rebase logic. The caller must be integrated into actual PMT4 node startup and tested on two independently administered hosts with restart, partition, stale-writer, lost-reply and disk-rollback scenarios.

**Do not mistake these boundaries:** passing unit tests with in-memory providers proves candidate logic under the test double, not cloud/provider semantics or independent trust. Two in-process fork-choice instances are not two hosts. A signed ECR1 manifest commitment is not proof that a pruned checkpoint's omitted history was valid; checkpoint authenticity remains a separate mandatory gate. PFM4 remains the live durable PMT4 store path until a reviewed, integrated and qualified replacement is explicitly approved.

## 3.6 Exact-head CI evidence (2026-11-06)

- PR #138 head `4995d947650a024c8e6c92bd786071e13e579970`; run [42236564111](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42236564111) was still IN_PROGRESS at last poll. EVM contract/wallet/dependency audit and Windows PMT4/TXN4 two-node loopback jobs passed; Rust `Test every target` was still running. Do not call the overall run green until its final conclusion is SUCCESS.
- The Windows job specifically passed signed TXN4 submission, invalid-signature rejection, peer propagation/replay, and PFM4 paged archive sync with inter-page reorg and stale-cursor rejection. Scope is the workflow's two-node loopback test, not public-network qualification.
- Prior exact-head run [42235955343](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42235955343) for `faef79f...` was CANCELLED/superseded; it is not a failed test and not a passing complete run. Run [42234319470](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42234319470) passed only for its own earlier commit `b4758e0...`.

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
| #93 | Draft QVAAC; stacked #90 â†’ #91 â†’ #92 â†’ #93 | Do not merge out of order; reuse candidate semantics |
| #60 | PFM5 checkpoint replay candidate | Review evidence; no blind merge |
| #124â€“#128 | PFM5 store/CAS candidate stack | Inspect base/head/dependencies and test evidence before any action |

This table is intentionally selective, not a complete PR inventory. Always query GitHub for the live list and dependency graph before work.

## 6. Mandatory continuation protocol

1. Read this file and the canonical master roadmap, then read the latest relevant CP-0567 A1C/A1B/A1/A0 records.
2. Verify `git status --short --branch`, `git log -1`, remote tracking, `gh pr view`, exact PR head SHA, and `gh run view` for the exact commit. Record timestamps and links.
3. Inspect source and tests on the actual base/head commits before proposing code. Do not infer integration from module existence or unit tests.
4. Label every result by scope: unit test, local node, loopback, private overlay, independent operator, public network, production deployment.
5. Update this handoff and the relevant canonical technical record in the same documentation PR when a material decision/status changes. Include exact commit, test command, environment, result, limitations, next blocker, and rollback/safety notes.
6. Keep superseded decisions as history and mark them superseded; do not silently erase them or maintain competing 'current' summaries.
7. Do not invent success. If a process is still running, poll it; if CI is pending, say pending; if a step was not run, say not tested.
8. Do not merge PRs, change Draft state, deploy, publish the website, approve brand/economics/release policy, change Genesis/consensus/economics/cryptographic trust, or enable public minting without explicit owner approval.
9. Do not alter VPN, NetBird policy, routes, firewall, adapters, DNS, or network services absent concrete evidence and explicit approval. Connectivity was previously restored; preserve it.
10. Never request or expose passwords, private keys, seed phrases, signing secrets, or credentials in chat or committed docs.

## 7. Next engineering sequence (not authorization to bypass gates)

1. Recheck PR #138 CI for the exact live PR head SHA (never reuse a prior commit's CI result); record the final result.
2. Inspect existing PFM5 PR stack #124â€“#128 and External-CAS client/store APIs against PR #60 replay; map what is implemented, tested, integrated, and missing. Do not create a second fork-choice engine.
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

## 9.1 Documentation validation checkpoint

Commit `b4758e0cf1a6eb19cde63ed880109c96e4c7922a` on PR #138 completed GitHub Actions run [42234319470](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42234319470) successfully across all three jobs: Rust format/check/test; Windows PMT4/TXN4 two-node loopback (including signed TXN4 rejection/propagation/replay and PFM4 paged archive reorg/stale-cursor checks); and EVM/wallet/dependency audit. This is CI evidence for that exact commit only, not PFM5 integration or public Mainnet readiness.

## 9.2 Live continuation verification (2026-11-06, 18:12 Europe/Warsaw)

- Local checkout: `D:\Temp\ASUS\QRUN_CP0566C_FINAL_MAINLINE_PREP_20261105`; branch `docs/qrun-master-roadmap-20261106`; worktree clean; local HEAD equals `origin/docs/qrun-master-roadmap-20261106`.
- PR #138 is OPEN, non-Draft, base `main`; live head is `faef79fc9328478133e203c9be8c0aa875792cee` (`docs(qrun): refresh continuation checkpoint`). `mergeStateStatus=UNSTABLE`; do not infer mergeability from CI alone.
- Latest exact-head workflow: run [42235955343](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42235955343), head `faef79fc9328478133e203c9be8c0aa875792cee`, was IN_PROGRESS at the verification time. EVM contract/wallet/dependency audit job had passed; Rust `Test every target` was running; Windows PMT4/TXN4 two-node loopback job was running signed TXN4 submit/rejection/propagation/replay, with PFM4 paged archive reorg/stale-cursor step still pending. This run must be polled before reporting a final result.
- Run [42234319470](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42234319470) is SUCCESS for exact commit `b4758e0cf1a6eb19cde63ed880109c96e4c7922a` only. It is not evidence that the later `9265479...` or `faef79...` commits passed CI.
- The later run [42235844835](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42235844835) for `9265479...` was CANCELLED when superseded; do not call it passed.
- PR #138 gained a PFM5 source-stack audit in commit `9265479bb5666cc195132db98cd6aa69cf8abe85`: PRs #123-#128 are a dependency stack, but their candidate pieces were not yet composed into a production caller. The precise composition gap and next integration design are recorded in section 3.4 above.
- Documentation-only maintenance was performed; no source, consensus, protocol, Genesis, cryptographic trust, monetary policy, release gate, or network configuration was changed. No PR was merged and no deployment/publication was performed.

**Operating principle:** the repository is the durable project memory; chat is an interface, not the source of truth. When evidence conflicts, source code + reproducible tests + exact GitHub commit/run take precedence over old chat summaries or this dated handoff. Update the handoff after verifying the new truth.
