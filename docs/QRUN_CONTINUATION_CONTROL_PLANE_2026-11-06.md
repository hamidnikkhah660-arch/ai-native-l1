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

## 3.7 Required PFJ1 / high-water / ECR1 caller state machine (design only)

The source APIs inspected on PR #126-#128 imply this ordering. This is an integration contract for the future caller, not an implemented or production-qualified workflow.

**Explicit bootstrap:** obtain a fresh authenticated ECR1 record and object-generation observation from the pinned provider; independently establish the external high-water authority identity/trust material; initialize PFJ1 exactly once from that verified record; initialize the independent high-water state to the exact PFJ1 Ready snapshot. Missing/corrupt local state, missing authority state, identity mismatch or uncertain bootstrap must stop. Never recreate either floor automatically from the current local disk.

**New publication transaction:**

1. Read authenticated high-water state and load PFJ1 with its sequence, ECR1 generation and object-generation floors. Require `verify_ready_snapshot` to prove exact equality before preparing a new operation.
2. Build the complete PFM5 immutable bundle only from the trusted checkpoint context and a branch archive that has already passed bounded consensus replay and checkpoint-authenticity policy. Prepare one deterministic `Pfm5ExternalCasIntent` against the exact Ready ECR1 predecessor/object generation.
3. Call PFJ1 `stage_intent` and durably read back the exact Prepared intent. Before any object publication or ECR1 CAS, call `advance_prepared_snapshot` against the independent authority. If this step cannot be authenticated and reconciled, do not call CP-0394.
4. Call CP-0394 `execute_intent` with that exact persisted intent and bundle. It performs a fresh signed ECR1 read, immutable object publication/read-back and exact CAS; on ambiguous CAS reply it performs another fresh signed read. Never generate a replacement intent merely because the result is ambiguous.
5. For `Committed`, `AlreadyCommitted` or `CommittedAfterAmbiguousReply`, finalize PFJ1 with the exact successor record and observed advanced object generation using `mark_committed`; then advance the independent authority using `advance_finalized_snapshot`. If either operation is ambiguous, reread the independent authority and reconcile exact states; do not admit a new transaction.
6. For `RetrySameIntent`, leave PFJ1 Prepared and the high-water Prepared floor intact; retry only the same byte-identical intent after a fresh authenticated reconciliation. For competing successor, wrong domain, missing object, invalid receipt, rollback, unresolved read or any ambiguous trust state, preserve evidence and fail closed.

**Crash/restart recovery matrix:**

- Crash after PFJ1 staging but before Prepared high-water advance: PFJ1 is Prepared while authority is still the exact prior Ready state. Re-authenticate both and advance only that exact Prepared state; no remote publication may have happened yet.
- Crash after Prepared high-water advance but before/during object publication or ECR1 CAS: load the exact Prepared intent, prove the authority matches it, reconstruct/fetch the referenced bundle and replay it, then retry only that same intent through CP-0394's fresh signed read.
- Crash after ECR1 CAS commit but before PFJ1 finalization: PFJ1 remains Prepared; CP-0394's fresh read must identify the exact successor, after which PFJ1 can be finalized.
- Crash after PFJ1 finalization but before Finalized high-water advance: PFJ1 is Ready at the successor while authority remains at the exact Prepared predecessor. Advance the Finalized authority transition; do not incorrectly require `verify_ready_snapshot` first.
- Local journal rollback while authority already records the exact finalized successor: use `observe_finalized_floor_for_prepared_intent` only for the exact pending intent and then repair PFJ1 from that independently authenticated evidence. Any other sequence/record/object-generation combination is a conflict and fails closed.

**Important implementation checks before coding:** the current PR #126 `execute_intent` may republish/read back objects on exact-successor recovery; provider create-if-absent and byte-exact read-back must be truly idempotent. Define how the caller obtains a verified bundle when recovering a Prepared intent (manifest commitment is not enough without fetching every referenced PCP4/envelope and replaying). Define resource ownership/lifetimes for all three provider clients and ensure no locks are held across remote network calls unless explicitly designed. Add crash injection at every boundary above, lost replies at both ECR1 and high-water CAS, concurrent writers, partition/reconnect, local disk rollback, provider object-generation mismatch and key/identity rotation. Do not implement production wiring until concrete independently administered provider adapters and checkpoint authenticity are approved.

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

## 3.8 Source-level API seam audit (2026-11-06)

Inspected the actual CP-0393 through CP-0396 source snapshots on `origin/pr-125-inspect` through `origin/pr-128-inspect`, and compared the live node entrypoint on `origin/main`. This is a source review, not a production integration or provider qualification.

### Confirmed API boundaries

- CP-0394 exposes `execute_intent(object_client, cas_client, pin, context, intent, bundle)`. It reconstructs and byte-compares the deterministic intent, checks the pinned ECR1 client, publishes the immutable bundle with read-back verification, then performs signed ECR1 CAS and classifies ambiguous outcomes. Its outcomes include `Committed`, `AlreadyCommitted`, `CommittedAfterAmbiguousReply`, and `RetrySameIntent`.
- The immutable-object seam is `Pfm5ImmutableObjectProviderTransport::{put_immutable,get}`. `Pfm5ImmutableObjectClient::publish_bundle` performs checkpoint/branch/manifest publication in bundle order and byte-exact read-back. The trait itself does not provide provider authentication, durability, cross-region consistency, or independent-host guarantees; these remain adapter qualification requirements.
- The ECR1 CAS seam is separately `ExternalCasProviderTransport`, wrapped by `VerifiedExternalCasClient` for pinned receipt verification. Object storage and ECR1 CAS are two distinct trust/availability domains; success in one must not be assumed to imply success in the other.
- CP-0395 exposes file-backed `Pfm5ExternalCasJournalStore::{initialize,load_checked,stage_intent,mark_committed}`. It is explicitly a local crash-recovery aid, not an anti-rollback root. Bootstrap is create-once from an already verified remote ECR1 record and object generation; missing/corrupt journal state must not be silently initialized again.
- CP-0396 exposes `Pfm5ExternalCasHighWaterProvider::{read_authenticated,compare_and_advance}` plus caller-side transition helpers (`verify_ready_snapshot`, `advance_prepared_snapshot`, `advance_finalized_snapshot`, `observe_finalized_floor_for_prepared_intent`). The trait's security requirements are authenticated out-of-band identity, state outside the node/journal rollback domain, linearizable atomic compare-and-advance, strict successor/sequence checks and durable-before-return. No production adapter is supplied; in-memory test doubles do not qualify.

### Important naming/integration distinction

`PrivateTestnetV4HybridForkStore::open_with_external_cas` exists in the inspected fork-store candidate, but it is the PFM4/External-CAS anchored-open path. It is not a PFM5 publication caller and does not compose CP-0394, PFJ1 and the CP-0396 high-water lifecycle. Do not cite the presence of this method as proof that the PFM5 pipeline is wired into node startup.

The live `run_monetary_v4_hybrid_peer_smoke` path on `origin/main` still opens `PrivateTestnetV4HybridForkStore` with local `open(...)` against `devnet_forkstore_pfm4`. The other `open_anchored` call sites inspected are recovery/test code, not this live peer-smoke startup. Thus the node-startup integration gap remains independently confirmed.

### Required next implementation boundary (not yet authorized or implemented)

A future caller must explicitly own and test the whole lifecycle: authenticate the remote ECR1 read and object-generation floor; explicitly bootstrap PFJ1 once; reconcile PFJ1 snapshot with independent high-water state; stage the exact deterministic intent; advance Prepared high-water before any remote side effect; invoke CP-0394 with independently authenticated object and ECR1 adapters; preserve the exact Prepared intent on `RetrySameIntent`; after a verified exact successor, finalize PFJ1 and advance Finalized high-water; on every ambiguous reply perform authenticated rereads; and quarantine any identity, generation, sequence, object, or checkpoint-authenticity mismatch. This caller must then be wired into an explicitly selected node startup mode and qualified through process crashes, disk rollback, two independently administered hosts and real provider semantics.

### Recovery consequence

The high-water record stores monotonic sequence plus ECR1 record and object generation, not the full serialized PFI1 intent. If local PFJ1 is rolled back to a Ready snapshot after the independent high-water has advanced to Prepared, the state cannot safely be reconstructed from the floor alone. Fail closed and quarantine for operator-assisted recovery; never synthesize a replacement intent or reset the high-water authority. If PFJ1 remains Prepared and the floor proves the exact finalized successor, recovery may proceed only after validating the pending intent and fresh authenticated ECR1/object state, then completing the idempotent local/floor transitions.

## 9.3 Exact-head CI completion (2026-11-06)

- GitHub Actions run [42238982273](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42238982273) completed with conclusion **SUCCESS** for exact head `76dffc48156a7b291c29e4225b9355f16acf5ba6`.
- Rust `Format, check, and test`: formatting, all-target check, and `Test every target` all passed.
- Windows PMT4/TXN4 two-node loopback: signed TXN4 submission, invalid-signature rejection, peer propagation/replay checks, and PFM4 paged archive synchronization with inter-page reorg and stale-cursor rejection all passed.
- EVM contract, wallet console, and dependency audit: all steps passed.
- This is CI evidence for the exact documentation commit and the exercised existing PMT4/PFM4/EVM paths. It does **not** qualify PFM5 production adapters, PFM5 node-startup integration, independent public hosts, public Mainnet readiness, or a QZXB/USDT market.
- PR #138 remains OPEN, non-Draft, unmerged; merge state was `UNSTABLE` at the last check. No merge or deployment was performed.
- Worktree was clean and synchronized with `origin/docs/qrun-master-roadmap-20261106` before this checkpoint update. Re-verify branch, worktree, PR and the new exact-head CI after committing this documentation update.

## 9.4 Exact-head CI and PR recheck (2026-11-06, 18:18 Europe/Warsaw)

- Documentation commit `87c669bce33c20aeaed5b6717e80651895381d6c` (`docs(qrun): record exact-head CI success`) was checked against GitHub Actions run [42240814998](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42240814998). The run completed **SUCCESS** for this exact head.
- Rust `Format, check, and test`: formatting, all-target check, and `Test every target` all passed.
- Windows PMT4/TXN4 two-node loopback: signed TXN4 submission, invalid-signature rejection, peer propagation/replay, and PFM4 paged archive sync with inter-page reorg and stale-cursor rejection all passed.
- EVM contract, wallet console, and dependency audit: all steps passed.
- `gh pr view 138` confirms PR #138 remains OPEN, non-Draft and unmerged; exact head is `87c669bce33c20aeaed5b6717e80651895381d6c`; all three required checks are SUCCESS; `mergeStateStatus=CLEAN`. CLEAN means GitHub currently reports no merge conflict/blocking state; it is not owner authorization to merge.
- Local branch `docs/qrun-master-roadmap-20261106` was clean and synchronized with its origin tracking branch at verification.
- Scope limitation remains: this CI does not qualify a real PFM5 high-water adapter, authenticated external authority, production object/ECR1 providers, PFJ1/high-water orchestration in PMT4 node startup, independent operator hosts, public Mainnet readiness, or a QZXB/USDT market.
- No merge, deployment, publication, consensus/Genesis/economic change, release-gate change, or network configuration change was performed.
- Next safe engineering task: specify and qualify the real PFM5 provider boundary (out-of-band authority pin, durable monotonic state, linearizable CAS, concurrent independent-host behavior, ambiguous replies, rollback/restart/partition tests) before selecting or wiring a production adapter. Provider choice, credential provisioning, and any live service creation require owner authorization.

## 9.5 Exact-head CI completion and AWS high-water adapter qualification boundary (2026-11-06)

### Exact-head CI result

- GitHub Actions run [42242916185](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42242916185) completed **SUCCESS** for exact head `2f8c47596bfcf7d43b6fc429621ec1b18ce3f59a`.
- Rust `Format, check, and test`: formatting, `Check every target`, and `Test every target` all passed.
- Windows PMT4/TXN4 two-node loopback: signed TXN4 submission, invalid-signature rejection, peer propagation/replay, and PFM4 paged archive synchronization with inter-page reorg and stale-cursor rejection all passed.
- EVM contract, wallet console, and dependency audit: all steps passed.
- PR #138 remains OPEN, non-Draft, unmerged. Its exact head is `2f8c47596bfcf7d43b6fc429621ec1b18ce3f59a`; GitHub reports `mergeStateStatus=CLEAN`. CLEAN is a GitHub merge-state observation, not authorization to merge.
- This run qualifies only the exact commit and listed CI paths. It does not prove PFM5 production integration, independent public-host operation, public Mainnet readiness, post-quantum security of the whole network, or a QZXB/USDT market.

### CP-0396 AWS DynamoDB candidate: compatibility and security boundary

Source reviewed: `src/native/pow_bench/src/external_cas_offhost_anchor_aws_dynamodb_candidate.rs` from the CP-0483 candidate in PR #113, together with the CP-0396 PFM5 high-water contract.

- The existing DynamoDB candidate is an **off-host anchor adapter candidate**, not yet a production-qualified CP-0396 high-water authority. Its current item model includes an anchor ID, provider/network/Genesis identifiers, receipt key identifiers and hashes, policy version, sequence, provider object generation, state digest and encoded state.
- Its conditional write compares the expected sequence and state digest and advances by one; its read path requests a strongly consistent GetItem. A conditional conflict is followed by a fresh consistent read. These are useful primitives, but they do not by themselves prove the full CP-0396 authority contract.
- CP-0396 requires an independently authenticated and pinned authority identity, binding to provider/network/Genesis, journal sequence, exact ECR1 predecessor/successor and object generation, plus a durable monotonic compare-and-advance operation. The adapter must not silently accept an anchor identity as a substitute for the pinned high-water authority identity.
- A future adapter may reuse the DynamoDB request runner and conditional-write mechanics, but must define a new canonical item/state encoding and digest that binds the complete CP-0396 state. The condition must compare the expected sequence **and** the complete canonical predecessor-state digest; the successor must be exactly the allowed next transition. Authentication and trust pinning must be verified independently of mutable table contents.
- Strongly consistent reads are available for DynamoDB tables and local secondary indexes; successful writes are documented as durably persisted. This is useful service documentation, not a substitute for our own real-service, two-host qualification.
- Do not treat default multi-region eventual replication / last-writer-wins global-table behavior as a linearizable cross-region CAS authority. The safe first candidate architecture, if later authorized, is a single-region table with every writer and recovery reader routed to that same region. Multi-region strong consistency is a separate design: MRSC global tables require three regions (two replicas plus a witness, or three replicas), have additional latency and feature/operational constraints, and require their own qualification. No global-table topology is selected here.
- The current candidate tests use scripted runner doubles. No AWS account, table, IAM role, KMS key, credential, or live cloud resource was provisioned or tested in this work.

### Mandatory real-provider qualification before production use

1. Pin authority identity out of band; bind provider ID, network ID and Genesis digest; define key rotation and emergency recovery without allowing silent authority substitution.
2. Define canonical, versioned CP-0396 state bytes and digest covering sequence, exact ECR1 predecessor/successor, object generation and all identity fields.
3. Enforce a single atomic conditional successor; deny delete/reset/overwrite paths to ordinary writers. Define IAM separation for writer, verifier, backup and operator roles.
4. Test two independently administered hosts racing from the same expected state; exactly one may advance, and the loser must reread authenticated state and fail/rebase safely.
5. Test lost acknowledgement after commit, timeout before commit, conditional conflict, unavailable read, partition, process restart, credential denial, stale authority pin, object-generation mismatch and wrong Genesis/network/provider.
6. Test local disk snapshot rollback while the independent floor is ahead; test service backup/restore and any table recovery path for sequence rollback. Fail closed and quarantine on mismatch; never reset the floor or synthesize a missing PFJ1 intent.
7. Verify durable-before-success and read-after-write behavior using the real service and independent hosts. Capture sanitized evidence, exact software versions, region/topology, IAM policy hashes and test timestamps without committing secrets.
8. Only if multi-region operation is required, separately qualify the chosen MRSC topology and failure/recovery behavior. Do not assume default MREC replication is safe for monotonic CAS.

### Next safe step

Complete the source-to-contract mapping and write the adapter qualification/test plan first. Do not provision cloud resources, request credentials, add secrets, select a paid topology, or wire a provider into PMT4 startup without explicit owner authorization. Keep PFM5 integration and checkpoint historical authenticity as separate release gates; a monotonic ECR1/high-water floor does not prove omitted checkpoint ancestry.

### CP-0485 AWS KMS Anchor signer: role separation from CP-0396

Source reviewed from PR #116 (`external_cas_aws_kms_signer_candidate.rs` and CP-0485):

- The candidate adds `AwsKmsCliOffhostAnchorReceiptSigner`, implementing `OffhostAnchorReceiptSigner`. Its constructor requires both the distinct `ExternalCasOffhostAnchorPin` and the matching `ExternalCasPin`; it validates their shared provider/network/Genesis domain and takes the expected signing key only from the Anchor pin.
- Startup obtains KMS public-key metadata and requires `ML_DSA_65`, `SIGN_VERIFY`, and `ML_DSA_SHAKE_256`; it extracts the raw key from SPKI DER and compares it byte-for-byte with the independently pinned Anchor public key. A domain-separated challenge binds Anchor ID, provider/network/Genesis and both receipt-key identities. Startup and each returned digest signature are locally verified.
- The AWS CLI is invoked directly without a shell, with bounded CLI connect/read timeouts. The private key remains KMS-side; runtime credentials are expected to come from the normal AWS provider chain, preferably a narrowly scoped workload role rather than long-lived keys.
- PR #116 reports local `cargo test --lib --locked --offline` (1,013 passed), `cargo check --all-targets --locked --offline`, formatting and diff checks. Its GitHub CI matrix checks are green. PR #116 remains OPEN and Draft; no AWS request, KMS key, account, IAM role or independent Anchor operator has been provisioned.
- **Critical role boundary:** this signer signs off-host Anchor receipts. It does not implement `Pfm5ExternalCasHighWaterProvider`, does not perform CP-0396 monotonic compare-and-advance, and does not by itself make an ECR1/PFJ1 transition atomic or rollback-resistant. A KMS-backed signature is not a substitute for a linearizable high-water store.
- Potential reuse is limited to a separately pinned signing primitive if the eventual CP-0396 authority protocol explicitly adopts it. The authority state machine, canonical state digest, monotonic CAS, independent read trust, recovery and two-host concurrency proof remain separate requirements.

### Provider/Anchor/high-water acceptance separation

Keep three independent questions in the qualification matrix:

1. **Provider receipt signer:** can the provider sign its own exact object/receipt claims under its own pinned key?
2. **Off-host Anchor receipt signer:** can an independently administered Anchor sign its own attestation with a distinct key and independently verified KMS identity?
3. **PFM5 high-water authority:** can an independently trusted service atomically advance and authenticate the complete monotonic CP-0396 state across competing hosts and rollback/recovery events?

Passing one row must never be reported as passing either of the other two.

### CP-0567 / PR #138 exact-head CI completion (2026-11-06)

- Workflow run `42244338895` completed with overall conclusion **success** on exact head `f39239f5bc1e402e2860e5e7b4f377481eb3ac39`.
- EVM contract, wallet console and dependency audit: success.
- Windows PMT4/TXN4 two-node loopback: success, including signed TXN4 submission, invalid-signature rejection, peer propagation, replay check, PFM4 paged archive sync, inter-page reorg and stale-cursor rejection.
- Rust validation: success, including independent Genesis monetary snapshot oracle, candidate issuance schedule oracle, formatting, all-target check and all-target tests.
- PR #138 is OPEN, non-Draft, and reports merge state CLEAN at the time of inspection. It remains unmerged. CI success is not a security audit, public-mainnet approval, external-host qualification, or authorization to merge.

### CP-0567 / PR #138 documentation-head CI completion (2026-11-06)

- Workflow run `42245842802` completed with overall conclusion **success** on exact head `0cb09625ee26630101a5566a6e065b04da99f205`.
- Rust validation: success. Independent Genesis monetary snapshot oracle, candidate issuance schedule oracle, formatting, `Check every target`, and `Test every target` all completed successfully. The all-target test step completed at 2026-11-06T15:52:22Z.
- EVM contract, wallet console and dependency audit: success.
- Windows PMT4/TXN4 two-node loopback: success, including signed TXN4 submission, invalid-signature rejection, peer propagation, replay check, PFM4 paged archive sync, inter-page reorg and stale-cursor rejection.
- PR #138 was OPEN, non-Draft and reported merge state CLEAN at inspection. It remains unmerged. This is exact-head CI evidence only; it is not an independent security audit, public-mainnet approval, live external-CAS/high-water qualification, or authorization to merge/deploy.
- Run: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42245842802
