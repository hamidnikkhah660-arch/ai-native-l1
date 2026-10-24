# QuantumZXB — Master Engineering and Public-Launch Roadmap v0.4
Date: 2026-10-24
Status: evidence-based planning checkpoint. No Mainnet launch date, exchange listing, token price, or liquidity outcome is promised.

## Executive status

The public repository and a curated source release exist. Commit `80935c27a4c7da22492cf6fa8b8ad39148d5a395` (CP-0406) passed GitHub Actions run `40112877967` on 2026-10-24, including Rust validation and Windows PMT4/TXN4 two-node loopback. Commit `e3ad9a535bb021d3c810434622ff5207244ac840` adds the injected external-CAS adapter and pending-manifest recovery for QZBE. Local focused tests pass **10/10**; full `cargo test --all-targets --locked --offline` exited 0 with **826 library tests passed**, both node suites at **36/36**, all-target `cargo check` and format check passed, and checksum/docs preflight passed at **377 entries / 48 README-relative links**. GitHub Actions run `40122352670` passed on that exact implementation SHA with both Rust validation and Windows PMT4/TXN4 loopback successful. CP-0408 adds an offline-only QZB4 v2/QZBE smoke executable that explicitly takes the schedule and Genesis scope, writes to a dedicated store, builds transaction-free candidate blocks, and closes/reopens to replay. Its six unit tests pass, and a manual run has advanced height 0→3 then resumed 3→5 with identical post-replay state. It opens no P2P/RPC/wallet/market listener and rejects all transactions. All-target validation and fresh CI for CP-0408 remain required. These changes remain candidates, not production-node integration.

Passing tests are necessary engineering evidence, not evidence that the current monetary candidate is active in the canonical node, a production network exists, or the coin has been issued or can be traded.

## Gate scoreboard

| Gate | Status | Evidence required before it can pass |
|---|---|---|
| G0 — legal receiving/payout path | OPEN — owner action | Owner verifies the actual donation/payout route privately, wallet control/access, tax/accounting handling, and obtains qualified advice for intended jurisdictions. No current receipt/revenue is claimed. |
| G1 — first real revenue | OPEN | A real signed client/sponsor scope, accepted milestone, and verified payment. A public service offer or outreach alone is not revenue. |
| G2 — canonical Genesis and issuance | OPEN — protocol blocker | Freeze one network/Genesis/monetary profile; integrate it into producer, importer, state transition, fork-choice/reorg, store, restart/replay and snapshots; enforce the lifetime cap and allocation ceilings atomically; independent vectors and cross-client agreement; independent review. |
| G8 — independent anti-rollback/recovery | OPEN — security blocker | A separately operated, durably atomic CAS/anchor provider outside node rollback scope; signed, challenge-bound exact-successor receipts; canonical-store integration; multi-host stale-restore, timeout, crash and storage-fault tests; independent review. A local checksum/store is not enough. |
| G12 — native EVM/RPC | OPEN — scope-dependent blocker | If native EVM compatibility remains part of the advertised product, integrate deterministic contract execution, account/gas/state/receipt semantics, RPC, persistence and reorg rollback into canonical consensus and validate across independently built nodes. |
| G13 — public zero-value devnet | OPEN | At least three independently operated nodes, public peer identity/discovery, safe test RPC, native wallet and explorer/indexer, monitoring, reproducible operations and published genuine telemetry. No value-bearing coin during qualification. |
| G14 — release/security/compliance | OPEN | Reproducible signed build and provenance/SBOM; independent protocol/cryptography review with critical/high findings resolved; finalized public disclosures; ticker/IP namespace review; jurisdiction-specific launch/offer/service advice. |
| G15 — first real market/liquidity | BLOCKED by earlier gates | An actual supported native-chain exchange or reviewed DEX/bridge route, real paired assets and counterparties, functional deposits/withdrawals or accessible pool, verifiable depth/spread/volume and honest risk disclosures. No fabricated trades or volume. |
| G16 — market-data platforms | BLOCKED by authentic market data | Only after a functional production network/explorer and real supported market exist: submit accurate, evidence-backed platform requests and record the actual decision. No platform acceptance or timeline is guaranteed. |

## Current technical line

### CP-0391–CP-0408: candidate protocol surfaces

- v0.4 allocation/Genesis/ledger candidates bind policy and state-root data, but do not by themselves establish that the canonical producer/importer uses the profile.
- CP-0403/0404 add a profile-bound QZB4 v2 transaction-bearing candidate and candidate snapshot/dispatch path. The test authenticator and configured subsidy schedules remain test inputs, not approved Mainnet economics.
- CP-0405 adds the QZBE envelope and an in-memory bounded branch graph. The CI run for SHA `f201b2d4f510cf7bd881c064012307c76b317456` passed; the candidate is still not wired into canonical node listeners/import or production storage.
- CP-0406 adds a local-only persistent QZBE branch archive with immutable numbered manifests, digest-named branches, manifest/profile checks, rejection of non-regular manifest/branch paths, and full Genesis replay during reopen. Its focused test command is `cargo test --locked --offline --lib monetary_pow_v04_store_candidate -- --nocapture`; **7 passed, 0 failed**. The final local `cargo test --all-targets --locked --offline` exited 0; the library harness reported **823 passed, 0 failed**, and both `devnet_node` and `private_testnet_node` test harnesses reported **36 passed, 0 failed** each, with all remaining targets passing. `cargo fmt --all -- --check`, `cargo check --all-targets --locked --offline`, release checksum rebuild (376 entries) and public docs preflight (47 README-relative links) also passed. GitHub Actions run `40112877967` passed on the exact CP-0406 SHA `80935c27a4c7da22492cf6fa8b8ad39148d5a395`, with both jobs successful. CP-0407 was subsequently validated on its exact implementation SHA by GitHub Actions run 40122352670; CP-0408 is a further offline-only candidate executable and requires its own full validation/CI before promotion.

- CP-0407 extends the QZBE store with candidate APIs for exact-manifest commitments, pinned signed anchor reads, conditional exact-successor CAS writes, and pending-manifest recovery after either CAS conflict or a lost response. The in-memory provider fixture is test-only. No concrete cloud/provider adapter or independent operator deployment exists. The focused candidate test suite reports **10 passed, 0 failed**; full local all-target tests (826 library tests), all-target check, format check, checksum rebuild (377 entries) and docs preflight (48 README-relative links) have passed. GitHub Actions run `40122352670` passed on implementation SHA `e3ad9a535bb021d3c810434622ff5207244ac840`; this validates the candidate build/tests, not independent provider deployment or Gate 8 closure.

- CP-0408 adds an offline-only executable called `qzbe_v04_candidate_smoke`. It requires explicit QZB4 v2 Genesis/schedule parameters, writes to a dedicated local store, builds blocks without transactions, and closes/reopens the store to replay the branch history. Six focused tests pass; an actual local run advanced height 0→3, then resumed the same store from 3→5. It opens no P2P, RPC, wallet or market listener. Local all-target tests (826 library tests, both node suites 36/36), all-target check and format check pass; exact-commit CI remains required.

Neither CP-0406 local storage nor CP-0407's injected CAS contract itself proves production anti-rollback resistance. The complete node directory remains mutable, the provider is still only an interface/test fixture, and external object-generation floors must be protected outside the node rollback domain. Do not describe this as Gate 8 closure or wire it to production-value state without independent qualification.

## Execution plan — no owner-funded spend

1. **CP-0407 local validation — complete on the staged working tree.** Format check passed; focused CAS suite 10/10; all-target tests exited 0 with 826 library tests and both node suites 36/36; all-target check passed; release checksum rebuild (377 entries), public docs preflight (48 README-relative links), and staged diff check passed. GitHub Actions run `40122352670` passed on the CP-0407 implementation SHA; independent-provider and security qualifications remain open.
2. **Publish a reviewable candidate commit.** Commit only reviewed files on the existing feature branch, push to its existing PR, and require fresh CI to pass. Keep the PR open for independent review; do not merge solely because automated checks are green.
3. **Finish canonical monetary integration (Gate 2).** Trace actual producer/import/state-transition/fork-choice/store/replay/RPC call sites. Define and approve the complete schedule and activation/migration rules before selecting parameters. Implement one versioned transition and prove exact-cap/cap+1, reward boundary, wrong-profile, forged reward, duplicate/replay, overflow, reorg and restart behavior with independent vectors.
4. **Integrate a genuinely independent CAS provider (Gate 8).** Reuse audited provider protocol types where appropriate, but select and operate a provider only after ownership, key custody, provider administration, recovery responsibility and acceptance tests are explicit. The mock/in-memory provider in tests cannot be the production trust anchor.
5. **Qualify a public zero-value devnet.** Define a reproducible operator package, use independent operators/hosts, test network splits, mixed versions, replay, reorg, snapshot restore and incident recovery; publish only measured, source-attributed telemetry.
6. **Complete security/release qualification (Gate 14).** Independent reviewers evaluate the actual selected runtime, signing/authentication, economics, storage trust boundary and release supply chain. Resolve critical/high findings and publish scope/limitations clearly.
7. **Complete owner/jurisdiction review before an offer or value-bearing launch.** In the EU/Netherlands, determine the precise MiCAR classification, issuer/offer/admission model, white-paper obligations and any CASP obligations with qualified counsel and relevant authorities. A white-paper notification is not regulatory approval. The owner must separately finish private payout/tax/accounting steps; these should not be placed in a public issue or repository.
8. **Launch the native asset only after explicit go/no-go.** Publish the exact selected source/release SHA, Genesis and supply methodology, node/wallet/RPC/explorer endpoints, operator/security evidence, incident contacts and real distribution rules. Mainnet activation, mint/distribution, signing keys and any value-bearing transactions require explicit owner authorization after the technical and legal prerequisites pass.
9. **Create actual market access, then apply for data coverage.** Choose either a genuine native-chain exchange integration or a separately reviewed DEX/bridge path with a real quote asset. Publish no price, circulating supply, liquidity or volume claim until authenticated, inspectable source data exists.

## Cash-flow track in parallel

The existing fixed-scope engineering-service offer is the practical no-token route to potential first revenue. Continue no-cost research/outreach for a written, measurable Rust/protocol, replay, reproducibility or developer-tooling engagement. The project has no confirmed paid contract or revenue in the currently verified evidence. Do not count proposed future coin allocations, a public call, a donation campaign, or prospective grant as cash received. Do not submit applications that fail a funder's actual eligibility or authorship rules.

## Release and trading decision

**GO now:** open-source engineering; reproducible zero-value tests; candidate docs; service-offer outreach; preparing a public zero-value devnet package.

**NO-GO on current evidence:** native QZXB Mainnet, production issuance, a public coin sale, value-bearing mining/distribution, custody/exchange services, a real-money DEX/pool, fabricated price/volume charts, or submitting the Sepolia QX ERC-20 as native QZXB.

The Sepolia QX asset is a separate testnet asset, not native QZXB. The proposed 10-billion lifetime cap and allocation envelopes remain design terms until Gate 2 is independently closed. The working ticker QZXB is not cleared as unique or trademark-safe.

## References

- [Native Gate 2 / Gate 8 closure plan](NATIVE_GATE2_GATE8_CLOSURE_PLAN_V01_2026-10-20.md)
- [CP-0401 global native-coin launch and liquidity fast path](CP-0401_GLOBAL_NATIVE_COIN_LAUNCH_AND_LIQUIDITY_FASTPATH_2026-10-24.md)
- [CP-0402 runtime call-site and compatibility audit](CP-0402_RUNTIME_CALLSITE_COMPATIBILITY_AUDIT_2026-10-24.md)
- [CP-0404 profile dispatch and anchored-persistence candidate](CP-0404_V04_PROFILE_RUNTIME_DISPATCH_PERSISTENCE_CANDIDATE_2026-10-24.md)
- [CP-0405 QZBE PoW/fork-choice candidate](CP-0405_QZBE_V04_POW_FORK_CHOICE_CANDIDATE_2026-10-24.md)
- [CP-0406 persistent QZBE branch-archive candidate](CP-0406_QZBE_PERSISTENT_BRANCH_ARCHIVE_CANDIDATE_2026-10-24.md)
- [CP-0407 QZBE external-CAS anchoring/recovery candidate](CP-0407_QZBE_EXTERNAL_CAS_ANCHOR_CANDIDATE_2026-10-24.md)
- [CP-0408 offline QZB4 v2/QZBE smoke runner](CP-0408_QZBE_OFFLINE_CANDIDATE_SMOKE_RUNNER_2026-10-24.md)
- [G0 public-launch and compliance checklist](CP_0372_G0_PUBLIC_LAUNCH_COMPLIANCE_CHECKLIST_2026-10-22.md)
- [Owner directive: zero-budget launch and real liquidity](OWNER_DIRECTIVE_ZERO_BUDGET_LAUNCH_AND_LIQUIDITY_GATE_V01_2026-10-21.md)

This roadmap records the work and evidence needed to reach a launch decision. It does not represent an approval, promise a date, or replace independent technical, legal or operational qualification.
