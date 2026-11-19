# QFP6 Unified Integration Handoff â€” 2026-11-18

## Purpose and source preservation

This is the isolated integration worktree combining the latest CP-0704 dual-attestation/Q6TS work with the CP-0596 QFP6 runtime, wallet, PMT4/PFM4 and market-ingress work. The original worktrees remain untouched:

- CP-0704 source: QRUN_CP0704_DUAL_ATTESTATION_20261116, base 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
- CP-0596 source: QRUN_QFP6_CP0596_20261111
- Unified branch: integration/qfp6-unified-20261118
- Unified worktree: QRUN_QFP6_UNIFIED_20261118

All tracked diffs were imported with three-way application. Untracked source and documentation were copied into the unified worktree without overwriting existing files. The colliding CP-0596 verifier was preserved under a _cp0596_legacy filename. Protected identity folders, local runtime state and private key material were not copied.

## Canonical economic policy

The unified permissionless launcher is bound to the later owner-requested CP-0651 policy (CP-0650/CP-0651), superseding CP-0566D/CP-0566E for the active candidate:

- 7,000,000,000 QZXB maximum gross issuance
- 1,000,000,000 QZXB owner Genesis allocation
- block subsidy and mining issuance are exactly zero at every height
- six accounting labels of 1,000,000,000 QZXB each (6,000,000,000 total)
- six labels are accounting ceilings only, not Genesis balances, spendable accounts or automatic mint authority
- producers receive canonical transaction fees only; fees transfer existing value and do not mint. The CP-0422 mining schedule is historical under CP-0651.

CP-0566D/CP-0566E remain preserved as the prior 10B/3B-mining policy; CP-0651 is the later owner-requested and active 7B/fee-only policy. The CP-0651 permissionless Genesis gate accepts only the version-7 CP-0651 fixed-supply snapshot with matching owner and policy fingerprint; CP-0528 and CP-0604 Genesis are rejected.

## Integration changes

- Combined CP-0596 QFP6 node/runtime and wallet/market modules with CP-0704 identity rotation and QAR2/QBT1/Q6TS anchor work.
- Resolved permissionless launcher integration while retaining CP-0704 QAR2/QBT1 trust components and binding Genesis admission to CP-0651.
- Preserved CP-0528 and CP-0604 as historical compatibility paths; the permissionless launcher accepts only CP-0651.
- Merged the current origin/main CP-0651 public documentation into the unified branch (local merge commit 419b9376d956ccc6a0082d1c628b9e975ce562bc); newer CP-0651 public-economics and Q6GA v2 wording is retained.
- CP-0778 attaches the exact existing CP-0651 Genesis snapshot, Q6GD, Q6CP, Q6PN, bootstrap-peers file and owner-signed Q6GA v2 Public Testnet authorization to release/qfp6-candidate/artifacts/. No artifact bytes were regenerated.
- The old local-only Q6GA v1 approval, DPAPI protected Noise credentials, runtime databases and local anchor-vault state were deliberately not copied.
- Candidate manifest now records exact artifact hashes, Q6GA v2 scope/bindings, and the public-network readiness boundary. The package validator checks Q6GA v2 envelope structure and exact artifact/founder-key bindings; it does not itself cryptographically verify signatures.
- The five required component files are present and hash-verified. bootstrap-peers.json is present but contains an empty array; public outbound sync and Q6AR address-book discovery are disabled in the existing seed config. This is not a connected multi-peer network.

## Validation observed on 2026-11-19

- CP-0777 Release build and test evidence remains unchanged; no full Rust suite was rerun for this artifact/documentation-only CP-0778 change.
- python tools/qfp6_candidate_package.py self-test: PASS, exit 0.
- python tools/qfp6_candidate_package.py validate release/qfp6-candidate: exit 2 / INCOMPLETE as intended. It reports all five component hashes verified, Q6GA v2 structure and exact artifact/founder-key bindings valid, and the four current network-readiness blockers: public Testnet launch not ready, public peer discovery not qualified in this package, inbound peer identity not authenticated in the current config, and no public Seed endpoint attached.
- Candidate manifest JSON parse: PASS. git diff --check: PASS.
- Artifact hashes and sizes are recorded in docs/CP-0778_PUBLIC_TESTNET_ARTIFACT_RECONCILIATION_2026-11-19.md.

## Runtime and release boundary

The pre-existing local process PID 20244 on port 30333 was not stopped, replaced, or reconfigured. It still runs the older CP-0596 binary with public-testnet-seed-config-runtime.json and config digest 679088482f3204605f5e4208076b89851d84a3dfb335af9d37709f01bf95a3c3. This live process is not the CP-0777 unified build. Its current package has an empty bootstrap peer list, outbound peer sync disabled and anonymous Noise XX ingress. A public listener alone does not prove that independent peers are connected or authenticated.

The owner reports Gate 2 and Gate 8 completed in prior sessions and explicitly instructs that these qualifications must not be repeated. This handoff treats both as owner-reported complete and does not schedule re-tests. Their existing external receipts and the independently operated Seed endpoint/Noise pin records are not yet attached to this unified release package. The next work is artifact/endpoint reconciliation and runtime binding, not repeating Gate 2 or Gate 8.

The Q6GA v2 authorization is a separate owner-signed authorization for ZERO_VALUE_PUBLIC_TESTNET_ONLY. It is not Mainnet authorization, not permission for real-value transfers, and not a market authorization. It binds the exact Genesis snapshot, Q6GD, Q6CP and Q6PN hashes plus CP-0651 economics. Its bootstrap-peer hash field is zero by protocol design; peer endpoints and Noise pins are handled by the network profile/bootstrap configuration.

No production keys were read or rotated. No external AWS/NetBird services were changed. No public listener was enabled or disabled by this CP-0778 operation. No Genesis was promoted, and no exchange/market listing or liquidity action was initiated.

## Next safe actions

1. Attach the already-qualified independent Seed endpoint(s), operator identity/attestation and Noise public-key fingerprints from the existing external records. Do not rerun Gate 2 or Gate 8.
2. Reconcile the peer pins with Q6PN/Q6AR and the exact CP-0651 profile. If Q6PN changes, the existing Q6GA v2 signature must be renewed locally over the new exact hash; never export wallet secrets or request them in chat.
3. Generate a new unified seed/joining runtime config with authenticated peer admission, approved outbound sync and address-book settings, while keeping the old PID 20244 and port 30333 untouched until a controlled replacement plan is approved.
4. Run the candidate validator and focused disposable-config preflight on the unified build, then submit the exact CP-0778 candidate for independent code review and protected-branch approval.
5. After the existing qualification receipts are attached and the candidate runtime is bound to the approved peer set, activate only the zero-value Public Testnet scope. Mainnet, real-value transfer, public mining rewards and market activity remain unauthorized.

This handoff records a unified candidate and attached owner-authorized zero-value Testnet Genesis inputs, not a claim that the multi-peer Public Testnet is already live or that Mainnet/trading is ready.


## CP-0780 â€” phased Testnet, economy/market and MiCA readiness update (2026-11-19)
See: docs/CP-0780_PHASED_PUBLIC_TESTNET_ECONOMIC_MARKET_AND_MICA_READINESS_2026-11-19.md

Owner-approved programme:
- Phase 1: zero-value Public Testnet on independent stable public hosting; owner's laptop/hotspot is auxiliary only.
- Phase 2: native market/UI/RPC/explorer completion, authentic liquidity preparation, platform readiness and legal classification/licensing preparation.
- Owner budget remains USD 0 new spend unless explicitly changed. No cloud/VPS/payment commitment was made.

Preserved state:
- Unified baseline remains CP-0779 / 90dc6eb29a848e1bc8e0bbadc116db019cee541e before this checkpoint's local edits.
- Existing PID 20244 and TCP 30333 were not stopped, restarted, replaced or reconfigured.
- The previously provisioned Seed public Noise fingerprint remains 9407504ce70ddf91478a82143195fffa6fd3375c52c0776ef223dff1a559ec48; this is the local identity pin, not proof of a current stable public endpoint.
- Public bootstrap list remains empty; public_seed_endpoint_attested=false; public_testnet_launch_ready=false.
- Q6MO/Q6MA/Q6MM, AMM and OrderBook implementation evidence exists in CP-0659/0660/0662/0673; user-facing public order RPC/wallet, indexer/explorer and a real quote asset/liquidity market remain separate work.
- Active CP-0651 economics remain 7B gross accounting ceiling, 1B owner Genesis allocation, six non-circulating 1B accounting labels, zero block subsidy and fee-only producer compensation. The old 3B mining subsidy is superseded; public mining rewards are not authorized.

CI correction staged locally:
- PR #198 baseline CI failed on Linux because one test in devnet_trust_provisioner requires Windows CurrentUser DPAPI.
- Added cfg(windows) to the DPAPI-specific rotation test and added a dedicated Windows CI step.
- Local Windows formatter check passed and devnet_trust_provisioner test passed 6/6 offline.
- The two-file change is not yet committed/pushed; new PR CI has not run. Do not report CI green until the pushed commit's Linux and Windows jobs pass.

Regulatory readiness:
- Prepared technical MiCA/Poland workstream only; no legal opinion, application, licence or offer has been made.
- See CP-0780 for current official ESMA/KNF/Sejm/Polish Tax Administration references and required legal work.
- The 1 July 2026 MiCA transition deadline has passed; do not treat the old Polish virtual-currency register as MiCA authorization. No Polish non-EMT CASP application route should be assumed before a competent authority is designated. Cross-border use of a properly authorised EU CASP requires counsel confirmation.

No Gate 2 or Gate 8 tests were repeated. They remain owner-reported complete for tracking; no new independent verification is claimed in this checkpoint.


Focused Phase 2 regressions run on the unified candidate (not Gate 2/8):
- Q6MO ingress protocol: 7/7 PASS.
- Q6MM journal: 3/3 PASS.
- Q6MO durable listener/service lifecycle through canonical block commit: 1/1 PASS.
- CP-0651 native OrderBook supply/snapshot regression: 1/1 PASS.
- Combined: 12 passed / 0 failed. All are local candidate tests; the Q6MO end-to-end lifecycle uses a local Noise session and does not establish a public market or independent Internet deployment.

## CP-0784 - canonical monetary read API (2026-11-19)

Current continuation point:
- Branch: `feat/q6ga-v3-mainnet-scope-20261119`.
- Worktree: `D:\Temp\ASUS\QRUN_QFP6_UNIFIED_20261118`.
- Base: CP-0783 commit `373ed0b449bade4297358136c59df58db33343ee`.
- Checkpoint document: `docs/CP-0784_PUBLICLY_VERIFIABLE_MONETARY_READ_API_2026-11-19.md`.

Implemented:
- Runtime-owned canonical account read with height/tip/state-root consistency checks.
- Canonical CP-0651 supply read; actual ledger total is separate from accounting-label budgets.
- Optional GET-only `/v1/status`, `/v1/account/{id}` and `/v1/supply` HTTP routes on a separate listener, serviced in the runtime-owning supervisor loop.
- Read API disabled by default. Non-loopback bind requires Mainnet mode plus `allow_public_read_api=true`; address must not alias P2P or a pinned outbound peer.
- Account responses expose the global state root but explicitly do not claim an account inclusion proof.
- Atom amounts and large counters are decimal strings in JSON to avoid JavaScript precision loss.

Validation:
- CP-0651 canonical account/supply/HTTP/restart test: 1/1 PASS.
- QFP6 supervisor regression module: 19/19 PASS.
- `cargo check --bin qrun_v06_node --locked --offline`: PASS.
- `cargo fmt --check` and `git diff --check`: PASS.

Important boundaries:
- No listener was activated; no public endpoint or network launch is claimed.
- No new Q6GA signature was produced. Because read API settings change the configuration bytes covered by Q6GA v3, any such settings in the Mainnet package require a fresh local QZKW2 approval over the exact new config digest. CP-0783 must not be reused for changed config bytes.
- Transaction/block API, Merkle account proofs and independent second-node cross-check remain outstanding.
- Gate 2 and Gate 8 were not re-tested or reclassified.
- PID 20244 / TCP 30333 and its data remain untouched; no private wallet/key material was accessed.

Next: finish transaction/block receipts and independent proof path; then prepare the exact Mainnet config and obtain local owner authorization only after the bind policy and peer set are reviewed. Public bind remains opt-in.

## CP-0785 - canonical block and transaction read API (2026-11-19)

Current continuation point:
- Branch: feat/q6ga-v3-mainnet-scope-20261119.
- Base: CP-0784 / 095b61f54dce965594114f9c0a3f829d2236cdfd.
- Checkpoint: docs/CP-0785_CANONICAL_BLOCK_AND_TRANSACTION_READS_2026-11-19.md.

Implemented:
- Runtime-owned canonical block lookup from a pinned fork-choice snapshot, with QFB6 execution block ID and QFP6 consensus tip returned separately.
- Native TXN2 transaction receipt lookup from the retained, validated fork archive.
- Receipt status distinguishes canonical from reorged; confirmation depth is informational only.
- New GET-only HTTP routes /v1/block/{height} and /v1/transaction/{64-hex-transaction-id}.
- Transaction lookup is bounded to 1,024 retained envelopes / 16 MiB and explicitly does not inspect mempool. Archive-limit exhaustion fails closed.
- Genesis/checkpoint base heights do not expose a block body through the current graph API. Historical segments beyond the active retained graph are not indexed by this endpoint.
- Fixed QFP6/QFB6 hash-domain confusion in canonical account/supply reads: runtime status tip is the QFP6 consensus digest; execution state's tip_hash()/QFB6 block ID is a separate domain. Reads now compare consensus tip to fork-choice status and recompute the state root.

Validation observed:
- Expanded CP-0651 runtime/API transfer + block + receipt + reorg + restart + malformed-input test: 1/1 PASS.
- QFP6 supervisor regression module: 19/19 PASS.
- cargo check --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node --locked --offline: PASS.
- cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --check: PASS.
- git diff --check: PASS.

Preserved boundaries:
- API listener remains disabled by default; no public socket enabled.
- No account inclusion proof is claimed. Global state root still requires independent full-node replay from trusted Genesis/checkpoint inputs.
- No Mainnet package change, Q6GA digest regeneration, QZKW2 authorization/signature, or wallet access.
- No public Testnet/Mainnet launch or public endpoint is claimed.
- PID 20244 / TCP 30333 and its CP-0596 datastore remain untouched.
- Gate 2 and Gate 8 remain owner-reported complete in this continuation context; this checkpoint did not re-test or reclassify either gate.
- No private key/seed/plaintext DPAPI material was read.

Next: independent second-node cross-check of these read surfaces; then account inclusion proof or reproducible replay verification design, plus historical archive indexing if explorer history must survive checkpoint rollover. Only later, after exact config review, may a fresh manual QZKW2 authorization be requested. Public bind remains off.
