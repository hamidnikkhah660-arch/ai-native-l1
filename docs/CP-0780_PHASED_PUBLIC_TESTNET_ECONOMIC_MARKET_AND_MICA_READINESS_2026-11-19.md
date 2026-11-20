# CP-0780 — Phased Public Testnet, Economic/Market Readiness and MiCA Workstream
Date: 2026-11-19
Project: AI_NATIVE_L1 / QRun / QZXB / QFP6
Worktree: D:\Temp\ASUS\QRUN_QFP6_UNIFIED_20261118
Branch: integration/qfp6-unified-20261118
Base HEAD at start: 90dc6eb29a848e1bc8e0bbadc116db019cee541e
Tag at start: CP-0779-UNIFIED-PUBLIC-DOCS-CHECKSUMS

## 1. Purpose and operating decision
The owner approved two parallel tracks:
1. zero-value Public Testnet and independent node hosting;
2. economic, native-market and platform-readiness work, with legal/regulatory preparation before any public offer, real-value trading, custody or exchange operation.

The laptop and mobile hotspot are not to be treated as permanent network infrastructure. The old CP-0596 process PID 20244 and TCP 30333 are explicitly preserved; this checkpoint does not stop, restart, replace or reconfigure them. No Genesis, Q6GA signature, Gate 2 test or Gate 8 test is regenerated or repeated.

This checkpoint records engineering and readiness work. It does not claim a public Testnet is live, a production coin is issued or transferable, a market is open, or any license/listing is granted.

## 2. Current unified candidate and Genesis authorization
Verified at the start of this checkpoint:
- HEAD: 90dc6eb29a848e1bc8e0bbadc116db019cee541e
- Tag: CP-0779-UNIFIED-PUBLIC-DOCS-CHECKSUMS
- Branch: integration/qfp6-unified-20261118
- Working tree was clean before this checkpoint's changes.
- PR #198 is open against main; no submitted review was present at inspection.
- CP-0778 attaches the exact CP-0651 Genesis snapshot, Q6GD, Q6CP, Q6PN and owner-signed Q6GA v2 authorization. Component hashes are recorded in CP-0778 and the package manifest.
- Q6GA v2 scope is ZERO_VALUE_PUBLIC_TESTNET_ONLY. It is not Mainnet, real-value transfer, public mining reward, listing or market authorization.

Package validator remains INCOMPLETE (exit 2) for expected network integration reasons:
- bootstrap-peers.json is the empty array [];
- bootstrap_peer_count=0;
- outbound peer sync and Q6AR address-book discovery are disabled in the candidate profile;
- no approved public Seed endpoint / operator receipt / attached peer-pin set is bound to this exact unified package;
- inbound peer identity and public discovery are not qualified by the attached release config;
- public_testnet_launch_ready=false and public_seed_endpoint_attested=false.

The previously recorded Seed Noise public identity fingerprint is:
9407504ce70ddf91478a82143195fffa6fd3375c52c0776ef223dff1a559ec48
CP-0686 records that its public key was derived from the existing Windows DPAPI-protected Seed key and matched in a local pinned Noise test. This is a local public-key identity record, not proof of a currently reachable public server or a stable public IP. The private key remains protected locally and is not included in this repository package.

## 3. Phase 1 — independent zero-value Public Testnet
Target topology:
- one or more stable, publicly reachable Seed endpoints hosted independently of the owner's laptop/hotspot;
- Joining/full nodes with distinct protected Noise identities and exact Seed public-key pins;
- public peer configuration bound to the frozen Q6PN and exact release build;
- authenticated peer admission and outbound history sync enabled only through reviewed, pinned configuration;
- public RPC / wallet / explorer / indexer / monitoring exposed through separately hardened interfaces, never by exposing loopback-only control endpoints;
- incident, restart, catch-up, backup, key-rotation and maintenance procedures published for users.

Current disposition:
- local Seed Noise identity exists and has an earlier loopback pin verification;
- no stable public Seed endpoint is attached to the unified package;
- bootstrap set is empty;
- no actual external inbound TCP qualification is evidenced for the current candidate;
- the current laptop receives internet through mobile hotspot/NAT; its observed public egress address and transient IPv6 address are not approved stable Seed endpoints;
- NetBird on the owner's laptop currently reports NeedsLogin; earlier private-overlay evidence is retained only for its recorded scope;
- the old process PID 20244 / TCP 30333 is untouched and remains the old CP-0596 binary, not this unified release;
- no independent public node is currently demonstrated by the current unified package.

Zero-budget hosting plan:
- prefer a genuinely independent volunteer/operator host or an already-available owner-controlled free-tier host only after checking provider eligibility, persistent storage, stable public routing, inbound firewall, protected local Linux key custody (systemd-creds/TPM where available), resource limits and recovery;
- do not copy Windows DPAPI key files to Linux;
- do not buy a VPS, enter payment-card details, create a paid cloud commitment or change the owner's budget without explicit approval;
- do not call two VMs under one account/operator an independently administered operator set;
- if no stable public host is presently available, keep the candidate package prepared and state NOT LAUNCHED rather than opening an untrusted or temporary hotspot listener.

No VPS account, DNS record, router/firewall rule, public endpoint or external cloud resource was created or changed in this checkpoint.

## 4. Phase 2 — economics, miner policy and native market
Active monetary policy is CP-0651:
- maximum gross accounting ceiling: 7,000,000,000 QZXB;
- owner Genesis allocation: 1,000,000,000 QZXB;
- six 1,000,000,000-QZXB accounting ceilings: community airdrop; exchange/market/liquidity partnerships; marketing partners; developers/security contributors; financial/strategic supporters; protocol burn reserve;
- the six labels are not Genesis balances, issued/spendable coins or automatic mint authority;
- block subsidy / mining issuance is exactly zero at every height;
- producers receive canonical transaction fees only, paid from existing balances.

The historical 3B mining allocation and 10B policy are superseded historical design, not active rewards. Public mining reward authorization is false. Under CP-0651, miners/producers may only receive canonical transaction fees; no 3B subsidy pool may be advertised or paid without a separately versioned, reviewed and authorized monetary-policy change.

Existing native market engineering to preserve:
- canonical candidate state includes native asset registry, AMM and OrderBook state;
- Q6MO/Q6MA defines bounded signed market-operation submission;
- Q6MM persists accepted market operations before returning Q6MA Accepted;
- shared account nonce ordering coordinates Q6TI transfers and Q6MO market operations;
- deterministic combined candidate construction, canonical inclusion and journal reconciliation exist in the candidate path;
- CP-0673 records integration through the combined Noise listener worker-pool and supervisor callback, plus local persistence/reopen/canonical-inclusion tests;
- Q6QA/Q6TS authorization logic exists in the candidate runtime and fails closed without exact quote-asset trust configuration.

Limitations before a genuine public market:
- these records are local engineering/loopback evidence, not an internet-facing public trading service;
- a native public RPC/order API, production wallet order-entry UI, market-data indexer and explorer are not qualified as a combined live user service;
- Q6QA test fixtures (for example TQ6A) are not USDT and do not provide reserves, bridge backing, redemption or liquidity;
- no live QZXB/USDT quote asset, reserve, bridge, market maker, counterparties, exchange pair, liquidity pool, executable depth, public price or trading volume is established;
- no exchange listing or data-platform acceptance is claimed.

Phase 2 execution order:
1. preserve and qualify the existing Q6MO/Q6MM, AMM and OrderBook canonical code on the exact release branch;
2. connect user-facing wallet order entry and read APIs to authenticated, rate-limited public RPC through a separate hardened gateway;
3. finish explorer/indexer and publish deterministic supply, transaction and market telemetry with network/build provenance;
4. define any quote asset separately: legal issuer/identity, canonical asset registration, permission authority, custody/redemption or bridge model, reserve evidence, risk disclosures and independent review;
5. only after those steps, arrange genuine counterparties and real liquidity; never fabricate trades, candles, holders, price or volume;
6. pursue platform applications only when their technical and market prerequisites are genuinely met.

## 5. Regulatory / licensing readiness — EU and Poland
This is a technical readiness memo, not legal advice and not a legal classification opinion. The exact legal entity, place of establishment, offer structure, user jurisdictions, token rights and services to be operated are not specified in the repository. Counsel must determine whether QZXB is a crypto-asset other than an ART/EMT, whether any exemption applies, who is the offeror/person seeking admission, and whether any activity constitutes a regulated crypto-asset service.

Verified public-source position on 2026-11-19:
- ESMA states that the MiCA transitional period across the EU expired on 1 July 2026; entities providing crypto-asset services to EU clients without a MiCA authorization must cease those services. The statement says this applies irrespective of whether MiCA has been implemented nationally.
- The official Polish Sejm legislative record shows the Polish Crypto-Asset Market Act was vetoed on 11 June 2026 and the Sejm did not re-enact it on 4 September 2026.
- KNF's official communication states that, due to the lack of an effective Polish MiCA implementing act, no Polish public authority had yet been designated as the competent authority for MiCA activities other than e-money-token issuer supervision; a Polish domestic CASP authorisation process cannot be initiated until a competent authority is designated.
- The Polish Tax Administration's official notice states that entry in the old Polish virtual-currency register is not MiCA authorization and does not entitle an entity to conduct MiCA-regulated virtual-currency activity after 1 July 2026.
- KNF's official position also notes that cross-border provision into Poland under a valid MiCA authorisation from another EU Member State may remain possible. This route requires specialist counsel confirmation of entity, authorisation scope, passporting and actual services; it is not assumed here.

For a person offering a crypto-asset other than an ART/EMT to the public in the EU, MiCA Article 4 generally requires a legal person, a compliant crypto-asset white paper, notification and publication, compliant marketing communications where applicable, and Article 14 obligations, subject to the Regulation's specific exemptions. Article 5 sets related requirements for a person seeking admission to trading. Article 8 requires notification to the home Member State competent authority at least 20 working days before publication and explanation why the asset is not excluded/ART/EMT. A white paper notification is not the same as a CASP operating licence and is not represented as prior regulatory approval.

Licensing work to prepare (not file yet):
- freeze the legal entity/offeror and the intended role: protocol developer, issuer/offeror, person seeking admission to trading, CASP, or none of these;
- document rights, purpose, supply, Genesis allocation, six accounting ceilings, zero block subsidy, transaction fees, governance, upgrade powers, custody and conflicts;
- prepare a MiCA Article 6 white-paper evidence set: project/person information; offer/admission details; token rights and obligations; technology; risks; consensus/environment indicators; fair, clear and non-misleading disclosures; machine-readable version;
- determine Article 4/5 exemption applicability and the correct home competent authority with counsel;
- separately assess CASP authorisation only if the project/entity will provide regulated services such as custody, exchange, execution, placing, transfer or operation of a trading platform;
- prepare AML/CFT, sanctions, governance, complaints, incident response, ICT/security, outsourcing, business continuity, conflicts and recordkeeping documentation only to the extent the chosen service/activity requires it;
- distinguish issuer/offeror responsibilities from the separate authorisation and due diligence of exchanges, market makers, custodians and fiat/payment providers;
- do not submit an application, make an offer, accept customer funds, custody assets, operate an exchange or promise a listing on the strength of this engineering checkpoint.

## 6. CI failure correction discovered in this session
GitHub PR #198 head 90dc6eb29a848e1bc8e0bbadc116db019cee541e had a Linux all-target test failure in devnet_trust_provisioner because one dual-attestation rotation test calls the Windows CurrentUser DPAPI protected-key provider. The test is Windows-specific; the Linux job correctly cannot satisfy that OS facility.

Local narrow fix applied:
- add cfg(windows) to rotate_peer_command_requires_dual_attestation_before_writing_npi1;
- add a dedicated Windows CI step to run cargo test --bin devnet_trust_provisioner --locked -- --test-threads=1 in the Windows job.

Verification actually run on the Windows owner workstation:
- cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check: PASS;
- cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_trust_provisioner --locked --offline -- --test-threads=1: 6 passed, 0 failed, exit 0;
- git diff --check: PASS.

The two-file CI fix is local and uncommitted at the time this checkpoint was drafted. It has not yet been pushed; a new GitHub CI run is therefore pending. The Linux all-target job and Windows targeted DPAPI test need to be observed on the same new commit before claiming CI green.

## 7. Gate and launch status
- Gate 2: OWNER-REPORTED COMPLETE / NOT RETESTED per explicit owner instruction; prior loopback and private-overlay records retain only their recorded scope. This checkpoint adds no claim of new Gate 2 verification.
- Gate 8: OWNER-REPORTED COMPLETE / NOT RETESTED per explicit owner instruction; CP-0774/QAR2/QBT1 documents and the unified manifest still need an exact package-level receipt reconciliation if they are to be claimed in a public release.
- Public zero-value Testnet: NOT LAUNCHED; bootstrap peers empty and no approved stable public Seed endpoint / peer set attached.
- Native value-bearing Mainnet and transfers: NOT AUTHORIZED.
- Public mining rewards: NOT AUTHORIZED; active CP-0651 subsidy is zero.
- Public native market / QZXB/USDT: NOT ESTABLISHED.
- CEX listing / CMC / CoinGecko / DEX Screener / TradingView: NOT APPLIED / NOT LISTED in this checkpoint.
- EU/Poland licensing and MiCA workstream: PREPARATION ONLY; no legal opinion, application, authorisation or filing.

## 8. Preservation
- Keep old PID 20244 and TCP 30333 untouched.
- Keep CP-0704 and CP-0596 source worktrees untouched.
- No private key, seed phrase, DPAPI plaintext, account credential or cloud credential was read or emitted.
- No Genesis or owner signature was regenerated.
- No Gate 2 or Gate 8 tests were rerun.
- No VPS/cloud service, DNS, firewall, router, VPN, exchange, market or payment account was modified.
- No funds, tokens, donations or paid services were moved or committed.
- At the time of drafting, the checkpoint had not yet been committed or pushed.

## 9. Authoritative references
- docs/CONTINUATION_HANDOFF_CURRENT.md
- docs/CP-0651_FIXED_7B_OWNER_1B_SIX_LABELS_FEE_ONLY_ECONOMICS_2026-11-14.md
- docs/CP-0658_CP0651_NATIVE_MARKET_EXECUTION_AND_TRADING_GATE_2026-11-14.md
- docs/CP-0659_Q6MO_MARKET_INGRESS_AND_DURABLE_QUEUE_2026-11-14.md
- docs/CP-0660_Q6QA_PERMISSIONLESS_RUNTIME_AUTHORIZATION_WIRING_2026-11-14.md
- docs/CP-0662_Q6QA_REAL_SIGNATURE_NOISE_ADMISSION_AND_TRUST_FILE_HARDENING_2026-11-14.md
- docs/CP-0673_Q6MO_PRODUCTION_LISTENER_INTEGRATION_AND_RELEASE_BUILD_2026-11-15.md
- docs/CP-0775_TWO_PROCESS_PMT4_PFM4_TXN4_MTA4_REORG_QUALIFICATION_2026-11-18.md
- docs/CP-0777_UNIFIED_SOURCE_AND_RELEASE_ARTIFACT_RECONCILIATION_2026-11-18.md
- docs/CP-0778_PUBLIC_TESTNET_ARTIFACT_RECONCILIATION_2026-11-19.md
- ESMA MiCA transitional-period statement: https://www.esma.europa.eu/sites/default/files/2026-04/ESMA75-113276571-1679_Statement_on_the_end_of_transitional_periods_under_MiCA.pdf
- KNF Poland MiCA status: https://www.knf.gov.pl/komunikacja/komunikaty?articleId=98874&p_id=18&page=11
- Polish Sejm legislative record: https://www.sejm.gov.pl/sejm10.nsf/PrzebiegProc.xsp?id=EDA6BC16C7D3E24AC1258DF1003CA0B8
- Polish Tax Administration notice on the old virtual-currency register: https://www.gov.pl/web/ias-katowice/informacja-dla-klientow-podmiotow-wpisanych-do-rejestru-dzialalnosci-z-zakresu-walut-wirtualnych
- MiCA Regulation (EU) 2023/1114: https://eur-lex.europa.eu/eli/reg/2023/1114/oj/eng

Final disposition: the two-phase programme is prepared and locally advanced; zero-value Public Testnet is not live until the approved public host/endpoint, pinned peer set and exact runtime package are connected and independently reviewed. Economic/market and regulatory preparation can progress without pretending that QZXB is already publicly tradable or licensed.


## 10. Follow-up focused market regressions on the unified candidate
Commands run on the unified CP-0779 source tree with locked offline dependencies:
- qrun_v06_market_ingress_candidate: 7 passed, 0 failed.
- qrun_v06_market_journal_candidate: 3 passed, 0 failed.
- qrun_v06_permissionless_service_candidate::tests::q6mo_is_durably_accepted_restored_mined_and_pruned_only_after_canonical_commit: 1 passed, 0 failed.
- qrun_v06_canonical_execution_candidate::tests::cp0651_native_quote_orderbook_match_preserves_supply_and_snapshot: 1 passed, 0 failed.

The Q6MO service test exercises a local authenticated Noise listener session, durable journal acceptance, service reopen/restore, canonical block inclusion and pruning after canonical commit. It remains loopback candidate evidence and does not establish an Internet-facing public market, independent operator operation, real quote-asset backing or a value-bearing trade.

The combined test total for these four focused invocations is 12 passed, 0 failed. The separate mempool-module filter matched zero tests and is not counted. No Gate 2 or Gate 8 test was rerun.
