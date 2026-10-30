# CP-0466 — Zero-Budget Route to Genuine QZXB Liquidity
Date: 2026-10-29

Status: **Action plan prepared; no pool, sale, market, or funding is claimed.**

## The decision in plain language

Real liquidity cannot be created from a number in a wallet or from a large token supply. An actual market needs someone to bring the quote asset (USDC/USDT/ETH) and accept the other side of a trade. With no founder cash, the realistic sources are: (1) real buyers funding a transparent token sale/auction, (2) an external market-maker/LP partner, or (3) a grant/sponsor that pays defined engineering milestones. These are different mechanisms and none is guaranteed.

**Do not deploy a second token with the name/ticker QZXB and call it the native QRun coin.** The 10B QZXB Genesis balance belongs to the candidate native ledger. It cannot be deposited into an EVM pool until a production chain and a sound, independently reviewed transfer/bridge path exist. The existing Sepolia QX token is a different test asset.

## Candidate paths

### Path A — preserve native QZXB identity (preferred for the native coin)

1. Keep the value-bearing `--mainnet` gate closed while consensus, history/recovery, independent operator, security and release criteria remain open.
2. Recruit at least two additional independent node operators. Exchange the Network ID, Genesis/profile hashes and Noise static public keys over an authenticated, out-of-band channel. Test multi-host sync, restart/reorg/partition recovery and independently verified transactions.
3. Publish an independently reproducible binary/source hash, node guide, wallet instructions, read-only explorer/indexer and recovery/contact policy.
4. Once value-bearing release criteria pass, pursue market counterparties. A direct OTC trade can use native QZXB, but swapping it for USDT still needs a trusted escrow/settlement design because USD₮ is not issued natively on QRun.
5. For a DEX pair, design and independently audit a bridge/custody model that escrows native QZXB and mints/burns a matching representation. Do not claim 1:1 backing before deposits, reserves, proof, keys, redemption and failure procedures are independently verifiable.

**Current status:** blocked at steps 1–3; no native QZXB/USDT pool exists.

### Path B — buyer-funded DEX launch without founder-funded LP (not native QZXB)

Uniswap's Continuous Clearing Auction (CCA) can sell an EVM token to bidders and route auction proceeds into starting Uniswap v4 liquidity. This avoids requiring the founder to personally provide both sides of the initial LP deposit, because participants provide the raise currency. It does **not** create money from nothing: bids must arrive, contract transactions cost gas, and a sale can fail to raise demand. The current Uniswap launch flow documents ETH or USDC as auction currencies. References: [CCA overview](https://developers.uniswap.org/docs/liquidity/liquidity-launchpad/overview), [launching a CCA](https://support.uniswap.org/hc/en-us/articles/46569604134157-Launching-a-Continuous-Clearing-Auction).

This path would create an **EVM token**, not the native QZXB coin. It must not be marketed as native QZXB or as redeemable/wrapped QZXB without an implemented, reviewed bridge and real backing. It must not be started until the project explicitly chooses that separate asset identity, verifies current contract/network parameters, completes an appropriate legal review, and has a wallet with enough gas for the launch transaction. In the EU, a public token offer/admission can trigger MiCA white-paper, notification, publication and offeror requirements, subject to statutory exceptions; obtain jurisdiction-specific advice before offering/selling anything. See [MiCA Article 4](https://www.esma.europa.eu/publications-and-data/interactive-single-rulebook/mica/article-4-offers-to-public-crypto-assets-other) and [Article 5](https://www.esma.europa.eu/publications-and-data/interactive-single-rulebook/mica/article-5-admission-trading-crypto-assets).

**Decision today:** do not deploy this EVM asset by assumption. It is an alternative that would require explicit approval and clear public separation from native QZXB.

### Path C — zero-budget first funding (start now; does not itself create coin liquidity)

Use current code and evidence to win a paid engineering milestone or voluntary infrastructure contribution:
- Rust protocol/replay/recovery testing and reproducible build engineering.
- ML/AI prototype or evaluation pipeline with deliverable and acceptance tests.
- Sponsored independent review of Genesis/issuance invariants.
- Independent operator/hosting contribution for public zero-value devnet.

Payment must be for a defined deliverable with written terms; QZXB allocations are not cash. The public sponsor/contract pitch must state what is already implemented, what remains candidate-only, the exact milestone acceptance criteria, and that no token investment/return or future listing is promised.

Existing support routes in the README may be used only after checking live eligibility and payout rules. Donation platforms are not a route to personal investment proceeds and must not be offered in exchange for tokens or promised returns.

## First seven executable actions

- [x] Restore Windows Firewall profiles and verify all three enabled.
- [x] Add one narrow Windows inbound rule for the QRun candidate executable on TCP 49341 only, Public profile. Verified rule: `QRun Public Alpha P2P TCP 49341 (application-scoped)`.
- [ ] Test TCP reachability from a genuinely external network only after an independent seed/operator and its pinned public key are ready. A local listener or Windows rule is not proof of Internet reachability.
- [ ] Recruit two independent operators and publish network identity, exact source SHA/build hash and onboarding instructions.
- [ ] Prepare a milestone-based paid engineering proposal and ask potential sponsors for either cash funding or clearly scoped hosting/review work; do not claim a sponsor until one confirms.
- [ ] Complete technical/legal decision on whether native QZXB should remain native-only until audited bridge readiness, or whether to propose a separately named EVM asset. No duplicate QZXB ticker is to be launched silently.
- [ ] After the selected, compliant path and required funding exist, run a transparent market launch with real counterparties and publish verified transaction/pool links, token contracts, reserves, ownership/lock details, fees, and risks.

## Outreach copy — independent node / technical sponsor

> **QRun Blockchain (QZXB) — independent operator and engineering sponsor request**
>
> QRun is an open-source Rust Layer-1 research project targeting a fixed-supply, fee-only native asset. The current node is an experimental public-alpha candidate, not a launched value-bearing Mainnet, and native QZXB/USDT liquidity does not yet exist. Local Rust all-target tests have passed, but independent protocol/security review and production-history recovery are still open.
>
> We are seeking (1) independent operators to test sync, restart/reorg recovery and cross-node state-root agreement, and (2) sponsors/clients for a specific funded milestone in Rust protocol engineering, deterministic state/replay validation, reproducible builds or AI/ML engineering. Contributions can be code, review or hosting with a written scope and acceptance checklist.
>
> No exchange listing, future price, token return, or sponsor acceptance is promised. Source and current evidence: https://github.com/hamidnikkhah660-arch/ai-native-l1
>
> Contact: hamidnikkhah660@gmail.com

## What counts as proof of real liquidity

All of the following must be published from the actual market/network: authentic token/quote-asset addresses, chain ID, pool/auction contract, successful independent buy and sell transactions, reserve balances, trade sizes, timestamp and source links. Report price impact and spread; distinguish FDV from circulating market cap. A pool page without reserves or an initial price without completed trades is not proof of meaningful liquidity. Never wash-trade, fabricate candles/volume, self-issue “USDT”, or promise a future price.

## Acceptance gates

- Native Mainnet: **OPEN / NO-GO** until CP-0465's exit criteria have evidence.
- Independent public P2P reachability: **NOT VERIFIED**; host firewall rule is only local configuration.
- Native QZXB/USDT market: **NOT LIVE**; no real reserves or pair verified.
- Buyer-funded CCA option: **NOT AUTHORIZED / NOT DEPLOYED**; it would be a separate EVM asset, require launch gas, real bidders and legal review.
- First paid engineering milestone: **OPEN**; a pitch is not a contract or revenue.
