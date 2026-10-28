# QRun Public Outreach Kit — 2026-10-29

## Positioning

**QRun Blockchain (QZXB)** is an open-source, founder-led Layer-1 research and engineering project. The project explores a Rust-native ledger, proof-of-work and fee-only block-production candidates, deterministic state transitions and recovery, authenticated peer networking, a native wallet and transaction-query tooling, ML-DSA-65/hybrid-signature research, an isolated EVM/revm smart-contract lab, market-data tooling, and an AI-native application roadmap.

The source repository and website are public. The running node remains **experimental public-alpha**. Value-bearing production Mainnet, a verified public network, a public explorer, a native QZXB/USDT market, real market liquidity, project revenue, and a completed independent security audit are **not claimed**.

## What is concrete today

- A public source repository with Rust protocol and recovery research.
- Candidate PoW/fork-choice and a fee-only QRun block/store path, with candidate profile and Genesis commitments documented.
- Authenticated peer-transport components and local multi-process tests; public-alpha P2P configuration does not itself prove Internet reachability.
- A Windows QZXB native-wallet CLI and local signed-transaction tests. Candidate balances are not publicly spendable Mainnet funds.
- An ML-DSA-65 verification adapter and selected hash-pinned test vectors; full production hybrid authentication is not claimed.
- A separate EVM/revm lab and an older QX test asset on Sepolia; QX is not native QZXB.
- EVM/native market-indexing components that process actual confirmed swap logs; these components do not create a market or liquidity.
- A local all-target Rust test pass was recorded for the current experimental work branch; it is regression evidence, not an independent audit, external-host qualification, or Mainnet launch approval.

## What needs contributors

1. **Independent node operators** on separate hosts and networks to verify identity/profile agreement, synchronization, restart/recovery, and state-root convergence.
2. **Rust protocol engineers** to review consensus boundaries, Genesis/issuance rules, full-history recovery and fee-only security economics.
3. **Security and cryptography reviewers** to assess peer transport, signing, rollback assumptions, malformed-input handling and release hardening.
4. **EVM/Solidity and wallet developers** to help integrate application execution, receipts, wallets and reliable developer workflows.
5. **AI/ML engineers and researchers** to prototype measurable developer and verifiable-compute applications.
6. **Milestone sponsors or clients** for explicitly scoped engineering, independent review, or infrastructure contributions with written acceptance criteria.

## Links

- Project website: https://hamidnikkhah660-arch.github.io/ai-native-l1/
- Public source: https://github.com/hamidnikkhah660-arch/ai-native-l1
- Latest experimental source branch (not a production release): https://github.com/hamidnikkhah660-arch/ai-native-l1/tree/work/qzbe-v04-persistent-mining-20261026
- Independent operator call: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/72
- Protocol/security review call: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/73
- Sponsors and contributors: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/1
- Zero-budget liquidity and market path: https://github.com/hamidnikkhah660-arch/ai-native-l1/blob/main/docs/CP-0466_QRUN_ZERO_BUDGET_REAL_LIQUIDITY_PATH_2026-10-29.md
- Mainnet/trading release decision: https://github.com/hamidnikkhah660-arch/ai-native-l1/blob/main/docs/CP-0465_QRUN_MAINNET_PUBLIC_TRADING_NO_GO_2026-10-29.md
- Paid engineering offer: https://github.com/hamidnikkhah660-arch/ai-native-l1/blob/main/docs/ENGINEERING_SERVICE_OFFER_V01.md
- Contact: hamidnikkhah660@gmail.com

## Short social post

QRun Blockchain (QZXB) is open for contributors. We are building in public across Rust Layer-1 protocol research, PoW and fee-only block candidates, deterministic recovery, authenticated P2P, ML-DSA experiments, EVM tooling and an AI-native roadmap. Seeking independent node operators, protocol/security reviewers, Rust/EVM contributors and milestone sponsors. Experimental public-alpha; not production Mainnet. No live QZXB market is claimed.

Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/
Operator call: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/72
Source: https://github.com/hamidnikkhah660-arch/ai-native-l1

## LinkedIn / professional-network post

**QRun Blockchain: open-source Layer-1 engineering and contributor call**

After years of research and engineering, the QRun source repository and project website are open for public technical participation. The project brings together Rust-native ledger research, consensus and fee-only block-production candidates, deterministic state/recovery, authenticated peer networking, ML-DSA-65 verification experiments, a separate EVM/revm lab, market-indexing tools, and an AI-native application roadmap.

We are looking for independent node operators, Rust protocol engineers, security/cryptography reviewers, EVM developers, AI/ML researchers, and milestone sponsors. Specific contributions should have a clear scope, reproducible evidence and acceptance criteria.

Transparency matters: QRun is currently an experimental public-alpha candidate. Production Mainnet, a verified public explorer, an independent security audit and genuine native QZXB/USDT liquidity are not being represented as live. The existing QX Sepolia test asset is separate from native QZXB.

Start here:
- Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/
- Independent operators: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/72
- Protocol review: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/73
- Sponsors and contributors: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/1

## Reddit / community forum post

**Title:** Looking for independent reviewers and node operators for an open-source Rust Layer-1 research project

**Body:**

I am opening QRun Blockchain (QZXB) to more independent technical participation. The public repo contains a Rust-native ledger, consensus and fee-only block/store candidates, deterministic recovery research, authenticated peer transport, wallet/transaction tooling, ML-DSA verification experiments, an EVM/revm lab, and market-indexing components.

I am looking for technically experienced people to reproduce tests on separate hosts, review consensus/recovery/security assumptions, and help shape the next public zero-value Devnet. Contributions should be measurable and independently reproducible.

Important limitations: the node is experimental public-alpha, not production Mainnet. A local Genesis balance is not publicly spendable; there is no verified native QZXB/USDT pool, public price or completed independent security audit. I am not asking anyone to buy tokens, send funds, or share wallet credentials.

Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/
Operator issue: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/72
Review issue: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/73

Please post to a community only after checking its rules and adapting the content to the community's purpose. Avoid repeated cross-posts, unsolicited DMs or requests for votes.

## DEV Community / technical blog draft

**Title:** Building a Layer-1 in the Open: What QRun Has and What Still Needs Independent Proof

I have made the QRun Blockchain (QZXB) source and project site public and am looking for more independent technical participation.

The project is a Rust-first Layer-1 research programme. Its source includes proof-of-work and fee-only block-production candidates, deterministic state and recovery components, authenticated peer networking, wallet and transaction-query tools, ML-DSA-65 verification research, an isolated EVM/revm lab, and market-data components that consume actual swap events rather than fabricating prices.

One lesson from this work is that a passing local test is not the same as a live public network. A process binding to an all-interface port does not prove that a router or ISP allows inbound traffic. A local Genesis balance is not a publicly transferable balance. A market indexer is not a market, and a token with a familiar ticker is not an authentic quote asset. Those distinctions are reflected in the release documents.

QRun's current node is experimental public-alpha. Production Mainnet, external multi-operator convergence, an independent protocol/security review, a public explorer, and genuine QZXB/USDT liquidity are not claimed as live. The selected candidate economic direction is 10 billion QZXB at Genesis, all assigned to the owner, with no further minting and no block subsidy; this is a candidate protocol direction, not proof that public funds are available. Fee-only block production needs explicit analysis of incentives and security economics.

I would welcome contributions from Rust protocol engineers, independent operators, security/cryptography reviewers, EVM developers, and AI/ML researchers. The highest-value next steps are independent multi-host tests for network identity, synchronization, restart/recovery and matching state roots; reproducible builds; and review of consensus and rollback assumptions.

Project: https://hamidnikkhah660-arch.github.io/ai-native-l1/
Source: https://github.com/hamidnikkhah660-arch/ai-native-l1
Operator onboarding: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/72
Independent protocol review: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/73

This is an invitation to reproduce, critique and improve an open-source engineering project, not an investment offer. No price, listing, token return, or liquidity is promised.

**Suggested tags:** rust, blockchain, opensource, contributorswanted.

## Hacker News submission preparation

Hacker News explicitly expects the author to submit and discuss their own work. Automated posting is inappropriate. A Show HN should be used only when people can genuinely try the project, rather than merely view a landing page or fundraiser. If that threshold is met, write the final submission personally and remain available to answer technical questions. Suggested factual title:

**Show HN: QRun, an open-source Rust Layer-1 research project**

Link: https://github.com/hamidnikkhah660-arch/ai-native-l1

Do not submit this automatically, do not solicit votes, and do not claim production readiness. Review the current guidelines first: https://news.ycombinator.com/showhn.html

## Platform execution status

- Website/social preview/SEO: prepared in source for publication.
- GitHub source, issues and public contributor calls: published.
- LinkedIn, Reddit, X and Bluesky: share links on the website; each post still requires an authenticated account.
- DEV Community: draft included above; publish via an account that controls the publication.
- Product Hunt: not submitted. Its current guidelines emphasize usable digital products, while QRun is still experimental public-alpha and not a general end-user product. Reassess after a self-serve runnable demo exists.
- Hacker News: draft only, because its guidelines require authentic human posting and discussion; do not automate it.

## Campaign ground rules

Never invent users, node counts, endorsements, grants, market prices, trading volume, reserves, listings or security audits. No paid ads have been purchased; no budget was authorized. Do not purchase votes, views, fake users, wash volume or paid listings. Use transparent project status and tailor each community submission.
