# CP-0443 — Bitcoin-Inspired Permissionless-First Launch Gate

Date: 2026-10-28

Status: Founder-directed execution policy. This is a decision rule for removing unnecessary approval dependencies; it does not claim that Mainnet is currently deployed or safe for value-bearing use.

## 1. Standing instruction

For every QuantumZXB launch decision, use the Bitcoin principle first: **a peer-to-peer protocol is launched by publishing working, reproducible software and a fixed set of consensus rules—not by waiting for an exchange, data platform, outside auditor, sponsor, or centralized gatekeeper to grant permission.** Any participant should be able to run compatible software and decide locally whether to join, mine, relay, or transact under the published rules.

Satoshi's paper describes a peer-to-peer timestamp network, digital signatures and proof-of-work rather than a trusted central transaction authority. Bitcoin.org likewise describes Bitcoin as open-source software with no central authority. See the references below.

This principle is now a standing project gate: future work must not turn a third party's commercial acceptance, listing, audit availability, sponsorship, or operator recruitment into an all-purpose permission requirement for publishing a permissionless native protocol.

## 2. Split readiness into three distinct lanes

### Lane A — protocol launch blockers (must be real)

Only a concrete defect or missing capability that prevents the chain from being identified, validated, operated, or used safely as the advertised protocol can block a value-bearing Mainnet release:

1. **One exact production identity:** finalized network ID, Genesis bytes/hash, consensus/profile versions, owner-controlled public identity, issuance schedule, fee rules, transaction formats and activation rules. No test-only identifiers or contradictory profiles.
2. **One canonical consensus path:** the production producer, block importer/validator, fork choice/reorg, persistent store, restart/replay and state-root calculation must enforce the same deterministic monetary transition and lifetime supply/category ceilings. Candidate-only tests do not satisfy this.
3. **Real transaction security:** signing keys remain user-controlled; signatures, network domain, nonce/replay, expiry, fee and balance checks are enforced; failures are atomic; wallet signing, submission, canonical inclusion and receipt/balance query work end-to-end.
4. **Real PoW and recovery:** production difficulty/reward validation is used by all nodes; no easy-PoW test shortcut; recovery and reorganisation fail closed on inconsistent history/profile/state. Any bounded history or probabilistic finality limits are explicit.
5. **Operational network path:** a release binary can connect to peers, sync canonical history, propagate blocks and transactions, expose appropriately protected production interfaces, and recover after restart. Local loopback success must not be described as Internet deployment.
6. **Reproducible release and honest disclosure:** source SHA, build instructions/artifact hashes, Genesis/profile identifiers, supply rules, wallet instructions, endpoint identities, known limitations and incident contact are published. A release must not represent an unimplemented capability as active.

These are engineering conditions, not an external organization's permission. Where an exact owner-controlled input is genuinely missing, record the specific field and ask only for that input; never fabricate it, silently use a fixture, or restart a generic approval checklist.

### Lane B — not permission gates for protocol launch

The following do not, by themselves, prevent publishing a permissionless native protocol or allow others to run it:

- exchange listing, CMC/CoinGecko tracking, DEX Screener indexing, TradingView support or a market-data vendor;
- a sponsor, grant, revenue stream or paid service contract;
- a third-party auditor or exchange's approval;
- a preselected number of independent operators signing off on launch;
- a marketing campaign, a price chart, or a liquidity target.

Pursue independent reviews and real multi-host operation as high-value evidence, but do not describe a missing external sign-off as a technical permission to launch. Publish the review status and known risks accurately. If a specific reproducible critical defect is found, fix it or explicitly keep the affected value-bearing feature disabled; do not hide the defect behind an "approval" label.

Jurisdiction-specific rules can apply to particular conduct such as an offer/sale, custody, operating an exchange, providing regulated services, or targeted promotion. Assess those activities on their actual facts and jurisdiction; do not treat a hypothetical universal permit as a protocol dependency, and do not treat the Bitcoin analogy as a legal exemption.

### Lane C — QZXB/USDT trading is a separate hard gate

Launching a native QZXB chain does not automatically create a QZXB/USDT market. To claim a real swap, the quote asset must be an authentic, chain-specific USDT representation or another clearly disclosed and redeemable implementation, the QZXB side must be authentic, and a real accessible venue/pool must hold both assets and accept transactions. The route must have a verifiable deposit/withdrawal, bridge/wrapper or native asset-registration/redemption model as appropriate.

A token label "USDT", a genesis-only balance, a test AMM pair, or a fabricated candle is not a substitute for real asset backing and market access. If the native chain cannot yet support a second asset with real deposit/redemption, evaluate a separately disclosed wrapped-QZXB market on an established chain; it must not be misrepresented as a native QZXB/USDT trade. No private key, treasury address, bridge, venue, or liquidity reserve may be invented.

## 3. Execution order: permissionless-first, shortest real path

1. **Freeze only the actual launch inputs:** final owner public account/key identity, network ID, Genesis, monetary/consensus profile and transaction-signature profile. Derive the public Genesis hash from those exact bytes.
2. **Integrate and verify the canonical production path:** producer, importer, fork choice, durable store, restart/replay, reorg and state root; enforce the 10B cap and category ceilings with independent vectors and adversarial tests.
3. **Build the production release path—not another testnet milestone:** remove test-only restrictions only by implementing a distinct, locked production profile with no easy-PoW, test Genesis or loopback-only assumptions. Never bypass a guard by changing a flag.
4. **Prove cross-host operation and publish the real endpoints:** start the actual production-profile nodes with consistent Genesis/profile; verify peer sync, block/transaction propagation, wallet signing, transaction inclusion and independent receipt/balance reads. Keep technical evidence separate from external approval.
5. **Publish the protocol permissionlessly:** publish the reproducible release, Genesis/profile details, node and wallet instructions, peer/bootstrap information, data/API endpoints, risks and limits. Do not wait for listing, market-data indexing, an auditor, a sponsor or a minimum operator count as a central gate.
6. **Create market access as a separate workstream:** choose a genuine USDT route, ensure the base/quote assets and redemption model are correct, provide real liquidity, submit a small user-authorized first swap, and verify its canonical transaction/receipt and reserve changes from independent reads.
7. **Activate real candles only from canonical confirmed trades:** index real swaps, survive reorgs and incomplete history correctly, then publish 1h, 1d, 1w and 1M bars. Before sufficient history exists, show only the bars actually supported by confirmed observations.

Do not spend time repeating loopback "happy path" tests once their specific regression has passed; keep local/CI tests as regression checks for every source change. The decisive work is production integration and deployment evidence, not accumulating test-only milestone numbers.

## 4. Release decision rule

- A successful CI run is necessary evidence for its source commit, not proof of Mainnet.
- An external listing, audit or legal-service decision is not a substitute for correct code and cannot make a broken consensus path safe.
- Lack of a listing, market, sponsor or external reviewer is not a reason to defer a technically sound permissionless protocol indefinitely.
- A real technical failure, unresolved network/Genesis ambiguity, invalid supply accounting, broken wallet/transaction flow, or missing asset-backing path for the claimed USDT pair remains a blocker for that specific feature.
- If the protocol is launched before a third-party security audit, disclose that fact and the residual risks; do not claim an audit or security guarantee.
- Only report Mainnet and a real QZXB/USDT market after the relevant production artifacts, endpoints and on-chain evidence have been independently read and verified.

## 5. Current application to QuantumZXB (2026-10-28)

The current source head is 16a78d2eb454a5f6cec1a586cbbda604cc5e05fa; its exact-head GitHub Actions run 40575841079 passed both jobs. The branch includes a QZXB native AMM/candle candidate, but the code and CP-0436/CP-0442 documents still identify the native monetary profile as candidate-only, mainnet=false, public_launch_approved=false, and lacking an authenticated second-asset deposit/redemption route. Public market checks returned zero exact QZXB pairs on DexScreener, zero exact CoinGecko results, and no QZXB-USDT instrument at OKX.

Under this gate, exchange listing, platform tracking, sponsor revenue, a minimum operator count and outside audit/CAS-provider availability are not the reason to stop the protocol launch. The actual remaining blockers include the production Genesis/runtime identity and integration, wallet/network operation, and a recovery path suitable for real production history (the current candidate archive is bounded), plus a truthful USDT/market route for the requested swap. Prefer full-history consensus-native validation/replay and cumulative-work fork choice; do not make a third-party CAS vendor mandatory for the base protocol. A separately pruned/checkpoint mode must state its own trust requirements. No real transaction, liquidity or Mainnet status is claimed by this policy document. New owner-funded spend remains unauthorized unless separately approved.

## References

- Satoshi Nakamoto, [Bitcoin: A Peer-to-Peer Electronic Cash System](https://bitcoin.org/bitcoin.pdf): digital signatures, proof-of-work, a public chain and direct peer-to-peer operation without a trusted transaction authority.
- [Bitcoin.org FAQ](https://bitcoin.org/en/faq): Bitcoin is described as a peer-to-peer payment network without a central authority and as open-source software.
- [Bitcoin Core — About](https://bitcoincore.org/en/about/): the open-source client lineage and public participation model.
