# CP-0658 — CP-0651 Native Market Execution Qualification and Trading-Gateway Gap

Date: 2026-11-14
Project: AI-NATIVE L1 / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Base HEAD: `df673d07050688a64b26822d97e6ea609b68ce88`
Local documentation commit before this checkpoint: `d0bd6348712a3cf87064885682d468221e5937a6`
Depends on: CP-0566C, CP-0587, CP-0614–CP-0616, CP-0649, CP-0651–CP-0657
Status: **CP-0651 native OrderBook execution regression passed locally; public order ingress, durable market-operation mempool, RPC/wallet/market-data, final artifacts and value-bearing trading remain NOT READY**

## 1. Previous single-host and two-host qualifications retained

The historical qualifications below are accepted as completed evidence within their exact recorded scope. They are not repeated merely to increase test counts.

### CP-0566C — two-host QFP6/QAP1 candidate qualification

- GitHub Actions cross-host run: [42205440686](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42205440686).
- Node A ran on the owner's Windows workstation; Node B was an ephemeral GitHub-hosted Windows Runner enrolled in the private NetBird overlay.
- Authenticated remote admission, replay rejection, and second-process QAP1 restart continuity passed.
- Manifest Anchor, State Root, height and generation were reproduced after restart.
- This is two-host private-candidate/QAP1 evidence. It is not independent public-network operation, public inbound reachability, permissionless full-history public convergence or real-value trading.

### CP-0587 — cross-host Q6TI/Q6MJ pending-transaction recovery

- GitHub Actions run: [43017541194](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/43017541194).
- Node A sent a signed Q6HA native transfer over the pinned Noise overlay to a separate ephemeral Node B runner.
- Q6TA Accepted was returned only after Q6MJ journal persistence. A second Node B process reopened the QFP6/Q6MJ state and restored the exact same pending TXID; generation advanced once.
- This verifies pending-transfer persistence/restart continuity in that candidate topology. Q6TA Accepted is not a mined, confirmed, finalized or tradeable transaction.
- It does not qualify the current CP-0651 permissionless market-operation path.

### CP-0649 — two independent Noise sources

- Two separate loopback Noise servers with separate keypairs and operator-assigned trust-domain IDs produced matching or divergent histories.
- Matching histories passed the exact bootstrap agreement gate; divergent valid histories were rejected.
- The test used 127.0.0.1 ephemeral listeners. It is not a new physical two-host test or public seed qualification.

## 2. Native market components already present in candidate execution

The current QFP6 canonical execution candidate has integrated state components for:

- Native QZXB asset identity.
- Signed asset registration and asset-registry state.
- AMM pair creation, liquidity addition/removal and swaps.
- OrderBook pair creation, deposits/withdrawals, limit orders, fills, expiry and escrow/vault accounting.
- State-root and versioned snapshot commitments that include AMM, registry and OrderBook state.
- Shared account nonces and validation against attempts to transfer or drain reserved OrderBook vault balances.
- External quote-asset authorization through Q6QA in the applicable anchored launcher path.

These are candidate execution components, not a publicly reachable trading service. A canonical state machine test is not proof that an ordinary wallet can submit an order to a live network.

## 3. New CP-0651-native trading regression

A local regression test was added to the existing QFP6 canonical execution candidate file:

`src/native/pow_bench/src/qrun_v06_canonical_execution_candidate.rs`

Test name:

`cp0651_native_quote_orderbook_match_preserves_supply_and_snapshot`

Test flow:

1. Construct CP-0651 Genesis with exactly 1,000,000,000 QZXB assigned to the owner account.
2. Register a fixed-supply test base asset.
3. Create a native OrderBook pair with the QZXB native asset as the quote asset.
4. Deposit both assets into the OrderBook sub-ledger.
5. Submit a seller ask and buyer IOC bid; execute one fill.
6. Settle maker/taker fees to the designated producer account.
7. Verify that the block subsidy is zero, the CP-0651 policy fingerprint is unchanged, total native Ledger supply remains exactly equal to the initial 1B Genesis balance, and all state/vault invariants hold.
8. Encode and decode the canonical snapshot; verify exact state equality, identical state root, preserved market fill and unchanged supply.

Observed current-worktree verification:

| Check | Result |
|---|---:|
| `cp0651_native_quote_orderbook_match_preserves_supply_and_snapshot` | 1 passed, 0 failed |
| QFB6 canonical AMM/OrderBook family (`qfb6_`) | 10 passed, 0 failed |
| CP-0651 fee-only Genesis/snapshot regression | 1 passed, 0 failed |
| AMM pair registration/liquidity/swap regression | 1 passed, 0 failed |
| Fully backed OrderBook matching/vault/shared-nonce regression | 1 passed, 0 failed |
| `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check` | PASS |
| `git diff --check` | PASS |

The targeted QFB6 suite includes external quote-asset authorization freshness/persistence, decimal mismatch rejection, snapshot continuation, market fills and escrow. The local test authenticator used by the CP-0651-specific fixture is explicitly test-only; this test is not an external signature audit or a live order submission.

The added source test remains part of the existing local modified source worktree and was not included in the documentation-only commit for this checkpoint. Other pre-existing source/manifest changes were preserved.

## 4. Exact current public trading-gateway gap

Source inspection found that the current permissionless runtime has a narrower user ingress than the canonical execution engine:

- Q6TI/Q6TA decodes a native `Transaction` transfer request only.
- `QRunV06PermissionlessMempool` is a bounded native-transfer mempool backed by the Q6MJ journal.
- The permissionless mining template selects pending `NativeTransfer` operations from that mempool. It does not select pending AMM or OrderBook operations.
- The permissionless application-frame dispatcher handles Q6TI transaction submission or Q6PB block admission. Q6PB can admit a complete block containing canonical operations, but this is not an ordinary user-facing order-submission API or a durable order mempool.
- No QFP6 public RPC/market API, production wallet order screen, market-data indexer or native explorer is qualified in the current release.
- The permissionless-full-history launcher does not currently load a Q6QA quote-asset bundle. The anchored QAP1 launcher has Q6QA configuration support, but that does not automatically qualify Q6QA for the permissionless base runtime.

**Decision:** the canonical market state transition path is locally testable, but ordinary users do not yet have a qualified public route to submit, persist, replace/cancel and query signed market operations through the permissionless node.

## 5. Next engineering gate — Q6MO market-operation ingress and durable selection

Implement a separate versioned market-operation ingress protocol (proposed family: Q6MO/Q6MA), without redefining Q6TI's existing native-transfer meaning.

Acceptance requirements:

1. Support bounded canonical encodings for the permitted AMM and OrderBook signed operation types; reject unknown tags, duplicate/noncanonical encodings, excessive frames and trailing bytes.
2. Validate network, profile, signature, asset permissions, account nonce, expiry, native/quote-asset rules, funds and OrderBook vault invariants against a cloned canonical state plus already-pending operations.
3. Enforce one shared per-account nonce sequence across native transfers, AMM operations and OrderBook operations. Prevent conflicting simultaneous Q6TI/Q6MO submissions from bypassing nonce ordering.
4. Apply global/per-account count and byte limits, expiry, duplicate IDs, deterministic selection and backpressure. Do not create unbounded per-peer state.
5. Persist accepted market operations before returning Q6MA Accepted. Acknowledgement must mean pending/journaled only, never mined or final.
6. Revalidate the market-operation queue after canonical block import, fork-choice change, reorg and restart. Remove only operations proven included in the exact canonical block; reject or retain side-branch operations according to deterministic policy.
7. Extend the block template builder to select native transfers and market operations in one deterministic, nonce-safe operation order; commit only through the same canonical execution, state-root, fork-choice and durable-store path.
8. Test crash windows around market-journal writes, block commit and pending-queue reconciliation. Test replay, duplicate submission, nonce conflict, queue saturation, cancellation, reorg and snapshot restoration.
9. Add independent client vectors and an end-to-end two-host run on the exact new permissionless executable path after local tests pass. Existing CP-0566C/CP-0587 evidence remains credited for its previous scope.

## 6. Quote asset and settlement boundary

A native QZXB/USDT market requires more than an OrderBook pair identifier:

- The USDT-side asset must exist on the native network under a separately approved asset identity, supply/custody model and Q6QA authorization, or a reviewed bridge/settlement design must bring a representation onto the native network.
- Q6QA signer authority, quote-asset decimals, permitted operations, freshness/expiry, revocation and key custody must be independently governed and included in the permissionless runtime's configuration and state-transition validation if external quote assets are enabled there.
- A Sepolia ERC-20 named QX is a distinct test asset. It is not native QZXB, not USDT, not a bridge and not a production quote asset.
- No USDT reserve, bridge, exchange integration, market maker, counterparty, executable liquidity or order-book depth is currently evidenced. Do not seed a fake QZXB/USDT pair or claim a market price/volume.
- CEX listing/deposit/withdrawal integration is a separate path requiring the exchange's own acceptance and operational support; a native AMM implementation does not create a CEX listing.

## 7. Release-artifact state and launch boundary

The candidate package self-test passed, but the real package validator still returns **INCOMPLETE** with five required artifacts missing:

- CP-0651 Genesis execution snapshot.
- Q6GD Genesis descriptor.
- Q6CP frozen consensus profile.
- Q6PN network profile.
- Hash-pinned bootstrap peer set.

Founder public keys remain candidate-bound only; the Genesis signature is absent. The Q6CP still inherits candidate/easy-test PoW settings and is not production-calibrated. Independent consensus, cryptography and economics reviews remain pending.

CP-0656 records that direct IPv6 inbound hosting from the current hotspot was not qualified. CP-0657 records that the current Noise protected-key provider is Windows DPAPI-only; Ubuntu seed provisioning needs a separately implemented and tested Linux credential provider. The previously completed CP-0566C/CP-0587 two-host tests remain valid and are not erased by these newer release blockers.

**Decision:** no public user trading gateway, no verified native quote settlement, no final CP-0651 release package and no permanent independent public seed set currently exist. Public Testnet remains **NO-GO / NOT LAUNCHED**. Native Mainnet, public mining, market liquidity and value-bearing trading remain **NOT AUTHORIZED / NOT ESTABLISHED**.

---
