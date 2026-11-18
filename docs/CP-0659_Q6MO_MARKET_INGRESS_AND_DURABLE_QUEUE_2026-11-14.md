# CP-0659 — Q6MO/Q6MA Market Ingress, Shared Nonce Queue and Q6MM Journal

Date: 2026-11-14
Project: AI-NATIVE L1 / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`
Base documentation checkpoint: CP-0658
Status: **Local implementation integrated into the permissionless service candidate; targeted tests pass. Full binary check and release/network qualification remain separate gates. No public trading authorization.**

## 1. Scope and compatibility

This checkpoint adds a separate versioned Q6MO/Q6MA market-operation ingress without changing Q6TI's existing native-transfer wire meaning.

- Q6MO is version 1, has a 20-byte fixed header, non-zero request ID, explicit payload length and a 32 KiB operation payload bound.
- Q6MA is a fixed 128-byte response carrying request ID, status, stable operation ID, pending-queue count/bytes and the canonical height/tip/state root observed for the request.
- Q6MA statuses distinguish Accepted, Duplicate and Rejected. Accepted means validated and durably pending only. It never means mined, confirmed, finalized or executable at an exchange.
- Operation IDs use a domain-separated SHA-256 commitment over canonical operation bytes.
- Canonical encoding checks exact length and canonical re-encoding; malformed, overlong, trailing-byte, invalid-version and unsupported-tag frames are rejected.

## 2. Strict operation allowlist

The market API currently accepts signed OrderBook operations and only these signed AMM operations:

- CreatePair
- SwapExactIn
- AddLiquidity
- RemoveLiquidity

It rejects NativeTransfer, asset registration/admin, category release, protocol burn-reserve retirement, AMM RegisterAsset, AMM TransferAsset and AMM MintTestQuote at the market codec/operation policy boundary. Asset registration/admin and supply-control changes remain separate policy-governed operation paths. Test quote minting is not a user market-ingress capability.

The Q6MO market candidate builder currently supplies no external Q6QA authorization provider. Therefore external quote assets fail closed through this permissionless candidate path. Native QZXB quote operations may only use actually registered assets and canonical balances/liquidity; a pair ID alone does not create a valid market or backing.

## 3. Shared canonical validation

A combined candidate-block builder merges pending Q6TI native transfers and Q6MO market operations and orders them deterministically by:

`(account_id, account_nonce, operation_id)`

The entire operation set is previewed against the same canonical QFP6 execution state before a queue mutation is accepted. This causes the canonical ledger's account nonce rules, signature checks, expiry checks, asset/funds checks, OrderBook vault invariants and AMM rules to apply across both operation families.

Q6TI submission now has a market-aware path: it clones the proposed native pool and checks the new transfer together with all current market operations before updating the live native pool. Q6MO admission likewise validates against the current native pool plus all already-pending market operations. Both paths use the same per-session replay guard in the permissionless Noise dispatcher.

A market operation that conflicts with a Q6TI pending nonce, or a Q6TI transfer that conflicts with Q6MO, is rejected by the shared candidate preview. The positive test uses OrderBook nonce 1 followed by a Q6TI native transfer nonce 2 from the same account; the negative case repeats nonce 1 and is rejected. Asset registration's issuer_nonce is a distinct registry sequence and is not conflated with the account operation nonce.

## 4. Bounded market mempool and durable Q6MM

A separate market mempool enforces the existing configured global transaction/byte limits and a maximum of 16 pending market operations per account. It rejects duplicate IDs, unsupported operations, wrong-network and expired operations. It is deterministic and revalidates after canonical parent changes.

The new Q6MM journal is kept in a separate sibling directory derived from the Q6MJ path with the `.market-operations` extension (for example, `mempool.market-operations`). It is deliberately not nested inside the Q6MJ directory because the Q6MJ scanner rejects unexpected entries. This preserves Q6MJ's version 1 native-transfer format and its strict directory validation. Q6MM provides:

- immutable, generation-numbered snapshots;
- Q6MM magic/version/header and bounded operation lengths/counts;
- domain-separated SHA-256 snapshot checksum and duplicate operation-ID rejection;
- an OS-backed exclusive writer lock;
- symlink/special-file rejection and stale temporary-file cleanup;
- write/flush/fsync followed by platform-specific atomic no-replace installation;
- bounded snapshot retention;
- startup restore followed by canonical and Q6TI-pending-set revalidation;
- refusal to persist the pool until startup reconciliation completes.

At startup the service restores Q6MJ native transfers first, then restores Q6MM market operations against that exact native pending set. If an operation no longer validates, it is dropped and the reconciled Q6MM snapshot is durably installed before ingress is allowed.

## 5. Service, dispatcher and miner integration

The permissionless service now opens Q6MJ and Q6MM, exposes market pending counts/bytes and Q6MM generation, handles Q6MO submission and returns Q6MA only after Q6MM persistence succeeds. If persistence fails, the in-memory market pool is rolled back and no Accepted response is returned.

The permissionless Noise application dispatcher routes Q6TI, Q6MO and Q6PB. Q6TI and Q6MO use the shared session replay guard. The Q6MO response uses the fixed 128-byte peer application response size.

The mining service builds one combined candidate from both pending pools and passes the ordered operations through the existing QFP6 miner and canonical durable runtime. After the exact mined block becomes canonical, only its included Q6TI and Q6MO entries are removed. Both journals are then reconciled against the new canonical state and refreshed. A side-branch commit does not prune pending entries as if they were canonical.

## 6. Local targeted verification

Executed on the active Windows worktree with locked offline dependencies:

| Target | Result |
|---|---:|
| `qrun_v06_market_ingress_candidate` | 6 passed, 0 failed |
| `qrun_v06_market_journal_candidate` | 3 passed, 0 failed |
| `qrun_v06_permissionless_service_candidate` | 4 passed, 0 failed |

The six ingress tests cover Q6MO/Q6MA round-trip and operation ID, request/version/length checks, native/governance rejection, AMM asset-control/test-quote rejection, and shared Q6TI/Q6MO nonce sequencing including duplicate-nonce rejection.

The three journal tests cover round-trip and checksum tamper rejection, startup-reconciliation gating, and durable reopen/restore of a revalidated signed market operation.

The four service tests cover existing nonce-cursor/canonical-pruning behavior plus an end-to-end local Q6MO lifecycle: a separately governed base-asset registration is canonicalized; a Q6MO OrderBook pair-create frame is accepted and persisted in Q6MM; a genuine QRunV06 Noise XX session is established with both static keys pinned; the client sends Q6MO inside an authenticated encrypted Noise record; the server invokes the exact application-dispatch function wired by the permissionless supervisor and returns Q6MA through the same Noise session; the service is closed and reopened; Q6MM restores the signed operation; the miner includes it in a combined candidate; the exact block becomes canonical; the operation is pruned; and a further reopen does not resurrect it. This focused loopback test uses a digest-comparison test authenticator and easy candidate PoW parameters, and uses a raw test TCP accept loop rather than the production peer-listener worker pool. It proves the Noise record, dispatcher, persistence/service/canonical lifecycle, not production cryptographic security or independent-host/network qualification.

An existing permissionless supervisor recovery/mining test also passes after widening its shutdown allowance from 180 ms to 1.5 s; the old cutoff raced startup after the second journal was added. It commits a block and recovers the durable Genesis-rooted state.

Final local verification on this worktree:

| Check | Result |
|---|---|
| `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked --offline` | PASS (exit 0; existing unused/dead-code warnings in unrelated files remain) |
| `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check` | PASS |
| `git diff --check` | PASS |

The bin check covered all package binaries, including the updated node/supervisor call path. The warnings were in existing unrelated files; no compile warning was emitted for the new Q6MO/Q6MM modules in the observed output.

## 7. Explicit limits and next release gates

This is a local candidate implementation, not an authorized or launched public trading venue.

1. A production peer-listener qualification still needs to send Q6MO through the actual listener worker pool and supervisor callback on the updated executable. The local loopback now exercises a real pinned QRunV06NoiseSession, encrypted Q6MO/Q6MA records and the exact supervisor application-dispatch function, but uses a raw test TCP accept loop rather than the production listener lifecycle.
2. A new independent-host test must use the exact updated permissionless executable and Q6MO path. Historic CP-0566C/CP-0587 host tests remain credited for their recorded QAP1/Q6TI scope; they are not misrepresented as Q6MO host evidence.
3. The permissionless runtime still lacks independently verified Q6QA quote-asset bundle loading. USDT-like external quote assets remain rejected/fail-closed until authorization, decimals, freshness, revocation and custody/settlement are wired and qualified.
4. No production wallet order-entry UX, public RPC/market API contract, market-data indexer or explorer is thereby qualified.
5. Public seed inventory, inbound reachability, Linux Noise key custody, frozen genesis/consensus/network/bootstrap artifacts, founder signatures and independent security/economics reviews remain open gates recorded in CP-0656 through CP-0658.
6. No USDT reserve, bridge, market maker, counterparty, CEX listing, public liquidity, native price or value-bearing trade has been created or verified.

**Decision:** Q6MO/Q6MM is locally implemented and targeted tests pass. Continue with executable-level integration testing and independent-host qualification. Public Testnet/Mainnet, public mining and real-value trading remain NOT AUTHORIZED until all release and network gates are independently satisfied.

The code changes in this worktree are intentionally not committed as a broad source commit because several touched source files already contained unrelated, pre-existing local modifications. No source reset, branch reset or push was performed for this checkpoint.
