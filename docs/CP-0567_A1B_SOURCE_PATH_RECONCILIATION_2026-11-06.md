# CP-0567 — A1B Source-Path Reconciliation (2026-11-06)

Status: READ-ONLY SOURCE AUDIT. No protocol, consensus, transaction, Genesis, wallet, monetary, node, or runtime code changed.

## Scope and exact source baseline

- Repository: `hamidnikkhah660-arch/ai-native-l1`
- Source branch inspected: `origin/main`
- Exact source commit: `c536caec696217234d6b35582663c0aa58652b9c` (2026-11-05)
- Audit purpose: reconcile CP-0567 A1 assumptions against the actual PMT4/PFM4 node path and identify the correct future integration boundary.

## Important correction to the earlier A1 inference

The earlier A1 audit correctly identified that `src/native/pow_bench/src/v4_transaction_mempool_candidate.rs` is documented as a candidate-only, side-effect-free pool module. However, the broader inference that TXN4 was not wired into any node CLI/peer runtime was too broad for the inspected `main` baseline.

`src/native/pow_bench/src/bin/devnet_node.rs` includes `private_testnet_node.rs` and calls `private_testnet_node::main_devnet()`. In that shared node implementation, `--monetary-v4-hybrid-peer-smoke` dispatches to `run_monetary_v4_hybrid_peer_smoke`. That path constructs `V4HybridMempoolCandidate`, opens a PFM4 fork store, binds PMT4 peer/status/TXN4 submission listeners, runs Noise-authenticated peer handling, imports PMT4 candidates, reconciles the mempool after canonical changes, and supports optional PFM4 archive-range synchronization.

Therefore, the accurate statement is: **a real, end-to-end PMT4/PFM4/TXN4 candidate peer-smoke runtime exists and is wired into the `devnet_node` binary, but it is deliberately restricted to a loopback diagnostic profile and is not a public or production monetary runtime.**

## Verified implementation path

1. `src/native/pow_bench/src/bin/devnet_node.rs`: includes the shared node implementation and dispatches to `main_devnet()`.
2. `src/native/pow_bench/src/bin/private_testnet_node.rs`:
   - parses `--monetary-v4-hybrid-peer-smoke`;
   - dispatches it from `run_devnet()` to `run_monetary_v4_hybrid_peer_smoke()`;
   - validates loopback-only listen, status, transaction and peer addresses;
   - opens `PrivateTestnetV4HybridForkStore` using the local `open(...)` path;
   - constructs `V4HybridMempoolCandidate`;
   - uses protected Noise static-key material and pinned peer identities;
   - accepts/submits signed TXN4, builds/imports PMT4 blocks, reconciles the pool after canonical changes, and can run PFM4 archive-range synchronization.
3. `src/native/pow_bench/src/v4_transaction_mempool_candidate.rs`: the reusable pool module remains a bounded in-memory candidate pool; its module header explicitly says it has no independent network or disk side effects. The node harness is the integration layer.
4. `src/native/pow_bench/src/private_testnet_v4_hybrid_fork_store_candidate.rs`: contains external-CAS APIs (`open_with_external_cas`, `submit_with_external_anchor`) and tests, but the PMT4 peer-smoke node path calls local `PrivateTestnetV4HybridForkStore::open(...)`; this audit found no use of the external-CAS methods in that peer-smoke runtime path.

## Production-boundary restrictions observed in source

- `validate_monetary_v4_peer_config` rejects every non-loopback listener and peer address.
- The peer-smoke path overrides the consensus target to `Uint256::MAX` and Argon2 memory to 8 MiB; this is explicitly an easy local PoW profile, not production difficulty calibration.
- Its startup event labels the profile `LOCAL_RESEARCH_40_30_30`, `profile_scope=loopback_diagnostic`, `pow_profile=LOCAL_EASY_POW_8MIB`, and `public_launch_approved=false`.
- The runtime uses local PFM4 storage, not an independently operated external CAS provider or externally anchored submit path.
- The containing file describes itself as a loopback-only private-testnet harness, not a public P2P node or Mainnet client.
- `docs/CP_0373_GATE2_PFM4_RUNTIME_PRODUCTION_BOUNDARY_2026-10-22.md` independently records the same boundary and minimum prerequisites. Its `Verified base` is older; the source reconciliation in this document is pinned to the exact `origin/main` commit above.

## CP-0567 data-model gap confirmed

The current TXN4 authorization envelope (`V4HybridAuthorization`) contains:

- network ID and manifest ID;
- sender and recipient account IDs;
- nonce, amount, fee, and exclusive expiry;
- identity scheme and Ed25519/ML-DSA-65 public-key tuple.

It does **not** contain a delegated capability ID, policy version, agent identity distinct from the owner/sender, asset ID, recipient/service scope, capability expiry, per-transaction/aggregate capability counters, or revocation epoch/tombstone.

`MonetaryLedgerState` currently wraps `LedgerState` plus `total_mined_atoms`; no capability registry, delegated-spend counters, revocation state, or capability policy version was found in that state shape. The current TXN4 path therefore does not implement CP-0567 bounded agent authorization. A signed TXN4 transfer is not equivalent to a delegated, owner-bounded agent capability.

## Correct CP-0567 integration target

For future work, use the PMT4/PFM4 monetary state transition and the actual `devnet_node` PMT4 peer-smoke integration as the architectural reference. Do not target the legacy BLK2 `ChainImportService` as if it were the active PMT4 monetary runtime. Do not treat the current loopback harness as a deployable public profile.

Before implementation, resolve and document:

1. A production-grade non-loopback runtime/profile boundary, including real PoW target/resource parameters and authenticated operator/peer policy.
2. How external CAS anchoring is injected into node startup, block commit, restart, recovery, and reorg; define atomic failure behavior before any state publication.
3. The canonical PMT4 block transaction execution point where capability registration, revocation, authorization checks, and spend counters can be applied atomically with balances, fees, nonce, and replay state.
4. Fork-choice/reorg rollback semantics for capability state and all associated counters/tombstones.
5. The owner-to-agent identity and key-custody/rotation model; current hybrid account identity does not itself create delegation.
6. Exact semantics for self-transfer, fee debit, expiry clock (TXN4 currently uses an `expires_at` field interpreted by candidate timestamp), same-block register/revoke/spend ordering, and state pruning.

## A1 conclusion

- PMT4/PFM4/TXN4 candidate peer runtime: **IMPLEMENTED IN A LOOPBACK DIAGNOSTIC HARNESS**; current CI validates selected loopback flows only.
- Public/non-loopback production monetary runtime: **NOT ESTABLISHED** by this source path.
- External CAS in the peer-smoke runtime: **NOT WIRED**; external-CAS library APIs/tests exist separately.
- CP-0567 delegated AI-agent authorization: **NOT IMPLEMENTED** in TXN4 or `MonetaryLedgerState`.
- Next safe action: produce a narrow CP-0567 A1 interface/state-transition proposal against the PMT4/PFM4 canonical import path, with typed errors and deterministic vectors, while leaving consensus/runtime code untouched until the production boundary and reorg/anchor semantics are decided.

No source code, protocol behavior, Genesis, supply, wallet, live balance, public listener, or network configuration was changed by this audit.
