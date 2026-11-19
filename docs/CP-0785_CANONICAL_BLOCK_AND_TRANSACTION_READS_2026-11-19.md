# CP-0785 - Canonical Block and Transaction Read API

Date: 2026-11-19
Base: CP-0784 / 095b61f54dce965594114f9c0a3f829d2236cdfd
Branch: feat/q6ga-v3-mainnet-scope-20261119

## Result

Added canonical QFP6 block lookup and native TXN2 transaction receipts to the existing optional read-only API. The routes derive their responses from the durable fork graph and its retained canonical/side-branch envelopes. They do not accept transactions, alter consensus, or enable a listener.

## Runtime read surfaces

QRunV06PermissionlessNodeRuntime::canonical_block_read(height):

- Pins one fork-choice snapshot and checks its consensus tip/height against runtime status.
- Reads a one-block canonical history page for the requested height.
- Decodes the stored QFP6 envelope and checks QFB6 execution block ID, retained branch state, recomputed execution root, and ancestry to the selected canonical tip.
- Returns network/profile, height, timestamp, execution parent, QFB6 execution block ID, QFP6 consensus tip, execution state root, producer, and bounded operation metadata.
- Native transfer operation metadata includes canonical TXN2 ID, sender, recipient, nonce, amount atoms, fee atoms and expiry. Signature bytes are not returned.
- The base Genesis/checkpoint state has no retained block body in this graph interface. Heights at or below the current base height therefore return block_not_available; this endpoint is not a full historical archive API.

QRunV06PermissionlessNodeRuntime::canonical_transaction_read(txid):

- Scans the retained fork archive under explicit bounds: at most MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS (1,024) envelopes and 16 MiB total.
- Derives transaction IDs with the same transaction_id_with_signature_limit function and signature limit used by canonical QFB6 execution.
- Rechecks each envelope against its retained execution state and recomputed QFB6 state root before returning a receipt.
- Returns canonical when the containing block is an ancestor of the current canonical consensus tip, with confirmation depth canonical_height - inclusion_height + 1.
- Returns reorged when the transaction is found only in a retained noncanonical branch; confirmations are zero.
- A transaction not present in the retained fork archive is not found. This endpoint does not inspect the mempool, and its response explicitly says mempool_checked=false; it must not be interpreted as a pending-transaction API.
- If the retained archive exceeds the scan limits, lookup fails closed rather than returning a false not-found response.

## HTTP routes

Added GET-only routes:

- GET /v1/block/{height}
- GET /v1/transaction/{64-hex-transaction-id}

Block JSON returns the distinct execution_block_id (QFB6) and consensus_tip (QFP6) commitments. Transaction JSON exposes inclusion status, block identifiers, canonical snapshot identifiers and confirmation depth. Atom values and large counters are decimal strings to preserve exact integer values in JavaScript clients. Malformed heights/IDs return HTTP 400; unsupported methods remain HTTP 405; unavailable canonical reads return 503; missing retained block/transaction records return 404 with explicit scope.

The transaction response uses finality=confirmation_depth_only. This is not a deterministic finality guarantee and does not imply irreversibility.

## Consensus/execution tip domain correction

The expanded post-Genesis test exposed an old snapshot-check defect in the account/supply read methods: QFP6 consensus tip was compared directly with QRunV06CanonicalExecutionState::tip_hash(), which is the separate QFB6 execution block ID. These are intentionally distinct hash domains.

The account and supply read checks now compare height and consensus tip to graph.canonical_tip(), while independently recomputing and checking the execution state root against runtime status. This preserves one canonical snapshot without conflating the two identifiers.

## Validation performed

- Expanded CP-0651 runtime/API test: 1 passed, 0 failed.
  - Creates a signed native TXN2 transfer using a deterministic test authenticator.
  - Mines and durably submits a QFP6 block.
  - Verifies canonical block lookup and TXN2 receipt values/IDs.
  - Checks /v1/block/1 and /v1/transaction/{id} response bodies.
  - Checks malformed height, malformed transaction ID, POST rejection and explicit archive-only not-found semantics.
  - Builds and commits a longer competing branch; verifies the original transfer receipt changes from canonical to reorged, while the selected canonical block at height 1 no longer contains that transfer.
  - Reopens the durable runtime and verifies the account/supply snapshot, canonical block and reorged receipt survive restart.
- QFP6 supervisor regression module: 19 passed, 0 failed.
- cargo check --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node --locked --offline: PASS.
- cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --check: PASS.
- git diff --check: PASS.

The compiler reported existing unrelated unused/dead-code warnings. No new build error remained.

## Proof/trust boundaries and preserved state

- Responses remain bound to canonical height, QFP6 consensus tip and QFB6 execution state root. They do not provide an account Merkle/inclusion proof; /v1/account continues to report global_state_root_only and account_inclusion_proof=null.
- Independent monetary verification still requires full-node replay from independently trusted Genesis/checkpoint inputs and reproduction of the same state root.
- Block reads are limited to bodies retained above the active fork-store base/checkpoint. Transaction lookup is limited to the currently retained fork archive and does not inspect the mempool or historical segments no longer in that graph.
- A confirmation count is not a finality certificate.
- The HTTP listener remains disabled unless explicitly configured. No public socket was opened.
- No Mainnet package/config digest was rewritten, no Q6GA v3 authorization was created, and no QZKW2 wallet/owner key was opened. Any future config change requires a fresh local owner authorization over the exact bytes and an explicit manual approval.
- No Mainnet launch, public Testnet launch, public endpoint, exchange, price or liquidity is claimed.
- PID 20244 / TCP 30333, its old CP-0596 binary and datastore were not touched.
- Gate 2 and Gate 8 were not re-tested or reclassified. Their state remains owner-reported complete in the continuation record; this checkpoint adds no independent receipt for either gate.
- No private key, seed phrase or plaintext DPAPI material was read.

## Next engineering steps

1. Provide an authenticated, independently reproducible full-node verification workflow for account and block/root reads; add a real per-account inclusion proof only if the committed state structure supports it.
2. Add historical segment/archive indexing if explorer history must survive checkpoint rollover; retain explicit mempool status as a separate surface.
3. Cross-check the exact read API responses against a second independently operated node before any public endpoint is exposed.
4. Review exact Mainnet API bind settings and peer set, regenerate the Q6GA v3 digest, and require a fresh local QZKW2 owner approval only after manual review. Keep public bind disabled until expressly authorized.

This checkpoint completes local candidate implementation and regression validation of canonical block/transaction reads. It does not qualify a public monetary service or activate a network listener.
