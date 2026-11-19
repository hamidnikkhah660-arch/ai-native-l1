# CP-0784 - Publicly Verifiable Monetary Read API

Date: 2026-11-19
Base: CP-0783 / `373ed0b449bade4297358136c59df58db33343ee`
Branch: `feat/q6ga-v3-mainnet-scope-20261119`

## Result

Implemented and locally validated the first native QFP6 read-only monetary API. This checkpoint makes canonical account balances and CP-0651 supply facts queryable from the runtime that owns the canonical state. It does not activate a listener, launch Mainnet, or claim that public real-value transfers are live.

## Canonical runtime reads

`QRunV06PermissionlessNodeRuntime::canonical_account_read`:

- Reads the selected canonical execution state from the durable fork graph.
- Recomputes the execution state root and checks that height, tip hash and root agree with the runtime status snapshot before returning a value.
- Returns network/profile/native-asset/account IDs, balance atoms, nonce, height, tip and state root.
- Represents an account absent from the ledger as `None`; it never fabricates a funded Genesis balance.

`QRunV06PermissionlessNodeRuntime::canonical_supply_read` applies the same height/tip/root consistency check and returns the actual canonical ledger total plus the CP-0651 fixed-supply policy values and policy fingerprint.

## Read-only HTTP routes

- `GET /v1/status` - network/profile IDs, canonical height, tip, state root, manifest generation and consensus fingerprint.
- `GET /v1/account/{64-hex-account-id}` - canonical native balance in atoms, nonce and the exact snapshot identifiers.
- `GET /v1/supply` - actual ledger total, owner Genesis allocation, maximum supply, block subsidy, accounting-label budget and policy fingerprint.

All monetary atom amounts and large counters are encoded as decimal strings in JSON, avoiding IEEE-754 rounding in JavaScript clients. The CP-0651 supply response explicitly marks `accounting_labels_are_minted=false`. At Genesis, the test verifies an actual owner ledger balance of `100,000,000,000,000,000` atoms, a `700,000,000,000,000,000` atom gross ceiling, zero block subsidy and `600,000,000,000,000,000` atoms of accounting labels that are not minted or spendable balances.

The API is strictly GET-only. Unsupported methods return HTTP 405. The listener is separate from the P2P listener and is polled by the supervisor on the runtime-owning thread, avoiding a separately copied or concurrently mutated canonical state. It handles at most one request per supervisor tick, caps the request line at 512 bytes, uses 250 ms socket timeouts and sends `Cache-Control: no-store`. Client disconnect/read/write errors are isolated and do not stop the consensus supervisor.

## Listener activation and authorization boundary

The API is disabled when no read API address is configured. The optional `permissionless_runtime` configuration keys are:

- `read_api_listen_address`: explicit socket address on a port separate from P2P and all pinned outbound peer endpoints.
- `allow_public_read_api`: must be `true` before a non-loopback bind is accepted. Non-loopback binding is accepted only in Mainnet mode.

The listener is bound only after runtime preparation and P2P listener setup. Merely implementing the API does not open a port. These fields are part of the exact runtime configuration bytes covered by the Q6GA v3 configuration digest. If either field is added or changed in the Mainnet package, the old CP-0783 authorization cannot be reused: the exact new config must be reviewed and signed locally again through QZKW2. No wallet or owner key was opened for this checkpoint.

## Proof and trust limits

Responses bind values to a canonical height, tip and global execution state root. The API reports `proof_type=global_state_root_only` and `account_inclusion_proof=null` for account reads. A global root is not, by itself, a Merkle inclusion proof for an individual account. Independent verification still requires a full node to replay the chain from trusted Genesis/checkpoint inputs and reproduce the same state root. The API is a read interface, not an independent trust oracle.

Transaction lookup, block-by-height lookup, transaction receipts and account inclusion proofs are not implemented in this checkpoint. A public explorer is not included.

## Validation performed

- CP-0651 canonical account/supply/API test: 1 passed, 0 failed. It verifies exact Genesis atoms, absent-account behavior, account JSON response, supply JSON values, GET-only rejection, a real loopback HTTP request, and account/supply equality after runtime restart.
- QFP6 supervisor regression module: 19 passed, 0 failed.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node --locked --offline`: PASS.
- `cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --check`: PASS.
- `git diff --check`: PASS.

Existing unrelated dead-code/unused-import warnings remain; no new build error was observed.

## Explicit non-claims and preserved state

- No read API listener was activated and no public socket was opened.
- No Mainnet package was rewritten or owner signature produced.
- No Mainnet Genesis was promoted; no public real-value transfer or spendable public balance is claimed.
- No independent public operator, peer reachability or public network launch was newly verified by this checkpoint.
- Gate 2 and Gate 8 were not re-tested or reclassified by this work.
- Existing PID 20244 and TCP port 30333 were not stopped, restarted, replaced or reconfigured.
- No private key, seed phrase, DPAPI plaintext or owner wallet material was read.

## Next engineering steps

1. Add the exact desired read API bind settings to the reviewed Mainnet package, recompute the full configuration digest, and obtain a fresh local Q6GA v3 owner authorization for those exact bytes. Keep public binding off until the operator explicitly approves it.
2. Add canonical transaction and block lookup from the durable fork graph, with receipts and reorg/restart semantics.
3. Add account inclusion proofs if the state commitment supports them; otherwise publish a reproducible full-node verification procedure and never label the global root as an account proof.
4. Cross-check the API from a second independently operated node before exposing it as a public monetary reference.
5. Connect the public explorer only to these canonical read surfaces; the explorer must not become the source of truth.