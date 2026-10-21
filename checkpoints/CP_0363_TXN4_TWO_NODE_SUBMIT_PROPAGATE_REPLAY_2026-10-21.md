# CP-0363 — PMT4/TXN4 two-node submission, propagation and replay

Date: 2026-10-21
Base main commit: 8d1ba78d2fc823c41297317650a016eba3295920
Scope: executable loopback regression evidence; no protocol/runtime source changed.

## Change

Added `simulations/cp0363_txn4_two_node_loopback.ps1`. It uses the existing test-only `txn4_loopback_fixture` example and two PMT4/PFM4 node processes bound to loopback. Node A exposes the bounded `/tx/submit` HTTP API and is allowed to mine one block; node B receives and validates the resulting PMT4 block as an authenticated peer. Founder identity is derived from the test fixture public keys so that the same candidate Genesis/manifest is used on both nodes.

The runner provisions fresh, network-bound, DPAPI-protected loopback Noise keys, picks ephemeral local ports and writes all test data under the Windows temporary directory. The fixture reports `private_keys_written=false`; no production key is generated or used.

## Execution result

Command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File simulations/cp0363_txn4_two_node_loopback.ps1
```

Observed initial result: **PASS**, exit code 0, runtime 41.79 seconds. PowerShell AST parse passed. Release builds of `devnet_node`, `noise_key_provisioner`, and `txn4_loopback_fixture` completed; existing unused/dead-code compiler warnings were non-fatal.

### Repeat run on current main (commit `866737881c16b1bb1e297bb59d8af8a1068a43e1`)

A new execution of the same runner passed on 2026-10-21 with exit code 0 in 44.71 seconds. This commit also contains the invalid-signature HTTP regression. Additional assertions confirmed:

- A copy of the signed TXN4 wire with the final byte flipped was rejected by `/tx/submit` with HTTP 422 and `transaction_rejected`.
- Immediately submitting the untouched valid wire returned HTTP 202, the expected TXN4 ID `5af7df1b9a524d9fed4dd7cf4bee767a7d228d843042a29cafc314b29ececa72`, and `mempool_count=1`.
- Node A broadcast one transaction in height 1 (`peers=1`, `duplicate_broadcast=false`), with block/tip `a0e109d1607baf3607099684fa3790b2448803b3f541225a65b99286b198ed36` and state root `5b36cb42a56c144359f4fee104068622d661880bcbfb0644425348066b150e7f`.
- Node B's acknowledgement and `/status` state matched the broadcast root/tip; both nodes then reported `height=1 ... replay=matched`.

This is still same-host loopback evidence; the new Windows CI job in the accompanying change will make the scenario repeatable on hosted Windows runners.

Assertions observed:

1. Fixture and both node manifests matched exactly.
2. An actually signed TXN4 fixture was POSTed as an exact binary `application/octet-stream` body to `/tx/submit`; response was HTTP 202 with `status=accepted`, and the returned transaction ID matched the fixture ID.
3. Node A accepted the TXN4 into its bounded mempool, included exactly one transaction in a height-1 PMT4 block, and broadcast it over the authenticated Noise loopback peer connection.
4. Node B acknowledged the block with the accepted protocol status, reached height 1, and reported the exact same state root and canonical tip as node A's broadcast event.
5. Both processes stopped within their bounded run and each PFM4 store reported `replay=matched` at height 1.

Runner assertion output:

- `CP-0363 TXN4_SUBMIT_PASS ... http=202`
- `CP-0363 TWO_NODE_CONSENSUS_PASS height=1 ...`
- `CP-0363 TXN4_TWO_NODE_REPLAY_PASS nodeA_height=1 nodeB_height=1 replay=matched`

Test artifacts are in a temporary directory on the authorized developer machine and are not committed.

### Fresh rerun on main commit e2af2ad (after multiline-log matcher fix)

The runner was repeated against the current main checkout. The first attempt stopped before node launch because the harness's regular expressions assumed the ready-event fields were all on one line; the node emitted the same event across multiple log lines. The matcher was corrected with PowerShell single-line regex mode `(?s)`, then the end-to-end run passed:

- Exit code 0; runtime 41.38 seconds.
- Mutated-signature request rejected with HTTP 422.
- Valid fixture transaction ID: `f3c8785755e3e681c68e314b389004a327485027be61e0d22af87bbdecdf6f98`; HTTP 202 accepted.
- Node A broadcast height 1 with state root `83124fed5c4a42ca20e3730dfc61df8c8527c82c358a208d77b445e94de273fa` and tip `40f067778d5914b3206cd4eaceeea7e2839363c544d55207e1ba1a5b19028612`; node B matched both values.
- Consensus assertion passed at height 1; both PFM4 nodes stopped with `replay=matched`.

This rerun only changes test-runner log matching; no Rust runtime or wire behavior changed. The full terminal output was captured during the run, and the temporary artifact directory was `%TEMP%\ain1_cp0363_txn4_two_node_8da66c270a8f4319b09c24e485d26554`.

## Boundaries and decision

- Same-host Windows loopback only; not a public testnet, independently administered multi-host run or independent-client implementation agreement.
- Explicit PMT4/PFM4 diagnostic candidate profile with local easy test PoW and test-fixture identity only; not production network parameters or production custody.
- The API, mempool, TXN4 validation, block creation, peer import, state-root/tip agreement and process replay were exercised together for one test transaction. This does not freeze final Mainnet policy, prove the full 10-billion lifetime supply cap across every runtime path, qualify forks/reorgs economically, or provide external security review.
- Gate 2 remains OPEN. Gate 8 remains OPEN because a local manifest anchor is not an independent rollback authority. Public-sale S1 remains OPEN.
- No native QZXB Mainnet, public coin issuance, public liquidity/market, listing, external audit or revenue is claimed.

## Next

Qualify the same canonical behavior from an independently built client/host, expand adversarial/multi-transaction and reorg coverage, and prioritize freezing/integrating the production Genesis/network/wire/monetary policy through one canonical runtime before any production-value launch.
