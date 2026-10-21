# CP-0364 — live TXN4 invalid-signature rejection and mempool isolation

Date: 2026-10-21
Base main commit: 8beb6b63c6ed883272ec526d96bb4382619606f9
Scope: negative HTTP admission evidence added to the CP-0363 two-node loopback runner; no runtime/protocol source changed.

## Change

Extended `simulations/cp0363_txn4_two_node_loopback.ps1` to submit a TXN4 fixture with one signature byte flipped before submitting the valid fixture. The node must reject the mutated transaction via the actual `/tx/submit` HTTP handler with HTTP 422 and `transaction_rejected`. The subsequent valid TXN4 must be admitted with `mempool_count=1`, proving the rejected attempt did not poison or partially populate the mempool.

The rest of CP-0363 remains in the same run: the valid TXN4 is included in a height-1 PMT4 block, propagated to a second authenticated loopback node, matched by state root and tip, and replayed by both PFM4 stores.

## Execution

Command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File simulations/cp0363_txn4_two_node_loopback.ps1
```

Observed result: **PASS**, exit code 0; runtime 41.87 seconds. PowerShell AST parse passed. Release build completed with existing non-fatal unused/dead-code warnings.

Runner output includes:

- `CP-0364 INVALID_SIGNATURE_HTTP_REJECT_PASS http=422`
- `CP-0363 TXN4_SUBMIT_PASS ... http=202` (valid fixture TXID matched the HTTP response)
- `CP-0364 INVALID_THEN_VALID_MEMPOOL_PASS count=1`
- `CP-0363 TWO_NODE_CONSENSUS_PASS height=1 ...`
- `CP-0363 TXN4_TWO_NODE_REPLAY_PASS nodeA_height=1 nodeB_height=1 replay=matched`

## Scope and gate status

- Same-host Windows loopback with a local diagnostic PMT4/PFM4 candidate profile, local easy test PoW and disposable fixture/Noise test keys only.
- The negative check exercises live HTTP parsing, candidate signature verification and mempool admission isolation. It is not independent-host qualification, production identity/key custody, nor a security audit.
- No runtime/protocol source changed. This test does not freeze the production Genesis or prove the lifetime supply cap across all canonical runtime paths.
- Gate 2 remains OPEN; Gate 8 remains OPEN; public-sale S1 remains OPEN. No production Mainnet, public QZXB issuance, public market/liquidity, listing, external audit or revenue is claimed.
