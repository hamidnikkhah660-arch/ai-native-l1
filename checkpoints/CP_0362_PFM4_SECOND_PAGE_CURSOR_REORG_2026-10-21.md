# CP-0362 — PMT4/PFM4 page-2 cursor reorg refusal

Date: 2026-10-21
Base main commit: 5aeefd9daa551e138ea73467ad6d98c75d250d76
Scope: end-to-end regression evidence; no runtime source changed.

## Change

Added `simulations/cp0362_pfm4_page2_cursor_reorg.ps1` to cover the later-cursor case that CP-0305 did not cover. It deliberately uses a one-item-per-page archive configuration and the existing explicit-only `--test-reorg-after-second-archive-range-page` test hook. This avoids simply rerunning the page-1 CP-0305 experiment.

## Execution

Command on the authorized Windows developer machine:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File simulations/cp0362_pfm4_page2_cursor_reorg.ps1
```

Observed runner result: exit code 0; runtime 168.60 seconds.

The runner:
1. Seeded a disposable PMT4/PFM4 baseline branch at height 3.
2. Started two local loopback node processes using distinct DPAPI-protected test key files and mutually pinned Noise peer identities; archive page size was one item.
3. Observed the client accept archive page 1 / block height 1 and page 2 / block height 2.
4. Observed the source reorg after page 2 to canonical height 4; log event binds `trigger_page=2`.
5. Observed the old page-3 continuation cursor rejected as stale because the PFM4 startup snapshot anchor changed.
6. Asserted that the source did not serve page 3 from its stale snapshot and the client did not accept heights 3 or 4.
7. Read status endpoints and verified source height 4 / client height 2.
8. Waited for both processes to stop and verified PFM4 replay reports `replay=matched` for source height 4 and client height 2.

Key assertion output:

- `CP-0362 INFLIGHT_CURSOR_REORG_PASS first_page_sent=true second_page_sent=true accepted_prefix=2 source_reorged=true stale_page3_rejected=true`
- `CP-0362 HEIGHTS_PASS source_after_reorg=4 client_stopped_at=2`
- `CP-0362 REORG_REPLAY_PASS source_height=4 client_height=2 replay=matched`

PowerShell AST validation: PASS. The runner builds the release `devnet_node` and `noise_key_provisioner` before starting the scenario. Existing non-fatal unused/dead-code compiler warnings were present.

## Boundaries

- This is same-host Windows loopback evidence, not independent-host/client compatibility or multi-operator testnet evidence.
- It uses the explicitly opted-in zero-value PMT4/PFM4 diagnostic profile, local test difficulty, and the test fault hook. It does not validate production mining difficulty, production transaction authentication/mempool/RPC, or public networking.
- No production key was generated; key files and test data were disposable local artifacts and are not committed.
- Gate 2 remains OPEN. This verifies one stale-cursor boundary; it does not freeze the canonical production Genesis/profile or integrate all issuance, fees and the 10B cap through one reviewed producer/import/fork-choice/store/replay/snapshot path.
- Gate 8 remains OPEN; local manifest anchoring is not an independent monotonic trust authority.
- Public-sale S1 remains OPEN. No native QZXB Mainnet, public coin issuance, market, liquidity, listing, external audit or revenue is claimed.

## Next

Prioritize a reproducible independent-client/host run with the same frozen vectors and continue the canonical monetary runtime integration described in Issue #2. Do not promote this same-host smoke test into a production gate pass.
