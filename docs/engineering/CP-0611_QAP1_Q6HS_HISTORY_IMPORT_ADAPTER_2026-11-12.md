# CP-0611 - QAP1-gated Q6HS history-page import adapter

Date: 2026-11-12
Status: candidate library adapter implemented; not connected to the node executable or live peer-sync loop.

## Change

`qrun_v06_history_sync_service_candidate::import_history_page_with_qap1` accepts a decoded, snapshot-pinned Q6HS page and a `QRunV06NodeRuntime` recovered through the QAP1 path. It refuses import unless QAP1 recovery was verified, no reopen/recovery is required, and no external anchor is pending.

Before importing, it checks page continuity against the independently committed Q6EA state, validates page boundaries and snapshot completion metadata, verifies the existing durable fork-choice tip, and validates the terminal PoW digest for a complete page. Each envelope is then submitted individually through `submit_envelope_with_qap1`; only an acknowledged Provider/Q6EA transition permits the next block. An anchor-pending result or any admission error stops the page immediately. The acknowledged prefix remains durable and the normal QAP1 restart recovery path is required after interruption.

This intentionally avoids adapting the QAP1 runtime into the non-QAP1 `QRunV06PermissionlessNodeRuntime` or calling its legacy `import_history_batch` path. No anchor guarantee is weakened to obtain bulk import semantics.

## Verification

- `cargo check --all-targets --locked --offline`: passed.
- `cargo fmt --all -- --check`: passed after formatting.
- `git diff --check`: passed.
- QAP1 runtime regression tests, serial execution: 30 passed, 0 failed. Serial execution avoids collisions in test fixtures that share temporary Q6EA writer-lock paths; an initial parallel run produced two `WriterLockHeld` fixture collisions, both passed on serial rerun.
- The history-sync service currently has no dedicated `tests` module; no test count is claimed for the new page-import function itself. A dedicated integration test with independently pinned Provider/Q6EA test authorities remains required.

## Still not done

- `sync_history_from_pinned_peer` and `sync_history_from_pinned_peer_until_complete` still take the non-QAP1 permissionless runtime. The new importer is not yet used by a QAP1-aware Noise/Q6HS download loop.
- The QAP1-aware listener/supervisor is not wired to this importer or to `qrun_v06_node`.
- The executable `--run` guard remains closed. No public listener, mining, Mainnet, or exchange is enabled.
- The six release artifacts and independently provisioned peer/trust inputs from CP-0609 remain missing.

## Next safe engineering step

Factor the Q6HR/Q6HP Noise transport loop behind a narrowly scoped page-source interface, then implement a QAP1 client that calls this importer for every decoded page and rechecks the source snapshot against the final independently anchored state. Add an integration test that interrupts after a confirmed page prefix, restarts through QAP1 recovery, and resumes from the exact next height. Only after that should the executable orchestration be considered.