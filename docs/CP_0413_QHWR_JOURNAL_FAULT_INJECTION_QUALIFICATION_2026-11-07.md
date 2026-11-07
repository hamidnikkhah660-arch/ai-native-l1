# CP-0413 - QHWR Journal Fault-Injection Qualification

Date: 2026-11-07
Status: Test-only hardening candidate. No production integration is claimed.

## Scope

CP0413 adds test-only fault injection to the CP0412 append-only operation journal candidate. The hooks are compiled only under `cfg(test)` and cannot be selected by production callers. The tests exercise interruption before any write, after the frame header, after payload, after checksum but before sync, and after sync but before the caller receives acknowledgement.

## Observed recovery rules

- Failure before writing leaves the previous state intact after reopen.
- An incomplete header or payload tail is truncated during recovery while previously acknowledged records remain intact.
- A complete frame that is present after a pre-sync interruption may be adopted on reopen even though the original caller received an error. This is an ambiguous outcome, not proof that the interrupted sync completed or that the bytes survived power loss. The caller must retry/resolve using the exact same operation key and identity; it must not create a new operation key.
- A lost acknowledgement after successful `sync_all` recovers the exact committed reservation on reopen.
- Once an append attempt becomes ambiguous, the live journal handle is poisoned and rejects further mutations until reopened.

## Test coverage

The focused Windows suite contains 14 tests covering lifecycle/reopen, exact response bytes, idempotent retries, illegal transitions, oversized frame rejection before allocation, checksum corruption, partial header/payload tails, one-writer locking, and the fault points listed above.

## Important limitations

These are deterministic control-flow fault injections, not real disk-controller, filesystem, power-cut, or kernel I/O fault tests. In particular, the injected pre-sync error is raised after complete bytes have been passed to `write_all`; it does not emulate an actual failing `sync_all`. The post-sync fault models lost acknowledgement after `sync_all` returns, not a dishonest storage device. Platform-specific power-loss durability, actual write/sync error injection, multi-host linearizability, independent anti-rollback, CP0406 external replay authority, CP0410 durable signer implementation, and production dispatcher integration remain unproven.

Public Mint remains disabled. This branch is stacked on CP0412 and must remain Draft pending broader qualification and independent review.
