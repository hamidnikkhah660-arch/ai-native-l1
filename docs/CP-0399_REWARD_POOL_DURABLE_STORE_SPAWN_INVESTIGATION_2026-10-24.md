# CP-0399 — Windows reward-pool child-process spawn investigation

**Date:** 2026-10-24  
**Status:** Not reproduced in this controlled run; underlying cause remains undetermined.

## Incident preserved

The prior full library run recorded **791 passed, 1 failed** for:

**reward_pool_durable_store::tests::independent_process_writers_leave_only_a_complete_committed_snapshot**

The recorded failure included Windows **Access is denied (os error 5)** from a child-process path and exit status 101. A later full offline test run on CP-0398 passed; the earlier failure is not erased by that success.

## Code-path finding

The test uses the current Rust test executable as the child process. It spawns four independent copies of the same test, uses uniquely named readiness files in the current temporary directory, releases the writers through a shared barrier, and then verifies that the final snapshot is one complete committed candidate. The spawn failure point is **Command::new(&executable).spawn()**, before that child can execute the writer's save path.

Therefore, an **Access is denied** error returned by spawn is evidence of a process-creation/launch failure; it is not evidence that the snapshot codec, checksum or atomic replacement rejected the data. The available record does not identify which operating-system component denied the launch.

## Controlled reproduction

Command, run from **src/native/pow_bench**:

**cargo test --locked --offline --lib reward_pool_durable_store::tests::independent_process_writers_leave_only_a_complete_committed_snapshot -- --nocapture --test-threads=1**

- Six separate serial invocations completed successfully: **6/6 passed**.
- Each invocation exercised the test's internal four-child writer race.
- Observed test durations were approximately 0.12–0.19 seconds per invocation.
- No Access is denied or exit-status-101 event reappeared during this controlled sample.

This reduces evidence for deterministic reproduction under the current local conditions. It does not establish a root cause and does not prove that the problem cannot recur in a parallel full-suite run or on another Windows host.

## Diagnostic change

The spawn error now reports the exact executable path, **io::ErrorKind**, raw OS error code and error string. This is diagnostic-only: it does not reduce the child count, ignore errors, retry a denied spawn, change the locking contract or turn the test into a pass on failure.

## Hypotheses not proven

Potential areas to examine if it recurs include a transient Windows process-launch denial, executable access/locking, temp-directory or executable ACLs, or external endpoint-security interference. None is confirmed by the current evidence. No security controls were disabled and no access-control exclusions were added.

## Follow-up if it recurs

1. Preserve the full test output, exact commit SHA, runner identity, executable path and raw OS error.
2. Determine whether the failure is at process creation or inside a started child's filesystem operation; do not collapse both into a generic Windows I/O failure.
3. On an authorized host, inspect Windows event/security logs and use process-monitoring evidence to identify the denying component.
4. Compare isolated, serial and full-suite runs, preserving both successes and failures.
5. Only change the production/test design when evidence identifies a defect; do not remove the concurrency test or soften its assertion to hide the incident.

## Current decision

The issue is **not closed**. Current evidence says “not reproduced in 6 controlled runs; cause unknown,” not “fixed.” Continue to retain the original failure in gate evidence until a repeatable root cause and a verified corrective action exist.
