# CP-0606 - CP-0604 permissionless supervisor lifecycle integration

**Date:** 2026-11-12  
**Status:** Local candidate integration test and offline validation passed; no production launch authorization.

## Implemented

- Added `cp0604_permissionless_supervisor_mines_and_recovers_durable_genesis_state` to `qrun_v06_node_supervisor_candidate`.
- The test constructs a CP-0604 Genesis state and profile descriptor, verifies a Q6PN pin against a separate test commitment, opens the permissionless durable runtime and persistent transaction journal, and enters the bounded permissionless mining supervisor on an ephemeral loopback listener.
- It asserts at least one block was durably committed and selected as canonical, then reopens the same store with the previously recorded manifest anchor and checks height, tip, state root and generation.
- Test-only identities, Noise keypairs, provider pins and easy SHA-256d parameters are generated inside the test process. No production or founder private key is used and no live endpoint is contacted.

## Validation

- Focused CP-0604 supervisor lifecycle test: **1 passed**.
- Full library suite: **1370 passed, 0 failed**.
- `cargo check --all-targets --locked --offline`: passed.
- `cargo fmt --check`: passed.
- `git diff --check`: passed.

Existing compiler warnings in unrelated library/binary targets remain; there were no compilation errors.

## Exact boundary / remaining launch gates

- This test exercises the library supervisor lifecycle and local mining/store recovery. It does not qualify a real peer-to-peer bootstrap, independent-host history sync, public network topology, live Q6TS trust-floor access, Provider/Q6EA anchored publication, or Mainnet consensus parameters.
- `qrun_v06_node --run` remains deliberately disabled; the executable still only exposes read-only preflight and QAP1 probe modes.
- `release/qfp6-candidate/` still has no actual Genesis snapshot, Q6GD, Q6CP, Q6PN, Q6TS or pinned bootstrap peer set. The local user profile also has no provisioned protected QFP6 node Noise key file.
- The permissionless supervisor test does not substitute for the QAP1-anchored runtime/supervisor path required for anti-rollback publication and independent restart qualification.
- Public listener, public mining, Mainnet Genesis signing/activation and QZXB/USDT trading remain disabled/not established.

No trust material, keys, endpoints, production parameters or market liquidity were fabricated. The executable launch guard and PR merge boundary remain unchanged.
