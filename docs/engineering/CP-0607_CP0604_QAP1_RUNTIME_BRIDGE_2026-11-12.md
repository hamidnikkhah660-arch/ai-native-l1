# CP-0607 - CP-0604 verified-store to QAP1 runtime bridge

**Date:** 2026-11-12  
**Status:** API integration implemented; all-target offline compile and full library suite passed. This is not production launch qualification.

## Implemented

Added `QRunV06PermissionlessNodeRuntime::open_qap1` as the bridge from the CP-0604 Genesis/profile-pin durable store to the existing QAP1-required `QRunV06NodeRuntime`.

The constructor:

1. Opens the durable store only through `open_with_verified_profile_pin`, validating Genesis descriptor, network/profile identity, founder/economic policy fingerprint and consensus fingerprint.
2. Requires exact equality between the Q6PN provider pin, QAP1 Provider pin, Q6EA pin, Genesis digest and Genesis descriptor commitment before opening the store.\n3. Does not infer external trust from the local manifest.
4. Passes the opened store to `recover_qap1_after_process_restart`, which reconciles any unresolved QAP1 journal against the separately pinned Provider and Q6EA services before returning an admission-capable runtime.
5. Returns a distinct `Qap1Recovery` error if independent recovery cannot be completed.

The existing base `open` path remains unchanged and still refuses unresolved QAP1 intents. The executable `--run` guard remains unchanged.

## Validation

- `cargo check --all-targets --locked --offline`: passed.
- Full library suite: **1370 passed, 0 failed**.
- The preceding CP-0606 supervisor mining/restart test remains green in the full suite.

## Remaining qualification gates

- The new bridge is a library API; it is not yet wired into `qrun_v06_node --run` or a production supervisor process.
- The current `release/qfp6-candidate/` package still contains only `manifest.json` and `README.txt`; actual Genesis snapshot, Q6GD, Q6CP, Q6PN, Q6TS and independent commitment records are not provisioned there.
- No independently authenticated Q6EA/Provider deployment pins and verifier keys, protected node Noise key, or trusted bootstrap peer identities/endpoints were found/provisioned.
- No independent second-host history-sync/restart qualification was performed for this CP-0604 path.
- Public listener/mining, Mainnet activation/signing, and QZXB/USDT trading remain disabled/not established.

No production trust records, private keys, endpoints or Genesis signatures were fabricated. No PR merge or Mainnet activation was performed.

