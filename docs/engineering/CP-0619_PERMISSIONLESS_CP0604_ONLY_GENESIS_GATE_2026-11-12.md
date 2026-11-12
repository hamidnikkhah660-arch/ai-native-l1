# CP-0619 ? Permissionless runtime requires CP-0604 Genesis

Status: implemented and locally validated; candidate-only, not Mainnet authorization.

## Finding

The shared QFP6 Genesis snapshot verifier intentionally retains CP-0528 compatibility. The permissionless launcher previously reused that verifier and then called `validate_consensus_parameters`. That method checks the selected issuance schedule when a CP-0604 policy exists, but legacy CP-0528 states remain valid for compatibility. As a result, the new permissionless startup path did not independently forbid the obsolete founder-allocation policy.

## Change

The permissionless launcher now applies an explicit CP-0604-only gate after decoding and verifying the Genesis snapshot, and before opening durable storage or binding the network listener. It rejects:

- Genesis snapshots without CP-0604 supply state (including legacy CP-0528);
- any legacy tokenomics component;
- founder account or CP-0604 policy fingerprint mismatch;
- any pre-mining issuance;
- founder balance other than the exact CP-0604 7B Genesis credit;
- Ledger total inconsistent with CP-0604 gross issuance accounting.

The existing `validate_consensus_parameters` call remains in place and binds the CP-0604 mining schedule to the exact Q6CP issuance parameters. Shared historical readers and private compatibility paths retain their previous behavior; the stricter rule is specific to permissionless QFP6 startup.

## Validation

- New regression: a CP-0528 Genesis is rejected; a CP-0604 7B/3B Genesis with matching founder and policy fingerprint is accepted; mismatched founder and fingerprint are rejected.
- `cargo test --bin qrun_v06_node --locked --offline`: 27 passed, 0 failed.
- `cargo check --all-targets --locked --offline`: passed.
- `cargo fmt --check`: passed.
- `git diff --check`: passed.

Existing unrelated compiler warnings remain. This change does not create the six release artifacts, choose production consensus parameters, create external trust authorities or seed operators, sign Genesis, or authorize public mining/Mainnet.
