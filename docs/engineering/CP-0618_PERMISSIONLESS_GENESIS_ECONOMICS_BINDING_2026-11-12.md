# CP-0618 ? Permissionless Genesis / Q6CP monetary-policy binding

Status: implemented in the candidate launcher; not Mainnet authorization.

## Change

The `--permissionless-run` launcher already verified the Q6PN-pinned Q6GD descriptor, the exact Genesis snapshot digest, and the decoded canonical execution state. CP-0618 closes an additional executable-boundary gap: immediately after decoding the Genesis snapshot, and before resolving/creating durable runtime state or binding the P2P listener, the launcher now calls `QRunV06CanonicalExecutionState::validate_consensus_parameters` with the exact parameters decoded from the independently hash-pinned Q6CP artifact.

This requires the Genesis economic policy and selected consensus issuance parameters to agree. For the CP-0604 path this includes the 10B gross issuance ceiling, the policy-selected mining subsidy and halving schedule, and the Genesis descriptor's founder/policy/consensus binding. A mismatch fails closed before runtime startup.

## Validation

- `cargo test --bin qrun_v06_node --locked --offline`: 26 passed, 0 failed.
- `cargo check --all-targets --locked --offline`: passed.
- `cargo fmt --check`: passed.
- `git diff --check`: passed.
- Existing warnings in unrelated legacy modules remain; no new warning was reported for this change.

## Explicitly not claimed

This change does not generate or sign Q6GD/Q6CP/Q6PN, choose a Genesis timestamp or production consensus parameters, provision trust roots or public seed operators, authenticate anonymous inbound Noise XX peers, authorize public mining, publish Mainnet, or create QZXB/USDT liquidity. The six candidate-package artifacts remain externally provisioned trust inputs. The production approval gate remains closed until those inputs and the independent network/security qualification are complete.
