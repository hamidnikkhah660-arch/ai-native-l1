# CP-0633 — Public Testnet Launch Guard and Validation
Date: 2026-11-13
Project: QuantumZXB / QRun native L1 / QFP6
Repository: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Branch: feat/cp0600-bootstrap-sync-startup
Base HEAD: df673d07050688a64b26822d97e6ea609b68ce88
Status: LOCAL CANDIDATE IMPLEMENTATION — NOT RELEASED, NOT PUBLICLY DEPLOYED

## Scope completed
- Added a distinct `--public-testnet-run` CLI path. It is separate from `--permissionless-run`.
- Exported `run_public_testnet_node` through the QFP6 launcher module.
- Added explicit zero-value / no-Mainnet acknowledgement and anonymous inbound Noise XX acknowledgement gates.
- Required `node_role` to be exactly `seed` or `joining`.
- Enforced seed topology with no configured bootstrap peers; joining topology requires at least one pinned, globally routable peer.
- Added strict bootstrap IP admission checks covering private, loopback, link-local, multicast, CGNAT, documentation, benchmarking, transition and selected special-use IPv4/IPv6 ranges; IPv4-mapped IPv6 is normalized through the IPv4 filter.
- Moved public TCP listener bind until after local key loading, runtime open, mempool restore and supervisor configuration validation.
- Kept public launch opt-in explicit; ordinary permissionless mode rejects public-listener opt-in.

## Validation evidence
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml`: completed.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --check`: PASS.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node --locked --offline -- --nocapture`: PASS — 32 passed, 0 failed.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: PASS, exit code 0.
- `git diff --check`: PASS, exit code 0.
- Build emits pre-existing unused-import/dead-code warnings in unrelated files; no warning was promoted to an error.

## Known limitations / release blockers
The current `release/qfp6-candidate/manifest.json` was inspected and remains explicitly not authorized:
- `production_authorized=false`; `mainnet_status=NOT_AUTHORIZED`.
- Genesis snapshot, Q6GD descriptor, Q6CP consensus profile, Q6PN network profile, Q6TS trust bundle and bootstrap peer artifacts are marked MISSING.
- Independent consensus, cryptography and economics reviews remain PENDING.
- Full-history replay and public listener qualification remain false.
- Public peer discovery remains unqualified/unimplemented.
- Inbound Noise XX is anonymous and unauthenticated; remote static identity is not authenticated and an active MITM can terminate/re-encrypt the transport.
- Serial inbound handshake / head-of-line and multi-host load/DoS qualification remain open.
- No independent multi-host seed/joining test, external network reachability test, firewall/router change, public port exposure or public node launch was performed.

## Worktree / safety
- No commit or push was created.
- No QRun node was launched.
- No port or firewall was opened.
- Existing uncommitted CP-0631 peer-address-manager work was preserved; it was not overwritten by this checkpoint.
- All changes remain local and uncommitted. Re-review the complete diff before any commit or deployment.

## Next authorized engineering gate
Provision and independently review the canonical Genesis/Q6GD/Q6CP/Q6PN and bootstrap artifacts; then perform isolated seed/joining integration tests on two or more controlled hosts, verify full-history replay and public listener resilience, and update the release manifest only when each gate has direct evidence. Do not promote to Mainnet or claim public-testnet readiness before these gates pass.
