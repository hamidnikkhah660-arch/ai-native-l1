# CP-0649 — Two-Source Noise Bootstrap Agreement: End-to-End

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Depends on: CP-0647, CP-0648  
Branch: feat/cp0600-bootstrap-sync-startup  
Observed HEAD before checkpoint write: df673d07050688a64b26822d97e6ea609b68ce88  
Status: implemented and locally validated; working tree only

## Objective

Exercise the CP-0648 multi-source bootstrap agreement gate with two independent Noise XX servers, not only synthetic report values. The test proves the real Q6HI/Q6HR/Q6HS sync results can be imported into one local fork archive and passed to the same source-snapshot validation function called by the permissionless bootstrap supervisor.

## Test harness

A shared integration fixture creates:

- one pinned QRun Genesis/profile and one local destination runtime;
- two separate source runtimes, each validating a first block from the same Genesis;
- two independent server Noise static-keypairs and two independent client keypairs;
- two loopback TCP listeners on ephemeral ports;
- one distinct operator-assigned trust-domain identifier per source;
- bounded one-page Q6HS synchronization sessions.

The second source timestamp is parameterized. Zero offset produces identical deterministic first-block history; a nonzero offset produces a valid sibling branch from the same Genesis. The test uses the same fixture for both cases.

## Verified cases

1. **Consistent independent sources — PASS**
   - Two independent Noise servers report the same consensus tip and execution tip.
   - The destination imports both source histories.
   - Both report tips are present in the destination's validated fork-choice archive.
   - The supervisor's `validate_bootstrap_source_snapshots` gate accepts the two distinct trust domains.

2. **Divergent independent sources — PASS**
   - Two independent Noise servers report different valid first blocks with the same pinned Genesis parent.
   - The destination imports both branches and retains both reported tips.
   - The exact same supervisor gate rejects the pair with `divergent histories`.
   - This proves that valid PoW/history from two independently authenticated sources is not treated as agreement merely because both sources completed sync.

## Targeted tests

- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib two_independent_noise_sources_with_same_history_pass_bootstrap_agreement --locked --offline` — **1 passed, 0 failed**.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib two_independent_noise_sources_with_divergent_histories_fail_bootstrap_agreement --locked --offline` — **1 passed, 0 failed**.
- Both tests were also executed together through the filter `two_independent_noise_sources_with_` — **2 passed, 0 failed**, 3.79s test execution time.
- Previous CP-0648 focused tests remain green: source ancestry relationship, metadata binding to archive, real fork-choice sibling ancestry, and Noise history-sync/restart regression.

## Build and hygiene

- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked --offline` — PASS.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check` — PASS.
- `git diff --check` — PASS.
- Existing unused-import/dead-code warnings remain in unrelated modules and binaries; no build errors.

## Scope and limitations

- The tests use ephemeral 127.0.0.1 listeners only; no public listener or port is opened.
- They exercise real Noise XX status/history exchange, history import and the exact supervisor agreement gate function. They do not start a long-running mining/listener supervisor or a public node.
- The fixtures deliberately use an easy test PoW target and do not qualify production mining difficulty or economics.
- Operator trust-domain IDs remain operator-provisioned assertions; separate Noise keys do not prove separate real-world ownership or absence of collusion.
- Ancestry agreement is not a Byzantine quorum, a source truth proof, or an Eclipse-resistance claim.

## Release boundary

No production node was launched. No public listener, firewall, router, or port was opened. No Public Testnet, deployment, commit, or push was performed. No monetary or consensus parameters were changed in this checkpoint.
