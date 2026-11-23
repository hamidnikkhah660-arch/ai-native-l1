# CP-0845 — CP-0843 Clean-Worktree Source Review and Build Provenance

Date: 2026-11-23
Scope: ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY
Status: CLEAN-WORKTREE RELEASE BUILD PASS; EXACT BINARY REPRODUCIBILITY NOT YET ESTABLISHED; PUBLIC RELEASE BLOCKED

## 1. Review branch and scope

- Review branch: `review/qfp6-cp0843-source-20261123`
- Base commit: `e73cfa4079da56b4f309ff61bb6318cbbeb37749`
- Base branch on GitHub: `feat/qfp6-public-testnet-dns-relay-20261120`
- The local technical branch is 148 commits ahead of `origin/main` and 3 commits behind it as of this review. This source review is therefore targeted at the existing technical feature branch, not directly at `main`; targeting `main` would pull a much larger historical diff into this review.
- A separate source worktree was created at `D:\\QJ6\\QFP6_CP0843_SOURCE_REVIEW_20261123`.
- Exactly 24 Rust source files were copied from the dirty CP-0843 source tree: 12 modified tracked files and 12 new Rust files.
- Six dated checkpoint documents were copied: CP-0831, CP-0832 Q6PD session manager, CP-0833, CP-0834, CP-0839, and CP-0844.
- No runtime configuration, local node database, private key, TPM metadata, log file, backup source file, target directory, or operator ZIP was copied into the source worktree.

## 2. Source files included

### Modified tracked Rust files

- `src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/permissionless.rs`
- `src/native/pow_bench/src/bin/qrun_v06_peer_book.rs`
- `src/native/pow_bench/src/lib.rs`
- `src/native/pow_bench/src/offline_signing_key_store.rs`
- `src/native/pow_bench/src/qrun_v06_history_sync_service_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_history_sync_wire_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_node_supervisor_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_noise_transport_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_peer_address_manager_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_peer_address_relay_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_peer_listener_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_pow_fork_choice_candidate.rs`

### New Rust files

- `src/native/pow_bench/src/bin/q6ar_process_probe.rs`
- `src/native/pow_bench/src/bin/qfp6_device_root_binding.rs`
- `src/native/pow_bench/src/bin/qfp6_noise_public_key_probe.rs`
- `src/native/pow_bench/src/bin/qfp6_public_seed_probe.rs`
- `src/native/pow_bench/src/bin/qfp6_q6pd_identity_provision.rs`
- `src/native/pow_bench/src/qfp6_device_identity_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_peer_connection_manager_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_peer_discovery_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_peer_discovery_store_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_peer_identity_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_q6pd_address_manager_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_q6pd_session_candidate.rs`

The changed set is broader than peer discovery alone. It includes adjacent node-supervisor, history-sync, Noise transport, peer-book, offline signing-store, and fork-choice changes present in the CP-0843 build worktree. These are kept together here so that the actual current source state is reviewable; this PR must not be described as a minimal isolated AddrMan patch.

## 3. Static checks on the clean worktree

- Secret-marker scan over the 24 Rust source files: PASS; no PEM private-key, GitHub-token, or extended-private-key markers matched. This is a targeted marker scan, not a comprehensive secret audit.
- `rustfmt --check --edition 2021` over the 24 Rust source files: PASS.
- `git diff --check`: PASS.
- The clean worktree contains no copied runtime key material or local node/TPM state.

## 4. Release build from the clean worktree

Command:

```powershell
cargo build --locked --offline --release --bin qrun_v06_node -j 1
```

Result: PASS. The optimized Release build completed in 4m 59s.

- Rebuilt executable size: 5,823,488 bytes.
- Clean-worktree rebuilt SHA-256: `916c37ba16b0e90c22acdcea1ebd823f5ee07d2f0bd6802ba420443145702108`.
- The executable embedded in the previously staged CP-0843 ZIP remains SHA-256 `519e695aed1a0b68195f841c167c06e4fe23176eb50cd96476a34113233c0470`.
- Both executables are the same file size, but their SHA-256 digests do not match. A byte comparison found 539 differing byte positions. The PE timestamp differs (original package: 2026-11-23 08:13:44 UTC; clean-worktree build: 2026-11-23 08:42:54 UTC), and embedded source-path strings differ because the two worktrees have different absolute paths. PE `.text` and `.rdata` section hashes also differ, so this review does not claim exact binary reproducibility or assert that all differences are metadata-only.
- The clean Release build proves the copied source set compiles. It does not, by itself, prove byte-for-byte identity with the packaged executable.
- The original packaged executable remains preserved inside the local CP-0843 ZIP. The Release build output under the shared Cargo target directory was overwritten by the clean-worktree build; live Seed and QA Joiner processes use the separate CP-0843 debug executable under `target-v6\\debug` and were not restarted or modified.

A future reproducible-build pass should pin/remap source paths and control linker timestamp/build metadata, then compare normalized PE sections and repeat the full build. Until that pass succeeds, exact reproducibility remains an open gate.

## 5. Existing focused test evidence

The following test evidence comes from logs generated in the original CP-0843 engineering worktree before this clean-worktree review; these tests were not rerun from the new worktree in this checkpoint.

- CP-0840 Q6PD Address Manager test run: 8 passed, 0 failed. The tests cover v1 migration, identity collision refusal, source address-group attribution, Bitcoin-Core-style bucket dimensions and persisted bucket keys, restart/reload of new/tried bucket indexes, selection penalty after failures, new-to-tried promotion after success, and tried-bucket collision/feeler replacement policy.
- CP-0843 build attestation: DNS resolver-order preservation and stable de-duplication; 3-second DNS seed connect timeout; 5-second seed I/O timeout; tried-collision/feeler tests PASS; Q6PD/AddrMan tests PASS; rotating address-inventory test PASS; locked offline Cargo check/build PASS.
- CP-0839 engineering note: signed Q6PD push/ack round-trip including tamper rejection and bidirectional gossip over one pinned local Noise session PASS. This is a local integration test, not an independent-host Internet test.
- The separate Release-profile test-target rebuild was stopped before tests executed after Rust compiler memory exceeded 1 GiB. No Release-profile test result is claimed.

## 6. Security and network qualification boundaries

- Scope remains `ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY`.
- The live topology documented in CP-0844 contains one public Seed identity. DNS routes to the same hostname/key are not independent peers; a same-device Joiner is not an independent operator.
- No independent external QFP6 identity, live multi-host A→B→C mesh, public soak, or production audit is claimed.
- Q6PD peer records are candidate route hints, not operator/validator/consensus trust. Candidate dialing remains tied to verified signed records and the exact Noise static key.
- Inbound Noise XX remains anonymous before Q6PD application checks. Transport remains classical X25519, not post-quantum.
- No Mainnet, real-value transfer, issuance/reward, exchange listing, or market activity is authorized.

## 7. Publication gate and next actions

1. Review this source diff and its adjacent history-sync/runtime changes on the dedicated PR.
2. Resolve the path/timestamp reproducibility gap or formally publish a separately rebuilt package with its own new digest and full provenance.
3. Re-run targeted tests from the clean review worktree if available without exceeding host memory limits.
4. Keep the CP-0843 ZIP local and the existing operator-package PR #205 in Draft until source review, inbound Noise XX exposure review, and package provenance gates are satisfied.
5. Only after those gates, onboard the first independently administered QFP6 host and qualify genuine multi-host record propagation, reconnect, and chain-state convergence.

This checkpoint is a source-review handover, not a security audit, production release, or decentralization claim.
