# CP-0673 — Q6MO Production Listener Integration and Release Build
Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`
Branch: `feat/cp0600-bootstrap-sync-startup`
Engineering HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Status: **local source patch verified by targeted tests; all-bin checks and optimized release build passed; full regression suite is recorded separately with exact source timing**

## 1. Q6MO listener gap corrected

The combined QFP6 peer listener now recognises Q6MO market-operation frames in the same bounded Noise application dispatch as Q6PB, Q6TI, Q6HS and Q6HI.

- Q6MO requests are decoded before dispatch and the request ID is extracted from the canonical bounded codec.
- The application handler is invoked only after the frame passes the Q6MO decoder.
- The Q6MA response is decoded and validated against the exact request ID and Q6MA schema; it is not incorrectly forced through the 128-byte Q6PA/Q6TA response validator.
- Listener module and API comments now document Q6MO/Q6MA support.
- The permissionless market service integration test now drives the actual combined production listener and its bounded Noise handshake worker pool rather than a hand-written TCP accept loop.

## 2. Targeted verification on the patched source

Commands used locked offline dependencies in the Windows worktree.

| Check | Result |
|---|---:|
| Q6MO durable service lifecycle through production listener | 1 passed, 0 failed |
| QFP6 peer listener regression module | 18 passed, 0 failed |
| `cargo fmt --check` | PASS |
| `cargo check --bins --locked --offline` | PASS, exit 0 |
| `git diff --check` | PASS |
| `cargo build --release --bins --locked --offline` | PASS, exit 0 |

The Q6MO end-to-end test verifies: a signed market operation crosses the actual listener worker-pool and Noise session; a valid Q6MA acknowledgement is returned; the operation is durably recorded in Q6MM; reopening restores it; mining commits it to the canonical chain; only then is the pending entry removed; a further reopen does not resurrect it.

The complete library suite on the pre-listener-patch tree passed 1,459 tests with zero failures. After the listener patch, the directly affected Q6MO integration test and all 18 listener tests were rerun and passed. A full post-patch library rerun is the remaining local regression step and must not be inferred from the earlier 1,459-test result.

The release build produced these files under `src/native/pow_bench/target/release`:
- `qrun_v06_node.exe`
- `qfp6_candidate_validate.exe`
- `qzxb_wallet.exe`

Build output contains pre-existing unused/dead-code warnings in unrelated legacy/candidate targets; no compiler errors were reported.

## 3. Owner wallet identity reconciliation

The QZKW2 wallet at `%LOCALAPPDATA%\QuantumZXB\wallets\QZXB-founder.qzw` was opened locally with the release wallet binary using the read-only public-address command.

- Account ID exactly matches candidate manifest: `b26ce4e019429ec524cb73d0464ec4c6a48d47ea8519b867d0374f07ab54b31d`.
- Complete Ed25519 public key matches the manifest.
- Complete ML-DSA-65 public key matches the manifest.
- CLI output explicitly reported `private_key_output=none`.
- CP-0672 records the exact field-by-field equality evidence.

The legacy QZKW1 wallet was not modified. No private material was printed or requested in chat. No Genesis signature was created and no funds were minted or transferred.

## 4. Release artifact status — remains NO-GO

Manifest `release/qfp6-candidate/manifest.json` remains a candidate manifest, with:
- `production_authorized=false`
- `mainnet_status=NOT_AUTHORIZED`
- `public_mining_authorized=false`
- CP-0651 economic policy: 7B accounting ceiling, 1B owner Genesis allocation, six non-circulating 1B labels, zero block subsidy and canonical-fee-only producer compensation.

Still missing:
- final Genesis execution snapshot and owner Genesis signature;
- Q6GD Genesis descriptor;
- Q6CP consensus profile artifact;
- Q6PN network profile/pin;
- independently administered bootstrap peer set and out-of-band verified endpoint/Noise public-key pins.

Consensus, cryptography and economics independent reviews remain pending. The Q6TS bundle is explicitly not required for the current permissionless full-history profile; it is not treated as a blocker.

No node process was launched, no public listener or port was opened, and no firewall/router/network exposure was changed. No public Testnet, Mainnet, value-bearing deployment, exchange listing or live trading is claimed.

## 5. Publication and repository state

- PR #195 remains open and unmerged. Its three CI checks pass, but there are no requested reviewers and no review submissions. The required independent approval is not present; do not self-approve or disable branch protection.
- The public Pages URLs still serve the old site content until PR #195 is merged and deployment is verified.
- Engineering branch remains 12 commits ahead of its remote tracking branch, with pre-existing modified and untracked files. Do not blanket-commit or push the entire working tree. The Q6MO listener source patch is local and currently uncommitted; preserve all unrelated changes.

## 6. Next safe sequence

1. Run the full library test suite again on this exact post-patch source and record its result.
2. Preserve and hash the final release binaries and test logs.
3. Review the engineering diff and separate already-validated implementation/checkpoint artifacts from unrelated local changes before any commit or push.
4. Obtain a genuine independent reviewer for PR #195, merge only after branch protection is satisfied, then verify live Pages content.
5. Complete Q6GD/Q6CP/Q6PN/Genesis/bootstrap provisioning, independent consensus/cryptography/economics reviews and protected owner signing. No Genesis signature or public launch before those are complete.

This checkpoint does not authorize signing, minting, transferring, exposing a public listener, or Mainnet activation.

## 7. Production call-path cross-check

A follow-up source trace confirmed that `run_qfp6_permissionless_mining_supervisor_inner` (the active permissionless supervisor used by the launcher) calls `serve_qfp6_history_listener_round`, which in turn calls `serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins_with_rate_limiter`. The supervisor's application callback routes Q6HI/Q6HS to history handling and all other application frames to `process_qfp6_application_frame_with_permissionless_runtime_and_quote_asset_authorization`, whose dispatcher explicitly handles Q6MO/Q6MA. The patched combined listener is therefore the actual listener family used by the permissionless supervisor, not an unrelated legacy Q6PB-only listener API.

The Q6MO integration test exercises the same combined listener API and the same application dispatcher callback. It does not launch an Internet-facing node or replace the required external-host/public-listener qualification.

## 8. Release binary SHA-256 fingerprints

The following optimized Windows release binaries were present and hashed after the successful build:

| Binary | SHA-256 |
|---|---|
| `qrun_v06_node.exe` | `88c912f79a4a98ce8ec6eb54c0a72b4bcd98f9be2457a3fdf3e73140b54c6768` |
| `qfp6_candidate_validate.exe` | `3010a5b21de5f8b9efd085661cfe59489b25cb69373bb8df82e91aead72d34f4` |
| `qzxb_wallet.exe` | `c06df0deeb1eb75d3ab3829ee5301aaaf46b895e00a443dbf5cc5a7401421183` |

These are local build fingerprints, not release signatures or public provenance attestations.

Post-patch full library regression completed on 2026-11-15:

```text
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib --locked --offline -- --test-threads=1
test result: ok. 1459 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
finished in 770.15s
POST_PATCH_FULL_LIBRARY_TEST_SUITE_PASS
```

This is the definitive full library result for the Q6MO listener patch recorded above. The separate Q6MO integration and 18-test listener regression were also rerun on the same patched source and passed.

## 9. Dedicated release-binary unit tests

After the optimized release build, the three release-critical executable targets were independently compiled in the test profile and their own binary test suites were executed:

| Binary target | Result |
|---|---:|
| `qrun_v06_node` | 37 passed, 0 failed |
| `qfp6_candidate_validate` | 2 passed, 0 failed |
| `qzxb_wallet` | 11 passed, 0 failed |

The node binary tests include CP-0651-only permissionless Genesis gating, public listener opt-in/topology guards, Q6GD/Q6CP preflight validation and refusal of public/Mainnet modes before secrets are loaded. The wallet tests include deterministic BIP39 hybrid derivation, QZKW2 DPAPI roundtrip/public-identity binding, Q6HA hybrid-transfer signing, and rejection of private-key command-line options.

## 10. Release CLI smoke

The optimized release executables were also invoked in non-mutating help mode:
- `qrun_v06_node.exe --help`: exit 0; usage identifies private candidate, permissionless candidate and explicit zero-value Public Testnet modes, and states that neither candidate mode authorizes Mainnet/value-bearing use.
- `qzxb_wallet.exe --help`: exit 0; usage exposes QZKW2 hybrid wallet commands and confirms the Q6HA signer refuses QZTS/1 broadcast.

No config was loaded, no secrets were opened by these help invocations, and no node/listener was started.
