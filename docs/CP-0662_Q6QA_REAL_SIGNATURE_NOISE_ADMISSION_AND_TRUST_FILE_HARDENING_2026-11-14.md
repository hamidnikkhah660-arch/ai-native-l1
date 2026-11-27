# CP-0662 — Real-signature Q6QA/Q6TS Noise admission and trust-file hardening

Date: 2026-11-14  
Branch: `feat/cp0600-bootstrap-sync-startup`  
State: local deterministic integration qualification PASS; code changes remain uncommitted/unpushed.

## Q6PN v2 / Q6TS / Q6QA socket test upgraded

The test `qfp6_noise_q6pb_listener_rejects_unqualified_quote_then_accepts_height_bound_q6qa` now uses actual test-key cryptographic signatures and the full profile-trust chain:

- Q6QA test quote qualification is signed with Ed25519 and verified against its pinned authority account/key ID.
- Q6PN v2 embeds the exact Q6QA bundle commitment, quote asset ID, authority account/key ID and qualification epoch.
- Q6TS Active epoch 1 signs the exact Q6PN v2 byte commitment with both Ed25519 and ML-DSA-65. The ML-DSA-65 signature is verified with the project's Libcrux verifier.
- The test floor is pre-provisioned to the exact Q6TS record/envelope IDs before node startup; node startup does not advance it. The floor implementation is an in-memory test double, not a production monotonic service.
- Startup and mining obtain fresh Q6TS/Q6QA authorizations through the provider. The listener also rereads the Q6TS source and floor and independently re-verifies Q6QA for the exact parent, quote asset and block height.
- A mined Q6PB envelope is sent over a real loopback TCP Noise XX session. The no-provider request is rejected; the same envelope with the fresh Q6QA-aware handler is accepted. Assertions cover one authenticated session, two requests/responses, ending height 1 and exactly one Q6TS source read and authorization callback for listener admission.

This proves the local Q6PN v2/Q6TS/Q6QA cryptographic verification and Q6PB listener/store seam. It does not prove a public trust service or independent-host trust-floor deployment.

## Launcher trust-file hardening

Added `read_regular_bounded` and applied it to:
- Q6QA qualification bundle
- Q6TS signed envelope source, including each subsequent reread
- Q6TS Ed25519 and ML-DSA-65 authority public-key files

Only bounded regular non-symlink files are accepted. Added a launcher test covering valid regular file, oversize rejection, directory rejection and symlink rejection when the platform permits symlink creation.

The launcher continues to require Q6PN v2's independently committed quote pin; Q6TS dual signatures, independently pinned authority keyset, and read-only AWS DynamoDB trust floor are mandatory when the quote pin exists. With Q6PN v1/no quote pin, quote trust configuration is rejected and external-quote admission remains fail-closed.

## Validation results

- Local Noise/Q6PB/Q6PN v2/Q6TS dual-signature/Q6QA Ed25519 integration test: 1/1 PASS.
- Full listener module: 18/18 PASS.
- Q6TS/profile trust module: 11/11 PASS.
- Q6QA qualification module: 7/7 PASS.
- Q6MO market ingress module: 7/7 PASS.
- `qrun_v06_node` launcher binary module, including regular-file hardening test: 37/37 PASS.
- Previously run in this work segment: permissionless runtime 3/3 PASS; supervisor 19/19 PASS.
- `cargo fmt -- --check`: PASS.
- `cargo check --bins --locked --offline`: PASS.
- `git diff --check`: PASS.
- Candidate package validator self-test: PASS.
- Actual candidate package validation: correctly remains INCOMPLETE (exit 2), with five missing artifacts: Genesis snapshot, Q6GD, Q6CP, Q6PN and bootstrap peers. `mainnet_authorized=false`; `public_mining_authorized=false`.

Warnings emitted by cargo are pre-existing unused/dead-code warnings in unrelated modules/binaries; there were no build errors.

## Qualification boundary / outstanding release gates

All signatures and identifiers used by this new integration test are deterministic test fixtures. The Q6QA test asset symbol is `TQ6A`; it is not USDT and provides no evidence of reserves, bridge custody, redemption, liquidity or an exchange market. The test trust floor is in-memory; the AWS DynamoDB read-only adapter is not provisioned or qualified against a live independent trust service here.

Still required: owner/authority-controlled final CP-0651 Genesis and signatures; complete Q6GD/Q6CP/Q6PN v2/Q6QA/Q6TS artifacts; independently administered monotonic trust floor and operator key custody; independently administered public seed hosts; public inbound reachability; Linux protected Noise key provider; then independent-host Q6QA/Q6PB qualification. Earlier CP-0566C/CP-0587 two-host evidence remains valid for its earlier native-transfer scope only.

Founder Account ID remains the already verified CP-0602/CP-0608/manifest value:
`b26ce4e019429ec524cb73d0464ec4c6a48d47ea8519b867d0374f07ab54b31d`.
The CP-0651 1B owner amount is a Genesis allocation target, not a transfer performed in this work. The six 1B accounting labels remain non-circulating. No private key, mnemonic, Genesis owner signature, token transfer, public deployment, Mainnet launch or live trade was created or used.

Only this checkpoint document is intended for the isolated documentation commit. Source changes are deliberately left uncommitted and unpushed in the existing dirty worktree.
