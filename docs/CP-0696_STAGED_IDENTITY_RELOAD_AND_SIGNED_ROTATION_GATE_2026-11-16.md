# CP-0696 — Staged Identity Reload Proof and Signed Rotation Authorization Gate — 2026-11-16

## Scope and safety boundary
- Project: AI-NATIVE L1
- Active worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`
- Branch: `feat/cp0600-bootstrap-sync-startup`
- HEAD remains: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
- This checkpoint adds a fresh-process verifier for the actual staged DPAPI files, a repeatable staged-bundle regression script, and a signed authorization preflight gate.
- No active Seed or Joining identity/key/config was replaced, activated, or pinned.
- No QRun node was started. No TCP listener was opened. No firewall/router/NAT/DNS/VPN/adapter changes were made.
- No commit, push, merge, reset, clean, stash, or rebase.

## 1. Fresh-process staged protected-key verifier

New Rust binary source:
`src/native/pow_bench/src/bin/noise_identity_reload_verify.rs`

SHA-256:
`4c7d1f01e5eeaf4cb2fbbc20609a88a209285ceba1628109d4ff71fad14f861f`

Release executable:
`src/native/pow_bench/target/release/noise_identity_reload_verify.exe`

SHA-256:
`aa8f3265994740e44bc03c5682f77a7247228756a3f7eeeaac6aa3ee89ea2a34`

Behavior:
- Loads an existing platform-protected Noise private key using the production library loader and exact network ID.
- Does not accept private-key bytes in arguments or environment variables.
- Builds a real Noise XX handshake with a temporary peer and proves the loaded static identity by comparing the remote-observed public key fingerprint with the expected staged fingerprint.
- Prints only pass/fail and public fingerprint-match status; never prints the private key.
- The verifier exits nonzero on wrong network, corrupt protected envelope, or mismatched public fingerprint.

Build:
`cargo build --locked --release --bin noise_identity_reload_verify`
Result: exit 0; release profile finished successfully.

## 2. Actual staged Seed and Joining reload regression

New script:
`tools/test-qfp6-staged-noise-identity-reload.ps1`

SHA-256:
`a5a2716950f9b0786ab39b0f77210b466f873e29a7612e2c078dc24260b72287`

The script validates both real generation-1 bundles and runs each protected-key check in a fresh child process. It also tests wrong network, wrong public fingerprint, and corrupted-envelope rejection. Corrupted copies are made only under a disposable TEMP directory and removed afterwards.

Exact final result:
```text
SEED_FRESH_PROCESS_RELOAD=PASS
SEED_WRONG_NETWORK_REJECTION=PASS
SEED_WRONG_FINGERPRINT_REJECTION=PASS
SEED_CORRUPTED_ENVELOPE_REJECTION=PASS
JOINING_FRESH_PROCESS_RELOAD=PASS
JOINING_WRONG_NETWORK_REJECTION=PASS
JOINING_WRONG_FINGERPRINT_REJECTION=PASS
JOINING_CORRUPTED_ENVELOPE_REJECTION=PASS
STAGED_IDENTITY_RELOAD_REGRESSION=PASS
PASSED_CASES=8
```
The process exited successfully. Both actual staged keys were reopened by new processes; the static public identity observed through Noise XX matched the fingerprint in each manifest. The wrong-network, wrong-fingerprint, and corrupted-envelope cases were rejected for both roles.

## 3. Signed, version-bound rotation authorization gate

New Rust binary source:
`src/native/pow_bench/src/bin/noise_identity_rotation_authorization_verify.rs`

SHA-256:
`e3479b932987f910f8893d467cf4b6bcf31eccdd24790d75adc97af1326bf2a7`

Release executable:
`src/native/pow_bench/target/release/noise_identity_rotation_authorization_verify.exe`

SHA-256:
`1bbd54f4f2aed19609c7345bf5178b25bad8fc7f1a0dc586b56a0aa033f6e0e7`

New PowerShell bundle-integrity wrapper:
`tools/qfp6-verify-noise-identity-rotation-authorization.ps1`

SHA-256:
`cccb99feedc37e2c14435259f03542d28f594bbbcfcb596102867c8a8c1a2ea5`

The wrapper verifies the staged identity, previous identity, protected-key and Seed prepared-config hashes; checks role/network/profile/public fingerprint bindings and inactive flags; and then invokes the Rust Ed25519 verifier.

The Rust verifier validates:
- An Ed25519 signature over the exact raw authorization JSON bytes.
- The authority public-key SHA-256 against an independently supplied trust pin.
- Exact binding to the complete manifest SHA-256, role, generation, network/profile, old/new identity hashes and old/new public fingerprints.
- The exact Seed endpoint and Seed fingerprint supplied independently to the verifier.
- Explicit independent endpoint and fingerprint attestations with evidence hashes.
- Different owner-approver and independent-operator identities.
- Zero-value Public Testnet scope only.
- A documented overlap policy and a bounded rollback window (5 minutes to 24 hours).
- Issue/expiry timestamps; expired, future-dated and excessive-lifetime authorizations are rejected.
- Manifest must remain `PREPARED_NOT_ACTIVATED`; activation and node/listener flags must all remain false.

The verifier is deliberately preflight-only. It does not install a trust pin, replace a file, update peers, activate a key, or start a node.

Unit tests:
`cargo test --locked --bin noise_identity_rotation_authorization_verify -- --nocapture`

Result: 6 passed, 0 failed:
- Valid signed exact-generation authorization accepted by the verifier logic.
- Wrong owner-authority fingerprint rejected.
- Modified signature rejected.
- Authorization signed for another manifest rejected.
- Expired authorization rejected.
- Seed endpoint or Seed fingerprint mismatch rejected.

Release build:
`cargo build --locked --release --bin noise_identity_rotation_authorization_verify`
Result: exit 0.

Important missing prerequisite:
- No owner Ed25519 authority public key has yet been pinned out-of-band.
- No owner-signed production authorization JSON or detached signature exists.
- No independent operator attestation or evidence files exist.
- Therefore the authorization preflight has not been run against a real owner-approved authorization and cannot authorize activation yet.
- The authority private key must remain outside the repository and must never be generated/assumed by this tool. The owner must establish and independently verify the authority public-key fingerprint before using it as the trust pin.

## 4. PowerShell and formatting checks
- Parser: 0 errors for:
  - `tools/qfp6-prepare-noise-identity-rotation.ps1`
  - `tools/test-qfp6-prepare-noise-identity-rotation.ps1`
  - `tools/test-qfp6-staged-noise-identity-reload.ps1`
  - `tools/qfp6-verify-noise-identity-rotation-authorization.ps1`
- `rustfmt --edition 2021 --check` for both new Rust binaries: exit 0.
- `git diff --check`: exit 0. Existing LF/CRLF notices only.
- Cargo emits 9 pre-existing library warnings in unrelated candidate modules; no new warnings remain in the authorization binary after import cleanup.

## 5. Seed endpoint and external reachability — still blocked

Read-only Windows network snapshot:
- Wi-Fi currently has global IPv6 addresses and an IPv6 default route.
- A final read-only recheck found two preferred global Wi-Fi IPv6 addresses, each with a router-advertised preferred lifetime of 3,328 seconds (about 55 minutes).
- Public egress IP discovery succeeded, but the address was deliberately not copied into this checkpoint or a public configuration.
- A public egress address alone does not prove inbound reachability, stable addressing, or control of a public DNS name.
- TCP 30333 and 30334 currently have zero local listeners.
- No independent external operator/host has tested inbound TCP 30333.
- No owner-approved stable Seed endpoint or stable DNS name is available in the verified project state.

Do not use the temporary Wi-Fi IPv6 address as a Seed endpoint. Do not create a Joining runtime config until all of the following are true:
1. Stable owner-controlled Seed endpoint (static IPv4/IPv6 or stable DNS name) is supplied.
2. Seed is deliberately deployed on a qualified host and its public listener is opened only under an approved deployment plan.
3. Independent operator verifies the endpoint from a separate network and records the evidence.
4. Independent operator verifies the exact Seed Noise fingerprint through a separate trusted channel.
5. Owner signs the exact versioned authorization record using an externally held Ed25519 authority key.

No firewall/router changes or port-forwarding attempts were made. If no stable host/domain exists, a separately administered VPS or other independently reachable host is required; purchasing/creating one requires the owner's account and approval.

## 6. Final state
- The two real generation-1 bundles remain `PREPARED_NOT_ACTIVATED`.
- Active Seed/Joining identities and protected keys remain unchanged.
- Joining runtime config remains absent.
- No QRun node process is running.
- TCP 30333 listeners: 0.
- TCP 30334 listeners: 0.
- HEAD remains `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- Worktree status entries after the four new source/script files and this checkpoint: 136.
- Preserve all pre-existing dirty/untracked files.

## Next step
The software-side reload and authorization checks are now implemented and locally tested. The remaining real-world blocker is the stable owner-controlled Seed endpoint plus independent operator verification. Once that exists, create and sign the exact authorization record, run the wrapper preflight, then prepare the Joining runtime config. Do not activate either identity as part of this checkpoint.
