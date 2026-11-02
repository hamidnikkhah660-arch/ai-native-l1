# CP-0500 — QRun v0.5 Public Alpha authenticated startup smoke

Date: 2026-11-02

Status: **The actual QRun Public Alpha node has now been started end-to-end against the DPAPI-backed RTP1/TMA1 Authority on Windows. The node loaded a network-bound DPAPI Noise key, accepted the signed time sample, created its disposable QFP5 state, and bound RPC, transaction and P2P listeners. An Authority outage was separately verified to fail closed before node data-directory creation. This is a single-host loopback qualification, not multi-host or public-network qualification.**

## Gap addressed

CP-0499 proved that the Authority executable could provision time keys, sign RTP1 policy, serve TMA1 and survive a process restart. It did not yet prove that the complete QRun Public Alpha executable could consume that service and reach its listener-ready state with a valid protected Noise key.

The NPK1 protection API already existed, but there was no small operator CLI to create a network-bound Noise XX key without exposing its private bytes. This checkpoint adds that missing provisioning path and exercises the actual node process.

## Implementation

### DPAPI-backed Noise key provisioner

New executable:

`qrun_v05_noise_key_provision`

Source:

`src/native/pow_bench/src/bin/qrun_v05_noise_key_provision.rs`

Usage:

```powershell
cargo run --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v05_noise_key_provision -- --network-id-hex HEX64 --output C:\absolute\path\node.npk1
```

The tool:

- generates a static keypair for `Noise_XX_25519_ChaChaPoly_SHA256` using the `snow` cryptographic random key-generation path;
- stores the 32-byte private key only through the existing NPK1 Windows CurrentUser DPAPI protection API, bound to the supplied nonzero Network ID;
- zeroizes local private-key buffers after the protection call;
- prints only the public key, Network ID, key format and output path;
- rejects malformed or zero Network IDs, non-absolute paths, missing output directories and an already existing output file.

This is Windows CurrentUser DPAPI custody, not an HSM, hardware key vault, portable backup or protection from compromise of the logged-in user's running session. The output file inherits the parent directory's Windows ACL. Production operators must secure and back up node key custody deliberately.

## Repeatable actual-node smoke

New script:

`tools/qrun-v05-public-alpha-reference-time-smoke.ps1`

Run on Windows PowerShell from the repository:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\qrun-v05-public-alpha-reference-time-smoke.ps1
```

The script builds the QRun node, Authority and Noise provisioner offline. In a unique temporary directory it then:

1. reads the current wallet-bound candidate Network ID and matching owner account/public-key pair from the candidate manifest;
2. provisions distinct DPAPI Authority and Policy Admin keys;
3. creates a signed, network-bound RTP1 policy with a temporary policy sequence;
4. provisions a fresh NPK1 Noise static key and proves a duplicate-output attempt is rejected without changing the original file;
5. starts the Authority on a dynamically selected loopback port;
6. launches the actual `qrun_v05_pow_local_node --public-alpha` process with a temporary Genesis epoch, the signed RTP1 policy, its admin-key pin, the Authority address, an independent RTS1 high-water file, and the DPAPI NPK1 Noise key;
7. verifies the node's authenticated reference-time provenance marker, experimental Public Alpha network class, `mainnet=false`, and all three listener-ready markers;
8. stops the Authority and launches a second Public Alpha startup attempt with a separate data directory and high-water file;
9. verifies that the second attempt exits with the authenticated reference-time startup-sample error and does not create its node data directory.

The current wallet-bound candidate identity is used only to exercise the QRun v0.5 calibrated identity path in a disposable local test. The Genesis epoch, signing keys, RTP1 policy, Authority sequence store, NPK1 Noise key, RTS1 node state and QFP5 data directory are temporary. The script deletes all temporary files and stops its child processes in its cleanup path. It does not rewrite the candidate manifest, production identity pins, Mainnet Genesis epoch, ECR1/QCF1/QRCP records or release gate.

## Observed Windows result

Executed on the connected Windows `heymed` device:

- Offline compilation of the QRun node, reference-time Authority and Noise key provisioner: **PASS**.
- Separate DPAPI Authority and Policy Admin key provisioning: **PASS**.
- Signed RTP1 policy creation: **PASS**.
- NPK1 Noise key generation and DPAPI protection: **PASS**.
- Duplicate NPK1 output overwrite rejection; original file hash unchanged: **PASS**.
- Independent Authority TCP process startup: **PASS**.
- Actual QRun Public Alpha startup using the authenticated provider: **PASS**.
- Node emitted `qrun_reference_time_ready source=ed25519-attested-time-v1 provenance=ConfiguredProvider`: **PASS**.
- Node emitted `QRUN_V05_PUBLIC_ALPHA_CANDIDATE_READY` and `network_class=public_alpha_experimental_not_mainnet`: **PASS**.
- RPC, QZTS/1 transaction and QRB5/2 block listeners all reached their ready markers: **PASS**. All three were explicitly bound to loopback for this test.
- Node reported `mainnet=false`: **PASS**.
- Authority outage caused a fail-closed Public Alpha startup error: **PASS**.
- Failed startup did not create the second node's data directory: **PASS**.
- Overall: `PUBLIC_ALPHA_REFERENCE_TIME_SMOKE=PASS`.

## What this proves — and what it does not

**Proved locally:** the Authority and the actual QRun Public Alpha process now interoperate through signed RTP1/TMA1; the actual QRun process reads the protected NPK1 key, derives its time-policy-bound session profile, creates its temporary QFP5 runtime and binds all three loopback listeners. An Authority outage does not trigger a local OS-clock fallback or allow a partial node data directory to be created.

**Not proved:** this is not a physical multi-host test, not an independent-operator test, not a remote P2P handshake, not a peer-reorg/partition/restart test, not an independently monitored time service, and not a BFT time protocol. The time source remains one trusted Authority whose OS clock and availability are explicit trust dependencies. The three listener sockets were loopback-only; no remote node joined and no external Internet reachability was tested.

## Release and identity boundary

- `QRUN_MAINNET_RELEASE_APPROVED = false` remains unchanged.
- No Mainnet Genesis epoch has been selected or frozen.
- The wallet-bound Network ID, Genesis ID, time-policy-bound Profile ID, state root, manifest and ECR1/QCF1/QRCP pins have not been regenerated as a coordinated identity freeze.
- No public trading, liquidity, exchange listing, public launch or independent user adoption is claimed.
- This checkpoint is Public Alpha startup evidence only; it does not change the Seed-readiness assessment.

**Decision:** keep the signed reference-time requirement fail-closed, make NPK1 node-key provisioning reproducible, and move the next qualification step to two or more independently operated machines with remote Noise sessions, restart/reorg/partition tests and separately monitored Authority operation. Mainnet remains closed.
