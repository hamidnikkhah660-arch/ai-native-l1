# CP-0472 — QRun Node External-CAS Backend Startup Wiring

Date: 2026-10-30

Status: **The QRun PoW node executable can now explicitly select either its historical local PFS2 backend or a wallet-bound QFP5 external-CAS backend at startup. A Windows end-to-end loopback test performed a real Noise XX session, verified a signed ML-DSA-65 provider read, opened the QCF1 floor, mined and submitted a QFP5 block, committed remote CAS and local PFS2, and verified matching resulting digests. This is not a deployed independent provider or a Mainnet release.**

## Startup selection

1. Added NodeForkStore, an enum adapter implementing QRunV05RuntimeStore for the local PrivateTestnetForkStore and external QRunV05ExternalCasForkStore using NoiseTcpExternalCasProviderTransport and LibcruxMlDsa65VerifierCandidate.
2. Added QRunV05PowForkRuntime::from_store. It validates the requested Genesis, Network ID, fee-only profile, supply and every branch before exposing mining/import operations. from_fee_only_store delegates to the shared constructor and still requires protocol version 5.
3. The production startup path now calls open_node_runtime. No external-CAS options means the existing local runtime path. A complete external-CAS configuration selects the pinned remote provider path. Once external options are supplied, any error aborts startup; there is no local-only fallback.
4. External-CAS startup is currently restricted to QFP5. It recomputes the wallet-bound QRunGenesisV05 and requires an exact match with the configured Genesis commitment.
5. The node reads a raw fixed-size ML-DSA-65 receipt public-key file and an exact-size ECR1 generation-zero bootstrap record. Both must be regular files, non-symlinks and exact length. Provider ID, Network ID, Genesis, receipt key ID and receipt public key are validated as one ExternalCasPin.
6. The Noise client private key is loaded from the existing network-bound NPK1/DPAPI protected-key format. It is not supplied on the command line. The transport pins the exact Noise server static public key and provider/network/Genesis/receipt pin.
7. An explicit absolute --external-cas-floor-dir is required. The parser rejects lexical overlap with --data-dir; operators must keep it in a separately permissioned and separately backed-up location. --external-cas-initialize-floor true creates a generation-zero floor only when absent; an already initialized floor is reopened, while a deleted or corrupt floor remains a fatal error.
8. Added CLI help for the provider endpoint and pin/configuration files. The endpoint parser accepts numeric IP:PORT and applies the existing network-mode listener policy.

## End-to-end test

external_cas_node_startup_uses_pinned_noise_provider_and_advances_floor_before_return runs all components in one Windows test using temporary keys and directories:

- Creates the exact wallet-bound QFP5 genesis and its initial local manifest anchor.
- Starts a real TCP provider listener bound only to 127.0.0.1, backed by DurableExternalCasProvider.
- Uses a client Noise static key protected by the real Windows DPAPI NPK1 provisioning path and pins the server static public key.
- Supplies a real ML-DSA-65 receipt public key and signer; the client verifies a signed provider read.
- Opens the independent QCF1 floor and the node runtime through external CAS.
- Mines and submits one QFP5 block using the normal QRun runtime.
- Verifies height 1, provider ECR1 generation 1, provider object generation 2, and that the remote committed state digest equals the locally published PFS2 manifest anchor.
- Verifies the runtime selected the external-CAS variant and shuts down the loopback provider thread. It does not expose a public socket or alter firewall configuration.

## Validation on the exact working tree

- cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check: PASS.
- cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v05_pow_local_node --locked --offline: PASS, 23 passed, 0 failed.
- cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --lib --locked --offline: PASS, 949 passed, 0 failed.
- cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline: PASS. Existing unused-import/dead-code/unused-mut warnings remain in unrelated candidate code and old node tests.
- git diff --check: PASS (Git emits only its configured LF-to-CRLF working-copy notice for the Windows node source).

The two dependency PRs are separate and stacked: PR #88 is the durable provider candidate; PR #89 adds its independent QCF1 floor. Their exact-head CI runs passed. CP-0472 is stacked on the PR #89 branch and requires its own CI and review.

## Security and release boundaries

- The end-to-end provider is a disposable test instance on loopback. No independent operator, remote host, cloud service, or internet-reachable provider has been provisioned or verified.
- QCF1 is separate from --data-dir, but still on one host. A whole-host/common-backup rollback can restore the floor and provider together. Production still requires an off-host monotonic anchor or TPM/HSM-backed floor in a separately administered recovery domain.
- The filesystem provider's checksum is not an authenticated anti-tamper control. Production ACLs, backup ownership, signer service and server key protection need separate operator review.
- Current Noise XX uses classical X25519/ChaChaPoly. ML-DSA-65 authenticates receipts separately; this does not make the Noise channel post-quantum or hybrid.
- The node still needs an actual remote service deployment, independently provisioned provider/Noise/receipt pins, provider key lifecycle, anti-rollback anchor, service monitoring and multi-host failure/recovery drills.
- Public P2P reachability and consensus calibration across independent operators, complete history/checkpoint validation, independent audit and release approval remain open.
- QRUN_MAINNET_RELEASE_APPROVED remains false; --mainnet remains blocked. Public mint remains disabled. No QZXB/USDT exchange market is established by these changes.

**Decision:** CP-0472 closes the code-level path from the node executable to the durable external-CAS/floor-backed runtime and proves it on local loopback. It does not prove independent network deployment or release readiness. Keep this PR Draft and do not open public firewall ports for the loopback test.
