# CP-0657 — Linux Seed-Host Noise-Key Custody Compatibility Blocker

Date: 2026-11-14
Project: AI-NATIVE L1 / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Observed HEAD: `df673d07050688a64b26822d97e6ea609b68ce88`
Depends on: CP-0615, CP-0616, CP-0655, CP-0656
Status: **Linux seed-host deployment is blocked by the current Windows-only DPAPI Noise-key provider; no Linux host or key was provisioned**

## 1. Finding

CP-0655 recommended Ubuntu 24.04 LTS x86_64 as the seed-host operating system. A source-level compatibility audit found that the current QFP6 permissionless runtime cannot load its configured protected Noise private key on Linux:

- `src/native/pow_bench/src/noise_key_provisioning.rs` documents the NPK1 format as Windows CurrentUser DPAPI-backed.
- On non-Windows targets, both `dpapi_protect` and `dpapi_unprotect` deliberately return `NoiseKeyProvisioningError::DpapiUnavailable`.
- `src/native/pow_bench/src/bin/noise_key_provisioner.rs` explicitly refuses to run outside Windows with `noise_key_provisioner requires Windows CurrentUser DPAPI`.
- The QFP6 `--permissionless-run` launcher loads `permissionless_runtime.node_noise_private_key_path` through `load_protected_noise_private_key` before opening the runtime/listener.

Therefore a Linux QFP6 seed built from the current tree cannot provision or load its Noise static private key through the supported protected-key path. A Linux VM may have sufficient CPU/RAM and network reachability but is not currently deployable as a QFP6 seed without a new key-provider implementation.

This is a code compatibility blocker, not an Ubuntu networking problem.

## 2. Security boundary

Do not work around this blocker by:

- Passing Noise private-key bytes in CLI arguments, environment variables, chat, shell history or logs.
- Persisting an unencrypted 32-byte Noise private key as an ordinary file.
- Reusing the Windows NPK1 DPAPI envelope on Linux.
- Disabling key protection, accepting a zero-key/empty key, or silently falling back to a plaintext file.
- Copying one seed's private key to another host.

Each seed must generate and retain its own distinct local Noise static private key. Only the corresponding public key/fingerprint is exported for bootstrap pinning.

## 3. Candidate Linux custody design to implement and qualify

Investigate a Linux-specific provider based on systemd service credentials, while retaining the existing Windows DPAPI provider:

1. Generate the Noise key on the target Linux host using the OS CSPRNG.
2. Build a versioned, network-bound credential envelope containing the network ID and exactly 32 nonzero private-key bytes.
3. Encrypt that envelope locally with `systemd-creds`; prefer TPM2-backed or host+TPM2 binding where the actual VPS supports it. Where TPM2 is unavailable, explicitly record the weaker host-key-only custody mode and require an owner-approved policy.
4. Configure the node's systemd unit with `LoadCredentialEncrypted=` and pass the decrypted credential into the service-private runtime credential directory.
5. Extend the QFP6 loader with an explicit Linux/systemd-credential provider. It must validate the exact network ID, version, key length, nonzero value, file type and path policy, then zeroize intermediate buffers. It must not silently reinterpret a DPAPI NPK1 file as a Linux credential.
6. Keep provider selection explicit and bound by the independently hashed node configuration. Reject missing provider, unknown provider, path substitution and fallback to plaintext.
7. Do not use systemd's `null` credential key mode: it provides neither confidentiality nor authenticity.

Official systemd documentation describes host-key, TPM2-key and combined host+TPM2 credential encryption, and explains how systemd service credentials are made available to a service. These semantics still need verification against the exact Ubuntu image/systemd version and the chosen VPS's TPM2 exposure before implementation is considered complete.

## 4. Required tests before Linux deployment

- Linux-only provisioning test: generate key without accepting secret bytes from CLI or stdout; output only public key and fingerprint.
- Round-trip: provision, restart service, load same network-bound key, and derive the same public key.
- Negative tests: wrong network, corrupt/truncated credential, wrong version, zero key, wrong length, symlink/path substitution, missing `CREDENTIALS_DIRECTORY`, missing credential, unavailable TPM/host key and invalid service permissions.
- Custody tests: ensure the persistent encrypted credential is not plaintext; verify no private key in logs, process arguments, environment, crash diagnostics or public artifacts.
- Rotation test: a new node key requires a new public pin/config digest; old pin is not silently retained.
- Cross-build/test on the exact Ubuntu 24.04 architecture and systemd version intended for the two seeds.
- Re-run QFP6 launcher, listener, startup/restart and full-history bootstrap checks against the Linux provider before calling a Linux seed qualified.

## 5. Deployment decision

- CP-0655 Ubuntu resource profile remains a candidate hardware recommendation only.
- Ubuntu seed provisioning is **BLOCKED** until the Linux credential provider is implemented and verified.
- A Windows Server deployment might use the existing DPAPI provider, but that alternative has not been qualified for unattended server service operation and is not substituted here.
- No host, key, endpoint, public fingerprint or Genesis artifact has been fabricated or provisioned.
- The two-independent-operator requirement from CP-0655 remains unchanged.
- Public Testnet remains **NO-GO / NOT LAUNCHED**; Mainnet remains **NOT AUTHORIZED**.

## 6. Next engineering gate

Implement and test the explicit Linux systemd-credential backend without weakening the Windows DPAPI path. After that, create a reproducible Ubuntu seed image/runbook, prove local key custody and restart recovery, and only then provision two independently administered hosts and continue the CP-0655 multi-host release gates.

---
