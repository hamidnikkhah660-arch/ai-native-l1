# CP-0665 — Linux systemd credential Noise-key provider candidate

Date: 2026-11-14
Project: AI-NATIVE L1 / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Base documentation commit: `6184f35`
Status: **candidate implementation added; Windows regression/build checks PASS; Linux-native compilation and host+TPM2 service qualification remain OPEN**

## 1. Purpose

CP-0657 identified that the protected Noise static-key provider was Windows CurrentUser DPAPI-only, which prevented the current Ubuntu seed-host plan from loading a protected key. This checkpoint records a first explicit Linux backend candidate while preserving the existing Windows NPK1/DPAPI path.

This is not a Linux seed qualification and does not authorize provisioning a production node.

## 2. Candidate implementation

Files changed in the existing working tree:

- `src/native/pow_bench/src/noise_key_provisioning.rs`
- `src/native/pow_bench/src/bin/noise_key_provisioner.rs`

### Windows compatibility

- Existing NPK1 envelope and CurrentUser DPAPI protection are retained.
- Existing Windows round-trip, network-binding, zero-key and corrupt-envelope tests remain in the targeted test set.
- The provisioner still reports the Windows DPAPI/NPK1 mode on Windows.

### Linux systemd credential path

- A distinct NPK2 payload was added: magic, version, 32-byte network ID, and exactly 32 nonzero Noise private-key bytes.
- Provisioning calls the fixed `/usr/bin/systemd-creds` executable with `--no-ask-password encrypt --with-key=host+tpm2 --name=<credential-id> - -`.
- The plaintext payload is passed through stdin, not command-line arguments or a plaintext key file, and is zeroized after the encryption attempt.
- No host-only or null-encryption fallback is used. If systemd-creds, host+TPM2 access, or the protected output path requirements are unavailable, provisioning fails closed.
- Encrypted output is atomically persisted under an absolute root-owned, non-symlink, non-group/world-writable parent directory. The temporary/output file is created with mode 0600.
- The Linux runtime configuration uses an explicit virtual reference `/systemd-credential/<credential-id>`. The systemd unit operator must map the encrypted file through `LoadCredentialEncrypted=<credential-id>:<encrypted-file-path>`.
- Runtime loading is permitted only from the service-provided `$CREDENTIALS_DIRECTORY`. The loader checks the credential path and directory, symlink/hardlink conditions, owner, file mode, exact payload length, NPK2 version, nonzero key, and network ID. It opens the credential with no-follow and close-on-exec flags, verifies the opened inode against the pre-open metadata, and zeroizes the payload buffer.
- Missing credential directory, missing credential, invalid reference, wrong network, malformed envelope, or unsupported platform are rejected. There is no plaintext fallback.

The provisioner now prints only the protected-file path, public network ID, public Noise static key, protection mode, runtime reference, and the corresponding systemd directive. It never prints or accepts the generated private key.

## 3. Local validation actually completed

Windows development worktree:

| Check | Result |
|---|---:|
| `cargo test --lib noise_key_provisioning::tests --locked --offline` | 5 passed, 0 failed |
| `cargo check --bins --locked --offline` | PASS, exit 0 |
| `cargo fmt -- --check` | PASS |
| `git diff --check` | PASS |

The five targeted unit tests include the existing Windows DPAPI tests plus NPK2 reference/payload tests for safe credential IDs, network binding, successful payload zeroization, and wrong-network/version/key/magic/length rejection.

WSL development smoke only:

- Local distribution: Ubuntu 26.04.1 LTS under WSL2.
- systemd: 259.5; `/usr/bin/systemd-creds` is present.
- A user-scoped host-key-only test credential round-trip succeeded. This was a harmless test string, not a Noise key, and does not validate the intended system-scope host+TPM2 provider.
- No `/dev/tpm*` device was exposed to this WSL environment.
- A system-scope host+TPM2 attempt from the unprivileged WSL user returned `InteractiveAuthenticationRequired`; it did not establish a successful TPM-backed encryption/decryption test.
- WSL has no Cargo executable. The Windows Rust sysroot currently has only `wasm32-unknown-unknown` and `x86_64-pc-windows-msvc` targets installed; no Linux target is installed.

## 4. Explicit unverified items

The Linux-specific `cfg(target_os = "linux")` source has **not yet been compiled for Linux** in this environment. The passing Cargo test/build results above are Windows-target results; pure NPK2 validation helpers are compiled into the Windows test target, but that is not a substitute for building the Linux-only filesystem and process code.

Still required before this provider can be considered qualified:

1. Compile and run the provider tests on a native Ubuntu 24.04 LTS x86_64 host with the exact systemd version selected for the seed.
2. Confirm the host exposes a usable TPM2 device and that systemd's host+TPM2 encryption works without prompting or fallback.
3. Provision a disposable test key locally as root into a root-owned encrypted credential store, then verify the service manager's `LoadCredentialEncrypted=` delivery and actual `$CREDENTIALS_DIRECTORY` ownership/mode/path.
4. Start and restart a disposable service under its intended unprivileged service account; verify the same public key is derived after restart without exposing private material.
5. Run negative tests on Linux for missing credential directory, symlink/path substitution, wrong network, wrong version, malformed/truncated payload, zero key, invalid permissions, and unavailable TPM2.
6. Review the exact systemd unit hardening, credential recovery/rotation procedure and TPM/OS reinstall recovery policy before provisioning either independent seed.

systemd documentation describes `host+tpm2` as requiring both the original TPM2 chip and the host installation, and documents `LoadCredentialEncrypted=`/ `$CREDENTIALS_DIRECTORY` as the service credential delivery path. References:

- https://www.freedesktop.org/software/systemd/man/255/systemd-creds.html
- https://www.freedesktop.org/software/systemd/man/250/systemd.exec.html
- https://github.com/systemd/systemd/blob/main/docs/CREDENTIALS.md

## 5. Release boundary

- No actual Linux seed host or production Noise key was provisioned.
- No systemd service or public listener was installed or started.
- No public endpoint, bootstrap fingerprint, Genesis signature, asset reserve, or live trading operation was created.
- CP-0655's two-independently-administered-seed requirement remains open.
- Candidate release artifacts remain incomplete; Public Testnet remains **NO-GO / NOT LAUNCHED** and Mainnet/public mining remain **NOT AUTHORIZED**.

The two source files remain uncommitted in the existing dirty worktree. This checkpoint is documentation-only; no broad source staging, source reset, push, or deployment is included.
