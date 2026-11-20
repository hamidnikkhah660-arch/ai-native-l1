# CP-0665 — Linux systemd credential Noise-key provider candidate

Date: 2026-11-14
Project: AI-NATIVE L1 / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Base documentation commit: `6184f35`
Status: **candidate implementation added; Windows and WSL-native Linux compile/targeted filesystem checks PASS; native Ubuntu seed + hardware TPM2/service qualification remain OPEN**

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
- Provisioning calls the fixed `/usr/bin/systemd-creds` executable with `encrypt --with-key=host+tpm2 --tpm2-pcrs=7 --name=<credential-id> - -`. PCR 7 is made explicit rather than relying on the systemd 255 default. The output-path validator requires effective UID 0 before this command can be reached; no host-only or null-key downgrade is attempted.
- The plaintext payload is passed through stdin, not command-line arguments or a plaintext key file, and is zeroized after the encryption attempt.
- No host-only or null-encryption fallback is used. If systemd-creds, host+TPM2 access, or the protected output path requirements are unavailable, provisioning fails closed.
- Encrypted output is atomically persisted under an absolute root-owned, non-symlink, non-group/world-writable parent directory. The temporary/output file is created with mode 0600.
- The Linux runtime configuration uses an explicit virtual reference `/systemd-credential/<credential-id>`. The systemd unit operator must map the encrypted file through `LoadCredentialEncrypted=<credential-id>:<encrypted-file-path>`.
- Runtime loading is permitted only from the service-provided `$CREDENTIALS_DIRECTORY`. The loader checks the credential path and directory, symlink/hardlink conditions, owner, access mode/ACL, exact payload length, NPK2 version, nonzero key, and network ID. It uses no-follow and close-on-exec flags and zeroizes the payload buffer. CP-0667 adds strict support for both systemd v255's root-owned POSIX ACL delivery form (directory/file mode 0550/0440, one named service-UID grant) and its no-ACL service-owned fallback (0500/0400).
- Missing credential directory, missing credential, invalid reference, wrong network, malformed envelope, or unsupported platform are rejected. There is no plaintext fallback.

The provisioner now prints only the protected-file path, public network ID, public Noise static key, protection mode, runtime reference, and the corresponding systemd directive. It never prints or accepts the generated private key.

### Intended system-service wiring (template; not installed)

For a system service running under a dedicated unprivileged account, the encrypted file and the runtime reference must be distinct:

- Encrypted, root-managed file: `/etc/credstore.encrypted/qfp6-noise-static-key`
- QFP6 runtime config value for `node_noise_private_key_path`: `/systemd-credential/qfp6-noise-static-key`

A minimal systemd service drop-in shape is:

```ini
[Service]
User=qfp6
Group=qfp6
LoadCredentialEncrypted=qfp6-noise-static-key:/etc/credstore.encrypted/qfp6-noise-static-key
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
```

The unit must also grant write access only to the specific durable QFP6 state directories it needs; the state path was deliberately not guessed here. systemd 255 documents that encrypted credentials are decrypted/authenticated by the service manager, exposed read-only through `$CREDENTIALS_DIRECTORY`, and accessible to the unit's `User=` identity. It also automatically adds `/dev/tpmrm0` access needed for `LoadCredentialEncrypted=` when the relevant device restrictions are enabled. This template has not been installed or tested on a real seed host.

The encrypted credential is intentionally bound to both the original host installation and its TPM2 device. PCR 7 is explicitly selected; firmware/Secure Boot measurement changes may therefore make an existing credential undecryptable. Replacing the TPM or reinstalling the OS also requires a controlled key-rotation/reprovision procedure and a new public bootstrap pin. Do not copy one seed's encrypted credential to another seed or weaken the policy to recover it.

The operator should provision the encrypted file as root using the Linux build of `noise_key_provisioner`, verify the printed public key/fingerprint out-of-band, set the runtime config to the virtual reference above, validate the config/package digest, then run `systemd-analyze verify` and inspect the effective unit before starting it. No service-start command is part of this candidate checkpoint.

### Additional source hardening

The Linux output-path validator now walks every directory component from `/` to the encrypted file's parent and requires each to be a real root-owned directory without group/world write permission. This closes the weaker case where a secure-looking final directory could sit beneath an untrusted writable ancestor.

## 3. Local validation actually completed

Windows development worktree:

| Check | Result |
|---|---:|
| `cargo test --lib noise_key_provisioning::tests --locked --offline` | 7 passed, 0 failed |
| `cargo check --bins --locked --offline` | PASS, exit 0 |
| `cargo fmt -- --check` | PASS |
| `git diff --check` | PASS |

The Windows target preserves the NPK1/DPAPI round-trip, network-binding, zero-key and corrupt-envelope cases. The NPK2 pure validation helpers are also exercised on Windows for safe credential IDs, network binding, version/key/magic/length rejection and payload zeroization.

Linux-native development worktree (Ubuntu 26.04.1 LTS under WSL2, Rust/Cargo 1.82.0):

| Check | Result |
|---|---:|
| `cargo check --lib --locked` | PASS |
| `cargo test --lib noise_key_provisioning::tests --locked` | 7 passed, 0 failed, 2 ignored (both systemd integrations separately run; see CP-0667) |
| `cargo check --bins --locked` | PASS, exit 0 |

The Linux-target test set includes the filesystem loader integration test: an owner-only read-only credential file is accepted; wrong network, hardlink, symlink, writable file mode and overly accessible credential directory are rejected. Pure NPK2 validation rejects wrong version, zero key, wrong magic and truncated data. CP-0667 additionally exercises (1) a root-owned POSIX ACL directory/file fixture as the unprivileged service UID and (2) the production loader inside a real transient WSL systemd service using plain `LoadCredential=`. All payloads are synthetic; these tests do not invoke TPM2 or provision a real encrypted credential.

Windows formatting and whitespace checks were rerun after the final test-fixture edit: `cargo fmt -- --check` and `git diff --check` both PASS. The subsequent Linux filesystem run, fixture correction, and exact Linux command results are recorded in CP-0666.

WSL development smoke only:

- Local distribution: Ubuntu 26.04.1 LTS under WSL2.
- systemd: 259.5; `/usr/bin/systemd-creds` is present.
- A user-scoped host-key-only test credential round-trip succeeded. This was a harmless test string, not a Noise key, and does not validate the intended system-scope host+TPM2 provider.
- No `/dev/tpm*` device was exposed to this WSL environment. The systemd TPM probe (`systemd-analyze has-tpm2`; the `systemd-creds has-tpm2` alias redirected to it) returned `partial`, with firmware, driver, subsystem and required TPM2 libraries unavailable (exit 27).
- A system-scope host+TPM2 attempt from the unprivileged WSL user returned `InteractiveAuthenticationRequired`; it did not establish a successful TPM-backed encryption/decryption test.
- A separate Linux Rust 1.82.0 toolchain was installed inside Ubuntu WSL for development; its CARGO_HOME and build artifacts are on D:. The existing Windows Rust toolchain was left unchanged.

## 4. Explicit unverified items

The Linux-specific `cfg(target_os = "linux")` source has been compiled on Ubuntu 26.04.1 WSL2 with Rust 1.82.0, including library/binary checks and direct filesystem tests for the owner-only and root-owned ACL forms (details in CP-0666 and CP-0667). This is Linux compilation, WSL filesystem evidence, and plain `LoadCredential=` service-delivery evidence, but **it is not native Ubuntu 24.04 host qualification and does not prove `LoadCredentialEncrypted=` delivery with host+TPM2, hardware TPM2 encryption, or a production seed restart**. WSL exposed no usable TPM2 device.

Still required before this provider can be considered qualified:

1. Run the same provider tests on a native Ubuntu 24.04 LTS x86_64 host with the exact systemd version selected for the seed.
2. Confirm that the host exposes a usable TPM2 device and that systemd's host+TPM2 encryption with PCR 7 works non-interactively without any host-only/null fallback.
3. Provision only a disposable test key as root into a root-owned encrypted credential store; verify systemd `LoadCredentialEncrypted=` delivery and the actual `$CREDENTIALS_DIRECTORY` ownership/mode/path for the intended unprivileged service account.
4. Start and restart a disposable service; verify that the same public key is derived after restart without exposing private material.
5. Add/run native-host negative tests for absent credential directory, missing credential, path substitution, wrong network/version, malformed payload, zero key, invalid owner/modes and TPM2 unavailability. WSL currently verifies the loader filesystem rules and NPK2 parser, but not TPM2 failure inside a real system service.
6. Review unit sandboxing, state-directory write grants, credential rotation and TPM/OS reinstall recovery before provisioning either independent seed.

systemd documentation describes `host+tpm2` as requiring both the original TPM2 chip and the host installation, and documents `LoadCredentialEncrypted=`/ `$CREDENTIALS_DIRECTORY` as the service credential delivery path. References:

- https://www.freedesktop.org/software/systemd/man/255/systemd-creds.html
- https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html
- https://github.com/systemd/systemd/blob/main/docs/CREDENTIALS.md
- systemd v255 credential ACL implementation details and Linux validation: see CP-0667.

## 5. Release boundary

- No actual Linux seed host or production Noise key was provisioned.
- No systemd service or public listener was installed or started.
- No public endpoint, bootstrap fingerprint, Genesis signature, asset reserve, or live trading operation was created.
- CP-0655's two-independently-administered-seed requirement remains open.
- Candidate release artifacts remain incomplete; Public Testnet remains **NO-GO / NOT LAUNCHED** and Mainnet/public mining remain **NOT AUTHORIZED**.

The two source files remain uncommitted in the existing dirty worktree. This checkpoint is documentation-only; no broad source staging, source reset, push, or deployment is included.
