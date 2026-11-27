# CP-0668 — Linux Noise provisioner TPM2 fail-closed qualification

Date: 2026-11-14
Project: AI-NATIVE L1 / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Base HEAD: `3ea9375 docs: record POSIX ACL-aware Linux credential loader`
Related: CP-0657, CP-0665, CP-0666, CP-0667
Status: **Linux provisioner binary build PASS; real provisioner invoked without TPM2 and failed closed with no persisted artifact; successful host+TPM2 provisioning remains OPEN**

## 1. Scope

This checkpoint exercises the Linux `noise_key_provisioner` executable itself, beyond `cargo check`. The test deliberately runs on the available Ubuntu 26.04.1 WSL2 environment, where no usable TPM2 device is exposed. The intended outcome is a clean failure with no encrypted file and no plaintext fallback.

This is a negative/fail-closed qualification only. It is not a successful TPM2 provisioning test.

## 2. Build

Using the separate pinned Rust/Cargo 1.82.0 WSL toolchain and ext4-backed target directory:

```sh
cargo build --manifest-path src/native/pow_bench/Cargo.toml --bin noise_key_provisioner --locked
```

Result: **PASS, exit 0**. Existing unrelated dead-code/unused warnings remain. Cargo.lock was not changed.

## 3. Actual provisioner execution

The binary was run as WSL root with:
- a temporary root-owned output directory: `/root/qfp6-provisioner-negative` (mode 0700);
- output filename: `qfp6-noise-static-key`;
- a non-secret test network ID consisting of 32 bytes of `0x31`;
- no supplied private key (the tool generates its own transient Noise XX key and rejects all private-key input flags).

Execution reached the real Linux store path and invoked the fixed `/usr/bin/systemd-creds` command with the required `encrypt --with-key=host+tpm2 --tpm2-pcrs=7 --name=...` arguments. The WSL environment lacks TPM2 support, so provisioning returned:

```text
NOISE_KEY_PROVISIONING_ERROR: protected Noise key provisioning failed: systemd-creds host+TPM2 credential encryption failed
PROVISIONER_EXIT=2
PROVISIONER_FAIL_CLOSED_NO_ARTIFACT=PASS
```

The test harness verified:
- exit code was exactly 2 (the provisioner's expected provisioning-error exit);
- the requested encrypted output file did not exist;
- no temporary file was left in the output directory;
- the root-owned output directory could be removed cleanly after the check.

The provisioner zeroizes its in-memory NPK2 payload immediately after the encryption attempt, before propagating the encryption error. Persistence is reached only after successful systemd-creds output validation. There was no host-only fallback, null-key mode, plaintext key file or emitted private-key material.

A transient random keypair was generated only inside the failing test process so the real provisioner path could execute; it was zeroized in memory on return and was never persisted or used as a network/seed key. No production key was generated or stored.

## 4. Cleanup

A follow-up root-owned WSL cleanup check confirmed all of the following were absent:
- `/root/qfp6-provisioner-negative`
- `/root/qfp6-loadcred-source`
- `/tmp/qfp6-systemd-acl-test`

No transient `qfp6-*.service` unit or installed `qfp6-*.service` unit remained. The disposable ACL fixture and LoadCredential source file had already been deleted by their test harnesses. No credential or test key artifact remains from this qualification.

## 5. QFP6 v06 launch-path wiring review

The active QFP6 v06 paths were traced after the provisioner test:

- `qrun_v06_node.rs` loads the Provider Noise client identity and Q6EA Anchor Noise client identity via `load_protected_noise_private_key()`.
- `qrun_v06_node_runtime_launch/mod.rs` loads the local node static identity using the same central loader; its Provider/Anchor client identities also use the central loader.
- `qrun_v06_node_runtime_launch/permissionless.rs` loads the local node key through the central loader before opening the listener.
- The v06 JSON config path resolver preserves absolute paths; the candidate runtime parser requires absolute paths. Therefore `/systemd-credential/<id>` references are not joined to the config directory or converted into worktree paths.
- QAP1 enforces pairwise-distinct node, Provider and Q6EA Anchor client identities and zeroizes the temporary client-key buffers after transport construction.
- One stale v06 source comment that described the client key provider as Windows-DPAPI-only was corrected to name the platform-native provider (Windows CurrentUser DPAPI / Linux systemd host+TPM2). `cargo fmt -- --check` and `git diff --check` passed after that comment-only correction.

This review does not claim that legacy v0.5 command-line option names have been modernized; they remain outside the scope of this QFP6 v06 launch-path review.

## 6. WSL TPM simulator feasibility

The WSL preflight reported:

- Kernel: `6.18.58.1-microsoft-standard-WSL2`.
- No `/dev/tpm*` device node.
- `modinfo tpm_vtpm_proxy` returned “Module tpm_vtpm_proxy not found”.
- A userspace `swtpm` package candidate exists, but the kernel bridge needed to expose a software TPM as a Linux TPM device node is absent from this WSL kernel.

systemd 255's `systemd-creds --tpm2-device=` accepts a TPM device-node path (for example `/dev/tpmrm0`), `auto`, or `list`; it does not accept an arbitrary swtpm Unix socket as the device argument. A full virtual machine with its own guest kernel and vTPM could be built as a separate simulation, but it would still not qualify a physical seed host. No simulator, VM, TPM bridge or persistent service was installed as part of this checkpoint.

Reference: https://www.freedesktop.org/software/systemd/man/255/systemd-creds.html

## 7. Qualification boundary

This checkpoint demonstrates that the actual Linux provisioner:
- builds successfully for Linux;
- calls the strict host+TPM2/PCR7 path;
- propagates unavailable TPM2 as a provisioning failure;
- does not create an encrypted output file or plaintext fallback when encryption fails.

It does **not** demonstrate:
- successful `systemd-creds host+tpm2` encryption or decryption;
- successful `LoadCredentialEncrypted=` service delivery;
- persistence/restart continuity for a TPM-bound key;
- native Ubuntu 24.04 LTS seed qualification;
- a production key, public node, public listener, Public Testnet or Mainnet.

The earlier CP-0667 transient-service test used plain `LoadCredential=` on WSL systemd 259.5. It verified manager-created POSIX ACL delivery and the production loader, but it was not encrypted credential delivery.

## 8. Repository handling

- Documentation-only checkpoint.
- Source changes in `noise_key_provisioning.rs` and `noise_key_provisioner.rs` remain uncommitted in the existing dirty worktree, mixed with earlier QFP6 changes.
- Only documentation files are intended for this commit.
- No push, deployment, public listener, permanent service, production key or release authorization is included.
