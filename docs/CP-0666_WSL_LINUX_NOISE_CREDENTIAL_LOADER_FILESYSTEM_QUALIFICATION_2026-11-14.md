# CP-0666 — WSL-native Linux Noise credential loader filesystem qualification

Date: 2026-11-14
Project: AI-NATIVE L1 / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Base HEAD: `88601bf docs: record TPM probe and systemd 255 provider boundary`
Related: CP-0657, CP-0655, CP-0665, CP-0667
Status: **Initial no-ACL Linux filesystem path PASS; systemd ACL-capable path additionally verified in CP-0667; hardware TPM2 and production systemd service qualification remain OPEN**

## 1. Scope

This checkpoint records the first execution of the Linux-specific Noise static-key provider code on a Linux runtime. The development machine is Windows `heymed`; the Linux runtime is Ubuntu 26.04.1 LTS under WSL2. A separate Linux Rust/Cargo 1.82.0 toolchain was installed for this validation, with Cargo cache/build artifacts on D:. The existing Windows toolchain was not modified.

The test validates the Linux credential-directory loader and its POSIX file checks. It does not provision a real Noise key or contact a TPM.

## 2. Linux filesystem validation

The test calls the production loader helper `load_systemd_credential_from_directory` with a synthetic NPK2 payload in a temporary Linux directory.

The tested acceptance/rejection behavior is:

- The no-ACL fallback path is accepted: a service-owned, private credential directory with mode 0500 and a single regular credential file with mode 0400. The decoded key matches the synthetic fixture.
- A network-ID mismatch returns `NetworkMismatch`.
- A hard-linked credential is rejected because link count is not exactly one.
- A symlink credential path is rejected.
- A credential file with mode 0600 is rejected.
- A service-owned directory with mode 0550 and no matching systemd ACL is rejected. This does not cover systemd's root-owned ACL mode 0550; that separate form was discovered and verified later in CP-0667.
- Pure payload tests additionally reject wrong version, zero key, incorrect magic and truncated payload, and verify that successful decode zeroizes the mutable payload buffer.
- A Linux non-Windows test verifies DPAPI calls fail closed.

### Fixture correction recorded

The first Linux run returned 4 passed / 1 failed. The loader rejected the test directory because the fixture had mode 0700, which includes the owner's write bit. This is the intended fail-closed behavior for a read-only systemd credential directory; the fixture, not the loader, was inconsistent with the intended systemd contract.

The fixture was corrected to use mode 0500 for acceptance tests. It temporarily switches to 0700 only while creating/removing test hardlinks/symlinks, then restores 0500 before invoking the loader. The second Linux run passed all five targeted tests. This checkpoint established the no-ACL fallback form; a later source review found that systemd v255 can instead use root-owned POSIX ACLs on ACL-capable filesystems. CP-0667 documents and tests that additional supported form.

## 3. Exact validation results

Linux / Ubuntu 26.04.1 WSL2 / Rust 1.82.0:

| Command/check | Result |
|---|---:|
| `cargo check --manifest-path src/native/pow_bench/Cargo.toml --lib --locked` | PASS |
| `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_key_provisioning::tests --locked` | 5 passed, 0 failed |
| `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked` | PASS, exit 0 |

The `--bins` check includes the Linux `noise_key_provisioner` and the QFP6 node launcher binaries. Cargo.lock was not changed; all commands used `--locked`.

Windows / Rust 1.82.0 MSVC regression after the fixture correction:

| Command/check | Result |
|---|---:|
| `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_key_provisioning::tests --locked --offline` | 5 passed, 0 failed |
| `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked --offline` | PASS, exit 0 |
| `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check` | PASS |
| `git diff --check` | PASS |

Existing unused/dead-code warnings remain in unrelated legacy modules and tools; no compile errors occurred in the validated targets.

## 4. Qualification boundary / remaining gates

The WSL environment reports systemd 259.5 and has `/usr/bin/systemd-creds`. A user-scoped host-key-only round-trip of a harmless test string passed. However:

- No `/dev/tpm*` device is exposed to WSL.
- `systemd-analyze has-tpm2` returned `partial` (exit 27), with required TPM/firmware/driver/subsystem support unavailable.
- A system-scope host+TPM2 attempt from the unprivileged WSL user returned `InteractiveAuthenticationRequired`; no successful host+TPM2 encryption/decryption was demonstrated.
- The Linux integration test uses a synthetic unencrypted NPK2 payload in a temporary directory. It does **not** execute a real systemd `LoadCredentialEncrypted=` service, invoke the Linux provisioner as root, or use hardware TPM2.
- No native Ubuntu 24.04 LTS server, independently administered seed host, production Noise key, public listener or systemd service was installed or started.

Therefore this checkpoint qualifies Linux compilation and the filesystem acceptance/rejection logic under WSL only. It does **not** qualify a production seed, the systemd host+TPM2 key provider, independent public nodes, Public Testnet or Mainnet.

## 5. Next qualification step

On an actual Ubuntu 24.04 LTS x86_64 host with a usable TPM2 device:

1. Build the same source using the pinned Rust 1.82.0 toolchain.
2. Verify `systemd-analyze has-tpm2` and a host+TPM2 encryption/decryption round-trip with PCR 7, without weakening the key mode.
3. Provision only a disposable test Noise key as root to the root-managed encrypted credstore.
4. Install a hardened disposable system unit with `LoadCredentialEncrypted=`, run it as the intended unprivileged user, and verify the runtime reference resolves inside the service's actual `$CREDENTIALS_DIRECTORY`.
5. Test service restart and key continuity, missing-credential failure, invalid permissions, path substitution and TPM unavailability.
6. Review TPM/Secure Boot/OS reinstall recovery and the public pin rotation plan before provisioning either independent seed.

## 6. Repository handling

The Linux provider source and provisioner source remain uncommitted in the pre-existing dirty worktree. This checkpoint, the CP-0665 update, and the CP-0667 ACL follow-up are documentation-only records; the provider source remains uncommitted. No broad source staging, reset, push, deployment or service launch is part of CP-0666.
