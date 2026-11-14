# CP-0667 — systemd POSIX ACL-aware Linux Noise credential loader

Date: 2026-11-14
Project: AI-NATIVE L1 / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Base HEAD: `f0ae428 docs: record WSL-native Linux credential loader qualification`
Related: CP-0657, CP-0655, CP-0665, CP-0666, CP-0668
Status: **systemd-style POSIX ACL, actual plain LoadCredential service delivery, and no-ACL credential loader paths PASS in WSL/ext4; provisioner fail-closed behavior PASS without TPM2; successful host+TPM2 provisioning remains OPEN**

## 1. Security compatibility finding

A source-level review of systemd's v255 stable implementation found that the original CP-0665/CP-0666 loader checks were too narrow for ACL-capable Linux filesystems.

In systemd v255, `write_credential()` creates a credential file, changes it to mode 0400, and attempts to grant the service UID read access with a POSIX ACL. If ACLs are unavailable, systemd can instead transfer ownership to the service UID. The credential directory is made read-only and the same service-UID ACL/fallback strategy is applied.

Consequently, the service-visible metadata can have either of these forms:

| Filesystem path | Credential directory | Credential file |
|---|---|---|
| ACL-capable filesystem | root-owned, mode 0550, one service-UID r-x ACL | root-owned, mode 0440, one service-UID r-- ACL |
| no-ACL fallback | service-UID-owned, mode 0500, no access ACL | service-UID-owned, mode 0400, no access ACL |

The group bits in 0550/0440 represent the POSIX ACL mask; they do not mean that the owning group receives access. systemd's minimal ACL leaves the owning group and OTHER permissions empty and grants access through one named service UID.

This was a material compatibility issue: a loader accepting only service-UID ownership plus 0500/0400 could reject valid credentials delivered by systemd on an ACL-capable filesystem.

Source references inspected from the systemd v255 stable branch:

- `src/core/exec-credential.c`: `write_credential()`, `acquire_credentials()`, and credential-directory setup.
- `src/shared/acl-util.c`: `fd_add_uid_acl_permission()`, `fd_acl_make_read_only()`, and the no-ACL fallback.

Links:
- https://github.com/systemd/systemd-stable/blob/v255-stable/src/core/exec-credential.c
- https://github.com/systemd/systemd-stable/blob/v255-stable/src/shared/acl-util.c

## 2. Corrective implementation

Changed source file: `src/native/pow_bench/src/noise_key_provisioning.rs`.

The Linux loader now accepts only the two explicit systemd delivery forms described above.

### Strict POSIX ACL validation

- Reads the opened inode's `system.posix_acl_access` xattr using `fgetxattr`.
- Validates Linux POSIX ACL version 2 and the exact five-entry ACL layout used by systemd: USER_OBJ, one named USER entry matching the process effective UID, GROUP_OBJ, MASK, and OTHER.
- For the directory, owner and service entries must be exactly r-x; owning group and OTHER must be empty; mask must be exactly r-x.
- For the file, owner and service entries must be exactly r--; owning group and OTHER must be empty; mask must be exactly r--.
- Additional named users/groups, wrong UIDs, group/OTHER access, broader masks, malformed/truncated ACLs, unsupported versions, and unexpected ACL shapes are rejected.
- On the no-ACL fallback, direct ownership by the effective service UID and exact 0500/0400 modes are accepted only when the access-ACL xattr is absent/unsupported.

### Path and file-opening hardening

- Requires the credential directory path to be absolute and canonical.
- Opens the directory with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and verifies its inode/device against the pre-open metadata.
- Opens the validated single-component credential ID using `openat()` relative to the already-validated directory file descriptor, with `O_NOFOLLOW | O_CLOEXEC`.
- Verifies regular-file type, exact payload length, and single-link count from the opened descriptor.
- Maps a symlink-related `ELOOP` to `InvalidPath`; missing credentials remain `SystemdCredentialUnavailable`.
- Keeps the existing NPK2 magic/version/network binding/nonzero-key checks and payload zeroization. The Windows NPK1/DPAPI path is unchanged.

## 3. Tests added and exact outcomes

### POSIX ACL policy unit tests

New parser tests accept the minimal systemd directory/file ACL forms and reject:
- group permissions,
- excessive ACL mask,
- OTHER permissions,
- a different service UID,
- extra named-user ACL entries,
- wrong ACL version,
- truncated ACL bytes.

### Linux runtime tests (Ubuntu 26.04.1 WSL2, ext4, Rust/Cargo 1.82.0)

| Command | Result |
|---|---:|
| `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_key_provisioning::tests --locked` | 7 passed, 0 failed, 2 ignored |
| Ignored root-owned ACL fixture test, run separately as service UID | 1 passed, 0 failed |
| Ignored actual systemd `LoadCredential=` integration test, run inside transient service | 1 passed, 0 failed |
| `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked` | PASS, exit 0 |

The ACL integration test created a disposable synthetic NPK2 credential on the WSL ext4 filesystem with these observed attributes:

- Directory: UID 0, mode 0550, link count 2.
- Credential file: UID 0, mode 0440, link count 1.
- Named service UID in both access ACLs: 1000.
- Owning group and OTHER ACL permissions: empty.
- The test process was run as UID 1000 and successfully loaded the synthetic 32-byte key through the production loader helper.

The root-owned directory and file were created with valid `system.posix_acl_access` xattrs; the test process immediately dropped from root to the unprivileged `asuswhoami` UID before invoking the Rust test. Fixture creation and test execution were performed in one WSL invocation to avoid any temporary-directory lifetime ambiguity.

The ordinary no-ACL loader test also remains green, including rejection of hardlinks, symlinks, wrong network, writable modes and overly accessible directories.

### Actual systemd service-delivery integration (plain LoadCredential)

A separate transient system service was started in WSL systemd 259.5 with `User=asuswhoami` (UID 1000) and `LoadCredential=qfp6-noise-static-key:/root/qfp6-loadcred-source`. The source file contained only the same synthetic 70-byte NPK2 test payload. systemd created the actual service credential directory at `/run/credentials/qfp6-loadcredential-probe.service` and exposed these observed values inside the unit:

- Credential directory: UID 0, mode 0550.
- Credential file: UID 0, mode 0440, link count 1.
- Access ACL: one named UID 1000 entry with r-x on the directory / r-- on the file; owning group and OTHER are empty.

The compiled provider test harness itself was then executed as the transient service's UID 1000. `systemd_credential_loader_accepts_actual_systemd_credentials_directory` called the production `load_systemd_credential()` path, read the actual `$CREDENTIALS_DIRECTORY` supplied by systemd, and passed: 1 passed, 0 failed. The transient service was collected after exit and the root source fixture was deleted.

This is a real systemd `LoadCredential=` (unencrypted) integration test on systemd 259.5. It validates manager-created ACL delivery and production-loader access, but is not `LoadCredentialEncrypted=`, does not use `systemd-creds host+tpm2`, and does not validate TPM-backed decryption.

### Windows regression (Rust 1.82.0 MSVC)

| Command | Result |
|---|---:|
| `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_key_provisioning::tests --locked --offline` | 7 passed, 0 failed |
| `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked --offline` | PASS, exit 0 |
| `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check` | PASS |
| `git diff --check` | PASS |

Existing unused/dead-code warnings in unrelated modules and tools remain; no errors occurred in the validated targets. Cargo.lock was not changed; Cargo checks/tests used `--locked`.

## 4. Explicit qualification boundary

This work now provides direct Linux execution evidence for:
- the Linux-specific provider code compiling,
- the no-ACL direct-owner path,
- the root-owned POSIX ACL path used by systemd on ACL-capable filesystems,
- strict rejection of broad or malformed ACL grants,
- all Linux binary targets compiling.

It still does **not** establish a production systemd host+TPM2 credential round-trip or a qualified seed:

- The environment is Ubuntu 26.04.1 LTS under WSL2 with systemd 259.5, not a native Ubuntu 24.04 LTS seed host running systemd 255.
- WSL exposes no usable `/dev/tpm*` device; its TPM probe remains `partial`.
- The root-owned ACL fixture test uses a synthetic NPK2 payload and POSIX ACLs constructed to match systemd v255 source behavior. The separate transient-service test verified actual `LoadCredential=` delivery on systemd 259.5 and invoked the production loader inside that service, but it did not invoke `LoadCredentialEncrypted=` or decrypt a TPM-bound credential.
- No production/seed Noise private key was persisted or provisioned. CP-0668 separately ran the actual provisioner in a no-TPM failure test; it generated a one-time ephemeral keypair in memory, failed at host+TPM2 encryption, zeroized the payload/key material and left no output file. No persistent seed service was installed or started; only disposable transient WSL test units ran.
- No independently administered second seed, public endpoint, Genesis signature or live-market operation was qualified.

## 5. Next qualification gate

On an actual Ubuntu 24.04 LTS x86_64 host with a usable TPM2 device:

1. Run the provider build/tests using the pinned Rust 1.82.0 toolchain.
2. Verify systemd's host+TPM2 encryption using PCR 7 without prompting or fallback.
3. Provision only a disposable test key as root into the encrypted credstore.
4. Start a hardened disposable service with `LoadCredentialEncrypted=` under its intended unprivileged UID and prove that the loader accepts the real `$CREDENTIALS_DIRECTORY` metadata (both ACL and fallback behavior as applicable).
5. Verify service restart/key continuity, credential absence, wrong-network, malformed-payload, path substitution, permission and TPM failure behavior.
6. Review state-directory write grants, TPM/Secure Boot/OS reinstall recovery and public bootstrap-pin rotation before either independent seed is provisioned.

## 6. Repository handling

- This checkpoint is documentation-only; CP-0668 records the provisioner fail-closed run.
- The provider source changes remain uncommitted in the pre-existing dirty worktree, mixed with earlier QFP6 development changes.
- CP-0665/CP-0666 documentation updates and this CP-0667 document are documentation-only records; no provider source was included in the docs commit.
- No source-wide staging, reset, clean, push, service launch, public listener or deployment is included.
