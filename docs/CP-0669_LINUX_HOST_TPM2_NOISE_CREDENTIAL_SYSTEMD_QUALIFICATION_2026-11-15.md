# CP-0669 — Linux host+TPM2 Noise Credential Provisioner and systemd Service Qualification

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Observed local HEAD before this checkpoint: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Upstream: `origin/feat/cp0600-bootstrap-sync-startup`
Observed ahead count before this checkpoint: 12 commits
Status: **PASS for the disposable Ubuntu vTPM2 credential custody path; local test only; no production release authorization**

## 1. Objective

Qualify the Linux `noise_key_provisioner` source path from the current QFP6 candidate on a real Ubuntu 24.04 guest with Hyper-V virtual TPM 2.0, then prove that systemd can inject the encrypted credential into an unprivileged service and that the project loader can recover the expected 32-byte key.

This checkpoint is limited to a disposable test key and a local virtual machine. It does not use the owner Genesis signing key, a production Noise identity, a wallet seed, or a value-bearing account.

## 2. Build provenance

- Source worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111\src\native\pow_bench`.
- Rust toolchain: `rustc 1.82.0`; `cargo 1.82.0`.
- Build environment: existing WSL Ubuntu toolchain and Cargo cache on the same Windows workstation.
- Build flags: `cargo check --bin noise_key_provisioner --locked --offline -j1`, then `cargo build --bin noise_key_provisioner --locked --offline -j1`.
- Provisioner binary SHA-256: `9547ecb60f705ba7f9031eadcca0775cb1aa9e5692966ca75c8804867abb62c4`.
- A temporary helper was built in a separate copy of the same crate using the original `Cargo.lock`, with `--locked --offline`; no dependency or lockfile change was introduced.
- Helper binary SHA-256: `bf9239e3460ed23b505594ac7cc6263b2b0625e16831a0bc649ba56d14e495a1`.
- Both binaries were copied to the Ubuntu VM and the provisioner hash was checked across WSL, Windows and the guest.

## 3. Guest and TPM prerequisites

The test guest was `AIN1-QFP6-Ubuntu2404-TPM2-QA` (Ubuntu 24.04.5 LTS, Hyper-V Gen2).

Previously verified guest properties:
- vTPM is enabled in Hyper-V.
- Secure Boot is enabled.
- Ubuntu exposes `/dev/tpm0` and `/dev/tpmrm0`.
- Kernel sysfs reports TPM major version 2 and recognizes the Microsoft virtual TPM device.
- systemd 255 and `systemd-creds` are present.
- `systemd-creds --tpm2-device=list` detects `/dev/tpmrm0` via `tpm_crb`.

## 4. Tests performed

### 4.1 systemd-creds host+TPM2/PCR7 round-trip

A disposable non-secret byte string was encrypted using:
- `systemd-creds encrypt --with-key=host+tpm2 --tpm2-pcrs=7`

It was decrypted and compared byte-for-byte with the original. Result:
- `SYSTEMD_HOST_TPM2_PCR7_ROUNDTRIP=PASS`
- Temporary file mode was `0600`, root-owned.
- Temporary file and directory were removed.

### 4.2 Candidate Noise provisioner

The current `noise_key_provisioner` binary was executed with a test-only 32-byte network ID (`0x31` repeated 32 times) and a root-owned output path under `/var/lib/qfp6-lab`.

The subsequent systemd encrypted-credential service test below proves that the provisioned encrypted file was readable through the same systemd host+TPM2 path. The generated test private key was not printed or exported.

### 4.3 Unprivileged systemd service using the project loader

A temporary helper was linked against the current candidate crate and called the actual `load_protected_noise_private_key` function with:
- credential path: `/systemd-credential/qfp6-noise-static-key`
- expected network ID: the same disposable 32-byte test network ID

A transient unit was launched with:
- `User=qfp6lab`
- `Group=qfp6lab`
- `LoadCredentialEncrypted=qfp6-noise-static-key:/var/lib/qfp6-lab/qfp6-noise-static-key`

The helper returns exit code 0 only if the project loader recovers a non-zero 32-byte private key and wipes the in-memory buffer before exiting. It returns non-zero if loading or validation fails.

Observed systemd result:
- Unit: `qfp6-noise-credential-probe.service`
- `Finished with result: success`
- main process: `code=exited/status=0`
- `SYSTEMD_PROBE_EXIT=0`

The transient unit was created with `--collect`; journald entries were no longer present when queried afterward. The successful unit result and zero exit status are retained as the evidence. The helper did not print private-key material.

## 5. Cleanup

Cleanup was explicitly approved and executed. A subsequent read-only check confirmed:
- `/var/lib/qfp6-lab` absent.
- `/home/qfp6lab/noise_key_provisioner` absent.
- `/home/qfp6lab/qfp6_noise_loader_probe` absent.
- Temporary encrypted credential absent.
- `swapon --show` returned no active swap; `/swapfile` was removed.
- Guest memory after cleanup: approximately 553 MiB available.
- Guest root disk: approximately 34 GiB free.

No persistent service unit was installed. No firewall, router, public listener or port was changed.

## 6. Candidate release boundary

This qualification demonstrates a working disposable **Linux host+TPM2 encrypted-credential handoff to an unprivileged systemd service** on the local Ubuntu vTPM guest.

It does not establish:
- production seed-host provisioning;
- independent public-operator key custody;
- public IPv6/TCP reachability;
- a signed CP-0651 Genesis;
- a production network identity or bootstrap peer set;
- permissionless public mining authorization;
- Mainnet or value-bearing transaction readiness.

The current candidate manifest remains `production_authorized=false` and `mainnet_status=NOT_AUTHORIZED`. Genesis snapshot, Q6GD, Q6CP, Q6PN and bootstrap peer-set artifacts remain marked missing in the current candidate manifest. Q6TS is not required for the permissionless full-history profile.

## 7. Worktree and website documentation state

The current candidate worktree remains preserved. At the time of this checkpoint it was 12 commits ahead of the origin branch and contained pre-existing local source/manifest modifications and untracked CP-0632–CP-0668 material. No reset, rebase, commit, push, merge or tag was performed for this checkpoint.

Local website documentation was reconciled (not published):
- `index.html`: changed the stale 10B/CP-0437 presentation to the active CP-0651 candidate economics and linked the current CP-0651/CP-0652 records.
- `economics.html`: updated the supply page, metadata and structured data to the 7B/1B/six-label CP-0651 policy.
- `status.html`: distinguished the completed scoped CP-0566C NetBird two-host qualification from CP-0649 loopback two-source agreement and the separate CP-0656 public IPv6 ingress limitation.
- These site changes are local only; they have not been committed or pushed to GitHub Pages.

## 8. Next steps

1. Validate the three edited HTML pages and run `git diff --check`.
2. Reconcile the remaining public-facing documents and README with CP-0651 without changing the release manifest's NO-GO state.
3. Reconcile any independently provisioned seed-host endpoints, public keys and trust-domain evidence only from verifiable host outputs.
4. Complete final CP-0651 Genesis/Q6GD/Q6CP/Q6PN/bootstrap artifacts and owner signature through the protected owner-controlled signer.
5. Complete independent consensus, cryptography and economics reviews and separate public listener qualification before any zero-value Public Testnet launch decision.
6. Only after a genuine supported trading venue or pool exists, prepare CMC tracked-listing and market-data submissions. TradingView chart integration must use a real backend datafeed; order entry requires a Broker API/service.

**Decision:** CP-0669 is a positive local security/custody qualification, not a release authorization. No public launch, asset transfer, market price, exchange listing or real-value trade occurred.
