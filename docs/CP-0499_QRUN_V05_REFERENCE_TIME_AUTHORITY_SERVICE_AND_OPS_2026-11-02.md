# CP-0499 — QRun v0.5 authenticated reference-time Authority service and operations

Date: 2026-11-02

Status: **A Windows DPAPI-backed RTP1/TMA1 Authority service, offline policy creation mode, authenticated probe mode, and repeatable multi-process restart smoke test are implemented. Public Alpha runtime integration exists; Mainnet remains gated.**

## Gap closed

CP-0498 wired QRun public-node live admission to the existing signed reference-time client, but the repository did not yet contain an operator executable that could provision the signer, serve bounded RTR1/TMA1 exchanges, or create a correctly signed RTP1 policy. A client-only deployment was not operationally complete.

This checkpoint adds the missing Authority-side process and an operator path that can be repeated on a Windows host.

## Implementation

### Key custody and separation

Two new immutable DPAPI key roles were added to ASK1:

- `reference-time-authority` — signs each TMA1 response and is intended to stay on the authority host.
- `reference-time-policy-admin` — signs RTP1 policy documents and should be controlled separately from the online Authority process.

The existing role and Network ID binding remain enforced by the protected-key loader. Seeds are generated using the OS cryptographic random source, stored through Windows CurrentUser DPAPI, and are not printed or written as plaintext key files. Public keys are printed for out-of-band pinning. Protected key files are tied to the Windows user and machine; they are not portable backups.

### New executable

Cargo auto-discovers `src/bin/qrun_v05_reference_time_authority.rs`, which provides four operator modes:

1. `provision-key` — generates and protects one of the two reference-time key roles.
2. `create-policy` — validates the authority public key, loads only a Policy Admin role key, signs an RTP1 policy, and creates the output file without overwriting an existing file.
3. `serve` — runs the independent TCP Authority service.
4. `probe` — loads and verifies an RTP1 file, constructs the same persistent authenticated provider used by QRun, and obtains a real TMA1 sample over TCP.

The policy output is domain-separated and binds Network ID, policy sequence, Authority public key, maximum round-trip time, and optional local-clock-skew bound. A failed protected-key role match is rejected before policy creation.

### TCP Authority service

The new `reference_time_authority` library module:

- accepts exactly one fixed-size RTR1 request per TCP connection;
- validates request magic, protocol version, Network ID and a nonzero 32-byte challenge before consuming a sequence;
- uses the Authority host Unix clock as its signed time input;
- durably reserves a bounded per-network sequence range before the service becomes ready, then claims unique sequence values from that in-memory lease before signing/sending TMA1 responses;
- signs the exact TMA1 body with the pinned Ed25519 Authority key and the existing attestation domain;
- enforces a total two-second request/response I/O deadline;
- uses a bounded worker ceiling of 32 concurrent connections.

The Authority reserves sequence ranges of 64 values using one durable RTS1 high-water update at startup (and again only when a lease is exhausted). Concurrent request handlers claim unique values under an in-process mutex, avoiding a file replacement/fsync on every time sample. A crash or restart intentionally skips the unused suffix of the previous lease; the next process reserves a fresh range strictly above the prior durable high-water. No sequence can be reused. The client accepts strictly increasing sequence values; gaps are safe. With a 64-value lease, a restart can skip up to 63 unused values.

The Authority sequence store uses the existing RTS1 durable, process-exclusive writer lock. It must be held separately from the signing-key file. One Authority process is active for a given local sequence store at a time.

### Network exposure

- Default listener: `127.0.0.1:49550`.
- A non-loopback bind is rejected unless the operator explicitly passes `--allow-non-loopback true`.
- Multicast IPs and port zero are rejected.
- External firewall/IP allow-list policy remains an operator responsibility.
- RTR1 requests are not authenticated and the response carries no confidentiality requirement; TMA1 authenticity is provided by the signature. The worker cap and I/O deadlines bound, but do not eliminate, denial-of-service risk.

### Time trust model

The Authority signs the time reported by its own operating-system clock. Therefore the host clock discipline, monitoring, patching, physical/virtual host security and availability are trust dependencies. RTP1 may enforce a client-local clock-skew sanity bound; the smoke test uses 300 seconds.

This service is a single trusted time attester, **not** BFT time consensus, not an NTP implementation, and not a quorum of independent clocks. It does not make a bad Authority clock correct. Multiple independently active Authorities sharing the same Network ID are not supported by this local RTS1 sequence-store design.

## Repeatable operational smoke test

New script:

`tools/qrun-v05-reference-time-authority-smoke.ps1`

Run from a Windows PowerShell session in the repository:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\qrun-v05-reference-time-authority-smoke.ps1
```

The script builds the executable offline when needed, uses an ephemeral Network ID and temporary directory, provisions both DPAPI roles, creates a signed RTP1 policy with a 300-second local-clock sanity bound, starts the Authority as an independent process, runs authenticated probes from two independent client state files (node 1 and node 2), restarts the Authority, then verifies that node 1's next accepted sequence is 65 because the restarted process durably reserves the next 64-value lease (65-128). It also verifies that public binding without explicit opt-in and use of the Authority key as the Policy Admin role both fail closed. Expected-failure CLI checks run as child processes and verify both the exit code and diagnostic. Temporary smoke-test key and state files are removed at exit.

## Observed Windows validation

The smoke test was executed on the connected Windows device with actual CurrentUser DPAPI, separate processes and loopback TCP:

- Authority key provisioning: **PASS**.
- Separate Policy Admin key provisioning: **PASS**.
- Signed RTP1 policy creation: **PASS**.
- Independent Authority process startup: **PASS**.
- Independent client node 1 probe: sequence **1**, **PASS**.
- Independent client node 2 probe with its own RTS1 state file: sequence **2**, **PASS**.
- Authority process restart with the same protected key and RTS1 state: **PASS**.
- Authenticated probe after restart: sequence **65** (new durable lease begins at 65), **PASS**.
- Non-loopback bind without explicit opt-in: rejected, **PASS**.
- Authority key substituted for Policy Admin key: rejected by role binding, **PASS**.
- Overall: `AUTHORITY_MULTI_PROCESS_SMOKE=PASS`.

The library Authority module tests pass **3/3** after CP-0501, covering challenge-bound Ed25519 responses, durable lease reservation across service recreation, rejection of wrong-network/malformed requests without sequence consumption, and unique sequences under eight concurrent clients. The older per-response durable-allocation behavior has been superseded by lease reservation.

Final code validation for CP-0499:

- Full Rust library suite: **1049/1049 PASS**.
- QRun local node binary suite: **33/33 PASS**, including the two-sided Noise handshake rejection for different signed time-policy digests.
- Authority binary test target: compiled and executed successfully (the CLI integration behavior is covered by the Windows PowerShell smoke test rather than inline binary unit tests).
- `cargo check --all-targets --locked --offline`: **PASS**.
- `cargo fmt --all -- --check`: **PASS**.
- `git diff --check`: **PASS** (only pre-existing LF-to-CRLF working-copy notices).

## Integration and release boundary

QRun's public node still requires all four reference-time options:

- `--reference-time-policy-file`
- `--reference-time-admin-public-key-hex`
- `--reference-time-address`
- `--reference-time-state-file`

The exact signed RTP1 policy digest is part of the public QRun session Profile ID. Every node joining that profile must use the exact same policy bytes. A policy rotation requires a higher policy sequence and coordinated rollout; because the digest changes, it also changes the public Profile ID and requires a coordinated network identity/profile transition.

No real Mainnet Genesis epoch is selected. The wallet-bound Network ID, Genesis ID, Profile ID, state root, ECR1/QCF1/QRCP pins and manifest have not been regenerated for a time-policy-bound Mainnet identity. `QRUN_MAINNET_RELEASE_APPROVED = false` remains unchanged.

## Remaining operational work

1. Select and provision the real Public Alpha network identity and its matching RTP1 policy.
2. Operate the Authority on a dedicated, monitored Windows host with independently checked clock synchronization and a documented key-backup/rotation ceremony.
3. Provision the same signed policy bytes and admin public-key pin on each independent Public Alpha node; ensure each node has its own RTS1 client high-water file outside node data and External-CAS floors.
4. Test independent hosts with deliberate clock skew, Authority outage, sequence gaps, Authority restart, policy rotation and partition/rejoin.
5. Complete peer/operator monitoring, firewall controls, time-source incident procedure and an external security review before public production exposure.

**Decision:** the Authority-side protocol gap is now closed for a single trusted time attester and repeatable Windows test deployment. This advances Public Alpha operations, but it is not proof of decentralized time consensus, multi-host Public Alpha readiness, or Mainnet release approval.
