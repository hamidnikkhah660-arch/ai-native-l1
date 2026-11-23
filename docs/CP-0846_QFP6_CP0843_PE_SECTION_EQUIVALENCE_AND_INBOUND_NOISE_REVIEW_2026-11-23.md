# CP-0846 — CP-0843 Build-Section Equivalence, PE Metadata, and Inbound Noise Review
Date: 2026-11-23
Repository review branch: `review/qfp6-cp0843-source-20261123`
CP-0843 source-review commit: `a114f91c0043eb22ebeeecda961eb454d9178267`
Follow-up build: Windows x86_64-pc-windows-msvc, Rust/Cargo 1.82.0, locked/offline dependencies.

## 1. Forced clean Release build

The source review worktree contained 24 Rust source files with SHA-256 values exactly matching the corresponding CP-0843 source files (zero source-file mismatches). A new Release build was forced from the original CP-0843 source path after:

```powershell
cargo clean --locked --offline -p ai_native_l1_pow_bench --release
cargo build --locked --offline --release --bin qrun_v06_node -j 1
```

Build result: PASS, Release profile finished in 4m42s.
- Rebuilt executable size: 5,823,488 bytes.
- Rebuilt executable SHA-256: `81d07a1087e36d9b46496f6062f9acc72e6cae3f06b447e89f471f06e1870ff0`.
- CP-0843 package executable SHA-256: `519e695aed1a0b68195f841c167c06e4fe23176eb50cd96476a34113233c0470`.

The rebuilt file is a local build artifact only. It was not substituted into or repacked with the CP-0843 ZIP, and it was not launched as a live node.

## 2. PE section comparison

A byte-level comparison of the packaged and freshly rebuilt executables found 28 differing bytes total. The section hashes are:

| PE section | Raw size | Result |
|---|---:|---|
| `.text` | 4,612,096 | IDENTICAL |
| `.data` | 512 | IDENTICAL |
| `.pdata` | 121,344 | IDENTICAL |
| `.reloc` | 10,240 | IDENTICAL |
| `.rdata` | 1,078,272 | DIFFERENT (metadata-bearing section) |

The identical `.text` SHA-256 is `f143a9599645f2103d845d68199395f3fde4725ac115cc9aa9baec221509e97d`.

Differing byte ranges:
- `0x00000108–0x0000010A` (3 bytes)
- `0x004FFCB4–0x004FFCB6` (3 bytes)
- `0x004FFCD0–0x004FFCD2` (3 bytes)
- `0x004FFCEC–0x004FFCEE` (3 bytes)
- `0x004FFE8C–0x004FFE9B` (16 bytes)

The PE COFF timestamps are different: packaged executable `2026-11-23T08:13:44Z`; rebuilt executable `2026-11-23T08:59:47Z`. The remaining ranges fall in PE/CodeView/PDB metadata. This result establishes that the emitted machine-code section `.text` and the other listed sections are identical for this exact source/toolchain comparison. It does **not** establish whole-file byte-for-byte reproducibility, nor does it independently prove that the packaged executable was built from the reviewed source.

## 3. Deterministic-linker probe

A minimal Rust program was linked twice using the installed MSVC linker with `-C link-arg=/Brepro` and a remapped temporary source path. The resulting whole-file SHA-256 values differed:
- First: `6a50053276789af65210189dde749ffa82b1d8e070e7eaf8104e872224453fcf`
- Second: `8b5d1fc9429c3eaa9ab29cb7df44e3eff562005221b3d2a64473a9776e5668a4`

Therefore `/Brepro` alone is not accepted as a reproducibility solution. No manual timestamp/GUID patching or binary mutation was applied. Whole-file deterministic linking remains OPEN.

## 4. Inbound Noise XX source review

The Public Testnet Q6PD listener path reviewed in `qrun_v06_peer_listener_candidate.rs` includes:
- Four fixed Noise-handshake workers.
- A bounded handshake job queue of eight connections; full-queue submissions are rejected.
- Source-prefix rate-limiter buckets (IPv4 /24 and IPv6 /56), plus a global token bucket and bounded prefix map.
- An eight-second Noise handshake deadline and a 1,024-byte handshake-message cap.
- A bounded application-session duration/read budget and serialized application handling after handshake completion.

Security boundary:
- When no remote static-key allowlist is configured, the public inbound path intentionally uses anonymous/unpinned Noise XX.
- The source code explicitly describes this mode as unauthenticated and notes that an active man-in-the-middle can terminate and re-encrypt the session.
- Q6PD record signatures, Network/Profile binding, replay controls, and bounded admission are additional application controls; they do not turn anonymous Noise XX into mutually authenticated transport.
- No external audit, Internet-scale DoS test, or production-readiness claim is made.

## 5. Validation status and release gate

- Rust source-file hash comparison: PASS (24 files, zero mismatches).
- Rustfmt check and Git diff whitespace check from the prior source-review pass: PASS.
- Forced Release build from the original path: PASS.
- PE machine-code-section comparison: PASS for `.text`, `.data`, `.pdata`, and `.reloc`.
- Whole-file reproducible build: OPEN / NOT ESTABLISHED.
- Focused test suite rerun from the clean review worktree: NOT YET VERIFIED in this follow-up.
- GitHub Actions: the existing Rust validation workflow's branch filters were expanded so the CP-0843 review branch can push-trigger validation and pull requests targeting `feat/qfp6-public-testnet-dns-relay-20261120` can run the existing PR workflow. A separate run must be observed before marking CI PASS.
- Package release, PR merge, public Mainnet, real-value transfers, issuance/rewards, and market activity remain blocked.

No live node process, listener, key, node config, peer database, or operator ZIP was modified during this follow-up. The prior primary Seed, local QA Joiner, and backup Seed were not used as attack targets or test harnesses.

## 6. Next required gates

1. Observe and record the GitHub Actions PR validation result for PR #206.
2. Rerun focused Address Manager, bounded Noise-worker, queue-overflow, and source/global rate-limiter tests from the clean review worktree when the controlled Windows build host is reachable.
3. Establish a documented reproducible-link procedure or explicitly adopt a new reproducible build baseline with a new package hash and full provenance; never retrofit the existing CP-0843 ZIP silently.
4. Obtain independent security review of anonymous inbound Noise XX and external-operator deployment before any broader exposure.
5. Qualify an actually independent operator and verify peer identity/host diversity. A loopback Joiner or alternate DNS path on the Seed machine does not count as an independent peer.
