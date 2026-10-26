# CP-0416 - immutable QZBE store profile lock and downgrade refusal

Date: 2026-10-26
Status: **local profile-isolation, downgrade guard, and full locked/offline all-target validation passed; exact-head CI pending; no public launch authorization**

## What changed

Every new QZBE candidate data directory now gets a root-level `qzbe-runtime.profile` marker before Noise key loading and before the QZBE fork store is opened. The marker uses a fixed-width canonical `QZRP` version-1 layout and a domain-separated SHA-256 checksum. It binds:

- the Network ID;
- the QZBE Genesis manifest hash (including the configured Genesis owner);
- the QZBE consensus-profile fingerprint (which binds the explicit candidate issuance schedule);
- a canonical fingerprint of the consensus parameters actually used by this runtime: protocol version, target-block time, difficulty window/clamps, PoW limit and starting target, algorithm/memory/iterations/lanes/output width, and issuance supply/subsidy/halving inputs.

Creation uses `create_new`, flushes the marker file, and syncs directory metadata where the platform's standard library supports directory fsync. Concurrent initial starts either create the exact marker or validate the winner's bytes. A marker is never auto-rewritten or deleted. Corrupt, truncated, wrong-version, wrong-width, wrong-network, wrong-Genesis, wrong-profile or wrong-consensus markers fail closed. If QZBE store artifacts already exist but the marker is missing, startup refuses to silently adopt or bless that legacy/unlocked store and requires a separately provisioned fresh directory. Existing external-CAS/pending markers remain an immediate refusal.

The existing default/legacy node runtime (`private_testnet_node::run_with_runtime_profile`, including the default `devnet_node` path) checks for `qzbe-runtime.profile` immediately after parsing the node configuration and **before** choosing PTB2/PFS2, PMT3/PFM3 or PMT4/PFM4 modes. If the marker path exists, including a symlink, it refuses implicit legacy dispatch/downgrade with an explicit error. The exact `devnet_node --qzbe-v04-peer-smoke` opt-in routes before that legacy code; it then verifies the marker against the requested profile and opens only the matching isolated QZBE store. A mismatching or corrupt marker cannot trigger an automatic fallback.

## Local evidence

- `cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: passed.
- `cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: passed; the repository continues to emit pre-existing unused/dead-code warnings in unrelated candidate modules.
- `cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: **passed, exit code 0 in 192.70 seconds**. The library reported **831 passed, 0 failed**; `devnet_node` **45/45**, `private_testnet_node` **39/39**, QZBE candidate smoke **6/6**, QZBE peer runtime/profile-lock **5/5**, test signer **1/1**, and every remaining binary/integration target passed. The legacy-path guard regression confirms the persistent `qzbe-store.lock` also blocks downgrade when the profile marker is missing.
- `cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_node --bin qzbe_v04_peer_node --locked --offline`: passed separately (**45 + 5 tests, zero failures**) during development of the profile lock.
- `simulations/cp0415_devnet_qzbe_dispatch_transaction_loopback.ps1`: passed against rebuilt Windows release binaries with exit code 0 after the final guard changes. It verified public-bind denial; ran the signed 2,500-atom transfer across two `devnet_node.exe --qzbe-v04-peer-smoke` processes; rejected a valid-PoW/tampered-signature block atomically; reopened/replayed both stores to matching height-2 root/tip and recipient balance; then invoked ordinary `devnet_node.exe --network-id ... --data-dir <QZBE-locked-dir>` without the QZBE subcommand. The default/legacy route exited nonzero because of the QZBE profile/lock evidence. Expected output markers: `CP-0415 PUBLIC_BIND_GUARD_PASS`, `CP-0416 QZBE_PROFILE_LOCK_DOWNGRADE_GUARD_PASS`, and `CP-0415 QZBE_DEVNET_ENTRYPOINT_SIGNED_TXN_TWO_NODE_PASS`. Earlier exact output for the signed-transfer part of this disposable scenario had root/tip `98f5a82b2a5d56d463286ace7d1373605a8724915eadaab16346deefbc25d7da` / `c96811641dbcd097ca7d1a4a828ccb8363b7b10b056e960b415e933fe30c7908` and recipient balance exactly 2,500 atoms; root/tip vary with fresh per-run Noise identities/keys and are not golden constants.
- Parent CP-0415 exact-head GitHub Actions run [40281745961](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40281745961) passed both jobs for `d9b1635c011e7faad2ed4eb53ea286a412fef969`. This parent result does not validate CP-0416. Fresh exact-head CI for CP-0416 remains pending.

## Limits / no-go boundary

The marker prevents accidental cross-profile interpretation in this candidate but is **not a security boundary against an operator or attacker who can rewrite the local data directory**: the checksum is unkeyed and detects corruption, not malicious replacement of the marker and state together. This does not replace the still-missing independently operated CAS/monotonic anti-rollback authority. No automatic migration is provided; existing stores without a marker must be backed up and separately reviewed/reprovisioned rather than blessed in place.

Most importantly, CP-0416 still locks the isolated QZBE candidate profile. It does not unify QZBE's producer/importer/fork-choice with the existing canonical PTB2/PFS2 or PMT4/PFM4 stores. The explicit QZBE subcommand remains loopback-only, uses local test PoW/issuance inputs and a one-key test transaction registry. The marker is not a Mainnet chain-identity freeze, not public peer discovery, not production economics, and not permission to expose a public listener or move value.

Gates 2, 8, 12, 13 and 14 remain open: canonical monetary Genesis/schedule/profile integration; independently operated CAS/anti-rollback; EVM/RPC scope as applicable; a reproducible zero-value public devnet with multiple independent operators; and external security/release/compliance review. Mainnet/value-bearing activation remains a separate explicit go/no-go decision.

## Next steps

1. Finish `cargo +stable fmt --check`, `cargo +stable check --all-targets --locked --offline`, and `cargo +stable test --all-targets --locked --offline` on this exact tree, then run the Windows dispatch/transaction/profile-lock scenario in CI.
2. Design canonical chain-profile dispatch and QZBE producer/importer/fork-choice integration without legacy fallback or cross-profile store reuse. Add competing-fork/reorg and restart tests to the canonical store, not only the candidate store.
3. Add the external independent monotonic CAS design, threat model and fault scenarios: malicious marker+state rewrites, stale restore, stale writer, split brain, partial write, crash and host loss.
4. Do not open public ingress until canonical runtime and external anti-rollback gates are independently reviewed. The eventual first public network should be an explicitly zero-value, independently operated devnet with bounded ingress, safe observability and rehearsed incident/upgrade procedures.
