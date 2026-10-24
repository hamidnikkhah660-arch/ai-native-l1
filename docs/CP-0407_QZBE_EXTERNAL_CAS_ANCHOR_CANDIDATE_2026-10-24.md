# CP-0407 — QZBE external-CAS anchoring and recovery candidate

Date: 2026-10-24

Status: **candidate implementation committed; local validation and CI pass on implementation SHA; not Gate 8 closure**

## Goal

Connect CP-0406's QZBE persistent branch archive to the repository's existing provider-independent external CAS receipt contract without treating a local checksum as anti-rollback protection. The new API remains injected-provider candidate code; no cloud or independently administered CAS service is deployed by this change.

## Added API

The QZBE store module adds:

- manifest_anchor() — computes a domain-separated commitment over the exact active QZMF manifest bytes.
- external_cas_genesis_digest() — binds the provider's pre-provisioned bootstrap record to the network ID, QZBE Genesis tip, monetary profile fingerprint and PoW profile.
- open_with_external_cas(...) — verifies a fresh, challenge-bound signed read from a pinned ExternalCasPin, checks the expected record and out-of-band minimum object-generation floor, validates the remote/local manifest equality, and resolves a pending manifest only if the remote signed state exactly identifies it.
- submit_with_external_cas(...) — validates the candidate block and branch graph in memory; writes the branch and pending manifest; asks the injected provider to compare-and-swap to the exact successor record; verifies the signed commit receipt; and only then publishes the immutable final QZMF generation.
- Normal submit(...) is blocked once the store is anchored or has unresolved pending CAS state. A duplicate envelope that does not change state is idempotent and does not request a new external CAS record.

## Recovery rules

A pending QZMF manifest is never assumed to be committed just because it exists locally.

1. If a fresh signed read still names the exact old anchor, the pending manifest is discarded and unreferenced branch files are pruned only after that signed read is verified.
2. If the fresh signed record is the exact successor and its state digest matches the pending manifest commitment, startup promotes that one pending manifest and replays the branch archive.
3. If the remote record, generation, previous state or pending digest does not match either allowed case, startup fails closed.
4. Provider conflicts and ambiguous transport failures leave pending state for this recovery path; the code never guesses that a failed RPC means either commit or abort.

The external record uses a pinned ML-DSA-65 receipt-verification key and the existing exact-successor CAS wire contract. The caller's minimum provider object-generation floor must be stored outside the mutable node directory.

## Validation

The focused command is:

cargo test --locked --offline --lib monetary_pow_v04_store_candidate -- --nocapture

The CP-0407-specific tests cover (a) signed CAS commit and reopen, (b) a provider-side generation conflict that preserves the old active manifest and is discarded after a fresh signed read, and (c) a CAS that commits remotely but loses the response, recovered by promoting only the exact pending manifest named by the fresh signed record. They also assert that the local submission entry point is blocked while a CAS outcome remains unresolved.

Local validation on the working tree: `cargo fmt --all -- --check` — PASS; `cargo test --locked --offline --lib monetary_pow_v04_store_candidate -- --nocapture` — **10 passed, 0 failed**; `cargo test --all-targets --locked --offline` — exit 0, **826 library tests passed, 0 failed**, both `devnet_node` and `private_testnet_node` suites **36 passed, 0 failed** each, all remaining targets successful; `cargo check --all-targets --locked --offline` — PASS; release checksum rebuild — PASS, **377 entries**; public docs preflight — PASS, **48 README-relative links**, `git diff --cached --check` — PASS. The implementation and its tests are committed as `e3ad9a535bb021d3c810434622ff5207244ac840` and passed GitHub Actions run `40122352670` on that exact SHA. Both `Format, check, and test` and `Windows PMT4 TXN4 two-node loopback` completed successfully. These results validate the candidate implementation only; the provider remains an in-memory fixture and Gate 2/Gate 8 remain open.

## Limitations and launch boundary

- The provider used in tests is an in-memory fixture. There is no concrete cloud API adapter, deployed atomic object-generation CAS, production key custody, independent operator administration, immutable retention policy or provider-side monitoring in this change.
- The caller-provided minimum object-generation floor must itself be maintained outside the node's rollback domain. Passing 1 in a test is not production key/floor management.
- Filesystem sync/rename and replay tests on one workstation do not replace multi-host crash, power-loss, storage-cache, stale-disk-restore and network-partition qualification.
- The code remains a candidate and is not wired into the canonical producer/importer, node listeners, wallet/RPC, public peer network or value-bearing Mainnet.
- No Mainnet activation, issuance, sale, exchange listing, or real-money market is implied.

**Gate 8 remains OPEN. Gate 2 remains OPEN.** Next is to implement or select a separately administered provider adapter and externally protected monotonic floor, execute adversarial multi-host qualification, obtain independent security review, then conduct a separate design review before canonical runtime integration.
