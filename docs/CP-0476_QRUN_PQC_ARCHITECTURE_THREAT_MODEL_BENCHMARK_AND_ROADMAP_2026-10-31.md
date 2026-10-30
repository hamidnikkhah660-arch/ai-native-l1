# CP-0476 — QRun PQC Architecture, Threat Model, Benchmark Plan and Integration Roadmap

Date: 2026-10-31

Status: **Engineering evidence pack / candidate architecture. Not a production cryptography approval, security audit, or Mainnet activation.** This document records the source-backed algorithm boundaries, defines a reproducible comparison benchmark, and sets explicit gates for any production migration.

## Executive decision

QRun currently has real ML-DSA-65 verification code based on the pinned `libcrux-ml-dsa = 0.0.4` dependency, including 53 selected hash-pinned C2SP/Wycheproof cases (48 expected-valid, 5 expected-invalid). It is used by the external-CAS receipt-verification path and by opt-in hybrid V4 candidate tests. It is **not** the wallet-signature algorithm of the QRun v0.5 node's current transaction path, and it does not make the current Noise transport post-quantum.

The current architecture is mixed:
- QRun v0.5 wallet transaction authorization: Ed25519.
- External-CAS provider receipts: ML-DSA-65 verification; AWS KMS signing adapter candidate, not verified against a real AWS account/key.
- V4/TXN4 hybrid account/transaction format: Ed25519 + ML-DSA-65, both required over one domain-separated digest; opt-in candidate, not the default v0.5 wallet path.
- P2P / external-CAS Noise XX transport: X25519 + ChaChaPoly + SHA-256; classical, not PQ/hybrid.
- PoW consensus: Argon2id proof-of-work; this is not a digital-signature scheme.
- QVAP/QVAAC asset and agent attestations: verifier interfaces and test fixtures; no production ML-DSA adapter is wired into those prototypes.

**Decision:** keep the public wording scoped to “ML-DSA-65 receipt verification and hybrid-transaction candidate work”. Do not describe the entire QRun network, wallet, consensus, or P2P channel as quantum-resistant today.

## 1. PQC architecture — which signature belongs to which layer

| Layer / artifact | Current source-backed mechanism | Current state | Required boundary / next action |
|---|---|---|---|
| QRun v0.5 wallet transactions (TXN2) | Ed25519; `TransactionAuthenticatorKind::Ed25519V1` | Current v0.5 node transaction authenticator is Ed25519 | Keep explicit suite IDs; design a versioned PQ/hybrid migration. Do not silently reinterpret TXN2. |
| V4 hybrid wallet/account identity (TXN4 candidate) | Ed25519 + ML-DSA-65; both signatures must verify the same SHA-256, domain-separated digest | Candidate codec and verifier interface; Libcrux adapter exercised in opt-in candidate tests, not default v0.5 Mainnet transaction admission | Freeze canonical FIPS 204 encoding, context, key lifecycle, account migration and network activation policy before use. |
| External-CAS receipts (ECRS) | ML-DSA-65 signature over the defined 32-byte receipt digest, empty ML-DSA context | Real Libcrux verifier is wired into the v0.5 external-CAS client. Local/loopback tests exercise signed receipts. Independent provider deployment remains unverified. | Deploy independently operated durable CAS; test actual provider signature, pin ceremony, KMS/HSM rotation and adversarial recovery. |
| External-CAS signing key | AWS KMS `ML_DSA_65` / `ML_DSA_SHAKE_256` adapter | Candidate implementation checks key metadata, public-key pin and a startup challenge; no real AWS account/key signing test is recorded | Run a controlled real-KMS integration test only after owner approval and budget approval; keep the private key in KMS/HSM. |
| P2P and CAS transport | Noise XX using X25519, ChaChaPoly and SHA-256 | Authenticated/pinned classical channel | ML-DSA does not replace key establishment. Evaluate a separately versioned hybrid KEM path (e.g. X25519 + ML-KEM-768) with transcript binding and downgrade tests. |
| Peer identity / deployment authority | Existing candidate trust and deployment records include classical Ed25519 signing and static X25519 peer-key pins | Classical trust path | Inventory each signed control-plane object and define hybrid or PQ authority migration; never infer PQ transport from a PQ receipt. |
| PoW / block consensus | Argon2id PoW and deterministic state transition | Not based on a public-key signature for block production | Document the actual consensus assumptions independently; PQ wallet signatures do not make PoW or networking “quantum-proof”. |
| Governance candidate | V3/V4 candidates carry hybrid identity/signature fields behind verifier interfaces | Candidate boundaries; not a blanket production governance-PQ claim | Require real verifier callsites, signer threshold tests, rotation/revocation and multi-operator fork/replay exercises. |
| QVAP / QVAAC issuer, custodian, inspector, evaluator and agent evidence | Injected verifier traits; unit-test fixtures are deliberately non-cryptographic | Prototype only | Add production key registry, role-bound ML-DSA/hybrid adapters, revocation/sequence persistence and independent evidence validation before any real asset or payment. |

### Source map (current code)

- `src/native/pow_bench/src/transaction_auth.rs`: explicit Ed25519 TXN2 authenticator and signer.
- `src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs`: v0.5 node uses `Ed25519TransactionAuthenticator`; its external-CAS client is parameterized with `LibcruxMlDsa65VerifierCandidate`.
- `src/native/pow_bench/src/v4_account_identity_candidate.rs`: canonical TXN4 hybrid envelope; Ed25519 verification plus an injected ML-DSA-65 verifier; no default PQ verifier or automatic migration.
- `src/native/pow_bench/src/v4_fat1_mldsa65_candidate.rs`: Libcrux portable ML-DSA-65 verifier candidate and 53 selected pinned vector cases.
- `src/native/pow_bench/src/external_cas_aws_kms_signer_candidate.rs`: AWS KMS ML-DSA-65 signer adapter candidate; actual cloud signing remains untested.
- `src/native/pow_bench/src/external_cas_anchor_candidate.rs` and `external_cas_noise_transport_candidate.rs`: signed external-CAS receipt contract and Noise transport.
- `src/native/pow_bench/src/qrun_verifiable_asset_passport_candidate.rs` and `qrun_verifiable_agentic_settlement_candidate.rs`: QVAP/QVAAC prototype boundaries; test verifiers are not production cryptography.

### ML-DSA-65 sizes and wire impact

FIPS 204 gives the following ML-DSA-65 sizes:

| Object | Size |
|---|---:|
| Expanded private key representation | 4,032 bytes |
| Public verification key | 1,952 bytes |
| Signature | 3,309 bytes |
| Seed representation (when using seed-based key storage) | 32 bytes |

The current TXN4 candidate has a fixed wire size of **5,527 bytes**. Its authentication tuple carries an Ed25519 public key/signature plus an ML-DSA-65 public key/signature (5,357 bytes of key/signature material), before any enclosing P2P, Noise, TCP, block or retransmission overhead. This is a candidate-format measurement, not a statement that TXN4 is currently the public v0.5 transaction format.

At 100 TXN4 transactions per second, the raw fixed-width transaction payload alone is 552,700 bytes/s (about 4.42 Mbit/s) in one direction. At 1,000 TPS it is 5,527,000 bytes/s (about 44.22 Mbit/s), before framing, block propagation, replication and protocol overhead. The implementation must benchmark real block packing, peer fan-out, queue limits, archive sync and CPU verification cost before claiming a sustainable TPS figure.

## 2. Threat model

### Assets to protect

1. QZXB authorization and balances: control of wallet signing keys, exact transaction intent, account identity and replay state.
2. Chain continuity: Network ID, Genesis, block/state commitments, nonce/expiry semantics, fork choice and recovery.
3. External-CAS safety: provider identity, signed read/commit receipts, monotonic object generation, independently retained rollback floor and idempotent recovery.
4. Control-plane integrity: deployment manifests, peer trust records, governance approvals, issuer/custodian/evaluator role keys and revocation history.
5. Availability and correctness: bounded parsing, signature-verification CPU, memory, P2P ingress, block size, archive sync and reorg processing.

### Adversaries and attack paths

| Adversary / failure | Attack examples | Required controls / tests |
|---|---|---|
| Future cryptographically relevant quantum adversary | Break classical public-key signatures (e.g. Ed25519) after collecting public keys/signatures; forge classical authentication where assumptions fail | ML-DSA or other standardized PQ signatures for the exact protected objects; separate PQ/hybrid KEM for transport; migration before exposure of long-lived high-value keys |
| Active network attacker | MITM, transcript manipulation, identity substitution, replay, truncation, cross-network replay | Authenticated channel, exact protocol domain, network/Genesis binding, sequence/expiry, canonical length checks and cross-network tests |
| Malicious or compromised peer | Invalid-signature flood, oversized PQ transactions, duplicate relay, stale archive cursor, reorg race | Bounded ingress/mempool, cheap prechecks, rate limits, verification budgets, deterministic rejection and peer fault tests |
| Stolen/weak signing key or bad entropy | Forged wallet, issuer, governance or CAS receipts; correlated/repeated key material | CSPRNG/DRBG assessment, key separation, KMS/HSM where appropriate, no test keys in production, rotation/revocation, backup recovery exercises |
| Malicious or compromised CAS operator | Equivocating reads, stale generation, rollback, forged receipt, lost/ambiguous write response | Pin provider and receipt key out-of-band, verify ML-DSA receipt, server-side atomic CAS, independently protected floor, fresh-read recovery, multi-operator adversarial testing |
| Compromised authority / insider | Unauthorized peer enrollment, asset attestation, issuer/custodian substitution, governance threshold abuse | Separate roles and keys, threshold approvals, timelock, scoped capabilities, independent evidence and revocation sequence |
| Supply-chain / build adversary | Dependency substitution, compromised release artifacts, toolchain or CI tampering | Locked dependencies, reproducible builds, provenance/SBOM, hash-pinned test vectors, reviewed upgrades, signed release artifacts |
| Resource-exhaustion attacker | Signature floods, parser edge cases, high verification cost, huge key/transaction sets | Strict sizes/counts, benchmarked verification budgets, bounded concurrency, allocation limits, fuzz/property tests and queue backpressure |

### Security assumptions and explicit limits

- FIPS 204 defines ML-DSA and states it is believed secure against adversaries with a large-scale quantum computer. This is a standardized cryptographic assumption, not a proof that every implementation, key store, protocol composition or QRun deployment is secure.
- ML-DSA is a **signature** scheme. It does not provide key establishment, encryption, forward secrecy or traffic confidentiality. The current Noise XX X25519 channel remains classical until a separately specified and tested PQ/hybrid KEM migration is implemented.
- The current TXN4 candidate requires both Ed25519 and ML-DSA-65 signatures. This supports a deliberate transition profile, but the full downgrade policy, signer migration, account recovery and protocol activation must still be frozen. No unknown suite may silently fall back to Ed25519.
- The current Libcrux adapter uses a domain-separated 32-byte SHA-256 digest as the ML-DSA message and an empty ML-DSA context. Every producer/verifier, KMS provider and cross-language comparator must use these exact bytes and context. A raw-digest API boundary must not be confused with signing a different message or prehash mode.
- A correct signature only proves that the matching private key signed the exact message. It does not prove the issuer owns an asset, that a custodian holds it, that an evaluator is independent, or that a legal right is enforceable.
- A compromised private key, compromised host/KMS authorization, weak entropy, malicious software update or incorrect account/role registry can defeat the system regardless of the signature algorithm.
- No independent production security audit of QRun's complete cryptographic architecture, ML-DSA integration, KMS ceremony, wallet key lifecycle, Noise protocol composition or consensus has been recorded here.

### Required security properties

- Explicit, versioned algorithm/suite IDs; canonical encodings; domain separation; exact transcript and network/Genesis binding.
- Nonce/sequence, expiry and revocation enforcement with durable, monotonic state; reject replay and unknown algorithms.
- Strict parsing: exact key/signature lengths, no trailing bytes, no permissive ASN.1/DER fallback, no cross-protocol signature reuse.
- Separate key roles for wallet, issuer, custodian, inspector, evaluator, governance, peer transport and CAS receipt signing.
- Secrets held by caller-controlled wallet or appropriately scoped HSM/KMS; never log seeds, private keys, mnemonic phrases or raw secret material.
- Test invalid signatures, wrong keys, wrong message/context, truncation, suffixes, duplicate fields, malformed encodings, stale sequences, expired grants, cross-network replay, key rotation, revocation, crash/restart and recovery.
- Treat signature verification as attacker-controlled workload: bound bytes, parallelism, CPU time, memory and pending queues.

## 3. ML-DSA-65 benchmark and CIRCL comparison

### What is measured

The first benchmark target is the exact QRun adapter profile: ML-DSA-65, 32-byte domain-separated SHA-256 digest, empty context, raw FIPS 204 encoding, and the current portable Libcrux implementation. Measure separately:

1. Key generation (including a separate end-to-end run where secure entropy acquisition is included).
2. Signing (separate deterministic benchmark mode from randomized production mode).
3. Verification of valid signatures.
4. Verification rejection for tampered message, signature and public key.
5. Public-key and signature bytes; TXN4 serialized transaction bytes; block bytes at several transaction counts.
6. End-to-end propagation: block build, serialization, P2P frame, peer receive, signature validation, mempool admission, archive import and replay.
7. CPU utilization, allocations/peak memory, p50/p95 latency and throughput under bounded concurrent verification.

### Reproducible comparison rules

- Pin the exact implementation versions and source revisions. Current QRun baseline: Cargo dependency `libcrux-ml-dsa = 0.0.4`; the current adapter explicitly selects Libcrux's `portable` backend.
- CIRCL comparator: Cloudflare CIRCL `v1.6.5`, package `github.com/cloudflare/circl/sign/mldsa/mldsa65`. Pin its module version and Go toolchain; do not benchmark a moving branch.
- Run both implementations on the same physical host, OS build, CPU power profile and process priority. Record CPU model, core count, RAM, OS, Rust/Go versions, compiler flags, dependency lock/hash and whether AVX2/native SIMD is enabled.
- Use identical ML-DSA-65 parameter set, same 32-byte digest, same empty context, same key/signature encodings, same valid/invalid vectors and same warm-up/sample counts.
- Run portable-only comparison first. Measure optimized SIMD paths as separate rows; do not compare Rust portable to Go optimized and present the result as an apples-to-apples language comparison.
- Report at least 31 sample batches, p50 and p95 ns/op, ops/s and sample dispersion. Run at idle and under concurrent verification load. Record keygen/signing randomness source and whether entropy acquisition time is inside the measured interval.
- Validate interoperability before timing: Libcrux-generated signatures must verify in CIRCL and CIRCL-generated signatures must verify in Libcrux for the exact profile. Both must accept the same valid fixtures and reject the same invalid fixtures.
- Timing results are host-specific engineering measurements, not an independent security certification or a TPS promise.

### CIRCL suitability and caveats

CIRCL is useful as an independent Go implementation for differential testing and benchmarking, not as an automatic production replacement. Its ML-DSA package exposes ML-DSA-65 key generation, signing and verification. The upstream README describes CIRCL as an experimental-deployment library, says APIs/code may change and advises caution for production because parts are experimental. The README lists packages with documented timing-leak caveats; `sign/mldsa` is not among that enumerated list, so we must not misstate the warning as proof that ML-DSA-65 itself is one of those listed leaking packages. Conversely, absence from that list is not a package-specific independent constant-time audit or deployment approval.

Libcrux is already the Rust-native dependency in QRun and its adapter is directly used in the external-CAS client. Upstream documentation describes formal verification of field arithmetic, NTT polynomial arithmetic and serialization, but the project is pre-1.0 and those verified components do not by themselves certify the complete signing/verification pipeline, entropy source, side-channel behavior, key custody, integration or QRun protocol. Keep the current dependency pinned until a deliberate review and compatibility test approve any upgrade.

**Benchmark execution limitation at this checkpoint:** the Windows development host has Rust 1.82.0 and an Intel Core i7-8565U CPU; Go is not installed. The Rust Libcrux benchmark harness is being added for local execution. CIRCL runtime measurements must be run on a host with a pinned Go toolchain, or a separate controlled runner; no CIRCL numbers are invented in this document.

## 4. Integration roadmap — candidate to production

| Stage | Deliverable | Exit criteria | Release effect |
|---|---|---|---|
| A — architecture inventory (this document) | Per-layer suite map, threat model, current-code/source map, explicit non-PQ boundaries | Review and freeze the distinction between current v0.5, opt-in candidates and future work | No release gate is closed |
| B — implementation comparison and conformance | Libcrux 0.0.4 baseline benchmark; CIRCL v1.6.5 comparison; interoperable signing/verification; FIPS 204 / ACVP / C2SP/Wycheproof vectors | Equal byte formats/context; both implementations accept valid and reject invalid vectors; p50/p95 and wire-size results reproducible on recorded hosts | No release gate is closed |
| C — protocol and key lifecycle design | Versioned algorithm registry; account/authority key formats; context/domain rules; secure entropy; HSM/KMS policies; key rotation, revocation and recovery | Written migration spec, deterministic vectors, downgrade/replay rules, exact signer-role and key-owner model | No default transaction switch |
| D — opt-in isolated devnet | Separate TXN4 hybrid admission path; ML-DSA verification budgets; P2P propagation and block-size/queue accounting | Multi-process restart, malformed input, resource-exhaustion, replay, wrong-network, expiry and reorg tests pass; measurements within explicit resource budgets | Candidate only; main v0.5 path unchanged |
| E — independent public testnet | At least three independent operators, separate key custody, key rotation/revocation drill, provider outage and fork/recovery tests | Reproducible state convergence, no silent downgrade, independent audit findings resolved, observable operational runbooks | Still not Mainnet until release review |
| F — production activation | Reviewed chain-upgrade/activation height, wallet support, account migration, HSM/KMS ceremony, recovery and rollback plan, audited releases | Signed approval for every independent security, performance, consensus, storage and operations gate | Only then consider production/Mainnet activation |
| PQ transport track (parallel, separate protocol) | Hybrid X25519 + ML-KEM-768 key establishment for Noise-like transport; transcript and downgrade binding | FIPS 203-compatible KEM conformance, cross-implementation vectors, handshake interop, downgrade/DoS review and independent assessment | ML-DSA receipt signatures alone do not satisfy this track |
| Asset/agent track (parallel after C) | Production key registry and real ML-DSA/hybrid verifier adapters for QVAP/QVAAC role attestations and delegated agent authority | Role separation, revocation/sequence persistence, independent evidence, dispute and legal controls; synthetic tests first | No real RWA or funds before approval |

### Order of work with maximum safe parallelism

1. **Benchmark lane:** keep the Rust Libcrux harness separate from consensus code; add a pinned CIRCL Go comparator in a separate benchmark directory/runner. Publish a results table with all hardware/toolchain metadata.
2. **Protocol lane:** write the signature-suite registry and TXN4 migration/activation spec without modifying TXN2 or the default v0.5 wallet path.
3. **Security lane:** perform focused review of entropy, secret storage, signer separation, parser limits, downgrade/replay and KMS/provider trust assumptions.
4. **Transport lane:** design a hybrid KEM separately from signature work; do not label the existing X25519 Noise channel as quantum-safe.
5. **Integration lane:** only after A–C reviews, wire TXN4 into a gated devnet and run independent multi-host tests. Preserve the Mainnet release constant and all existing release gates.

## 5. Acceptance checklist

- [ ] Exact algorithm/suite ID and canonical message bytes are documented for every signed object.
- [ ] ML-DSA-65 valid/invalid vector coverage is expanded and pinned; cross-implementation interop passes.
- [ ] Libcrux 0.0.4 and CIRCL v1.6.5 microbenchmarks are run on identical hardware profiles; benchmark metadata and raw results are committed.
- [ ] TXN4 transaction bytes, block size, bandwidth, peer fan-out, verification CPU and mempool memory are measured at target workloads.
- [ ] Key generation entropy, backup, rotation, revocation, compromise recovery and signer separation are tested.
- [ ] Unknown suite IDs, malformed encodings, truncation, suffixes, replay, downgrade, wrong Network ID/Genesis, nonce and expiry failures are rejected.
- [ ] P2P transport has a separate PQ/hybrid KEM design and review; ML-DSA is not treated as key establishment.
- [ ] QVAP/QVAAC have real production cryptographic adapters and durable key/revocation registries before any real asset/payment integration.
- [ ] Independent cryptographic and protocol security reviews are complete and remediations closed.
- [ ] Mainnet release blockers, consensus calibration, storage/recovery and independent operator gates are separately satisfied.

**Release guard:** this evidence pack does not set `QRUN_MAINNET_RELEASE_APPROVED` to true and does not authorize public minting, public Mainnet, live asset issuance, escrow or an exchange market.

## 6. References

1. NIST, FIPS 204 — Module-Lattice-Based Digital Signature Standard: https://csrc.nist.gov/pubs/fips/204/final
2. NIST FIPS 204 publication page and errata planning note (31 July 2026): https://csrc.nist.gov/pubs/fips/204/final
3. Cloudflare CIRCL repository and security disclaimer: https://github.com/cloudflare/circl
4. CIRCL ML-DSA-65 API/package documentation: https://pkg.go.dev/github.com/cloudflare/circl/sign/mldsa/mldsa65
5. CIRCL release history; v1.6.5 release: https://github.com/cloudflare/circl/releases
6. Libcrux ML-DSA crate documentation: https://docs.rs/libcrux-ml-dsa/
7. Libcrux proof project and scope: https://github.com/cryspen/libcrux-proofs
8. QRun source adapter: `src/native/pow_bench/src/v4_fat1_mldsa65_candidate.rs`
9. QRun v0.5 node / CAS verifier: `src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs`
10. QRun TXN2 authenticator: `src/native/pow_bench/src/transaction_auth.rs`
11. QRun TXN4 hybrid candidate: `src/native/pow_bench/src/v4_account_identity_candidate.rs`

### Initial Libcrux portable measurements — 31 October 2026

Harness: `src/native/pow_bench/examples/mldsa65_bench.rs`
Command: `cargo +stable run --release --locked --offline --example mldsa65_bench` (from `src/native/pow_bench`).

| Host / setting | Value |
|---|---|
| CPU | Intel Core i7-8565U @ 1.80 GHz, 4 cores / 8 logical processors |
| RAM | 7.9 GiB |
| OS | Windows NT 10.0.26300.0 |
| Rust | rustc 1.82.0 |
| Power profile | Balanced |
| Backend | Libcrux 0.0.4, portable |
| Message / context | 32-byte digest / empty context |
| Sampling | 31 batches per operation, 3 warm-up batches; release build |

| Operation | Run 1 p50 | Run 1 p95 | Run 2 p50 | Run 2 p95 |
|---|---:|---:|---:|---:|
| Key generation | 182.195 µs/op | 211.050 µs/op | 157.660 µs/op | 185.595 µs/op |
| Signing | 484.647 µs/op | 801.381 µs/op | 473.978 µs/op | 551.016 µs/op |
| Verification | 137.439 µs/op | 186.088 µs/op | 136.566 µs/op | 157.043 µs/op |

The run-1 signing p95 is notably higher than run 2. This is a useful initial baseline, not yet a stable performance characterization. The reported p50/p95 are percentiles over **batch-average ns/op samples**, not per-request tail latency. The harness uses deterministic benchmark seeds; it excludes OS CSPRNG/DRBG acquisition, KMS/network latency, allocation/accounting outside the primitive, and all P2P/consensus work. Go is not installed on this host, so no CIRCL timing is reported. Repeat on an otherwise idle dedicated host, collect more independent runs, and add a controlled randomized-signing/entropy measurement before using these figures for engineering limits.
