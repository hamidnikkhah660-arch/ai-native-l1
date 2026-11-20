# CP-0761 — Versioned dual-attested bootstrap trust receipt

Date: 2026-11-17  
Project: QRun Blockchain / QFP6 / QZXB  
Parent: CP-0759 — Independent root enrollment and Windows operator authorization audit  
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116  
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116  
HEAD observed before and after: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3  
Disposition: **QBT1 PURE CODEC/DUAL-SIGNATURE VERIFIER IMPLEMENTED / TARGETED TESTS PASS / NO REAL ENROLLMENT / GATE 8 OPEN**

## 1. Objective and isolation

CP-0761 implements a new, fixed-width QBT1 bootstrap-trust receipt candidate. It supplies a pure verification layer between externally pinned owner/operator trust and the already existing Provider ECR1/ECS1 and off-host Anchor QAR1 contracts.

QBT1 is a new module and wire format. Existing ECR1, ECS1, QAR1, Provider state and Anchor state V1 encodings were not changed. The implementation does not provision a cloud resource, create an Anchor record, install a Windows service, enroll a real signer, modify ACLs, open a network listener, or activate a node.

The source module is:

- src/native/pow_bench/src/external_cas_bootstrap_trust_candidate.rs
- registered in src/native/pow_bench/src/lib.rs

The module is explicitly candidate-only. Passing synthetic tests proves the codec and verifier behavior, not custody separation, trust-pin provenance, durable storage, or Gate 8 closure.

## 2. Existing V1 contract compatibility

Source inspection confirmed the existing contract boundaries:

- ECR1 is a 272-byte fixed-width, big-endian record. Its explicit bootstrap record has logical generation 0 and zero predecessor links.
- ExternalCasOffhostAnchorState::provision_bootstrap creates the initial Anchor state with sequence 1 and Provider object generation 1.
- QAR1 is a separate version-1 Anchor receipt with a fixed-width canonical payload and one ML-DSA-65 signature.
- The existing off-host service model verifies Provider ECR1/ECS1 evidence, requires an atomic sequence-plus-full-state-digest CAS, and performs an authoritative read-back before signing Applied.

QBT1 binds to those exact initial values without changing their encoding:

- bootstrap generation: 1
- Provider ECR1 logical generation: 0
- Provider object generation: 1
- Anchor sequence: 1
- initial ECR1 record digest: exact canonical ECR1 digest
- initial ECR1 state digest: the record's next_state_digest
- initial Anchor state digest: recomputed from the existing initial Anchor-state constructor

The verifier receives the exact ECR1 bootstrap record as an argument. It does not trust a caller-supplied Anchor-state digest without recomputing the state and digest from that record and the pinned Provider identity.

## 3. QBT1 wire contract

QBT1 version 1 has a fixed payload of 560 bytes followed by two fixed-size ML-DSA-65 signatures:

- magic: QBT1
- version: 1
- flags: zero
- owner role: 1
- independent-custodian role: 2
- signature algorithm: ML-DSA-65 identifier 1
- reserved field: zero
- bootstrap generation: u64 big-endian, exactly 1
- Provider logical generation: u64 big-endian, exactly 0
- Provider object generation: u64 big-endian, exactly 1
- Anchor sequence: u64 big-endian, exactly 1
- sixteen 32-byte bindings: Provider ID, Anchor ID, network ID, profile digest, Genesis digest, Provider receipt-key ID and fingerprint, Anchor receipt-key ID and fingerprint, owner signer ID and key fingerprint, independent-custodian signer ID and key fingerprint, initial ECR1 record digest, initial ECR1 state digest, and initial Anchor-state digest
- owner ML-DSA-65 signature
- independent-custodian ML-DSA-65 signature

The complete encoded length is exactly 560 + 2 × ML_DSA_65_SIGNATURE_BYTES. Decode rejects a wrong length, wrong magic, unsupported version, nonzero flags/reserved field, wrong role/algorithm identifiers, invalid fixed bootstrap generations, zero bindings, duplicate role identities, and key-fingerprint reuse. Extra trailing bytes are rejected.

The two signatures cover the same canonical 560-byte payload. They use separate, domain-separated signing digests: one for owner acceptance and one for independent-custodian acceptance. The complete receipt digest uses its own domain and includes both signatures. The receipt digest is compared with the independently supplied expected_receipt_digest.

Public-key fingerprints are SHA-256 over a dedicated ML-DSA-65 fingerprint domain and the complete encoded public key. Key IDs are separate identifiers; they are not treated as public keys or as evidence of human identity.

## 4. Out-of-band trust inputs

BootstrapTrustPin is deliberately not decoded from QBT1. It contains the expected full receipt digest, profile digest, initial ECR1 digest, initial Anchor-state digest, owner signer ID/public key, and independent-custodian signer ID/public key.

Verification also receives the existing ExternalCasPin and ExternalCasOffhostAnchorPin. It checks:

- Provider and Anchor pins are valid and refer to the same Provider/network/Genesis domain;
- Provider and Anchor receipt keys are distinct;
- owner and custodian IDs are distinct from each other and from Provider/Anchor receipt-key IDs;
- owner and custodian public keys are distinct from each other and from Provider/Anchor receipt public keys;
- all recorded key IDs and key fingerprints match the supplied pins;
- QBT1 domain fields match exact Provider, Anchor, network, profile and Genesis bindings;
- the supplied ECR1 record is the exact generation-zero bootstrap and matches the out-of-band record digest;
- the initial Anchor state recomputes to sequence 1, Provider object generation 1, and the separately pinned initial Anchor-state digest;
- the complete QBT1 digest equals the independently supplied expected receipt digest;
- both role-specific ML-DSA-65 signatures verify under their separately pinned public keys.

The profile digest is an explicit trust binding. CP-0761 does not define or compute the canonical QFP6 profile descriptor hash; the caller must obtain that exact value from the separately reviewed profile-identity layer.

No timestamp or wall-clock expiry is used as a trust substitute. Revocation, rotation and recovery require a separately pinned policy and are not implemented here.

## 5. Verification boundary

The public verify_bootstrap_trust_receipt function is pure. It decodes and checks the QBT1 bytes, checks the out-of-band pins, verifies both signatures, reconstructs the exact initial Anchor state, and returns a VerifiedBootstrapTrust result.

It performs no filesystem or cloud I/O, no conditional write, no CAS, no listener startup, no key generation, no first-root self-enrollment, no retry fallback, and no state mutation. A missing pin is an error; an empty directory or empty remote table is not permission to trust the first presented root.

A distinct public key and signer ID prove only distinct cryptographic inputs. They do not prove different humans, organizations, devices, administrators, backups or custody domains. A genuine independent custodian must still be identified and must actually control and approve the second key.

## 6. Targeted Windows validation

Device: heymed  
Device ID: d350fcce-b411-45dd-b2ff-568acbef16dc  
Shell: Windows PowerShell 5.1  
Manifest: src/native/pow_bench/Cargo.toml

| Command / test group | Result |
|---|---:|
| cargo fmt --manifest-path ... --all -- --check | PASS |
| external_cas_bootstrap_trust_candidate::tests | 10 passed, 0 failed |
| external_cas_offhost_anchor_protocol_candidate::tests | 12 passed, 0 failed |
| qrun_v06_node_runtime_candidate::tests::qap1 | 12 passed, 0 failed |
| cargo check --manifest-path ... --bins | PASS |
| git diff --check | PASS |

The QBT1 tests use deterministic synthetic ML-DSA-65 keys and the repository's Libcrux ML-DSA-65 verifier candidate. They cover canonical round-trip, both valid signatures, unpinned receipt digest, altered scope, duplicate signer identity, signer key reuse, zero profile pin, changed ECR1 bootstrap, changed Anchor-state digest, invalid bootstrap sequence/generation/object-generation, signature tampering, wrong role/reserved bytes, wrong length/trailing bytes, and invalid Provider/Anchor pins.

The QAR1 regression group re-ran the existing 12 tests for signed reads, challenge binding, concurrent CAS, exact authoritative read-back, conflict behavior and fail-closed handling.

The QAP1 regression group re-ran 12 existing runtime-candidate tests, including hybrid-transfer acknowledgement after Anchor finalization, lost-CAS-response recovery, restart behavior, cross-host driver policy and the QZXB/QUSDT test trade/AMM paths. The bind-policy test prints expected panic messages for intentionally rejected bind addresses and finishes successfully.

The bins check emitted existing warnings in unrelated files (unused imports/dead code and one unused mut); the command completed successfully. No new QBT1 warning remained after removing unused fixture fields. Git emitted existing LF-to-CRLF working-copy notices for other modified files; diff --check completed with exit code zero.

These were targeted tests and a bin check, not a complete library test-suite run.

## 7. Critical remaining gaps — Gate 8 stays OPEN

QBT1 does not by itself close the bootstrap-to-runtime trust gap.

1. **Out-of-band pin provenance is not implemented.** The verifier assumes BootstrapTrustPin, Provider pin, Anchor pin and profile digest came from a separately authenticated channel. No external owner/operator ceremony or independently verified trust-pin delivery was performed.
2. **No real independent custodian is enrolled.** Synthetic keys do not prove separate custody.
3. **No one-time durable bootstrap transaction exists.** No off-host service or DynamoDB adapter was changed to conditionally create an immutable bootstrap receipt, strongly read it back, and reject a conflicting pre-existing enrollment.
4. **QAR1/Anchor-state V1 does not carry a QBT1 commitment.** CP-0761 intentionally did not mutate QAR1 V1 or the persisted Anchor-state encoding. Before runtime integration, a reviewed design must preserve the enrollment commitment in an immutable separately pinned backend record or define an explicit versioned successor format and migration. It must not overload operation_id/request_digest or silently change V1.
5. **No live AWS environment was contacted.** AWS CLI, credentials, account/role/table ARN, region mode, IAM/SCP controls and provisioned table state were not available or verified.
6. **No project Windows service is installed.** Actual service SID/token, complete effective AccessCheck, least-privilege ACL policy and retained-handle production provider remain unqualified.
7. **No independent monotonic witness is deployed or verified.** Local checksums, local files and local high-water state remain rollbackable with the host/VM.
8. **No independent security review has occurred.**

Accordingly, CP-0761 does not authorize real signer enrollment, service startup, public-network deployment, Mainnet use, QZXB launch, or public launch readiness. Gate 8 remains OPEN.

## 8. Next checkpoint

CP-0762 should specify and test the one-time off-host bootstrap transaction without changing QAR1 V1:

- validate QBT1 and all external pins before any mutation;
- accept bootstrap only through an explicit provisioning operation, never through first-read auto-enrollment;
- create a separate immutable bootstrap-enrollment item with a server-side create-if-absent condition;
- require a strongly consistent authoritative read-back of the exact receipt digest and initial Anchor-state digest;
- reject a different existing receipt without overwrite or fallback;
- make retries idempotent only for the exact same receipt digest;
- bind every future Anchor-service startup to the same externally pinned bootstrap record;
- document the later state-format migration needed if the receipt commitment must be included in every versioned Anchor state/receipt.

Only after that local contract is independently reviewed should a separately administered live witness and real two-custodian ceremony be provisioned.

## 9. Repository safety

- Branch remains feat/cp0704-dual-attestation-rotation-gate-20261116.
- HEAD remains 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3.
- The pre-existing modified and untracked work was preserved.
- CP-0761 added one new source module, one lib.rs module declaration, and this checkpoint document.
- Nothing was staged, committed, pushed, merged, reset, checked out, cleaned or stashed.
- No AWS resource, Windows service, ACL, TPM, real signer key, wallet, node, listener, account balance or network state was created or changed.

**Final disposition: QBT1 local pure contract implemented and targeted tests passed; no real enrollment; Gate 8 OPEN.**
