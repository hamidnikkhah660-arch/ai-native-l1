# CP-0759 — Independent root enrollment and Windows operator authorization audit

Date: 2026-11-17  
Project: QRun Blockchain / QFP6 / QZXB  
Parent: CP-0758 — Windows handle-bound store adapter composition probe  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
HEAD observed before and after: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`  
Disposition: **READ-ONLY TRUST/IDENTITY AUDIT COMPLETE / ENROLLMENT CONTRACT PROPOSED / NO REAL IDENTITY ENROLLED / GATE 8 OPEN**

## 1. Executive disposition

CP-0759 audits the missing bridge between cryptographic verification and independently established trust. It also audits whether the current Windows evidence can identify the real runtime writer and evaluate its effective mutation rights.

The current repository already contains:
- a strict DPC1 verifier with an independently supplied nonzero governance-root epoch floor;
- executable-path use of that strict verifier in the inspected private-testnet, chain-import and trust-provisioner paths;
- DCS1 v2 local persistence of DPC1 sequence, exact digest and governance-root epoch;
- STB1 signed-bundle codec/verification and STH1 local high-water state;
- PIS2/PIV2 versioned peer-identity scope and anchor candidates;
- a test-only Windows retained-handle publication sequence from CP-0758.

These are meaningful local controls. They do **not** establish who independently supplied the initial trust pins, who controls the owner/operator keys, which Windows service identity is authorized to write the store, or an anti-rollback witness outside the local host. DCS1, STH1 and PIV2 remain local state; a full-disk/VM/host rollback can restore their earlier contents.

No real owner/operator key, service SID allowlist, root pin, independent custodian or external monotonic witness was available to enroll or verify in this checkpoint. A test key, a second key controlled by the same person, a guessed SID, or a locally self-signed manifest cannot fill those gaps.

## 2. Existing trust chain — findings

### 2.1 DPC1 and DCS1

CP-0750 added `verify_signed_deployment_config_with_floors(..., minimum_root_epoch)`. CP-0751 passed an explicit nonzero minimum root epoch through the inspected executable paths and added DCS1 v2 root-epoch high-water.

The current executable flags include:
- `--deployment-config-min-root-epoch` for signed private-testnet identity mode;
- `--peer-noise-deployment-min-root-epoch` for provider-bound chain-import Noise mode;
- `--minimum-root-epoch` for the inspected trust-provisioner rotation/issuer operations.

This closes the earlier *API/callsite omission* in the inspected paths. It does not prove that the values supplied at process launch came from an independent immutable source. A command-line argument is a separately supplied value, not by itself an authenticated enrollment ceremony. DCS1 v2 is still stored on a local filesystem and does not resist whole-volume or VM snapshot rollback.

### 2.2 STB1 and STH1

The STB1 verifier binds the bundle to a verified DPC1/GRC1 context, network/profile, governance root epoch/fingerprint, sequence and predecessor digest. It requires owner and independent-operator roles and signed acceptance receipts.

The initial enrollment remains external to the codec:
- the first trusted deployment-authority pin and DPC1 sequence floor need independent confirmation;
- the initial governance-root and recovery fingerprints need independent confirmation;
- the authority allowed to sign the first STB1 must already be authorized;
- the owner and a genuinely separate operator must each confirm control of their own key and scope;
- the exact initial trust receipt must be preserved outside the writable state it authorizes.

STH1 records a local latest accepted head. Its checksum and file identity detect some local corruption/replacement cases but do not constitute an independent monotonic witness.

### 2.3 PIS2 and PIV2

PIS2 provides a typed, versioned scope; PIV2 provides a separate append-only local anchor candidate and explicit enrollment. Neither module proves the origin of the expected profile configuration or signer pins. Neither is wired to a production startup/activation caller. Their path-based persistence also remains detached from the CP-0758 test-only handle-bound sequence.

## 3. Root enrollment contract — proposed, not implemented

A future initial enrollment must have two distinct layers:

1. **Out-of-band bootstrap pin.** Before trusting a writable DPC1, GRC1 or STB1 file, the operator verifies an exact bootstrap-record fingerprint through a separately authenticated channel. The expected fingerprint must not be learned solely from the same directory, command line, or manifest whose authenticity it is meant to establish.
2. **Signed enrollment receipt.** The canonical receipt binds the project/network/profile, bootstrap-record digest, deployment-authority fingerprint and minimum sequence, governance-root fingerprint and minimum epoch, recovery-key fingerprint, signer-registry authority, owner/operator signer IDs and fingerprints, roles, generations, purpose/scope, and the initial bundle digest/sequence.

The receipt must require:
- explicit approval of the first governance and signer-registry roots;
- an owner acceptance signature;
- an independent-operator acceptance signature from a separate custody domain;
- distinct public-key fingerprints and distinct signer IDs for the two roles;
- exact network/profile/scope binding;
- a monotonically increasing enrollment generation/sequence;
- a human-verifiable export of the exact digest and identities enrolled;
- a recovery procedure that does not silently replace the initial root or lower any floor.

The canonical envelope format and trust-domain separation are not yet frozen. A name such as `QRT1` is only a candidate label, not an existing protocol type. No source code should accept a self-enrolled first record merely because a directory is empty.

A different Ed25519 key is evidence of a different key, not evidence of a different human, organization or custody domain. Independence requires a real second custodian and an operationally separate key-generation, backup and approval process.

## 4. Windows service/operator identity — observed gaps

### 4.1 No runtime service identity to authorize

A read-only host inventory found no QRun/QFP6/QZXB-related Windows service and no related node or provisioner process. Consequently, there is no installed service configuration from which to derive a real service SID, service SID type, service account, restricted SID set or actual runtime token.

The interactive PowerShell token was non-elevated: the Administrators groups were present as deny-only, and the token did not contain `SeTakeOwnershipPrivilege` or `SeRestorePrivilege`. The earlier CP-0734 inventory records the same limitation. No privilege was enabled and no elevation was attempted.

The Windows TPM query returned no populated status fields in this session. TPM presence/readiness is therefore **unverified**; this result is not proof that the machine has no TPM. No TPM provisioning or NV-counter operation was attempted.

### 4.2 SID policy cannot be guessed

The future policy must distinguish:
- the dedicated runtime service SID that is allowed only the exact state/lock/staging operations it needs;
- the offline installation/custodian principal that owns and protects the root namespace;
- the interactive human operator account(s), which are not automatically runtime writers;
- system principals and local administrators, whose authority must be explicitly included or excluded in the threat model.

A Windows SID does not prove human identity or key custody. Any mapping from a human owner/operator role to a Windows account must be documented and authenticated independently; it must not be inferred from a username, process name, DACL entry or synthetic fixture.

Do not grant write authority to broad principals such as Everyone, Authenticated Users or BUILTIN\Users. Do not derive an allowlist from the same DACL being evaluated. Do not choose a real service SID or owner SID until the actual service/account design exists and has been independently reviewed.

## 5. Effective-access evidence — current implementation is partial

The existing `windows_acl_snapshot_probe.rs` explicitly describes itself as a structural snapshot/parser, not an effective-rights evaluator.

Verified source limitations:
- the parser understands only standard `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_DENIED_ACE_TYPE` ACEs;
- unsupported ACE types make the snapshot incomplete;
- `derive_conservative_mutation_evidence` computes an upper bound over explicit allow ACEs and deliberately does not subtract deny ACEs;
- owner implicit `WRITE_DAC` is retained conservatively; OWNER RIGHTS interactions are not fully evaluated;
- callback, object, conditional and other unsupported ACE semantics are not resolved;
- the AccessCheck probe is documented as checking only the current process token, not every user, group, service token or possible mutator;
- the token-information path in this probe does not constitute a complete inventory of enabled/deny-only/restricted groups, privileges, integrity level and impersonation context.

The harness correctly fails closed on incomplete snapshots for its current test contract. That is safer than treating unknown evidence as safe, but it does not convert the parser into complete Windows authorization.

Before production qualification, a reviewed provider must obtain security descriptors from the exact retained handles, evaluate the actual runtime service token and its complete relevant token state, and account for every supported ACE/object/conditional/inheritance and privilege path. Unknown or unsupported descriptors, token classes, filesystems or access semantics must reject. Any AccessCheck/Authz implementation must be tested against real disposable ACLs and the exact installed service token, not only the interactive developer token.

The threat model must explicitly state whether local Administrators, SYSTEM, kernel compromise, offline physical access and storage-controller compromise are trusted or adversarial. A DACL on a host cannot protect itself from a fully privileged local administrator or kernel compromise. Whole-host rollback requires a separate trust domain.

## 6. Independent anti-rollback requirement

DCS1, STH1 and PIV2 are local high-water/state stores. Local checksums, retained file IDs, volume serials, a second local disk and same-handle atomic publication do not defeat a coordinated rollback of all local state or a host/VM snapshot.

Before Gate 8 can close, the design needs an independently administered witness with:
- authenticated, read-only retrieval of the current network/profile/trust-domain tuple, epoch/sequence and exact digest;
- an atomic compare-and-swap update from the exact expected predecessor to a strictly higher successor;
- monotonic rejection of lower sequence/epoch, same-sequence digest conflicts and predecessor mismatch;
- signed, uniquely identifiable receipts for both reads and accepted writes;
- durable append-only audit evidence and explicit witness key rotation/recovery;
- a failure policy that stops trust updates and startup when the witness is unavailable or inconsistent;
- independent administration and recovery from the local node/host, not merely another directory or partition on the same machine.

A local TPM NV counter may strengthen a local threat model if actual TPM capability and lifecycle are separately qualified. It is not a substitute for an independently administered witness when whole-host/virtual-TPM snapshot rollback is in scope. No witness or TPM counter is currently enrolled.

## 7. Gate disposition

| Requirement | Evidence at CP-0759 | Status |
|---|---|---|
| Strict external root-epoch floor in inspected executable paths | CP-0750/0751 API, flags and targeted tests | Implemented locally |
| Initial deployment/governance root provenance | No independently confirmed bootstrap pin/receipt | OPEN |
| Real owner and independent-operator custody | No real enrollment or second custodian verified | OPEN |
| Actual runtime service SID/token | No project service installed | OPEN |
| Complete Windows effective-access policy | Structural subset parser; current-token probe only | OPEN |
| Handle-bound state publication | CP-0758 test-only composition probe passed | Test-only |
| Independent monotonic/CAS witness | None provisioned or verified | OPEN |
| Production STB1/PIV2 provider and caller | Not wired to production runtime | OPEN |
| Independent security review | Not performed | OPEN |

**Gate 8 remains OPEN.** No identity activation, real signer enrollment, production provisioning, public-network use or mainnet action is authorized by CP-0759.

## 8. Next checkpoint

CP-0760 should define and test a pure, versioned bootstrap-trust receipt contract. It must accept the initial root fingerprint and exact receipt digest only as externally supplied trust inputs, reject missing/zero/ambiguous floors, and bind owner/operator acceptance to one exact network/profile/scope. Use deterministic synthetic keys only for codec and negative tests; synthetic passing tests must never be reported as real enrollment.

In parallel, do not invent a Windows service identity. First design the least-privilege service boundary, then install/use a disposable test service only under a separately approved test setup. Qualify its actual SID and token using read-only inventory before any real trust-store ACL is designed. Keep the runtime detached until the independent witness, complete access policy, storage review and external security review pass.

No further input from the real owner/operator or external custodian is implied by this document. The independent bootstrap pin, second-custodian identity, real service identity and witness remain prerequisites that software cannot fabricate.

## 9. Validation and repository safety

This checkpoint used read-only source/document inspection, Git status/diff checks, current-token inventory, service/process discovery and a read-only TPM query. It did not modify ACLs, ownership, privilege state, Windows services, TPM state, production paths, keys, anchors, runtime state or network state.

No Rust source or tests were changed. No test suite was run because CP-0759 is a read-only trust/identity audit. The initial `git diff --check` returned without whitespace errors; pre-existing LF-to-CRLF notices remain.

- Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3` (unchanged)
- Existing modified and untracked work was preserved.
- Nothing was staged, committed, pushed, merged, reset, checked out, cleaned or stashed.

Gate 8 remains **OPEN**.
