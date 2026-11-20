# CP-0748 — Signer-pin provenance and Windows path/ACL/volume audit

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Base HEAD observed: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Disposition: READ-ONLY SOURCE AND HOST AUDIT COMPLETE; SIGNER-PIN PROVENANCE NOT ESTABLISHED; WINDOWS ACL/PATH QUALIFICATION NOT COMPLETE; NO SOURCE/RUNTIME/KEY/STORE MUTATION.

## 1. Executive result

CP-0748 examined the trust inputs accepted by `rotate-peer`, the offline signing-key role store, the D-side identity-generation high-water path, the C-side QFP6 anchor directory, the PIV2 implementation, and the Windows host's current volume/ACL metadata.

Results:
- The dual-attestation verifier correctly checks that each supplied public key hashes to its supplied SHA-256 pin, verifies both Ed25519 signatures, rejects a reused owner/operator key, and binds the authorization to the exact rotation evidence and identity transition.
- The verifier itself documents that signer-pin provenance is an external trust input. The current CLI takes both public-key files and both pin values from the caller. No independent owner/operator pin registry or reviewed pin-enrollment ceremony was found in the inspected path.
- `SigningKeyRole` in the DPAPI ASK1 store has roles for deployment authority, governance root, offline recovery, peer issuer, reference-time authority, and reference-time policy admin. It has no owner or independent-operator role.
- Current Windows storage inventory maps C: to a Kingston disk and D: to a Toshiba disk, on distinct Windows disk numbers. This confirms distinct host-visible disk devices at this observation point; it does not establish protection against full-device rollback, Administrator-level tampering, controller/firmware compromise, or simultaneous loss.
- The existing C-side QFP6 `anchor-vault` directory exists, but its observed ACL is inherited and grants Full Control to the current user, local Administrators, and SYSTEM. This is not an independently protected ACL policy.
- The proposed C-side `peer-identity-anchor-vault` directory does not exist. No PIV2 provisioning or real-store qualification has occurred.
- The actual D-side high-water directory is chosen from runtime `config.data_dir`; it is not a single fixed path in the source. The node creates `peer_identity_highwater` below that directory, but this checkpoint did not identify a running node's configured data directory or qualify its ACL.
- PIV2 has no caller outside its own module/tests. The read-only C/D reconciliation function is currently called only from its own tests. The existing private-testnet node opens D-side high-water state but does not open PIV1/PIV2 C-side peer identity anchors in the inspected startup path.

Gate 8 remains OPEN. Do not treat dual signatures as independently trusted signer identity until a separately protected trust root supplies the expected pins.

## 2. Signer-key and pin provenance findings

### 2.1 ASK1 / DPAPI key custody

Source: `src/native/pow_bench/src/offline_signing_key_store.rs`.

The module describes itself as an offline Windows candidate, not an HSM. Private signing seeds are protected using Windows CurrentUser DPAPI with optional entropy derived from the domain, network ID, and signing-key role. The encoded ASK1 envelope also binds magic, version, network ID, role byte, reserved bytes, and protected blob length.

The role enum currently defines:
- `DeploymentAuthority`;
- `GovernanceRoot`;
- `OfflineRecovery`;
- `PeerIssuer`;
- `ReferenceTimeAuthority`;
- `ReferenceTimePolicyAdmin`.

There is no `Owner` or `IndependentOperator` role. The current file writer uses create-new semantics and refuses overwrite. The reader checks the file type, bounds, version, network, role, and DPAPI result, and zeroes the temporary plaintext seed buffer after copying it.

Boundary:
- CurrentUser DPAPI is Windows user/machine-bound protection; it is not a hardware security module or independent witness.
- The module explicitly warns that DPAPI files are not portable backups and require a separate offline recovery ceremony.
- The inspected writer does not set or verify a restrictive Windows DACL; file access inherits from the destination directory's security policy.
- The ASK1 key store therefore does not establish an owner/operator key custody and provenance workflow.

### 2.2 rotate-peer inputs

Source: `src/native/pow_bench/src/bin/devnet_trust_provisioner.rs`, `rotate_peer_with_keys`.

The command obtains these inputs from caller-specified CLI options:
- operator public-key file;
- operator SHA-256 pin string;
- operator signature file;
- owner public-key file;
- owner SHA-256 pin string;
- owner signature file.

The provisioner reads bounded regular non-symlink files, requires 32-byte public keys and 64-byte signatures, builds the successor in memory, calls the dual-attestation verifier, and writes NPI1 output only after both signatures verify. It does not load the owner/operator key material from ASK1 under dedicated owner/operator roles.

The CLI pins are therefore expected values supplied by the same command invocation. They are not loaded from a separately provisioned trusted signer registry in this path.

### 2.3 verifier contract

Source: `src/native/pow_bench/src/noise_identity_rotation_authorization.rs`.

The verifier:
- hashes the supplied operator and owner public keys;
- compares those hashes to the caller-supplied pin strings;
- rejects equal fingerprints;
- validates Ed25519 public keys and signatures;
- binds manifest, prepared identities, DPC1, IRG1, previous NPI1, endpoint evidence, fingerprint evidence, policy, network, generations, and successor identity fields;
- requires distinct `operator_id` and `owner_authorization_id` strings;
- verifies the operator signature over the canonical intent digest;
- verifies the owner signature over the same digest plus the operator fingerprint and operator signature hash.

The source's own type-level comment says: “Pin provenance remains an external trust input.” The canonical intent carries textual operator/owner identifiers, but the inspected verifier does not resolve those identifiers through a separately trusted signer registry or authenticate the provenance of the supplied pin values.

Correct interpretation:
- The implementation verifies that the two supplied key files contain the keys whose signatures were supplied and that the signatures authorize the exact bound intent.
- It does not independently prove that those keys belong to the real owner and a genuinely independent operator.
- Supplying a matching public key, its hash as a pin, and a valid signature is not a substitute for prior trust establishment of the key's identity.

### 2.4 test boundary

The prior CP-0705 provisioner tests used synthetic deterministic test keys and temporary directories. Those tests exercise the verifier's rejection/acceptance logic; they do not demonstrate real owner/operator custody, independent key possession, out-of-band confirmation, or an operational key ceremony. No real owner or operator key was opened or generated in CP-0748.

## 3. Existing D-side high-water path

Source: `src/native/pow_bench/src/bin/private_testnet_node.rs`.

The private-testnet node:
1. derives `state_dir = config.data_dir.join("peer_identity_highwater")`;
2. creates that directory;
3. verifies each configured signed peer identity against the network and issuer;
4. builds a per-issuer/credential/key high-water filename;
5. opens `IdentityGenerationStateStore` and observes the signed record.

This is a D-side store under a runtime-configured data directory. CP-0748 did not infer a concrete runtime path from the source and did not inspect a guessed directory. The actual configured path and its ACL must be obtained from the selected node configuration before path-level acceptance.

The module header in `identity_generation_store.rs` states that rollback detection relies on the state file and stable writer-lock sibling being protected by operator-controlled filesystem ACLs; it is not hardware-backed against rollback/deletion of the whole protected directory.

The node creates the directory with `create_dir_all`. The inspected code does not apply or verify a restrictive DACL at that point.

## 4. Reconciliation and PIV2 integration status

Source search was performed across the active `src/native/pow_bench/src` Rust tree.

Observed call-site status:
- `PeerIdentityAnchorVaultV2` references outside its implementation/test module: none found.
- `compare_peer_identity_state` references outside `peer_identity_reconciliation.rs`: none found; its positive/negative call sites are tests in that module.
- `private_testnet_node` opens the D-side `IdentityGenerationStateStore`; no PIV2 open or C-side peer identity anchor comparison occurs in the inspected path.
- `chain_import_node` also opens a D-side identity generation store; no PIV2 caller was found there.
- `verify_anchored_successor_proof` remains without a production caller, consistent with CP-0744.

The existing C-side QFP6 manifest anchor vault and peer-identity PIV1/PIV2 vault are different record domains. Their co-location under a common QFP6 parent directory does not make them one integrated peer-identity trust chain.

## 5. Windows volume and ACL observations

Read-only host commands used:
- `Get-Partition -DriveLetter C,D` with `Get-Disk` metadata;
- `Test-Path` and `Get-Acl` for the known QFP6 local anchor paths.

Observed volume mapping:
- C: → Windows Disk 1, model reported as Kingston RBUSNS8154P3256GJ3, approximately 238.5 GB.
- D: → Windows Disk 0, model reported as Toshiba MQ04ABF100, approximately 931.5 GB.

This supports the local two-disk failure-domain proposal more strongly than two partitions on one disk. It is a host-visible inventory observation, not an independent hardware attestation.

Observed C-side paths:
- `C:\Users\ASUS\AppData\Local\AI_NATIVE_L1\QFP6\anchor-vault\`: exists.
- Owner reported by Windows: current local account.
- Access entries reported: inherited Full Control for SYSTEM, local Administrators, and the current user.
- `C:\Users\ASUS\AppData\Local\AI_NATIVE_L1\QFP6\peer-identity-anchor-vault\`: absent.

The existing `anchor-vault` is the QFP6 manifest-anchor location and must not be silently repurposed as the PIV2 directory. Its observed inherited ACL is not proof of a hardened least-privilege policy. The proposed peer-identity directory is not yet provisioned and has no ACL evidence.

The actual D-side high-water path could not be qualified without the runtime `config.data_dir` value. Do not substitute the D: repository worktree path for the node data directory.

## 6. Path, locking, ACL, and durability audit

### 6.1 Positive controls observed

`SnapshotWriterLock::acquire` in `snapshot_store.rs`:
- rejects a direct final-path symlink/directory in the precheck;
- canonicalizes an existing target or its parent before deriving the sibling writer-lock path;
- uses Windows `LockFileEx` with an exclusive, fail-immediately lock;
- keeps the lock handle alive for the store lifetime.

PIV2:
- requires an absolute root path;
- checks the root and event entries with `symlink_metadata`;
- rejects direct symlinks/non-regular event entries;
- checks event sequence, scope digest, predecessor digest, and full chain transitions;
- creates a unique staged event with create-new;
- writes, flushes, syncs, reads back, decodes, and validates the exact staged bytes;
- uses a no-overwrite publication primitive.

These are meaningful local integrity/concurrency controls.

### 6.2 Remaining path and ACL gaps

The inspected code does not:
- obtain and pin the physical volume identity for the C or D root;
- verify that the resolved path remains under a configured protected directory on the expected volume;
- read and enforce an allowlisted Windows DACL before opening or mutating the stores;
- reject every reparse-point ancestry component through a handle-based path walk;
- eliminate the check-then-open gap between `symlink_metadata(path)` and a later `File::open(path)` for bounded inputs;
- bind the open file handle's volume/file identity to the path used for subsequent operations;
- prove resistance to a privileged local Administrator or hostile service able to alter paths/ACLs.

A direct symlink check on the final component and canonicalization for lock naming are not a complete Windows reparse-point/ACL/volume security boundary. A directory junction or ancestor-path change, ACL inheritance change, or path replacement race requires separate handle-based Windows qualification.

### 6.3 Durability boundary

PIV2's Windows publication calls the shared no-overwrite publisher, which uses `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` and deliberately does not request replacement. File data are flushed and sync'd before publication. This is a useful implementation property, but the current test suite does not simulate physical power loss or disk/controller failure on Windows, nor does it independently demonstrate durable directory metadata across every crash point.

The successful temporary-directory tests are not equivalent to the required physical crash/recovery matrix.

## 7. Required trust and provisioning design before implementation

Do not solve pin provenance by merely adding owner/operator strings or by trusting CLI pin arguments. The next design must specify:

1. **Trust root:** who/what authenticates the initial owner and independent-operator public-key fingerprints before the first rotation. The expected fingerprints must originate outside the command's untrusted argument set.
2. **Enrollment ceremony:** explicit out-of-band fingerprint confirmation, exact canonical encoding, signed receipt, and durable record of the first trust bundle.
3. **Role separation:** owner authorization and independent operator authority must remain distinct identities and keys; a test fixture or a single process creating both keys is not independence.
4. **Rotation/revocation:** a separately authenticated process for replacing/revoking a signer key, with generation monotonicity and rollback detection.
5. **Storage protection:** signed/pinned trust-bundle storage whose ACL, path, volume, backup, and recovery semantics are independently reviewed.
6. **Verification API:** the provisioner must receive an already-verified trusted signer set or verify a signed trust bundle against an independent root, then compare the supplied public keys against those pinned fingerprints before signature acceptance.
7. **Audit receipts:** preserve the trust-bundle version/digest, owner and operator fingerprints, intent digest, nonce, and verification result without exposing private signing material.

DPC1/IRG1 currently provide deployment/governance/issuer trust for their own domains. This audit did not establish that they authorize initial owner/operator identity pins; that mapping must not be invented.

## 8. Next gates and sequencing

Before any PIV2-to-runtime integration:
- qualify the actual D `config.data_dir` and its ACL;
- provision the dedicated C-side peer-identity directory only under an explicit reviewed path and volume policy;
- define and test Windows handle-based path/reparse-point validation;
- define least-privilege ACLs and verify them at open/provision time;
- bind the C/D stores to expected physical volume identities;
- add physical crash/power-loss and disk-failure recovery tests;
- establish independently trusted owner/operator pins and signer lifecycle;
- add a read-only startup caller that checks PIV2 and D high-water before any listener opens;
- prove session drain/expiry behavior separately;
- obtain independent review.

Next safe checkpoint: CP-0749 should draft and test the signer-pin trust-bundle contract in disposable temporary directories only. It must not generate or provision real owner/operator keys, mutate the existing C-side QFP6 vault, or create the missing PIV2 production directory. First decide the trust root and out-of-band ceremony; code cannot manufacture identity provenance.

## 9. Repository and safety state

CP-0748 was read-only with respect to Rust source, keys, configuration, C/D stores, and runtime state. Only this audit document is added by CP-0748.

No commit, push, PR update, merge, reset, checkout, clean, stash, key generation, key rotation, provisioning, ACL change, directory creation, anchor mutation, node start, or listener start was performed.

Current disposition:
- signer-pin cryptographic verification: implemented;
- signer-pin provenance: NOT ESTABLISHED;
- C/D host-visible separate disks: OBSERVED;
- actual D high-water path/ACL: NOT QUALIFIED;
- existing C QFP6 anchor ACL: observed inherited Full Control entries, not accepted as hardened;
- proposed C peer-identity vault: absent;
- PIV2 production caller: absent;
- Gate 8: OPEN;
- production identity activation and Mainnet: NO-GO.

[executed on device: heymed (de0adbe3-6583-4775-a26e-c479a62aa941)]
