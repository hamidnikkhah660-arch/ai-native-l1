# CP-0480 — QRun Off-Host Monotonic Anchor Service Design

Date: 2026-10-31

Status: **Design proposal only. No cloud table, anchor daemon, separate AWS account, or off-host service is deployed. This document does not close the anti-rollback gate.**

## 1. Decision being designed

QRun currently has:
- a durable single-host external-CAS Provider containing the current ECR1 record;
- a local QCF1 floor which remembers the last verified ECR1 record and Provider object generation;
- signed ECS1 Provider receipts using a pinned ML-DSA-65 key;
- a node startup/commit path which can use the Provider and local QCF1 floor.

The paired-backup negative test demonstrates that an operator who can restore both the Provider state file and QCF1 floor file can make an old bootstrap appear current again. Two directories on one host are not an independent monotonic authority.

The proposed next component is a **separately administered QRun External-CAS Monotonic Anchor Service**. Its stored high-water state must remain outside the Provider host, node host, and their shared backup/recovery domain. The service is authoritative; local QCF1 becomes a cache/recovery aid and must never override a newer remote anchor observation.

An AWS-first deployment is a plausible candidate because the repository already has an AWS KMS ML-DSA-65 receipt signer. DynamoDB is considered for a single strongly-consistent item per anchor identity, with conditional writes; this remains a design choice to validate in a disposable staging account, not an existing deployment.

## 2. Trust domains and roles

The deployment must separate these roles and their credentials:

1. **QRun node/operator:** holds only an authorized client identity and out-of-band pins for Provider and Anchor endpoints/keys. It cannot administer or restore the anchor table.
2. **External-CAS Provider:** owns Provider state and its Provider receipt-signing key. It cannot modify, delete, or restore Anchor state.
3. **Anchor service runtime:** verifies Provider ECS1 receipts against the pinned Provider key, reads/advances only the anchor item, and signs Anchor responses. It has no Provider filesystem access and no ability to restore the table.
4. **Anchor security administrator:** separately provisions the anchor identity, bootstrap high-water state, anchor ML-DSA-65 key, table policy, and recovery controls. This role must not be the Provider operator or node operator.
5. **Independent audit/recovery custodian:** reviews changes to anchor policy, key rotation, restore permissions, and recovery evidence. A single routine service identity must not be able to lower or recreate the anchor.

A separate hostname, process, directory, or IAM role on the same administrator-controlled host is not sufficient. The threat boundary is an independently administered account/recovery domain. Protection against collusion or compromise of the Anchor account's ultimate administrators requires a further independent witness or second anchor and is outside this first deployment profile.

## 3. Anchor identity and stored high-water item

An anchor identity is pinned out of band and domain-separated by at least:
- anchor ID;
- Provider ID;
- Network ID;
- wallet-bound Genesis digest;
- Provider receipt key ID and hash of the exact Provider ML-DSA-65 public key;
- Anchor receipt key ID and hash of the exact Anchor ML-DSA-65 public key;
- deployment/policy version.

The one authoritative item stores:
- the exact canonical ECR1 record bytes (not merely a client-supplied height);
- Provider object generation;
- an independent Anchor sequence number;
- last applied operation ID and request digest;
- the digest of the last accepted Provider ECS1 commit receipt;
- the pinned anchor identity/version.

The Anchor sequence is an independent CAS version. It increments by exactly one only when the stored ECR1 record and Provider object generation advance by exactly one. Initial provisioning is a separate reviewed operation which installs the exact generation-zero bootstrap ECR1 at Provider object generation one. The service must never bootstrap itself from the first unauthenticated Provider response.

A single item per anchor identity avoids split-brain from reading or writing separate high-water components. No GSI, stream, cache, eventually consistent replica, or client-side cached value may be used as the authority for a high-water read.

## 4. Provider evidence validation at the Anchor

The Anchor must not trust a node's statement that a Provider commit happened. Every advance request contains:
- the exact next ECR1 record;
- the Provider's signed ECS1 commit receipt;
- the expected Anchor sequence/state;
- a fresh nonzero request challenge;
- the operation ID and request digest bound by the Provider receipt.

The Anchor independently reconstructs the Provider write precondition from the signed ECS1 receipt and ECR1 successor:
- request nonce, operation ID, request digest come from ECS1;
- expected logical generation is the exact predecessor of ECR1;
- expected Provider object generation is the exact predecessor of ECS1 object generation;
- expected record digest and state digest come from ECR1 predecessor links;
- next ECR1 is supplied byte-for-byte and decoded canonically.

The Anchor then verifies the reconstructed write request and ECS1 commit signature with the out-of-band Provider ExternalCasPin. It accepts only an Applied or AlreadyApplied commit receipt. The ECR1 successor must link to the Anchor's exact current record and state digest; both logical generation and Provider object generation must advance by one. A Provider receipt for another Network ID, Genesis, Provider, key, operation, challenge, record or object generation is rejected.

The Anchor has its own distinct ML-DSA-65 signing key. Provider and Anchor receipt keys must never be conflated. The node pins both public keys independently.

## 5. Read and advance protocol

### Read

1. Client generates a fresh unpredictable challenge.
2. Anchor performs an authoritative read of the single item.
3. Anchor returns the full Anchor identity, challenge, Anchor sequence, exact ECR1 record, Provider object generation, last operation metadata, and an ML-DSA-65 signature over a domain-separated canonical digest.
4. Client verifies the pinned Anchor key, full domain, exact challenge, canonical state and signature.
5. Startup compares the fresh Provider observation with the Anchor high-water state. A Provider state below the Anchor floor is a rollback and must quarantine; same-generation different digest is equivocation; an unexplained generation jump is not auto-accepted.

### Advance

1. Provider CAS completes and the node independently verifies the signed ECS1 response.
2. Node sends the exact ECR1 successor and signed ECS1 receipt to the Anchor with the observed old Anchor sequence/state and a fresh challenge.
3. Anchor verifies Provider evidence itself (Section 4), then atomically compare-and-swaps the one stored item from the exact expected sequence and state to the exact successor.
4. Anchor signs a response binding the challenge, operation ID, request digest, outcome, new Anchor sequence and complete new high-water state.
5. Node verifies the Anchor receipt and performs an authoritative read-back. Only after the remote Anchor is confirmed at the exact successor may the node advance its local QCF1 cache and publish the PFS2 manifest.

### Ambiguous outcomes and retry

A timeout is never interpreted as abort or success. The node obtains a fresh challenge-bound signed Anchor read:
- exact expected old state: retry the same immutable operation ID, ECR1 and Provider receipt with a new challenge;
- exact target state and matching operation/request/receipt digests: classify as committed;
- later exact descendant: hand off to explicit journal/recovery logic; do not pretend the earlier CAS response itself proves the later state;
- any unrelated, conflicting, skipped or lower state: quarantine and fail closed.

The Anchor retains enough last-operation metadata to make an exact retry idempotent while the target remains current. Reuse of an operation ID with changed payload is a hard conflict.

## 6. AWS-first storage and signing profile (candidate)

For a DynamoDB implementation:
- Use one table item keyed by the full anchor ID.
- Use GetItem with ConsistentRead=true against the base table for every authoritative read; do not read the high-water from a GSI.
- Use PutItem with a ConditionExpression over the current Anchor sequence, ECR1 digest and Provider object generation. A conditional failure is a conflict, never a reason to write unconditionally.
- Store the entire new item in the same conditional write. The item includes sequence, canonical ECR1 bytes, object generation, domain pins, last operation ID/request digest and Provider receipt digest.
- Use a single Region for the first qualification. Any multi-Region mode requires its own consistency and partition tests before it can serve as the authority.
- Use a separate AWS KMS ML_DSA_65 key for Anchor receipts with ML_DSA_SHAKE_256. Sign only the short domain-separated digest, not an unbounded request body. Verify each returned signature locally against the pinned Anchor public key.
- The Anchor runtime identity receives only the minimum table read/conditional-write access and KMS Sign access to this one key. It must not receive DeleteItem, BatchWriteItem, table administration, backup restore, key administration or policy administration privileges.
- Explicitly deny RestoreTableToPointInTime and RestoreTableFromBackup to routine operational identities. Keep table restore, deletion, policy changes and anchor-key replacement under separate security administration, with independently reviewed and audited controls. A policy on the runtime role alone does not constrain an account administrator.
- No local file, Provider-side directory, node-side QCF1 backup, or operator workstation backup may be authoritative for remote Anchor state.

The AWS service primitives support the mechanics but do not establish the trust boundary by themselves: DynamoDB GetItem can request strongly consistent reads; PutItem supports condition expressions; and AWS KMS supports ML_DSA_65 with ML_DSA_SHAKE_256. IAM can restrict DynamoDB backup/restore actions. These controls still require an independently administered account and deployment review.

## 7. Commit and recovery ordering after remote Anchor integration

The required durable order becomes:

1. Persist QAP1 intent and exact pending local manifest.
2. Execute Provider CAS and verify the Provider ECS1 receipt.
3. Advance the remote Anchor using that exact Provider evidence.
4. Verify the signed Anchor response and authoritative read-back.
5. Advance local QCF1 as a cache/recovery aid.
6. Publish the exact PFS2 manifest and in-memory state.
7. Clear QAP1 only after startup/commit recovery confirms all required evidence.

If the Anchor is unavailable, the node stops anchored writes. It never falls back to local QCF1-only acceptance. If the Provider commits while the Anchor is unavailable, QAP1 remains pending and the node resolves the operation through fresh signed Provider and Anchor observations; it does not mint another operation or skip generations.

On startup, the remote Anchor is read and verified before the node can accept block production/import. A local QCF1 value ahead of the remote Anchor is a conflict requiring quarantine, not permission to advance the remote service from local bytes. A remote Anchor ahead of Provider/local state requires exact recovery evidence; it must never be lowered to match a restored Provider backup.

## 8. Required qualification matrix

Before production use, implement and test:

- exact bootstrap provisioning; no silent first-read initialization;
- Provider signature forgery, wrong Provider key, wrong Anchor key, wrong Network ID and wrong Genesis rejection;
- altered ECR1 bytes, ECS1 digest, object generation, predecessor record/state, operation ID and request digest rejection;
- fresh challenge validation, stale receipt replay rejection and same-operation/different-payload rejection;
- one exact successor only; skip, rollback and same-generation equivocation rejected;
- two concurrent advance requests with exactly one winner;
- crash/timeout after Provider commit, after Anchor conditional write, after Anchor signature, after Anchor read-back, after local QCF1 update and before PFS2 publication;
- lost Anchor response recovered by a fresh signed read and exact immutable retry;
- Provider-only backup rollback detected by the remote Anchor;
- joint Provider + local QCF1 backup rollback detected because the remote Anchor remains ahead;
- Anchor table unavailable, KMS unavailable, wrong key, stale read, conditional conflict and malformed item all fail closed;
- restore attempts and IAM/SCP guardrails are tested in a separate staging account by a security administrator who is not the service operator;
- multi-host power-loss, network partition, failover, key rotation, audit retention and incident recovery drills;
- independent security review of the service, account separation, receipt protocol, backup controls and client integration.

## 9. Scope and release gate

This proposal is **not implemented or deployed**. No AWS account, DynamoDB table, KMS Anchor key, Anchor endpoint or operator separation has been provisioned or verified. There is no claim that an AWS-backed floor exists today.

The next engineering sequence is:
1. implement a QRun-specific ECR1/ECS1 Anchor protocol contract and adversarial in-memory model;
2. test the server-side reconstruction and independent verification of Provider commit receipts;
3. implement the separately deployable service and conditional storage adapter;
4. provision a disposable, separately administered staging account and verify the actual IAM/KMS/DynamoDB behavior;
5. integrate the remote anchor into node startup and QAP1/QCF1/PFS2 recovery only after the service passes crash and multi-host tests.

Until all gates pass: keep Mainnet release approval false, public mint disabled, public firewall unchanged, and do not describe QZXB/USDT trading as live.

## 10. References

- AWS DynamoDB GetItem consistency: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetItem.html
- AWS DynamoDB conditional PutItem: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html
- AWS DynamoDB read consistency: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html
- AWS KMS ML-DSA keys and message limits: https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html
- AWS KMS key specifications: https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html
- AWS IAM DynamoDB backup and restore controls: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/backuprestore_IAM.html
