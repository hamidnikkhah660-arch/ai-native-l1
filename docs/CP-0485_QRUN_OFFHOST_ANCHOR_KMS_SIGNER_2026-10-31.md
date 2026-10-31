# CP-0485 — QRun Off-Host Anchor AWS KMS ML-DSA-65 Signer Candidate

Date: 2026-10-31

Status: **An Anchor-specific KMS signer wrapper is implemented and locally tested. No Anchor KMS key, AWS account, staging service or independent security administrator has been provisioned; no live AWS request has been made.**

## Scope

Updated module:
- \`src/native/pow_bench/src/external_cas_aws_kms_signer_candidate.rs\`

New type:
- \`AwsKmsCliOffhostAnchorReceiptSigner\`, implementing the CP-0482 \`OffhostAnchorReceiptSigner\` interface.

The existing Provider signer remains pinned to \`ExternalCasPin\`. The new Anchor signer accepts an \`ExternalCasOffhostAnchorPin\` plus the matching Provider pin and takes its expected signing public key exclusively from the Anchor pin. It does not reuse the Provider receipt key or silently substitute one pin for the other.

## Startup pin and key checks

The Anchor constructor:
1. validates that the Anchor ID, Provider ID, Network ID and wallet-bound Genesis digest match the Provider pin, and that the Anchor receipt key ID/public key are distinct from the Provider receipt key;
2. requires a full AWS KMS key ARN, not an alias or short key ID;
3. queries KMS public-key metadata and requires \`ML_DSA_65\`, \`SIGN_VERIFY\`, and \`ML_DSA_SHAKE_256\`;
4. extracts the exact raw ML-DSA-65 public key from SPKI DER and compares it byte-for-byte with the independently configured Anchor public key;
5. signs a domain-separated Anchor self-test challenge which binds the Anchor identity, provider scope and both independent receipt key identities, then verifies the signature locally against the Anchor public key.

Each subsequent digest signature is also verified locally before being returned. AWS CLI continues to run without a shell and uses the configured AWS credential chain; private key bytes are never loaded into the process.

## Tests and boundaries

A new deterministic test checks that the Anchor startup challenge changes when the Anchor ID, Anchor public key, or Provider public key changes, and that a mismatched Provider network is rejected.

The focused KMS signer tests pass: 3 passed, 0 failed. They validate SPKI parsing and challenge binding; they do not emulate AWS KMS, credentials, IAM, key policy, or network behavior.

## Production qualification still required

- Provision a distinct ML-DSA-65 Anchor KMS key in a separately administered staging account.
- Verify the live key spec, usage, signing algorithm, SPKI match, signature self-test and real receipt signing/verification.
- Restrict the Anchor service role to signing with that key and the exact Anchor table item; keep KMS administration, key deletion/rotation policy, table restore and account recovery outside the routine runtime role.
- Exercise KMS throttling, access denial, timeouts, malformed responses, key rotation/revocation and recovery.
- Deploy the Anchor daemon and integrate it into QRun startup and the QAP1/Provider/Anchor/QCF1/PFS2 durable commit order.
- Complete multi-host fault tests and independent security review.

Until those gates are completed, the Anchor KMS signer is an implementation candidate only; it does not establish a remote monotonic authority or Mainnet readiness.
