# CP-0573 — QFP6 standalone bootstrap preflight (phase A)

**Status:** implementation candidate; preflight only.
**Base:** CP-0572 / 899ec769261780e4dd9770afc1b2876b31580f78.

## Delivered in this phase

Adds the auto-discovered Cargo executable **qrun_v06_node**. Its explicit **--preflight** mode:

1. Reads a bounded JSON config and bounded regular-file artifacts; symbolic links are refused.
2. Verifies the exact SHA-256 of the complete config against a digest passed separately on the command line. The digest must come from an independently administered/reviewed channel; reading the digest from the same config or an adjacent file defeats this protection.
3. Decodes Q6PN only against a commitment pinned inside that externally-digested config; the commitment is not derived from the Q6PN file.
4. Checks Q6GD network, profile, Founder, consensus and CP-0528 tokenomics fingerprints against separately pinned values in the config.
5. Decodes Q6TS, requires Active status, and checks exact network/profile/Q6PN binding.
6. Loads Ed25519 and ML-DSA-65 authority public keys and checks their keyset ID against the pinned Q6TS keyset ID in the externally-digested config.
7. Loads the Q6TS monotonic floor using the strongly consistent, read-only AWS DynamoDB adapter and verifies both signatures.
8. Requires the signed Q6TS envelope to be the exact current floor head. It does not provision or advance the floor.

The executable reports the verified identity and exits. It does **not** open a QFP6 data directory, mutate the QFP6 store or trust floor, bind the node P2P listener, instantiate consensus, or mine. The AWS CLI performs a read-only network request to DynamoDB and may use its normal credential/cache behavior outside the QFP6 data directory. **--run** is intentionally rejected.

## Invocation

PowerShell example:

```powershell
$configSha256 = (Get-FileHash .\qrun-v06-node.json -Algorithm SHA256).Hash.ToLowerInvariant()
cargo run --locked --offline --bin qrun_v06_node -- --preflight --config .\qrun-v06-node.json --config-sha256 $configSha256
```

The config digest must be compared with an independently approved value delivered via a separate administrative channel before use. Calculating it locally is useful only after that external comparison; trusting a hash copied from the same untrusted directory is not an independent pin.

Example config shape (all identity values below are placeholders and must be replaced only with independently approved deployment values):

```json
{
  "network_id": "<64 lowercase hex characters>",
  "profile_id": "<64 lowercase hex characters>",
  "profile_pin_commitment": "<64 lowercase hex characters, independently pinned Q6PN commitment>",
  "founder_account": "<64 lowercase hex characters>",
  "consensus_fingerprint": "<64 lowercase hex characters>",
  "tokenomics_policy_fingerprint": "<64 lowercase hex characters>",
  "q6pn_path": ".\\trust\\q6pn.bin",
  "q6ts_path": ".\\trust\\q6ts.bin",
  "q6ts_ed25519_authority_public_key_path": ".\\trust\\q6ts-authority-ed25519.pub",
  "q6ts_mldsa65_authority_public_key_path": ".\\trust\\q6ts-authority-mldsa65.pub",
  "q6ts_authority_keyset_id": "<64 lowercase hex characters, independently pinned keyset ID>",
  "aws_cli_path": "aws",
  "aws_region": "<independently administered AWS region>",
  "q6ts_floor_table": "<pre-provisioned Q6TS trust-floor table>"
}
```

A bare **aws** executable name is resolved by the operating-system PATH; an explicit relative executable path is resolved relative to the config file. AWS credentials are resolved by the AWS CLI credential chain. The table must already exist and contain the independently provisioned floor; a missing floor is a hard failure. The config file's own SHA-256 must be independently pinned and passed on the command line. The Q6TS floor's AWS account/table must be administered separately from the node; a table in the same operator's account does not by itself prove independent trust.

The ML-DSA verifier currently used is **LibcruxMlDsa65VerifierCandidate**, which repository documentation explicitly classifies as candidate-only, not production-approved. This preflight is not a substitute for external cryptographic review, hardware/key custody review, AWS IAM/SCP separation or an audit of the trust bootstrap.

## Remaining before a runnable QFP6 node

This phase is not the node runtime. Still required: production-approved crypto/key custody; independently administered Q6TS and Q6EA/Provider services and pins; durable QFP6 store creation/reopen bound to an external manifest anchor; QAP1 intent recovery using the exact provider and anchor transports; transaction authentication and quote-asset authorization; node identity/key provisioning; externally reachable P2P policy; full-history synchronization and anti-rollback; and independent cross-operator qualification/security review. The existing provider/floor adapters are candidate implementations and have not been presented as deployed production services.

A successful preflight therefore means only that the supplied configuration, Q6GD/Q6PN/Q6TS artifacts, dual signatures and current Q6TS floor agree. It is not a Mainnet go decision.
