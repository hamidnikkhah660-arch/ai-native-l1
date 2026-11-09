# CP-0573 — QFP6 standalone bootstrap preflight

**Status:** implementation candidate; preflight only.
**Branch:** feat/cp0573-qfp6-node-bootstrap-preflight-20261109
**Base:** CP-0572 / 899ec769261780e4dd9770afc1b2876b31580f78.

## Implemented

The auto-discovered Cargo executable **qrun_v06_node** exposes a fail-closed **--preflight** command. No runtime mode is enabled in this phase.

The preflight requires an out-of-band SHA-256 for the complete configuration and then:

1. Reads bounded JSON/configuration and bounded regular-file artifacts; symbolic links are refused.
2. Verifies the complete configuration SHA-256 against the digest supplied separately on the command line. The expected digest must arrive through an independently administered/reviewed channel. Reading it from the same config or adjacent untrusted directory defeats this protection.
3. Decodes Q6PN only against the Q6PN commitment pinned in the externally digested config; it never derives the commitment from the Q6PN file.
4. Checks the Q6GD network, profile, Founder, consensus fingerprint and CP-0528 tokenomics policy fingerprint against the pinned configuration values.
5. Reads the **complete canonical QFB6 Genesis execution snapshot**, checks its separately pinned SHA-256, decodes it with the expected network/profile and runs the execution-state invariants.
6. Requires the complete snapshot's embedded Q6GD descriptor to equal the Q6PN descriptor, requires height zero, CP-0528 tokenomics state and the exact 1,000,000,000 QZXB Founder Genesis balance (100,000,000,000,000,000 atoms). The tokenomics validation also ties total Ledger value to the issued-supply counters, so the Founder amount cannot be accompanied by extra spendable Genesis supply.
7. Computes and reports the full Genesis state root; a corrupt snapshot, wrong descriptor, wrong consensus fingerprint, policy drift or Founder allocation mismatch is rejected.
8. Decodes Q6TS, requires Active status, and checks exact network/profile/Q6PN commitment binding.
9. Loads Ed25519 and ML-DSA-65 authority public keys and checks their keyset ID against the independently pinned Q6TS authority keyset ID.
10. Loads the Q6TS monotonic floor through the strongly consistent, read-only AWS DynamoDB adapter, verifies both signatures and requires the signed envelope to be the exact current floor head. It never provisions or advances the floor.
11. Requires a Q6EA Anchor pin bound to the Provider ID, network ID and Genesis digest embedded in Q6PN. The Anchor receipt key ID and ML-DSA-65 public key must both differ from the Provider receipt key ID/public key.
12. Requires Provider and Q6EA Anchor endpoints to be distinct numeric SocketAddr values with nonzero ports and specified unicast IP addresses. DNS names, wildcard and multicast addresses are refused. This catches malformed/identical endpoint configuration but does not establish independent operators.
13. Requires separate 32-byte Provider and Q6EA Anchor Noise XX server static public keys, each SHA-256 pinned in the externally digested config; all-zero, altered or identical keys are rejected. The corresponding client private keys are deliberately not accepted as plaintext files in this preflight.

The executable reports the verified network/profile, Q6GD commitment, full Genesis snapshot digest/state root, Founder atoms, Provider ID/endpoint, Q6EA Anchor ID/endpoint, Q6TS epoch and whether Q6PN includes a Q6QA quote-asset pin.

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
  "genesis_snapshot_path": ".\\genesis\\qfp6-genesis.q6gs",
  "genesis_snapshot_sha256": "<64 lowercase hex characters, independently pinned full snapshot SHA-256>",
  "q6pn_path": ".\\trust\\q6pn.bin",
  "q6ts_path": ".\\trust\\q6ts.bin",
  "q6ts_ed25519_authority_public_key_path": ".\\trust\\q6ts-authority-ed25519.pub",
  "q6ts_mldsa65_authority_public_key_path": ".\\trust\\q6ts-authority-mldsa65.pub",
  "q6ts_authority_keyset_id": "<64 lowercase hex characters, independently pinned keyset ID>",
  "aws_cli_path": "aws",
  "aws_region": "<independently administered AWS region>",
  "q6ts_floor_table": "<pre-provisioned Q6TS trust-floor table>",
  "q6ea_anchor_id": "<64 lowercase hex characters>",
  "q6ea_receipt_key_id": "<64 lowercase hex characters, distinct from Provider receipt key ID>",
  "q6ea_receipt_public_key_path": ".\\trust\\q6ea-anchor-mldsa65.pub",
  "provider_noise_server_key_path": ".\\trust\\provider-noise-static.pub",
  "provider_noise_server_key_sha256": "<64 lowercase hex characters, independently pinned SHA-256>",
  "q6ea_anchor_noise_server_key_path": ".\\trust\\q6ea-noise-static.pub",
  "q6ea_anchor_noise_server_key_sha256": "<64 lowercase hex characters, independently pinned SHA-256>",
  "provider_endpoint": "<numeric-ip>:<port>",
  "q6ea_anchor_endpoint": "<different-numeric-ip>:<port>"
}
```

A bare **aws** executable name is resolved through the operating-system PATH. Explicit relative executable paths resolve relative to the config file; Windows drive-letter and UNC paths are recognized even when preflight is tested on Linux. AWS credentials are resolved by the AWS CLI credential chain. The table must already exist and contain the independently provisioned floor; a missing floor is a hard failure. The config file's own SHA-256 and the full Genesis snapshot SHA-256 must be independently pinned. The Q6TS floor's AWS account/table must be administered separately from the node; a table in the same operator's account does not by itself prove independent trust.

## Scope and remaining production gates

This phase remains **preflight-only**. It does not open or mutate a QFP6 durable store, connect to Provider/Q6EA services, recover a QAP1 intent, bind a node P2P listener, start consensus, accept transactions or mine. The read-only AWS CLI lookup does use network access to DynamoDB and may use its normal credential/cache behavior outside the QFP6 data directory. **--run** intentionally returns a nonzero refusal.

The config's consensus fingerprint is checked against Q6GD, but this phase does not yet load and instantiate a frozen production QFP6 consensus-parameter artifact. Candidate testnet/v0.5 settings are not substituted.

Still required before a runnable QFP6 node: independently reviewed/frozen v0.6 consensus and issuance parameters; production-approved crypto and key custody (the current **LibcruxMlDsa65VerifierCandidate** remains candidate-only); separately administered and provisioned Q6TS floor, Provider and Q6EA/Anchor services with distinct keys/operators; durable QFP6 store open/recovery tied to the exact external manifest anchor; QAP1 intent recovery through the pinned Provider/Anchor transports; actual transaction key registry/custody; Q6QA signed quote-asset qualification where external quote assets are intended; operational Noise peer identities; externally reachable P2P policy; complete history sync and anti-rollback qualification; multi-operator testing and independent security review.

A successful preflight means only that the pinned configuration, full Genesis snapshot, Q6GD/Q6PN/Q6TS artifacts, dual signatures, current Q6TS floor and structural Q6EA/Provider pin/endpoint bindings agree. It does not prove that either remote service is online, that distinct endpoint operators are independent, or that either service has been security-reviewed. It is not node-runtime readiness, public Devnet approval or a Mainnet go decision.
