# CP-0575 - Q6CP canonical consensus-parameter profile binding

**Status:** candidate implementation; no Mainnet authorization.  **Current wire version:** Q6CP v2 (294 bytes), SHA-256d only. This supersedes the original v1/Argon2id draft description.
**Branch:** feat/cp0575-q6cp-consensus-profile-pinning-20261109
**Base:** CP-0574 / f2cca64a564bdfad2a6b21c8ddde7bbf85efe2ca.

## Purpose

Prior preflight compared the supplied consensus fingerprint with Q6GD/Q6PN but did not load the underlying consensus parameter set. CP-0575 adds a canonical, fixed-width **Q6CP v2** artifact and requires every node preflight to decode it, validate all consensus parameters, recompute the fingerprint, and match the exact Q6GD descriptor already bound by Q6PN.

A Q6CP artifact is a parameter container, **not** a signature, not a security review, and not a Mainnet authorization. Its raw file SHA-256 must be pinned independently in the externally digested deployment config. Q6TS/Q6PN continue to provide the separate trust-authority and network-profile binding.

## Q6CP v2 wire layout

Q6CP v2 is exactly **294 bytes**. It has no variable-length fields or permitted trailing bytes.

| Field | Encoding |
|---|---|
| Magic | ASCII `Q6CP` |
| Version | u16 big-endian, currently 2 |
| Header reserved | 2 zero bytes |
| Network ID | 32 bytes |
| Profile ID | 32 bytes |
| Q6GD descriptor commitment | 32 bytes |
| Protocol version | u16 big-endian, must be 6 |
| Target block time | u64 big-endian |
| Difficulty window | u64 big-endian |
| Minimum retarget ratio divisor | u64 big-endian |
| Maximum retarget ratio | u64 big-endian |
| PoW limit | 32-byte big-endian Uint256 |
| Initial target | 32-byte big-endian Uint256 |
| PoW algorithm | one byte; 2 = SHA-256d (the v2 validator rejects Argon2id) |
| PoW reserved | 3 zero bytes |
| PoW memory KiB | u32 big-endian; zero for SHA-256d |
| PoW iterations | u32 big-endian; zero for SHA-256d |
| PoW lanes | u32 big-endian; zero for SHA-256d |
| PoW output bytes | u8 |
| PoW reserved | 3 zero bytes |
| Maximum supply | u128 big-endian atoms |
| Initial subsidy | u128 big-endian atoms |
| Blocks per halving | u64 big-endian |
| Consensus fingerprint | 32 bytes |

The decoder rejects unsupported versions/algorithms, nonzero reserved bytes, malformed parameters, unsupported protocol version, invalid monetary execution schedule, a bad recomputed fingerprint, noncanonical length and trailing bytes.

The fingerprint is recomputed from all encoded consensus fields using the existing QFP6 consensus-fingerprint function. It is compared both with the fingerprint embedded in Q6CP and the immutable consensus fingerprint in Q6GD/Q6PN.

## Monetary execution constraints

The Q6CP v2 artifact must pass `ConsensusParameters::validate_monetary_execution_compatibility()` and `validate_parameters()`; the current v2 validator accepts SHA-256d only. In the current code this requires an exact match to the native execution constants:

- Maximum supply: 10,000,000,000 QZXB.
- Initial mining subsidy: 35,673,515,981 atoms per block before the remaining-supply cap.
- Halving interval: 4,204,800 blocks.
- Genesis allocation is not encoded in Q6CP. CP-0604 separately defines a 7,000,000,000 QZXB founder Genesis credit and a 3,000,000,000 QZXB mining cap; descriptor/policy fingerprint and full Genesis snapshot are checked separately.

These values are a **candidate protocol configuration** until they are independently reviewed and explicitly approved. Q6CP does not silently adopt v0.5 fee-only issuance, nor does a matching fingerprint make the current candidate PoW target, memory cost, block interval, or mining economics Mainnet-approved.

## New required preflight config fields

The externally SHA-256-pinned JSON config now requires:

```json
{
  "consensus_profile_path": ".\\trust\\qfp6-consensus.q6cp",
  "consensus_profile_sha256": "<64 lowercase hex characters; raw SHA-256 of the exact 294-byte Q6CP file, pinned independently>"
}
```

The digest is a raw SHA-256 of the bytes. It must be compared against a value supplied through a separate trusted administrative/review channel; calculating a hash from an untrusted file and trusting that same hash is not an independent pin.

Both `--preflight` and `--probe-qap1` require this Q6CP pair. They fail closed when the file is absent, malformed, hash-mismatched, for another network/profile/Genesis descriptor, or inconsistent with Q6GD's consensus fingerprint.

## Preflight output

On success, the binary reports the Q6CP raw digest and consensus fingerprint, protocol version, target block interval, difficulty window, target/limit, PoW algorithm (SHA-256d), supply cap, initial subsidy and halving interval. It explicitly reports:

```
q6cp_qualification=CANDIDATE_ONLY_NOT_MAINNET_APPROVED
```

The executable remains preflight/probe-only; `--run` still refuses to start a node. Q6CP does not yet instantiate a node runtime, open the QFP6 durable fork store, recover a QAP1 intent, or start consensus/mining.

## Local validation

The new Q6CP module has tests for:
- Canonical 294-byte round-trip and full fingerprint recomputation.
- Rejection of trailing bytes, nonzero reserved bytes and altered PoW parameters.
- Exact Q6GD binding for network, profile and Genesis descriptor commitment.
- Rejection of fee-only issuance and monetary parameter drift.
- File-level SHA-256 pinning before decode, Q6GD descriptor mismatch and fingerprint corruption even when a modified file is re-hashed.

The full QFP6 QAP1/Noise regression remains required after these changes. CI on the exact CP-0575 head is required before this PR can be considered green.

## Remaining Mainnet gates

A correctly pinned Q6CP only proves configuration consistency. It does **not** approve a consensus configuration for production. Still required: independent economic/PoW calibration and protocol review; production-approved post-quantum verifier and cryptographic review; HSM/KMS and node-key custody; separately administered production Q6TS/Provider/Q6EA services and trust floors; restart/fault-injection proof for QAP1 with the durable QFP6 manifest anchor; complete archive/history sync and anti-rollback qualification; public P2P reachability; multiple independently administered operators; released wallet/RPC/explorer; and a genuine external quote asset, custody/settlement path, counterparties and liquidity for QZXB/USDT.

No production key, trust floor, live service, Mainnet Genesis, public listener, exchange market, token value, or real-money trade is created by this change.
