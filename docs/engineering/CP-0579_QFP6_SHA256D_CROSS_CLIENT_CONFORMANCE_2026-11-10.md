# CP-0579 - QFP6 SHA-256d independent conformance vectors

**Date:** 2026-11-10
**Status:** Candidate conformance evidence; not a consensus freeze or Mainnet authorization
**Parent:** CP-0578 / QFP6 v0.6 SHA-256d profile candidate

## Purpose

CP-0578 added the SHA-256d PoW algorithm to the Rust consensus candidate. CP-0579 adds a second-language reference implementation that independently reconstructs the fixed-width QFP6 PoW header and computes the digest with Python's standard-library \`hashlib\`.

This reduces the risk that the Rust implementation and its Rust-only tests share the same byte-order, field-order, or hashing mistake. The reference does not reuse serialized bytes emitted by Rust: it independently serializes typed vector fields.

## Canonical header format

The header preimage is exactly 198 bytes:

| Offset | Length | Field | Encoding |
|---:|---:|---|---|
| 0 | 12 | \`AIN1-POW-V1\\0\` | Literal bytes including NUL |
| 12 | 2 | protocol version | Unsigned big-endian |
| 14 | 32 | network ID | Raw bytes; nonzero |
| 46 | 8 | height | Unsigned big-endian |
| 54 | 8 | timestamp | Unsigned big-endian |
| 62 | 32 | parent hash | Raw bytes |
| 94 | 32 | previous consensus hash | Raw bytes |
| 126 | 32 | state root | Raw bytes |
| 158 | 32 | target | Unsigned big-endian |
| 190 | 8 | nonce | Unsigned big-endian |

PoW digest:

\`SHA256(SHA256(canonical_header_bytes))\`

The digest and target are interpreted as unsigned 256-bit big-endian integers. A header meets its target exactly when \`digest <= target\`.

## Independent implementation and vectors

- \`simulations/qfp6_sha256d_reference.py\` reconstructs the header with explicit big-endian packing, runs double SHA-256, and checks the target comparison.
- \`simulations/qfp6_sha256d_conformance_vectors.json\` stores two independent fixtures including every typed field, full expected preimage bytes, expected digest, and target result.
- Vector \`qfp6-test-header-initial-target\` matches the existing Rust SHA-256d golden digest \`dc5ea6f42f0d0a504a968dadbed90853099ed35e7c85e346512b2c7118a0971c\`. It intentionally does **not** meet the candidate easy target.
- Vector \`qfp6-test-header-maximum-target\` exercises acceptance against the maximum 256-bit target and has digest \`de16b24aee733c5bc38fec35261cf153bf7533a71e2b253be26f96bb85601d91\`.
- Negative cases reject zero network ID, zero target, zero protocol version, and booleans passed as integer fields.
- A nonce mutation is required to change both the serialized preimage and digest.

## CI and local verification

The Rust validation workflow now runs the independent Python reference before Rust format/check/test steps:

\`python3 ../../../simulations/qfp6_sha256d_reference.py\`

Local Windows execution on 2026-11-10:
- Python independent reference: 3 tests passed.
- CP-0578 Rust golden-vector test remains the companion implementation-side vector.
- This candidate must still receive exact-SHA GitHub Actions validation.

## Scope limits

This establishes agreement on these fixed canonical header vectors only. It does not:
- implement or activate a QFP6 node runtime, P2P service, mempool, or miner;
- calibrate the candidate difficulty target, retarget timing, hashrate economics, or attack-cost assumptions;
- prove independent production clients, operator diversity, or a security audit;
- make SHA-256d a post-quantum signature or quantum-resistant consensus design;
- create a Genesis, issue QZXB, or enable public/value-bearing transactions.

The node executable remains preflight/probe-only. Public Devnet qualification, production signature verification, canonical runtime wiring, wallet/key custody, and independent review remain separate release gates.
