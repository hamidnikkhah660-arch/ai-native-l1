# QFP6 Railway trusted-manifest anchor provisioning

**Scope:** zero-value public testnet only. This procedure is a configuration contract, not authorization to change a live Railway service.

## Variable contract

The Railway entrypoint accepts an optional service-level variable:

`QFP6_TRUSTED_MANIFEST_ANCHOR`

- It must contain exactly 64 lowercase hexadecimal characters (32 bytes), and must not be all zeroes.
- It is a public trust commitment, not a private signing key. Do not place private keys, credentials, or signatures in this variable.
- When present, the entrypoint copies it into `permissionless_runtime.trusted_manifest_anchor` in the generated, SHA-256-bound node configuration.
- When absent, the field is omitted. A node with existing durable manifests will continue to fail closed. A genuinely fresh Genesis-only node can continue through its separate bootstrap path.
- Invalid values cause the entrypoint to refuse before writing the bootstrap/config files.

## Provisioning requirements

Do not populate this variable by copying a value out of the same node volume and treating it as an independent pin. Before configuring a service:

1. Obtain the exact sequence-1 root anchor from an independently retained operator record or other independently authenticated source.
2. Compare it with that service's own local anchor-vault sequence-1 record and verify the complete local vault/witness chain against the expected network and profile.
3. Independently inventory the service's manifest generations and canonical tip. Do not assume seed, relay, and joiner share the same root or history.
4. Provision the value separately in the corresponding Railway service-level configuration, outside the mounted `/data` directory.
5. Keep a separate, independently durable monotonic high-water/witness source. The environment variable is only the immutable root pin; it does not by itself make a local volume-resident vault immune to rollback.
6. Only after all checks pass should an operator approve a controlled restart/deployment and verify the startup log, listener, and peer synchronization.

If the independent root anchor or a genuinely independent rollback witness is unavailable, leave the variable unset and keep the node stopped. Never guess the value, derive it from a checksum, delete existing history, switch an existing node to fresh-Genesis mode, or weaken the Rust startup gate.

## Per-node rule

Provision and validate seed, relay, and joiner separately. Do not copy one node's anchor to another unless independent evidence proves that their sequence-1 root is identical and the local witness chains validate independently.

## Change introduced by this patch

The entrypoint now has a strict optional environment-to-config bridge and unit tests for absent, valid, malformed, uppercase, wrong-length, non-hex, and zero values. It does not change Railway variables, restart services, read live volume contents, infer any anchor value, or bypass Rust validation.
