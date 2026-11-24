# QFP6 Railway trusted-manifest anchor provisioning

**Scope:** zero-value public testnet only. This procedure is a configuration contract, not authorization to change a live Railway service.

## Variable contract

The Railway entrypoint accepts three paired service-level variables for nodes with existing history:

- `QFP6_TRUSTED_MANIFEST_ANCHOR`: the immutable sequence-1 root, exactly 64 lowercase hex characters (32 bytes), nonzero.
- `QFP6_TRUSTED_MANIFEST_FLOOR_GENERATION`: a canonical unsigned decimal integer in the u64 range.
- `QFP6_TRUSTED_MANIFEST_FLOOR_ANCHOR`: the manifest anchor at exactly that floor generation, exactly 64 lowercase hex characters, nonzero.

All three values must be present together. The two anchor values are public commitments, not private signing keys. The floor generation and floor anchor must come from an independently retained, authenticated operator checkpoint—not from a checksum or a value copied from the same Railway volume. The runtime verifies that the local append-only vault contains that exact generation and anchor. A vault below the floor or with a different anchor at the pinned generation is rejected.

When these variables are absent, they are omitted from the generated, SHA-256-bound node configuration. Existing durable history continues to fail closed. A genuinely fresh Genesis-only node must omit all three and can continue through its separate bootstrap path. Invalid or partial values cause the entrypoint to refuse before writing bootstrap/config files.

**Security boundary:** this is an externally pinned minimum checkpoint, not a continuously advancing remote CAS service. A rollback below the pinned generation is rejected; a rollback to the pinned generation itself can still pass. Advance the floor after each independently verified backup/checkpoint to narrow that rollback window. This does not qualify the candidate for value-bearing Mainnet.

## Existing data-layout compatibility

The currently observed service images do not all use the same directory version: the seed image's entrypoint uses v3 paths, while the relay/joiner image refresh uses v4 paths. The updated entrypoint selects an already existing per-role v3 or v4 layout rather than blindly switching to v4:

- If only v3 paths exist, keep v3.
- If only v4 paths exist, keep v4.
- If neither exists, use v4 for a new node.
- If both versions exist, or an existing path is a symlink/non-directory, refuse startup and require an explicit data inventory. It never merges or deletes the directories.

This is intended to prevent an image refresh from silently ignoring a node's previous durable history. It does not migrate data between layouts.

## Checkpoint-floor operating rule

For an existing node, select a floor generation that is independently recorded outside the node's Railway volume and verify its corresponding manifest anchor. If the current local vault is ahead of that checkpoint, the floor remains a lower bound. To make the bound useful, refresh the external floor after each independently verified backup/checkpoint and preserve the previous approved record offline.

The floor does not advance automatically with block production. It is not a substitute for a continuously available, strongly consistent external monotonic anchor service. Do not claim that it defeats rollback of both the Railway volume and the service-level configuration.

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

The entrypoint now has strict root/floor environment parsing, v3/v4 history-preserving layout selection, and 19 Python unit tests. The Rust runtime validates the external floor against the local vault chain, with regression tests for stale and mismatched floors. The image workflow runs Python tests, Rust formatting, and targeted `qrun_v06_node` tests before building/publishing. This patch does not change Railway variables, restart services, read live volume contents, infer any anchor value, or bypass Rust validation.
