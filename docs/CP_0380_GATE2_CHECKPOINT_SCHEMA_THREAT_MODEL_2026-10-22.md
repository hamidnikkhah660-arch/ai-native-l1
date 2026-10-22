# CP-0380 — Gate 2 checkpoint schema and trust boundary

Date: 2026-10-22
Base source: `1bc600803ffeab378450abb8b984bebba4a56942` (PR #48 merge)
Status: **implementation design proposal; no checkpoint wire/runtime code is added by this document**
Scope: private-testnet PMT4/PFM4 candidate only; no production or Mainnet authorization.

## Decision sought

Proceed with a versioned checkpoint record and a separately versioned checkpoint-aware manifest. Do not increase `MAX_V4_HYBRID_FORK_ARCHIVE_HEIGHT`, modify the production-candidate retarget/halving values, or prune ancestry as a substitute for a checkpoint. The record schema below is a concrete implementation baseline for review; it is not yet an implemented wire format and must not be advertised as interoperable until independent byte vectors and restore tests pass.

## Source findings that constrain the design

- `PrivateTestnetChain` combines the monetary state, PoW consensus-tip digest, cumulative work, and `TargetHistory`.
- The monetary-state snapshot already authenticates its own canonical ledger bytes and policy fingerprint and carries `total_mined_atoms`; it is not itself an anti-rollback trust anchor.
- `TargetHistory` is currently indexed from height zero. At the default 2,016-block window, the next-height 2,017 retarget requires timestamps for heights 1 through 2,016 and the target at height 2,016. A compressed history must keep logical heights separate from in-memory vector offsets; otherwise it can produce a missing or misindexed retarget observation after restore.
- The chain's `cumulative_work` is currently updated with saturating addition. Checkpoint implementation must resolve and test exact fork-work/overflow semantics rather than treating a stored work value as self-authenticating. If exact cumulative work can overflow, admission must fail closed or follow an explicitly frozen protocol rule; silent saturation must not create an accidental fork-choice tie.
- PFM4 currently stores an index of PMT4 envelopes and rebuilds the branch graph from those envelopes. Its local checksum is not an independent anti-rollback proof. The existing external-CAS provider is a contract/test fixture rather than a deployed independent HTTPS service.

## Threat model and trust boundary

The checkpoint can be corrupted, truncated, replaced with a different valid-looking snapshot, replayed from an older disk image, paired with a stale manifest, or supplied by a malicious or compromised writer. A snapshot checksum only detects accidental or non-adaptive corruption; a local snapshot and local manifest restored together can roll back together. A hash chain of checkpoints also does not establish a trusted origin unless its initial commitment is independently trusted.

A checkpoint may be accepted only when one of these conditions holds:

1. A verifier replays and validates the complete ancestry from an already trusted origin to the checkpoint, including every state transition, PoW, target, timestamp, issuance amount, and fork-work update; or
2. A protocol-defined checkpoint authorization is verified against an independently provisioned trust policy and binds the exact checkpoint digest, network/profile, height, parent commitment and freshness/generation.

A future remote-CAS receipt can provide freshness/anti-rollback evidence only under a pinned and independently trusted provider key and an atomic-generation contract. It does **not** prove that the checkpoint's state or chainwork is semantically correct. Do not accept checkpoint bytes merely because the checksum is valid or a writer was able to store them.

No production trust key, threshold, provider, HTTPS transport, or checkpoint quorum is selected here. Gate 8 remains an explicit dependency.

## Proposed canonical PCP4 record, version 1

All integers are unsigned big-endian. There are no optional trailing extensions: unknown versions, flags, length mismatches, trailing bytes, unknown enum values, and over-budget inputs fail closed. `record_len` includes the terminal 32-byte digest.

| Field, in order | Width | Validation / purpose |
|---|---:|---|
| Magic `PCP4` | 4 bytes | Record type; never interpreted as a PMT4 block. |
| Schema version | u16 | Exactly `1`. |
| Flags | u16 | Exactly zero in version 1. |
| Total record length | u32 | Must equal the actual bounded input length. |
| Network ID | 32 bytes | Must equal the configured network. |
| Genesis fingerprint | 32 bytes | Domain-separated commitment to canonical genesis monetary snapshot and the selected profile. |
| Consensus/profile fingerprint | 32 bytes | Recomputed from validated consensus parameters and monetary policy; never trusted from input alone. |
| Transaction manifest ID | 32 bytes | Must equal the active transaction manifest. |
| Logical checkpoint height | u64 | Must equal the decoded state's height. |
| Consensus tip digest | 32 bytes | PoW/header-chain digest at the checkpoint; distinct from the ledger's internal block tip. |
| Ledger tip hash | 32 bytes | Must equal the decoded ledger tip hash. |
| Monetary state root | 32 bytes | Must equal the decoded state root and the checkpoint transition's committed root. |
| Total mined atoms | u128 | Must exactly equal the value decoded from the monetary snapshot. |
| Cumulative chainwork | 32 bytes | Canonical unsigned 256-bit value; independently verified/replayed or covered by a valid checkpoint authorization. |
| Parent checkpoint commitment | 32 bytes | Zero only for a genesis-trusted checkpoint; otherwise commits to the exact parent checkpoint record. It is linkage, not proof of trust by itself. |
| Monetary snapshot length | u32 | Checked against the existing monetary-snapshot maximum and remaining input before allocation. |
| Monetary snapshot | variable | Exact output of the canonical `MonetaryLedgerState` snapshot codec. |
| Target-history start height | u64 | First logical height represented by the history records below. |
| Target-history entry count | u32 | Bounded before allocation; no larger than the approved profile's window plus any specifically required bootstrap entry. |
| Target-history entries | 49 bytes each | `height:u64`, `target:[u8;32]`, `timestamp_present:u8`, `timestamp:u64`. Heights are contiguous; target is nonzero and at most `pow_limit`; flag is 0 or 1. Only height zero may use `timestamp_present=0`, with timestamp bytes zero. All represented heights above zero require timestamps that increase strictly. |
| Checksum/domain digest | 32 bytes | SHA-256 domain-separated digest over all preceding record bytes; detects corrupt bytes but is not an authenticity or freshness proof. |

The schema-level checksum preimage uses the domain `AIN1-PMT4-CHECKPOINT-CHECKSUM-V1\0`. The checkpoint commitment used by a parent record or manifest uses a separate domain `AIN1-PMT4-CHECKPOINT-COMMITMENT-V1\0` over the complete canonical record, including its checksum. Implementations must use the repository's audited, existing domain-hash primitive consistently and include cross-implementation golden vectors; do not substitute a non-domain-separated hash in one client.

### Canonical target-history window

For a checkpoint at logical height `H` and difficulty window `W`:

- At `H = 0`, encode only height 0, the configured initial target, and an absent genesis timestamp.
- For `0 < H < W`, encode every height `0..=H`; height 0 has no timestamp and all later entries have a timestamp.
- For `H >= W`, encode exactly `W` entries with heights `H-W+1..=H`; each entry has a timestamp. At `H = W = 2,016`, this is heights `1..=2,016`, which supplies the first default retarget observation for next height `2,017`.

The last entry's target must be the target used at height `H`. The restored in-memory history must retain an explicit logical start/base height and must not treat the first retained entry as height zero. Before restore is enabled, tests must prove the exact target result at the first default retarget and the next retarget boundaries, including the timestamp endpoint/interval convention. If a profile specifies a different window, the canonical coverage rule follows that validated profile and remains subject to a hard record-size limit.

## Checkpoint-aware manifest and storage protocol

Do not silently reinterpret an existing PFM4 manifest as checkpoint-aware. Use a separately versioned manifest (proposed magic `PFM5`) that commits to:

- the checkpoint record digest, checkpoint height, network/profile/manifest identifiers and parent checkpoint commitment;
- the canonical suffix envelope digests after the checkpoint;
- the canonical tip and manifest generation;
- explicitly configured, separately enforced retained-block count, retained-byte, suffix-replay-work and maximum-reorg-depth budgets.

The trusted checkpoint is the lower ancestry boundary. Forks whose common ancestor is at the checkpoint are eligible for normal fork choice, subject to the configured reorg-depth and resource budgets. Any reorg whose common ancestor is below the trusted checkpoint is rejected unless a separate, authenticated checkpoint-replacement protocol has been specified and implemented. Old envelopes may be pruned only after the replacement checkpoint, suffix files and new manifest are durable and the external generation CAS (when configured) confirms the exact new commitment.

Crash-safe publication sequence: write checkpoint and suffix files to bounded temporary paths; flush file contents; rename into canonical names; flush parent directories where the platform supports it; write and flush the pending manifest; conditionally advance the independently trusted external generation; atomically publish the committed manifest; then prune files no longer referenced by the committed manifest. A failed local write or CAS leaves the previous committed manifest authoritative. Startup must recover only the old committed generation or the exact newly anchored one, never infer commitment from a pending file alone. Windows and POSIX durability semantics require explicit tests and documentation.

The store lock remains necessary for a single local writer but is not a substitute for server-side atomic CAS across hosts. PFM4 opening remains replay-based; any conversion to PFM5 must replay the existing PFM4 ancestry first and must not silently infer checkpoint trust from local files.

## Budgets and failure behavior

Treat the following as different limits: logical lifetime height; retained branch-record count; aggregate retained bytes; maximum reorg depth; maximum snapshot bytes; maximum target-history entries; maximum work performed during replay/validation; and maximum file/manifest sizes. Check sizes before allocations and arithmetic with checked operations. Freeze numeric production values only after representative measurements and resource-attack tests; this design deliberately does not invent a larger height ceiling or unmeasured memory budget.

Malformed, stale, over-budget, profile-mismatched, noncanonical or unauthenticated checkpoints must fail without changing the canonical tip, branch archive, checkpoint file, committed manifest, external generation, or issuance state. A restore failure must never fall back to accepting an unverified checkpoint.

## Required implementation sequence and acceptance tests

1. Resolve chainwork overflow semantics and create an independently specified checkpoint trust/authorization interface before enabling checkpoint restore.
2. Implement canonical PCP4 encode/decode and PFM5 manifest support with explicit bounds, checked arithmetic, and unknown-version rejection. Keep the existing PFM4 path separate.
3. Refactor target history so its logical height and retained-vector offsets are distinct; prove restore/continue equivalence before integrating checkpoint pruning.
4. Add independent Rust/Python byte vectors for the checkpoint, profile fingerprint, state root, target history, and manifest references. Round-trip tests within one implementation are necessary but insufficient.
5. Exercise checkpoint heights 0, 1, `W-1`, `W`, and `W+1`; explicitly restore height 2,016 and verify the exact default-profile retarget decision for next height 2,017. Verify the next default retarget transition without replacing production parameters with a short test window.
6. Independently verify monetary state/cumulative-mined fields at heights 4,204,799, 4,204,800 and 4,204,801 with cross-checked vectors; do not claim this is an executed live chain merely because a synthetic fixture is accepted.
7. Test reorgs whose common ancestor is the checkpoint, reorg depth exactly `R` and `R+1`, attempts to cross the checkpoint, duplicate/conflicting suffix branches, malformed timestamps/targets, wrong roots, old profile/manifest, stale checkpoint generations, corrupt/truncated/oversized files, process crashes at each publication boundary, lost acknowledgements, disk restore/rollback, and two hosts racing a generation CAS.
8. Measure worst-case checkpoint creation, restore, retained bytes and replay work under adversarial branch fan-out. Complete independent protocol/economic/security review and Gate 8 provider/key-lifecycle qualification before any public-value deployment.

## Status after this design pass

This document makes no source-runtime changes. It does not implement PCP4/PFM5, shorten replay, resolve work-overflow semantics, make the default 2,017 retarget or the halving boundary reachable through the current archive path, or close Gate 2/Gate 8. Existing CI passing on the current main baseline is regression evidence only. Native QZXB Mainnet, public mining, exchange listing, native liquidity and revenue are not claimed. Owner-funded spend remains USD 0; no paid service or production key is introduced.
