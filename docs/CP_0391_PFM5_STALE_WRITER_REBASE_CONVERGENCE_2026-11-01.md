# CP-0391 — PFM5 stale-writer rebase and sibling-branch convergence (2026-11-01)

## Context

CP-0390 added bounded PMT4 fork-choice replay rooted in an authenticated PCP4/PFM5 checkpoint. That makes it possible for a node to reconstruct the complete retained branch graph and deterministically select a canonical tip. It did not yet define the local reconciliation step for a writer whose external compare-and-swap (CAS) loses because another node published a competing sibling block first.

This increment adds a deterministic manifest-construction helper for that rebase step and extends the CP-0390 retarget-boundary regression with two independently instantiated fork-choice replicas.

## Behavior added

`next_pfm5_manifest_after_replay` accepts:

- the exact current PFM5 manifest and commitment obtained by the caller from a fresh authenticated external read;
- the checkpoint and configured PCP4 validation context;
- caller-maintained minimum manifest-generation and checkpoint-height floors;
- a fork-choice archive which has already been replayed from that checkpoint and may include locally retained, not-yet-committed branch envelopes.

Before producing a successor manifest, it:

1. validates the current manifest against the exact checkpoint and network/profile context;
2. recomputes the current manifest commitment and requires equality with the caller-supplied expected commitment;
3. enforces the configured generation and checkpoint-height floors;
4. checks that the archive's base tip, transaction-manifest identity, and consensus-profile fingerprint match the supplied checkpoint;
5. derives the entire retained branch digest set from bounded PMT4 envelopes, re-computes each PoW digest, checks network and post-checkpoint height, and rejects duplicate digests;
6. refuses to remove any digest already published by the current manifest (append-only within a checkpoint generation);
7. increments the manifest generation with checked arithmetic, links the exact current commitment as the parent, and binds the fork-choice-selected canonical tip;
8. encodes the result before returning it, so canonical schema/size failures happen before a caller stages any durable write.

The helper performs no provider I/O, signing, durable file writes, or CAS. A caller must obtain the latest manifest through a freshly authenticated provider read, persist every referenced envelope safely, submit the exact expected remote generation/commitment to the provider CAS, and retry a conflict by fetching and replaying the new winner. This code does not treat a local manifest checksum as an independent trust anchor.

## Regression scenario

The existing CP-0390 test reaches logical height 2,016, creates a PCP4 checkpoint and constructs two valid sibling PMT4 blocks at the first default retarget height (2,017).

The extended test models the following execution:

1. Node A and Node B start from the same authenticated checkpoint.
2. Both independently produce a different valid sibling at height 2,017.
3. Node A wins the external-CAS race in the model and publishes generation 2 containing branch A.
4. Node B's stale generation-2 proposal is not accepted as a successor. It fresh-replays generation 2, reapplies its still-valid branch B, and builds generation 3 with generation 2's exact commitment as parent and both sibling digests in the branch set.
5. Two separately reconstructed replicas replay generation 3 with opposite envelope arrival orders and agree on canonical tip, full chain tip (height/work/hash), monetary state, cumulative work, and retained branch count.
6. A writer whose replay archive omits branch A is rejected rather than silently pruning a branch already committed by generation 2.
7. Wrong current-manifest commitment, too-high minimum generation, and too-high checkpoint-height floor are each rejected.

The expected sibling winner is derived from the existing deterministic cumulative-work comparator. The test does not change PoW parameters or the comparator. It uses the existing deliberately low-cost Argon2id test profile only inside the 2,016-block regression helper.

## Validation

Run from `src/native/pow_bench`:

```text
cargo test --locked --offline --lib private_testnet_v4_hybrid_fork_choice_candidate::tests -- --test-threads=1
```

Observed on Windows:

- 5 fork-choice module tests passed; 0 failed.
- The 2,016 → 2,017 PFM5 retarget, stale-writer rebase, sibling preservation and two-replica convergence scenario passed.
- `cargo fmt` and `git diff --check` passed before the full-suite run.

The complete native test suite and hosted Linux CI are still required for this increment.

## Explicit boundaries

- This is a deterministic in-process model with two separately instantiated fork-choice objects. It is not a two-host network test.
- No live HTTPS/provider CAS operation is executed; no provider response, signature, request nonce, object generation or conditional write is produced by this helper.
- PFM5 still has no durable branch-store/node-startup integration in this change. It does not replace PFM4 persistence.
- A checkpoint remains a hard pruning/finality boundary. The authority for checkpoint publication, independent monotonic rollback protection and checkpoint rotation must be defined and deployed separately.
- No consensus-parameter, Genesis, network identity, transaction wire, tokenomics, PoW, or issuance policy changed.
- Gate 2 and Gate 8 remain open. This is not public testnet, production mining, mainnet, listing, liquidity, or production-security approval.

## Next required engineering gate

Integrate this helper behind the actual PFM5 checkpoint store and the verified external-CAS client using a bounded conflict-retry loop. Then qualify it with at least three independent OS processes, followed by separate hosts and provider-side rollback/failure injection. A node must not announce a checkpoint generation as canonical until its exact provider CAS result has been verified and the durable branch set can be replayed from disk.
