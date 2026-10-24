# CP-0405 - QZBE PoW envelope and v0.4 fork-choice candidate

Date: 2026-10-24

Status: **candidate-level implementation; not canonical-node integration or Mainnet activation**

## Scope

CP-0405 adds a separate QZBE envelope for the transaction-bearing QZB4 v2 execution body and an in-memory branch graph that replays each branch against its own v0.4 monetary state, target/timestamp history, and cumulative work. It intentionally does not reuse PMT3, PMT4, PFM3, or PFM4, whose payload/state contracts belong to earlier monetary execution paths.

The envelope binds:
- a versioned QZBE family discriminator and envelope version;
- a fingerprint over the configured PoW/difficulty parameters (protocol version, target timing/window, retarget clamps, PoW limit/initial target, and Argon2id parameters);
- the existing PoW header fields (network, height, timestamp, ledger parent, prior consensus digest, state root, target, nonce);
- the canonical QZB4 v2 body with its independent monetary-profile fingerprint and transaction execution data.

Decoding is exact-length and canonical: unsupported versions, truncation, trailing bytes, a different monetary profile, or a different PoW/difficulty configuration are rejected rather than retried through another codec. The candidate checks that header and body agree and that the PoW header passes the explicitly supplied ConsensusParameters.

## Candidate fork-choice behavior

V04ExecutionForkChoiceCandidate accepts only envelopes whose parent is the configured Genesis baseline or an already validated branch tip. It clones the referenced branch state, validates branch-local target history/timestamp progression, checks proof of work and checked cumulative-work arithmetic, then replays QZB4 v2 using the same configured monetary profile and injected transaction authenticator. The branch is recorded only after the staged replay passes.

Tip selection uses the repository's deterministic compare_chain_tips cumulative-work comparator, not height alone. The branch archive has explicit candidate resource ceilings and can be rebuilt by sorting envelopes by height and replaying them from Genesis. Unit tests cover two competing branches, an extension that causes a reorg, state-root/work equality after archive replay, strict codec-family/version handling, cross-profile/cross-PoW-parameter rejection, malformed parent/target/root rejection, and no mutation after rejected blocks.

The test authenticator is only a fixture. The caller must supply the Genesis state, exact v0.4 profile/schedule, and exact PoW/difficulty parameters. No Mainnet economics, default schedule, or production signature scheme is chosen.

## Limits and remaining integration

This is a bounded in-memory branch graph, not a crash-safe persistent branch archive. It is not wired into chain_import_node, devnet_node, the canonical P2P listener, runtime QZP4 snapshot commit/recovery, or the external monotonic-anchor provider from CP-0404. The QZBE envelope and replay tests therefore demonstrate a candidate protocol boundary; they do not demonstrate live-node canonical reorg or production anti-rollback.

Before production use, the persistent archive/checkpoint format must bind the Genesis manifest, monetary profile fingerprint, PoW consensus fingerprint, branch records, target history, cumulative work, chosen tip and exact snapshot digest; recovery must replay/verify data and reconcile it with an independently durable CAS anchor. Fault-injection, multi-node mixed-version, and deep-reorg tests remain necessary.

## Gate status

- Gate 2: **open** - canonical profile/runtime wiring and production consensus configuration remain incomplete.
- Gate 8: **open** - durable branch archive, real external anti-rollback provider, and canonical reorg/recovery integration remain incomplete.
- Gate 12: **open** - no smart-contract execution or contract-transition validation is added here.

GitHub Actions run 40110485321 completed with success for exact commit f201b2d4f510cf7bd881c064012307c76b317456 on 2026-10-24. Both Format, check, and test and Windows PMT4 TXN4 two-node loopback passed. This is CI evidence for that candidate commit only; it does not close Gate 2/Gate 8 or prove canonical-node integration.
