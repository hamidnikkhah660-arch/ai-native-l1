# CP-0851 — QFP6 Three-Node Staging Qualification and History-Sync Gap

Date: 2026-11-24  
Scope: ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY  
Status: Three persistent Railway services are online and exchanging authenticated peer traffic. Cross-host NAT-only session qualification and normalized Windows PE reproducibility passed. Full multi-node canonical-tip convergence is NOT YET PROVEN.

## 1. Live staging topology (read-only inspection)

The existing Railway `staging` environment contains three separate services:

| Service | Role | Runtime | Persistent volume | Region |
|---|---|---:|---:|---|
| `qfp6-node-a-seed` | Genesis-rooted Seed | 1/1 online | 500 MB | `iad` |
| `qfp6-node-b-relay` | Public Relay | 1/1 online | 500 MB | `iad` |
| `qfp6-node-c-joiner` | Outbound-only Joiner | 1/1 online | 500 MB | `iad` |

At inspection time, all three deployments reported SUCCESS, no crashed replicas, no active warnings or critical notifications, and no recent deployment failures. Their volumes and local data paths are separate.

This is three distinct running services, not three independent operators. They are in one Railway project, one staging environment, one cloud region, and under one account/operator. No independent community operator has been qualified by this observation. No service configuration, deployment, volume, or secret was modified during this inspection.

## 2. Transport and discovery evidence

Observed runtime evidence includes:

- Seed and Relay established outbound Noise sessions to one another using operator-pinned bootstrap identities.
- Signed Q6PD peer records were announced, pulled, and gossiped.
- Seed and Relay continued reporting healthy persistent sessions; observed heartbeat counters reached approximately 1,962.
- The Joiner established pinned Noise connections and repeatedly requested history from its configured Seed.
- The live service metrics showed low observed CPU, memory, disk, and network use during the sample window. This is not a billing or free-tier determination; account credits and actual charges were not available through the read-only inspection.

The Windows hosted-runner qualification also passed on 2026-11-24:
- pinned Noise handshake and Q6HI/Q6HR: PASS;
- signed Q6PD record pull: PASS;
- NAT-only persistent session: six heartbeats: PASS;
- worker stopped cleanly after its bounded session.
- Scope was a short-lived external Joiner transport test only, not a complete consensus node or independent operator.

Workflow: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/45321438688

## 3. Initial bootstrap versus periodic resynchronization

The startup logs for Relay and Joiner show successful initial bounded bootstrap at the then-current Seed height (approximately 22–24 blocks), with `complete=true`.

The running supervisor then performs periodic outbound resynchronization every 30 seconds. In the deployed source revision, that periodic refresh is deliberately bounded to:

- `max_blocks_per_page = 16`
- `max_pages = 2`
- `max_rounds = 1`

This yields at most 32 imported blocks per polling call. The client-side snapshot and page cursor are local to that call; the supervisor creates a fresh sync call at the next 30-second poll. Consequently, runtime reports after the source history grew beyond the first 32 blocks repeatedly show `blocks_imported=32`, `pages=2`, and `complete=false`. In the inspected sample, a reported source snapshot height remained around 642 while local reported heights continued increasing.

This is a confirmed limitation of the current periodic-refresh policy. It is not proof by itself that the nodes have a consensus fork, but it also cannot establish that they are currently on the same chain. The server-side retained history snapshot may remain pinned while a client keeps abandoning the cursor before completion; this interaction needs a dedicated regression test before choosing a fix.

## 4. Consensus qualification status

Do not claim the network is converged or decentralized yet.

The following must be demonstrated before a release or PR merge:

1. A bounded, resumable history-sync strategy that advances the page cursor across finite reconnect windows without violating Noise-key verification, connection accounting, replay protection, or source-snapshot immutability.
2. Explicit current-tip comparison across all services: same network/profile, height, consensus tip hash, execution tip/state root, and a clear fork-choice outcome.
3. Restart/reconnect qualification with durable history and anchor-vault state preserved.
4. A real separately operated node with a fresh locally generated identity. Multiple services owned by one operator do not satisfy this criterion.

The periodic Q6PD heartbeat session is transport liveness only; it does not itself confer consensus authority or prove block propagation. The inbound Q6PB frame path is an admission interface. A complete outbound block-announcement/gossip and fork-choice audit is still required.

## 5. Reproducible Windows build evidence

The updated workflow built the same source revision on two separate hosted Windows machines. Both artifacts were 5,822,464 bytes. Raw hashes differed because of linker-produced PE metadata. The verifier normalizes only:
- the COFF file-header timestamp;
- the three IMAGE_DEBUG_DIRECTORY timestamps;
- the RSDS CodeView PDB GUID.

Every remaining byte is compared exactly. Both normalized artifacts produced:

```text
0c1bc4dfe25437139ca8ea60a195acec460967cae5f7167c96fa770f16b7305d
RESULT=PE_CONTENT_IDENTICAL_AFTER_BUILD_METADATA_NORMALIZATION
```

Workflow: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/45322495660

## 6. Operational decision

- Keep PR #208 Draft until all consensus and multi-operator gates pass.
- Do not redeploy or restart the existing Railway services as part of this qualification.
- Do not read, print, export, rotate, or copy service secrets or TPM-bound keys.
- Do not add paid infrastructure or claim Railway is free; billing/credit state was not verified.
- Next engineering item is a tested resumable sync cursor / retained-snapshot design, followed by a time-aligned consensus convergence harness.


## 7. CP-0852 CI and live-staging recheck (2026-11-24)

The follow-up implementation is committed on the Draft PR branch at `24cffd1a0235dd0a3c5eb8df88552278ef48cbb2`. GitHub Actions run [45324671074](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/45324671074) completed successfully across all three jobs:

- `cargo fmt --all -- --check`, `cargo check --all-targets`, and `cargo test --all-targets`: PASS.
- Windows PMT4/TXN4 two-node loopback suite: PASS, including DPAPI offline trust provisioner, signed transaction submit/invalid-signature rejection/peer propagation/replay, and PFM4 paged archive sync with inter-page reorg and stale-cursor rejection.
- EVM contract, wallet console, and dependency audit: PASS.

This validates the source revision against the existing CI suite. It does not prove multi-round live synchronization or multi-operator consensus.

A read-only Railway recheck found all three staging services still live, each with its own 500 MB volume, no staged changes, and successful current deployments. The deployed immutable images remain the prior build: Seed image tag `1c2edc459093`; Relay and Joiner image tag `6fbbd98f4730`. None contains CP-0852. No deployment, restart, volume mutation, or secret change was performed.

Recent runtime logs show the unresolved old-image behavior directly: Relay and Joiner repeatedly report `start_height=1`, import only two 16-block pages (`blocks_imported=32`), and finish with `complete=false` while the Seed source snapshot is around height 712. The Seed's own history client also reports one-block incomplete imports. This confirms the deployed staging topology is not yet demonstrating complete synchronization. The observed final heights are not sufficient to establish matching canonical tips; log samples also show different tip hashes and heights at different times, so no convergence claim is justified.

CP-0852's 64 reconnect-window change remains un-deployed and therefore has not yet changed these live logs. Keep PR #208 Draft. Before any live canary, add a focused regression test for the verified-session callback across reconnect windows and qualify the exact CP-0852 binary in an isolated or safely recoverable environment. Then collect time-aligned network/profile, height, consensus tip, execution tip/state root, and fork-choice evidence from all services. Preserve existing volumes and anchor-vault state; do not roll all three services at once.
