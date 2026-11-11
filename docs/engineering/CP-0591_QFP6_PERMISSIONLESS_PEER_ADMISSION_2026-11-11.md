# CP-0591 - Permissionless QFP6 peer-frame admission

## Implemented in this candidate

- Adds a Q6PB frame processor that consumes the authenticated session's `QRunV06PeerReplayGuard` before attempting admission.
- Routes the decoded native block envelope to `QRunV06PermissionlessNodeRuntime::submit_envelope`, reusing the durable fork store's full validation, execution, fork-choice, and manifest publication path.
- Encodes the existing fixed-width Q6PA response. `Accepted` is emitted only when the local durable store returns a commit; malformed frames remain ingress errors, replayed IDs and runtime/store failures return `Rejected`.
- Adds a listener callback adapter so the existing bounded Noise listener can call the permissionless path after its pinned-peer handshake. The anchored and QAP1 callbacks remain unchanged.
- Keeps quote-asset authorization out of the base path; this bridge is native-only until a separately authorized quote-asset extension is supplied.

## Security and semantics

- The listener still requires an authenticated Noise session and independently pinned remote static key. The replay guard is session-owned and must not be shared across peers.
- `Accepted` means local durable admission/commit only. It is not a claim of network-wide propagation, confirmation depth, finality, or external-anchor approval.
- This does not bypass Genesis/profile pin verification, consensus validation, signature checks, PoW checks, branch-local MTP, durable-store checks, or unresolved-QAP1 fail-closed behavior.

## Explicit limitations

This is a peer-frame adapter, not yet a complete permissionless node service. It does not add peer discovery, multi-peer orchestration, full-history network synchronization, Q6TI mempool integration, a miner lifecycle, public RPC/explorer, or public listener policy. The existing listener is still private/overlay/loopback-only and serial.

## Qualification

- Local full-suite run: 1,335 library tests and all binary/integration targets passed before the final isolated admission-mapping test helper was added.
- Final-tree focused peer-ingress tests passed (rejected/replayed request, malformed frame, and Accepted only with a durable commit); `cargo check --all-targets --locked --offline`, `cargo fmt --check`, and `git diff --check` passed.
- Exact-head GitHub Actions CI must pass before this candidate is treated as CI-qualified.
- PR remains Draft/unmerged; no Mainnet activation is authorized by this change.
