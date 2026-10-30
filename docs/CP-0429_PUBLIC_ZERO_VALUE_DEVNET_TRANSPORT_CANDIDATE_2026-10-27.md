# CP-0429 - Explicit Public Zero-Value Devnet Transport Candidate

**Date:** 2026-10-27
**Status:** Local Windows Release two-process integration passed; exact-commit CI runs this test. Mainnet and general public Devnet launch are not approved.

## Decision

Follow the useful part of Bitcoin's original release pattern: ship a runnable node and let independent operators connect, without pretending the existing monetary QZBE candidate is production-ready. The `devnet_node --public-devnet` flag now enables an external TCP bind only for the existing **zero-balance PTB2/PFS2 Devnet candidate**. All default/private-smoke operation remains loopback-only.

This does not expose the separate `--qzbe-v04-peer-smoke` runtime. That runtime remains isolated and loopback-only; it contains value-bearing candidate economics and is not canonical production Mainnet.

## Network boundary

- `--public-devnet` is explicit and may be supplied only once. It is accepted only by the normal `devnet_node` zero-value Devnet runtime, never the private-smoke profile.
- Without the flag, non-loopback listen addresses and peers are rejected. In the explicit zero-value mode, the P2P listener may bind an external interface (for example `0.0.0.0:49301`) and may accept remote socket addresses.
- The explicit mode requires a protected Noise static-key file plus at least one trusted peer key or signed peer-identity file. `--test-easy-pow` is separately opt-in and only valid together with `--public-devnet`; it creates a distinct QVDN profile ID with a max target and 8 MiB Argon2id for disposable integration tests. It cannot reuse a normal candidate manifest and is not suitable for any real network. Noise transport and the peer allowlist are still mandatory; the flag does **not** turn off authentication or trust unknown peer keys. Outbound `--peer` entries remain paired in order with their corresponding pin/identity.
- The status listener, if configured, remains loopback-only. Do not put management/status surfaces on a public interface.
- The gate rejects PMT3/PMT4/QZBE monetary candidate modes, the candidate transaction listener, test transactions and test seed/funding options. The existing PTB2/PFS2 Devnet transaction authenticator still rejects transactions; no faucet or transferable QZXB balance is created by this change.
- Peer bootstrap is static/out-of-band. There is no DHT, automatic peer discovery, public RPC, wallet API, explorer, or continuously operated production service in this change.

## Reproducible validation

Focused Rust tests cover: explicit external-bind mode, default-mode rejection, required Noise/trust configuration, rejection under private or monetary modes, test-funding rejection, loopback-only status API, and inbound remote-address policy. `simulations/cp0429_public_zero_value_devnet_transport.ps1` builds the Windows release binaries, provisions disposable protected Noise keys, binds one zero-value node to a wildcard interface, and checks a pinned peer's empty-block broadcast and canonical state-root/tip convergence. CI runs this script alongside the existing wallet/transaction-gossip regressions.

Local Windows Release result: `CP-0429 EXPLICIT_PUBLIC_ZERO_VALUE_BIND_READY_PASS`, `CP-0429 AUTHENTICATED_NOISE_BLOCK_BROADCAST_ACK_PASS`, and `CP-0429 ZERO_VALUE_EXTERNAL_BIND_STATE_ROOT_TIP_CONVERGENCE_PASS` were emitted on the original successful local attempt. The CI follow-up exposed two harness-only defects: use of an ordinary candidate target for a time-bounded smoke, and a CLI readiness/flag mismatch. The fix adds a distinct, explicit test-only zero-value PoW profile (separate profile ID and manifest), corrects the argument value and readiness assertions, and reruns the two-process test locally. All three CP-0429 success markers now emit and the run exits 0; exact-commit CI remains required before this checkpoint is green. The zero-value chain creates no QZXB balance and accepts no transactions.

Passing this harness demonstrates a **local two-process transport integration** only. It does not establish inbound reachability from the public Internet, three independently operated hosts, safe firewall/DoS posture, anti-rollback across hosts, or production availability.

## Operator invocation shape

Use a new, empty data directory and a fresh network ID for the intended test network. After separately provisioning Noise keys, an operator command has this shape:

```powershell
.\devnet_node.exe --public-devnet `
  --network-id <64-hex-network-id> `
  --data-dir <fresh-data-directory> `
  --listen 0.0.0.0:49301 `
  --peer <trusted-peer-host-or-ip:port> `
  --noise-static-private-key-dpapi-file <protected-noise-key-file> `
  --trusted-peer-key-hex <matching-64-hex-peer-public-key> `
  --run-seconds 3600
```

The matching remote operator must provision a separate key for the same network and configure the reverse static peer connection. Network ID, profile and Genesis must match exactly. The example is a bounded candidate run, not a production service recipe; the protected Windows DPAPI key file is user/machine-bound and is not a portable recovery backup.

## Release decision

**GO:** focused code tests and a repeatable local two-process transport test; prepare external-host testing with known operators and explicit trust artifacts.
**NO-GO:** call this Mainnet, invite anonymous peers to an unmonitored production endpoint, claim balances/trading/liquidity, or announce a production public Devnet. Public RPC/wallet/explorer, reliable discovery/bootstrap or published peer lists, independent operator testing, persistent operations/monitoring, external anti-rollback, canonical monetary runtime integration, and independent protocol/security review remain separate gates.
