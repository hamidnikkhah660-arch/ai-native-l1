# CP-0487 - QRun Off-host Anchor Node Lifecycle Owner

Date: 2026-10-31

## Scope

This step adds an opt-in ownership seam between the QRun v0.5 `NodeState` lifetime and the
CP-0486 supervised off-host Anchor daemon task. The seam is deliberately disabled during ordinary
startup. It does not parse daemon configuration, provision keys, construct an Anchor signer or CAS
store, bind a listener, spawn a daemon, or automatically restart a failed service.

## Ownership contract

- `OffhostAnchorNodeServiceOwner::disabled()` creates an empty owner and starts no threads.
- `try_attach` accepts exactly one already spawned `OffhostAnchorNoiseDaemonTask`. If a task is
  already attached, the new task is returned intact to its caller; it is not silently dropped or
  substituted.
- Live stats and a cooperative shutdown request are available while the task is attached.
- `shutdown_and_join` consumes the owned task, returns its final stats or service error, and is
  idempotent after the first call.
- Dropping the owner requests shutdown and joins the daemon. The node's `NodeState::drop` explicitly
  joins the optional service before zeroizing the node's outgoing Noise private key.
- In-flight Anchor handlers may run up to the existing 20-second socket I/O deadline. Drop cannot
  report an error; callers that need the final service result must call `shutdown_and_join` first.
- There is no retry policy, hidden fallback, or automatic re-use of an old configuration after
  service failure.

## QRun node integration

`qrun_v05_pow_local_node::NodeState` now owns an `OffhostAnchorNodeServiceOwner`. Production startup
constructs it with `disabled()` and never calls the provisioner hook. A private future
provisioner hook can accept an already built task after its configuration and trust domain have been
independently validated. The regular Provider External-CAS client configuration is not an Anchor
daemon configuration and is not re-used as one.

The current QRun node event loop has no explicit process signal handler. This step therefore does
not claim that Ctrl-C or forced process termination runs Rust destructors. The owner guarantees
shutdown/join when `NodeState` is dropped through normal Rust control flow or an explicit lifecycle
call; adding a portable process signal/cancellation path is a separate step. An OS-level forced kill
cannot be made graceful by a Drop implementation.

## Validation

The lifecycle tests cover the disabled default, idempotent empty shutdown, attaching a real loopback
daemon task, live worker stats, explicit shutdown request/join, owner Drop/join, duplicate-attach
rejection that returns the second task intact, and the QRun node's disabled startup state. Existing CP-0486 tests continue to cover Noise authentication, ML-DSA receipts,
Provider-proof CAS, exact pin comparison, overload bounds, worker panic fail-closed behavior and
explicit fresh-daemon recovery.

## Exclusions

No listener address, Network ID, Genesis, wallet, supply, consensus, PoW, public mint, firewall,
public port, or ordinary node startup behavior is changed. No AWS DynamoDB table, KMS key, remote
Anchor host, or independent operator trust domain is provisioned or qualified. This remains a
candidate-only integration seam and is not production, Mainnet, or public-mint approval.
