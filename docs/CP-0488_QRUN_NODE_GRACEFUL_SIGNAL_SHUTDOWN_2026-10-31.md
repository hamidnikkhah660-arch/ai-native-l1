# CP-0488 - QRun Node Graceful Process-Signal Shutdown

Date: 2026-10-31

## Scope

This step adds a narrow process-signal bridge for the QRun v0.5 local-node event loop. The OS
callback only records a shutdown request in an atomic flag. It does not acquire locks, perform
network I/O, join threads, invoke the Anchor daemon, or mutate chain state.

No new crate dependency is introduced. Unix uses the existing direct `libc` dependency; Windows
uses the operating system `SetConsoleCtrlHandler` API.

## Platform behavior

- Unix installs handlers for SIGINT and SIGTERM and restores the exact prior `sigaction` values
  when the registration is explicitly removed or dropped.
- Windows installs a console handler for Ctrl+C and Ctrl+Break. Other console control events,
  including close/logoff/shutdown, are not claimed as graceful because the operating system may
  terminate the process after a short callback deadline.
- Only one registration may be active per process. A duplicate install fails with
  `AlreadyExists`; a failed platform registration rolls back the process-wide guard.
- The callback performs one atomic flag update. All shutdown work stays on the node thread.

## Node lifecycle integration

Signal handling becomes active only after optional authenticated startup sync has completed and all
three RPC, transaction and block listeners have successfully bound and entered nonblocking mode.
The running event loop checks the request flag on every pass; when idle it already wakes every
5 milliseconds. An in-flight request is allowed to return through its existing socket handling
path and configured I/O timeouts; this is cooperative shutdown, not forced cancellation of an
active request.

After the loop observes the signal, or a listener error causes the loop to stop, the node:

1. Explicitly calls `NodeState::shutdown_offhost_anchor_service` on the node thread so an attached
   optional daemon is asked to stop and joined, with errors surfaced to the caller.
2. Drops `NodeState`, which retains its idempotent Drop cleanup and zeroization of the node-local
   outgoing Noise private-key buffer.
3. Restores the prior process signal/console handler and releases the registration.
4. Reports lifecycle cleanup completion. A signal-driven stop returns through normal Rust control
   flow rather than using `process::exit`.

The optional off-host Anchor owner is still constructed disabled during ordinary node startup.
This signal path does not parse an Anchor configuration, provision keys, bind or spawn an Anchor
daemon, restart a failed daemon, or repurpose the regular External-CAS client configuration.

## Boundaries and limitations

- Signals received before startup sync has completed and listeners have bound are not covered by
  this event-loop registration.
- Windows console close, logoff and shutdown events are not intercepted. Unix signals other than
  SIGINT/SIGTERM are not intercepted.
- An OS-level forced kill, power loss, process crash, or abrupt termination cannot run Rust Drop
  and is not made graceful by this work.
- A signal may wait for the currently executing listener handler to return through its existing
  socket I/O path. This implementation does not claim a hard global shutdown-time bound.
- There is no automatic restart, background supervisor, or production deployment integration.

## Validation

The focused signal-registration test verifies exclusive process-wide registration, the platform
callback-to-atomic-flag path, cleanup/restoration, and that a fresh registration starts clear. The
QRun node test continues to verify the off-host Anchor daemon remains disabled by default. Full
crate and all-target tests, formatting, and diff checks are run for this change; remote CI must pass
before this candidate step is treated as complete.

## Exclusions

No Network ID, Genesis, wallet, QZXB supply, consensus, PoW, public mint, firewall, listener address,
or public port changes. No AWS KMS/DynamoDB resource, remote Anchor host, independent operator trust
domain, or production/Mainnet activation is created or qualified.
