# CP-0489 - QRun Signal Subprocess Lifecycle Verification

Date: 2026-10-31

## Purpose

CP-0488 introduced cooperative SIGINT/SIGTERM and Windows console Ctrl+C/Ctrl+Break handling.
This step verifies that the operating system can deliver a real signal to a child process and
that both the actual QRun node executable and the separately supervised Anchor owner follow their
expected cleanup paths. The tests use subprocesses so process-wide handlers and signal state cannot
contaminate the parent Rust test runner.

## Real QRun node executable test

`tests/qrun_node_shutdown_signal_subprocess_candidate.rs` launches the actual
`qrun_v05_pow_local_node` executable using a throwaway deterministic test identity and an isolated
temporary data directory. It reserves three distinct ephemeral TCP ports and passes only
`127.0.0.1` RPC, transaction and block listeners. No existing wallet, chain store, provider
configuration, remote peer or fixed/public endpoint is used.

The parent waits for the node's `qrun_pow_local_block_ready` marker. That marker is emitted after
startup has reached the listener-ready point and the process signal handlers have been installed.
Only then does the parent send the operating-system control:

- Unix: separate SIGINT and SIGTERM child-process runs.
- Windows: targeted CTRL_BREAK_EVENT to a child started with CREATE_NEW_PROCESS_GROUP.

Each case must exit normally with status code 0, report that the signal was observed, and print
`qrun_node_lifecycle_cleanup_complete`. The cleanup marker is emitted only after NodeState cleanup,
the explicit service-owner shutdown path, and successful restoration of the prior process handler.

## Supervised Anchor owner subprocess test

A second isolated library-test subprocess binds a real candidate off-host Anchor daemon to an
ephemeral loopback port, starts two worker threads, and attaches the task to
`OffhostAnchorNodeServiceOwner`. The parent sends SIGTERM on Unix or CTRL_BREAK_EVENT on Windows.
The child waits for the atomic signal request, calls `shutdown_and_join`, and asserts:

- both worker threads were started and zero remain active;
- the service owner is detached after the join;
- the daemon's shared worker counter is zero;
- signal-handler restoration succeeds before the child reports success and exits zero.

This checks process isolation, real OS delivery, service-owner shutdown and thread joining without
creating a production Anchor provisioning/configuration path.

## What this does and does not establish

The real QRun node subprocess test starts with the normal default-disabled Anchor owner. The
separate owner subprocess test verifies the owner abstraction when an already provisioned test
daemon is attached. There is still no production provisioner or regular-startup configuration that
attaches an Anchor daemon to NodeState; therefore these tests do not claim that normal node startup
starts Anchor or that a production Anchor host is deployed.

Signals delivered before startup sync and successful listener binding remain outside the installed
event-loop handler window. Windows CTRL_CLOSE/LOGOFF/SHUTDOWN, Unix signals other than SIGINT and
SIGTERM, forced termination, power loss and process crashes are not graceful. The tests do not
provide a hard upper bound for an in-flight listener operation.

## Validation

The focused Windows validation runs both subprocess tests:
- the real QRun node executable starts on loopback, receives CTRL_BREAK_EVENT, prints its cleanup
  marker and exits zero;
- the supervised Anchor owner subprocess receives CTRL_BREAK_EVENT, joins its two workers, restores
  the handler, and exits zero.

The integration test is part of Cargo's all-target test graph so Unix CI can additionally exercise
SIGINT and SIGTERM separately. Full library/binary/all-target tests, formatting, all-target check
and diff checks are run for this step. Both Push and Pull Request CI for the pushed commit must pass
before this candidate is called CI-complete.

## Exclusions

No Network ID, Genesis, wallet identity, QZXB supply, consensus, PoW, issuance, public mint,
firewall, listener address policy or public port is changed. The process tests create only
temporary local test data and ephemeral loopback listeners. No AWS KMS/DynamoDB resources, remote
Anchor endpoint, independent operator trust domain, production/Mainnet activation or security
audit is created or implied.
