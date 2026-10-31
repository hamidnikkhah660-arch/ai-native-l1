# CP-0486 — QRun Off-host Anchor Bounded Noise Daemon Candidate

Date: 2026-10-31

## Scope

This change adds an explicit, opt-in TCP daemon wrapper around the existing one-request-per-connection
Noise XX Anchor handler. It is a candidate runtime boundary, not node startup integration or a
production deployment. Nothing binds a listener until a caller explicitly invokes
\`OffhostAnchorNoiseDaemon::bind\`; no background workers start until \`run_until_shutdown\` or \`spawn\`.

## Bounded resource policy

- Exactly 1–64 worker threads are created per run.
- The in-memory socket queue is bounded to 1–4096 entries.
- The trusted Noise client allowlist must contain 1–256 unique, nonzero static public keys.
- When the queue is full, the newly accepted TCP socket is dropped and counted as overload-rejected;
  the daemon never creates a per-connection thread.
- Each accepted worker connection uses the existing handler's 20-second socket read/write deadlines.
- Shutdown is caller-controlled through an \`AtomicBool\`. No new queued work is started after the
  shutdown flag is observed; in-flight handlers finish within their I/O deadline, then workers join.
- \`OffhostAnchorNoiseDaemon::spawn\` starts the daemon on one named owner thread and returns a task
  handle with live stats, \`request_shutdown\`, \`is_finished\`, \`join\`, and \`shutdown_and_join\`.
- Dropping the task handle requests shutdown and joins the daemon thread, which in turn joins every
  worker. In-flight handlers may run until their 20-second I/O deadline. Drop cannot return a service
  error; callers that need error reporting use explicit join.
- A worker panic is caught at the worker boundary, signals fatal shutdown, discards queued sockets,
  joins remaining workers, and returns a daemon error promptly. No automatic restart is attempted.
- The listener polls nonblocking accept at a 10 ms interval so shutdown is observed without a
  permanently blocked accept call.

## Key and identity handling

The Noise static private key is redacted from Debug. The configuration zeroizes its key buffer
when dropped, including validation and bind failures. After binding, the key is moved out of the
configuration and held by a shared wrapper that uses `zeroize` when the last worker/daemon reference
is dropped. The Anchor and Provider pins must validate
as one domain, the server key must be nonzero, and trusted client keys must be distinct and nonzero.
Before the listener is bound, the daemon compares the complete Anchor and Provider pin values against
the exact pins held by the injected `ExternalCasOffhostAnchorMemoryModel`. Anchor ID, Provider ID,
Network ID, Genesis digest, both receipt key IDs, and both full ML-DSA public keys must match
byte-for-byte.
The full Noise profile still binds Anchor ID, Provider ID, Network ID, Genesis digest and both
receipt-key identities through the existing transport handler.
Worker threads use scoped lifetimes and observe the caller's shutdown flag directly before starting
another queued socket. This avoids a propagation race in which a worker could otherwise begin queued
work after shutdown was requested.
Runtime stats include the number of worker threads started and currently active in addition to
accepted, overload-rejected, completed, and failed counts. The active-worker counter is guarded by
RAII so normal exit and unwinding both release the count.

## Explicit exclusions

This candidate does not create or configure an AWS DynamoDB table, make AWS API calls, provision or
qualify a KMS key, persist local state, open a public firewall rule, launch on node startup, or
change Genesis, Network ID, wallet allocation, mining, or public mint settings. The caller must inject
a correctly provisioned durable CAS store, independently pinned verifier and separately administered
Anchor signer. The existing memory model is suitable for local tests only.

## Validation

The lifecycle test suite now exercises a real loopback daemon using independent ML-DSA Provider
and Anchor fixtures, authenticated Noise Read with signature-verified receipt, a provider-proof
CAS followed by a stale-state conflict, exact config/model pin mismatch rejection before listener
bind, unpinned client rejection, incorrect server-key pin rejection, handshake timeout followed by
worker reuse, bounded queue overload, worker-count ceilings, shutdown/join behavior, supervised
task shutdown and Drop/join behavior, active-worker accounting, private-key redaction in both config
and daemon Debug output, and injected worker panic propagation. The panic test also confirms prompt fail-closed
termination and explicit rebind on the released address using a newly built daemon configuration.

Each active connection is managed by an RAII guard. Normal success marks the request completed;
ordinary errors and unwinding both decrement the active-connection counter and record one failed
request. Worker panics are caught at the worker boundary, stop the accept loop, and are propagated
as a daemon error after all workers are joined. Service replacement is an explicit owner action; no
retry loop or implicit configuration reuse is present.

Secret cleanup uses the pinned direct `zeroize` dependency. Dropping an unbound configuration (or
any validation/bind failure) zeroizes its key buffer; successful bind transfers the key out of the
configuration and into a shared `SecretNoiseKey`, which zeroizes on its final drop.

Windows local validation for the lifecycle expansion (package `src/native/pow_bench`):
- `cargo test --lib --locked --offline`: 1,026 passed, 0 failed.
- Focused daemon suite: 13 passed, 0 failed.
- `cargo check --all-targets --locked --offline`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.

The all-target check reports existing unused/dead-code warnings in unrelated modules and binaries;
no warnings were emitted from the changed daemon, protocol-pin, or transport files. CI for the
resulting PR commit and both push and pull_request workflow events must still pass before this
candidate can be accepted. A real AWS staging deployment, independent-host tests, operational key
rotation, rate limiting at the network edge, and external security review remain separate
qualification gates.
