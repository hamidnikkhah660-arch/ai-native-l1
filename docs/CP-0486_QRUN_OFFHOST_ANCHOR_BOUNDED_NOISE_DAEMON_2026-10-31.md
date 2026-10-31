# CP-0486 — QRun Off-host Anchor Bounded Noise Daemon Candidate

Date: 2026-10-31

## Scope

This change adds an explicit, opt-in TCP daemon wrapper around the existing one-request-per-connection
Noise XX Anchor handler. It is a candidate runtime boundary, not node startup integration or a
production deployment. Nothing binds a listener until a caller explicitly invokes
\`OffhostAnchorNoiseDaemon::bind\` and then \`run_until_shutdown\`.

## Bounded resource policy

- Exactly 1–64 worker threads are created per run.
- The in-memory socket queue is bounded to 1–4096 entries.
- The trusted Noise client allowlist must contain 1–256 unique, nonzero static public keys.
- When the queue is full, the newly accepted TCP socket is dropped and counted as overload-rejected;
  the daemon never creates a per-connection thread.
- Each accepted worker connection uses the existing handler's 20-second socket read/write deadlines.
- Shutdown is caller-controlled through an \`AtomicBool\`. No new queued work is started after the
  shutdown flag is observed; in-flight handlers finish within their I/O deadline, then workers join.
- The listener polls nonblocking accept at a 10 ms interval so shutdown is observed without a
  permanently blocked accept call.

## Key and identity handling

The Noise static private key is redacted from Debug and held by a shared wrapper that overwrites its
key bytes when the last worker/daemon reference is dropped. The Anchor and Provider pins must validate
as one domain, the server key must be nonzero, and trusted client keys must be distinct and nonzero.
The full Noise profile still binds Anchor ID, Provider ID, Network ID, Genesis digest and both
receipt-key identities through the existing transport handler.

## Explicit exclusions

This candidate does not create or configure an AWS DynamoDB table, make AWS API calls, provision or
qualify a KMS key, persist local state, open a public firewall rule, launch on node startup, or
change Genesis, Network ID, wallet allocation, mining, or public mint settings. The caller must inject
a correctly provisioned durable CAS store, independently pinned verifier and separately administered
Anchor signer. The existing memory model is suitable for local tests only.

## Validation

The module includes unit tests for worker/queue limits and Noise client allowlist validation.
Full crate tests, all-target check, rustfmt, and Windows P2P loopback CI must still pass on the PR
commit before this candidate can be accepted. A real AWS staging deployment, independent-host tests,
operational key rotation, rate limiting at the network edge, and external security review remain
separate qualification gates.
