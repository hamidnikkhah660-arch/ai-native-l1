# CP-0786 - Independent QFP6 Read API Comparison Tool

Date: 2026-11-19
Base: CP-0785 / 125e170088b52bbe612187ac07a85777da28e832
Branch: feat/q6ga-v3-mainnet-scope-20261119

## Result

Added a credential-free, GET-only Python comparator for two independently operated QFP6 read API endpoints:

- Tool: tools/qfp6_independent_read_api_compare.py
- Tests: tools/test_qfp6_independent_read_api_compare.py

The comparator is designed for a second operator to run from their own host after both nodes have a separately approved read endpoint. It does not start a node, open a port, change runtime configuration, sign authorization, use a wallet, or read protected keys.

## What it compares

For each endpoint it fetches /v1/status and /v1/supply, then optional:
- /v1/account/{64-hex-account-id}
- /v1/block/{height}
- /v1/transaction/{64-hex-transaction-id}

It validates and compares:
- network ID, consensus profile, canonical height, QFP6 consensus tip, global state root, consensus fingerprint and status API version;
- manifest generation syntax (not equality: it is local storage metadata, not a consensus commitment);
- CP-0651 supply values, owner Genesis allocation, maximum supply, zero subsidy, non-minted accounting-label budget and policy fingerprint;
- requested account balance/nonce and explicit lack of account inclusion proof;
- requested canonical block data, both QFB6 execution block ID and QFP6 consensus tip, contiguous operation indexes and native transfer fields;
- requested transaction receipt, canonical status, confirmation-depth arithmetic and retained-archive/mempool scope.

When a transaction receipt and its inclusion block are both selected, the tool cross-links TXID, execution block ID, consensus tip, state root, producer, sender, recipient, nonce, amount, fee and expiry. A matching response from two endpoints is not accepted if the receipt does not match the selected canonical block body.

## Endpoint and transport safeguards

- Remote endpoints must use HTTPS; Python's default TLS certificate validation remains enabled.
- Node A and Node B must use different URL hostnames, not just different ports on the same host.
- URL user information, path, query and fragment are rejected.
- All HTTP redirects are rejected; the tool does not forward account IDs or TXIDs to a redirect target.
- Each response is capped at 16 MiB; per-request timeout is constrained to 0.5-60 seconds.
- The tool sends GET only and does not accept usernames, passwords, bearer tokens, client private keys or node key material.
- Loopback mode requires the explicit --allow-loopback-test option and is marked as a disposable harness only. Loopback results are not independent-node evidence.
- Output report records operator_independence=NOT_VERIFIED_BY_API_COMPARISON. Hostname diversity alone is also insufficient: separate human administrators, provider/account control and network/failure domains must still be evidenced by the already-existing out-of-band operator receipts.

## Usage

Run on a separate operator's machine after the two approved read API URLs are made available:

    py -3 tools/qfp6_independent_read_api_compare.py --node-a https://seed.example --node-b https://joining.example --account-id ACCOUNT_ID_64_HEX --block-height CANONICAL_HEIGHT --txid TXID_64_HEX --output qfp6-read-api-comparison.json

Options --account-id, --block-height, and --txid are repeatable. Select the same public account ID, retained canonical block height and TXID on both endpoints. The output report includes only the compared public data and commitments; it does not include endpoint URLs or credentials.

Exit code 0 means the requested API data matched under these schema checks. It does not mean operator independence, account inclusion, irreversible finality, public-network readiness, or launch authorization has been proven.

## Validation performed

- Python syntax compilation: PASS.
- Comparator unit tests: 13 passed, 0 failed.
- CLI --help smoke test: PASS.
- Tests cover matching status/supply/account/block/receipt, root divergence, account proof overclaim, reorged receipt, confirmation-depth mismatch, nonzero subsidy, noncanonical block, same-host/different-port rejection, loopback rejection for independence mode, HTTPS/userinfo restrictions, real loopback GET transport, redirect rejection, and receipt-to-block field mismatch.

All tests use synthetic in-memory JSON fixtures. No actual second-node HTTP comparison was performed.

## Actual external comparison status on 2026-11-19

NOT RUN / BLOCKED ? no second independent API endpoint is presently available in this session.

Observed on the owner workstation:
- Desktop Commander inventory lists only heymed; no second Desktop Commander node is online.
- NetBird CLI is installed but reports management and signal disconnected; the displayed peer count does not establish a reachable independent operator.
- Unified candidate release/qfp6-candidate/artifacts/bootstrap-peers.json contains zero peers.
- No approved stable Seed/Joining endpoint pair is attached to the unified candidate package.
- The current read API listener has not been activated. The existing launcher policy only permits non-loopback read API binding in Mainnet mode with allow_public_read_api=true. No listener-policy bypass or Mainnet configuration change was made to force an early test.
- Existing PID 20244 remains active and was not stopped or changed.

The comparator therefore has local implementation/test evidence only. It has not yet produced a cross-node matching report. The project issue #72 records the owner's previous independent qualification work as not to be repeated; the remaining task is importing those already-approved operator/Seed receipts and binding the existing approved endpoints/Noise public fingerprints into the unified release configuration. This checkpoint does not ask to rerun Gate 2 or Gate 8.

## Boundaries preserved

- No node listener was started or opened.
- No bootstrap peer, public IP, hostname, Noise key or operator identity was invented or inserted.
- No Q6PN/Q6GA/Genesis/config artifact was changed.
- No owner signature or QZKW2 wallet was used.
- No Mainnet or zero-value Public Testnet launch is claimed.
- Gate 2 and Gate 8 were not re-tested or reclassified.
- No private key, seed phrase, DPAPI plaintext, cloud credential or wallet material was read.
- PID 20244 / TCP 30333 and its datastore remain untouched.

## Next action

When the already-approved second operator's endpoint and public Noise fingerprint are available through the existing out-of-band receipts, expose only the reviewed read surface via the authorized architecture and run this comparator from that operator's own machine. Keep the zero-value Testnet authorization boundary intact; do not turn on Mainnet-only public binding or create a new Q6GA signature merely to bypass the current endpoint policy.
