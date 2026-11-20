# CP-0656 — IPv6 Hotspot Ingress Qualification and Release-Gate Reconciliation

Date: 2026-11-14
Project: AI-NATIVE L1 / QZXB / QFP6
Branch: `feat/cp0600-bootstrap-sync-startup`
Observed HEAD: `df673d07050688a64b26822d97e6ea609b68ce88`
Depends on: CP-0652 through CP-0655
Status: **local targeted checks passed; direct public IPv6 ingress from the current mobile-hotspot path NOT QUALIFIED; Public Testnet remains NO-GO**

## 1. Worktree and source-of-truth reconciliation

- The current candidate worktree is `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`.
- The older `C:\Users\ASUS\Desktop\AI_NATIVE_L1` worktree and the candidate worktree share the same Git common directory and the same origin repository. They are separate Git worktrees, not a filesystem junction.
- The candidate worktree is on `feat/cp0600-bootstrap-sync-startup`, based at `df673d07050688a64b26822d97e6ea609b68ce88`.
- The pre-existing candidate working-tree changes were preserved: 15 tracked files modified and 27 untracked files at the post-test inspection. No reset, checkout, commit, push, merge or tag was performed.
- No QRun/QFP6 node process was left running.

## 2. Local IPv6 egress and host-firewall observations

Observed on the Windows development workstation `heymed` while connected through the Xiaomi phone hotspot:

- Wi-Fi had a preferred global IPv6 address in prefix `2a02:4540:ac:6723::/64`.
- `curl -6 https://api6.ipify.org` succeeded and returned the same global IPv6 address assigned locally to the Wi-Fi interface.
- TCP connectivity to an external IPv6 destination on port 443 succeeded.
- Windows Firewall was enabled for Domain, Private and Public profiles.
- The effective inbound default action was Block for all three profiles.
- The current Desktop Commander session was not elevated; the bounded one-time test therefore used a Windows UAC elevation prompt for its temporary rule.
- The laptop VPN and phone hotspot were left in their pre-test states. No router configuration or persistent Windows firewall setting was changed.

These observations establish outbound IPv6 reachability. They do not establish unsolicited inbound reachability.

## 3. Bounded inbound test

A one-time test was executed with the following safeguards:

- A high TCP port was selected at random: `58744`.
- A temporary listener bound only to the current Wi-Fi global IPv6 privacy address.
- The temporary inbound firewall allow rule was restricted to TCP port `58744`, the exact current local IPv6 address, the Wi-Fi interface, the Public profile and the PowerShell program used by the test.
- The test window was limited to 60 seconds.
- The application listener did not accept any inbound connection before the deadline.

Independent external checks:

1. Pingie external TCP/IPv6 checker: `CLOSED`, 4004 ms, targeting the same public IPv6 address and port `58744`.
2. A first checker returned `open` with HTTP 403, but the local listener recorded no accepted connection. That inconsistent result is not treated as positive reachability evidence.

Conclusion: the current mobile-hotspot path did not demonstrate externally reachable inbound TCP/IPv6 during this test. This does not isolate the cause to the mobile carrier: the phone hotspot, its IPv6 firewall/routing, the mobile operator, or another upstream network policy may be responsible. Direct hosting from this laptop on this connection is therefore **not qualified**.

## 4. Cleanup verification

After the 60-second test window:

- Temporary firewall rules matching `AI_NATIVE_L1_TEMP_IPV6_*`: 0.
- Listener on test port `58744`: 0.
- Temporary probe script/log files: 0.
- No production listener was opened.
- Port `30333` was not opened.
- No router/port-forward rule was added.
- No QRun/QFP6 node was launched.

The host was returned to the pre-test network/firewall state.

## 5. Candidate-code verification on the current worktree

The following current-worktree checks completed successfully:

| Check | Result |
|---|---:|
| `cargo test --bin qrun_v06_node --locked --offline` | 36 passed, 0 failed |
| `cargo test --lib bounded_handshake_worker --locked --offline` | 2 passed, 0 failed |
| `cargo test --lib application_session_has_absolute_lifetime_and_per_record_read_budget --locked --offline` | 1 passed, 0 failed |
| `cargo test --lib qfp6_listener_ --locked --offline` | 9 passed, 0 failed |
| `cargo check --bins --locked --offline` | PASS |
| `cargo fmt -- --check` | PASS |
| `git diff --check` | PASS |

A separate full-library run enumerated 1,441 tests and ran for approximately 564 seconds. It was intentionally terminated during `qra1_copies_every_manifest_branch_and_is_idempotently_verifiable` to avoid continued unbounded resource use. The harness exited abnormally because of that external termination. This full-library run is **INCOMPLETE**, not a full-suite pass and not an assertion failure report. Tests preceding the termination had not reported assertion failures in the captured output.

The targeted release-path checks above remain independent, completed results.

## 6. Public Testnet / Mainnet decision

The CP-0651 economic candidate remains:

- 7,000,000,000 QZXB maximum accounting ceiling.
- 1,000,000,000 QZXB owner Genesis allocation.
- Six non-circulating accounting labels with 1B QZXB ceilings each.
- Zero block subsidy; fee-only producer compensation.

The candidate release manifest remains deliberately unauthorized. The following are still missing or pending:

- Final CP-0651 Genesis snapshot and Q6GD descriptor.
- Exact Q6CP consensus-profile artifact.
- Exact Q6PN network-profile artifact.
- Bootstrap peer set with locally generated protected Noise keys and independently checked public-key fingerprints.
- Two independently administered seed hosts in separate trust domains, plus an external joining node.
- Owner confirmation that the public account already bound in the manifest is the intended Genesis recipient, followed by a signature of the frozen Genesis digest using the protected owner signer.
- Explicit owner acknowledgement of the current zero-value candidate inbound transport limitation: anonymous Noise XX over classical X25519 does not authenticate the real-world peer operator and is not post-quantum transport.
- Independent consensus, cryptography and economics review.
- External multi-host sync, divergence rejection, restart/replay, peer-loss and public-listener load qualification.

The current device inventory still contains only the user's workstation. Do not fabricate endpoints, keys, fingerprints, signatures, Genesis bytes, independent operators or review evidence.

**Decision:** the candidate code has passed the targeted local checks listed above, but direct IPv6 ingress through this hotspot is not qualified and the independent-host/signing/review prerequisites remain outstanding. Public Testnet remains **NO-GO / NOT LAUNCHED**. Mainnet and value-bearing deployment remain **NOT AUTHORIZED**.

## 7. Next engineering/operations gate

1. Provision two separately administered seed hosts and connect them as separate Desktop Commander devices. Prefer distinct providers/ASNs, not two VMs under one administrator.
2. Inspect both hosts, generate each Noise key locally, and export only public endpoints and fingerprints.
3. Prepare and hash-pin the actual Q6GD/Q6CP/Q6PN/CP-0651 Genesis package; have the owner verify the bound public account and sign the exact frozen digest through the protected signer.
4. Record the explicit zero-value Noise XX risk acknowledgement, or keep public inbound blocked until authenticated peer identity is designed and qualified.
5. Run preflight and independent full-history agreement on the separate hosts before any public listener is enabled.
6. Only then evaluate a separately authorized zero-value Public Testnet launch. Mainnet remains a later, separately reviewed decision.

---
