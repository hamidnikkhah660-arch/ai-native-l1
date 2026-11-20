# CP-0790 - QFP6 Unified Merge and Live Operational Status
Date: 2026-11-20
Status: source integration merged and fully CI-validated; public multi-node launch not qualified.

## 1. Canonical source state

- Repository: hamidnikkhah660-arch/ai-native-l1
- Canonical local worktree: D:\Temp\ASUS\QRUN_QFP6_UNIFIED_20261118
- Branch: feat/q6ga-v3-mainnet-scope-20261119
- Unified HEAD and origin branch HEAD: 0b522b045f14a3de1bd8c041a025eabc1ddb8dde
- Merge commit: 0b522b045f14a3de1bd8c041a025eabc1ddb8dde
- PR: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/200
- PR #200 merged at 2026-11-20T07:14:10Z. The owner explicitly authorized proceeding without independent PR review.
- CP-0788 commit: 596676ead6ac58b733a6ba44505d7980f8d9a845
- CP-0789 commit: 9898855c0bc7004231419cb94e1b483f90f2bbb9
- The merge contains two commits ahead of the CP-0787 base, four source files changed. Local Unified checkout was fast-forwarded to the merge commit and was clean at verification. git diff --check passed.

## 2. Code changes integrated

CP-0788:
- Hardened StoreWriterLock on Unix and Windows.
- Unix open flags include O_NOFOLLOW, O_CLOEXEC and O_NONBLOCK, with regular-file and single-link validation.
- Windows reparse-point and hard-link validation is included.
- File metadata is checked before and after open.
- OS-backed lock ownership is authoritative; diagnostic lock-file bytes are no longer rewritten or truncated.
- Windows OVERLAPPED remains stack-local to preserve Send behavior.

CP-0789:
- Corrected CP-0604 runtime test fixtures to use QFP6 SHA-256d consensus with the historical 10B mining schedule.
- CP-0651-specific fixtures retain the fixed-supply, zero-subsidy Genesis and matching fee-only consensus profile.
- No consensus/economic guard was weakened and no active economic policy was changed.

Known residual security work:
- Parent-directory component replacement and broader directory TOCTOU protection are still separate follow-up work. This merge does not claim to close that race class.

## 3. Hosted validation

Pre-merge CI: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/44691178957
Post-merge CI: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/44693600570

The post-merge run on the actual Unified merge commit completed successfully across all three jobs:
- Rust validation: 2,001 passed, 0 failed, 2 ignored across 110 test binaries. Formatting, all-target compilation, independent Genesis/issuance/PoW/MTP oracle checks and Test every target passed.
- Windows PMT4/TXN4/PFM4: SUCCESS. DPAPI and QZKW2/Q6HA wallet/signing tests, invalid-signature rejection, valid signed submit, two-node consensus/replay, paged PFM4 sync, stale-cursor rejection and reorg replay passed.
- EVM contract, wallet console and dependency audit: SUCCESS. Compile and local tests passed; npm audit reported zero known vulnerabilities.

## 4. Release build from the merged Unified source

Built locally on Windows from HEAD 0b522b045f14a3de1bd8c041a025eabc1ddb8dde:

cargo build --manifest-path src/native/pow_bench/Cargo.toml --release --locked --offline --bin qrun_v06_node --bin qzxb_wallet

Both release executables were produced and --help smoke checks returned exit 0.

- qrun_v06_node.exe SHA-256: 121C5468746F0EDA81EB9AF3156FE64185E7AB2C5F18C40CAFF76452FBE69EA1
- qzxb_wallet.exe SHA-256: 85FC5FBDF88E849298876A73D0F72136D3687979EE22D68BB83281EFB9701366

The binaries were built but not deployed over the running Seed process.

## 5. Release artifact equivalence and signature preflight

The six consensus-critical files in the prior live Seed package and release/qfp6-candidate/artifacts/ match byte-for-byte by SHA-256:
- bootstrap-peers.json: 37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570
- consensus-profile.q6cp: 0ff4786c2b62228883699c687b34d57a85f3bcddde9a545c95f5515a388c516f
- genesis-descriptor.q6gd: e5bbd024511f907d1e9bf3c1d4004d05851cd96c79eebd0f1ce446aee15a1888
- genesis-snapshot.q6sn: 6961e7517adcb66c04a3c566ec8c5cba398940eb273eabd082b706bb32a4f757
- public-testnet-authorization.q6ga: 72d58ef455d9b6f6ab9a5514f5f0fb40f333d347af288363b3897b5584c2f169
- q6pn-profile.q6pn: bb3d1e5710827afd8248292f9c19ab250dcdc8e508711597dd049c77a6ec8233

Package tooling:
- python tools/qfp6_candidate_package.py self-test: PASS, exit 0.
- python tools/qfp6_candidate_package.py validate release/qfp6-candidate: INCOMPLETE, exit 2. This is the expected fail-closed result while topology/peer readiness fields are not qualified.
- The package has the five required component artifacts and matching hashes. Its bootstrap peer file is empty ([]).

A disposable negative-topology preflight was run with the new Unified binary using the exact existing public-testnet artifacts and a temporary copy of the runtime config. The only changed field was listen_address=127.0.0.1:30334, deliberately invalid for public-testnet mode. The binary:
- verified Q6GA with Ed25519 and ML-DSA-65;
- reported scope ZERO_VALUE_PUBLIC_TESTNET_ONLY;
- reported mainnet_authorization=NOT_GRANTED and market_authorization=NOT_GRANTED;
- correctly refused the loopback public listener;
- did not start a node, open a listener, or modify the live data store;
- removed the temporary config after the test.

This proves the Q6GA v2 and artifact bindings against the new binary, but is not a full runtime/data migration test.

## 6. Live Seed and external reachability

The pre-existing live process was intentionally preserved:
- PID 20244
- Executable remains the CP-0596 binary under QRUN_QFP6_CP0596_20261111
- It listens locally on 0.0.0.0:30333
- Its runtime mode is public-testnet-zero-value-candidate
- Its active config has an empty bootstrap peer set, enable_approved_peer_outbound_sync=false and enable_q6ar_candidate_address_book=false.
- The active inbound acknowledgement is ANONYMOUS_NOISE_XX_UNAUTHENTICATED. The joining client must pin the Seed's Noise identity out-of-band; this is not authenticated inbound peer identity.

External reachability probes on the current egress IPv4 did not establish public reachability:
- portchecker.io returned status=false for TCP 30333.
- MTRXTools returned filtered / no reply (timeout) for TCP 30333.
- Kordu Probe rejected the target as invalid_target at its Cloudflare vantage; this is not a reachability result.
- The IPv6 Port.Tools external tester was run against 2a02:4540:ab:f8a9:2de6:2473:2516:224:30333 and returned failed / Resource temporarily unavailable at 2026-11-20 07:45:51 UTC. MTRXTools could not route its own vantage to that IPv6 (EADDRNOTAVAIL). A separate TCPData result labeled open with HTTP 403 is not accepted as proof of a live QRun listener.

Windows Firewall has an inbound Allow rule for TCP 30333, but the external probes show that local firewall configuration alone is insufficient. The cause may be upstream NAT/ISP/VPN routing or mismatch between egress and inbound address; it is not yet isolated. No router, firewall, VPN, or ISP setting was changed in this checkpoint.

Historical local evidence records a Noise XX handshake and Q6HI/Q6HR status exchange with the prior Seed, but no independently operated Internet node has been shown to complete a block-history transfer from this current release package. Prior status-only/loopback results are not counted as multi-node network readiness.

## 7. Authorization and launch boundary

- Existing Q6GA v2 scope is ZERO_VALUE_PUBLIC_TESTNET_ONLY.
- It does not authorize Mainnet, value-bearing transfers, public mining rewards, market activity or liquidity operations.
- Mainnet-native mode requires a separate Q6GA v3 authorization bound to a non-empty independently pinned bootstrap peer set and authenticated/pinned Noise static-key admission.
- Gate 2 and Gate 8 remain owner-reported complete from prior work. They were not retested or reclassified in this checkpoint.
- The live Seed was not restarted, replaced, upgraded, or reconfigured. No private key, wallet seed, DPAPI plaintext or signing secret was read.
- No cloud/VPS purchase or paid infrastructure commitment was made.

## 8. Remaining operational work (not a request to repeat prior gates)

1. Establish a stable, globally reachable inbound Seed endpoint on a host/network that actually accepts outside TCP connections. Current laptop egress IP is not yet a qualified public endpoint.
2. Reconcile the already-qualified independent operator records and Noise pins with the current release package; do not repeat Gate 2 or Gate 8.
3. Generate the separate Joining-node configuration using the actual public Seed endpoint, its out-of-band verified Noise fingerprint and a distinct protected Joining identity.
4. Start a second, independently operated node with separate data and anchor-vault paths; verify Noise pinning, actual block-page transfer, height/state-root agreement, restart recovery and a two-process reorg scenario.
5. Only after that, plan a controlled upgrade of PID 20244 to the CP-0790 release binary with a verified rollback and store backup. Do not run two writers against the same data or reuse one Noise identity concurrently.
6. Keep Mainnet disabled until the exact Q6GA v3 owner authorization and pinned authenticated peer topology are available. Market authorization remains separate.

CP-0790 closes the CP-0788/CP-0789 source-integration work in CP-0787 Unified. It does not claim the complete QZXB ecosystem is a live public multi-operator network or that Mainnet is operational.