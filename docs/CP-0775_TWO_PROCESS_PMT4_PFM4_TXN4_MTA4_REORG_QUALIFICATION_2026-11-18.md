# CP-0775 — Two-Process PMT4/PFM4 Reorg, TXN4 and MTA4 Qualification

**Date:** 2026-11-18  
**Project:** AI_NATIVE_L1 / QRun / QZXB  
**Branch:** `feat/cp0704-dual-attestation-rotation-gate-20261116`  
**Worktree:** `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
**Observed HEAD:** `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Disposition

**TWO INDEPENDENT OS PROCESSES / PMT4-PFM4 PAGE-2 REORG AND STALE-CURSOR REJECTION PASS / SIGNED TXN4 SUBMISSION PASS / MTA4 ACK PASS / BOTH NODES REOPEN AND REPLAY PASS / LOOPBACK DIAGNOSTIC ONLY / GATE 2 OPEN / GATE 8 OPEN**

CP-0775 reruns two existing Windows end-to-end scripts against the current release build. The tests use two distinct `devnet_node.exe` processes, separate data directories, separate temporary DPAPI-protected Noise identities, ephemeral loopback TCP listeners, and disposable local monetary state. No new consensus feature, production key, public listener, AWS service, wallet, or value transfer is introduced.

## 1. CP-0362 — PFM4 two-process archive sync and page-2 reorg

**Script:** `simulations/cp0362_pfm4_page2_cursor_reorg.ps1`  
**Result:** PASS; script process exit code 0; runtime 272.48 seconds.

### Topology and actions

- A deterministic baseline PFM4 archive was seeded to height 3 in a disposable data directory.
- A source node B and a cursor client C were launched as separate operating-system processes with separate data directories and separate temporary NPK1/DPAPI Noise keys.
- Both processes used the same diagnostic Network ID and PMT4 manifest commitment, but distinct Noise identities and reciprocal static-key pins.
- The authenticated archive range was constrained to one item per page.
- B served page 1 and page 2. After the second page was sent, B imported a longer competing branch and reorged its canonical PFM4 state from the seeded branch to height 4.
- The client's continuation request using the old immutable snapshot cursor was rejected because the source manifest anchor had changed. The client did not import a page 3/height 3 or page 4 item from the stale startup snapshot.
- Both processes stopped and independently reopened/replayed their own PFM4 stores.

### Observed results

| Assertion | Result |
|---|---|
| Source B ready at height 3 | PASS |
| Client C ready at height 0 | PASS |
| Authenticated page 1 sent | PASS |
| Authenticated page 2 sent | PASS |
| Source reorg after page 2 | PASS; canonical height 4 |
| Stale continuation/page 3 rejected | PASS |
| Client remains at accepted prefix | PASS; canonical height 2 |
| Source reopen/replay | PASS; height 4, `replay=matched` |
| Client reopen/replay | PASS; height 2, `replay=matched` |

Key source-side log evidence:

- `event=devnet_archive_range_page_served ... page=1 ... items=1`
- `event=devnet_archive_range_page_served ... page=2 ... items=1`
- `event=test_fault_reorg_after_pfm4_archive_page ... canonical_height=4 trigger_page=2`
- `event=monetary_v4_archive_range_request_rejected ... reason=stale_snapshot manifest_anchor_changed=true`
- `event=monetary_v4_peer_smoke_stopped height=4 ... replay=matched`

Key client-side log evidence:

- `event=monetary_v4_archive_range_item_imported ... status=ACCEPTED height=1`
- `event=monetary_v4_archive_range_item_imported ... status=ACCEPTED height=2`
- `event=monetary_v4_archive_range_sync_failed ... Noise transport ... peer_closed`
- `event=monetary_v4_peer_smoke_stopped height=2 ... replay=matched`

Saved test artifacts and logs:

`D:\Temp\ASUS\ain1_cp0362_pfm4_page2_cursor_reorg_740f96ce6fad416393a53a54c06e828a`

## 2. CP-0363 / CP-0364 — PMT4/TXN4 submission, peer import and MTA4

**Script:** `simulations/cp0363_txn4_two_node_loopback.ps1`  
**Result:** PASS; script process exit code 0; runtime 75.95 seconds.

### Topology and actions

- Two separate `devnet_node.exe` processes (A and B) were launched with separate PFM4 data directories, protected Noise static keys and reciprocal peer-key pins.
- A disposable TXN4 fixture supplied an explicit hybrid founder identity and signed native transfer.
- Node A exposed its loopback-only TXN4 submission HTTP endpoint; Node B exposed the PMT4 Noise peer listener.
- An altered TXN4 signature was submitted first and rejected with HTTP 422. The valid TXN4 was then submitted and accepted with HTTP 202. The response reported one pending mempool entry and the expected TXID.
- Node A selected the pending transaction, built and admitted a PMT4 block at height 1, broadcast it to B over authenticated Noise, and validated the returned MTA4 acknowledgement.
- Node B accepted the PMT4 candidate and emitted `MTA4 status=0` bound to the submitted candidate height/digest, with the canonical state root and tip.
- The script compared Node A's broadcast state root/tip with Node B's status API.
- Both processes stopped and independently reopened/replayed PFM4.

### Observed results

| Assertion | Result |
|---|---|
| Invalid TXN4 signature rejected | PASS; HTTP 422 |
| Valid TXN4 submission | PASS; HTTP 202 |
| Pending count after valid submission | PASS; exactly 1 |
| Expected TXID preserved | PASS |
| A mines/broadcasts PMT4 height 1 with 1 transaction | PASS |
| B returns MTA4 status 0 for same candidate | PASS |
| A/B canonical state root identical | PASS |
| A/B consensus tip identical | PASS |
| Node A reopen/replay | PASS; height 1 |
| Node B reopen/replay | PASS; height 1 |

Observed TXID:

`de0d73705619547221851911fbfd1d27a5534f1e51f6f53d49763ef637978602`

Observed height-1 state root:

`0ece7ddd9ea50559330ce18f38018620528f95365749b1a687a923f40df70266`

Observed consensus tip / PMT4 block digest:

`be2b71b8218028fa0078f2ba25c70903d202b315fa7f880775f18ae1a8062d27`

Key Node A log evidence:

- `event=txn4_submission_accepted txid=... mempool_count=1`
- `event=monetary_v4_peer_broadcast_complete height=1 ... peers=1 transactions=1`
- `event=monetary_v4_peer_smoke_stopped height=1 ... replay=matched`

Key Node B log evidence:

- `event=monetary_v4_peer_ack_sent ... ack=MTA4 status=0 candidate_height=1 candidate_digest=...`
- `event=monetary_v4_peer_smoke_stopped height=1 ... replay=matched`

Saved test artifacts and logs:

`D:\Temp\ASUS\ain1_cp0363_txn4_two_node_62e5e53a5c9e491ea116f4118ffed92d`

## 3. Exact scope and limitations

Both scripts ran on the same Windows workstation but used separate operating-system processes, independent local directories and distinct temporary Noise identities. This is stronger than an in-process thread-only test and establishes actual two-process protocol exchange and restart/replay for the current diagnostic candidate.

It remains **loopback-only diagnostic evidence**, not a public multi-operator network qualification:

- The runtime itself prints `profile_scope=loopback_diagnostic` and `public_launch_approved=false`.
- The PMT4 peer validator rejects every non-loopback listen/peer/status/transaction address.
- Both nodes use the deliberately trivial `LOCAL_EASY_POW_8MIB` profile (`initial_target = Uint256::MAX`, Argon2 memory 8 MiB). This does not qualify production mining difficulty, fairness, throughput or Sybil resistance.
- The test Genesis log reports `genesis_profile=LOCAL_RESEARCH_40_30_30` and `genesis_value_atoms=700000000000000000`. This disposable test profile is not the approved 10B CP-0566D economic design and must not be treated as production tokenomics or a frozen Genesis.
- PFM4 reopen/replay here uses a local manifest anchor (`anchor=local_only`). It does not exercise the QAR2/QBT1/Q6TS independently administered AWS anchor from CP-0774.
- Reorg in CP-0362 is a deterministic test fault injected after the second page; it does not qualify arbitrary-depth fork-choice/reorg under production PoW.
- The tests do not reach the default 2,016-block retarget boundary (next height 2,017), the 4,204,800-block halving boundary, or the PFM4 1,024 logical-height ceiling. The bounded checkpoint/PCP4/PFM5 durability and target-history architecture remains incomplete.
- No public inbound IP, independent physical host/provider/operator, Internet peer discovery, public RPC/explorer, wallet or market service was tested.
- These tests do not create a token listing, market maker, USDT quote asset, exchange account, liquidity pool, public price, or trading volume.

Therefore:

- **PMT4/PFM4 two-process local diagnostics: PASS**
- **TXN4/MTA4 two-process local transfer-to-block path: PASS**
- **Gate 2: OPEN** — frozen 10B production profile, checkpoint/retarget/halving reachability, complete canonical producer/import/fork/reorg/snapshot path, independent vectors and external review remain outstanding.
- **Gate 8: OPEN** — separately administered AWS Anchor and Q6TS trust-floor deployment, host rollback/power-loss proof and external review remain outstanding.
- **Public seed / public value-bearing Testnet / Mainnet / trading: NOT AUTHORIZED / NOT ESTABLISHED.**

## 4. Integrity and environment

SHA-256:

| Artifact | SHA-256 |
|---|---|
| `simulations/cp0362_pfm4_page2_cursor_reorg.ps1` | `5E80CA9598BE06B3429D22282C0C7460C3DEAF8E5B3A41FF686BF085FEE8E7F8` |
| `simulations/cp0363_txn4_two_node_loopback.ps1` | `0A9E4CCB52A3D51A79D3144C693242A6E23E1CA5C3C3EAF101AA2F6D672FB2FC` |
| `target/release/devnet_node.exe` | `AF0AD11D24A94A322A8B5592CF1661E8207A4BF14F44EC356DDC1BF06A6CA17A` |
| `target/release/noise_key_provisioner.exe` | `4FFCCE8AAF6A11A1FF78D150F406CA717B88D01069676501AE408D36CAF839AE` |
| `target/release/examples/txn4_loopback_fixture.exe` | `73CAF27D8CED0BE0703FE8FAAD4F413B38553EFC47C5E6D45AB17224D7A3191B` |

- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: PASS.
- `git diff --check`: PASS (pre-existing CRLF working-copy warnings only).
- The test launcher completed with exit code 0 for both scripts.
- All `devnet_node.exe` and `noise_key_provisioner.exe` child processes exited; no node listener was left running.
- The NPK1/DPAPI Noise keys and fixture data were generated only under disposable `%TEMP%` directories, not production directories. No private key was read or exported by this checkpoint.
- No AWS credential, cloud account, public IP listener, production wallet, production key or external service was used.

## 5. Git preservation

- Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- HEAD unchanged: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- No staged files.
- No commit, push, merge, reset, clean, stash or checkout.
- The only project file added by this checkpoint is this engineering report; the two simulation scripts were existing source files.

**Final disposition:** fresh two-process evidence now proves PMT4/PFM4 archive sync, page-2 reorg/stale cursor rejection, signed TXN4 submission, MTA4 peer acknowledgement, matching canonical state and independent-process reopen/replay on the loopback candidate. It materially strengthens Gate 2's runtime evidence but does not close Gate 2 or Gate 8 and does not authorize public launch or trading.
