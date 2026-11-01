# CP-0491 ? QRun v0.5 Genesis-to-Checkpoint Migration Executor

Date: 2026-11-01

Status: **The consuming migration API and explicit one-time node CLI path are implemented. The local Windows end-to-end test passes with a signed loopback provider, and the ordinary post-migration runtime restarts from the generated QRCP. This remains a candidate maintenance operation: it does not enable Mainnet or provision a production/independent provider.**

## Purpose

QRA1 archive creation/replay, QRM1 exact migration intent, signed External-CAS recovery, QCF1 floor advancement and checkpoint-rooted PFS2 installation previously existed as separate primitives. CP-0491 adds a consuming method to `QRunV05ExternalCasForkStore`:

`migrate_genesis_rooted_store_to_checkpoint(...)`

This follow-up wires the method to an explicit operator-supplied option in `qrun_v05_pow_local_node`. It performs only the first migration of an already initialized **Genesis-rooted** QRun v0.5 fee-only PFS2 store to a QFP5 checkpoint. It is not automatic for ordinary node startup; without the explicit migration flag, the existing local/external-CAS startup paths are unchanged.

## Explicit CLI contract

The migration is requested with this option set (all paths are absolute):

```text
--external-cas-migrate-genesis-checkpoint true
--external-cas-history-archive-root <EXISTING-ARCHIVE-DIRECTORY>
--external-cas-checkpoint-output-file <NEW-QRCP-FILE>
--external-cas-migration-parent-commitment-hex <64-HEX-CHARACTERS>
```

The complete existing External-CAS trust tuple is also required: numeric provider endpoint, provider ID, wallet-bound Genesis commitment, Noise server static public-key pin, protected local Noise private-key file, receipt-key ID and ML-DSA-65 public-key file, ECR1 bootstrap record file, and the separate QCF1 floor directory. The provider is not discovered or created by this command. It must already be configured and reachable using the pinned Noise/TCP identity and signed receipt key.

`--external-cas-initialize-floor true` may be used only when the matching generation-zero ECR1 bootstrap is intended to initialize a not-yet-existing QCF1 floor. When the floor already exists, leave this option false (the default); an already initialized floor is reopened, never reset. A missing or mismatched floor remains fatal.

The parent commitment is not an arbitrary trust-on-first-use value. The CLI independently reconstructs the deterministic height-zero QRCP from the active Genesis, network and consensus profile, then requires the supplied parent commitment to match exactly before it reads bootstrap material, initializes QCF1, opens Noise/TCP or touches PFS2. The consuming Store API repeats the check for direct callers. A mismatch therefore cannot create the QCF1 floor, QRA1 archive, QRM1 intent or QRCP file, and cannot issue a provider request or CAS mutation through this CLI path.

The checkpoint output file must be outside the QCF1 floor, source PFS2 store and the entire QRA1 archive root. The executor canonicalizes the floor, archive and output-parent paths before checking their separation, so parent traversal and path aliases cannot place QRCP inside those trust stores. The floor and archive roots must also be disjoint. Existing different output bytes are not overwritten. The migration flag cannot be combined with `--external-cas-recover-qrm1 true` or with caller-supplied checkpoint-bootstrap fields; recovery remains a separate operation.

After a successful migration, startup verifies that the persisted QRCP bytes equal the checkpoint returned by QRM1 recovery, reopens QCF1, creates a fresh pinned Noise/TCP client session, opens the checkpoint-rooted PFS2 store and continues with the ordinary node runtime.

If an earlier run stopped with an ambiguous committed QRM1 intent, use the existing explicit recovery path with `--external-cas-recover-qrm1 true` and the same archive root, against the same provider pins and existing QCF1 floor. Do not try to restart the first-migration operation with new pins or to reset the floor.

## Execution ordering

1. Construct the wallet-bound Genesis and independently derive the deterministic height-zero QRCP parent commitment from the active network and consensus profile. Compare it with the operator-supplied value before reading ECR1/receipt bootstrap material, initializing or opening QCF1, loading the protected Noise key, creating a Noise/TCP session, opening PFS2 or contacting the provider.
2. Load and validate the pinned provider identity, ML-DSA-65 receipt key and generation-zero ECR1 bootstrap. Open the existing QCF1 floor, or initialize it only when the explicit initialization switch is supplied for the intended first bootstrap; then construct the pinned authenticated provider client.
3. Open the wallet-bound Genesis-rooted fee-only PFS2 store with its writer lock and attached floor. The consuming Store API independently derives and rechecks the height-zero parent commitment before reading the floor snapshot or issuing its fresh challenge-bound signed provider read.
4. While the source PFS2 writer lock is held, create-or-verify QRA1 and replay it from the original wallet-bound Genesis. Replay checks archive identity/profile/Genesis/manifest bindings and reconstructs the canonical QFP5 tip.
5. Prepare the exact QRM1 intent from the verified replay and exact current ECR1 successor.
6. Persist the bounded QRCP bytes to the separate caller-supplied absolute path using create-once semantics. Identical existing bytes are idempotent; different bytes, symlinks/reparse points and paths inside the PFS2, QRA1 archive root or independent QCF1 floor are refused. Sync the file and parent directory where supported.
7. Persist QRM1 while the source PFS2 lock is still held, then release that lock.
8. Invoke the existing recovery executor only after lock release. It reconciles exact provider CAS state, verifies the signed receipt, advances QCF1 and installs the checkpoint-rooted PFS2 manifest. QRM1 is cleared only after successful recovery.
9. Verify the recovered checkpoint commitment and bytes against the durable QRCP file. Reopen QCF1 and a fresh authenticated Noise/TCP session before ordinary runtime startup continues.

The API and CLI do not initialize a provider, replace a trust pin, reset a floor, infer provider state or fall back to a local store.

## Integration tests

`qrun_genesis_rooted_migration_executor_archives_commits_and_reopens_checkpoint` covers the consuming API with wallet-bound test Genesis, one QFP5 block, QRA1 replay, an ML-DSA-65 signed provider, QCF1, a deliberately lost first CAS response, QRM1 recovery, exact QRCP bytes, advanced object generation, fresh provider client and reopened checkpoint-rooted PFS2 tip/state-root.

The Windows node integration test `external_cas_node_startup_uses_pinned_noise_provider_and_advances_floor_before_return` now drives the real CLI/startup migration path. It creates a Genesis-rooted PFS2 source and a loopback Noise/TCP provider, uses a DPAPI-protected test Noise key and signed ML-DSA-65 receipts, verifies an incorrect parent is rejected before any provider request or QCF1 floor creation, without changing the source store, executes the correct migration, checks QRA1/QRCP publication and QCF1 generation advance, creates a further QFP5 block, then restarts from the generated QRCP and confirms canonical height, tip and state root. All paths, identities and keys are disposable test fixtures on loopback; no user wallet or production provider is involved.

## Validation on this branch

- Full Rust library suite on the final source: **1,037 passed, 0 failed** (`cargo test --lib --locked --offline`).
- QRun node binary suite: **28 passed, 0 failed**, including the Windows explicit-migration end-to-end test.
- Focused Genesis-rooted migration executor integration test: **1 passed, 0 failed**.
- QCF1/QRA1/QRCP path-isolation regressions: **2 library tests and the CLI path-overlap test passed**, covering traversal aliases, canonical directory overlap and output placement.
- All-target compile check: **PASS** (`cargo check --all-targets --locked --offline`).
- Rust formatting check: **PASS** (`cargo fmt --all -- --check`).
- `git diff --check`: **PASS**.
- Existing warnings are unrelated unused-import/dead-code/unused-mut warnings in candidate modules.

The stacked parent PR #119 at base SHA `67a53cdd5431616ada6d8092f59ac1b35e2cd1e7` and head SHA `f5be3da0244f1ffdcf0432e49761971d11e0bd6a` completed both exact-head CI workflows successfully: [push run 41264531536](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/41264531536) and [pull-request run 41264548563](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/41264548563). PR #119 remains Draft/Open and is not merged.

## Explicit limitations

- **First migration only:** this operation accepts a Genesis-rooted store and creates the first non-Genesis checkpoint. Repeated checkpoint-to-checkpoint rollover requires a linked multi-segment history/archive design and is not inferred here.
- **No production provider:** no AWS account/table/KMS resource, independent provider host, independent administrative/backup domain or production Noise endpoint was provisioned or contacted. The end-to-end provider in tests is loopback-only.
- **No public network:** this change does not expose P2P/RPC/TX listeners, change firewall rules or prove multi-host sync/recovery.
- **Mainnet remains disabled:** `QRUN_MAINNET_RELEASE_APPROVED` remains false. Genesis, Network ID, owner identity, supply, consensus/PoW and mint settings are unchanged.
- **Candidate maintenance interface:** the explicit flags execute during node initialization and therefore require the same operator-controlled local paths and pinned credentials as existing External-CAS startup. This is not a signed remote maintenance API, hosted control plane or approval to run against Mainnet.

This checkpoint closes the local code path for the first Genesis-to-checkpoint transaction. It does not close repeated-rollover/full-history, independent-provider, multi-host safety or public-network launch gates.
