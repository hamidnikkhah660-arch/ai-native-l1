# CP-0457 ? QRun v0.5 Checkpoint-Rooted External-CAS Reopen

Date: 2026-10-28

Status: **candidate implementation and focused tests passed; no production CAS provider or Mainnet activation is asserted**

## Purpose

QFP5 can resume from a QRCP checkpoint and append a PFS2 suffix. That alone does not make the suffix restart-safe against stale local-directory restoration: the store must carry the same signed, monotonic external-CAS contract as a Genesis-rooted store.

## Implemented

- Added QRunV05ExternalCasForkStore::open_from_checkpoint(...).
- The constructor requires protocol version 5, the exact proposed QRun network ID/Genesis commitment, the expected QRCP bytes and commitment, a nonzero checkpoint height floor, a client pinned to the caller-supplied provider/key, a previously retained signed-CAS record, and a nonzero external object-generation floor.
- It reconstructs the checkpoint's QFP5 fee-only chain before opening the checkpoint-profile PFS2 suffix store.
- The PFS2 profile fingerprint and manifest base tip are tied to the exact checkpoint commitment and base chain.
- The wrapper uses the same signed-read and compare-and-swap commit contract for suffix commits. Pending QAP1 recovery validates the exact profile fingerprint and base tip instead of assuming every store is Genesis-rooted.
- The opener never creates or overwrites a CAS provider's initial record; the matching checkpoint manifest anchor must already be independently provisioned.

## Focused validation

- cargo test qrun_external_cas --lib ? 4 passed, 0 failed, including checkpoint-rooted commit/reopen.
- cargo test qrun_checkpoint_pfs2 --lib ? 1 passed, 0 failed.
- cargo check --all-targets ? passed.
- cargo fmt --all -- --check ? passed.
- git diff --check ? passed.

The new checkpoint-rooted CAS test builds a valid one-block QFP5 chain, captures QRCP, anchors the checkpoint PFS2 manifest in the test provider, appends one QFP5 suffix block through the signed CAS transaction, closes the store, then reopens the same checkpoint and suffix using the successor record and object-generation floor. It asserts height 2, identical state root, and the exact 10,000,000,000 QZXB total.

The tests use an in-memory mock provider with test signing keys. They validate the protocol/API wiring and crash/reopen rules only; they do not prove independent provider operation or off-machine key custody.

## Open production work

This addition is not automatic checkpoint rollover. It does not remove the need for a production decision between full-history consensus-native replay from Genesis and a verified checkpoint-rotation policy. A real independently operated CAS provider and independently provisioned receipt key/record/object-generation floor are not deployed by this change. The existing QRun executable remains loopback-only, with disposable easy-PoW parameters; no public listener, production mining profile, public peer bootstrap, or value-bearing Mainnet is activated by this checkpoint.
