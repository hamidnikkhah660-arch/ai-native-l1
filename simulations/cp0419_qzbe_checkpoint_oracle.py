#!/usr/bin/env python3
"""Independent byte-level oracle for the CP-0419 QZBE Genesis checkpoint fixture."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "src/native/pow_bench/tests/fixtures/cp0419_qzbe_genesis_checkpoint.hex"
CHECKSUM_DOMAIN = b"QUANTUMZXB-QZBE-CHECKPOINT-CHECKSUM-V1\0"
COMMITMENT_DOMAIN = b"QUANTUMZXB-QZBE-CHECKPOINT-COMMITMENT-V1\0"
PREFIX_BYTES = 340
HISTORY_ENTRY_BYTES = 49
CHECKSUM_BYTES = 32
EXPECTED_COMMITMENT = "e61e49db0f5a2a3eaa68fda2187bc80692469c29317a13f7455ec538f7e607ce"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"CP0419_QZBE_CHECKPOINT_ORACLE=FAIL: {message}")


def u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "big")


def main() -> int:
    raw = FIXTURE.read_text(encoding="ascii").strip()
    require(bool(raw) and len(raw) % 2 == 0, "fixture is not a canonical hex string")
    try:
        encoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise SystemExit(f"CP0419_QZBE_CHECKPOINT_ORACLE=FAIL: invalid hex: {exc}") from exc

    require(len(encoded) == 1333, f"unexpected vector length {len(encoded)}")
    require(encoded[:4] == b"QZCP", "wrong checkpoint magic")
    require(u16(encoded, 4) == 1, "wrong checkpoint schema version")
    require(u16(encoded, 6) == 0, "nonzero flags")
    require(u32(encoded, 8) == len(encoded), "encoded length field mismatch")
    require(encoded[12:44] == bytes([0x31]) * 32, "network ID mismatch")
    require(
        encoded[44:76].hex()
        == "099876ace3094b5a7ea761952c665af7a1448f1333ee8beb2bf04925ba1d64dc",
        "Genesis manifest hash mismatch",
    )
    require(
        encoded[76:108].hex()
        == "c7de3abcff40fded6a8e9669931fab43639e08e04567b9e3857fdf49aa7787b7",
        "monetary profile fingerprint mismatch",
    )
    require(
        encoded[108:140].hex()
        == "6b54c2813382281bbd07ddc44e626d93785f51894d8404f71ab62ec3a33beacc",
        "PoW consensus fingerprint mismatch",
    )
    require(u64(encoded, 140) == 0, "Genesis logical height must be zero")
    require(encoded[148:180] == bytes(32), "Genesis QZBE tip must equal zero ledger tip")
    require(encoded[180:212] == bytes(32), "Genesis ledger tip should be all-zero")
    require(
        encoded[212:244].hex()
        == "9b33ec66b9e9607b70e67741eec5cd108c5f40a06f81072f876ee3171f4913aa",
        "Genesis state root mismatch",
    )
    require(int.from_bytes(encoded[244:260], "big") == 0, "Genesis mined counter must be zero")
    require(encoded[260:292] == bytes(32), "Genesis chainwork must be zero")
    require(encoded[292:324] == bytes(32), "Genesis parent checkpoint link must be zero")

    snapshot_len = u32(encoded, 324)
    history_start = u64(encoded, 328)
    history_count = u32(encoded, 336)
    require(snapshot_len == 912, f"unexpected QZP4 snapshot length {snapshot_len}")
    require(history_start == 0, "Genesis target-history start must be zero")
    require(history_count == 1, "Genesis target history must have one entry")
    expected_total = PREFIX_BYTES + snapshot_len + history_count * HISTORY_ENTRY_BYTES + CHECKSUM_BYTES
    require(expected_total == len(encoded), "length-delimited sections do not consume the record")

    snapshot_start = PREFIX_BYTES
    snapshot_end = snapshot_start + snapshot_len
    snapshot = encoded[snapshot_start:snapshot_end]
    require(snapshot[:4] == b"QZP4", "nested state snapshot magic mismatch")
    require(u16(snapshot, 4) == 2, "nested state snapshot version mismatch")
    require(snapshot[6:38] == encoded[12:44], "nested snapshot network mismatch")
    require(snapshot[38:42] == b"QZCP", "nested v0.4 profile magic mismatch")
    ledger_len = u32(snapshot, 292)
    amm_length_offset = 296 + ledger_len
    require(amm_length_offset + 4 <= len(snapshot), "nested ledger length exceeds state snapshot")
    amm_len = u32(snapshot, amm_length_offset)
    require(amm_len == 98, f"unexpected QAMS v2 snapshot length {amm_len}")
    amm_start = amm_length_offset + 4
    amm_end = amm_start + amm_len
    require(amm_end + 64 == len(snapshot), "nested state snapshot lengths mismatch")
    amm_snapshot = snapshot[amm_start:amm_end]
    require(amm_snapshot[:4] == b"QAMS", "nested AMM snapshot magic mismatch")
    require(u16(amm_snapshot, 4) == 2, "nested AMM snapshot version mismatch")
    require(amm_snapshot[6:38] == encoded[12:44], "nested AMM network mismatch")
    require(
        amm_snapshot[-32:]
        == hashlib.sha256(
            b"QZXB-NATIVE-AMM-SNAPSHOT-CHECK-V1\0" + amm_snapshot[:-32]
        ).digest(),
        "nested AMM snapshot checksum mismatch",
    )
    nested_root = snapshot[amm_end : amm_end + 32]
    require(nested_root == encoded[212:244], "nested snapshot state root differs from checkpoint")
    require(snapshot[-32:] == hashlib.sha256(
        b"QUANTUMZXB-V04-PROFILE-BOUND-SNAPSHOT-CHECK-CANDIDATE-V1\0"
        + snapshot[:-32]
    ).digest(), "nested snapshot checksum mismatch")

    entry = encoded[snapshot_end : snapshot_end + HISTORY_ENTRY_BYTES]
    require(u64(entry, 0) == 0, "Genesis target-history entry height mismatch")
    target = entry[8:40]
    require(target != bytes(32), "Genesis target must be nonzero")
    require(entry[40] == 0 and entry[41:49] == bytes(8), "Genesis timestamp must use canonical absent marker")

    expected_checksum = hashlib.sha256(CHECKSUM_DOMAIN + encoded[:-CHECKSUM_BYTES]).digest()
    require(encoded[-CHECKSUM_BYTES:] == expected_checksum, "outer checkpoint checksum mismatch")
    commitment = hashlib.sha256(COMMITMENT_DOMAIN + encoded).hexdigest()
    require(commitment == EXPECTED_COMMITMENT, "domain-separated checkpoint commitment mismatch")

    # Mutation smoke: changing a payload byte while leaving the checksum untouched must fail.
    tampered = bytearray(encoded)
    tampered[212] ^= 1
    require(
        hashlib.sha256(CHECKSUM_DOMAIN + tampered[:-CHECKSUM_BYTES]).digest()
        != tampered[-CHECKSUM_BYTES:],
        "tampered checkpoint unexpectedly retained its checksum",
    )

    print(
        "CP0419_QZBE_CHECKPOINT_ORACLE=PASS "
        f"bytes={len(encoded)} snapshot_bytes={snapshot_len} "
        f"history_entries={history_count} commitment={commitment}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
