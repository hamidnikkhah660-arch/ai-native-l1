#!/usr/bin/env python3
"""Independent Python encoder/checker for the CP-0384 PCP4 v1 Genesis golden vector."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "src" / "native" / "pow_bench" / "tests" / "fixtures"
VECTOR_PATH = FIXTURES / "cp0384_pcp4_genesis_vector.json"
HEX_PATH = FIXTURES / "cp0384_pcp4_genesis_vector.hex"
PROFILE_DOMAIN = b"AIN1-PMT4-CHECKPOINT-PROFILE-V1\0"
GENESIS_DOMAIN = b"AIN1-PMT4-CHECKPOINT-GENESIS-V1\0"
CHECKSUM_DOMAIN = b"AIN1-PMT4-CHECKPOINT-CHECKSUM-V1\0"


def u(value: int | str, width: int) -> bytes:
    number = int(value)
    if number < 0 or number >= 1 << (8 * width):
        raise ValueError(f"integer {number} does not fit in {width} bytes")
    return number.to_bytes(width, "big")


def h(value: str) -> bytes:
    result = bytes.fromhex(value)
    if len(result) != 32:
        raise ValueError("expected a 32-byte hexadecimal field")
    return result


def domain_hash(domain: bytes, *parts: bytes) -> bytes:
    return hashlib.sha256(domain + b"".join(parts)).digest()


def main() -> int:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    p = vector["profile"]
    profile_bytes = b"".join(
        [
            u(p["protocol_version"], 2),
            u(p["target_block_time_secs"], 8),
            u(p["difficulty_window_blocks"], 8),
            u(p["difficulty_min_ratio_divisor"], 8),
            u(p["difficulty_max_ratio"], 8),
            h(p["pow_limit_hex"]),
            h(p["initial_target_hex"]),
            u(p["pow_algorithm_id"], 1),
            u(p["pow_memory_kib"], 4),
            u(p["pow_iterations"], 4),
            u(p["pow_lanes"], 4),
            u(p["pow_output_bytes"], 1),
            u(p["issuance_maximum_supply_atoms"], 16),
            u(p["issuance_initial_subsidy_atoms"], 16),
            u(p["issuance_blocks_per_halving"], 8),
            u(p["atoms_per_coin"], 16),
            u(p["maximum_supply_atoms"], 16),
            u(p["founder_allocation_atoms"], 16),
            u(p["miner_budget_atoms"], 16),
            u(p["public_goods_budget_atoms"], 16),
            u(p["monetary_initial_subsidy_atoms"], 16),
            u(p["monetary_blocks_per_halving"], 8),
        ]
    )
    profile_fp = domain_hash(PROFILE_DOMAIN, profile_bytes)
    if profile_fp.hex() != vector["profile_fingerprint_hex"]:
        raise ValueError("profile fingerprint mismatch")

    network = h(vector["network_id_hex"])
    manifest = h(vector["transaction_manifest_id_hex"])
    snapshot = bytes.fromhex(vector["monetary_snapshot_hex"])
    genesis_fp = domain_hash(
        GENESIS_DOMAIN,
        network,
        profile_fp,
        manifest,
        u(len(snapshot), 4),
        snapshot,
    )
    if genesis_fp.hex() != vector["genesis_fingerprint_hex"]:
        raise ValueError("Genesis fingerprint mismatch")

    history = vector["target_history"]
    history_count = len(history)
    record_len = 372 + len(snapshot) + history_count * 49
    if record_len > 9 * 1024 * 1024:
        raise ValueError("record exceeds the candidate size ceiling")
    record = bytearray()
    record.extend(b"PCP4")
    record.extend(u(vector["schema_version"], 2))
    record.extend(u(0, 2))
    record.extend(u(record_len, 4))
    record.extend(network)
    record.extend(genesis_fp)
    record.extend(profile_fp)
    record.extend(manifest)
    record.extend(u(vector["logical_height"], 8))
    record.extend(h(vector["consensus_tip_digest_hex"]))
    record.extend(h(vector["ledger_tip_hash_hex"]))
    record.extend(h(vector["monetary_state_root_hex"]))
    record.extend(u(vector["total_mined_atoms"], 16))
    record.extend(h(vector["cumulative_chainwork_hex"]))
    record.extend(h(vector["parent_checkpoint_commitment_hex"]))
    record.extend(u(len(snapshot), 4))
    record.extend(snapshot)
    record.extend(u(vector["target_history_start_height"], 8))
    record.extend(u(history_count, 4))
    for entry in history:
        record.extend(u(entry["height"], 8))
        record.extend(h(entry["target_hex"]))
        record.extend(u(entry["timestamp_present"], 1))
        record.extend(u(entry["timestamp"], 8))
    if len(record) + 32 != record_len:
        raise ValueError("record length calculation mismatch")
    record.extend(domain_hash(CHECKSUM_DOMAIN, bytes(record)))

    expected = bytes.fromhex(HEX_PATH.read_text(encoding="ascii").strip())
    if bytes(record) != expected:
        raise ValueError("Python output differs from checked-in Rust golden vector")
    if len(expected) != int.from_bytes(expected[8:12], "big"):
        raise ValueError("encoded length field mismatch")
    if domain_hash(CHECKSUM_DOMAIN, expected[:-32]) != expected[-32:]:
        raise ValueError("checksum mismatch")

    print("PCP4_GOLDEN_VECTOR=PASS")
    print(f"record_bytes={len(expected)}")
    print(f"profile_fingerprint={profile_fp.hex()}")
    print(f"genesis_fingerprint={genesis_fp.hex()}")
    print("commitment_domain=AIN1-PMT4-CHECKPOINT-COMMITMENT-V1\\0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())