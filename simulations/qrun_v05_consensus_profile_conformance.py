#!/usr/bin/env python3
"""Cross-check the QRun v0.5 calibrated profile against the wallet-bound runtime identity.

This oracle independently serializes the exact profile fingerprint preimage used by
qrun_v05_pow_local_node.rs. It is a candidate-consistency check, not a consensus audit
or Mainnet activation decision.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "profiles/qrun_v05_consensus_calibration_candidate.json"
IDENTITY_PATH = ROOT / "profiles/qrun_v05_wallet_bound_mainnet_identity_candidate.json"
PROFILE_DOMAIN = b"QUANTUMZXB-QRUN-V05-CONSENSUS-PROFILE\0"


def require(condition: bool, message: str) -> None:
    """Fail closed even when Python runs with optimization (-O)."""
    if not condition:
        raise SystemExit(f"QRUN_V05_PROFILE_CONFORMANCE_FAILED: {message}")


def bytes32(value: str, label: str) -> bytes:
    require(isinstance(value, str), f"{label} must be hexadecimal text")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise SystemExit(f"QRUN_V05_PROFILE_CONFORMANCE_FAILED: invalid {label}: {exc}") from exc
    require(len(decoded) == 32, f"{label} must be exactly 32 bytes")
    return decoded


def main() -> int:
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    identity = json.loads(IDENTITY_PATH.read_text(encoding="utf-8"))

    require(profile["profile_status"] == "candidate_multi_runner_calibrated_not_frozen",
            "calibration profile status must remain explicitly candidate-only")
    require(profile["protocol_version"] == 5, "candidate protocol version must be 5")
    require(profile["mainnet_activated"] is False, "calibration profile must not claim Mainnet activation")
    require(profile["production_consensus_profile_frozen"] is False,
            "calibration profile must not claim production consensus freeze")
    require(profile["post_genesis_minting_enabled"] is False,
            "post-Genesis minting must remain disabled")
    require(profile["miner_subsidy_atoms_per_block"] == "0",
            "QRun v0.5 subsidy must remain zero")

    pow_profile = profile["pow"]
    require(pow_profile == {
        "algorithm": "Argon2id-v1.3",
        "memory_kib": 65536,
        "iterations": 1,
        "lanes": 1,
        "output_bytes": 32,
    }, "PoW parameters differ from the QRun v0.5 calibrated candidate")

    difficulty = profile["difficulty"]
    require(difficulty["target_block_time_seconds"] == 30, "target block time mismatch")
    require(difficulty["window_blocks"] == 2016, "difficulty window mismatch")
    require(difficulty["minimum_adjustment_ratio_divisor"] == 4, "minimum retarget clamp mismatch")
    require(difficulty["maximum_adjustment_ratio"] == 4, "maximum retarget clamp mismatch")
    pow_limit = bytes32(difficulty["pow_limit_hex"], "PoW limit")
    require(pow_limit == b"\xff" * 32, "PoW limit differs from the current QRun v0.5 candidate")
    initial_target = bytes32(difficulty["initial_target_hex"], "initial target")

    evidence = profile["calibration_evidence"]
    samples = evidence["samples"]
    require([sample["memory_mib"] for sample in samples] == [16, 32, 64],
            "calibration sample memory matrix changed")
    selected = next(
        (sample for sample in samples if sample["memory_mib"] == evidence["selected_memory_mib"]),
        None,
    )
    require(selected is not None and evidence["selected_memory_mib"] == 64,
            "the 64 MiB sample must remain the selected calibration point")
    hps_milli = evidence["selected_median_hashes_per_second_milli"]
    require(hps_milli == round(selected["median_hashes_per_second"] * 1000),
            "selected milli-hash rate does not match the recorded sample")
    expected_attempts_milli = hps_milli * difficulty["target_block_time_seconds"]
    derived_target = (((1 << 256) - 1) * 1000) // expected_attempts_milli
    require(initial_target == derived_target.to_bytes(32, "big"),
            "initial target does not match the conservative measured-throughput derivation")
    expected_attempts = expected_attempts_milli / 1000
    require(abs(evidence["expected_attempts_at_30_seconds"] - expected_attempts) < 1e-9,
            "expected attempts per target interval do not match the selected throughput")

    matrix = evidence["cross_platform_runner_matrix"]
    require(matrix["successful_runner_count"] == 3, "cross-platform runner count mismatch")
    require({row["os"] for row in matrix["runner_results"]} == {
        "ubuntu-latest", "windows-latest", "macos-latest"
    }, "cross-platform runner matrix is incomplete")
    require(evidence["independent_host_count"] == 4,
            "historical calibration host count changed")
    require(evidence["independent_operator_count"] == 2,
            "historical operator evidence changed")
    require(evidence["power_watts_measured"] is False,
            "calibration evidence must not claim measured power consumption")

    issuance = profile["issuance"]
    maximum_supply = int(identity["maximum_supply_atoms"])
    require(issuance["mode"] == "fee_only", "issuance mode must remain fee-only")
    require(int(issuance["maximum_supply_atoms"]) == maximum_supply,
            "calibration supply differs from the wallet-bound identity manifest")
    require(int(issuance["initial_subsidy_atoms"]) == 0,
            "fee-only issuance subsidy must be zero")
    require(issuance["blocks_per_halving"] == 1,
            "fee-only issuance profile must retain its canonical nonzero interval")
    require(maximum_supply == 10_000_000_000 * int(identity["atoms_per_coin"]),
            "wallet-bound supply does not equal 10 billion QZXB")
    require(int(identity["genesis_owner_balance_atoms"]) == maximum_supply,
            "Genesis owner allocation must equal the fixed supply")
    require(identity["post_genesis_minting_enabled"] is False,
            "wallet-bound manifest must keep minting disabled")
    require(identity["miner_subsidy_atoms_per_block"] == "0",
            "wallet-bound manifest must keep block subsidy at zero")

    network_id = bytes32(identity["network_id_hex"], "wallet-bound Network ID")
    genesis_id = bytes32(identity["genesis_id_hex"], "wallet-bound Genesis ID")
    expected_profile_id = bytes32(identity["profile_id_hex"], "wallet-bound profile ID")

    # Byte-for-byte independent implementation of qrun_v05_pow_local_node.rs::profile_id.
    # All integer widths and endianness are explicit; no native ABI layout is used.
    preimage = bytearray(PROFILE_DOMAIN)
    preimage.extend(network_id)
    preimage.extend(genesis_id)
    preimage.extend(struct.pack(">H", profile["protocol_version"]))
    preimage.extend(struct.pack(">Q", difficulty["target_block_time_seconds"]))
    preimage.extend(struct.pack(">Q", difficulty["window_blocks"]))
    preimage.extend(struct.pack(">Q", difficulty["minimum_adjustment_ratio_divisor"]))
    preimage.extend(struct.pack(">Q", difficulty["maximum_adjustment_ratio"]))
    preimage.extend(pow_limit)
    preimage.extend(initial_target)
    preimage.extend(b"\x01")  # Rust PowAlgorithm::Argon2id discriminant.
    preimage.extend(struct.pack(">I", pow_profile["memory_kib"]))
    preimage.extend(struct.pack(">I", pow_profile["iterations"]))
    preimage.extend(struct.pack(">I", pow_profile["lanes"]))
    preimage.extend(struct.pack(">B", pow_profile["output_bytes"]))
    preimage.extend(maximum_supply.to_bytes(16, "big"))
    preimage.extend((0).to_bytes(16, "big"))  # fee-only initial subsidy
    preimage.extend(struct.pack(">Q", issuance["blocks_per_halving"]))

    computed_profile_id = hashlib.sha256(preimage).digest()
    require(computed_profile_id == expected_profile_id,
            "calibrated consensus fields do not reproduce the wallet-bound runtime profile ID")

    print("QRUN_V05_CONSENSUS_PROFILE_CROSS_LANGUAGE=PASS")
    print(f"network_id={network_id.hex()}")
    print(f"genesis_id={genesis_id.hex()}")
    print(f"initial_target={initial_target.hex()}")
    print(f"profile_id={computed_profile_id.hex()}")
    print(f"fixed_supply_atoms={maximum_supply}; post_genesis_minting=false; block_subsidy_atoms=0")
    print("production_consensus_profile_frozen=false; mainnet_activated=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
