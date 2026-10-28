#!/usr/bin/env python3
"""Independent check of the single-host QRun PoW calibration candidate (not a launch gate)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = json.loads(
    (ROOT / "profiles/qrun_v05_consensus_calibration_candidate.json").read_text(encoding="utf-8")
)

pow_profile = PROFILE["pow"]
difficulty = PROFILE["difficulty"]
evidence = PROFILE["calibration_evidence"]
assert PROFILE["mainnet_activated"] is False
assert PROFILE["production_consensus_profile_frozen"] is False
assert pow_profile == {
    "algorithm": "Argon2id-v1.3",
    "memory_kib": 65536,
    "iterations": 1,
    "lanes": 1,
    "output_bytes": 32,
}
assert difficulty["target_block_time_seconds"] == 30
assert difficulty["window_blocks"] == 2016
assert difficulty["minimum_adjustment_ratio_divisor"] == 4
assert difficulty["maximum_adjustment_ratio"] == 4
assert difficulty["pow_limit_hex"] == "ff" * 32

samples = evidence["samples"]
assert [sample["memory_mib"] for sample in samples] == [16, 32, 64]
selected = next(sample for sample in samples if sample["memory_mib"] == evidence["selected_memory_mib"])
hps_milli = evidence["selected_median_hashes_per_second_milli"]
assert hps_milli == round(selected["median_hashes_per_second"] * 1000)
assert evidence["independent_host_count"] == 1
assert evidence["required_independent_host_count"] >= 3
assert evidence["power_watts_measured"] is False

# Compute a deterministic integer target from the measured median throughput. HPS is stored in
# milli-hashes/second to avoid platform-dependent floating-point rounding in the target itself.
expected_attempts_milli = hps_milli * difficulty["target_block_time_seconds"]
derived_target = (((1 << 256) - 1) * 1000) // expected_attempts_milli
derived_hex = derived_target.to_bytes(32, "big").hex()
assert difficulty["initial_target_hex"] == derived_hex
expected_attempts = expected_attempts_milli / 1000
assert abs(evidence["expected_attempts_at_30_seconds"] - expected_attempts) < 1e-9
assert int(difficulty["initial_target_hex"], 16) < int(difficulty["pow_limit_hex"], 16)

print("QRUN_V05_CONSENSUS_CALIBRATION_ORACLE=PASS")
print(f"pow=Argon2id memory_kib={pow_profile['memory_kib']} iterations={pow_profile['iterations']} lanes={pow_profile['lanes']}")
print(f"measured_hps_64mib={selected['median_hashes_per_second']:.3f} hps_mad={selected['hps_mad']:.3f}")
print(f"target_block_seconds={difficulty['target_block_time_seconds']} expected_attempts={expected_attempts:.3f}")
print(f"candidate_initial_target={derived_hex}")
print(f"independent_hosts={evidence['independent_host_count']}/{evidence['required_independent_host_count']}")
print("production_consensus_profile_frozen=false; mainnet_activated=false")
