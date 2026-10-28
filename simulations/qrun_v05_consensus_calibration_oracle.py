#!/usr/bin/env python3
"""Independent check of the QRun multi-runner PoW calibration candidate (not a launch gate)."""
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
assert PROFILE["post_genesis_minting_enabled"] is False
assert PROFILE["miner_subsidy_atoms_per_block"] == "0"
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
assert evidence["independent_host_count"] == 4
assert evidence["required_independent_host_count"] >= 3
assert evidence["independent_operator_count"] == 2
assert evidence["required_independent_operator_count"] >= 3
assert evidence["power_watts_measured"] is False

matrix = evidence["cross_platform_runner_matrix"]
assert matrix["run_id"] == 40744185485
assert matrix["commit"] == "188faee3034dd46f41a285b377483083c22b685e"
assert matrix["successful_runner_count"] == 3
runner_results = matrix["runner_results"]
assert {row["os"] for row in runner_results} == {
    "ubuntu-latest",
    "windows-latest",
    "macos-latest",
}
assert len(runner_results) == 3
runner_hps_64 = []
for runner in runner_results:
    assert len(runner["samples"]) == 3
    assert [sample["memory_mib"] for sample in runner["samples"]] == [16, 32, 64]
    selected_64 = next(sample for sample in runner["samples"] if sample["memory_mib"] == 64)
    assert selected_64["median_hashes_per_second"] > 0
    assert selected_64["hps_mad"] >= 0
    runner_hps_64.append(round(selected_64["median_hashes_per_second"] * 1000))

# Keep the target based on the conservative minimum across the local host and all three
# independent CI runner environments. Do not call this a frozen production profile.
assert hps_milli <= min(runner_hps_64)
assert matrix["cpu_model_recorded"] is False
assert matrix["power_watts_measured"] is False
assert matrix["independent_operator_count"] < matrix["required_independent_operator_count"]

# Compute a deterministic integer target from measured median throughput. HPS is stored in
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
print(f"local_64mib_hps={selected['median_hashes_per_second']:.3f} hps_mad={selected['hps_mad']:.3f}")
for runner in runner_results:
    result = next(sample for sample in runner["samples"] if sample["memory_mib"] == 64)
    print(f"runner={runner['os']} 64mib_hps={result['median_hashes_per_second']:.3f} hps_mad={result['hps_mad']:.3f}")
print(f"target_block_seconds={difficulty['target_block_time_seconds']} expected_attempts={expected_attempts:.3f}")
print(f"conservative_candidate_initial_target={derived_hex}")
print(f"benchmark_hosts={evidence['independent_host_count']}/{evidence['required_independent_host_count']}; operators={evidence['independent_operator_count']}/{evidence['required_independent_operator_count']}")
print("production_consensus_profile_frozen=false; mainnet_activated=false")
