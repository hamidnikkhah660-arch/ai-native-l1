#!/usr/bin/env python3
"""Consistency check for the latest QRun full-supply Genesis direction; not a launch check."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAP = 10_000_000_000
ATOMS_PER_COIN = 100_000_000
EXPECTED_ATOMS = CAP * ATOMS_PER_COIN

doc = (ROOT / "docs/CP-0437_QRUN_FULL_SUPPLY_GENESIS_DIRECTION_2026-10-28.md").read_text(encoding="utf-8")
readme = (ROOT / "README.md").read_text(encoding="utf-8")
module = (ROOT / "src/native/pow_bench/src/qrun_v05_genesis_candidate.rs").read_text(encoding="utf-8")
lib = (ROOT / "src/native/pow_bench/src/lib.rs").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/rust-ci.yml").read_text(encoding="utf-8")

assert "10,000,000,000 QZXB" in doc
assert "10,000,000,000 QZXB (100% of supply)" in doc
assert "Subsequent minting and miner subsidy: **zero**" in doc
assert "The historical 4B founder profile is also retired" in doc
assert "Mainnet node is currently running" in doc
assert "CP-0437" in readme and "CP-0437_QRUN_FULL_SUPPLY_GENESIS_DIRECTION_2026-10-28.md" in readme
assert "pub mod qrun_v05_genesis_candidate;" in lib
assert "GENESIS_DOMAIN" in module and "QUANTUMZXB-QRUN-GENESIS-V05" in module
assert "MAX_TOTAL_SUPPLY_ATOMS" in module
assert "10_000_000_000 * ATOMS_PER_COIN" in module
assert "QRunGenesisV05::new" in module
assert "state_root" in module and "commitment" in module
assert "qrun_full_genesis_direction_checker.py" in workflow
assert "does **not** mean 10B coins have been issued on a live network" in doc
assert CAP * ATOMS_PER_COIN == EXPECTED_ATOMS == 1_000_000_000_000_000_000
print("QRUN_FULL_SUPPLY_GENESIS_DIRECTION_CHECK=PASS")
print(f"max_supply_coins={CAP}; atoms_per_coin={ATOMS_PER_COIN}; genesis_owner_percent=100; post_genesis_mint_and_miner_subsidy=0")
print("candidate_genesis_is_not_mainnet_activation=EXPLICIT")
