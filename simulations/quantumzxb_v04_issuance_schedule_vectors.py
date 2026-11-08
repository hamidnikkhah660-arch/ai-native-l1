#!/usr/bin/env python3
"""Independent CP-0397 reference vectors for a candidate-only v0.4 mining schedule.

The schedule parameters below are inherited from the current legacy mining schedule solely as
an arithmetic comparison baseline. They are NOT frozen or approved as v0.4 consensus parameters.
This script uses only Python's standard library and does not call or parse Rust output.
"""
from hashlib import sha256
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "simulations" / "quantumzxb_v04_issuance_schedule_vectors.txt"

ATOMS_PER_COIN = 100_000_000
MAX_TOTAL_SUPPLY_ATOMS = 10_000_000_000 * ATOMS_PER_COIN
POLICY_VERSION = 4
POLICY_ID = b"QUANTUMZXB-TOKENOMICS-V04-2026-10-24\0"
POLICY_DOMAIN = b"QUANTUMZXB-ALLOCATION-POLICY-FINGERPRINT-V04\0"
SCHEDULE_DOMAIN = b"QUANTUMZXB-V04-MINING-SCHEDULE-FINGERPRINT-CANDIDATE-V1\0"
RULES_TAG = (
    b"HEIGHT-ONE-BASED;INTEGER-RIGHT-SHIFT-FLOOR;"
    b"REWARD-CAPPED-TO-REMAINING-MINING-BUDGET;NO-TERMINAL-TOP-UP\0"
)
SCHEDULE_VERSION = 1
FIRST_ELIGIBLE_HEIGHT = 1

# Exploratory comparison only; these are not v0.4 defaults.
INITIAL_SUBSIDY_ATOMS = 35_673_515_981
BLOCKS_PER_HALVING = 4_204_800
BUCKETS = [
    (0, 3_000_000_000, 3_000),
    (1, 1_000_000_000, 1_000),
    (2, 1_000_000_000, 1_000),
    (3, 1_000_000_000, 1_000),
    (4, 1_000_000_000, 1_000),
    (5, 1_000_000_000, 1_000),
    (6, 1_000_000_000, 1_000),
    (7, 1_000_000_000, 1_000),
]
MINING_BUDGET_ATOMS = BUCKETS[0][1] * ATOMS_PER_COIN


def u16(n):
    return struct.pack(">H", n)


def u64(n):
    return struct.pack(">Q", n)


def u128(n):
    return n.to_bytes(16, "big", signed=False)


def policy_fingerprint():
    preimage = bytearray(POLICY_DOMAIN)
    preimage.extend(POLICY_ID)
    preimage.extend(u16(POLICY_VERSION))
    preimage.extend(u128(ATOMS_PER_COIN))
    preimage.extend(u128(MAX_TOTAL_SUPPLY_ATOMS))
    for index, coins, shares in BUCKETS:
        preimage.extend(bytes([index]))
        preimage.extend(u128(coins))
        preimage.extend(u16(shares))
    return sha256(preimage).digest()


def nominal_reward(height):
    if height < FIRST_ELIGIBLE_HEIGHT:
        raise ValueError("invalid block height")
    era = (height - FIRST_ELIGIBLE_HEIGHT) // BLOCKS_PER_HALVING
    return INITIAL_SUBSIDY_ATOMS >> era


def reward_for_height(height, already_mined):
    if height < FIRST_ELIGIBLE_HEIGHT:
        raise ValueError("invalid block height")
    if already_mined > MINING_BUDGET_ATOMS:
        raise ValueError("mining issuance exceeds bucket budget")
    return min(nominal_reward(height), MINING_BUDGET_ATOMS - already_mined)


def cumulative_issuance_after_blocks(blocks_mined):
    # Independent bounded summation by halving era, rather than iterating every block.
    remaining_blocks = blocks_mined
    total = 0
    for era in range(128):
        if remaining_blocks == 0 or total == MINING_BUDGET_ATOMS:
            break
        subsidy = INITIAL_SUBSIDY_ATOMS >> era
        if subsidy == 0:
            break
        blocks_in_era = min(remaining_blocks, BLOCKS_PER_HALVING)
        remaining_supply = MINING_BUDGET_ATOMS - total
        if subsidy > remaining_supply // blocks_in_era:
            return MINING_BUDGET_ATOMS
        total += subsidy * blocks_in_era
        remaining_blocks -= blocks_in_era
    return total


def schedule_fingerprint():
    preimage = bytearray(SCHEDULE_DOMAIN)
    preimage.extend(u16(SCHEDULE_VERSION))
    preimage.extend(policy_fingerprint())
    preimage.extend(u64(FIRST_ELIGIBLE_HEIGHT))
    preimage.extend(u128(MINING_BUDGET_ATOMS))
    preimage.extend(u128(INITIAL_SUBSIDY_ATOMS))
    preimage.extend(u64(BLOCKS_PER_HALVING))
    preimage.extend(RULES_TAG)
    return sha256(preimage).digest()


def make_vectors():
    full_schedule = cumulative_issuance_after_blocks(BLOCKS_PER_HALVING * 128)
    return [
        ("profile_label", "REFERENCE_ONLY_INHERITED_LEGACY_PARAMETERS_NOT_FROZEN"),
        ("policy_fingerprint", policy_fingerprint().hex()),
        ("mining_budget_atoms", str(MINING_BUDGET_ATOMS)),
        ("initial_subsidy_atoms", str(INITIAL_SUBSIDY_ATOMS)),
        ("blocks_per_halving", str(BLOCKS_PER_HALVING)),
        ("first_eligible_height", str(FIRST_ELIGIBLE_HEIGHT)),
        ("reward_height_1", str(reward_for_height(1, 0))),
        ("reward_height_4204800", str(reward_for_height(4_204_800, 0))),
        ("reward_height_4204801", str(reward_for_height(4_204_801, 0))),
        ("reward_height_8409600", str(reward_for_height(8_409_600, 0))),
        ("reward_height_8409601", str(reward_for_height(8_409_601, 0))),
        ("reward_height_u64_max", str(reward_for_height(2**64 - 1, 0))),
        ("reward_with_one_atom_left", str(reward_for_height(1, MINING_BUDGET_ATOMS - 1))),
        ("reward_at_budget", str(reward_for_height(1, MINING_BUDGET_ATOMS))),
        ("cumulative_issuance_after_all_nonzero_eras_atoms", str(full_schedule)),
        ("unissued_mining_budget_atoms", str(MINING_BUDGET_ATOMS - full_schedule)),
        ("schedule_fingerprint", schedule_fingerprint().hex()),
    ]


def rendered_vectors():
    output = [
        "# CP-0397 candidate vectors; inherited legacy parameters are a comparison only.",
        "# These values are NOT approved/frozen v0.4 consensus or Genesis parameters.",
    ]
    output.extend(f"{key}={value}" for key, value in make_vectors())
    return "\n".join(output) + "\n"


def main():
    import sys

    expected = rendered_vectors()
    if "--check" in sys.argv[1:]:
        if not OUT.exists():
            raise SystemExit(f"missing CP-0397 fixture: {OUT}")
        actual = OUT.read_text(encoding="utf-8")
        if actual != expected:
            raise SystemExit(
                "CP-0397 fixture differs from independent Python computation; "
                "run this script without --check to regenerate it."
            )
        print("CP0397_V04_ISSUANCE_SCHEDULE_ORACLE=PASS")
        print(f"schedule_fingerprint={schedule_fingerprint().hex()}")
        print(f"cumulative_issuance_after_all_nonzero_eras_atoms={cumulative_issuance_after_blocks(BLOCKS_PER_HALVING * 128)}")
        return

    OUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUT}")
    print(expected, end="")


if __name__ == "__main__":
    main()
