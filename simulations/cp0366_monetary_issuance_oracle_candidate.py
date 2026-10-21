#!/usr/bin/env python3
"""Independent integer-arithmetic oracle for the provisional native issuance schedule.

This model deliberately sums the finite non-zero geometric eras instead of reproducing
the Rust implementation's remaining-block loop. The emitted vectors are candidate-only
conformance fixtures, not frozen Mainnet monetary policy.
"""

from __future__ import annotations

import argparse
from pathlib import Path

MINER_BUDGET_ATOMS = 300_000_000_000_000_000
INITIAL_SUBSIDY_ATOMS = 35_673_515_981
BLOCKS_PER_HALVING = 4_204_800
U64_MAX = (1 << 64) - 1

HEIGHTS = (
    1,
    2,
    BLOCKS_PER_HALVING - 1,
    BLOCKS_PER_HALVING,
    BLOCKS_PER_HALVING + 1,
    2 * BLOCKS_PER_HALVING - 1,
    2 * BLOCKS_PER_HALVING,
    2 * BLOCKS_PER_HALVING + 1,
    3 * BLOCKS_PER_HALVING,
    4 * BLOCKS_PER_HALVING,
    8 * BLOCKS_PER_HALVING,
    35 * BLOCKS_PER_HALVING + 1,
    36 * BLOCKS_PER_HALVING,
    36 * BLOCKS_PER_HALVING + 1,
    100_000_000,
    1_000_000_000,
    U64_MAX,
)


def cumulative_issued_atoms(blocks_mined: int) -> int:
    """Closed-form sum of all scheduled eras, capped at the miner budget."""
    if not 0 <= blocks_mined <= U64_MAX:
        raise ValueError("blocks_mined must fit u64")

    full_eras, tail_blocks = divmod(blocks_mined, BLOCKS_PER_HALVING)
    nonzero_eras = INITIAL_SUBSIDY_ATOMS.bit_length()
    complete_era_count = min(full_eras, nonzero_eras)

    # Python's arbitrary-precision integers make the geometric sum exact.
    issued = BLOCKS_PER_HALVING * sum(
        INITIAL_SUBSIDY_ATOMS >> era for era in range(complete_era_count)
    )
    if full_eras < nonzero_eras:
        issued += tail_blocks * (INITIAL_SUBSIDY_ATOMS >> full_eras)
    return min(issued, MINER_BUDGET_ATOMS)


def row_for_height(block_height: int) -> tuple[int, int, int, int]:
    if not 1 <= block_height <= U64_MAX:
        raise ValueError("block_height must be in 1..=u64::MAX")

    prior = cumulative_issued_atoms(block_height - 1)
    schedule_era = (block_height - 1) // BLOCKS_PER_HALVING
    scheduled_subsidy = INITIAL_SUBSIDY_ATOMS >> schedule_era
    reward = min(scheduled_subsidy, max(0, MINER_BUDGET_ATOMS - prior))
    after = cumulative_issued_atoms(block_height)
    # Keep the oracle internally self-checking before emitting a vector.
    if after - prior != reward:
        raise AssertionError(
            f"oracle inconsistency at height {block_height}: "
            f"delta={after - prior}, reward={reward}"
        )
    return block_height, prior, reward, after


def render() -> str:
    lines = [
        "# CANDIDATE-ONLY: not a frozen or activated Mainnet policy",
        f"# miner_budget_atoms={MINER_BUDGET_ATOMS}",
        f"# initial_subsidy_atoms={INITIAL_SUBSIDY_ATOMS}",
        f"# blocks_per_halving={BLOCKS_PER_HALVING}",
        "block_height\tprior_issued_atoms\texpected_reward_atoms\tissued_after_block_atoms",
    ]
    lines.extend("\t".join(str(value) for value in row_for_height(height)) for height in HEIGHTS)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).with_name("cp0366_monetary_issuance_vectors_candidate.tsv"),
        help="vector file path (default: adjacent candidate TSV)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the existing vector file differs from this independently computed output",
    )
    args = parser.parse_args()
    expected = render()

    if args.check:
        if not args.output.is_file():
            print(f"missing vector file: {args.output}")
            return 1
        actual = args.output.read_text(encoding="utf-8")
        if actual != expected:
            print(f"vector mismatch: {args.output}")
            return 1
        print(f"PASS: {len(HEIGHTS)} independent issuance vectors match {args.output}")
        return 0

    args.output.write_text(expected, encoding="utf-8", newline="\n")
    print(f"wrote {len(HEIGHTS)} candidate issuance vectors to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
