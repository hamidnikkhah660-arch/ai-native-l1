"""Prototype parameters. NOT production consensus parameters."""
MAX_SUPPLY = 10_000_000_000
TARGET_BLOCK_SECONDS = 30
DROPS_PER_YEAR = 365 * 24 * 60 * 60
BLOCKS_PER_YEAR = DROPS_PER_YEAR // TARGET_BLOCK_SECONDS
MICRO_UNITS = 1_000_000

# Simulation only: these candidates are compared before any protocol constants are finalized.
INITIAL_SUBSIDY = 10_000_000
HALVING_YEARS = 4
