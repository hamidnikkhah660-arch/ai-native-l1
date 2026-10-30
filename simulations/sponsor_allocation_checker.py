#!/usr/bin/env python3
"""HISTORICAL_V03_ONLY: preserve CP-0343's retired 4B founder-tranche arithmetic for old artifacts. Not the active v0.4 tokenomics checker."""
from dataclasses import dataclass

TOTAL_CAP = 10_000_000_000
FOUNDER_ENVELOPE = 4_000_000_000
MINING_SECURITY = 3_000_000_000
PUBLIC_GOODS = 3_000_000_000
SPONSOR_MAX = 1_000_000_000
CONTRIBUTOR_MIN = 100_000_000
CONTRIBUTOR_MAX = 1_000_000_000
FOUNDER_DIRECT_MIN = 2_000_000_000


@dataclass(frozen=True)
class Allocation:
    sponsor: int
    contributors: int
    founder_discretionary: int
    mining_security: int = MINING_SECURITY
    public_goods: int = PUBLIC_GOODS

    @property
    def founder_envelope_total(self) -> int:
        return self.sponsor + self.contributors + self.founder_discretionary

    @property
    def total(self) -> int:
        return self.founder_envelope_total + self.mining_security + self.public_goods


def candidate(contributor_award: int, sponsor_award: int = SPONSOR_MAX) -> Allocation:
    if not 0 <= sponsor_award <= SPONSOR_MAX:
        raise ValueError("sponsor award must be between zero and 1B")
    if not CONTRIBUTOR_MIN <= contributor_award <= CONTRIBUTOR_MAX:
        raise ValueError("contributor award must be between 0.1B and 1B")
    founder_discretionary = FOUNDER_ENVELOPE - sponsor_award - contributor_award
    if founder_discretionary < FOUNDER_DIRECT_MIN:
        raise ValueError("founder discretionary amount would fall below 2B")
    row = Allocation(sponsor_award, contributor_award, founder_discretionary)
    assert row.founder_envelope_total == FOUNDER_ENVELOPE
    assert row.total == TOTAL_CAP
    return row


def _run() -> None:
    low = candidate(CONTRIBUTOR_MIN)
    high = candidate(CONTRIBUTOR_MAX)
    assert low.founder_discretionary == 2_900_000_000
    assert high.founder_discretionary == FOUNDER_DIRECT_MIN
    assert low.total == high.total == TOTAL_CAP
    assert low.sponsor / TOTAL_CAP == 0.10
    assert low.sponsor / FOUNDER_ENVELOPE == 0.25
    for bad in (0, CONTRIBUTOR_MIN - 1, CONTRIBUTOR_MAX + 1):
        try:
            candidate(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid contributor award accepted: {bad}")
    try:
        candidate(CONTRIBUTOR_MAX, SPONSOR_MAX + 1)
    except ValueError:
        pass
    else:
        raise AssertionError("over-cap sponsor award accepted")
    print("CP0343_SPONSOR_ALLOCATION_CHECK=PASS_HISTORICAL_V03_ONLY")
    print("historical_v03_total_cap=10000000000")
    print("historical_v03_founder_envelope=4000000000")
    print("historical_v03_sponsor_max=1000000000 (10% total cap; 25% founder envelope)")
    print("historical_v03_contributor_pool=100000000..1000000000 (1%-10% total cap)")
    print(f"historical_v03_founder_direct_at_1pct_contributor_pool={low.founder_discretionary}")
    print(f"historical_v03_founder_direct_at_10pct_contributor_pool={high.founder_discretionary}")
    print("historical_v03_vesting_or_lock=not_in_scope")


if __name__ == "__main__":
    _run()
