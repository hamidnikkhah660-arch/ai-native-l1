"""Toy anti-eclipse P2P model for protocol research.
Not a real networking stack and not a security proof.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from random import Random


@dataclass(frozen=True)
class Peer:
    peer_id: str
    prefix: str
    source: str
    client: str
    honest: bool = True


def choose_outbound(
    peers: list[Peer],
    slots: int = 8,
    max_per_prefix: int = 2,
    max_per_source: int = 3,
    rng: Random | None = None,
) -> list[Peer]:
    """Choose peers using diversity-first heuristics.

    Real production code needs address bucketing, churn, scoring,
    discovery independence, and chain-view cross-checking.
    """
    rng = rng or Random(0)
    pool = peers[:]
    rng.shuffle(pool)
    selected: list[Peer] = []
    prefixes = Counter()
    sources = Counter()

    while pool and len(selected) < slots:
        eligible = [
            p for p in pool
            if prefixes[p.prefix] < max_per_prefix
            and sources[p.source] < max_per_source
        ]
        if not eligible:
            break

        peer = rng.choice(eligible)
        pool.remove(peer)
        selected.append(peer)
        prefixes[peer.prefix] += 1
        sources[peer.source] += 1

    return selected


def attack_share(peers: list[Peer], **kwargs: int) -> float:
    selected = choose_outbound(peers, **kwargs)
    if not selected:
        return 1.0
    return sum(not p.honest for p in selected) / len(selected)


def make_population() -> list[Peer]:
    peers: list[Peer] = []

    for i in range(32):
        peers.append(
            Peer(
                peer_id=f"h-{i}",
                prefix=f"h-{i // 4}",
                source=f"s-{i % 4}",
                client="client-a",
                honest=True,
            )
        )

    for i in range(64):
        peers.append(
            Peer(
                peer_id=f"a-{i}",
                prefix="evil-prefix",
                source="evil-source",
                client="client-x",
                honest=False,
            )
        )

    return peers


def demo() -> dict[str, float]:
    peers = make_population()
    rng = Random(7)

    naive_selected = rng.sample(peers, 8)
    naive_share = sum(not p.honest for p in naive_selected) / len(naive_selected)

    protected_share = attack_share(
        peers,
        slots=8,
        max_per_prefix=2,
        max_per_source=3,
        rng=Random(7),
    )

    return {
        "naive_attack_share": naive_share,
        "diversity_first_attack_share": protected_share,
    }


if __name__ == "__main__":
    print(demo())
