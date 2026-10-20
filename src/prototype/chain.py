"""Toy PoW chain for research experiments. Not secure and not for real funds."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, json, time

@dataclass(frozen=True)
class BlockHeader:
    height: int
    prev_hash: str
    merkle_root: str
    timestamp: int
    nonce: int
    bits: int

    def digest(self) -> str:
        payload = json.dumps(self.__dict__, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()

@dataclass(frozen=True)
class Block:
    header: BlockHeader
    subsidy: int

def mine_once(header: BlockHeader) -> tuple[int, str] | None:
    """"Toy search: valid iff leading hex zeros meet bits threshold."""
    target = "0" * header.bits
    for nonce in range(10_000_000):
        h = BlockHeader(header.height, header.prev_hash, header.merkle_root, header.timestamp, nonce, header.bits).digest()
        if h.startswith(target):
            return nonce, h
    return None

def adjusted_bits(current_bits: int, observed_seconds: float, target_seconds: float) -> int:
    """Simple bounded toy difficulty controller; production design will be more rigorous."""
    ratio = observed_seconds / target_seconds if target_seconds else 1.0
    if ratio < 0.25: return min(current_bits + 2, 64)
    if ratio < 0.67: return min(current_bits + 1, 64)
    if ratio > 4.0: return max(current_bits - 2, 1)
    if ratio > 1.5: return max(current_bits - 1, 1)
    return current_bits
