#!/usr/bin/env python3
"""Independent CP-0394 QZL4 golden-vector generator.

Uses only Python's standard library and independently encodes the fixed v0.4 Genesis
fixture, LedgerState snapshot, eight-bucket accounting record, monetary root, and QZL4
snapshot envelope. This file deliberately does not call or parse Rust output.
"""
from hashlib import sha256
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "simulations" / "quantumzxb_v04_ledger_snapshot_vectors.txt"
NETWORK = bytes([0x31]) * 32
OWNER = bytes([0xA7]) * 32
ATOMS_PER_COIN = 100_000_000
MAX_SUPPLY_ATOMS = 10_000_000_000 * ATOMS_PER_COIN
ISSUED = [0] * 8
ISSUED[7] = 1_000_000_000 * ATOMS_PER_COIN
BURNED = 0
MINED = 0
BUCKETS = [
    (0, 3_000_000_000, 3000),
    (1, 1_000_000_000, 1000),
    (2, 1_000_000_000, 1000),
    (3, 1_000_000_000, 1000),
    (4, 1_000_000_000, 1000),
    (5, 1_000_000_000, 1000),
    (6, 1_000_000_000, 1000),
    (7, 1_000_000_000, 1000),
]

def u16(n): return struct.pack(">H", n)
def u32(n): return struct.pack(">I", n)
def u64(n): return struct.pack(">Q", n)
def u128(n): return n.to_bytes(16, "big")
def H(domain, *parts): return sha256(domain + b"".join(parts)).digest()

policy_preimage = (
    b"QUANTUMZXB-ALLOCATION-POLICY-FINGERPRINT-V04\0"
    + b"QUANTUMZXB-TOKENOMICS-V04-2026-10-24\0"
    + u16(4)
    + u128(ATOMS_PER_COIN)
    + u128(MAX_SUPPLY_ATOMS)
    + b"".join(bytes([bucket]) + u128(coins) + u16(share) for bucket, coins, share in BUCKETS)
)
policy_fingerprint = sha256(policy_preimage).digest()

accounting = (
    b"QZAL" + u16(1)
    + b"".join(u128(n) for n in ISSUED)
    + u128(BURNED)
)
assert len(accounting) == 150
accounting_commitment = H(b"QUANTUMZXB-ALLOCATION-ACCOUNTING-STATE-V01\0", accounting)

ledger_state_preimage = (
    b"AIN1-STATE-V2\0" + NETWORK + u64(0) + u64(0) + u64(0)
    + u32(1) + OWNER + u64(ISSUED[7]) + u64(0)
)
ledger_root = H(b"AIN1-STATE-ROOT-V2\0", ledger_state_preimage)

ledger_snapshot_preimage = (
    b"STV2" + u16(2) + NETWORK + u64(0) + u64(0) + bytes(32)
    + u64(0) + u32(1) + OWNER + u64(ISSUED[7]) + u64(0)
)
ledger_snapshot = ledger_snapshot_preimage + H(
    b"AIN1-STATE-SNAPSHOT-CHECK-V2\0", ledger_snapshot_preimage
)
assert len(ledger_snapshot) == 178

monetary_state_root = H(
    b"QUANTUMZXB-MONETARY-STATE-ROOT-V04\0",
    policy_fingerprint,
    ledger_root,
    accounting_commitment,
    u128(MINED),
)
snapshot_preimage = (
    b"QZL4" + u16(1) + NETWORK + u32(len(ledger_snapshot))
    + ledger_snapshot + accounting + u128(MINED) + monetary_state_root
)
snapshot = snapshot_preimage + H(
    b"QUANTUMZXB-MONETARY-SNAPSHOT-CHECK-V04\0", snapshot_preimage
)
assert len(snapshot) == 450
assert ISSUED[7] == 1_000_000_000 * ATOMS_PER_COIN
assert sum(ISSUED) - BURNED == ISSUED[7]

rows = [
    "# CP-0394 independently generated QZL4 golden vector; hex values are canonical bytes.",
    "network_id=" + NETWORK.hex(),
    "owner_id=" + OWNER.hex(),
    "policy_fingerprint=" + policy_fingerprint.hex(),
    "ledger_state_root=" + ledger_root.hex(),
    "accounting_hex=" + accounting.hex(),
    "accounting_commitment=" + accounting_commitment.hex(),
    "ledger_snapshot_hex=" + ledger_snapshot.hex(),
    "monetary_state_root=" + monetary_state_root.hex(),
    "snapshot_hex=" + snapshot.hex(),
    "snapshot_sha256=" + sha256(snapshot).hexdigest(),
]
OUT.write_text("\n".join(rows) + "\n", encoding="ascii")
print(f"wrote {OUT} ({len(snapshot)} snapshot bytes)")
for row in rows[1:]:
    if not row.startswith("snapshot_hex=") and not row.startswith("ledger_snapshot_hex=") and not row.startswith("accounting_hex="):
        print(row)
print("snapshot_hex_length=" + str(len(snapshot.hex())))
