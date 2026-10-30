#!/usr/bin/env python3
"""Independent CP-0392 golden-vector generator for the proposed QuantumZXB v0.4 Genesis.

This deliberately does not import Rust-generated output or reuse the Rust implementation.
The outputs are language-neutral lowercase hex records consumed by the Rust test suite.
The profile remains a candidate and is not an activated Mainnet Genesis.
"""

from hashlib import sha256

ATOMS_PER_COIN = 100_000_000
MAX_TOTAL_SUPPLY_ATOMS = 10_000_000_000 * ATOMS_PER_COIN
POLICY_VERSION = 4
GENESIS_FORMAT_VERSION = 1
PROTOCOL_VERSION = 4

POLICY_ID = b"QUANTUMZXB-TOKENOMICS-V04-2026-10-24\0"
POLICY_FINGERPRINT_DOMAIN = b"QUANTUMZXB-ALLOCATION-POLICY-FINGERPRINT-V04\0"
ACCOUNTING_COMMITMENT_DOMAIN = b"QUANTUMZXB-ALLOCATION-ACCOUNTING-STATE-V01\0"
V04_MONETARY_STATE_ROOT_DOMAIN = b"QUANTUMZXB-MONETARY-STATE-ROOT-V04\0"
GENESIS_MANIFEST_HASH_DOMAIN = b"QUANTUMZXB-GENESIS-MANIFEST-HASH-V04\0"

# Index, coins, basis points. Enum order is consensus-sensitive.
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


def be(value: int, width: int) -> bytes:
    return value.to_bytes(width, "big", signed=False)


def make_vectors() -> list[tuple[str, bytes]]:
    network_id = bytes([0x31]) * 32
    owner_account = bytes([0xA7]) * 32

    preimage = bytearray(POLICY_FINGERPRINT_DOMAIN)
    preimage.extend(POLICY_ID)
    preimage.extend(be(POLICY_VERSION, 2))
    preimage.extend(be(ATOMS_PER_COIN, 16))
    preimage.extend(be(MAX_TOTAL_SUPPLY_ATOMS, 16))
    for index, coins, share_basis_points in BUCKETS:
        preimage.extend(bytes([index]))
        preimage.extend(be(coins, 16))
        preimage.extend(be(share_basis_points, 2))
    policy_fingerprint = sha256(preimage).digest()

    issued = [0] * 8
    issued[7] = 1_000_000_000 * ATOMS_PER_COIN
    accounting = bytearray(b"QZAL")
    accounting.extend(be(1, 2))
    for value in issued:
        accounting.extend(be(value, 16))
    accounting.extend(be(0, 16))
    accounting_bytes = bytes(accounting)
    assert len(accounting_bytes) == 150
    accounting_commitment = sha256(
        ACCOUNTING_COMMITMENT_DOMAIN + accounting_bytes
    ).digest()

    ledger_canonical = bytearray(b"AIN1-STATE-V2\0")
    ledger_canonical.extend(network_id)
    ledger_canonical.extend(be(0, 8))  # height
    ledger_canonical.extend(be(0, 8))  # last timestamp
    ledger_canonical.extend(be(0, 8))  # fee pool
    ledger_canonical.extend(be(1, 4))  # one initial account
    ledger_canonical.extend(owner_account)
    ledger_canonical.extend(be(1_000_000_000 * ATOMS_PER_COIN, 8))
    ledger_canonical.extend(be(0, 8))  # owner nonce
    ledger_state_root = sha256(b"AIN1-STATE-ROOT-V2\0" + ledger_canonical).digest()

    root_preimage = bytearray(V04_MONETARY_STATE_ROOT_DOMAIN)
    root_preimage.extend(policy_fingerprint)
    root_preimage.extend(ledger_state_root)
    root_preimage.extend(accounting_commitment)
    root_preimage.extend(be(0, 16))  # cumulative mined atoms at Genesis
    state_root = sha256(root_preimage).digest()
    manifest = bytearray(b"QZGM")
    manifest.extend(be(GENESIS_FORMAT_VERSION, 2))
    manifest.extend(be(PROTOCOL_VERSION, 2))
    manifest.extend(network_id)
    manifest.extend(owner_account)
    manifest.extend(policy_fingerprint)
    manifest.extend(accounting_bytes)
    manifest.extend(state_root)
    manifest_bytes = bytes(manifest)
    assert len(manifest_bytes) == 286
    manifest_hash = sha256(
        GENESIS_MANIFEST_HASH_DOMAIN + manifest_bytes
    ).digest()

    return [
        ("network_id", network_id),
        ("owner_account", owner_account),
        ("policy_fingerprint", policy_fingerprint),
        ("initial_accounting", accounting_bytes),
        ("accounting_commitment", accounting_commitment),
        ("genesis_state_root", state_root),
        ("genesis_manifest_bytes", manifest_bytes),
        ("genesis_manifest_hash", manifest_hash),
    ]


def main() -> None:
    for name, value in make_vectors():
        print(f"{name}|{value.hex()}")


if __name__ == "__main__":
    main()
