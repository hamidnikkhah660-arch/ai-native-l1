"""Independent Python oracle for the CP-0361 monetary Genesis snapshot bytes.

Rebuilds STV2 and MST3 snapshot serialization plus their domain-separated checksums
without importing or invoking Rust. Its frozen vector is shared with Rust unit tests.
This is candidate-format conformance, not Mainnet protocol selection or launch approval.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "simulations" / "cp0361_monetary_genesis_snapshot_vectors.tsv"

NETWORK_ID = bytes.fromhex("aa" * 32)
FOUNDER_ID = bytes.fromhex("01" * 32)
PUBLIC_GOODS_ID = bytes.fromhex("02" * 32)
FOUNDER_ATOMS = 400_000_000_000_000_000
PUBLIC_GOODS_ATOMS = 300_000_000_000_000_000
MAX_SUPPLY_ATOMS = 1_000_000_000_000_000_000
MINER_BUDGET_ATOMS = 300_000_000_000_000_000
INITIAL_SUBSIDY_ATOMS = 35_673_515_981
BLOCKS_PER_HALVING = 4_204_800
MONETARY_POLICY_DOMAIN = b"AIN1-MONETARY-POLICY-CANDIDATE-V4\0"
MONETARY_FEE_POLICY_ID = b"AIN1-MONETARY-FEE-SENDER-PAYS-FEE-POOL-NO-MINER-PAYOUT-V1\0"
MONETARY_REWARD_BENEFICIARY_POLICY_ID = (
    b"AIN1-MONETARY-REWARD-HEIGHT-SCHEDULE-CREDIT-BLOCK-MINER-V1\0"
)
MONETARY_ACTIVATION_POLICY_ID = (
    b"AIN1-MONETARY-ACTIVATION-EXPLICIT-PROFILE-NO-IMPLICIT-MIGRATION-V1\0"
)

def sha256_domain(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()

def policy_fingerprint() -> bytes:
    return sha256_domain(
        MONETARY_POLICY_DOMAIN,
        MAX_SUPPLY_ATOMS.to_bytes(16, "big"),
        FOUNDER_ATOMS.to_bytes(16, "big"),
        MINER_BUDGET_ATOMS.to_bytes(16, "big"),
        PUBLIC_GOODS_ATOMS.to_bytes(16, "big"),
        INITIAL_SUBSIDY_ATOMS.to_bytes(16, "big"),
        BLOCKS_PER_HALVING.to_bytes(8, "big"),
        (8).to_bytes(2, "big"),
        MONETARY_FEE_POLICY_ID,
        MONETARY_REWARD_BENEFICIARY_POLICY_ID,
        MONETARY_ACTIVATION_POLICY_ID,
    )

def encode_ledger_snapshot(network_id: bytes, accounts: list[tuple[bytes, int]]) -> bytes:
    if len(network_id) != 32 or network_id == bytes(32):
        raise ValueError("network ID must be nonzero 32-byte value")
    accounts = sorted(accounts, key=lambda row: row[0])
    if not accounts or len({account for account, _ in accounts}) != len(accounts):
        raise ValueError("Genesis accounts must be nonempty and unique")
    if any(len(account) != 32 or account == bytes(32) for account, _ in accounts):
        raise ValueError("account IDs must be nonzero 32-byte values")
    if any(not 0 <= amount < (1 << 64) for _, amount in accounts):
        raise ValueError("balances must fit u64")
    if sum(amount for _, amount in accounts) > MAX_SUPPLY_ATOMS:
        raise ValueError("Genesis exceeds candidate supply cap")

    payload = bytearray(b"STV2")
    payload.extend((2).to_bytes(2, "big"))
    payload.extend(network_id)
    payload.extend((0).to_bytes(8, "big"))  # height
    payload.extend((0).to_bytes(8, "big"))  # last block timestamp
    payload.extend(bytes(32))  # genesis tip hash
    payload.extend((0).to_bytes(8, "big"))  # fee pool
    payload.extend(len(accounts).to_bytes(4, "big"))
    for account_id, balance in accounts:
        payload.extend(account_id)
        payload.extend(balance.to_bytes(8, "big"))
        payload.extend((0).to_bytes(8, "big"))  # nonce
    return bytes(payload) + sha256_domain(b"AIN1-STATE-SNAPSHOT-CHECK-V2\0", bytes(payload))

def encode_monetary_snapshot(ledger_snapshot: bytes, policy: bytes, total_mined_atoms: int = 0) -> bytes:
    if not 0 <= total_mined_atoms <= MINER_BUDGET_ATOMS:
        raise ValueError("mined counter outside budget")
    payload = bytearray(b"MST3")
    payload.extend((3).to_bytes(2, "big"))
    payload.extend(policy)
    payload.extend(total_mined_atoms.to_bytes(16, "big"))
    payload.extend(len(ledger_snapshot).to_bytes(4, "big"))
    payload.extend(ledger_snapshot)
    return bytes(payload) + sha256_domain(b"AIN1-MONETARY-SNAPSHOT-CHECK-V3\0", bytes(payload))

def make_vector() -> str:
    total_atoms = FOUNDER_ATOMS + PUBLIC_GOODS_ATOMS
    if total_atoms != 700_000_000_000_000_000 or total_atoms > MAX_SUPPLY_ATOMS:
        raise ValueError("unexpected candidate Genesis total")
    ledger_snapshot = encode_ledger_snapshot(
        NETWORK_ID,
        [(FOUNDER_ID, FOUNDER_ATOMS), (PUBLIC_GOODS_ID, PUBLIC_GOODS_ATOMS)],
    )
    policy = policy_fingerprint()
    monetary_snapshot = encode_monetary_snapshot(ledger_snapshot, policy)
    ledger_root = sha256_domain(
        b"AIN1-STATE-ROOT-V2\0",
        b"AIN1-STATE-V2\0"
        + NETWORK_ID
        + (0).to_bytes(8, "big")
        + (0).to_bytes(8, "big")
        + (0).to_bytes(8, "big")
        + (2).to_bytes(4, "big")
        + b"".join(
            account + amount.to_bytes(8, "big") + (0).to_bytes(8, "big")
            for account, amount in sorted(
                [(FOUNDER_ID, FOUNDER_ATOMS), (PUBLIC_GOODS_ID, PUBLIC_GOODS_ATOMS)],
                key=lambda row: row[0],
            )
        ),
    )
    monetary_root = sha256_domain(
        b"AIN1-MONETARY-STATE-ROOT-V3\0",
        policy,
        ledger_root,
        (0).to_bytes(16, "big"),
    )
    fields = [
        "MONETARY_GENESIS_SNAPSHOT_V1",
        NETWORK_ID.hex(),
        FOUNDER_ID.hex(),
        str(FOUNDER_ATOMS),
        PUBLIC_GOODS_ID.hex(),
        str(PUBLIC_GOODS_ATOMS),
        ledger_snapshot.hex(),
        monetary_snapshot.hex(),
        hashlib.sha256(ledger_snapshot).hexdigest(),
        hashlib.sha256(monetary_snapshot).hexdigest(),
        ledger_root.hex(),
        policy.hex(),
        monetary_root.hex(),
        str(total_atoms),
    ]
    return "|".join(fields)

def main() -> int:
    expected = make_vector()
    if "--write-vectors" in sys.argv:
        VECTORS.write_text(
            "# CP-0361 frozen candidate Genesis snapshot vector; atoms are 8-decimal units.\n"
            "# Rust and Python reconstruct these bytes independently; this is not production protocol approval.\n"
            + expected + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(f"WROTE={VECTORS}")
    if not VECTORS.is_file():
        raise SystemExit(f"FAIL: missing vector file {VECTORS}; run with --write-vectors once")
    rows = [
        line.strip()
        for line in VECTORS.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if rows != [expected]:
        raise SystemExit("FAIL: independently reconstructed snapshot vector differs from frozen bytes")
    fields = expected.split("|")
    ledger_snapshot = bytes.fromhex(fields[6])
    monetary_snapshot = bytes.fromhex(fields[7])
    if len(ledger_snapshot) != 226 or len(monetary_snapshot) != 316:
        raise SystemExit(f"FAIL: unexpected snapshot lengths ledger={len(ledger_snapshot)} monetary={len(monetary_snapshot)}")
    print("CP0361_MONETARY_GENESIS_SNAPSHOT_ORACLE=PASS")
    print(f"ledger_snapshot_bytes={len(ledger_snapshot)} sha256={fields[8]}")
    print(f"monetary_snapshot_bytes={len(monetary_snapshot)} sha256={fields[9]}")
    print(f"ledger_root={fields[10]}")
    print(f"policy_fingerprint={fields[11]}")
    print(f"monetary_state_root={fields[12]}")
    print(f"genesis_total_atoms={fields[13]}")
    print("SCOPE=independent bytes/vector only; no canonical issuance activation")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
