#!/usr/bin/env python3
"""Independent CP-0398 QZCP/QZB4 candidate vectors (standard library only).

The fixture parameters are deliberately tiny test values, not approved v0.4 economics.
This implementation independently derives the base QZGM Genesis bytes/root, QZCP profile,
profile-bound Genesis state root, and first QZB4 mining block. It does not import Rust output.
"""
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "simulations" / "quantumzxb_v04_transition_profile_vectors.txt"

NETWORK = bytes([0x31]) * 32
OWNER = bytes([0xA7]) * 32
MINER = bytes([0xC4]) * 32
ATOMS_PER_COIN = 100_000_000
MAX_TOTAL_SUPPLY_ATOMS = 10_000_000_000 * ATOMS_PER_COIN
MINING_BUDGET_ATOMS = 3_000_000_000 * ATOMS_PER_COIN
POLICY_ID = b"QUANTUMZXB-TOKENOMICS-V04-2026-10-24\0"
POLICY_FP_DOMAIN = b"QUANTUMZXB-ALLOCATION-POLICY-FINGERPRINT-V04\0"
ACCOUNTING_COMMIT_DOMAIN = b"QUANTUMZXB-ALLOCATION-ACCOUNTING-STATE-V01\0"
MONETARY_STATE_ROOT_DOMAIN = b"QUANTUMZXB-MONETARY-STATE-ROOT-V04\0"
GENESIS_MANIFEST_HASH_DOMAIN = b"QUANTUMZXB-GENESIS-MANIFEST-HASH-V04\0"
SCHEDULE_FP_DOMAIN = b"QUANTUMZXB-V04-MINING-SCHEDULE-FINGERPRINT-CANDIDATE-V1\0"
SCHEDULE_RULES_TAG = (
    b"HEIGHT-ONE-BASED;INTEGER-RIGHT-SHIFT-FLOOR;"
    b"REWARD-CAPPED-TO-REMAINING-MINING-BUDGET;NO-TERMINAL-TOP-UP\0"
)
PROFILE_FP_DOMAIN = b"QUANTUMZXB-V04-CONSENSUS-PROFILE-FINGERPRINT-CANDIDATE-V1\0"
PROFILE_CHECK_DOMAIN = b"QUANTUMZXB-V04-CONSENSUS-PROFILE-CHECK-CANDIDATE-V1\0"
TRANSITION_ROOT_DOMAIN = b"QUANTUMZXB-V04-PROFILE-MONETARY-STATE-ROOT-CANDIDATE-V1\0"
MINING_BLOCK_ID_DOMAIN = b"QUANTUMZXB-V04-MINING-BLOCK-ID-CANDIDATE-V1\0"
PROFILE_VERSION = 1
SCHEDULE_VERSION = 1
GENESIS_FORMAT_VERSION = 1
PROTOCOL_VERSION = 4
FIRST_ELIGIBLE_HEIGHT = 1

# Explicit comparison-only schedule used by the Rust tests; not a network default.
INITIAL_SUBSIDY_ATOMS = 10_000
BLOCKS_PER_HALVING = 2
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


def h(domain: bytes, preimage: bytes) -> bytes:
    return sha256(domain + preimage).digest()


def derive():
    policy_preimage = bytearray(POLICY_FP_DOMAIN)
    policy_preimage.extend(POLICY_ID)
    policy_preimage.extend(be(4, 2))
    policy_preimage.extend(be(ATOMS_PER_COIN, 16))
    policy_preimage.extend(be(MAX_TOTAL_SUPPLY_ATOMS, 16))
    for index, coins, shares in BUCKETS:
        policy_preimage.extend(bytes([index]))
        policy_preimage.extend(be(coins, 16))
        policy_preimage.extend(be(shares, 2))
    policy_fp = sha256(policy_preimage).digest()

    issued = [0] * 8
    issued[7] = 1_000_000_000 * ATOMS_PER_COIN
    accounting = bytearray(b"QZAL")
    accounting.extend(be(1, 2))
    for value in issued:
        accounting.extend(be(value, 16))
    accounting.extend(be(0, 16))
    accounting_bytes = bytes(accounting)
    assert len(accounting_bytes) == 150
    accounting_commitment = h(ACCOUNTING_COMMIT_DOMAIN, accounting_bytes)

    # Existing QZGM's initial root is intentionally reproduced without changing its wire format.
    ledger_canonical = bytearray(b"AIN1-STATE-V2\0")
    ledger_canonical.extend(NETWORK)
    ledger_canonical.extend(be(0, 8))
    ledger_canonical.extend(be(0, 8))
    ledger_canonical.extend(be(0, 8))
    ledger_canonical.extend(be(1, 4))
    ledger_canonical.extend(OWNER)
    ledger_canonical.extend(be(1_000_000_000 * ATOMS_PER_COIN, 8))
    ledger_canonical.extend(be(0, 8))
    genesis_ledger_root = h(b"AIN1-STATE-ROOT-V2\0", bytes(ledger_canonical))

    qzgm_root_preimage = bytearray(MONETARY_STATE_ROOT_DOMAIN)
    qzgm_root_preimage.extend(policy_fp)
    qzgm_root_preimage.extend(genesis_ledger_root)
    qzgm_root_preimage.extend(accounting_commitment)
    qzgm_root_preimage.extend(be(0, 16))
    qzgm_root = sha256(qzgm_root_preimage).digest()

    qzgm = bytearray(b"QZGM")
    qzgm.extend(be(GENESIS_FORMAT_VERSION, 2))
    qzgm.extend(be(PROTOCOL_VERSION, 2))
    qzgm.extend(NETWORK)
    qzgm.extend(OWNER)
    qzgm.extend(policy_fp)
    qzgm.extend(accounting_bytes)
    qzgm.extend(qzgm_root)
    qzgm_bytes = bytes(qzgm)
    assert len(qzgm_bytes) == 286
    qzgm_hash = h(GENESIS_MANIFEST_HASH_DOMAIN, qzgm_bytes)

    schedule_preimage = bytearray(SCHEDULE_FP_DOMAIN)
    schedule_preimage.extend(be(SCHEDULE_VERSION, 2))
    schedule_preimage.extend(policy_fp)
    schedule_preimage.extend(be(FIRST_ELIGIBLE_HEIGHT, 8))
    schedule_preimage.extend(be(MINING_BUDGET_ATOMS, 16))
    schedule_preimage.extend(be(INITIAL_SUBSIDY_ATOMS, 16))
    schedule_preimage.extend(be(BLOCKS_PER_HALVING, 8))
    schedule_preimage.extend(SCHEDULE_RULES_TAG)
    schedule_fp = sha256(schedule_preimage).digest()

    profile_fp_preimage = bytearray(PROFILE_FP_DOMAIN)
    profile_fp_preimage.extend(be(PROFILE_VERSION, 2))
    profile_fp_preimage.extend(NETWORK)
    profile_fp_preimage.extend(qzgm_hash)
    profile_fp_preimage.extend(qzgm_root)
    profile_fp_preimage.extend(policy_fp)
    profile_fp_preimage.extend(be(INITIAL_SUBSIDY_ATOMS, 16))
    profile_fp_preimage.extend(be(BLOCKS_PER_HALVING, 8))
    profile_fp_preimage.extend(schedule_fp)
    profile_fp = sha256(profile_fp_preimage).digest()

    profile_preimage = bytearray(b"QZCP")
    profile_preimage.extend(be(PROFILE_VERSION, 2))
    profile_preimage.extend(NETWORK)
    profile_preimage.extend(qzgm_hash)
    profile_preimage.extend(qzgm_root)
    profile_preimage.extend(policy_fp)
    profile_preimage.extend(be(INITIAL_SUBSIDY_ATOMS, 16))
    profile_preimage.extend(be(BLOCKS_PER_HALVING, 8))
    profile_preimage.extend(schedule_fp)
    profile_preimage.extend(profile_fp)
    profile_bytes = bytes(profile_preimage) + h(PROFILE_CHECK_DOMAIN, bytes(profile_preimage))
    assert len(profile_bytes) == 254

    # Height 1 means schedule index 0. The first reward is therefore 10,000 atoms.
    reward = min(INITIAL_SUBSIDY_ATOMS, MINING_BUDGET_ATOMS)
    next_issued = issued.copy()
    next_issued[0] += reward
    block_accounting = bytearray(b"QZAL")
    block_accounting.extend(be(1, 2))
    for value in next_issued:
        block_accounting.extend(be(value, 16))
    block_accounting.extend(be(0, 16))
    block_accounting_bytes = bytes(block_accounting)
    block_accounting_commitment = h(ACCOUNTING_COMMIT_DOMAIN, block_accounting_bytes)

    # Account IDs sort lexicographically: owner 0xA7... precedes miner 0xC4...
    ledger1 = bytearray(b"AIN1-STATE-V2\0")
    ledger1.extend(NETWORK)
    ledger1.extend(be(1, 8))
    ledger1.extend(be(1, 8))
    ledger1.extend(be(0, 8))
    ledger1.extend(be(2, 4))
    ledger1.extend(OWNER)
    ledger1.extend(be(1_000_000_000 * ATOMS_PER_COIN, 8))
    ledger1.extend(be(0, 8))
    ledger1.extend(MINER)
    ledger1.extend(be(reward, 8))
    ledger1.extend(be(0, 8))
    ledger1_root = h(b"AIN1-STATE-ROOT-V2\0", bytes(ledger1))

    state_root_preimage = bytearray(TRANSITION_ROOT_DOMAIN)
    state_root_preimage.extend(profile_fp)
    state_root_preimage.extend(ledger1_root)
    state_root_preimage.extend(block_accounting_commitment)
    state_root_preimage.extend(be(reward, 16))
    state_root1 = sha256(state_root_preimage).digest()

    block = bytearray(b"QZB4")
    block.extend(be(1, 2))
    block.extend(profile_fp)
    block.extend(be(1, 8))
    block.extend(be(1, 8))
    block.extend(bytes(32))  # Genesis tip hash.
    block.extend(MINER)
    block.extend(be(reward, 16))
    block.extend(state_root1)
    block_bytes = bytes(block)
    assert len(block_bytes) == 166
    block_id = h(MINING_BLOCK_ID_DOMAIN, block_bytes)

    return [
        ("profile_label", "TEST_ONLY_PARAMETERS_NOT_APPROVED_FOR_NETWORK"),
        ("policy_fingerprint", policy_fp.hex()),
        ("qzgm_manifest_hash", qzgm_hash.hex()),
        ("qzgm_initial_state_root", qzgm_root.hex()),
        ("schedule_fingerprint", schedule_fp.hex()),
        ("profile_fingerprint", profile_fp.hex()),
        ("qzcp_profile_bytes", profile_bytes.hex()),
        ("qzcp_profile_length", str(len(profile_bytes))),
        ("transition_genesis_state_root", h(TRANSITION_ROOT_DOMAIN, profile_fp + genesis_ledger_root + accounting_commitment + be(0, 16)).hex()),
        ("block1_reward_atoms", str(reward)),
        ("block1_ledger_state_root", ledger1_root.hex()),
        ("block1_accounting_hex", block_accounting_bytes.hex()),
        ("block1_state_root", state_root1.hex()),
        ("qzb4_block1_bytes", block_bytes.hex()),
        ("qzb4_block1_id", block_id.hex()),
    ]


def rendered_vectors():
    lines = [
        "# CP-0398 independent QZCP/QZB4 vectors generated with Python standard library only.",
        "# Subsidy=10000 atoms and halving interval=2 are test fixtures, not approved economics.",
    ]
    lines.extend(f"{name}={value}" for name, value in derive())
    return "\n".join(lines) + "\n"


def main():
    if "--check" in sys.argv[1:]:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != rendered_vectors():
            raise SystemExit(
                "CP-0398 fixture differs from independent Python computation; "
                "run this script without --check to regenerate."
            )
        print("CP0398_V04_PROFILE_TRANSITION_ORACLE=PASS")
        for name, value in derive():
            if name in ("profile_fingerprint", "qzcp_profile_length", "block1_reward_atoms", "qzb4_block1_id"):
                print(f"{name}={value}")
        return
    OUT.write_text(rendered_vectors(), encoding="utf-8")
    print(f"wrote {OUT}")
    print(rendered_vectors(), end="")


if __name__ == "__main__":
    main()
