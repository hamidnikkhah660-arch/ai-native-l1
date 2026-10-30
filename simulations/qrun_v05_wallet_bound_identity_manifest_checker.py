#!/usr/bin/env python3
"""Verify current wallet-bound QRun identity-manifest parity with runtime constants.

This is a consistency check, not an independent consensus/security audit.
The original CP-0450 manifest/oracle remains unchanged as historical evidence.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads(
    (ROOT / "profiles/qrun_v05_wallet_bound_mainnet_identity_candidate.json")
    .read_text(encoding="utf-8")
)
source = (
    ROOT / "src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs"
).read_text(encoding="utf-8")
historical = json.loads(
    (ROOT / "profiles/qrun_v05_mainnet_identity_candidate.json")
    .read_text(encoding="utf-8")
)


def require(condition: bool, message: str) -> None:
    """Fail closed even when Python is invoked with optimization (-O)."""
    if not condition:
        raise SystemExit(f"QRUN_IDENTITY_MANIFEST_CHECK_FAILED: {message}")


def rust_const_bytes(name: str) -> str:
    match = re.search(
        rf"const {re.escape(name)}:\s*[^=]*=\s*\[(.*?)\];",
        source,
        re.S,
    )
    require(match is not None, f"Rust source missing byte constant {name}")
    values = re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))
    value = bytes(int(item, 16) for item in values)
    require(len(value) == 32, f"{name} must contain exactly 32 bytes")
    return value.hex()


def rust_const_string(name: str) -> str:
    match = re.search(
        rf'const {re.escape(name)}:\s*[^=]*=\s*"([0-9a-fA-F]+)"',
        source,
        re.S,
    )
    require(match is not None, f"Rust source missing string constant {name}")
    value = match.group(1).lower()
    require(len(value) == 64, f"{name} must be a 32-byte hex string")
    return value


runtime_values = {
    "network_id_hex": rust_const_bytes("QZXB_MAINNET_NETWORK_ID"),
    "owner_account_id_hex": rust_const_bytes("QZXB_MAINNET_OWNER_ACCOUNT_ID"),
    "owner_public_key_hex": rust_const_bytes("QZXB_MAINNET_OWNER_PUBLIC_KEY"),
    "genesis_id_hex": rust_const_string("QZXB_MAINNET_GENESIS_ID_HEX"),
    "profile_id_hex": rust_const_string("QZXB_MAINNET_PROFILE_ID_HEX"),
    "genesis_state_root_hex": rust_const_string("QZXB_MAINNET_STATE_ROOT_HEX"),
}
for field, expected in runtime_values.items():
    actual = manifest[field].lower()
    require(
        actual == expected,
        f"manifest/runtime mismatch for {field}: manifest={actual} runtime={expected}",
    )

approved = re.search(
    r"const QRUN_MAINNET_RELEASE_APPROVED:\s*bool\s*=\s*(true|false)\s*;",
    source,
)
require(approved is not None, "Rust source missing Mainnet release gate")
require(approved.group(1) == "false", "Mainnet release gate must remain closed")
require(manifest["mainnet_activated"] is False, "manifest must not claim Mainnet activation")
require(
    manifest["post_genesis_minting_enabled"] is False,
    "post-Genesis minting must remain disabled",
)
require(
    manifest["miner_subsidy_atoms_per_block"] == "0",
    "block subsidy must remain zero",
)
supply = int(manifest["maximum_supply_atoms"])
require(
    int(manifest["maximum_supply_coins"]) * int(manifest["atoms_per_coin"]) == supply,
    "maximum coin supply and atomic-unit supply do not match",
)
require(supply == 1_000_000_000_000_000_000, "fixed supply atoms do not match the 10B target")
require(
    int(manifest["genesis_owner_balance_atoms"]) == supply,
    "Genesis owner balance must equal the fixed supply target",
)
gates = manifest["release_gates"]
require(
    gates["canonical_producer_importer_replay_wired"] is True,
    "canonical producer/importer/replay wiring evidence must remain true",
)
require(
    gates["fee_only_producer_payout_committed_in_block"] is True,
    "fee-only producer payout evidence must remain true",
)
closed_gates = {
    key: value
    for key, value in gates.items()
    if key not in {
        "canonical_producer_importer_replay_wired",
        "fee_only_producer_payout_committed_in_block",
    }
}
require(
    all(value is False for value in closed_gates.values()),
    f"release gates must remain closed unless explicitly evidenced: {closed_gates}",
)

old_network = historical["network_id_hex"].lower()
require(
    old_network == manifest["historical_candidate"]["network_id_hex"].lower(),
    "historical CP-0450 manifest identity changed",
)
require(
    old_network != manifest["network_id_hex"].lower(),
    "historical and current candidate network identities must remain distinct",
)

print("QRUN_CURRENT_WALLET_BOUND_IDENTITY_MANIFEST_PARITY=PASS")
print(f"network_id={runtime_values['network_id_hex']}")
print(f"owner_account_id={runtime_values['owner_account_id_hex']}")
print(f"genesis_id={runtime_values['genesis_id_hex']}")
print(f"profile_id={runtime_values['profile_id_hex']}")
print(f"state_root={runtime_values['genesis_state_root_hex']}")
print(f"fixed_supply_atoms={supply}; minting=false; block_subsidy_atoms=0")
print(f"historical_CP0450_network_id={old_network} (distinct; retained unchanged)")
print("mainnet_release_approved=false; public_mainnet_activation=false")
