#!/usr/bin/env python3
"""Independent SHA-256 verification for the QRun v0.5 identity/Genesis candidate (not a launch check)."""
from hashlib import sha256
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((ROOT / "profiles/qrun_v05_mainnet_identity_candidate.json").read_text(encoding="utf-8"))
source = (ROOT / "src/native/pow_bench/src/qrun_v05_profile_identity_candidate.rs").read_text(encoding="utf-8")
doc = (ROOT / "docs/CP-0450_QRUN_V05_IDENTITY_CANDIDATE_2026-10-28.md").read_text(encoding="utf-8")

network_id = sha256(b"QUANTUMZXB-QRUN-MAINNET-NETWORK-ID-V05\0").digest()
owner = bytes.fromhex(manifest["owner_account_id_hex"])
amount = int(manifest["maximum_supply_atoms"])
assert len(owner) == 32
assert int(manifest["maximum_supply_coins"]) * int(manifest["atoms_per_coin"]) == amount == 1_000_000_000_000_000_000
assert network_id.hex() == manifest["network_id_hex"]

# Independently reproduce LedgerState::state_root for its sorted, one-account Genesis state.
canonical = (
    b"AIN1-STATE-V2\0" + network_id + (0).to_bytes(8, "big")
    + (0).to_bytes(8, "big") + (0).to_bytes(8, "big")
    + (1).to_bytes(4, "big") + owner + amount.to_bytes(8, "big")
    + (0).to_bytes(8, "big")
)
state_root = sha256(b"AIN1-STATE-ROOT-V2\0" + canonical).digest()
commitment = sha256(
    b"QUANTUMZXB-QRUN-GENESIS-V05\0" + network_id + owner
    + amount.to_bytes(16, "big") + state_root
).digest()
assert state_root.hex() == manifest["genesis_state_root_hex"]
assert commitment.hex() == manifest["genesis_commitment_hex"]

def rust_const_hex(name: str) -> str:
    match = re.search(rf"pub const {name}:[^=]*=\s*\[(.*?)\];", source, re.S)
    assert match, f"Rust source missing byte constant {name}"
    values = re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))
    result = bytes(int(value, 16) for value in values)
    assert len(result) == 32, f"{name} should be exactly 32 bytes"
    return result.hex()

assert rust_const_hex("PROPOSED_QRUN_V05_NETWORK_ID") == network_id.hex()
assert rust_const_hex("PROPOSED_OWNER_ACCOUNT_ID") == owner.hex()
assert rust_const_hex("PROPOSED_GENESIS_STATE_ROOT") == state_root.hex()
assert rust_const_hex("PROPOSED_GENESIS_COMMITMENT") == commitment.hex()
assert manifest["post_genesis_minting_enabled"] is False
assert manifest["miner_subsidy_atoms_per_block"] == "0"
assert manifest["mainnet_activated"] is False
gates = manifest["release_gates"]
assert gates["canonical_producer_importer_replay_wired"] is True
assert gates["fee_only_producer_payout_committed_in_block"] is True
assert all(
    value is False
    for key, value in gates.items()
    if key not in {
        "canonical_producer_importer_replay_wired",
        "fee_only_producer_payout_committed_in_block",
    }
)
assert "Mainnet remains **not activated**" in doc
print("QRUN_V05_IDENTITY_GENESIS_MANIFEST_ORACLE=PASS")
print(f"network_id={network_id.hex()}; owner={owner.hex()}")
print(f"supply_atoms={amount}; genesis_state_root={state_root.hex()}; genesis_commitment={commitment.hex()}")
print("candidate_qfp5_producer_importer_replay_wired=true; fee_only_payout_committed=true")
print("mainnet_activated=false; production_consensus_profile_frozen=false; checkpoint_rollover=false")