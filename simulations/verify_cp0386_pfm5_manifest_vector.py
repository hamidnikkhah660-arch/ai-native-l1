#!/usr/bin/env python3
"""Independent Python encoder/checker for the CP-0386 PFM5 Genesis manifest vector."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "src" / "native" / "pow_bench" / "tests" / "fixtures"
PCP4_META = FIX / "cp0384_pcp4_genesis_vector.json"
PCP4_HEX = FIX / "cp0384_pcp4_genesis_vector.hex"
PFM5_META = FIX / "cp0386_pfm5_genesis_manifest.json"
PFM5_HEX = FIX / "cp0386_pfm5_genesis_manifest.hex"
PCP4_CHECKSUM_DOMAIN = b"AIN1-PMT4-CHECKPOINT-CHECKSUM-V1\0"
PCP4_COMMITMENT_DOMAIN = b"AIN1-PMT4-CHECKPOINT-COMMITMENT-V1\0"
PFM5_CHECKSUM_DOMAIN = b"AIN1-PFM5-CHECKPOINT-MANIFEST-CHECKSUM-V1\0"
PFM5_COMMITMENT_DOMAIN = b"AIN1-PFM5-CHECKPOINT-MANIFEST-COMMITMENT-V1\0"
FIXED_PREFIX_BYTES = 380
CHECKSUM_BYTES = 32
MAX_BRANCHES = 4096


def u(value: int | str, width: int) -> bytes:
    n = int(value)
    if n < 0 or n >= 1 << (width * 8):
        raise ValueError(f"integer {n} does not fit in {width} bytes")
    return n.to_bytes(width, "big")


def h32(value: str) -> bytes:
    b = bytes.fromhex(value)
    if len(b) != 32:
        raise ValueError("expected a 32-byte hexadecimal field")
    return b


def domain_hash(domain: bytes, *parts: bytes) -> bytes:
    return hashlib.sha256(domain + b"".join(parts)).digest()


def main() -> int:
    pcp4_meta = json.loads(PCP4_META.read_text(encoding="utf-8"))
    pfm5_meta = json.loads(PFM5_META.read_text(encoding="utf-8"))
    pcp4 = bytes.fromhex(PCP4_HEX.read_text(encoding="ascii").strip())
    if pcp4[:4] != b"PCP4" or len(pcp4) != int.from_bytes(pcp4[8:12], "big"):
        raise ValueError("PCP4 source fixture has invalid magic or length")
    if domain_hash(PCP4_CHECKSUM_DOMAIN, pcp4[:-32]) != pcp4[-32:]:
        raise ValueError("PCP4 source fixture checksum mismatch")

    branches = [h32(value) for value in pfm5_meta["branch_digests_hex"]]
    if len(branches) > MAX_BRANCHES or branches != sorted(set(branches)):
        raise ValueError("PFM5 branch digest set is over-limit, duplicated or noncanonical")
    network = h32(pcp4_meta["network_id_hex"])
    profile = h32(pcp4_meta["profile_fingerprint_hex"])
    genesis = h32(pcp4_meta["genesis_fingerprint_hex"])
    parent = h32(pfm5_meta["parent_manifest_commitment_hex"])
    checkpoint_consensus_tip = h32(pcp4_meta["consensus_tip_digest_hex"])
    canonical_tip = h32(pfm5_meta["canonical_tip_digest_hex"])
    checkpoint_commitment = domain_hash(PCP4_COMMITMENT_DOMAIN, pcp4)
    generation = int(pfm5_meta["generation"])
    checkpoint_height = int(pcp4_meta["logical_height"])
    canonical_height = int(pfm5_meta["canonical_tip_height"])
    if generation <= 0 or ((generation == 1) != (parent == bytes(32))):
        raise ValueError("generation/parent linkage invalid")
    if canonical_height < checkpoint_height:
        raise ValueError("canonical tip predates checkpoint")
    if canonical_height == checkpoint_height and canonical_tip != checkpoint_consensus_tip:
        raise ValueError("checkpoint-height canonical tip must match the checkpoint")
    if canonical_height > checkpoint_height and canonical_tip not in branches:
        raise ValueError("canonical tip digest is absent from the branch set")
    if checkpoint_consensus_tip in branches:
        raise ValueError("checkpoint tip must not be repeated as a post-checkpoint branch")

    record_len = FIXED_PREFIX_BYTES + len(branches) * 32 + CHECKSUM_BYTES
    if record_len > FIXED_PREFIX_BYTES + MAX_BRANCHES * 32 + CHECKSUM_BYTES:
        raise ValueError("PFM5 record exceeds hard byte ceiling")
    out = bytearray()
    out.extend(b"PFM5")
    out.extend(u(pfm5_meta["schema_version"], 2))
    out.extend(u(0, 2))
    out.extend(u(record_len, 4))
    out.extend(network)
    out.extend(profile)
    out.extend(genesis)
    out.extend(u(generation, 8))
    out.extend(parent)
    out.extend(u(checkpoint_height, 8))
    out.extend(checkpoint_commitment)
    out.extend(u(len(pcp4), 4))
    out.extend(checkpoint_consensus_tip)
    out.extend(h32(pcp4_meta["ledger_tip_hash_hex"]))
    out.extend(h32(pcp4_meta["monetary_state_root_hex"]))
    out.extend(u(pcp4_meta["total_mined_atoms"], 16))
    out.extend(h32(pcp4_meta["cumulative_chainwork_hex"]))
    out.extend(u(canonical_height, 8))
    out.extend(canonical_tip)
    out.extend(u(len(branches), 4))
    for digest in branches:
        out.extend(digest)
    if len(out) + CHECKSUM_BYTES != record_len:
        raise ValueError("PFM5 fixed-prefix/count arithmetic mismatch")
    out.extend(domain_hash(PFM5_CHECKSUM_DOMAIN, bytes(out)))
    expected = bytes.fromhex(PFM5_HEX.read_text(encoding="ascii").strip())
    if bytes(out) != expected:
        raise ValueError("Python PFM5 bytes differ from the checked-in Rust golden vector")
    if len(expected) != int.from_bytes(expected[8:12], "big"):
        raise ValueError("PFM5 declared length mismatch")
    if domain_hash(PFM5_CHECKSUM_DOMAIN, expected[:-32]) != expected[-32:]:
        raise ValueError("PFM5 checksum mismatch")

    print("PFM5_GOLDEN_VECTOR=PASS")
    print(f"record_bytes={len(expected)}")
    print(f"checkpoint_commitment={checkpoint_commitment.hex()}")
    print(f"manifest_commitment={domain_hash(PFM5_COMMITMENT_DOMAIN, expected).hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())