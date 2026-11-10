#!/usr/bin/env python3
"""Independent QFP6 SHA-256d header serialization and digest reference.

Uses only Python's standard library. This implementation is intentionally separate from
the Rust consensus code and reconstructs the canonical preimage from typed fields.
The bundled vectors are non-production fixtures, not mined blocks.
"""
from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path
from typing import Any

VECTOR_PATH = Path(__file__).with_name("qfp6_sha256d_conformance_vectors.json")
POW_DOMAIN = b"AIN1-POW-V1\x00"
HEADER_BYTES = 198


def _hex_bytes(value: Any, name: str, expected_len: int) -> bytes:
    if not isinstance(value, str) or len(value) != expected_len * 2:
        raise ValueError(f"{name} must be exactly {expected_len} bytes of hexadecimal")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} is not valid hexadecimal") from exc
    if len(result) != expected_len:
        raise ValueError(f"{name} must be exactly {expected_len} bytes")
    return result


def _u64(value: Any, name: str) -> bytes:
    # bool is a subclass of int in Python; explicitly reject it.
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
        raise ValueError(f"{name} must be an unsigned 64-bit integer")
    return struct.pack(">Q", value)


def encode_header(fields: dict[str, Any]) -> bytes:
    """Encode the QFP6 PoW header using the protocol's fixed-width big-endian layout."""
    if not isinstance(fields, dict):
        raise ValueError("fields must be an object")

    version = fields.get("protocol_version")
    if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version < 2**16:
        raise ValueError("protocol_version must be a nonzero unsigned 16-bit integer")

    network_id = _hex_bytes(fields.get("network_id_hex"), "network_id", 32)
    if network_id == bytes(32):
        raise ValueError("network_id must not be zero")

    parent = _hex_bytes(fields.get("parent_hash_hex"), "parent_hash", 32)
    previous = _hex_bytes(
        fields.get("previous_consensus_hash_hex"), "previous_consensus_hash", 32
    )
    state_root = _hex_bytes(fields.get("state_root_hex"), "state_root", 32)
    target = _hex_bytes(fields.get("target_hex"), "target", 32)
    if target == bytes(32):
        raise ValueError("target must not be zero")

    nonce = _u64(fields.get("nonce"), "nonce")
    encoded = b"".join(
        (
            POW_DOMAIN,
            struct.pack(">H", version),
            network_id,
            _u64(fields.get("height"), "height"),
            _u64(fields.get("timestamp"), "timestamp"),
            parent,
            previous,
            state_root,
            target,
            nonce,
        )
    )
    if len(encoded) != HEADER_BYTES:
        raise AssertionError(f"canonical QFP6 header length changed: {len(encoded)}")
    return encoded


def sha256d(preimage: bytes) -> bytes:
    """Return SHA256(SHA256(preimage)) as 32 raw bytes."""
    return hashlib.sha256(hashlib.sha256(preimage).digest()).digest()


def meets_target(digest: bytes, target: bytes) -> bool:
    """Compare both 32-byte values as unsigned big-endian integers."""
    if len(digest) != 32 or len(target) != 32:
        raise ValueError("digest and target must each be exactly 32 bytes")
    if target == bytes(32):
        raise ValueError("target must not be zero")
    return int.from_bytes(digest, "big") <= int.from_bytes(target, "big")


def load_vectors() -> dict[str, Any]:
    with VECTOR_PATH.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if value.get("schema") != "QFP6_SHA256D_CONFORMANCE_V1":
        raise ValueError("unsupported vector schema")
    vectors = value.get("vectors")
    if not isinstance(vectors, list) or len(vectors) < 2:
        raise ValueError("at least two conformance vectors are required")
    return value


class Sha256dReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = load_vectors()

    def test_independent_header_bytes_and_sha256d_vectors(self) -> None:
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                encoded = encode_header(vector["fields"])
                self.assertEqual(encoded.hex(), vector["expected_header_hex"])
                digest = sha256d(encoded)
                self.assertEqual(digest.hex(), vector["expected_sha256d_hex"])
                target = bytes.fromhex(vector["fields"]["target_hex"])
                self.assertEqual(
                    meets_target(digest, target), vector["expected_meets_target"]
                )

    def test_header_mutation_changes_digest(self) -> None:
        vector = self.document["vectors"][0]
        original = encode_header(vector["fields"])
        altered_fields = dict(vector["fields"])
        altered_fields["nonce"] += 1
        altered = encode_header(altered_fields)
        self.assertNotEqual(original, altered)
        self.assertNotEqual(sha256d(original), sha256d(altered))

    def test_rejects_invalid_consensus_fields(self) -> None:
        base = dict(self.document["vectors"][0]["fields"])
        invalid_cases = []
        zero_network = dict(base)
        zero_network["network_id_hex"] = "00" * 32
        invalid_cases.append(zero_network)
        zero_target = dict(base)
        zero_target["target_hex"] = "00" * 32
        invalid_cases.append(zero_target)
        zero_version = dict(base)
        zero_version["protocol_version"] = 0
        invalid_cases.append(zero_version)
        boolean_height = dict(base)
        boolean_height["height"] = True
        invalid_cases.append(boolean_height)
        for fields in invalid_cases:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    encode_header(fields)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Sha256dReferenceTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
