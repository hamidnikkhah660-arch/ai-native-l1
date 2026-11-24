#!/usr/bin/env python3
"""Unit tests for the Railway entrypoint's independently pinned anchor input."""
from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import patch

ENTRYPOINT_PATH = Path(__file__).with_name("entrypoint.py")
SPEC = importlib.util.spec_from_file_location("qfp6_railway_entrypoint", ENTRYPOINT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load QFP6 Railway entrypoint for tests")
ENTRYPOINT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENTRYPOINT)


class TrustedManifestAnchorEnvironmentTests(unittest.TestCase):
    VARIABLE = "QFP6_TRUSTED_MANIFEST_ANCHOR"

    def read_with(self, value: str | None) -> str | None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(self.VARIABLE, None)
            if value is not None:
                os.environ[self.VARIABLE] = value
            return ENTRYPOINT.trusted_manifest_anchor_from_env()

    def test_missing_anchor_is_omitted_for_fresh_genesis(self) -> None:
        self.assertIsNone(self.read_with(None))

    def test_empty_anchor_is_treated_as_unset(self) -> None:
        self.assertIsNone(self.read_with("  "))

    def test_valid_lowercase_32_byte_anchor_is_returned_unchanged(self) -> None:
        anchor = "ab" * 32
        self.assertEqual(self.read_with(anchor), anchor)

    def test_uppercase_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "64 lowercase hexadecimal"):
            self.read_with("AB" * 32)

    def test_wrong_length_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "64 lowercase hexadecimal"):
            self.read_with("ab" * 31)

    def test_non_hexadecimal_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "64 lowercase hexadecimal"):
            self.read_with("g0" * 32)

    def test_zero_anchor_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "must not be zero"):
            self.read_with("0" * 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
