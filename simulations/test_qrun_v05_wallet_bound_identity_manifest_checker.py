#!/usr/bin/env python3
"""Regression tests proving the CP-0468 checker remains fail-closed under python -O."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
CHECKER_NAME = "qrun_v05_wallet_bound_identity_manifest_checker.py"
RUNTIME_RELATIVE = Path("src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs")
CURRENT_MANIFEST = "qrun_v05_wallet_bound_mainnet_identity_candidate.json"
HISTORICAL_MANIFEST = "qrun_v05_mainnet_identity_candidate.json"


class OptimizedCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="qrun-identity-check-")
        self.root = Path(self.temp.name)
        (self.root / "simulations").mkdir()
        (self.root / "profiles").mkdir()
        (self.root / RUNTIME_RELATIVE).parent.mkdir(parents=True)
        shutil.copy2(
            SOURCE_ROOT / "simulations" / CHECKER_NAME,
            self.root / "simulations" / CHECKER_NAME,
        )
        shutil.copy2(
            SOURCE_ROOT / RUNTIME_RELATIVE,
            self.root / RUNTIME_RELATIVE,
        )
        for name in (CURRENT_MANIFEST, HISTORICAL_MANIFEST):
            shutil.copy2(
                SOURCE_ROOT / "profiles" / name,
                self.root / "profiles" / name,
            )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-O", str(self.root / "simulations" / CHECKER_NAME)],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_valid_manifest_passes_with_python_optimization(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("QRUN_CURRENT_WALLET_BOUND_IDENTITY_MANIFEST_PARITY=PASS", result.stdout)

    def test_manifest_runtime_mismatch_fails_with_python_optimization(self) -> None:
        path = self.root / "profiles" / CURRENT_MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["network_id_hex"] = "00" * 32
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("manifest/runtime mismatch for network_id_hex", result.stderr)

    def test_unselected_genesis_epoch_is_fail_closed_with_python_optimization(self) -> None:
        path = self.root / "profiles" / CURRENT_MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["genesis_time_anchor"]["timestamp_unix_seconds"] = 1_800_000_000
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("no Mainnet Genesis epoch may be invented", result.stderr)

    def test_attested_time_provider_is_not_claimed_as_bft_consensus_clock(self) -> None:
        path = self.root / "profiles" / CURRENT_MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["genesis_time_anchor"]["reference_time_authority_is_bft_consensus"] = True
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("without claiming a BFT consensus clock", result.stderr)

    def test_public_profile_must_bind_exact_signed_time_policy_digest(self) -> None:
        path = self.root / "profiles" / CURRENT_MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["genesis_time_anchor"]["public_profile_id_binds_reference_time_policy_digest"] = False
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("bind one exact authenticated time policy", result.stderr)

    def test_open_mainnet_gate_fails_with_python_optimization(self) -> None:
        path = self.root / RUNTIME_RELATIVE
        source = path.read_text(encoding="utf-8")
        old = "const QRUN_MAINNET_RELEASE_APPROVED: bool = false;"
        self.assertIn(old, source)
        path.write_text(
            source.replace(old, "const QRUN_MAINNET_RELEASE_APPROVED: bool = true;", 1),
            encoding="utf-8",
        )

        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Mainnet release gate must remain closed", result.stderr)


if __name__ == "__main__":
    unittest.main()
