#!/usr/bin/env python3
"""Mutation tests for the QRun v0.5 cross-language profile fingerprint oracle."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
CHECKER = "qrun_v05_consensus_profile_conformance.py"
PROFILE = "qrun_v05_consensus_calibration_candidate.json"
IDENTITY = "qrun_v05_wallet_bound_mainnet_identity_candidate.json"


class ConsensusProfileConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="qrun-profile-conformance-")
        self.root = Path(self.temp.name)
        (self.root / "simulations").mkdir()
        (self.root / "profiles").mkdir()
        shutil.copy2(SOURCE_ROOT / "simulations" / CHECKER, self.root / "simulations" / CHECKER)
        for filename in (PROFILE, IDENTITY):
            shutil.copy2(SOURCE_ROOT / "profiles" / filename, self.root / "profiles" / filename)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-O", str(self.root / "simulations" / CHECKER)],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )

    def edit_json(self, filename: str, edit) -> None:
        path = self.root / "profiles" / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        edit(data)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def test_candidate_profile_matches_wallet_bound_runtime_fingerprint(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("QRUN_V05_CONSENSUS_PROFILE_CROSS_LANGUAGE=PASS", result.stdout)
        self.assertIn("75596fa188dc308088efc6b138e9fcd50be6de82ec2bc117c13e81d7eebfdb09",
                      result.stdout)

    def test_pow_memory_mutation_cannot_keep_the_frozen_profile_id(self) -> None:
        self.edit_json(PROFILE, lambda data: data["pow"].update(memory_kib=32768))
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("PoW parameters differ", result.stderr)

    def test_initial_target_mutation_fails_calibration_reproduction(self) -> None:
        self.edit_json(
            PROFILE,
            lambda data: data["difficulty"].update(initial_target_hex="00" * 32),
        )
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("initial target does not match", result.stderr)

    def test_wallet_network_or_genesis_mutation_fails_profile_binding(self) -> None:
        self.edit_json(IDENTITY, lambda data: data.update(network_id_hex="11" * 32))
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("calibrated consensus fields do not reproduce", result.stderr)

    def test_fee_only_interval_mutation_fails_profile_binding(self) -> None:
        self.edit_json(PROFILE, lambda data: data["issuance"].update(blocks_per_halving=2))
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("fee-only issuance profile must retain its canonical nonzero interval", result.stderr)

    def test_mainnet_or_mint_activation_claim_is_rejected(self) -> None:
        self.edit_json(PROFILE, lambda data: data.update(mainnet_activated=True))
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("must not claim Mainnet activation", result.stderr)


if __name__ == "__main__":
    unittest.main()
