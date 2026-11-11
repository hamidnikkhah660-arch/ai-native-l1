#!/usr/bin/env python3
"""Build and validate an explicitly non-production QFP6 candidate package."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, sys

SCHEMA = "qfp6-candidate-package/v1"
COMPONENTS = ("genesis_snapshot", "genesis_descriptor_q6gd", "consensus_profile_q6cp", "network_profile_q6pn", "trust_bundle_q6ts", "bootstrap_peers")


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def init_package(root: pathlib.Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "artifacts").mkdir(exist_ok=True)
    manifest = {
        "schema": SCHEMA,
        "network_name": "QZXB",
        "protocol_family": "QFP6",
        "release_channel": "candidate",
        "production_authorized": False,
        "mainnet_status": "NOT_AUTHORIZED",
        "owner_genesis_account": None,
        "components": {name: {"path": None, "sha256": None, "status": "MISSING"} for name in COMPONENTS},
        "independent_review": {"consensus": "PENDING", "cryptography": "PENDING", "economics": "PENDING"},
        "signing": {"q6ts_signatures_present": False, "trust_floor_provisioned": False},
        "runtime": {"wired": False, "full_history_replay_qualified": False, "public_listener_qualified": False},
        "notes": [
            "Candidate scaffold only. No Genesis, public keys, trust roots, signatures, or service endpoints are fabricated.",
            "Do not promote this manifest to Mainnet. Replace each missing component only with independently reviewed canonical artifacts.",
            "Q6CP candidate parameters and QFP6 SHA-256d easy-fixture targets are not Mainnet-approved."
        ]
    }
    target = root / "manifest.json"
    if target.exists():
        raise FileExistsError(f"refusing to overwrite existing manifest: {target}")
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (root / "README.txt").write_text(
        "QFP6 CANDIDATE PACKAGE\n\n"
        "This is a structural scaffold, not a deployable network release.\n"
        "Artifacts are intentionally absent until canonical inputs and independent trust material exist.\n"
        "Run: python tools/qfp6_candidate_package.py validate <package-directory>\n",
        encoding="utf-8")
    print(f"created candidate scaffold: {root.resolve()}")


def validate_package(root: pathlib.Path) -> int:
    manifest_path = root / "manifest.json"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"INVALID: cannot read manifest: {exc}")
        return 2
    errors, missing, checked = [], [], []
    if data.get("schema") != SCHEMA:
        errors.append("unsupported or missing schema")
    if data.get("protocol_family") != "QFP6" or data.get("network_name") != "QZXB":
        errors.append("wrong network/protocol identity")
    if data.get("production_authorized") is not False or data.get("mainnet_status") != "NOT_AUTHORIZED":
        errors.append("candidate package must remain explicitly non-production")
    components = data.get("components")
    if not isinstance(components, dict):
        errors.append("components object is missing")
        components = {}
    for name in COMPONENTS:
        item = components.get(name)
        if not isinstance(item, dict):
            missing.append(name)
            continue
        rel, expected = item.get("path"), item.get("sha256")
        if not rel or not expected:
            missing.append(name)
            continue
        if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            errors.append(f"{name}: sha256 must be 64 lowercase hex characters")
            continue
        artifact = (root / rel).resolve()
        try:
            artifact.relative_to(root.resolve())
        except ValueError:
            errors.append(f"{name}: artifact path escapes package directory")
            continue
        if not artifact.is_file() or artifact.is_symlink():
            errors.append(f"{name}: artifact missing or not a regular file")
            continue
        actual = sha256_file(artifact)
        if actual != expected:
            errors.append(f"{name}: SHA-256 mismatch")
        else:
            checked.append(name)
    if errors:
        print("INVALID: " + "; ".join(errors))
        return 2
    print(f"package_schema={SCHEMA}")
    print(f"artifacts_hash_verified={len(checked)}")
    print(f"artifacts_missing={len(missing)}" + (":" + ",".join(missing) if missing else ""))
    print("qfp6_package_status=CANDIDATE_SCAFFOLD_ONLY")
    print("mainnet_authorized=false")
    print("runtime_wired=false")
    print("public_mining_authorized=false")
    print("exit_status=" + ("INCOMPLETE" if missing else "HASHES_VALID_CANDIDATE_ONLY"))
    return 2 if missing else 0


def self_test() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(temp) / "package"
        init_package(root)
        code = validate_package(root)
        if code != 2:
            print("SELF-TEST FAILED: incomplete scaffold must fail closed")
            return 1
        m = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        sample = root / "artifacts" / "sample.bin"
        sample.write_bytes(b"qfp6-test")
        m["components"]["genesis_snapshot"] = {"path": "artifacts/sample.bin", "sha256": sha256_file(sample), "status": "CANDIDATE"}
        (root / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
        if validate_package(root) != 2:
            print("SELF-TEST FAILED: partially populated scaffold must remain incomplete")
            return 1
    print("SELF-TEST PASSED: missing artifacts fail closed; no production promotion")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_init = sub.add_parser("init")
    p_init.add_argument("directory", type=pathlib.Path)
    p_val = sub.add_parser("validate")
    p_val.add_argument("directory", type=pathlib.Path)
    sub.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "init":
        init_package(args.directory)
        return 0
    if args.command == "validate":
        return validate_package(args.directory)
    return self_test()

if __name__ == "__main__":
    raise SystemExit(main())
