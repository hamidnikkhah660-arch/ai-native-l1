#!/usr/bin/env python3
"""Build and validate an explicitly non-production QFP6 candidate package."""
from __future__ import annotations
import argparse, hashlib, json, pathlib

SCHEMA = "qfp6-candidate-package/v1"
COMPONENTS = ("genesis_snapshot", "genesis_descriptor_q6gd", "consensus_profile_q6cp", "network_profile_q6pn", "trust_bundle_q6ts", "bootstrap_peers")
ACCOUNT_DOMAIN = b"AIN1-QFP6-ACCOUNT-ID-HYBRID-V1\0"
ED25519_PUBLIC_KEY_BYTES = 32
MLDSA65_PUBLIC_KEY_BYTES = 1952


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def founder_account_id(ed25519: bytes, mldsa65: bytes) -> bytes:
    if len(ed25519) != ED25519_PUBLIC_KEY_BYTES or len(mldsa65) != MLDSA65_PUBLIC_KEY_BYTES:
        raise ValueError("founder public-key lengths do not match the QFP6 hybrid suite")
    return hashlib.sha256(ACCOUNT_DOMAIN + (1).to_bytes(2, "big") + ed25519 + mldsa65).digest()


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
        "founder_identity": None,
        "components": {name: {"path": None, "sha256": None, "status": "MISSING"} for name in COMPONENTS},
        "independent_review": {"consensus": "PENDING", "cryptography": "PENDING", "economics": "PENDING"},
        "signing": {"q6ts_signatures_present": False, "trust_floor_provisioned": False},
        "runtime": {"wired": False, "full_history_replay_qualified": False, "public_listener_qualified": False},
        "notes": [
            "Candidate scaffold only. No Genesis, trust roots, signatures, or service endpoints are fabricated.",
            "Founder identity, when bound, is public-key metadata only and does not authorize or sign a Genesis.",
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
        "Optional founder binding stores public keys only; it does not sign or authorize Genesis.\n"
        "Run: python tools/qfp6_candidate_package.py validate <package-directory>\n",
        encoding="utf-8")
    print(f"created candidate scaffold: {root.resolve()}")


def bind_founder(root: pathlib.Path, identity_path: pathlib.Path) -> int:
    manifest_path = root / "manifest.json"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        identity = json.loads(identity_path.read_text(encoding="utf-8-sig"))
        ed = bytes.fromhex(identity["ed25519_public_key_hex"])
        pq = bytes.fromhex(identity["mldsa65_public_key_hex"])
        account_hex = identity.get("public_account_id_hex", identity.get("account_id_hex"))
        supplied_account = bytes.fromhex(account_hex)
        calculated = founder_account_id(ed, pq)
    except Exception as exc:
        print(f"INVALID: cannot bind founder identity: {exc}")
        return 2
    if len(supplied_account) != 32 or supplied_account != calculated:
        print("INVALID: founder account ID does not match the QFP6 hybrid public-key derivation")
        return 2
    if data.get("schema") != SCHEMA or data.get("protocol_family") != "QFP6":
        print("INVALID: unsupported candidate manifest")
        return 2
    if data.get("production_authorized") is not False or data.get("mainnet_status") != "NOT_AUTHORIZED":
        print("INVALID: refusing to bind identity to a production-authorized manifest")
        return 2
    data["founder_identity"] = {
        "status": "PUBLIC_KEYS_BOUND_CANDIDATE_ONLY",
        "derivation": "AIN1-QFP6-ACCOUNT-ID-HYBRID-V1",
        "public_account_id_hex": supplied_account.hex(),
        "ed25519_public_key_hex": ed.hex(),
        "mldsa65_public_key_hex": pq.hex(),
        "private_key_material_included": False,
        "genesis_signature_present": False
    }
    data["owner_genesis_account"] = supplied_account.hex()
    manifest_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("founder_identity_binding=VALID")
    print(f"public_account_id_hex={supplied_account.hex()}")
    print("private_key_material_included=false")
    print("genesis_signature_present=false")
    print("mainnet_authorized=false")
    return 0


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
    founder = data.get("founder_identity")
    if founder is not None:
        try:
            ed = bytes.fromhex(founder["ed25519_public_key_hex"])
            pq = bytes.fromhex(founder["mldsa65_public_key_hex"])
            account = bytes.fromhex(founder["public_account_id_hex"])
            if founder.get("status") != "PUBLIC_KEYS_BOUND_CANDIDATE_ONLY":
                raise ValueError("founder identity status is not candidate-only")
            if founder.get("private_key_material_included") is not False or founder.get("genesis_signature_present") is not False:
                raise ValueError("candidate identity must contain no private key or Genesis signature")
            if founder_account_id(ed, pq) != account or data.get("owner_genesis_account") != account.hex():
                raise ValueError("founder account ID/public-key binding mismatch")
        except Exception as exc:
            errors.append(f"founder identity invalid: {exc}")
    elif data.get("owner_genesis_account") is not None:
        errors.append("owner_genesis_account is set without a validated founder_identity")
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
    print("founder_identity_status=" + ("PUBLIC_KEYS_BOUND_CANDIDATE_ONLY" if founder else "NOT_BOUND"))
    print("qfp6_package_status=CANDIDATE_SCAFFOLD_ONLY")
    print("mainnet_authorized=false")
    runtime = data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
    print("runtime_wired=" + str(runtime.get("wired") is True).lower())
    print("public_mining_authorized=false")
    print("exit_status=" + ("INCOMPLETE" if missing else "HASHES_VALID_CANDIDATE_ONLY"))
    return 2 if missing else 0


def self_test() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(temp) / "package"
        init_package(root)
        if validate_package(root) != 2:
            print("SELF-TEST FAILED: incomplete scaffold must fail closed")
            return 1
        ed, pq = bytes(range(32)), bytes((i % 251 for i in range(MLDSA65_PUBLIC_KEY_BYTES)))
        account = founder_account_id(ed, pq)
        manifest_path = root / "manifest.json"
        m = json.loads(manifest_path.read_text(encoding="utf-8"))
        m["founder_identity"] = {
            "status": "PUBLIC_KEYS_BOUND_CANDIDATE_ONLY",
            "derivation": "AIN1-QFP6-ACCOUNT-ID-HYBRID-V1",
            "public_account_id_hex": account.hex(),
            "ed25519_public_key_hex": ed.hex(),
            "mldsa65_public_key_hex": pq.hex(),
            "private_key_material_included": False,
            "genesis_signature_present": False
        }
        m["owner_genesis_account"] = account.hex()
        manifest_path.write_text(json.dumps(m), encoding="utf-8")
        if validate_package(root) != 2:
            print("SELF-TEST FAILED: valid founder binding must not promote incomplete package")
            return 1
        m["owner_genesis_account"] = "00" * 32
        manifest_path.write_text(json.dumps(m), encoding="utf-8")
        if validate_package(root) != 2:
            print("SELF-TEST FAILED: mismatched founder account must fail closed")
            return 1
    print("SELF-TEST PASSED: founder identity binding is verified; incomplete package remains non-production")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_init = sub.add_parser("init")
    p_init.add_argument("directory", type=pathlib.Path)
    p_val = sub.add_parser("validate")
    p_val.add_argument("directory", type=pathlib.Path)
    p_bind = sub.add_parser("bind-founder")
    p_bind.add_argument("directory", type=pathlib.Path)
    p_bind.add_argument("--identity-json", required=True, type=pathlib.Path)
    sub.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "init":
        init_package(args.directory)
        return 0
    if args.command == "validate":
        return validate_package(args.directory)
    if args.command == "bind-founder":
        return bind_founder(args.directory, args.identity_json)
    return self_test()


if __name__ == "__main__":
    raise SystemExit(main())
