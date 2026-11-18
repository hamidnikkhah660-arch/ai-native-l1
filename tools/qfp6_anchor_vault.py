#!/usr/bin/env python3
"""Owner-controlled, local dual-disk QFP6 anchor vault.

The QFP6 data directory remains on D:. By default this vault lives below
%LOCALAPPDATA% on C:. It detects D:-only rollback while C: remains intact.
It is NOT a TPM monotonic counter and cannot defeat full-machine/two-disk rollback.
The launcher must independently verify this vault before trusting its anchor.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

MANIFEST_DOMAIN = b"QRUN-V06-DURABLE-FORK-STORE-COMMITMENT-V1\0"
VAULT_DOMAIN = b"QFP6-LOCAL-ANCHOR-VAULT-RECORD-V1\0"
SCHEMA = "qfp6-local-anchor-vault/v1"
MANIFEST_RE = re.compile(r"^qfp6-manifest-(\d{20})\.q6mf$")
RECORD_RE = re.compile(r"^q6av-(\d{20})\.json$")
WITNESS_RE = re.compile(r"^q6sw-(\d{20})\.json$")
MAX_RECORDS = 100_000
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_WITNESS_BYTES = 8192
MAX_CHECKPOINT_BYTES = 72 * 1024 * 1024
WITNESS_DOMAIN = b"QFP6-CHECKPOINT-SEGMENT-WITNESS-V1\0"
CHECKPOINT_COMMITMENT_DOMAIN = b"QRUN-V06-CHECKPOINT-COMMITMENT-V3\0"
CHECKPOINT_CHECKSUM_DOMAIN = b"QRUN-V06-CHECKPOINT-CHECKSUM-V3\0"


class VaultError(RuntimeError):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hex32(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise VaultError(f"{label} must be exactly 64 lowercase hexadecimal characters")
    return bytes.fromhex(value)


def default_vault_dir() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise VaultError("LOCALAPPDATA is unavailable; pass --vault-dir explicitly")
    root = Path(local)
    if root.drive.upper() != "C:":
        raise VaultError("default local anchor vault must be on C: (the separate Kingston SSD)")
    return root / "AI_NATIVE_L1" / "QFP6" / "anchor-vault"


def real_directory(path: Path, label: str, must_exist: bool = True) -> None:
    if path.is_symlink():
        raise VaultError(f"{label} must not be a symlink")
    if not path.exists():
        if must_exist:
            raise VaultError(f"{label} does not exist: {path}")
        return
    if not path.is_dir():
        raise VaultError(f"{label} must be a directory: {path}")


def package_paths(package: Path) -> tuple[Path, Path, Path, Path]:
    package = package.resolve()
    if not package.is_dir():
        raise VaultError(f"package directory not found: {package}")
    config_path = package / "permissionless-config.json"
    manifest_path = package / "local-devnet-manifest.json"
    q6ga_path = package / "genesis-owner-approval.q6ga"
    for p in (config_path, manifest_path, q6ga_path):
        if p.is_symlink() or not p.is_file():
            raise VaultError(f"required package file missing or symlinked: {p}")
    return package, config_path, manifest_path, q6ga_path


def load_package(package: Path | str, allow_config_manifest_mismatch: bool = False) -> dict[str, Any]:
    package = Path(package)
    package, config_path, manifest_path, q6ga_path = package_paths(package)
    config_bytes = config_path.read_bytes()
    manifest_bytes = manifest_path.read_bytes()
    config = json.loads(config_bytes)
    manifest = json.loads(manifest_bytes)
    runtime = config.get("permissionless_runtime")
    if not isinstance(runtime, dict):
        raise VaultError("permissionless_runtime must be an object")
    if manifest.get("schema") != "qfp6-local-only-devnet/v1":
        raise VaultError("not a QFP6 local-only devnet package")
    if manifest.get("scope") != "LOCAL_SINGLE_OPERATOR_LOOPBACK_ONLY":
        raise VaultError("package scope is not local single-operator loopback")
    if runtime.get("listen_address") != "127.0.0.1:30333":
        raise VaultError("refusing a non-loopback listen address")
    if runtime.get("allow_public_listener") is not False:
        raise VaultError("public listener must remain disabled")
    if runtime.get("enable_approved_peer_outbound_sync") is not False:
        raise VaultError("approved peer outbound sync must remain disabled for local-only vault")
    if manifest.get("public_testnet_authorized") is not False or manifest.get("mainnet_authorized") is not False:
        raise VaultError("public Testnet/Mainnet authorization must remain false")

    actual_config_hash = sha256_hex(config_bytes)
    config_manifest_match = manifest.get("permissionless_config_sha256") == actual_config_hash
    if not config_manifest_match and not allow_config_manifest_mismatch:
        raise VaultError("local-devnet-manifest does not pin the exact permissionless config bytes")
    q6ga_hash = sha256_hex(q6ga_path.read_bytes())
    if runtime.get("owner_genesis_approval_sha256") != q6ga_hash:
        raise VaultError("Q6GA hash does not match permissionless config")
    if manifest.get("owner_genesis_approval_sha256") != q6ga_hash:
        raise VaultError("Q6GA hash does not match local-devnet manifest")

    network = hex32(manifest.get("network_id_hex"), "network_id_hex")
    profile = hex32(manifest.get("profile_id_hex"), "profile_id_hex")
    config_anchor = hex32(runtime.get("trusted_manifest_anchor"), "trusted_manifest_anchor")

    data_rel = runtime.get("data_directory")
    if not isinstance(data_rel, str) or not data_rel.strip():
        raise VaultError("permissionless_runtime.data_directory is required")
    data_dir = Path(data_rel)
    if not data_dir.is_absolute():
        data_dir = package / data_dir
    if data_dir.is_symlink() or not data_dir.is_dir():
        raise VaultError(f"QFP6 data directory missing or symlinked: {data_dir}")
    manifests_dir = data_dir / "manifests"
    real_directory(manifests_dir, "QFP6 manifests directory")

    manifest_files: list[tuple[int, Path]] = []
    for entry in manifests_dir.iterdir():
        match = MANIFEST_RE.fullmatch(entry.name)
        if not match:
            raise VaultError(f"unexpected entry in manifest directory: {entry.name}")
        if entry.is_symlink() or not entry.is_file():
            raise VaultError(f"manifest must be a regular file: {entry.name}")
        generation = int(match.group(1))
        manifest_files.append((generation, entry))
    manifest_files.sort(key=lambda pair: pair[0])
    if not manifest_files:
        raise VaultError("no durable QFP6 manifests found")
    if len(manifest_files) > MAX_RECORDS:
        raise VaultError("manifest count exceeds safety limit")
    for expected, (actual, _) in enumerate(manifest_files):
        if expected != actual:
            raise VaultError(f"manifest generation gap: expected {expected}, found {actual}")

    latest_generation, latest_path = manifest_files[-1]
    if latest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise VaultError("latest QFP6 manifest exceeds size limit")
    latest_bytes = latest_path.read_bytes()
    latest_anchor = hashlib.sha256(MANIFEST_DOMAIN + latest_bytes).digest()

    return {
        "package": package,
        "config_path": config_path,
        "manifest_path": manifest_path,
        "config": config,
        "manifest": manifest,
        "config_bytes": config_bytes,
        "manifest_bytes": manifest_bytes,
        "config_hash": actual_config_hash,
        "config_manifest_match": config_manifest_match,
        "network": network,
        "profile": profile,
        "config_anchor": config_anchor,
        "generation": latest_generation,
        "anchor": latest_anchor,
        "data_dir": data_dir,
    }


def record_digest(record: dict[str, Any]) -> str:
    seq = int(record["sequence"])
    generation = int(record["manifest_generation"])
    payload = (
        VAULT_DOMAIN
        + seq.to_bytes(8, "big")
        + hex32(record["network_id_hex"], "network_id_hex")
        + hex32(record["profile_id_hex"], "profile_id_hex")
        + generation.to_bytes(8, "big")
        + hex32(record["manifest_anchor_hex"], "manifest_anchor_hex")
        + hex32(record["previous_record_sha256"], "previous_record_sha256")
    )
    return sha256_hex(payload)


def vault_records_dir(vault_dir: Path, create: bool = False) -> Path:
    if create:
        vault_dir.mkdir(parents=True, exist_ok=True)
    real_directory(vault_dir, "anchor vault directory", must_exist=not create)
    records = vault_dir / "records"
    if create:
        records.mkdir(exist_ok=True)
    real_directory(records, "anchor vault records directory", must_exist=not create)
    return records


def load_vault(vault_dir: Path) -> list[dict[str, Any]]:
    records_dir = vault_records_dir(vault_dir)
    files: list[tuple[int, Path]] = []
    for entry in records_dir.iterdir():
        match = RECORD_RE.fullmatch(entry.name)
        if not match:
            raise VaultError(f"unexpected anchor vault entry: {entry.name}")
        if entry.is_symlink() or not entry.is_file() or entry.stat().st_size > 4096:
            raise VaultError(f"anchor record must be a bounded regular file: {entry.name}")
        files.append((int(match.group(1)), entry))
    files.sort(key=lambda pair: pair[0])
    if not files:
        raise VaultError("anchor vault has no records")
    if len(files) > MAX_RECORDS:
        raise VaultError("anchor vault record count exceeds safety limit")

    result: list[dict[str, Any]] = []
    previous_digest = "00" * 32
    previous_generation = -1
    previous_network: bytes | None = None
    previous_profile: bytes | None = None
    for expected_sequence, (actual_sequence, path) in enumerate(files, start=1):
        if actual_sequence != expected_sequence:
            raise VaultError(f"anchor vault sequence gap: expected {expected_sequence}, found {actual_sequence}")
        record = json.loads(path.read_bytes())
        if record.get("schema") != SCHEMA:
            raise VaultError(f"unsupported anchor record schema: {path.name}")
        if record.get("sequence") != expected_sequence:
            raise VaultError(f"anchor record sequence mismatch: {path.name}")
        if record.get("previous_record_sha256") != previous_digest:
            raise VaultError(f"anchor record chain mismatch: {path.name}")
        network = hex32(record.get("network_id_hex"), "network_id_hex")
        profile = hex32(record.get("profile_id_hex"), "profile_id_hex")
        hex32(record.get("manifest_anchor_hex"), "manifest_anchor_hex")
        generation = record.get("manifest_generation")
        if not isinstance(generation, int) or generation < 0:
            raise VaultError(f"anchor generation is invalid: {path.name}")
        if previous_generation >= 0 and generation != previous_generation + 1:
            raise VaultError(f"anchor generation gap: expected {previous_generation + 1}, found {generation}")
        digest = record.get("record_sha256")
        if digest != record_digest(record):
            raise VaultError(f"anchor record checksum mismatch: {path.name}")
        if previous_network is not None and network != previous_network:
            raise VaultError("anchor vault network identity changed")
        if previous_profile is not None and profile != previous_profile:
            raise VaultError("anchor vault profile identity changed")
        previous_digest = digest
        previous_generation = generation
        previous_network = network
        previous_profile = profile
        result.append(record)
    return result


def witness_u64(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise VaultError(f"{label} must be an unsigned 64-bit integer")
    return value


def checkpoint_witness_digest(witness: dict[str, Any]) -> str:
    # Keep this byte order identical to witness_digest() in the Rust vault implementation.
    ordered = bytearray(WITNESS_DOMAIN)
    for key in ("sequence", "predecessor_vault_sequence", "predecessor_global_generation"):
        ordered.extend(witness_u64(witness.get(key), key).to_bytes(8, "big"))
    for key in (
        "predecessor_manifest_anchor_hex",
        "predecessor_record_digest_hex",
        "checkpoint_commitment_hex",
        "segment_root_manifest_anchor_hex",
    ):
        ordered.extend(hex32(witness.get(key), key))
    ordered.extend(witness_u64(witness.get("checkpoint_base_height"), "checkpoint_base_height").to_bytes(8, "big"))
    for key in (
        "checkpoint_tip_hash_hex",
        "checkpoint_state_root_hex",
        "checkpoint_cumulative_work_hex",
        "network_id_hex",
        "profile_id_hex",
        "genesis_descriptor_commitment_hex",
        "consensus_fingerprint_hex",
        "previous_witness_digest_hex",
    ):
        ordered.extend(hex32(witness.get(key), key))
    return sha256_hex(bytes(ordered))


def effective_package_tip(
    state: dict[str, Any], vault_dir: Path, records: list[dict[str, Any]]
) -> tuple[int, bytes]:
    """Verify either the original Genesis-rooted package or its witnessed checkpoint segments."""
    base_generation = state["generation"]
    base_anchor = state["anchor"]
    witness_dir = vault_dir / "checkpoint-segment-witnesses"
    segment_root = state["data_dir"].parent / f"{state['data_dir'].name}.checkpoint-segments"

    if not witness_dir.exists():
        if segment_root.exists():
            raise VaultError("checkpoint segment data exists without a C: witness ledger")
        latest = records[-1]
        if latest["manifest_generation"] != base_generation:
            raise VaultError("vault high-water generation differs from latest local manifest generation")
        if hex32(latest["manifest_anchor_hex"], "manifest_anchor_hex") != base_anchor:
            raise VaultError("vault high-water anchor differs from latest local QFP6 manifest commitment")
        return base_generation, base_anchor

    real_directory(witness_dir, "checkpoint segment witness directory")
    witness_files: list[tuple[int, Path]] = []
    for entry in witness_dir.iterdir():
        match = WITNESS_RE.fullmatch(entry.name)
        if not match:
            raise VaultError(f"unexpected checkpoint witness entry: {entry.name}")
        if entry.is_symlink() or not entry.is_file() or entry.stat().st_size > MAX_WITNESS_BYTES:
            raise VaultError(f"checkpoint witness must be a bounded regular file: {entry.name}")
        witness_files.append((int(match.group(1)), entry))
    witness_files.sort(key=lambda pair: pair[0])

    if not witness_files:
        if segment_root.exists():
            raise VaultError("checkpoint segment data exists but the C: witness ledger is empty")
        latest = records[-1]
        if latest["manifest_generation"] != base_generation:
            raise VaultError("vault high-water generation differs from latest local manifest generation")
        if hex32(latest["manifest_anchor_hex"], "manifest_anchor_hex") != base_anchor:
            raise VaultError("vault high-water anchor differs from latest local QFP6 manifest commitment")
        return base_generation, base_anchor

    real_directory(segment_root, "checkpoint segment root")
    expected_segment_names = {f"segment-{sequence:020d}" for sequence, _ in witness_files}
    actual_segment_names: set[str] = set()
    for entry in segment_root.iterdir():
        if entry.is_symlink() or not entry.is_dir():
            raise VaultError(f"checkpoint segment entry must be a real directory: {entry.name}")
        actual_segment_names.add(entry.name)
    if actual_segment_names != expected_segment_names:
        raise VaultError("checkpoint segment directories do not exactly match the witness sequence")

    previous_witness_digest = "00" * 32
    previous_tip_sequence: int | None = None
    previous_tip_generation: int | None = None
    previous_tip_anchor: bytes | None = None
    previous_tip_height: int | None = None

    for expected_sequence, (actual_sequence, witness_path) in enumerate(witness_files, start=1):
        if actual_sequence != expected_sequence:
            raise VaultError(f"checkpoint witness sequence gap: expected {expected_sequence}, found {actual_sequence}")
        raw_witness = witness_path.read_bytes()
        try:
            witness = json.loads(raw_witness)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise VaultError(f"invalid checkpoint witness JSON: {witness_path.name}") from error
        if not isinstance(witness, dict) or witness.get("schema") != "qfp6-checkpoint-segment-witness/v1":
            raise VaultError(f"unsupported checkpoint witness schema: {witness_path.name}")
        if witness_u64(witness.get("sequence"), "sequence") != expected_sequence:
            raise VaultError("checkpoint witness sequence field mismatch")
        if witness.get("previous_witness_digest_hex") != previous_witness_digest:
            raise VaultError("checkpoint witness hash chain mismatch")
        if hex32(witness.get("network_id_hex"), "network_id_hex") != state["network"]:
            raise VaultError("checkpoint witness network ID differs from the package")
        if hex32(witness.get("profile_id_hex"), "profile_id_hex") != state["profile"]:
            raise VaultError("checkpoint witness profile ID differs from the package")
        if witness.get("witness_digest_hex") != checkpoint_witness_digest(witness):
            raise VaultError(f"checkpoint witness checksum mismatch: {witness_path.name}")

        predecessor_sequence = witness_u64(witness.get("predecessor_vault_sequence"), "predecessor_vault_sequence")
        predecessor_generation = witness_u64(witness.get("predecessor_global_generation"), "predecessor_global_generation")
        if predecessor_sequence < 1 or predecessor_sequence > len(records):
            raise VaultError("checkpoint witness predecessor is outside the C: vault chain")
        predecessor_record = records[predecessor_sequence - 1]
        predecessor_anchor = hex32(witness.get("predecessor_manifest_anchor_hex"), "predecessor_manifest_anchor_hex")
        predecessor_digest = hex32(witness.get("predecessor_record_digest_hex"), "predecessor_record_digest_hex")
        if (
            predecessor_record["manifest_generation"] != predecessor_generation
            or hex32(predecessor_record["manifest_anchor_hex"], "manifest_anchor_hex") != predecessor_anchor
            or predecessor_record["record_sha256"] != predecessor_digest.hex()
        ):
            raise VaultError("checkpoint witness does not bind its exact C: predecessor record")
        if expected_sequence == 1:
            if predecessor_generation != base_generation or predecessor_anchor != base_anchor:
                raise VaultError("first checkpoint witness does not descend from the package's pinned Genesis tip")
        elif (
            predecessor_sequence != previous_tip_sequence
            or predecessor_generation != previous_tip_generation
            or predecessor_anchor != previous_tip_anchor
        ):
            raise VaultError("checkpoint witness predecessor does not match the preceding segment tip")
        if predecessor_sequence + 1 > len(records):
            raise VaultError("checkpoint segment root has no corresponding C: vault successor")

        segment_dir = segment_root / f"segment-{expected_sequence:020d}"
        real_directory(segment_dir, "checkpoint segment directory")
        checkpoint_path = segment_dir / "qfp6-base.checkpoint"
        if checkpoint_path.is_symlink() or not checkpoint_path.is_file():
            raise VaultError("checkpoint segment is missing its regular qfp6-base.checkpoint file")
        if checkpoint_path.stat().st_size > MAX_CHECKPOINT_BYTES:
            raise VaultError("checkpoint segment snapshot exceeds the 72 MiB safety limit")
        checkpoint_bytes = checkpoint_path.read_bytes()
        if len(checkpoint_bytes) < 282 + 32 or checkpoint_bytes[:4] != b"Q6CP":
            raise VaultError("checkpoint segment snapshot has an invalid Q6CP header")
        if int.from_bytes(checkpoint_bytes[4:6], "big") != 3:
            raise VaultError("checkpoint segment snapshot version is unsupported")
        if hashlib.sha256(CHECKPOINT_CHECKSUM_DOMAIN + checkpoint_bytes[:-32]).digest() != checkpoint_bytes[-32:]:
            raise VaultError("checkpoint segment snapshot checksum mismatch")
        checkpoint_commitment = hashlib.sha256(CHECKPOINT_COMMITMENT_DOMAIN + checkpoint_bytes).digest()
        if checkpoint_commitment != hex32(witness.get("checkpoint_commitment_hex"), "checkpoint_commitment_hex"):
            raise VaultError("checkpoint snapshot bytes differ from the external witness commitment")

        checkpoint_network = checkpoint_bytes[6:38]
        checkpoint_profile = checkpoint_bytes[38:70]
        checkpoint_consensus = checkpoint_bytes[70:102]
        checkpoint_genesis = checkpoint_bytes[102:134]
        checkpoint_height = int.from_bytes(checkpoint_bytes[134:142], "big")
        checkpoint_tip = checkpoint_bytes[150:182]
        checkpoint_work = checkpoint_bytes[214:246]
        checkpoint_state_root = checkpoint_bytes[246:278]
        if previous_tip_height is not None and checkpoint_height != previous_tip_height:
            raise VaultError("checkpoint segment base height does not continue the preceding segment tip")
        if (
            checkpoint_network != state["network"]
            or checkpoint_profile != state["profile"]
            or checkpoint_consensus != hex32(witness.get("consensus_fingerprint_hex"), "consensus_fingerprint_hex")
            or checkpoint_genesis != hex32(witness.get("genesis_descriptor_commitment_hex"), "genesis_descriptor_commitment_hex")
            or checkpoint_height != witness_u64(witness.get("checkpoint_base_height"), "checkpoint_base_height")
            or checkpoint_tip != hex32(witness.get("checkpoint_tip_hash_hex"), "checkpoint_tip_hash_hex")
            or checkpoint_state_root != hex32(witness.get("checkpoint_state_root_hex"), "checkpoint_state_root_hex")
            or checkpoint_work != hex32(witness.get("checkpoint_cumulative_work_hex"), "checkpoint_cumulative_work_hex")
        ):
            raise VaultError("checkpoint header identity/state differs from its external witness")

        root_sequence = predecessor_sequence + 1
        root_record = records[root_sequence - 1]
        root_generation = predecessor_generation + 1
        root_anchor = hex32(witness.get("segment_root_manifest_anchor_hex"), "segment_root_manifest_anchor_hex")
        if (
            root_record["sequence"] != root_sequence
            or root_record["manifest_generation"] != root_generation
            or hex32(root_record["manifest_anchor_hex"], "manifest_anchor_hex") != root_anchor
        ):
            raise VaultError("checkpoint segment root is not anchored by the exact next C: vault record")

        manifests_dir = segment_dir / "manifests"
        branches_dir = segment_dir / "branches"
        real_directory(manifests_dir, "checkpoint segment manifests directory")
        real_directory(branches_dir, "checkpoint segment branches directory")
        manifest_files: list[tuple[int, Path]] = []
        for entry in manifests_dir.iterdir():
            match = MANIFEST_RE.fullmatch(entry.name)
            if not match:
                raise VaultError(f"unexpected checkpoint segment manifest entry: {entry.name}")
            if entry.is_symlink() or not entry.is_file() or entry.stat().st_size > MAX_MANIFEST_BYTES:
                raise VaultError(f"checkpoint segment manifest must be a bounded regular file: {entry.name}")
            manifest_files.append((int(match.group(1)), entry))
        manifest_files.sort(key=lambda pair: pair[0])
        if not manifest_files or len(manifest_files) > MAX_RECORDS:
            raise VaultError("checkpoint segment manifest count is empty or exceeds its safety limit")
        for local_generation, (actual_generation, _) in enumerate(manifest_files):
            if actual_generation != local_generation:
                raise VaultError(
                    f"checkpoint segment manifest gap: expected {local_generation}, found {actual_generation}"
                )

        branch_entries = list(branches_dir.iterdir())
        if len(branch_entries) > MAX_RECORDS:
            raise VaultError("checkpoint segment branch count exceeds its safety limit")
        for entry in branch_entries:
            if entry.is_symlink() or not entry.is_file():
                raise VaultError(f"checkpoint segment branch must be a regular file: {entry.name}")

        segment_tip_anchor = root_anchor
        for local_generation, (_, manifest_path) in enumerate(manifest_files):
            manifest_bytes = manifest_path.read_bytes()
            manifest_anchor = hashlib.sha256(MANIFEST_DOMAIN + manifest_bytes).digest()
            if local_generation == 0 and manifest_anchor != root_anchor:
                raise VaultError("segment-local generation-zero manifest differs from the witnessed root anchor")
            global_generation = predecessor_generation + 1 + local_generation
            vault_sequence = predecessor_sequence + 1 + local_generation
            if vault_sequence > len(records):
                raise VaultError("checkpoint segment manifest is ahead of the C: vault high-water")
            record = records[vault_sequence - 1]
            if (
                record["sequence"] != vault_sequence
                or record["manifest_generation"] != global_generation
                or hex32(record["manifest_anchor_hex"], "manifest_anchor_hex") != manifest_anchor
            ):
                raise VaultError(
                    f"segment-local generation {local_generation} does not map to its exact global C: record"
                )
            segment_tip_anchor = manifest_anchor

        local_tip_generation = len(manifest_files) - 1
        if len(branch_entries) < local_tip_generation:
            raise VaultError("checkpoint segment has fewer durable branches than committed local generations")
        previous_tip_sequence = predecessor_sequence + 1 + local_tip_generation
        previous_tip_generation = predecessor_generation + 1 + local_tip_generation
        previous_tip_anchor = segment_tip_anchor
        previous_tip_height = checkpoint_height + local_tip_generation
        previous_witness_digest = witness["witness_digest_hex"]

    latest = records[-1]
    if (
        latest["sequence"] != previous_tip_sequence
        or latest["manifest_generation"] != previous_tip_generation
        or hex32(latest["manifest_anchor_hex"], "manifest_anchor_hex") != previous_tip_anchor
    ):
        raise VaultError("C: vault high-water does not exactly match the latest checkpoint segment tip")
    return previous_tip_generation, previous_tip_anchor


def write_new_record(vault_dir: Path, record: dict[str, Any]) -> Path:
    records_dir = vault_records_dir(vault_dir, create=True)
    sequence = int(record["sequence"])
    path = records_dir / f"q6av-{sequence:020d}.json"
    encoded = (json.dumps(record, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    with path.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def make_record(
    sequence: int, network: bytes, profile: bytes, generation: int, anchor: bytes, previous_digest: str
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "sequence": sequence,
        "network_id_hex": network.hex(),
        "profile_id_hex": profile.hex(),
        "manifest_generation": generation,
        "manifest_anchor_hex": anchor.hex(),
        "previous_record_sha256": previous_digest,
    }
    record["record_sha256"] = record_digest(record)
    return record


def backup_before_rebind(vault_dir: Path, sequence: int, package_state: dict[str, Any]) -> None:
    backups = vault_dir / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    real_directory(backups, "anchor vault backups directory")
    for label, raw in (
        ("permissionless-config", package_state["config_bytes"]),
        ("local-devnet-manifest", package_state["manifest_bytes"]),
    ):
        target = backups / f"{label}.before-sequence-{sequence:020d}.json"
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise VaultError(f"existing backup is not a regular file: {target}")
            # Preserve the first pre-rotation backup across interrupted retries.
            continue
        with target.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())


def atomic_replace(path: Path, data: bytes) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def rebind_config_and_manifest(package_state: dict[str, Any], new_anchor: bytes, vault_dir: Path, sequence: int) -> str:
    config = package_state["config"]
    manifest = package_state["manifest"]
    runtime = config["permissionless_runtime"]
    runtime["trusted_manifest_anchor"] = new_anchor.hex()
    new_config = (json.dumps(config, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    new_hash = sha256_hex(new_config)
    manifest["permissionless_config_sha256"] = new_hash
    new_manifest = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    backup_before_rebind(vault_dir, sequence, package_state)
    atomic_replace(package_state["config_path"], new_config)
    atomic_replace(package_state["manifest_path"], new_manifest)
    return new_hash


def command_init(args: argparse.Namespace) -> None:
    state = load_package(args.package_dir)
    segment_root = state["data_dir"].parent / f"{state['data_dir'].name}.checkpoint-segments"
    if segment_root.exists():
        raise VaultError("refusing to initialize a new Vault from a package that already contains checkpoint segments")
    vault_dir = Path(args.vault_dir) if args.vault_dir else default_vault_dir()
    if vault_dir.exists():
        real_directory(vault_dir, "anchor vault directory")
        if any(vault_dir.iterdir()):
            raise VaultError("anchor vault already exists and is not empty; refusing to overwrite")
    if state["config_anchor"] != state["anchor"]:
        raise VaultError("config anchor does not match the exact latest QFP6 manifest commitment")
    record = make_record(1, state["network"], state["profile"], state["generation"], state["anchor"], "00" * 32)
    path = write_new_record(vault_dir, record)
    print("LOCAL_QFP6_ANCHOR_VAULT=PROVISIONED")
    print(f"vault_path={vault_dir.resolve()}")
    print(f"record_path={path.resolve()}")
    print(f"manifest_generation={state['generation']}")
    print(f"manifest_anchor={state['anchor'].hex()}")
    print(f"record_sha256={record['record_sha256']}")
    print("rollback_scope=DETECTS_DATA_VOLUME_ONLY_WHILE_ANCHOR_VOLUME_REMAINS_INTACT")


def command_verify(args: argparse.Namespace) -> None:
    state = load_package(args.package_dir)
    vault_dir = Path(args.vault_dir) if args.vault_dir else default_vault_dir()
    records = load_vault(vault_dir)
    root = records[0]
    latest = records[-1]
    if hex32(root["network_id_hex"], "network_id_hex") != state["network"]:
        raise VaultError("vault root network ID differs from package network ID")
    if hex32(root["profile_id_hex"], "profile_id_hex") != state["profile"]:
        raise VaultError("vault root profile ID differs from package profile ID")
    if state["config_anchor"] != hex32(root["manifest_anchor_hex"], "root manifest_anchor_hex"):
        raise VaultError("permissionless config trusted_manifest_anchor must remain pinned to the immutable sequence-1 vault root")
    generation, anchor = effective_package_tip(state, vault_dir, records)
    if not state["config_manifest_match"]:
        raise VaultError("local-devnet-manifest does not pin the exact unchanged permissionless config bytes")
    print("LOCAL_QFP6_ANCHOR_VAULT=PASS")
    print(f"vault_sequence={latest['sequence']}")
    print(f"manifest_generation={generation}")
    print(f"manifest_anchor={anchor.hex()}")
    print(f"record_sha256={latest['record_sha256']}")


def validate_final_status_file(path_text: str, generation: int, anchor_hex: str) -> None:
    path = Path(path_text)
    if path.is_symlink() or not path.is_file():
        raise VaultError("final status file must be a regular non-symlink file")
    if path.stat().st_size > 1024 * 1024:
        raise VaultError("final status file exceeds the 1 MiB safety limit")
    try:
        output = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise VaultError(f"cannot read final status file: {error}") from error
    required = {
        "QFP6 PERMISSIONLESS BASE RUNTIME: STARTING (candidate qualification only)",
        "owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED",
        f"final_manifest_generation={generation}",
        f"final_manifest_anchor={anchor_hex}",
        "anchor_persistence_status=LOCAL_C_VAULT_PER_COMMIT_PERSISTED",
        "runtime_status=STOPPED",
    }
    missing = sorted(required.difference(set(output.splitlines())))
    if missing:
        raise VaultError("final status file is missing required successful-stop evidence: " + "; ".join(missing))


def command_advance(args: argparse.Namespace) -> None:
    """Verify that per-commit Rust persistence already anchored the final clean-stop tip.

    The C: vault is now advanced before each successful local commit is acknowledged.
    This compatibility command deliberately performs no manual rotation and never edits
    permissionless-config.json or local-devnet-manifest.json.
    """
    if not args.confirm_clean_shutdown:
        raise VaultError("final verification requires --confirm-clean-shutdown")
    supplied_anchor = hex32(args.final_anchor, "final_manifest_anchor")
    validate_final_status_file(args.final_status_file, args.final_generation, supplied_anchor.hex())
    state = load_package(args.package_dir)
    vault_dir = Path(args.vault_dir) if args.vault_dir else default_vault_dir()
    records = load_vault(vault_dir)
    root, latest = records[0], records[-1]
    generation, anchor = effective_package_tip(state, vault_dir, records)
    if args.final_generation != generation or supplied_anchor != anchor:
        raise VaultError("final status does not match the exact latest anchored QFP6 segment tip")
    if state["config_anchor"] != hex32(root["manifest_anchor_hex"], "root manifest_anchor_hex"):
        raise VaultError("config no longer matches immutable vault root; manual audit required")
    if not state["config_manifest_match"]:
        raise VaultError("permissionless config/manifest digest mismatch; manual audit required")
    if latest["manifest_generation"] != generation or latest["manifest_anchor_hex"] != anchor.hex():
        raise VaultError("per-commit local anchor is behind the clean-stop tip; keep the node stopped and perform a Rust recovery audit")
    print("LOCAL_QFP6_ANCHOR_ROTATION=PER_COMMIT_TIP_ALREADY_PERSISTED")
    print(f"vault_sequence={latest['sequence']}")
    print(f"manifest_generation={generation}")
    print(f"manifest_anchor={anchor.hex()}")
    print("config_rewrite=NOT_REQUIRED_IMMUTABLE_ROOT_PIN_RETAINED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", required=True, help="QFP6 local package directory")
    parser.add_argument("--vault-dir", help="override default C:-drive LOCALAPPDATA vault")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="one-time provision from an already pinned package")
    sub.add_parser("verify", help="verify package, latest manifest and full vault chain")
    advance = sub.add_parser("advance", help="verify per-commit anchor persistence after a verified clean shutdown")
    advance.add_argument("--final-generation", type=int, required=True)
    advance.add_argument("--final-anchor", required=True)
    advance.add_argument("--final-status-file", required=True, help="captured stdout from the same Release node run")
    advance.add_argument("--confirm-clean-shutdown", action="store_true")
    args = parser.parse_args()
    try:
        {"init": command_init, "verify": command_verify, "advance": command_advance}[args.command](args)
        return 0
    except (VaultError, OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"QFP6_ANCHOR_VAULT_ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
