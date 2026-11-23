#!/usr/bin/env python3
"""Download and verify a public QFP6 zero-value-testnet release bundle, then drop privileges."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

OWNER = "hamidnikkhah660-arch"
REPOSITORY = "ai-native-l1"
BUNDLE_NAME = "qfp6-node-linux-x86_64.tar.gz"
APP_DIR = Path("/app")
DATA_DIR = Path("/data")
RUNTIME_UID = 65534  # nobody
RUNTIME_GID = 65534


def fetch(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "QFP6-Railway-Testnet/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        with destination.open("wb") as output:
            shutil.copyfileobj(response, output)


def extract_safe(archive_path: Path) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError(f"unsafe path in release archive: {member.name}")
            target = APP_DIR.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise RuntimeError(f"unsupported archive member type: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"archive member could not be read: {member.name}")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)


def make_volume_writable() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(DATA_DIR, RUNTIME_UID, RUNTIME_GID)
    for root, directories, files in os.walk(DATA_DIR):
        os.chown(root, RUNTIME_UID, RUNTIME_GID)
        for name in directories:
            os.chown(Path(root) / name, RUNTIME_UID, RUNTIME_GID)
        for name in files:
            os.chown(Path(root) / name, RUNTIME_UID, RUNTIME_GID)


def main() -> None:
    tag = os.environ.get("QFP6_BUNDLE_TAG", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", tag):
        raise RuntimeError("QFP6_BUNDLE_TAG is missing or malformed")

    base = f"https://github.com/{OWNER}/{REPOSITORY}/releases/download/{tag}"
    bundle_url = f"{base}/{BUNDLE_NAME}"
    checksum_url = f"{base}/{BUNDLE_NAME}.sha256"

    temporary = Path("/tmp/qfp6-railway")
    temporary.mkdir(parents=True, exist_ok=True)
    archive_path = temporary / BUNDLE_NAME
    checksum_path = temporary / f"{BUNDLE_NAME}.sha256"

    fetch(checksum_url, checksum_path)
    expected = checksum_path.read_text(encoding="ascii").split()[0].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("release SHA-256 sidecar is malformed")

    fetch(bundle_url, archive_path)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if digest != expected:
        raise RuntimeError("QFP6 Linux release bundle SHA-256 mismatch")

    extract_safe(archive_path)
    binary = APP_DIR / "qrun_v06_node"
    entrypoint = APP_DIR / "entrypoint.py"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("verified release bundle has no executable qrun_v06_node")
    if not entrypoint.is_file():
        raise RuntimeError("verified release bundle has no QFP6 entrypoint.py")
    if not (APP_DIR / "assets" / "genesis-snapshot.q6sn").is_file():
        raise RuntimeError("verified release bundle is missing QFP6 Genesis assets")

    make_volume_writable()
    print(f"QFP6_LINUX_BUNDLE_SHA256={digest}", flush=True)
    print(f"QFP6_LINUX_BUNDLE_TAG={tag}", flush=True)
    print("QFP6_RUNTIME_UID=65534", flush=True)

    os.environ["HOME"] = "/tmp"
    os.setgroups([])
    os.setgid(RUNTIME_GID)
    os.setuid(RUNTIME_UID)
    os.execv(sys.executable, [sys.executable, str(entrypoint)])


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"QFP6_RAILWAY_BOOTSTRAP_REFUSED={exc}", file=sys.stderr, flush=True)
        raise SystemExit(2)
