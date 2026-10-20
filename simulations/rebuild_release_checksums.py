#!/usr/bin/env python3
"""Rebuild RELEASE_SHA256SUMS.txt from the canonical Git index blob bytes.

Stage all intended release files first. This script then hashes every indexed
file except RELEASE_SHA256SUMS.txt itself. It is designed for the curated public
release tree so Windows working-tree line endings do not change the result.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "RELEASE_SHA256SUMS.txt"


def run_git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True
    ).stdout


def main() -> int:
    try:
        paths = [
            item.decode("utf-8")
            for item in run_git("ls-files", "-z").split(b"\0")
            if item
        ]
        entries: list[str] = []
        for path in sorted(paths):
            if path == MANIFEST:
                continue
            blob = run_git("cat-file", "blob", f":{path}")
            entries.append(f"{hashlib.sha256(blob).hexdigest()}  {path}")
        (ROOT / MANIFEST).write_text("\n".join(entries) + "\n", encoding="ascii", newline="\n")
    except (OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        print(f"CHECKSUM_REBUILD=FAIL: {exc}", file=sys.stderr)
        return 1

    print("CHECKSUM_REBUILD=PASS")
    print(f"entries={len(entries)}")
    print(f"manifest={MANIFEST}")
    print("hash_basis=canonical Git index blob bytes; self-hash excluded")
    print("note=stage intended release files before running this tool")
    return 0


if __name__ == "__main__":
    sys.exit(main())
