#!/usr/bin/env python3
"""Offline preflight for the public QuantumZXB documentation/site release.

Run from any directory:
    python simulations/public_docs_refresh_checker.py

The release checksum manifest hashes the canonical Git blob bytes in the index,
not the platform-dependent working-tree line endings.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKSUMS = ROOT / "RELEASE_SHA256SUMS.txt"
EMAIL = "hamidnikkhah660@gmail.com"
VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}


class MarkupValidator(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.ids: set[str] = set()
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if attr.get("id"):
            if attr["id"] in self.ids:
                self.errors.append(f"duplicate HTML id: {attr['id']}")
            self.ids.add(attr["id"])
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if attr.get("id"):
            self.ids.add(attr["id"])

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID_TAGS:
            self.errors.append(f"void HTML tag has closing tag: {tag}")
            return
        if not self.stack:
            self.errors.append(f"unexpected closing tag: {tag}")
        elif self.stack[-1] != tag:
            self.errors.append(f"closing tag {tag} does not match open tag {self.stack[-1]}")
            if tag in self.stack:
                while self.stack and self.stack[-1] != tag:
                    self.stack.pop()
                if self.stack:
                    self.stack.pop()
        else:
            self.stack.pop()


def git_blob(path: str) -> bytes:
    return subprocess.run(
        ["git", "cat-file", "blob", f":{path}"],
        cwd=ROOT, check=True, capture_output=True,
    ).stdout


def check_markdown_links(errors: list[str]) -> int:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    count = 0
    for match in re.finditer(r"!??\[[^\]]*\]\(([^)]+)\)", readme):
        target = match.group(1).strip().split(" ", 1)[0].split("#", 1)[0].split("?", 1)[0]
        if not target or target.startswith(("https://", "http://", "mailto:", "tel:", "data:")):
            continue
        count += 1
        if not (ROOT / target).exists():
            errors.append(f"README relative link target missing: {target}")
    return count


def check_checksums(errors: list[str]) -> int:
    if not CHECKSUMS.exists():
        errors.append("RELEASE_SHA256SUMS.txt is missing")
        return 0
    manifest: dict[str, str] = {}
    for number, line in enumerate(CHECKSUMS.read_text(encoding="ascii").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2:
            errors.append(f"checksum line {number} has invalid format")
            continue
        digest, path = parts
        if path == "RELEASE_SHA256SUMS.txt":
            errors.append("checksum file must not hash itself")
            continue
        if path in manifest:
            errors.append(f"duplicate checksum path: {path}")
        manifest[path] = digest

    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout.split(b"\0")
    expected_paths = {
        item.decode("utf-8") for item in tracked if item and item.decode("utf-8") != "RELEASE_SHA256SUMS.txt"
    }
    if set(manifest) != expected_paths:
        missing = sorted(expected_paths - set(manifest))
        extra = sorted(set(manifest) - expected_paths)
        errors.append(f"checksum path set mismatch; missing={missing[:5]}, extra={extra[:5]}")

    for path, expected in manifest.items():
        try:
            actual = hashlib.sha256(git_blob(path)).hexdigest()
        except subprocess.CalledProcessError:
            errors.append(f"cannot read Git index blob: {path}")
            continue
        if actual != expected:
            errors.append(f"checksum mismatch: {path}")
    return len(manifest)


def main() -> int:
    errors: list[str] = []
    html_path = ROOT / "index.html"
    html = html_path.read_text(encoding="utf-8")
    parser = MarkupValidator()
    parser.feed(html)
    parser.close()
    errors.extend(parser.errors)
    if parser.stack:
        errors.append(f"unclosed HTML tags: {parser.stack[-8:]}")
    for target in re.findall(r'href="#([^"]+)"', html):
        if target not in parser.ids:
            errors.append(f"HTML in-page link target missing: #{target}")

    readme_links = check_markdown_links(errors)
    profile = (ROOT / "docs" / "FOUNDER_PROFILE_AND_COLLABORATION.md").read_text(encoding="utf-8")
    mining = (ROOT / "docs" / "MINING_HALVING_PERFORMANCE_AND_SCALING_V01.md").read_text(encoding="utf-8")
    if EMAIL not in html or EMAIL not in profile or EMAIL not in (ROOT / "README.md").read_text(encoding="utf-8"):
        errors.append("direct founder email is not consistently present")
    for token in ("4,204,800", "35,673,515,981", "2,999,999,999.139264", "Gate 2 remains open"):
        if token not in mining:
            errors.append(f"mining report is missing expected candidate disclosure: {token}")

    interval = 4_204_800
    subsidy_atoms = 35_673_515_981
    total_atoms = interval * sum(subsidy_atoms >> epoch for epoch in range(subsidy_atoms.bit_length()))
    budget_atoms = 3_000_000_000 * 100_000_000
    if total_atoms != 299_999_999_913_926_400:
        errors.append(f"candidate emission sum mismatch: {total_atoms}")
    if budget_atoms - total_atoms != 86_073_600:
        errors.append(f"candidate rounding remainder mismatch: {budget_atoms - total_atoms}")

    checksummed = check_checksums(errors)
    if errors:
        print("PUBLIC_DOCS_PREFLIGHT=FAIL")
        for error in errors:
            print(f"- {error}")
        return 1

    print("PUBLIC_DOCS_PREFLIGHT=PASS")
    print(f"html_tags=PASS ids={len(parser.ids)}")
    print(f"README_relative_links=PASS count={readme_links}")
    print(f"direct_contact=PASS email={EMAIL}")
    print(f"candidate_emission_arithmetic=PASS atoms={total_atoms} remainder_atoms={budget_atoms-total_atoms}")
    print(f"git_blob_checksums=PASS entries={checksummed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
