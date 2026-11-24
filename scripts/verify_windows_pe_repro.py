#!/usr/bin/env python3
"""Compare Windows PE images while ignoring only linker-generated build metadata.

Normalized fields:
  * COFF file-header TimeDateStamp
  * TimeDateStamp in each IMAGE_DEBUG_DIRECTORY entry
  * GUID in each RSDS CodeView record (the per-link PDB identity)

All code, resources, section bytes, relocations, CodeView age/path, and other PE
metadata remain part of the comparison. This is deliberately strict: malformed
PE files or unknown CodeView formats fail closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

IMAGE_DEBUG_TYPE_CODEVIEW = 2
IMAGE_DEBUG_DIRECTORY_SIZE = 28


def u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_range(data: bytes | bytearray, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"{label} is outside the PE file")


def rva_to_file_offset(
    data: bytes | bytearray,
    section_table: int,
    section_count: int,
    rva: int,
    size: int,
) -> int:
    for index in range(section_count):
        entry = section_table + index * 40
        checked_range(data, entry, 40, "section header")
        virtual_size = u32(data, entry + 8)
        virtual_address = u32(data, entry + 12)
        raw_size = u32(data, entry + 16)
        raw_pointer = u32(data, entry + 20)
        span = max(virtual_size, raw_size)
        if virtual_address <= rva and rva + size <= virtual_address + span:
            delta = rva - virtual_address
            if delta + size > raw_size:
                raise ValueError("debug directory maps beyond section raw data")
            offset = raw_pointer + delta
            checked_range(data, offset, size, "debug directory")
            return offset
    raise ValueError(f"cannot map debug-directory RVA 0x{rva:x} to a file offset")


def normalize_pe(path: Path) -> tuple[bytes, dict[str, int | str]]:
    original = path.read_bytes()
    data = bytearray(original)
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{path} is not a valid DOS/PE image")

    pe_offset = u32(data, 0x3C)
    checked_range(data, pe_offset, 24, "PE and COFF headers")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{path} has no PE signature")

    # IMAGE_FILE_HEADER.TimeDateStamp, immediately after the PE signature.
    coff_timestamp_offset = pe_offset + 8
    checked_range(data, coff_timestamp_offset, 4, "COFF timestamp")
    data[coff_timestamp_offset : coff_timestamp_offset + 4] = b"\0" * 4

    section_count = u16(data, pe_offset + 6)
    optional_header_size = u16(data, pe_offset + 20)
    optional_header = pe_offset + 24
    checked_range(data, optional_header, optional_header_size, "optional header")
    magic = u16(data, optional_header)
    if magic == 0x10B:  # PE32
        number_of_directories_offset = optional_header + 92
        data_directories = optional_header + 96
    elif magic == 0x20B:  # PE32+
        number_of_directories_offset = optional_header + 108
        data_directories = optional_header + 112
    else:
        raise ValueError(f"unsupported PE optional-header magic: 0x{magic:x}")

    checked_range(data, number_of_directories_offset, 4, "data-directory count")
    directory_count = u32(data, number_of_directories_offset)
    if directory_count <= 6:
        raise ValueError("PE image has no debug data directory")
    debug_directory_entry = data_directories + 6 * 8
    checked_range(data, debug_directory_entry, 8, "debug data-directory entry")
    debug_rva = u32(data, debug_directory_entry)
    debug_size = u32(data, debug_directory_entry + 4)
    if debug_rva == 0 or debug_size == 0 or debug_size % IMAGE_DEBUG_DIRECTORY_SIZE:
        raise ValueError("PE debug directory is missing or malformed")

    section_table = optional_header + optional_header_size
    checked_range(data, section_table, section_count * 40, "section table")
    debug_offset = rva_to_file_offset(data, section_table, section_count, debug_rva, debug_size)

    debug_timestamp_count = 0
    codeview_guid_count = 0
    for index in range(debug_size // IMAGE_DEBUG_DIRECTORY_SIZE):
        entry = debug_offset + index * IMAGE_DEBUG_DIRECTORY_SIZE
        checked_range(data, entry, IMAGE_DEBUG_DIRECTORY_SIZE, "debug-directory entry")

        # IMAGE_DEBUG_DIRECTORY.TimeDateStamp is at byte offset +4.
        timestamp_offset = entry + 4
        data[timestamp_offset : timestamp_offset + 4] = b"\0" * 4
        debug_timestamp_count += 1

        debug_type = u32(data, entry + 12)
        payload_size = u32(data, entry + 16)
        payload_pointer = u32(data, entry + 24)
        if debug_type == IMAGE_DEBUG_TYPE_CODEVIEW:
            checked_range(data, payload_pointer, payload_size, "CodeView payload")
            if payload_size < 24 or data[payload_pointer : payload_pointer + 4] != b"RSDS":
                raise ValueError("CodeView record is not a supported RSDS record")
            # RSDS = signature (4), GUID (16), age (4), then the PDB path.
            guid_start = payload_pointer + 4
            data[guid_start : guid_start + 16] = b"\0" * 16
            codeview_guid_count += 1

    if codeview_guid_count == 0:
        raise ValueError("PE image has no RSDS CodeView identity to normalize")

    stats: dict[str, int | str] = {
        "size_bytes": len(original),
        "original_sha256": sha256(original),
        "normalized_sha256": sha256(data),
        "coff_timestamps_normalized": 1,
        "debug_timestamps_normalized": debug_timestamp_count,
        "codeview_guids_normalized": codeview_guid_count,
    }
    return bytes(data), stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-a", required=True, type=Path)
    parser.add_argument("--binary-b", required=True, type=Path)
    args = parser.parse_args()

    try:
        normalized_a, stats_a = normalize_pe(args.binary_a)
        normalized_b, stats_b = normalize_pe(args.binary_b)
    except (OSError, ValueError, struct.error) as exc:
        print(f"PE_REPRO_ERROR={exc}", file=sys.stderr)
        return 2

    print("BUILD_A=" + json.dumps(stats_a, sort_keys=True))
    print("BUILD_B=" + json.dumps(stats_b, sort_keys=True))
    if len(normalized_a) != len(normalized_b):
        print("RESULT=PE_SIZE_DIFFERENT_AFTER_METADATA_NORMALIZATION")
        return 1
    if normalized_a != normalized_b:
        print("RESULT=PE_CONTENT_DIFFERENT_AFTER_METADATA_NORMALIZATION")
        return 1
    print("RESULT=PE_CONTENT_IDENTICAL_AFTER_BUILD_METADATA_NORMALIZATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
