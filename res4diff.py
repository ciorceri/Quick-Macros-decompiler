#!/usr/bin/env python3
"""res4diff.py - compare the main script resource (res4) of two QM executables.

Purpose: closed-loop validation of reconstructed scripts. When you compile a
reconstructed .qml with QM 2.4.12, run:

    python res4diff.py original.exe rebuilt.exe

It extracts resource type 252 payloads from both files, compares res4
(main script: string pool + bytecode) at three levels:

  1. raw bytes      - identical means byte-perfect reconstruction
  2. string pool    - same strings in same order (source-level equivalence)
  3. decoded listing- qmdis.py JSON listing diff (semantic equivalence)

Usage:
    python res4diff.py <fileA> <fileB> [--json out.json]

Exit codes: 0 = identical, 1 = differences found, 2 = error.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path

# reuse qmtool's PE resource parsing
sys.path.insert(0, str(Path(__file__).parent))
from qmtool import QM_RESOURCE_TYPE, parse_pe_resources  # noqa: E402


def get_res4(path: Path) -> bytes:
    """Extract res4 from a QM exe (PE), or pass through a raw res4 payload.

    A raw payload is detected by the PE magic check: if the file is not a
    valid PE, we assume it is already the res4 payload (e.g. res4.bin from
    an earlier extraction).
    """
    data = path.read_bytes()
    if len(data) >= 2 and data[:2] == b"MZ":
        resources = parse_pe_resources(data)
        payloads = resources.get(QM_RESOURCE_TYPE, [])
        if len(payloads) < 4:
            raise ValueError(
                f"{path}: found {len(payloads)} resource type 252 payloads "
                "(need >= 4) - not a QM executable?"
            )
        return payloads[3]
    # raw res4 payload - use as-is
    return data


def decoded_listing(res4: bytes) -> list[dict]:
    """Decode res4 bytecode with qmdis and return the listing entries."""
    import qmdis

    try:
        code_base, stream_offset, code_end = qmdis.locate_code_and_stream(
            res4, None, None)
    except ValueError:
        # Small scripts: the run-length heuristic needs >= 8 stream entries
        # and assumes the original-1 header layout (9 ptrs, code at 0x4C).
        # Freshly compiled small samples have fewer statements and a
        # different header size - brute-force the layout instead.
        code_base, stream_offset, code_end = _brute_force_offsets(res4)
    result = qmdis.disassemble(res4, code_base, stream_offset, code_end)
    return result.get("listing", [])


def _brute_force_offsets(res4: bytes) -> tuple[int, int, int]:
    """Find (code_base, stream_offset, code_end) by trial and scoring.

    Tries even code_base candidates in the header region and every even
    stream offset, disassembles each combination, and keeps the one with
    the best score: +1 per cleanly decoded instruction, -10 per raised
    (undocumented/undecodable) entry. Only practical for small res4
    payloads; large ones must rely on the primary heuristic.
    """
    import struct

    total = len(res4)
    if total > 8192:
        raise ValueError(
            "could not locate the instruction stream in res4 "
            f"(size 0x{total:x} too large for brute-force fallback); "
            "pass --stream-offset explicitly")

    best: tuple[int, int, int, int] | None = None  # (score, cb, so, n_ok)
    for code_base in range(32, min(128, total - 8), 2):
        for stream_offset in range(code_base, total - 2, 2):
            # quick sanity: first stream u16 should be a small code offset
            first, = struct.unpack_from("<H", res4, stream_offset)
            if first >= total - code_base:
                continue
            try:
                result = _disassemble_safe(res4, code_base, stream_offset, total)
            except Exception:
                continue
            if result is None:
                continue
            score, n_ok = result
            if best is None or score > best[0]:
                best = (score, code_base, stream_offset, n_ok)
    if best is None or best[3] < 3:
        raise ValueError(
            "brute-force stream search found no plausible disassembly; "
            "pass --stream-offset explicitly")
    return best[1], best[2], total


def _disassemble_safe(res4: bytes, code_base: int, stream_offset: int,
                      code_end: int) -> tuple[int, int] | None:
    """Disassemble and return (score, n_ok); None if nothing decodes."""
    import qmdis

    try:
        result = qmdis.disassemble(res4, code_base, stream_offset, code_end)
    except Exception:
        return None
    listing = result.get("listing", [])
    if not listing:
        return None
    n_ok = 0
    n_bad = 0
    for entry in listing:
        if entry.get("status") in (None, "ok"):
            n_ok += 1
        else:
            n_bad += 1
    if n_ok == 0:
        return None
    return n_ok - 10 * n_bad, n_ok


def listing_text(res4: bytes) -> str:
    """Render the decoded listing as comparable text (one line per entry)."""
    lines: list[str] = []
    for entry in decoded_listing(res4):
        parts = [
            f"0x{entry.get('code_offset', 0):04x}",
            str(entry.get("mnemonic", entry.get("opcode"))),
        ]
        operand = entry.get("operand")
        if operand:
            parts.append(json.dumps(operand, sort_keys=True))
        if entry.get("status") not in (None, "ok"):
            parts.append(f"status={entry['status']}")
        lines.append(" ".join(parts))
    return "\n".join(lines)


def strings_text(res4: bytes) -> list[str]:
    """Extract printable strings from res4 (same heuristic as qmtool)."""
    from qmtool import extract_printable_strings

    return [s["text"] for s in extract_printable_strings_safe(res4)]


def extract_printable_strings_safe(res4: bytes) -> list[dict]:
    from qmtool import extract_printable_strings

    return extract_printable_strings(res4)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("fileA", help="original exe")
    ap.add_argument("fileB", help="rebuilt exe")
    ap.add_argument("--json", dest="json_out", help="write full diff report here")
    args = ap.parse_args()

    try:
        res4_a = get_res4(Path(args.fileA))
        res4_b = get_res4(Path(args.fileB))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report: dict = {
        "fileA": args.fileA,
        "fileB": args.fileB,
        "res4_size_A": len(res4_a),
        "res4_size_B": len(res4_b),
    }

    # level 1: raw bytes
    raw_identical = res4_a == res4_b
    report["raw_identical"] = raw_identical
    print(f"[1] raw bytes: {'IDENTICAL' if raw_identical else 'DIFFER'} "
          f"({len(res4_a)} vs {len(res4_b)} bytes)")

    if raw_identical:
        print("result: byte-identical res4 - full validation passed")
        return 0

    # level 2: string pool
    strs_a = [s["text"] for s in extract_printable_strings_safe(res4_a)]
    strs_b = [s["text"] for s in extract_printable_strings_safe(res4_b)]
    strings_equal = strs_a == strs_b
    report["strings_identical"] = strings_equal
    report["strings_only_in_A"] = [s for s in strs_a if s not in strs_b]
    report["strings_only_in_B"] = [s for s in strs_b if s not in strs_a]
    print(f"[2] string pool: {'identical' if strings_equal else 'DIFFERENT'}")
    for line in difflib.unified_diff(strs_a, strs_b, "original", "rebuilt", lineterm=""):
        print("    " + line)

    # level 3: decoded listing
    try:
        text_a = listing_text(res4_a)
        text_b = listing_text(res4_b)
        listing_equal = text_a == text_b
        report["listing_identical"] = listing_equal
        print(f"[3] decoded listing: {'identical' if listing_equal else 'DIFFERENT'}")
        if not listing_equal:
            diff = list(difflib.unified_diff(
                text_a.splitlines(), text_b.splitlines(),
                "original", "rebuilt", lineterm=""))
            report["listing_diff_lines"] = len(
                [l for l in diff if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
            )
            for line in diff[:80]:
                print("    " + line)
            if len(diff) > 80:
                print(f"    ... {len(diff) - 80} more diff lines")
    except Exception as exc:
        print(f"[3] decoded listing: could not decode ({exc})")
        report["listing_error"] = str(exc)

    identical = raw_identical and strings_equal and report.get("listing_identical", False)
    print(f"result: {'FULL MATCH' if identical else 'DIFFERENCES FOUND'}")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"report written to {args.json_out}")
    return 0 if identical else 1


if __name__ == "__main__":
    sys.exit(main())
