#!/usr/bin/env python3
"""Level 1 extractor for Quick Macros (QM) executables.

A QM-created exe consists of the common QM runtime (native code) plus the
user's precompiled script stored in the PE resource table as custom resource
type 252. This tool:

  1. parses the PE resource table using the dedicated `pefile` library
  2. extracts all resource type 252 payloads
  3. decodes the container (numbers are the PE resource NAME ids; QM uses
     1,2,3,4,6,8,9 - there is no 5 or 7):
       res1 - function-table header: count, ONE GUID + main-function name,
              builder banner
       res2 - function table (20-byte records: id, flags, name offset into
              res3, data-block offset into res4)
       res3 - XOR-chain-encrypted identifier names
       res4 - main script: code + instruction stream + string pool
       res6 - global-variable definitions (loaded by FUN_004022f3 as name 6)
       res8 - u16 count + `count` NUL-terminated DLL names (an EMPTY name is a
              valid entry, e.g. 05 00 "user32" "" "kernel32" "wtsapi32"
              "oleacc")
       res9 - per-exe 0x49 builtin-id table: u16 count + entries
              {u16 id, u16 dll (low 15 bits = index into res8, 0x8000 = flag),
              name+NUL}; opcode 0x49 looks its u16 id up here (0x4294d0) and
              GetProcAddress resolves it
       res10 - (only some exes) u16 count + 8-byte records {u16 id, u16 size,
              u16 type, u16 flags} = hidden global variables (`int+`/`str+`,
              lock) declared at load, read by opcode 0x20 (u16 id)
  4. dumps everything as JSON plus a printable-string fingerprint

Output files are named res<name>.bin using the PE name id (res1,2,3,4,6,8,9).

Usage:
    python qmtool.py <executable> [-o output_dir] [--json]

Works on any exe built with Quick Macros 2.4.x (validated against 38 exes:
3 QM 2.4.2 exes (original-1/2/3), 35 QM 2.4.12 compile samples).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys

import pefile

QM_RESOURCE_TYPE = 252

# ---------------------------------------------------------------------------
# QM runtime encryption key (recovered from FUN_00438c3b, QM 2.4.2 runtime)
#
# The runtime stores a 4-byte XOR key table. Its location differs between QM
# builds (2.4.2: RVA 0x55854, 2.4.12: RVA 0x64efc), so check_runtime_key()
# SEARCHES the file for the key instead of trusting one hard-coded RVA. The
# key itself is a runtime constant, not per-script. If no copy is found the
# check reports ABSENT and res3 decryption is skipped instead of silently
# producing garbage.
# ---------------------------------------------------------------------------
QM_KEY_RVA = 0x55854  # QM 2.4.2 location (kept for reference)
KNOWN_QM_KEY = bytes([0x5D, 0x91, 0x38, 0x6F])
KNOWN_KEY_RVAS = {0x55854: "QM 2.4.2", 0x64EFC: "QM 2.4.12"}


# ---------------------------------------------------------------------------
# PE parsing (pefile library)
# ---------------------------------------------------------------------------


def parse_pe_resources_named(data: bytes) -> dict[int, dict[int, bytes]]:
    """Parse the PE resource directory with pefile.

    Returns {type_id: {name_id: payload}}. name_id is the real PE resource
    name (QM 252 uses 1,2,3,4,6,8,9 - sparse). Only the first language entry
    of each name is kept.

    Args:
      data: The complete PE file contents.

    Returns:
      Nested mapping of resource type id to resource name id to payload.
    """
    pe = pefile.PE(data=data)
    resources: dict[int, dict[int, bytes]] = {}

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return resources

    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if not hasattr(type_entry, "directory"):
            continue
        for name_entry in type_entry.directory.entries:
            for lang_entry in name_entry.directory.entries:
                data_rva = lang_entry.data.struct.OffsetToData
                data_size = lang_entry.data.struct.Size
                payload = pe.get_data(data_rva, data_size)
                resources.setdefault(type_entry.id, {}).setdefault(
                    name_entry.id, payload
                )
    return resources


def parse_pe_resources(data: bytes) -> dict[int, list[bytes]]:
    """Positional view: {type_id: [payloads in directory order]}.

    Kept for callers (res4diff.py) that index by position; for QM type 252
    index 3 is res4. Prefer parse_pe_resources_named() when the PE name matters.

    Args:
      data: The complete PE file contents.

    Returns:
      Mapping of resource type id to payloads in directory order.
    """
    return {
        t: list(names.values())
        for t, names in parse_pe_resources_named(data).items()
    }


# ---------------------------------------------------------------------------
# QM runtime key check + decryption
# ---------------------------------------------------------------------------


def find_runtime_key(data: bytes) -> list[int]:
    """Return RVAs of every copy of the 4-byte key table inside a section.

    Args:
      data: The complete PE file contents.

    Returns:
      RVAs of each occurrence of KNOWN_QM_KEY that lies inside a section.
    """
    pe = pefile.PE(data=data)
    rvas: list[int] = []
    pos = data.find(KNOWN_QM_KEY)
    while pos >= 0:
        try:
            rva = pe.get_rva_from_offset(pos)
        except Exception:  # offset not inside a section
            rva = None
        if rva is not None:
            rvas.append(rva)
        pos = data.find(KNOWN_QM_KEY, pos + 1)
    return rvas


def check_runtime_key(data: bytes) -> dict:
    """Locate the XOR key table and report which QM build layout it matches.

    Args:
      data: The complete PE file contents.

    Returns:
      A report dict with the known key, the RVAs found and a status text.
    """
    rvas = find_runtime_key(data)
    base = {
        "known_key": KNOWN_QM_KEY.hex(),
        "found_rvas": [f"0x{r:x}" for r in rvas],
    }
    known = [r for r in rvas if r in KNOWN_KEY_RVAS]
    if known:
        r = known[0]
        return {
            **base,
            "present": True,
            "rva": f"0x{r:x}",
            "stored_key": KNOWN_QM_KEY.hex(),
            "matches_known": True,
            "status": f"match - {KNOWN_KEY_RVAS[r]} runtime key @ RVA 0x{r:x}",
        }
    if rvas:
        return {
            **base,
            "present": True,
            "rva": f"0x{rvas[0]:x}",
            "stored_key": KNOWN_QM_KEY.hex(),
            "matches_known": True,
            "status": (
                f"match - key found at unrecognized RVA "
                f"0x{rvas[0]:x} (new QM build?)"
            ),
        }
    return {
        **base,
        "present": False,
        "matches_known": False,
        "status": (
            "ABSENT - known key not found anywhere in the file; "
            "res3 not decrypted (different key or not a QM exe)"
        ),
    }


def qm_decrypt(data: bytes, key: bytes = KNOWN_QM_KEY) -> bytes:
    """QM runtime XOR-chain decryption (FUN_00438c3b / 2.4.12 FUN_00439c31).

    Decrypts backward from the last byte to the first:
        k starts as KEY[n & 3]; each byte is XORed with k, then k becomes
        (KEY[i & 3] + original_byte) & 0xFF.

    Args:
      data: The encrypted bytes.
      key: The 4-byte XOR key table.

    Returns:
      The decrypted bytes (same length as data).
    """
    buf = bytearray(data)
    n = len(data)
    if n == 0:
        return bytes(buf)
    k = key[n & 3]
    for i in range(n - 1, -1, -1):
        b = data[i]
        buf[i] = b ^ k
        k = (key[i & 3] + b) & 0xFF
    return bytes(buf)


# ---------------------------------------------------------------------------
# QM container decoding
# ---------------------------------------------------------------------------


def extract_printable_strings(blob: bytes, min_len: int = 3) -> list[dict]:
    """Extracts printable ASCII runs with their offsets.

    This is the behavioral fingerprint of a blob.

    Args:
      blob: Bytes to scan.
      min_len: Minimum run length to report.

    Returns:
      A list of dicts with keys offset, hex_offset and text.
    """
    entries: list[dict] = []
    start = -1
    run = b""
    for i in range(len(blob) + 1):
        b = blob[i] if i < len(blob) else 0
        if 32 <= b < 127:
            if not run:
                start = i
            run += bytes([b])
        else:
            if len(run) >= min_len:
                entries.append(
                    {
                        "offset": start,
                        "hex_offset": f"0x{start:04x}",
                        "text": run.decode("ascii"),
                    }
                )
            run = b""
    return entries


def parse_bytecode_index(blob: bytes) -> list[dict]:
    """Parse res2: the function table (20-byte records).

    Layout (little-endian). Verified on 13 exes (len % 20 == 0; count equals
    the res1 function count) and against the runtime loader FUN_00401ff1
    (REA, 2026-11-07), which walks these records with stride 0x14:
        +0  <H id>        copied to runtime record +0 (QM-internal id/offset;
                          the earlier docs called it code_off - unverified)
        +2  <H flags>     bit0 = has res4 data block, bit1 = has res5 blob
        +4  <H kind> <H flags2>   copied as a dword to runtime record +4;
                          dword & 0x200 => res4 block is XOR-chain encrypted
        +8  <I name_off>  offset of this function's name in DECRYPTED res3
                          (NOT a size: equals the cumulative start of each
                          NUL-terminated name, checked on all 12 QM exes)
        +12 <I block_off> offset of this function's data block in res4
        +16 <I blob_off>  offset into res5 (only if flags bit1; else 0)

    Args:
      blob: The res2 payload.

    Returns:
      One dict per record with keys index, id, flags, kind, flags2,
      name_off, block_off and blob_off.

    Raises:
      ValueError: If the length is not a multiple of 20.
    """
    if len(blob) % 20:
        raise ValueError(f"res2 length {len(blob)} is not a multiple of 20")
    recs: list[dict] = []
    for pos in range(0, len(blob), 20):
        rid, flags, kind, flags2, name_off, block_off, blob_off = (
            struct.unpack_from("<HHHHIII", blob, pos)
        )
        recs.append(
            {
                "index": len(recs),
                "id": rid,
                "flags": flags,
                "kind": kind,
                "flags2": flags2,
                "name_off": name_off,
                "block_off": block_off,
                "blob_off": blob_off,
            }
        )
    return recs


def parse_res8(blob: bytes) -> list[str]:
    """Parses res8: u16 count + count NUL-terminated names.

    Empty names are allowed.

    Args:
      blob: The res8 payload.

    Returns:
      The list of DLL names.

    Raises:
      ValueError: If the framing does not consume the blob exactly.
    """
    if len(blob) < 2:
        raise ValueError("res8 too short")
    cnt = struct.unpack_from("<H", blob)[0]
    pos, out = 2, []
    for _ in range(cnt):
        e = blob.index(b"\0", pos)
        out.append(blob[pos:e].decode("latin-1"))
        pos = e + 1
    if pos != len(blob):
        raise ValueError(f"res8 framing: consumed {pos} of {len(blob)} bytes")
    return out


def parse_res9(blob: bytes, dlls: list[str] | None = None) -> dict[int, dict]:
    """Parses res9: u16 count + entries {u16 id, u16 dll, name+NUL}.

    Args:
      blob: The res9 payload.
      dlls: Optional res8 DLL list; when given, each entry also gets
        dll = dlls[dll_index & 0x7fff].

    Returns:
      {id: {name, dll_index, flag, dll}}.

    Raises:
      ValueError: On bad framing or a duplicate id.
    """
    if len(blob) < 2:
        raise ValueError("res9 too short")
    cnt = struct.unpack_from("<H", blob)[0]
    pos, out = 2, {}
    for _ in range(cnt):
        fid, dix = struct.unpack_from("<HH", blob, pos)
        e = blob.index(b"\0", pos + 4)
        ent = {
            "name": blob[pos + 4 : e].decode("latin-1"),
            "dll_index": dix & 0x7FFF,
            "flag": dix & 0x8000,
        }
        if dlls is not None:
            ent["dll"] = (
                dlls[ent["dll_index"]] if ent["dll_index"] < len(dlls) else None
            )
        if fid in out:
            raise ValueError(f"res9 duplicate id {fid}")
        out[fid] = ent
        pos = e + 1
    if pos != len(blob):
        raise ValueError(f"res9 framing: consumed {pos} of {len(blob)} bytes")
    return out


def parse_res10(blob: bytes) -> dict[int, dict]:
    """Parses res10: hidden global variables.

    Loaded by 2.4.12 FUN_0040248f / helper 0x40f430. Layout: u16 count +
    8-byte records {u16 id, u16 size, u16 type, u16 flags}.
    Loader: the 8 bytes are memcpy'd into a 12-byte table entry [0x473be0];
    size != 0 -> the variable is `malloc(size)` bytes (raw int/byte/word
    storage); size == 0 -> the variable is an OBJECT created by the factory
    registered for `type` (table 0x473bbc, vtable +0x40: str, lock, ...).
    Opcode 0x20 looks the record up by id and gives the VM ctx type byte =
    type (0xff when >= 0x2a) and flag byte = flags.
    Observed: `int+`/`str+` globals = (id, 4, 0, 8) / (id, 0, 4, 8); hidden
    lock object = (0x14, 0, 0x28, 0).

    Args:
      blob: The res10 payload.

    Returns:
      {id: {size, type, flags}}.

    Raises:
      ValueError: On bad framing or a duplicate id.
    """
    cnt = struct.unpack_from("<H", blob)[0]
    if len(blob) != 2 + 8 * cnt:
        raise ValueError(f"res10 framing: {len(blob)} bytes for count {cnt}")
    out = {}
    for i in range(cnt):
        rid, size, ty, fl = struct.unpack_from("<HHHH", blob, 2 + 8 * i)
        if rid in out:
            raise ValueError(f"res10 duplicate id {rid}")
        out[rid] = {"size": size, "type": ty, "flags": fl}
    return out


def parse_builtin_tables(named: dict[int, bytes]) -> dict:
    """Parses res8/res9/res10 together.

    Args:
      named: {name_id: payload} of the type-252 resources.

    Returns:
      {'dlls': res8 list, 'ids': res9 table (with dll names),
      'globals': res10}.
    """
    dlls = parse_res8(named[8]) if 8 in named else []
    ids = parse_res9(named[9], dlls) if 9 in named else {}
    glob = parse_res10(named[10]) if 10 in named else {}
    return {"dlls": dlls, "ids": ids, "globals": glob}


def read_null_terminated_strings(blob: bytes, min_len: int = 3) -> list[str]:
    """Read printable-ASCII runs (res1/res3/res8/res9 style name lists).

    Args:
      blob: Bytes to scan.
      min_len: Minimum run length to report.

    Returns:
      The text of each printable run, in order.
    """
    return [e["text"] for e in extract_printable_strings(blob, min_len)]


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_qm_executable(path: Path) -> dict:
    """Full Level-1 analysis of a QM executable.

    Args:
      path: Path of the executable to analyse.

    Returns:
      The analysis result dict.

    Raises:
      ValueError: If the file has no QM resources.
    """
    data = path.read_bytes()
    named = parse_pe_resources_named(data).get(QM_RESOURCE_TYPE)
    if not named:
        raise ValueError(
            f"no resource type {QM_RESOURCE_TYPE} found - "
            "not a Quick Macros executable (or unsupported QM version)"
        )

    result: dict = {
        "file": str(path),
        "size": len(data),
        "qm_resource_count": len(named),
        "qm_resource_names": sorted(named),
        "resource_sizes": {f"res{n}": len(p) for n, p in sorted(named.items())},
        "runtime_key_check": check_runtime_key(data),
    }

    if 1 in named:
        result["res1_strings"] = read_null_terminated_strings(named[1])
    if 2 in named:
        result["bytecode_index"] = parse_bytecode_index(named[2])
    if 3 in named:
        if result["runtime_key_check"].get("matches_known"):
            result["res3_decrypted"] = read_null_terminated_strings(
                qm_decrypt(named[3])
            )
        else:
            result["res3_decrypted"] = None
    if 4 in named:
        result["res4_size"] = len(named[4])
        result["script_strings"] = extract_printable_strings(named[4])
    bt = parse_builtin_tables(named)
    if 8 in named:
        result["dll_names"] = bt["dlls"]
    if 9 in named:
        result["api_names"] = [v["name"] for v in bt["ids"].values()]
        result["builtin_id_table"] = {str(k): v for k, v in bt["ids"].items()}
    if 10 in named:
        result["hidden_globals"] = {str(k): v for k, v in bt["globals"].items()}
    return result


def project_exes(corpus: str | Path | None = None) -> list[Path]:
    """Returns all exes of the corpus.

    See qmcorpus.py: --corpus / $QM_CORPUS / ./corpus.

    Args:
      corpus: Optional corpus directory.
    """
    import qmcorpus

    return qmcorpus.find_exes(corpus)


def dump_all_tables(out_path: Path, corpus: str | Path | None = None) -> None:
    """Writes analysis/res9_tables.json: every exe's OWN res8/res9/res10.

    Args:
      out_path: JSON file to write.
      corpus: Optional corpus directory.
    """
    root = Path(corpus) if corpus else Path("corpus")
    res: dict = {}
    for f in project_exes(corpus):
        named = parse_pe_resources_named(f.read_bytes())[QM_RESOURCE_TYPE]
        bt = parse_builtin_tables(named)
        try:
            key = str(f.relative_to(root))
        except ValueError:
            key = f.name
        res[key.replace("\\", "/")] = {
            "res_names_present": sorted(named),
            "res8_dlls": bt["dlls"],
            "res9_ids": {
                str(k): {
                    "name": v["name"],
                    "dll": v["dll"],
                    "dll_index": v["dll_index"],
                    "flag_0x8000": bool(v["flag"]),
                }
                for k, v in sorted(bt["ids"].items())
            },
            "res10_globals": {
                str(k): dict(v) for k, v in bt["globals"].items()
            },
        }
    doc = {
        "_doc": (
            "Per-exe 0x49 builtin-id tables parsed from each exe's own PE "
            "resources (res8 = dll names, res9 = {id, dll index, name}, "
            "res10 = hidden globals {size,type,flags}). "
            "Observed from the PE bytes; ids are NOT comparable across exes. "
            "Generated by "
            "`python qmtool.py --dump-all analysis/res9_tables.json "
            "[corpus_dir]`."
        ),
        "exes": res,
    }
    out_path.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"wrote {out_path} ({len(res)} exes)")


def main() -> int:
    """Command-line entry point.

    Returns:
      The process exit code (0 on success, 1 on error).
    """
    if len(sys.argv) >= 3 and sys.argv[1] == "--dump-all":
        dump_all_tables(
            Path(sys.argv[2]), sys.argv[3] if len(sys.argv) > 3 else None
        )
        return 0
    parser = argparse.ArgumentParser(
        description="Level 1 extractor for Quick Macros executables"
    )
    parser.add_argument(
        "executable", type=Path, help="QM-built .exe to analyze"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="output directory (default: alongside the exe)",
    )
    parser.add_argument(
        "--json", action="store_true", help="print full JSON report to stdout"
    )
    args = parser.parse_args()

    exe_path = args.executable
    if not exe_path.exists():
        print(f"error: {exe_path} not found", file=sys.stderr)
        return 1

    try:
        result = analyze_qm_executable(exe_path)
    except (ValueError, OSError, pefile.PEFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    out_dir = args.output or exe_path.parent / (exe_path.stem + "_qm")
    out_dir.mkdir(parents=True, exist_ok=True)

    # raw payloads, named by the PE resource NAME id (res1,2,3,4,6,8,9)
    resources = parse_pe_resources_named(exe_path.read_bytes())[
        QM_RESOURCE_TYPE
    ]
    for name_id, payload in resources.items():
        (out_dir / f"res{name_id}.bin").write_bytes(payload)

    # string fingerprint
    if result.get("res4_size"):
        lines = [
            f"{s['hex_offset']} ({s['offset']}): {s['text']}"
            for s in result["script_strings"]
        ]
        (out_dir / "res4_strings.txt").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )

    # structured JSON
    (out_dir / "analysis.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )

    if args.json:
        print(json.dumps(result, indent=2))

    # console summary
    print(f"file: {result['file']}")
    print(
        f"QM resources: {result['qm_resource_count']} "
        f"(names {result['qm_resource_names']})"
    )
    key_check = result["runtime_key_check"]
    print(f"runtime key: {key_check.get('status')}")
    if result.get("res3_decrypted"):
        print("res3 identifiers:", ", ".join(result["res3_decrypted"][:6]))
    if result.get("res1_strings"):
        print(
            "res1 (GUID, main name, banner):",
            ", ".join(x[:40] for x in result["res1_strings"][:3]),
        )
    if result.get("api_names"):
        print(f"dynamic APIs: {len(result['api_names'])}")
    if result.get("bytecode_index"):
        print(f"function records (res2): {len(result['bytecode_index'])}")
    if result.get("script_strings"):
        print(f"script strings: {len(result['script_strings'])}")
    print(f"output: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
