#!/usr/bin/env python3
"""Publish guard: scans the whole repository tree, exits non-zero on any hit.

    python tools/check_publish.py [--private FILE] [ROOT]
    (ROOT defaults to the repository root)

FILE (or the QM_RE_PRIVATE_TOKENS environment variable) is an optional
PRIVATE token list kept OUTSIDE the repository: plain text lines
`s:<substring>` or `r:<regex>`, `#` comments. Put your own names, machine
names, callsigns, and the GUIDs of your own macros there; never commit it.

Checks, for every file under ROOT (text AND binary, including this script):
  * forbidden extensions: .exe .ex$ .bin .chm (QM runtime / resource dumps /
    QM help must never be published)
  * forbidden directories: .git, __pycache__, corpus, roundtrip
  * files larger than 5 MB
  * forbidden tokens from tools/forbidden_tokens.txt (plain substrings and
    regexes, case-insensitive; each searched as ASCII/UTF-8 and as UTF-16LE).
    The token file stores them hex-encoded so that it does not contain what
    it forbids. A line is `<kind>:<hex>` with kind `s` (substring) or `r`
    (regex); `#` starts a comment.

Matches are reported as file, byte offset and token number only (the token
itself is masked). Standard library only; runs standalone.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
TOKENS = HERE / "forbidden_tokens.txt"
MAX_BYTES = 5 * 1024 * 1024
BAD_EXT = {".exe", ".bin", ".chm"}
BAD_NAME_SUFFIX = ("ex$",)  # names ending in .ex$
BAD_DIRS = {".git", "__pycache__", "corpus", "roundtrip"}


def load_tokens() -> tuple[list[str], list[re.Pattern[str]]]:
    """Loads the hex-encoded forbidden tokens.

    Returns:
      Tuple (substrings, compiled regexes).

    Raises:
      SystemExit: If a token line is malformed.
    """
    subs, regs = [], []
    for ln in TOKENS.read_text(encoding="ascii").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        kind, _, hx = ln.partition(":")
        text = bytes.fromhex(hx).decode("utf-8")
        if kind == "s":
            subs.append(text)
        elif kind == "r":
            regs.append(re.compile(text, re.I))
        else:
            raise SystemExit(f"bad token line: {ln[:20]}")
    return subs, regs


def load_private(
    path: str | Path,
) -> tuple[list[str], list[re.Pattern[str]]]:
    """Loads the private plain-text token list at path.

    Args:
      path: File with `s:<substring>` or `r:<regex>` lines.

    Returns:
      Tuple (substrings, compiled regexes).

    Raises:
      SystemExit: If a line is malformed.
    """
    subs, regs = [], []
    for ln in Path(path).read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        kind, _, text = ln.partition(":")
        if kind == "s":
            subs.append(text)
        elif kind == "r":
            regs.append(re.compile(text, re.I))
        else:
            raise SystemExit(
                "bad private token line (expected s:<text> or r:<regex>)"
            )
    return subs, regs


def mask(s: str) -> str:
    """Masks all but the first character of a string.

    Args:
      s: The string to mask.

    Returns:
      The first character of s followed by one "*" per remaining character.
    """
    return s[:1] + "*" * max(0, len(s) - 1)


def scan_file(
    path: Path, subs: list[str], regs: list[re.Pattern[str]]
) -> list[tuple[int, str]]:
    """Scans one file for forbidden tokens.

    Args:
      path: File to scan.
      subs: Forbidden substrings.
      regs: Compiled forbidden regexes.

    Returns:
      List of (byte offset, message) hits.
    """
    hits = []
    data = path.read_bytes()
    low = data.lower()
    for i, t in enumerate(subs):
        tb = t.lower().encode("utf-8")
        for enc, needle in (
            ("utf8", tb),
            ("utf16", t.lower().encode("utf-16-le")),
        ):
            pos = low.find(needle)
            if pos >= 0:
                hits.append((pos, f"forbidden token #{i} ({mask(t)}, {enc})"))
    if regs:
        text = data.decode("latin-1")
        text16 = None
        for j, rg in enumerate(regs):
            m = rg.search(text)
            if m:
                hits.append((m.start(), f"forbidden pattern r{j}"))
            else:
                if text16 is None:
                    try:
                        text16 = data.decode("utf-16-le", errors="ignore")
                    except Exception:
                        text16 = ""
                m = rg.search(text16)
                if m:
                    hits.append((m.start(), f"forbidden pattern r{j} (utf16)"))
    return hits


def main(argv: list[str]) -> int:
    """Runs the guard.

    Args:
      argv: Command line, including the program name at index 0.

    Returns:
      0 if clean, 1 on problems, 2 on error.
    """
    import os

    args = list(argv[1:])
    private = os.environ.get("QM_RE_PRIVATE_TOKENS")
    if "--private" in args:
        i = args.index("--private")
        private = args[i + 1]
        del args[i : i + 2]
    root = Path(args[0]).resolve() if args else HERE.parent
    if not TOKENS.exists():
        print(f"error: {TOKENS} missing", file=sys.stderr)
        return 2
    subs, regs = load_tokens()
    if private:
        ps, pr = load_private(private)
        subs += ps
        regs += pr
    else:
        print(
            "note: no private token file given (--private FILE / "
            "QM_RE_PRIVATE_TOKENS): only generic patterns checked"
        )
    problems = []
    n = 0
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        parts = set(rel.parts)
        if p.is_dir():
            if p.name in BAD_DIRS:
                problems.append(f"{rel}: forbidden directory")
            continue
        if parts & BAD_DIRS:
            problems.append(f"{rel}: inside a forbidden directory")
            continue
        n += 1
        name = p.name.lower()
        if (
            p.suffix.lower() in BAD_EXT
            or name.endswith(BAD_NAME_SUFFIX)
            or name.endswith(".ex$")
        ):
            problems.append(f"{rel}: forbidden file type")
        if p.stat().st_size > MAX_BYTES:
            problems.append(f"{rel}: larger than 5 MB")
            continue
        for pos, msg in scan_file(p, subs, regs):
            problems.append(f"{rel}: {msg} at byte {pos}")
        # the file NAME is scanned too
        for i, t in enumerate(subs):
            if t.lower() in str(rel).lower():
                problems.append(f"{rel}: forbidden token #{i} in the path")
    if problems:
        print("PUBLISH GUARD: FAIL")
        for s in problems:
            print("  ", s)
        print(f"{len(problems)} problem(s) in {n} files")
        return 1
    print(f"PUBLISH GUARD: OK ({n} files scanned under {root})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
