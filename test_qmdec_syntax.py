#!/usr/bin/env python3
r"""Syntax check of every *.qmdec.qml: only valid QM comment forms (IDP_COMMENT.html):
`stmt;;note` trailing comments and whole lines starting with space, `/`, `\` or `;`.
Fails on `/*` `*/` outside strings, lines starting with `//`, `;;` inside a string literal,
and trailing notes that do not start with `;;`. Exit 0 = pass."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def split_line(ln):
    """-> (code, note, in_string_hits) ; note is the text after the first ';;' outside strings."""
    instr, i, bad = False, 0, []
    while i < len(ln):
        c = ln[i]
        if c == '"':
            instr = not instr
        elif instr:
            if ln.startswith(";;", i):
                bad.append("';;' inside string literal")
            if ln.startswith("/*", i) or ln.startswith("*/", i):
                pass  # inside a string: allowed
        else:
            if ln.startswith(";;", i):
                return ln[:i], ln[i:], bad
            if ln.startswith("/*", i) or ln.startswith("*/", i):
                bad.append("'" + ln[i:i + 2] + "' outside string")
                i += 1
        i += 1
    return ln, None, bad


def check(path):
    errs = []
    for n, ln in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        if ln.startswith("//"):
            errs.append((n, "line starts with //"))
            continue
        if ln.lstrip()[:1] == ";" and not ln.startswith(";;") and ln.startswith((" ", "\t")):
            pass
        if ln[:1] == ";":                      # disabled line: nothing else to check
            continue
        code, note, bad = split_line(ln)
        errs += [(n, b) for b in bad]
        if note is not None and not note.startswith(";;"):
            errs.append((n, "trailing note does not begin with ;;"))
        if note is not None and "/*" in note:
            errs.append((n, "/* inside note"))
    return errs


def main():
    import argparse
    ap = argparse.ArgumentParser(description="syntax self-check of decompiler output (*.qmdec.qml)")
    ap.add_argument("dirs", nargs="*", type=Path, help="directories searched recursively (default: ./out and ./corpus)")
    a = ap.parse_args()
    dirs = a.dirs or [Path("out"), Path("corpus")]
    files = sorted({f for d in dirs if d.is_dir() for f in d.rglob("*.qmdec.qml")})
    if not files:
        print("no .qmdec.qml found - decompile first, e.g. `python qmdec.py corpus -o out`")
        return 1
    fails = 0
    for f in files:
        for n, m in check(f):
            fails += 1
            print(f"FAIL {f}:{n}: {m}")
    print(f"{len(files)} files, {fails} failures -> {'PASS' if not fails else 'FAIL'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
