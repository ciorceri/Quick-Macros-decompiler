"""qmcorpus.py - locate the exes to analyse (the "corpus").

The corpus is a directory of QM-built executables that YOU produced (or are
entitled to analyse). It is never shipped with this project. Resolution order:
    1. an explicit directory/file passed by the caller (CLI option --corpus)
    2. the QM_CORPUS environment variable
    3. ./corpus
The directory is searched recursively for *.exe (also *.ex$ if present).
Set QM_EXCLUDE=name1,name2 to skip exes whose file name contains any entry.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
DEFAULT_CORPUS = "corpus"


def corpus_dir(arg: str | Path | None = None) -> Path:
    """Returns the corpus location.

    Args:
      arg: Optional explicit directory or file; wins over the environment.

    Returns:
      arg if given, else $QM_CORPUS if set, else ./corpus.
    """
    if arg:
        return Path(arg)
    env = os.environ.get("QM_CORPUS")
    return Path(env) if env else Path(DEFAULT_CORPUS)


def find_exes(arg: str | Path | None = None, quiet: bool = False) -> list[Path]:
    """Finds the exes under the corpus.

    Args:
      arg: Optional explicit directory or file (CLI option --corpus).
      quiet: If True, do not print the error message when nothing is found.

    Returns:
      Sorted list of exes found under the corpus; [] (plus a message on
      stderr unless quiet) if none.
    """
    base = corpus_dir(arg)
    if base.is_file():
        found = [base]
    elif base.is_dir():
        found = sorted(set(base.rglob("*.exe")) | set(base.rglob("*.ex$")))
    else:
        found = []
    ex = [x for x in os.environ.get("QM_EXCLUDE", "").split(",") if x]
    found = [f for f in found if not any(x in f.name for x in ex)]
    if not found and not quiet:
        print(
            f"error: no executables found in corpus '{base}'.\n"
            "  Build the samples in samples/ with your own Quick Macros "
            "installation (Make Exe),\n"
            "  put the resulting .exe files in ./corpus, or pass --corpus DIR "
            "/ set QM_CORPUS.\n"
            "  See README.md.",
            file=sys.stderr,
        )
    return found
