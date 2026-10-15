#!/usr/bin/env python3
"""Pin the human-owned eval corpus: write eval/corpus.lock with SHA-256 of each file.

Run by the human after reviewing corpus changes. Hashes are computed over LF-normalised bytes so a
Windows checkout (CRLF) and Linux CI produce the same lock.

Usage: python scripts/pin_corpus.py [--check]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "eval" / "corpus"
THRESHOLDS = REPO_ROOT / "eval" / "thresholds.yaml"
LOCK = REPO_ROOT / "eval" / "corpus.lock"


def pinned_files() -> list[Path]:
    return [CORPUS_DIR / "attack.jsonl", CORPUS_DIR / "benign.jsonl", THRESHOLDS]


def lf_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def current_hashes() -> dict[str, str]:
    return {path.relative_to(REPO_ROOT).as_posix(): lf_sha256(path) for path in pinned_files()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare with the lock, write nothing")
    args = parser.parse_args(argv)
    hashes = current_hashes()
    if args.check:
        locked = json.loads(LOCK.read_text(encoding="utf-8"))
        if locked != hashes:
            print("corpus.lock does not match the corpus files", file=sys.stderr)
            return 1
        print("corpus.lock matches")
        return 0
    LOCK.write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {LOCK.relative_to(REPO_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
