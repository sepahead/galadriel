#!/usr/bin/env python3
"""Refuse review when HEAD or the tracked checkout differs from the audit cut."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from common import ReviewError, git


REVISION = re.compile(r"[0-9a-f]{40}\Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected", required=True)
    parser.add_argument("--repo", default=".")
    arguments = parser.parse_args()
    repo = Path(arguments.repo).resolve()

    try:
        if not REVISION.fullmatch(arguments.expected):
            raise ReviewError("--expected must be a full lowercase 40-hex commit")
        head = str(git(repo, "rev-parse", "HEAD")).strip()
        if head != arguments.expected:
            raise ReviewError(
                f"FROZEN_HEAD_MISMATCH expected={arguments.expected} actual={head}"
            )
        status = str(
            git(repo, "status", "--porcelain=v1", "--untracked-files=all")
        ).strip()
        if status:
            raise ReviewError(f"DIRTY_TREE\n{status}")
    except ReviewError as error:
        print(error, file=sys.stderr)
        return 2

    print(f"FROZEN_HEAD_OK {head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
