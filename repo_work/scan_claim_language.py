#!/usr/bin/env python3
"""Inventory strong claim language in tracked prose without judging validity."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from common import ReviewError, canonical_json, git


CLAIM = re.compile(
    r"(?i)\b(safe|secure|verified|validated|production[- ]ready|field[- ]tested|"
    r"exact|identical|complete|correct|real[- ]time|certified|compatible|stable|"
    r"proven|guarantee(?:d|s)?)\b"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--out", default="audit/generated/CLAIM_LANGUAGE.json")
    arguments = parser.parse_args()
    repo = Path(arguments.repo).resolve()
    requested_output = Path(arguments.out)
    output = (
        requested_output.resolve()
        if requested_output.is_absolute()
        else (repo / requested_output).resolve()
    )

    try:
        if output.exists():
            raise ReviewError("--out must name a new file")
        git_directory = (repo / ".git").resolve()
        if output == git_directory or git_directory in output.parents:
            raise ReviewError("--out must not be inside the Git metadata directory")
        status = str(
            git(repo, "status", "--porcelain=v1", "--untracked-files=no")
        ).strip()
        if status:
            raise ReviewError("claim-language inventory requires clean tracked files")
        raw = bytes(
            git(
                repo,
                "ls-files",
                "-z",
                "*.md",
                "*.rst",
                "*.txt",
                text=False,
            )
        )
        findings: list[dict[str, object]] = []
        for encoded in raw.split(b"\0"):
            if not encoded:
                continue
            relative = encoded.decode("utf-8", "surrogateescape")
            try:
                lines = (repo / relative).read_text(encoding="utf-8").splitlines()
            except UnicodeError:
                continue
            for line_number, line in enumerate(lines, 1):
                terms = sorted({match.group(0).lower() for match in CLAIM.finditer(line)})
                if terms:
                    findings.append(
                        {
                            "path": relative,
                            "line": line_number,
                            "terms": terms,
                            "text": line[:500],
                        }
                    )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(canonical_json(findings))
    except (OSError, ReviewError) as error:
        print(f"claim-language scan failed: {error}", file=sys.stderr)
        return 2

    print(json.dumps({"findings": len(findings)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
