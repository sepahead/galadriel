#!/usr/bin/env python3
"""Inventory strong claim language in tracked prose without judging validity."""

from __future__ import annotations

import argparse
import io
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
MAX_PROSE_FILES = 100_000
MAX_PROSE_FILE_BYTES = 256 * 1024 * 1024
MAX_PROSE_AGGREGATE_BYTES = 4 * 1024 * 1024 * 1024
MAX_CLAIM_FINDINGS = 100_000


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
                "--stage",
                "-z",
                "*.md",
                "*.mdc",
                "*.rst",
                "*.txt",
                text=False,
            )
        )
        findings: list[dict[str, object]] = []
        file_count = 0
        aggregate_bytes = 0
        for entry in raw.split(b"\0"):
            if not entry:
                continue
            file_count += 1
            if file_count > MAX_PROSE_FILES:
                raise ReviewError("tracked prose exceeds the file-count limit")
            try:
                metadata, encoded_path = entry.split(b"\t", 1)
                mode, object_id, stage = metadata.decode("ascii").split()
            except (UnicodeError, ValueError) as error:
                raise ReviewError("tracked prose index is malformed") from error
            if stage != "0":
                raise ReviewError("tracked prose contains an unmerged index entry")
            if mode == "160000":
                continue
            relative = encoded_path.decode("utf-8", "surrogateescape")
            document = bytes(
                git(
                    repo,
                    "cat-file",
                    "blob",
                    object_id,
                    text=False,
                    max_bytes=MAX_PROSE_FILE_BYTES,
                )
            )
            aggregate_bytes += len(document)
            if aggregate_bytes > MAX_PROSE_AGGREGATE_BYTES:
                raise ReviewError("tracked prose exceeds the aggregate byte limit")
            try:
                text = document.decode("utf-8", "strict")
            except UnicodeError:
                continue
            for line_number, line in enumerate(io.StringIO(text), 1):
                terms = sorted(
                    {match.group(0).lower() for match in CLAIM.finditer(line)}
                )
                if terms:
                    if len(findings) >= MAX_CLAIM_FINDINGS:
                        raise ReviewError(
                            "claim-language findings exceed the item limit"
                        )
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
