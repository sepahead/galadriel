#!/usr/bin/env python3
"""Partition a file-review ledger into deterministic, balanced review packets."""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

from common import (
    ReviewError,
    canonical_json,
    canonical_relative_parts,
    read_bounded_regular_file,
)


GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CANONICAL_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
GIT_MODES = frozenset({"100644", "100755", "120000", "160000"})
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_LEDGER_ROWS = 100_000
MAX_LEDGER_CELL_BYTES = 1024 * 1024
MAX_PATH_BYTES = 4 * 1024
MAX_PATH_COMPONENT_BYTES = 255
MAX_PATH_DEPTH = 128
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_AGGREGATE_BYTES = 4 * 1024 * 1024 * 1024
MAX_FILE_LINES = 100_000_000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger")
    parser.add_argument("--out", default="audit/generated/review-packets")
    parser.add_argument("--lanes", type=int, default=3)
    arguments = parser.parse_args()

    try:
        if not 1 <= arguments.lanes <= 3:
            raise ReviewError("--lanes must be between one and three")
        ledger_bytes = read_bounded_regular_file(
            Path(arguments.ledger),
            max_bytes=MAX_LEDGER_BYTES,
            label="file-review ledger",
        )
        try:
            ledger_text = ledger_bytes.decode("utf-8", "strict")
            reader = csv.DictReader(io.StringIO(ledger_text, newline=""))
            required = {
                "path",
                "git_mode",
                "git_blob_id",
                "sha256",
                "lines",
                "bytes",
                "language",
                "generated",
                "public_surface",
                "security_critical",
                "science_critical",
                "authority_critical",
                "reviewer",
                "review_status",
            }
            fields = reader.fieldnames or []
            if len(fields) != len(set(fields)):
                raise ReviewError("ledger contains duplicate columns")
            if not required.issubset(fields):
                raise ReviewError(f"ledger is missing columns: {sorted(required)}")
            rows: list[dict[str, str]] = []
            for row_number, row in enumerate(reader, 1):
                if row_number > MAX_LEDGER_ROWS:
                    raise ReviewError(f"ledger exceeds the {MAX_LEDGER_ROWS}-row limit")
                if None in row or any(value is None for value in row.values()):
                    raise ReviewError(f"ledger row {row_number} is malformed")
                if any(
                    len(value.encode("utf-8")) > MAX_LEDGER_CELL_BYTES
                    for value in row.values()
                ):
                    raise ReviewError(
                        f"ledger row {row_number} exceeds the cell-size limit"
                    )
                rows.append(row)
        except ReviewError:
            raise
        except (UnicodeError, csv.Error) as error:
            raise ReviewError(f"cannot read file-review ledger: {error}") from error
        if not rows:
            raise ReviewError("ledger contains no tracked paths")
        if len({row["path"] for row in rows}) != len(rows):
            raise ReviewError("ledger contains duplicate paths")
        aggregate_bytes = 0
        for row in rows:
            canonical_relative_parts(
                row["path"],
                label="ledger path",
                max_path_bytes=MAX_PATH_BYTES,
                max_component_bytes=MAX_PATH_COMPONENT_BYTES,
                max_depth=MAX_PATH_DEPTH,
            )
            if row["git_mode"] not in GIT_MODES:
                raise ReviewError(f"ledger has an invalid Git mode for {row['path']}")
            if not GIT_OBJECT.fullmatch(row["git_blob_id"]):
                raise ReviewError(f"ledger has an invalid Git object for {row['path']}")
            if not SHA256.fullmatch(row["sha256"]):
                raise ReviewError(f"ledger has an invalid SHA-256 for {row['path']}")
            if (
                len(row["lines"]) > 10
                or len(row["bytes"]) > 10
                or not CANONICAL_DECIMAL.fullmatch(row["lines"])
                or not CANONICAL_DECIMAL.fullmatch(row["bytes"])
            ):
                raise ReviewError(f"ledger has an invalid extent for {row['path']}")
            lines = int(row["lines"])
            size = int(row["bytes"])
            if lines > MAX_FILE_LINES or size > MAX_FILE_BYTES:
                raise ReviewError(f"ledger extent exceeds its bound for {row['path']}")
            aggregate_bytes += size
            if aggregate_bytes > MAX_AGGREGATE_BYTES:
                raise ReviewError("ledger exceeds the aggregate byte limit")

        lanes: list[dict[str, object]] = [
            {"line_weight": 0, "byte_weight": 0, "files": []}
            for _ in range(arguments.lanes)
        ]
        ordered = sorted(
            rows,
            key=lambda row: (-int(row["lines"]), -int(row["bytes"]), row["path"]),
        )
        for row in ordered:
            lane = min(
                lanes,
                key=lambda item: (
                    int(item["line_weight"]),
                    int(item["byte_weight"]),
                    len(item["files"]),
                ),
            )
            lane["files"].append(
                {
                    "path": row["path"],
                    "git_mode": row["git_mode"],
                    "git_blob_id": row["git_blob_id"],
                    "sha256": row["sha256"],
                    "lines": int(row["lines"]),
                    "bytes": int(row["bytes"]),
                    "language": row["language"],
                    "generated": row["generated"],
                    "public_surface": row["public_surface"],
                    "security_critical": row["security_critical"],
                    "science_critical": row["science_critical"],
                    "authority_critical": row["authority_critical"],
                    "reviewer": row["reviewer"],
                    "review_status": row["review_status"],
                    "review_scope": (
                        {
                            "kind": "lines",
                            "start": 1,
                            "end_inclusive": int(row["lines"]),
                        }
                        if int(row["lines"]) > 0
                        else {
                            "kind": "bytes",
                            "start": 0,
                            "end_exclusive": int(row["bytes"]),
                        }
                    ),
                }
            )
            lane["line_weight"] = int(lane["line_weight"]) + int(row["lines"])
            lane["byte_weight"] = int(lane["byte_weight"]) + int(row["bytes"])

        output = Path(arguments.out)
        if output.exists():
            raise ReviewError("--out must name a new directory")
        output.mkdir(parents=True, exist_ok=False)
        for index, lane in enumerate(lanes, 1):
            packet = {
                "schema": "galadriel.review-packet.v1",
                "lane": index,
                "human_review_claimed": False,
                "instructions": (
                    "Review the complete declared line or byte scope from the exact "
                    "Git mode and blob. Record findings separately. Assignment is not "
                    "evidence of completion."
                ),
                **lane,
            }
            (output / f"lane-{index}.json").write_bytes(canonical_json(packet))
    except (OSError, ReviewError, ValueError) as error:
        print(f"review-packet generation failed: {error}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "lanes": arguments.lanes,
                "files": len(rows),
                "line_totals": [lane["line_weight"] for lane in lanes],
                "byte_totals": [lane["byte_weight"] for lane in lanes],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
