#!/usr/bin/env python3
"""Partition a file-review ledger into deterministic, balanced review packets."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from common import ReviewError, canonical_json


GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger")
    parser.add_argument("--out", default="audit/generated/review-packets")
    parser.add_argument("--lanes", type=int, default=3)
    arguments = parser.parse_args()

    try:
        if not 1 <= arguments.lanes <= 3:
            raise ReviewError("--lanes must be between one and three")
        with Path(arguments.ledger).open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            required = {
                "path",
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
            if reader.fieldnames is None or not required.issubset(reader.fieldnames):
                raise ReviewError(f"ledger is missing columns: {sorted(required)}")
            rows = list(reader)
        if not rows:
            raise ReviewError("ledger contains no tracked paths")
        if len({row["path"] for row in rows}) != len(rows):
            raise ReviewError("ledger contains duplicate paths")
        for row in rows:
            if not row["path"] or Path(row["path"]).is_absolute():
                raise ReviewError("ledger contains an invalid path")
            if not GIT_OBJECT.fullmatch(row["git_blob_id"]):
                raise ReviewError(f"ledger has an invalid Git object for {row['path']}")
            if not SHA256.fullmatch(row["sha256"]):
                raise ReviewError(f"ledger has an invalid SHA-256 for {row['path']}")
            if int(row["lines"]) < 0 or int(row["bytes"]) < 0:
                raise ReviewError(f"ledger has a negative extent for {row['path']}")

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
                    "Review the complete declared line/byte scope from the exact Git blob; "
                    "record findings separately. Assignment is not evidence of completion."
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
