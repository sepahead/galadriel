#!/usr/bin/env python3
"""Assert the audited Zenoh compression advisory path remains disabled."""

from __future__ import annotations

import datetime as dt
import subprocess
import sys


EXPIRY = dt.date(2026, 10, 1)
FORBIDDEN = 'zenoh-transport feature "transport_compression"'


def main() -> int:
    if dt.datetime.now(dt.timezone.utc).date() > EXPIRY:
        print(
            "RUSTSEC-2026-0041 exception expired; upgrade the dependency or renew with review",
            file=sys.stderr,
        )
        return 2
    process = subprocess.run(
        ["cargo", "tree", "--workspace", "--all-features", "-e", "features", "--locked"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if process.returncode != 0:
        print(f"cargo tree failed: {process.stderr.strip()}", file=sys.stderr)
        return 2
    if FORBIDDEN in process.stdout:
        print(
            "RUSTSEC-2026-0041 mitigation invalid: transport_compression is enabled",
            file=sys.stderr,
        )
        return 2
    print("vulnerable feature assertion verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
