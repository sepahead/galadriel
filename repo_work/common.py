"""Shared, dependency-free helpers for release review utilities."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Literal, overload


class ReviewError(RuntimeError):
    """The checkout or review input violates the review contract."""


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    """Load strict UTF-8 JSON with duplicate-member rejection."""

    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReviewError(f"cannot load {path}: {error}") from error


def canonical_json(value: Any) -> bytes:
    """Return deterministic, human-readable UTF-8 JSON bytes."""

    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


@overload
def git(repo: Path, *arguments: str, text: Literal[True] = True) -> str: ...


@overload
def git(repo: Path, *arguments: str, text: Literal[False]) -> bytes: ...


def git(repo: Path, *arguments: str, text: bool = True) -> str | bytes:
    """Run Git without shell interpretation and return stdout."""

    process = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        capture_output=True,
        text=text,
    )
    if process.returncode != 0:
        stderr = process.stderr if text else process.stderr.decode("utf-8", "replace")
        raise ReviewError(
            f"git {' '.join(arguments)} failed with {process.returncode}: {stderr.strip()}"
        )
    return process.stdout


def contained_path(root: Path, relative: str) -> Path:
    """Return a lexical contained path while rejecting every symlink component."""

    candidate = Path(relative)
    if (
        not relative
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ReviewError(f"artifact path must be nonempty and relative: {relative!r}")
    resolved_root = root.resolve()
    lexical = resolved_root / candidate
    current = resolved_root
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            raise ReviewError(f"artifact path contains a symlink: {relative!r}")
    resolved = lexical.resolve()
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise ReviewError(f"artifact path escapes root: {relative!r}")
    return lexical
