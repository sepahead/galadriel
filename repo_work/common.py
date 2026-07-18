"""Shared, dependency-free helpers for release review utilities."""

from __future__ import annotations

import json
import math
import subprocess
from pathlib import Path
from typing import Any, Callable, Literal, overload


class ReviewError(RuntimeError):
    """The checkout or review input violates the review contract."""


JSON_INTEGER_MAX_DIGITS = 128
JSON_INTEGER_ABSOLUTE_BOUND = 10**JSON_INTEGER_MAX_DIGITS - 1


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> Any:
    """Reject the non-JSON constants accepted by Python's decoder."""

    raise ValueError(f"nonstandard JSON constant: {value}")


def parse_finite_float(value: str) -> float:
    """Decode a JSON fraction only when it fits the finite float domain."""

    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"JSON number is outside the finite float range: {value!r}")
    mantissa = value.split("e", 1)[0].split("E", 1)[0]
    if parsed == 0.0 and any(character in "123456789" for character in mantissa):
        raise ValueError(f"JSON number is outside the finite float range: {value!r}")
    return parsed


def parse_bounded_integer(value: str) -> int:
    """Decode a valid JSON integer with a deterministic resource bound.

    JSON integers are exact and retained evidence legitimately contains unsigned 64-bit
    seeds above binary64's consecutive-integer range. Schema validators decide where a
    smaller numeric domain is required; this lexical bound prevents oversized integer
    tokens from becoming unbounded parser work.
    """

    digits = value.removeprefix("-")
    if len(digits) > JSON_INTEGER_MAX_DIGITS:
        raise ValueError(
            f"JSON integer exceeds {JSON_INTEGER_MAX_DIGITS} decimal digits"
        )
    return int(value)


def validate_json_number_bounds(value: Any) -> None:
    """Require generated JSON numbers to round-trip through :func:`loads_json`."""

    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > JSON_INTEGER_ABSOLUTE_BOUND:
            raise ValueError(
                f"JSON integer exceeds {JSON_INTEGER_MAX_DIGITS} decimal digits"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON float is not finite")
        return
    if isinstance(value, dict):
        for item in value.values():
            validate_json_number_bounds(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            validate_json_number_bounds(item)


def loads_json(
    document: str | bytes,
    *,
    object_pairs_hook: Callable[[list[tuple[str, Any]]], Any] = reject_duplicate_pairs,
) -> Any:
    """Decode strict UTF-8 JSON with finite floats and bounded integer tokens."""

    if isinstance(document, bytes):
        try:
            document = document.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("JSON input is not valid UTF-8") from error
    return json.loads(
        document,
        object_pairs_hook=object_pairs_hook,
        parse_constant=reject_nonstandard_constant,
        parse_float=parse_finite_float,
        parse_int=parse_bounded_integer,
    )


def load_json(path: Path) -> Any:
    """Load strict UTF-8 JSON with duplicate-member rejection."""

    try:
        return loads_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise ReviewError(f"cannot load {path}: {error}") from error


def canonical_json(value: Any) -> bytes:
    """Return deterministic, human-readable UTF-8 JSON bytes."""

    try:
        validate_json_number_bounds(value)
        encoded = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except ValueError as error:
        raise ReviewError(f"cannot encode canonical JSON: {error}") from error
    return (encoded + "\n").encode("utf-8")


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
