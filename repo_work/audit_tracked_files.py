#!/usr/bin/env python3
"""Create an immutable per-path review ledger without claiming review."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from pathlib import Path

from common import ReviewError, canonical_json, git


TEXT_EXTENSIONS = {
    ".bash",
    ".c",
    ".cc",
    ".cfg",
    ".cjs",
    ".cpp",
    ".css",
    ".csv",
    ".h",
    ".hpp",
    ".html",
    ".js",
    ".json",
    ".json5",
    ".jsx",
    ".lake",
    ".lean",
    ".m",
    ".md",
    ".mjs",
    ".mm",
    ".msg",
    ".proto",
    ".py",
    ".pyi",
    ".rs",
    ".rst",
    ".scss",
    ".sh",
    ".srv",
    ".svg",
    ".toml",
    ".ts",
    ".tsv",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}

LANGUAGES = {
    ".json": "JSON",
    ".json5": "JSON5",
    ".md": "Markdown",
    ".py": "Python",
    ".rs": "Rust",
    ".sh": "Shell",
    ".svg": "SVG/XML",
    ".toml": "TOML",
    ".yaml": "YAML",
    ".yml": "YAML",
}

REVIEWER_BY_LANGUAGE = {
    "Rust": "Sepehr Mahmoudian / Rust and statistical implementation",
    "Python": "Sepehr Mahmoudian / release and deployment tooling",
    "Shell": "Sepehr Mahmoudian / release and deployment tooling",
    "YAML": "Sepehr Mahmoudian / CI and automation",
    "TOML": "Sepehr Mahmoudian / dependency and build metadata",
}


def generated_by(path: str) -> str | None:
    """Return the retained generator identity for known generated artifacts."""

    if path in {"Cargo.lock", "fuzz/Cargo.lock"}:
        return "cargo generate-lockfile --locked dependency resolution"
    if path.startswith("deploy/reference/"):
        return "scripts/secure_deployment.py check"
    if path in {
        "release/0.9.0/audit-manifest.json",
        "release/0.9.0/requirements-ledger.json",
    }:
        return "scripts/release_audit.py generate"
    if path.startswith("release/0.9.0/evidence/baseline-"):
        return "repo_work/reproduce_baseline.py"
    if path.startswith("release/0.9.0/api/"):
        return "cargo public-api with the recorded toolchain"
    if path.startswith("evidence/results/"):
        return "galadriel-eval evidence publisher"
    if path.startswith("fuzz/corpus/"):
        return "pinned cargo-fuzz/libFuzzer corpus campaign"
    return None


def criticality(path: str) -> tuple[bool, bool, bool, bool]:
    """Classify public, security, scientific, and authority review surfaces."""

    public = (
        path.endswith(("README.md", ".schema.json"))
        or path
        in {
            "Cargo.toml",
            "CHANGELOG.md",
            "CITATION.cff",
            "RELEASE-POLICY.md",
            "SECURITY.md",
            "SUPPORT.md",
        }
        or path.startswith(("docs/", "release/0.9.0/", ".github/"))
        or (path.startswith("crates/") and "/src/" in path)
    )
    security = path.startswith(
        (
            "crates/galadriel-ncp/",
            "deploy/",
            ".github/",
            "scripts/",
            "repo_work/",
        )
    ) or path in {
        "Cargo.lock",
        "Cargo.toml",
        "deny.toml",
        "fuzz/deny.toml",
        "SECURITY.md",
        "docs/THREAT-MODEL.md",
        "docs/SECURE-DEPLOYMENT.md",
    }
    science = path.startswith(
        (
            "crates/galadriel-core/",
            "crates/galadriel-sim/",
            "crates/galadriel-eval/",
            "crates/galadriel-pid/",
            "crates/galadriel-justify/",
            "evidence/",
        )
    ) or path in {
        "docs/CLAIMS.md",
        "docs/EVALUATION.md",
        "docs/JUSTIFICATION.md",
        "docs/PAPER.md",
        "docs/STATISTICAL-CONTRACT.md",
    }
    authority = path in {
        "crates/galadriel-core/src/authority.rs",
        "crates/galadriel-core/src/fusion.rs",
        "docs/ADVISORY-BOUNDARY.md",
        "docs/ECOSYSTEM-CONNECTIONS.md",
        "docs/PRODUCER-CONTRACT.md",
    } or path.startswith(("deploy/", "crates/galadriel-ncp/"))
    return public, security, science, authority

SUSPICIOUS = re.compile(
    r"(?i)\b(TODO|FIXME|HACK|XXX|temporary|experimental|unimplemented|"
    r"unreachable|unwrap|expect|panic|unsafe|fallback|default)\b"
)

LEDGER_COLUMNS = [
    "path",
    "git_blob_id",
    "sha256",
    "bytes",
    "lines",
    "language",
    "generated",
    "generator",
    "public_surface",
    "security_critical",
    "science_critical",
    "authority_critical",
    "reviewer",
    "review_status",
    "requirements",
    "assumptions",
    "defects",
    "tests",
    "evidence",
    "disposition",
    "completed_at",
]


def classify_language(path: str, text: str | None) -> str:
    """Classify enough formats to assign language-specific review."""

    name = Path(path).name
    extension = Path(path).suffix.lower()
    if name in {"Cargo.lock", "Cargo.toml", "rust-toolchain.toml"}:
        return "TOML"
    if name in {"LICENSE", "LICENSE-APACHE", "LICENSE-MIT"}:
        return "License text"
    if extension in LANGUAGES:
        return LANGUAGES[extension]
    if text is None:
        return "Binary/data"
    return "Text"


def parse_index(repo: Path) -> list[tuple[str, str, str]]:
    """Return `(mode, object_id, path)` rows from the exact index."""

    raw = bytes(git(repo, "ls-files", "--stage", "-z", text=False))
    rows: list[tuple[str, str, str]] = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, encoded_path = entry.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise ReviewError("unmerged index entries cannot be reviewed")
        rows.append(
            (mode, object_id, encoded_path.decode("utf-8", "surrogateescape"))
        )
    return rows


def blob_bytes(repo: Path, mode: str, object_id: str) -> bytes:
    """Read the exact indexed bytes, with an explicit submodule representation."""

    if mode == "160000":
        return object_id.encode("ascii") + b"\n"
    return bytes(git(repo, "cat-file", "blob", object_id, text=False))


def decode_text(path: str, data: bytes) -> str | None:
    """Decode likely text strictly; invalid UTF-8 remains binary/data."""

    extension = Path(path).suffix.lower()
    if extension not in TEXT_EXTENSIONS and b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def tracked_worktree_bytes(repo: Path, mode: str, path: str) -> bytes | None:
    """Return working-tree material in the same representation as a Git blob."""

    filesystem_path = repo / path
    try:
        if mode == "120000":
            return os.readlink(filesystem_path).encode("utf-8", "surrogateescape")
        if mode == "160000":
            return None
        return filesystem_path.read_bytes()
    except OSError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--out", default="audit/generated")
    arguments = parser.parse_args()
    repo = Path(arguments.repo).resolve()
    requested_output = Path(arguments.out)
    output = (
        requested_output.resolve()
        if requested_output.is_absolute()
        else (repo / requested_output).resolve()
    )

    try:
        if output == repo or output.exists():
            raise ReviewError("--out must name a new directory distinct from --repo")
        git_directory = (repo / ".git").resolve()
        if output == git_directory or git_directory in output.parents:
            raise ReviewError("--out must not be inside the Git metadata directory")
        status = str(
            git(repo, "status", "--porcelain=v1", "--untracked-files=all")
        ).strip()
        if status:
            raise ReviewError("tracked-file audit requires a clean checkout")

        output.mkdir(parents=True, exist_ok=False)
        ledger_rows: list[dict[str, object]] = []
        manifest_rows: list[dict[str, object]] = []
        findings: list[dict[str, object]] = []

        for mode, object_id, relative in parse_index(repo):
            data = blob_bytes(repo, mode, object_id)
            text = decode_text(relative, data)
            line_count = (
                0
                if text is None
                else text.count("\n") + (1 if text and not text.endswith("\n") else 0)
            )
            digest = hashlib.sha256(data).hexdigest()
            worktree = tracked_worktree_bytes(repo, mode, relative)
            matches = worktree is None if mode == "160000" else worktree == data
            language = classify_language(relative, text)
            generator = generated_by(relative)
            public, security, science, authority = criticality(relative)
            reviewer = REVIEWER_BY_LANGUAGE.get(
                language, "Sepehr Mahmoudian / contracts and release evidence"
            )
            ledger_rows.append(
                {
                    "path": relative,
                    "git_blob_id": object_id,
                    "sha256": digest,
                    "bytes": len(data),
                    "lines": line_count,
                    "language": language,
                    "generated": "YES" if generator else "NO",
                    "generator": generator or "",
                    "public_surface": "YES" if public else "NO",
                    "security_critical": "YES" if security else "NO",
                    "science_critical": "YES" if science else "NO",
                    "authority_critical": "YES" if authority else "NO",
                    "reviewer": reviewer,
                    "review_status": "UNREVIEWED",
                    "requirements": "",
                    "assumptions": "",
                    "defects": "",
                    "tests": "",
                    "evidence": "",
                    "disposition": "",
                    "completed_at": "",
                }
            )
            manifest_rows.append(
                {
                    "path": relative,
                    "git_mode": mode,
                    "git_blob_id": object_id,
                    "sha256": digest,
                    "bytes": len(data),
                    "lines": line_count,
                    "language": language,
                    "generated": generator is not None,
                    "generator": generator,
                    "public_surface": public,
                    "security_critical": security,
                    "science_critical": science,
                    "authority_critical": authority,
                    "reviewer_assignment": reviewer,
                    "review_scope": (
                        {"kind": "bytes", "start": 0, "end_exclusive": len(data)}
                        if text is None
                        else {"kind": "lines", "start": 1, "end_inclusive": line_count}
                    ),
                    "text": text is not None,
                    "working_tree_matches_index": matches,
                }
            )
            if not matches:
                raise ReviewError(f"working tree differs from indexed blob: {relative}")
            if text is not None:
                for line_number, line in enumerate(text.splitlines(), 1):
                    tokens = sorted({match.group(0).lower() for match in SUSPICIOUS.finditer(line)})
                    if tokens:
                        findings.append(
                            {
                                "path": relative,
                                "line": line_number,
                                "tokens": tokens,
                                "text": line[:500],
                            }
                        )

        ledger_path = output / "FILE_REVIEW_LEDGER.csv"
        with ledger_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=LEDGER_COLUMNS)
            writer.writeheader()
            writer.writerows(ledger_rows)

        ignored_raw = bytes(
            git(
                repo,
                "status",
                "--porcelain=v1",
                "-z",
                "--ignored=matching",
                "--untracked-files=all",
                text=False,
            )
        )
        ignored = sorted(
            entry[3:].decode("utf-8", "surrogateescape")
            for entry in ignored_raw.split(b"\0")
            if entry.startswith(b"!! ")
        )
        head = str(git(repo, "rev-parse", "HEAD")).strip()
        tree = str(git(repo, "rev-parse", "HEAD^{tree}")).strip()
        manifest = {
            "schema": "galadriel.tracked-file-manifest.v1",
            "head": head,
            "tree": tree,
            "tracked_files": len(manifest_rows),
            "tracked_bytes": sum(int(row["bytes"]) for row in manifest_rows),
            "text_lines": sum(int(row["lines"]) for row in manifest_rows),
            "files": manifest_rows,
        }
        reconciliation = {
            "schema": "galadriel.filesystem-reconciliation.v1",
            "head": head,
            "tracked_files": len(manifest_rows),
            "untracked_files": [],
            "ignored_paths": ignored,
            "note": "Ignored build/cache paths are not release inputs unless separately declared.",
        }
        (output / "TRACKED_FILE_MANIFEST.json").write_bytes(canonical_json(manifest))
        (output / "FILESYSTEM_RECONCILIATION.json").write_bytes(
            canonical_json(reconciliation)
        )
        (output / "SUSPICIOUS_TOKEN_INVENTORY.json").write_bytes(
            canonical_json(findings)
        )
    except (OSError, ReviewError, ValueError) as error:
        print(f"tracked-file audit failed: {error}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "head": head,
                "tracked_files": len(manifest_rows),
                "tracked_bytes": manifest["tracked_bytes"],
                "text_lines": manifest["text_lines"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
