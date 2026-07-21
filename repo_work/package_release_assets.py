#!/usr/bin/env python3
"""Build and verify deterministic GitHub release evidence assets.

The two evidence tiers remain separate tar roots.  A canonical, detached
SSH-signed manifest binds their bytes to one candidate and one signed tag.  The
verifier treats both the asset directory and each tar stream as hostile input;
extraction is performed only while the canonical representation is rechecked.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterator

from common import ReviewError, canonical_json, contained_path, loads_json
from finalize_release import PublicationDurabilityError, publish_staged_output
from release_assurance import (
    AUTHOR,
    GIT_OBJECT,
    SHA256,
    SIGNING_PRINCIPAL,
    VERSION,
    derive_external_allowed_signers,
    digest_file,
    require_digest_record,
    require_keys,
    sign_file,
    verify_signature,
)


SCHEMA = "galadriel.github-release-assets.v1"
SIGNATURE_NAMESPACE = "galadriel-release-assets"
TAG_NAME = "v0.9.0"
MANIFEST_NAME = "galadriel-0.9.0-release-asset-map.json"
SIGNATURE_NAME = f"{MANIFEST_NAME}.sig"
MAX_ASSET_BYTES = 2 * 1024**3
MAX_GITHUB_ASSETS = 1_000
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_ALLOWED_SIGNERS_BYTES = 4 * 1024
MAX_TREE_ENTRIES = 100_000
MAX_TREE_DEPTH = 128
COPY_BLOCK_BYTES = 1024 * 1024

TIER_ORDER = ("qualification", "closure")
ASSET_NAMES = {
    "qualification": "galadriel-0.9.0-qualification.tar",
    "closure": "galadriel-0.9.0-closure.tar",
}
ROOT_PREFIXES = {
    "qualification": "galadriel-0.9.0-qualification",
    "closure": "galadriel-0.9.0-closure",
}
EXPECTED_ASSET_FILES = frozenset({MANIFEST_NAME, SIGNATURE_NAME, *ASSET_NAMES.values()})


@dataclass(frozen=True)
class _Identity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class _PathState:
    path: str
    identity: _Identity


@dataclass(frozen=True)
class _TreeSnapshot:
    root: Path
    root_identity: _Identity
    directories: tuple[_PathState, ...]
    files: tuple[_PathState, ...]

    def directory_map(self) -> dict[str, _Identity]:
        return {row.path: row.identity for row in self.directories}

    def file_map(self) -> dict[str, _PathState]:
        return {row.path: row for row in self.files}


def _identity(metadata: os.stat_result) -> _Identity:
    return _Identity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _absolute(path: Path | str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _descriptor_flags(*, directory: bool) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or non_block is None or directory_flag is None:
        raise ReviewError("atomic nonblocking no-follow reads are unavailable")
    flags = os.O_RDONLY | no_follow | non_block | getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= directory_flag
    return flags


def _safe_relative(value: str, label: str) -> tuple[str, ...]:
    if type(value) is not str or not value:
        raise ReviewError(f"{label} must be a nonempty relative path")
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise ReviewError(f"{label} is unsafe: {value!r}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ReviewError(f"{label} is unsafe: {value!r}")
    if PurePosixPath(value).as_posix() != value:
        raise ReviewError(f"{label} is not canonical: {value!r}")
    for part in parts:
        try:
            part.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise ReviewError(f"{label} is not valid UTF-8: {value!r}") from error
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            raise ReviewError(f"{label} contains a control character: {value!r}")
    if len(parts) > MAX_TREE_DEPTH:
        raise ReviewError(f"{label} exceeds the {MAX_TREE_DEPTH}-component limit")
    return tuple(parts)


def _entry_relative(parent: tuple[str, ...], name: str) -> str:
    relative = "/".join((*parent, name))
    _safe_relative(relative, "evidence path")
    return relative


def _snapshot_tree(root: Path | str) -> _TreeSnapshot:
    """Inventory one directory through no-follow descriptors.

    File and directory identities are retained so a later read can reject a
    component replacement or any ordinary metadata/content change.
    """

    absolute = _absolute(root)
    try:
        root_descriptor = os.open(absolute, _descriptor_flags(directory=True))
    except OSError as error:
        raise ReviewError(f"evidence root is missing or unsafe: {absolute}") from error
    directories: list[_PathState] = []
    files: list[_PathState] = []
    discovered_entries = 0
    try:
        root_identity = _identity(os.fstat(root_descriptor))

        def visit(
            descriptor: int,
            parent: tuple[str, ...],
            expected_directory: _Identity,
        ) -> None:
            nonlocal discovered_entries
            try:
                with os.scandir(descriptor) as iterator:
                    rows = []
                    for entry in iterator:
                        if discovered_entries >= MAX_TREE_ENTRIES:
                            raise ReviewError(
                                "evidence root exceeds the "
                                f"{MAX_TREE_ENTRIES}-entry limit"
                            )
                        discovered_entries += 1
                        relative = _entry_relative(parent, entry.name)
                        try:
                            metadata = entry.stat(follow_symlinks=False)
                        except OSError as error:
                            raise ReviewError(
                                f"cannot classify evidence path: {relative}"
                            ) from error
                        rows.append((relative, entry.name, _identity(metadata)))
            except OSError as error:
                raise ReviewError("cannot inventory evidence directory") from error
            for relative, name, entry_identity in sorted(rows):
                if len(directories) + len(files) >= MAX_TREE_ENTRIES:
                    raise ReviewError(
                        f"evidence root exceeds the {MAX_TREE_ENTRIES}-entry limit"
                    )
                mode = entry_identity.mode
                if stat.S_ISLNK(mode):
                    raise ReviewError(f"evidence root contains a symlink: {relative}")
                if stat.S_ISREG(mode):
                    if entry_identity.links != 1:
                        raise ReviewError(
                            f"evidence root contains a multiply linked file: {relative}"
                        )
                    files.append(_PathState(relative, entry_identity))
                    continue
                if not stat.S_ISDIR(mode):
                    raise ReviewError(
                        f"evidence root contains a special file: {relative}"
                    )
                directories.append(_PathState(relative, entry_identity))
                try:
                    child = os.open(
                        name, _descriptor_flags(directory=True), dir_fd=descriptor
                    )
                except OSError as error:
                    raise ReviewError(
                        f"evidence directory changed or became unsafe: {relative}"
                    ) from error
                try:
                    if _identity(os.fstat(child)) != entry_identity:
                        raise ReviewError(
                            f"evidence directory changed while inventoried: {relative}"
                        )
                    visit(child, tuple(relative.split("/")), entry_identity)
                finally:
                    os.close(child)
            if _identity(os.fstat(descriptor)) != expected_directory:
                location = "/".join(parent) or "."
                raise ReviewError(
                    f"evidence directory changed while inventoried: {location}"
                )

        visit(root_descriptor, (), root_identity)
    finally:
        os.close(root_descriptor)
    return _TreeSnapshot(
        root=absolute,
        root_identity=root_identity,
        directories=tuple(sorted(directories, key=lambda row: row.path)),
        files=tuple(sorted(files, key=lambda row: row.path)),
    )


@contextlib.contextmanager
def _open_snapshot_file(snapshot: _TreeSnapshot, row: _PathState) -> Iterator[BinaryIO]:
    parts = _safe_relative(row.path, "snapshotted path")
    directory_states = snapshot.directory_map()
    owned_directories: list[int] = []
    handle: BinaryIO | None = None
    try:
        try:
            directory_descriptor = os.open(
                snapshot.root, _descriptor_flags(directory=True)
            )
        except OSError as error:
            raise ReviewError("evidence root changed or became unsafe") from error
        owned_directories.append(directory_descriptor)
        if _identity(os.fstat(directory_descriptor)) != snapshot.root_identity:
            raise ReviewError("evidence root changed after it was inventoried")
        traversed: list[str] = []
        for part in parts[:-1]:
            traversed.append(part)
            relative = "/".join(traversed)
            expected = directory_states.get(relative)
            if expected is None:
                raise ReviewError(f"unrecorded evidence directory: {relative}")
            try:
                next_descriptor = os.open(
                    part,
                    _descriptor_flags(directory=True),
                    dir_fd=directory_descriptor,
                )
            except OSError as error:
                raise ReviewError(
                    f"evidence path changed or became unsafe: {row.path}"
                ) from error
            owned_directories.append(next_descriptor)
            directory_descriptor = next_descriptor
            if _identity(os.fstat(directory_descriptor)) != expected:
                raise ReviewError(f"evidence directory changed: {relative}")
        try:
            descriptor = os.open(
                parts[-1],
                _descriptor_flags(directory=False),
                dir_fd=directory_descriptor,
            )
        except OSError as error:
            raise ReviewError(
                f"evidence file changed or became unsafe: {row.path}"
            ) from error
        try:
            handle = os.fdopen(descriptor, "rb", closefd=True)
        except BaseException:
            os.close(descriptor)
            raise
        if _identity(os.fstat(handle.fileno())) != row.identity:
            raise ReviewError(f"evidence file changed: {row.path}")
        yield handle
        if _identity(os.fstat(handle.fileno())) != row.identity:
            raise ReviewError(f"evidence file changed while read: {row.path}")
    finally:
        if handle is not None:
            handle.close()
        for descriptor in reversed(owned_directories):
            os.close(descriptor)


class _InventoryReader:
    def __init__(
        self,
        source: BinaryIO,
        expected_size: int,
        destination: BinaryIO | None = None,
    ) -> None:
        self.source = source
        self.expected_size = expected_size
        self.destination = destination
        self.size = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size)
        if self.size + len(data) > self.expected_size:
            raise ReviewError("tar member yielded more bytes than declared")
        self.size += len(data)
        self.digest.update(data)
        if self.destination is not None:
            view = memoryview(data)
            while view:
                written = self.destination.write(view)
                if written is None or written <= 0:
                    raise ReviewError("cannot write reconstructed evidence bytes")
                view = view[written:]
        return data

    def finish(self) -> str:
        if self.size != self.expected_size:
            raise ReviewError(
                f"tar member yielded {self.size} of {self.expected_size} bytes"
            )
        if self.source.read(1) != b"":
            raise ReviewError("tar member has bytes beyond its declared size")
        return self.digest.hexdigest()


class _DigestSink:
    """A write-only tar target that retains only its length and SHA-256."""

    def __init__(self) -> None:
        self.size = 0
        self.digest = hashlib.sha256()

    def write(self, data: bytes) -> int:
        self.size += len(data)
        self.digest.update(data)
        return len(data)

    def tell(self) -> int:
        return self.size

    def flush(self) -> None:
        return None

    def hexdigest(self) -> str:
        return self.digest.hexdigest()


class _BoundedWriter:
    """Forward writes while preventing a partial tar from reaching 2 GiB."""

    def __init__(self, destination: BinaryIO, asset_name: str) -> None:
        self.destination = destination
        self.asset_name = asset_name
        self.size = 0

    def write(self, data: bytes) -> int:
        if self.size + len(data) >= MAX_ASSET_BYTES:
            raise ReviewError(
                f"{self.asset_name} must be strictly smaller than 2 GiB "
                f"({MAX_ASSET_BYTES} bytes)"
            )
        view = memoryview(data)
        total = 0
        while view:
            written = self.destination.write(view)
            if written is None or written <= 0:
                raise ReviewError(f"cannot write release asset: {self.asset_name}")
            total += written
            self.size += written
            view = view[written:]
        return total

    def tell(self) -> int:
        return self.size

    def flush(self) -> None:
        self.destination.flush()


def _tar_info(name: str, *, directory: bool, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o755 if directory else 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = 0 if directory else size
    info.linkname = ""
    info.devmajor = 0
    info.devminor = 0
    info.pax_headers = {}
    return info


def _archive_rows(snapshot: _TreeSnapshot) -> list[tuple[str, str, _PathState | None]]:
    rows: list[tuple[str, str, _PathState | None]] = [("directory", "", None)]
    rows.extend(("directory", row.path, row) for row in snapshot.directories)
    rows.extend(("file", row.path, row) for row in snapshot.files)
    return [rows[0], *sorted(rows[1:], key=lambda row: row[1])]


def _archive_size(size: int, asset_name: str) -> None:
    if type(size) is not int or size < 0:
        raise ReviewError(f"{asset_name} has an invalid byte count")
    if size >= MAX_ASSET_BYTES:
        raise ReviewError(
            f"{asset_name} must be strictly smaller than 2 GiB "
            f"({MAX_ASSET_BYTES} bytes)"
        )


def _write_archive(
    snapshot: _TreeSnapshot, destination: Path, tier: str
) -> dict[str, Any]:
    asset_name = ASSET_NAMES[tier]
    prefix = ROOT_PREFIXES[tier]
    if sum(row.identity.size for row in snapshot.files) >= MAX_ASSET_BYTES:
        raise ReviewError(
            f"{asset_name} input payload cannot fit below the 2 GiB asset limit"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ReviewError("no-follow output creation is unavailable")
    flags |= no_follow
    try:
        descriptor = os.open(destination, flags, 0o600)
    except OSError as error:
        raise ReviewError(
            f"refusing to replace release asset: {destination}"
        ) from error
    file_inventory: list[dict[str, Any]] = []
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            bounded_output = _BoundedWriter(output, asset_name)
            with tarfile.open(
                fileobj=bounded_output,
                mode="w|",
                format=tarfile.PAX_FORMAT,
                dereference=False,
                encoding="utf-8",
                errors="strict",
            ) as archive:
                for kind, relative, state in _archive_rows(snapshot):
                    name = prefix if not relative else f"{prefix}/{relative}"
                    if kind == "directory":
                        archive.addfile(_tar_info(name, directory=True))
                        continue
                    assert state is not None
                    with _open_snapshot_file(snapshot, state) as source:
                        reader = _InventoryReader(source, state.identity.size)
                        archive.addfile(
                            _tar_info(name, directory=False, size=state.identity.size),
                            reader,
                        )
                        digest = reader.finish()
                    file_inventory.append(
                        {
                            "path": relative,
                            "sha256": digest,
                            "size_bytes": state.identity.size,
                        }
                    )
            bounded_output.flush()
            os.fsync(output.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    if _snapshot_tree(snapshot.root) != snapshot:
        destination.unlink(missing_ok=True)
        raise ReviewError(f"{tier} evidence changed while its archive was built")
    metadata = destination.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        destination.unlink(missing_ok=True)
        raise ReviewError(f"generated asset is not regular: {asset_name}")
    _archive_size(metadata.st_size, asset_name)
    digest, size = digest_file(destination)
    return {
        "tier": tier,
        "asset_name": asset_name,
        "root_prefix": prefix,
        "sha256": digest,
        "size_bytes": size,
        "directories": [row.path for row in snapshot.directories],
        "files": file_inventory,
    }


def _require_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require_keys(value, keys, label)
    assert isinstance(value, dict)
    return value


def _require_object_id(value: Any, label: str) -> str:
    if type(value) is not str or GIT_OBJECT.fullmatch(value) is None:
        raise ReviewError(f"{label} must be a full lowercase Git object ID")
    return value


def _validate_identity_values(
    candidate_commit: str,
    candidate_tree: str,
    tag_name: str,
    tag_object: str,
    tag_target: str,
) -> None:
    _require_object_id(candidate_commit, "candidate commit")
    _require_object_id(candidate_tree, "candidate tree")
    _require_object_id(tag_object, "signed tag object")
    _require_object_id(tag_target, "signed tag target")
    if tag_name != TAG_NAME:
        raise ReviewError(f"signed tag name must be exactly {TAG_NAME}")
    if tag_target != candidate_commit:
        raise ReviewError("signed tag target must equal the candidate commit")
    if tag_object == tag_target:
        raise ReviewError("signed annotated-tag object must differ from its target")


def _manifest_document(
    candidate_commit: str,
    candidate_tree: str,
    tag_name: str,
    tag_object: str,
    tag_target: str,
    assets: list[dict[str, Any]],
) -> dict[str, Any]:
    _validate_identity_values(
        candidate_commit, candidate_tree, tag_name, tag_object, tag_target
    )
    if len(EXPECTED_ASSET_FILES) > MAX_GITHUB_ASSETS:
        raise ReviewError("release pack exceeds GitHub's 1,000-asset limit")
    if sum(asset["size_bytes"] for asset in assets) >= (
        len(TIER_ORDER) * MAX_ASSET_BYTES
    ):
        raise ReviewError("release tar assets exceed the aggregate byte limit")
    return {
        "schema": SCHEMA,
        "release": {
            "version": VERSION,
            "author": AUTHOR,
            "doi": None,
            "zenodo": None,
        },
        "candidate": {"commit": candidate_commit, "tree": candidate_tree},
        "signed_tag": {
            "name": tag_name,
            "object": tag_object,
            "target": tag_target,
        },
        "signature": {
            "format": "sshsig",
            "namespace": SIGNATURE_NAMESPACE,
            "principal": SIGNING_PRINCIPAL,
        },
        "github_asset_count": len(EXPECTED_ASSET_FILES),
        "assets": assets,
    }


def _validate_inventory_path(value: Any, label: str) -> str:
    if type(value) is not str:
        raise ReviewError(f"{label} must be a string")
    _safe_relative(value, label)
    return value


def _validate_manifest(
    document: Any,
    *,
    expected_candidate: str,
    expected_tree: str,
    expected_tag_name: str,
    expected_tag_object: str,
    expected_tag_target: str,
) -> list[dict[str, Any]]:
    root = _require_object(
        document,
        {
            "schema",
            "release",
            "candidate",
            "signed_tag",
            "signature",
            "github_asset_count",
            "assets",
        },
        "release-assets manifest",
    )
    if root["schema"] != SCHEMA:
        raise ReviewError("release-assets manifest has an unexpected schema")
    release = _require_object(
        root["release"], {"version", "author", "doi", "zenodo"}, "release"
    )
    if release != {
        "version": VERSION,
        "author": AUTHOR,
        "doi": None,
        "zenodo": None,
    }:
        raise ReviewError("release identity must bind 0.9.0 without DOI or Zenodo")
    candidate = _require_object(root["candidate"], {"commit", "tree"}, "candidate")
    tag = _require_object(
        root["signed_tag"], {"name", "object", "target"}, "signed tag"
    )
    _validate_identity_values(
        candidate["commit"],
        candidate["tree"],
        tag["name"],
        tag["object"],
        tag["target"],
    )
    expected_values = (
        (candidate["commit"], expected_candidate, "candidate commit"),
        (candidate["tree"], expected_tree, "candidate tree"),
        (tag["name"], expected_tag_name, "signed tag name"),
        (tag["object"], expected_tag_object, "signed tag object"),
        (tag["target"], expected_tag_target, "signed tag target"),
    )
    for actual, expected, label in expected_values:
        if actual != expected:
            raise ReviewError(f"{label} does not match the required expectation")
    signature = _require_object(
        root["signature"], {"format", "namespace", "principal"}, "signature"
    )
    if signature != {
        "format": "sshsig",
        "namespace": SIGNATURE_NAMESPACE,
        "principal": SIGNING_PRINCIPAL,
    }:
        raise ReviewError("release-assets signature contract is not exact")
    if (
        type(root["github_asset_count"]) is not int
        or root["github_asset_count"] != len(EXPECTED_ASSET_FILES)
        or root["github_asset_count"] > MAX_GITHUB_ASSETS
    ):
        raise ReviewError("release-assets manifest has an invalid GitHub asset count")
    if type(root["assets"]) is not list or len(root["assets"]) != len(TIER_ORDER):
        raise ReviewError("release-assets manifest must contain exactly two tiers")

    assets: list[dict[str, Any]] = []
    for index, tier in enumerate(TIER_ORDER):
        asset = _require_object(
            root["assets"][index],
            {
                "tier",
                "asset_name",
                "root_prefix",
                "sha256",
                "size_bytes",
                "directories",
                "files",
            },
            f"assets[{index}]",
        )
        if asset["tier"] != tier:
            raise ReviewError("release-assets tiers are missing or out of order")
        if asset["asset_name"] != ASSET_NAMES[tier]:
            raise ReviewError(f"{tier} asset name is not exact")
        if asset["root_prefix"] != ROOT_PREFIXES[tier]:
            raise ReviewError(f"{tier} root prefix is not exact")
        if (
            type(asset["sha256"]) is not str
            or SHA256.fullmatch(asset["sha256"]) is None
        ):
            raise ReviewError(f"{tier} asset has an invalid SHA-256 digest")
        if type(asset["size_bytes"]) is not int:
            raise ReviewError(f"{tier} asset has an invalid byte count")
        _archive_size(asset["size_bytes"], asset["asset_name"])
        if type(asset["directories"]) is not list:
            raise ReviewError(f"{tier} directory inventory must be an array")
        directories = [
            _validate_inventory_path(value, f"{tier} directory")
            for value in asset["directories"]
        ]
        if directories != sorted(set(directories)):
            raise ReviewError(f"{tier} directory inventory is not unique and ordered")
        if type(asset["files"]) is not list:
            raise ReviewError(f"{tier} file inventory must be an array")
        if len(directories) + len(asset["files"]) > MAX_TREE_ENTRIES:
            raise ReviewError(
                f"{tier} inventory exceeds the {MAX_TREE_ENTRIES}-entry limit"
            )
        file_paths: list[str] = []
        for file_index, record in enumerate(asset["files"]):
            require_digest_record(record, f"{tier} files[{file_index}]")
            path = _validate_inventory_path(record["path"], f"{tier} file path")
            file_paths.append(path)
        if file_paths != sorted(set(file_paths)):
            raise ReviewError(f"{tier} file inventory is not unique and ordered")
        if set(file_paths) & set(directories):
            raise ReviewError(f"{tier} path is both a file and a directory")
        directory_set = set(directories)
        for relative in [*directories, *file_paths]:
            parent = PurePosixPath(relative).parent
            while parent != PurePosixPath("."):
                if parent.as_posix() not in directory_set:
                    raise ReviewError(
                        f"{tier} inventory omits parent directory {parent.as_posix()}"
                    )
                parent = parent.parent
        if "SHA256SUMS" not in file_paths:
            raise ReviewError(f"{tier} archive must retain its root SHA256SUMS")
        assets.append(asset)
    if sum(asset["size_bytes"] for asset in assets) >= (
        len(TIER_ORDER) * MAX_ASSET_BYTES
    ):
        raise ReviewError("release tar assets exceed the aggregate byte limit")
    return assets


def _write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ReviewError("no-follow output creation is unavailable")
    try:
        descriptor = os.open(path, flags | no_follow, mode)
    except OSError as error:
        raise ReviewError(f"refusing to replace output: {path}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _require_generated_regular_file(path: Path, maximum: int, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReviewError(f"generated {label} is missing: {path}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ReviewError(f"generated {label} is not a regular file")
    if metadata.st_size > maximum:
        raise ReviewError(f"generated {label} exceeds its {maximum}-byte limit")


def _read_snapshot_file(
    snapshot: _TreeSnapshot, row: _PathState, maximum: int, label: str
) -> bytes:
    if row.identity.size > maximum:
        raise ReviewError(f"{label} exceeds its {maximum}-byte limit")
    with _open_snapshot_file(snapshot, row) as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise ReviewError(f"{label} exceeds its {maximum}-byte limit")
    if len(data) != row.identity.size:
        raise ReviewError(f"{label} changed while read")
    return data


def _flat_asset_snapshot(root: Path | str) -> _TreeSnapshot:
    snapshot = _snapshot_tree(root)
    if snapshot.directories:
        raise ReviewError("release-assets directory contains a nested directory")
    actual = {row.path for row in snapshot.files}
    if actual != EXPECTED_ASSET_FILES:
        missing = sorted(EXPECTED_ASSET_FILES - actual)
        extra = sorted(actual - EXPECTED_ASSET_FILES)
        raise ReviewError(
            f"release-assets file set is not exact: missing={missing}, extra={extra}"
        )
    return snapshot


def _digest_snapshot_file(snapshot: _TreeSnapshot, row: _PathState) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with _open_snapshot_file(snapshot, row) as handle:
        for block in iter(lambda: handle.read(COPY_BLOCK_BYTES), b""):
            size += len(block)
            digest.update(block)
    if size != row.identity.size:
        raise ReviewError(f"asset changed while hashed: {row.path}")
    return digest.hexdigest(), size


def _expected_tar_rows(asset: dict[str, Any]) -> list[tuple[str, str, Any]]:
    rows: list[tuple[str, str, Any]] = [("directory", "", None)]
    rows.extend(("directory", path, None) for path in asset["directories"])
    rows.extend(("file", row["path"], row) for row in asset["files"])
    return [rows[0], *sorted(rows[1:], key=lambda row: row[1])]


def _validate_tar_metadata(
    member: tarfile.TarInfo, *, directory: bool, expected_size: int
) -> None:
    expected_type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    expected_mode = 0o755 if directory else 0o644
    if member.type != expected_type:
        raise ReviewError(f"tar member has an unsafe type: {member.name}")
    if member.mode != expected_mode:
        raise ReviewError(f"tar member has noncanonical mode: {member.name}")
    if (
        member.uid != 0
        or member.gid != 0
        or member.uname != ""
        or member.gname != ""
        or member.mtime != 0
        or member.size != expected_size
        or member.linkname != ""
        or member.devmajor != 0
        or member.devminor != 0
        or member.sparse is not None
    ):
        raise ReviewError(f"tar member has noncanonical metadata: {member.name}")


def _make_secure_directory(root: Path, relative: str) -> Path:
    target = contained_path(root, relative)
    try:
        target.mkdir(mode=0o700)
    except FileExistsError:
        metadata = target.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ReviewError(f"reconstruction path is unsafe: {relative}")
    return target


def _create_secure_file(root: Path, relative: str) -> tuple[Path, BinaryIO]:
    target = contained_path(root, relative)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ReviewError("no-follow reconstruction is unavailable")
    try:
        descriptor = os.open(target, flags | no_follow, 0o600)
    except OSError as error:
        raise ReviewError(f"refusing unsafe reconstruction path: {relative}") from error
    try:
        return target, os.fdopen(descriptor, "wb", closefd=True)
    except BaseException:
        os.close(descriptor)
        target.unlink(missing_ok=True)
        raise


def _verify_archive(
    snapshot: _TreeSnapshot,
    row: _PathState,
    asset: dict[str, Any],
    *,
    extract_root: Path | None,
) -> None:
    _archive_size(row.identity.size, row.path)
    actual_digest, actual_size = _digest_snapshot_file(snapshot, row)
    if (actual_digest, actual_size) != (asset["sha256"], asset["size_bytes"]):
        raise ReviewError(f"release asset digest or size differs: {row.path}")
    prefix = asset["root_prefix"]
    expected_rows = _expected_tar_rows(asset)
    canonical = _DigestSink()
    try:
        with _open_snapshot_file(snapshot, row) as source:
            with tarfile.open(
                fileobj=source, mode="r:", encoding="utf-8", errors="strict"
            ) as archive:
                members = iter(archive)
                seen_names: set[str] = set()
                with tarfile.open(
                    fileobj=canonical,
                    mode="w|",
                    format=tarfile.PAX_FORMAT,
                    dereference=False,
                    encoding="utf-8",
                    errors="strict",
                ) as regenerated:
                    for kind, relative, record in expected_rows:
                        try:
                            member = next(members)
                        except StopIteration as error:
                            raise ReviewError(
                                f"tar member set is not exact: {row.path}"
                            ) from error
                        if member.name in seen_names:
                            raise ReviewError(
                                f"tar contains a duplicate member: {row.path}"
                            )
                        seen_names.add(member.name)
                        expected_name = (
                            prefix if not relative else f"{prefix}/{relative}"
                        )
                        if member.name != expected_name:
                            raise ReviewError(
                                f"tar order or path is not exact: {member.name!r}"
                            )
                        directory = kind == "directory"
                        expected_size = 0 if directory else record["size_bytes"]
                        _validate_tar_metadata(
                            member,
                            directory=directory,
                            expected_size=expected_size,
                        )
                        regenerated_info = _tar_info(
                            expected_name,
                            directory=directory,
                            size=expected_size,
                        )
                        if directory:
                            regenerated.addfile(regenerated_info)
                            if extract_root is not None:
                                _make_secure_directory(extract_root, expected_name)
                            continue
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            raise ReviewError(f"cannot read tar member: {member.name}")
                        destination_path: Path | None = None
                        destination: BinaryIO | None = None
                        if extract_root is not None:
                            destination_path, destination = _create_secure_file(
                                extract_root, expected_name
                            )
                        try:
                            reader = _InventoryReader(
                                extracted, expected_size, destination
                            )
                            regenerated.addfile(regenerated_info, reader)
                            member_digest = reader.finish()
                            if member_digest != record["sha256"]:
                                raise ReviewError(
                                    f"tar member digest differs: {member.name}"
                                )
                            if destination is not None:
                                destination.flush()
                                os.fsync(destination.fileno())
                        except BaseException:
                            if destination is not None:
                                destination.close()
                            if destination_path is not None:
                                destination_path.unlink(missing_ok=True)
                            raise
                        finally:
                            extracted.close()
                        if destination is not None:
                            destination.close()
                    try:
                        unexpected = next(members)
                    except StopIteration:
                        unexpected = None
                    if unexpected is not None:
                        if unexpected.name in seen_names:
                            raise ReviewError(
                                f"tar contains a duplicate member: {row.path}"
                            )
                        raise ReviewError(f"tar member set is not exact: {row.path}")
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ReviewError(f"cannot verify canonical tar {row.path}: {error}") from error
    if (canonical.hexdigest(), canonical.size) != (actual_digest, actual_size):
        raise ReviewError(
            f"tar bytes are not in the canonical representation: {row.path}"
        )


def _read_external_regular(path: Path | str, maximum: int, label: str) -> bytes:
    absolute = _absolute(path)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or non_block is None:
        raise ReviewError("atomic nonblocking no-follow reads are unavailable")
    try:
        descriptor = os.open(
            absolute,
            os.O_RDONLY | no_follow | non_block | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise ReviewError(f"{label} is missing or unsafe: {absolute}") from error
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        before = _identity(os.fstat(handle.fileno()))
        if not stat.S_ISREG(before.mode) or before.size > maximum:
            raise ReviewError(f"{label} is not a bounded regular file")
        data = handle.read(maximum + 1)
        after = _identity(os.fstat(handle.fileno()))
    if before != after or len(data) != before.size:
        raise ReviewError(f"{label} changed while read")
    if len(data) > maximum:
        raise ReviewError(f"{label} exceeds its {maximum}-byte limit")
    return data


def _verify_manifest_signature(
    manifest_bytes: bytes, signature_bytes: bytes, allowed_signers: Path | str
) -> None:
    allowed_bytes = _read_external_regular(
        allowed_signers, MAX_ALLOWED_SIGNERS_BYTES, "allowed-signers trust root"
    )
    with tempfile.TemporaryDirectory(prefix="galadriel-release-assets-verify-") as name:
        root = Path(name)
        manifest = root / MANIFEST_NAME
        signature = root / SIGNATURE_NAME
        trust_root = root / "ALLOWED_SIGNERS"
        _write_exclusive(manifest, manifest_bytes)
        _write_exclusive(signature, signature_bytes)
        _write_exclusive(trust_root, allowed_bytes)
        verify_signature(
            manifest,
            signature,
            trust_root,
            SIGNATURE_NAMESPACE,
        )


def _verify_release_assets(
    assets_root: Path | str,
    allowed_signers: Path | str,
    *,
    expected_candidate: str,
    expected_tree: str,
    expected_tag_name: str,
    expected_tag_object: str,
    expected_tag_target: str,
    extract_root: Path | None = None,
) -> dict[str, Any]:
    _validate_identity_values(
        expected_candidate,
        expected_tree,
        expected_tag_name,
        expected_tag_object,
        expected_tag_target,
    )
    snapshot = _flat_asset_snapshot(assets_root)
    files = snapshot.file_map()
    manifest_bytes = _read_snapshot_file(
        snapshot, files[MANIFEST_NAME], MAX_MANIFEST_BYTES, "release-assets manifest"
    )
    signature_bytes = _read_snapshot_file(
        snapshot, files[SIGNATURE_NAME], MAX_SIGNATURE_BYTES, "detached signature"
    )
    _verify_manifest_signature(manifest_bytes, signature_bytes, allowed_signers)
    try:
        document = loads_json(manifest_bytes)
    except (UnicodeError, ValueError) as error:
        raise ReviewError(f"cannot parse release-assets manifest: {error}") from error
    if canonical_json(document) != manifest_bytes:
        raise ReviewError("release-assets manifest is not canonical JSON")
    asset_rows = _validate_manifest(
        document,
        expected_candidate=expected_candidate,
        expected_tree=expected_tree,
        expected_tag_name=expected_tag_name,
        expected_tag_object=expected_tag_object,
        expected_tag_target=expected_tag_target,
    )
    for asset in asset_rows:
        _verify_archive(
            snapshot,
            files[asset["asset_name"]],
            asset,
            extract_root=extract_root,
        )
    if _flat_asset_snapshot(snapshot.root) != snapshot:
        raise ReviewError("release-assets directory changed while verified")
    return document


def verify_release_assets(
    assets_root: Path | str,
    allowed_signers: Path | str,
    *,
    expected_candidate: str,
    expected_tree: str,
    expected_tag_name: str,
    expected_tag_object: str,
    expected_tag_target: str,
) -> dict[str, Any]:
    """Authenticate and semantically verify one complete release-asset set."""

    return _verify_release_assets(
        assets_root,
        allowed_signers,
        expected_candidate=expected_candidate,
        expected_tree=expected_tree,
        expected_tag_name=expected_tag_name,
        expected_tag_object=expected_tag_object,
        expected_tag_target=expected_tag_target,
    )


def _assert_new_directory_destination(destination: Path, label: str) -> None:
    if destination.exists() or destination.is_symlink():
        raise ReviewError(f"refusing to replace existing {label}: {destination}")
    try:
        metadata = destination.parent.lstat()
    except OSError as error:
        raise ReviewError(f"{label} parent is missing: {destination.parent}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ReviewError(f"{label} parent is unsafe: {destination.parent}")


def _resolved_destination(destination: Path) -> Path:
    return destination.parent.resolve(strict=True) / destination.name


def _overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _reject_path_overlap(inputs: list[Path], destination: Path) -> None:
    resolved_inputs = [value.resolve(strict=True) for value in inputs]
    resolved_destination = _resolved_destination(destination)
    for root in resolved_inputs:
        if _overlap(root, resolved_destination):
            raise ReviewError("release output must not overlap an evidence input")
    for index, root in enumerate(resolved_inputs):
        for other in resolved_inputs[index + 1 :]:
            if _overlap(root, other):
                raise ReviewError("qualification and closure roots must not overlap")


def _reject_signing_key_in_inputs(signing_key: Path, inputs: list[Path]) -> None:
    try:
        resolved_key = signing_key.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ReviewError(f"SSH signing key is unavailable: {signing_key}") from error
    for root in inputs:
        resolved_root = root.resolve(strict=True)
        if resolved_key == resolved_root or resolved_root in resolved_key.parents:
            raise ReviewError(
                "the signing-key handle must remain outside both evidence roots"
            )


def _remove_staging(staging: Path, original: BaseException) -> None:
    if not staging.exists():
        return
    try:
        shutil.rmtree(staging)
    except OSError as cleanup_error:
        raise ReviewError(
            f"release packaging failed and staging cleanup also failed: {staging}: "
            f"{cleanup_error}"
        ) from original


def build_release_assets(
    qualification_root: Path | str,
    closure_root: Path | str,
    output: Path | str,
    signing_key: Path | str,
    *,
    candidate_commit: str,
    candidate_tree: str,
    tag_name: str,
    tag_object: str,
    tag_target: str,
) -> Path:
    """Build, self-verify, and atomically publish a new four-file asset pack."""

    qualification_path = _absolute(qualification_root)
    closure_path = _absolute(closure_root)
    destination = _absolute(output)
    key = _absolute(signing_key)
    _reject_signing_key_in_inputs(key, [qualification_path, closure_path])
    qualification = _snapshot_tree(qualification_path)
    closure = _snapshot_tree(closure_path)
    _validate_identity_values(
        candidate_commit, candidate_tree, tag_name, tag_object, tag_target
    )
    _assert_new_directory_destination(destination, "release-assets output")
    _reject_path_overlap([qualification.root, closure.root], destination)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent)
    )
    os.chmod(staging, 0o700)
    try:
        assets = [
            _write_archive(
                qualification, staging / ASSET_NAMES["qualification"], "qualification"
            ),
            _write_archive(closure, staging / ASSET_NAMES["closure"], "closure"),
        ]
        if _snapshot_tree(qualification.root) != qualification:
            raise ReviewError("qualification evidence changed during packaging")
        if _snapshot_tree(closure.root) != closure:
            raise ReviewError("closure evidence changed during packaging")
        document = _manifest_document(
            candidate_commit,
            candidate_tree,
            tag_name,
            tag_object,
            tag_target,
            assets,
        )
        manifest = staging / MANIFEST_NAME
        manifest_bytes = canonical_json(document)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ReviewError(
                "generated release-assets manifest exceeds its "
                f"{MAX_MANIFEST_BYTES}-byte limit"
            )
        _write_exclusive(manifest, manifest_bytes)
        signature = sign_file(manifest, key, SIGNATURE_NAMESPACE)
        os.chmod(signature, 0o600)
        _require_generated_regular_file(
            signature, MAX_SIGNATURE_BYTES, "detached signature"
        )
        with tempfile.TemporaryDirectory(
            prefix="galadriel-release-assets-trust-"
        ) as temporary:
            allowed_signers = Path(temporary) / "ALLOWED_SIGNERS"
            derive_external_allowed_signers(key, allowed_signers)
            _verify_release_assets(
                staging,
                allowed_signers,
                expected_candidate=candidate_commit,
                expected_tree=candidate_tree,
                expected_tag_name=tag_name,
                expected_tag_object=tag_object,
                expected_tag_target=tag_target,
            )
        if _snapshot_tree(qualification.root) != qualification:
            raise ReviewError("qualification evidence changed before publication")
        if _snapshot_tree(closure.root) != closure:
            raise ReviewError("closure evidence changed before publication")
        publish_staged_output(staging, destination)
    except BaseException as error:
        _remove_staging(staging, error)
        raise
    return destination


def extract_release_assets(
    assets_root: Path | str,
    allowed_signers: Path | str,
    output: Path | str,
    *,
    expected_candidate: str,
    expected_tree: str,
    expected_tag_name: str,
    expected_tag_object: str,
    expected_tag_target: str,
) -> Path:
    """Verify and safely reconstruct both fixed-prefix evidence trees."""

    assets = _absolute(assets_root)
    destination = _absolute(output)
    _assert_new_directory_destination(destination, "reconstruction output")
    if _overlap(assets.resolve(strict=True), _resolved_destination(destination)):
        raise ReviewError("reconstruction output must not overlap the asset pack")
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent)
    )
    os.chmod(staging, 0o700)
    try:
        _verify_release_assets(
            assets,
            allowed_signers,
            expected_candidate=expected_candidate,
            expected_tree=expected_tree,
            expected_tag_name=expected_tag_name,
            expected_tag_object=expected_tag_object,
            expected_tag_target=expected_tag_target,
            extract_root=staging,
        )
        publish_staged_output(staging, destination)
    except BaseException as error:
        _remove_staging(staging, error)
        raise
    return destination


def _add_expectations(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-candidate", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-tag-name", default=TAG_NAME)
    parser.add_argument("--expected-tag-object", required=True)
    parser.add_argument("--expected-tag-target", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build a new signed release-asset pack")
    build.add_argument("--qualification-root", required=True, type=Path)
    build.add_argument("--closure-root", required=True, type=Path)
    build.add_argument("--out", required=True, type=Path)
    build.add_argument("--signing-key", required=True, type=Path)
    build.add_argument("--candidate-commit", required=True)
    build.add_argument("--candidate-tree", required=True)
    build.add_argument("--tag-name", default=TAG_NAME)
    build.add_argument("--tag-object", required=True)
    build.add_argument("--tag-target", required=True)

    verify = commands.add_parser("verify", help="verify a complete release-asset pack")
    verify.add_argument("--assets", required=True, type=Path)
    verify.add_argument("--allowed-signers", required=True, type=Path)
    _add_expectations(verify)

    extract = commands.add_parser(
        "extract",
        aliases=["reconstruct"],
        help="verify then safely reconstruct both evidence roots",
    )
    extract.add_argument("--assets", required=True, type=Path)
    extract.add_argument("--allowed-signers", required=True, type=Path)
    extract.add_argument("--out", required=True, type=Path)
    _add_expectations(extract)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "build":
            output = build_release_assets(
                arguments.qualification_root,
                arguments.closure_root,
                arguments.out,
                arguments.signing_key,
                candidate_commit=arguments.candidate_commit,
                candidate_tree=arguments.candidate_tree,
                tag_name=arguments.tag_name,
                tag_object=arguments.tag_object,
                tag_target=arguments.tag_target,
            )
        elif arguments.command == "verify":
            verify_release_assets(
                arguments.assets,
                arguments.allowed_signers,
                expected_candidate=arguments.expected_candidate,
                expected_tree=arguments.expected_tree,
                expected_tag_name=arguments.expected_tag_name,
                expected_tag_object=arguments.expected_tag_object,
                expected_tag_target=arguments.expected_tag_target,
            )
            output = arguments.assets
        else:
            output = extract_release_assets(
                arguments.assets,
                arguments.allowed_signers,
                arguments.out,
                expected_candidate=arguments.expected_candidate,
                expected_tree=arguments.expected_tree,
                expected_tag_name=arguments.expected_tag_name,
                expected_tag_object=arguments.expected_tag_object,
                expected_tag_target=arguments.expected_tag_target,
            )
    except PublicationDurabilityError as error:
        print(f"error: {error}", file=sys.stderr)
        return 3
    except (ReviewError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
