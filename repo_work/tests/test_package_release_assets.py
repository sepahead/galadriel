"""Adversarial tests for the deterministic GitHub release-asset packager."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

from common import ReviewError, canonical_json  # noqa: E402
import package_release_assets as pack  # noqa: E402
from release_assurance import (  # noqa: E402
    derive_external_allowed_signers,
    sign_file,
)


COMMIT = "1" * 40
TREE = "2" * 40
TAG_OBJECT = "3" * 40


class PackageReleaseAssetsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.qualification = self.root / "qualification"
        self.closure = self.root / "closure"
        self.qualification.mkdir()
        self.closure.mkdir()
        (self.qualification / "SHA256SUMS").write_text(
            "qualification checksums\n", encoding="utf-8"
        )
        (self.qualification / "report.json").write_text(
            '{"status":"qualified"}\n', encoding="utf-8"
        )
        (self.qualification / "nested").mkdir()
        (self.qualification / "nested" / "evidence.bin").write_bytes(
            b"qualification evidence\x00\xff"
        )
        (self.qualification / "empty").mkdir()
        long_directory = self.qualification / ("long-directory-" + "x" * 96)
        long_directory.mkdir()
        (long_directory / ("long-file-" + "y" * 110 + ".txt")).write_text(
            "PAX path evidence\n", encoding="utf-8"
        )
        (self.qualification / "unicode-Δ.txt").write_text(
            "explicit UTF-8 path encoding\n", encoding="utf-8"
        )
        (self.closure / "SHA256SUMS").write_text(
            "closure checksums\n", encoding="utf-8"
        )
        (self.closure / "decision.json").write_text(
            '{"decision":"GO"}\n', encoding="utf-8"
        )
        self.key = self.root / "signing-key"
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                pack.SIGNING_PRINCIPAL,
                "-f",
                str(self.key),
            ],
            check=True,
        )
        self.allowed_signers = self.root / "ALLOWED_SIGNERS"
        derive_external_allowed_signers(self.key, self.allowed_signers)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, name: str = "assets") -> Path:
        return pack.build_release_assets(
            self.qualification,
            self.closure,
            self.root / name,
            self.key,
            candidate_commit=COMMIT,
            candidate_tree=TREE,
            tag_name=pack.TAG_NAME,
            tag_object=TAG_OBJECT,
            tag_target=COMMIT,
        )

    def expectations(self) -> dict[str, str]:
        return {
            "expected_candidate": COMMIT,
            "expected_tree": TREE,
            "expected_tag_name": pack.TAG_NAME,
            "expected_tag_object": TAG_OBJECT,
            "expected_tag_target": COMMIT,
        }

    def verify(self, assets: Path) -> dict[str, object]:
        return pack.verify_release_assets(
            assets, self.allowed_signers, **self.expectations()
        )

    def manifest(self, assets: Path) -> dict[str, object]:
        return json.loads((assets / pack.MANIFEST_NAME).read_text(encoding="utf-8"))

    def resign(
        self, assets: Path, *, namespace: str = pack.SIGNATURE_NAMESPACE
    ) -> None:
        signature = assets / pack.SIGNATURE_NAME
        signature.unlink(missing_ok=True)
        sign_file(assets / pack.MANIFEST_NAME, self.key, namespace)

    def write_manifest(self, assets: Path, document: dict[str, object]) -> None:
        (assets / pack.MANIFEST_NAME).write_bytes(canonical_json(document))
        self.resign(assets)

    def rewrite_archive(
        self,
        assets: Path,
        tier: str,
        mutate: object,
    ) -> None:
        archive_path = assets / pack.ASSET_NAMES[tier]
        rows: list[tuple[tarfile.TarInfo, bytes | None]] = []
        with tarfile.open(archive_path, mode="r:") as archive:
            for member in archive.getmembers():
                source = archive.extractfile(member) if member.isfile() else None
                data = source.read() if source is not None else None
                if source is not None:
                    source.close()
                rows.append((copy.copy(member), data))
        mutate(rows)
        archive_path.unlink()
        with tarfile.open(
            archive_path, mode="w|", format=tarfile.PAX_FORMAT
        ) as archive:
            for member, data in rows:
                if data is None:
                    archive.addfile(member)
                else:
                    import io

                    archive.addfile(member, io.BytesIO(data))
        document = self.manifest(assets)
        digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        size = archive_path.stat().st_size
        for row in document["assets"]:
            if row["tier"] == tier:
                row["sha256"] = digest
                row["size_bytes"] = size
        self.write_manifest(assets, document)

    def test_build_verify_and_manifest_contract(self) -> None:
        assets = self.build()
        document = self.verify(assets)
        self.assertEqual(
            set(path.name for path in assets.iterdir()), pack.EXPECTED_ASSET_FILES
        )
        self.assertEqual(document["schema"], pack.SCHEMA)
        self.assertEqual(
            document["release"],
            {
                "author": "Sepehr Mahmoudian",
                "doi": None,
                "version": "0.9.0",
                "zenodo": None,
            },
        )
        self.assertEqual(document["candidate"], {"commit": COMMIT, "tree": TREE})
        self.assertEqual(
            document["signed_tag"],
            {"name": "v0.9.0", "object": TAG_OBJECT, "target": COMMIT},
        )
        self.assertEqual(document["github_asset_count"], 4)
        for asset in document["assets"]:
            self.assertLess(asset["size_bytes"], 2 * 1024**3)
            self.assertIn("SHA256SUMS", [row["path"] for row in asset["files"]])

    def test_cli_build_dispatches_every_identity_and_path_flag(self) -> None:
        output = self.root / "cli-assets"
        arguments = [
            "build",
            "--qualification-root",
            str(self.qualification),
            "--closure-root",
            str(self.closure),
            "--out",
            str(output),
            "--signing-key",
            str(self.key),
            "--candidate-commit",
            COMMIT,
            "--candidate-tree",
            TREE,
            "--tag-name",
            pack.TAG_NAME,
            "--tag-object",
            TAG_OBJECT,
            "--tag-target",
            COMMIT,
        ]

        with (
            mock.patch.object(
                pack, "build_release_assets", return_value=output
            ) as build,
            mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            self.assertEqual(pack.main(arguments), 0)

        build.assert_called_once_with(
            self.qualification,
            self.closure,
            output,
            self.key,
            candidate_commit=COMMIT,
            candidate_tree=TREE,
            tag_name=pack.TAG_NAME,
            tag_object=TAG_OBJECT,
            tag_target=COMMIT,
        )
        self.assertEqual(stdout.getvalue(), f"{output}\n")

    def test_cli_verify_extract_and_reconstruct_dispatch_exact_expectations(
        self,
    ) -> None:
        assets = self.root / "downloaded-assets"
        reconstructed = self.root / "reconstructed-cli"
        expectations = [
            "--expected-candidate",
            COMMIT,
            "--expected-tree",
            TREE,
            "--expected-tag-name",
            pack.TAG_NAME,
            "--expected-tag-object",
            TAG_OBJECT,
            "--expected-tag-target",
            COMMIT,
        ]
        with (
            mock.patch.object(pack, "verify_release_assets") as verify,
            mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            status = pack.main(
                [
                    "verify",
                    "--assets",
                    str(assets),
                    "--allowed-signers",
                    str(self.allowed_signers),
                    *expectations,
                ]
            )
        self.assertEqual(status, 0)
        verify.assert_called_once_with(
            assets,
            self.allowed_signers,
            **self.expectations(),
        )
        self.assertEqual(stdout.getvalue(), f"{assets}\n")

        for command in ("extract", "reconstruct"):
            with self.subTest(command=command):
                with (
                    mock.patch.object(
                        pack,
                        "extract_release_assets",
                        return_value=reconstructed,
                    ) as extract,
                    mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
                ):
                    status = pack.main(
                        [
                            command,
                            "--assets",
                            str(assets),
                            "--allowed-signers",
                            str(self.allowed_signers),
                            "--out",
                            str(reconstructed),
                            *expectations,
                        ]
                    )
                self.assertEqual(status, 0)
                extract.assert_called_once_with(
                    assets,
                    self.allowed_signers,
                    reconstructed,
                    **self.expectations(),
                )
                self.assertEqual(stdout.getvalue(), f"{reconstructed}\n")

    def test_cli_maps_review_os_and_durability_failures_to_stable_statuses(
        self,
    ) -> None:
        arguments = [
            "verify",
            "--assets",
            str(self.root / "assets"),
            "--allowed-signers",
            str(self.allowed_signers),
            "--expected-candidate",
            COMMIT,
            "--expected-tree",
            TREE,
            "--expected-tag-object",
            TAG_OBJECT,
            "--expected-tag-target",
            COMMIT,
        ]
        cases = (
            (ReviewError("review failure"), 2),
            (OSError("operating-system failure"), 2),
            (pack.PublicationDurabilityError("durability uncertain"), 3),
        )
        for error, expected in cases:
            with self.subTest(error=type(error).__name__):
                with (
                    mock.patch.object(pack, "verify_release_assets", side_effect=error),
                    mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
                ):
                    self.assertEqual(pack.main(arguments), expected)
                self.assertIn(str(error), stderr.getvalue())

    def test_archives_and_manifest_are_deterministic(self) -> None:
        first = self.build("first")
        second = self.build("second")
        for name in pack.EXPECTED_ASSET_FILES:
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

    def test_tar_read_write_and_regeneration_pin_utf8_strictly(self) -> None:
        calls: list[tuple[str | None, str | None, str | None]] = []
        real_open = tarfile.open

        def record_open(*args: object, **kwargs: object) -> tarfile.TarFile:
            calls.append(
                (
                    kwargs.get("mode") if isinstance(kwargs.get("mode"), str) else None,
                    kwargs.get("encoding")
                    if isinstance(kwargs.get("encoding"), str)
                    else None,
                    kwargs.get("errors")
                    if isinstance(kwargs.get("errors"), str)
                    else None,
                )
            )
            return real_open(*args, **kwargs)

        with mock.patch.object(pack.tarfile, "open", side_effect=record_open):
            assets = self.build("utf8")
            self.verify(assets)

        self.assertGreaterEqual(len(calls), 6)
        self.assertTrue(
            all(
                encoding == "utf-8" and errors == "strict"
                for _, encoding, errors in calls
            )
        )

    def test_extract_restores_fixed_prefixes_paths_empty_directories_and_bytes(
        self,
    ) -> None:
        assets = self.build()
        output = pack.extract_release_assets(
            assets,
            self.allowed_signers,
            self.root / "reconstructed",
            **self.expectations(),
        )
        for tier, source in (
            ("qualification", self.qualification),
            ("closure", self.closure),
        ):
            restored = output / pack.ROOT_PREFIXES[tier]
            source_paths = sorted(
                path.relative_to(source).as_posix() for path in source.rglob("*")
            )
            restored_paths = sorted(
                path.relative_to(restored).as_posix() for path in restored.rglob("*")
            )
            self.assertEqual(restored_paths, source_paths)
            for relative in source_paths:
                original = source / relative
                reconstructed = restored / relative
                if original.is_file():
                    self.assertEqual(reconstructed.read_bytes(), original.read_bytes())
                    self.assertEqual(stat.S_IMODE(reconstructed.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)

    def test_refuses_build_and_extract_overwrite(self) -> None:
        assets = self.build()
        with self.assertRaisesRegex(ReviewError, "refusing to replace"):
            self.build()
        output = self.root / "reconstructed"
        output.mkdir()
        with self.assertRaisesRegex(ReviewError, "refusing to replace"):
            pack.extract_release_assets(
                assets,
                self.allowed_signers,
                output,
                **self.expectations(),
            )

    def test_rejects_extra_and_missing_asset_files(self) -> None:
        extra = self.build("extra")
        (extra / "unexpected.txt").write_text("extra\n", encoding="utf-8")
        with self.assertRaisesRegex(ReviewError, "file set is not exact"):
            self.verify(extra)
        missing = self.build("missing")
        (missing / pack.ASSET_NAMES["closure"]).unlink()
        with self.assertRaisesRegex(ReviewError, "file set is not exact"):
            self.verify(missing)

    def test_rejects_archive_tamper(self) -> None:
        assets = self.build()
        with (assets / pack.ASSET_NAMES["qualification"]).open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaisesRegex(ReviewError, "digest or size differs"):
            self.verify(assets)

    def test_rejects_reordered_tar_members(self) -> None:
        assets = self.build()

        def reorder(rows: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
            rows[1], rows[2] = rows[2], rows[1]

        self.rewrite_archive(assets, "qualification", reorder)
        with self.assertRaisesRegex(ReviewError, "tar order or path is not exact"):
            self.verify(assets)

    def test_rejects_manifest_tamper_before_semantic_parsing(self) -> None:
        assets = self.build()
        (assets / pack.MANIFEST_NAME).write_bytes(b"not json\n")
        with self.assertRaisesRegex(ReviewError, "invalid galadriel-release-assets"):
            self.verify(assets)

    def test_rejects_wrong_signature_namespace(self) -> None:
        assets = self.build()
        self.resign(assets, namespace="wrong-release-assets")
        with self.assertRaisesRegex(ReviewError, "invalid galadriel-release-assets"):
            self.verify(assets)

    def test_rejects_duplicate_json_keys(self) -> None:
        assets = self.build()
        manifest = assets / pack.MANIFEST_NAME
        original = manifest.read_bytes()
        manifest.write_bytes(b'{"schema":"duplicate",' + original[1:])
        self.resign(assets)
        with self.assertRaisesRegex(ReviewError, "duplicate JSON key"):
            self.verify(assets)

    def test_rejects_wrong_candidate_tree_and_tag_expectations(self) -> None:
        assets = self.build()
        cases = (
            {
                **self.expectations(),
                "expected_candidate": "4" * 40,
                "expected_tag_target": "4" * 40,
            },
            {**self.expectations(), "expected_tree": "4" * 40},
            {**self.expectations(), "expected_tag_object": "4" * 40},
        )
        for expectations in cases:
            with self.subTest(expectations=expectations):
                with self.assertRaisesRegex(ReviewError, "does not match"):
                    pack.verify_release_assets(
                        assets, self.allowed_signers, **expectations
                    )

    def test_strict_two_gib_boundary_and_github_asset_limit(self) -> None:
        assets = self.build()
        boundary = (assets / pack.ASSET_NAMES["qualification"]).stat().st_size
        with mock.patch.object(pack, "MAX_ASSET_BYTES", boundary):
            with self.assertRaisesRegex(ReviewError, "strictly smaller"):
                self.verify(assets)
        with mock.patch.object(pack, "MAX_GITHUB_ASSETS", 3):
            with self.assertRaisesRegex(ReviewError, "GitHub asset count"):
                self.verify(assets)

    def test_build_streaming_cap_stops_before_limit_and_cleans_output(self) -> None:
        payload_size = sum(
            path.stat().st_size
            for path in self.qualification.rglob("*")
            if path.is_file()
        )
        output = self.root / "bounded-build"
        with mock.patch.object(pack, "MAX_ASSET_BYTES", payload_size + 1):
            with self.assertRaisesRegex(ReviewError, "strictly smaller"):
                self.build("bounded-build")
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".bounded-build.staging-*")), [])

    def test_bounded_manifest_and_signature_reads(self) -> None:
        assets = self.build()
        manifest_size = (assets / pack.MANIFEST_NAME).stat().st_size
        with mock.patch.object(pack, "MAX_MANIFEST_BYTES", manifest_size - 1):
            with self.assertRaisesRegex(ReviewError, "exceeds"):
                self.verify(assets)
        signature_size = (assets / pack.SIGNATURE_NAME).stat().st_size
        with mock.patch.object(pack, "MAX_SIGNATURE_BYTES", signature_size - 1):
            with self.assertRaisesRegex(ReviewError, "exceeds"):
                self.verify(assets)

    def test_build_bounds_generated_manifest_and_signature_and_cleans_staging(
        self,
    ) -> None:
        cases = (
            ("MAX_MANIFEST_BYTES", 1, "generated release-assets manifest"),
            ("MAX_SIGNATURE_BYTES", 1, "generated detached signature"),
        )
        for constant, limit, message in cases:
            name = f"bounded-{constant.lower()}"
            with self.subTest(constant=constant):
                with mock.patch.object(pack, constant, limit):
                    with self.assertRaisesRegex(ReviewError, message):
                        self.build(name)
                self.assertFalse((self.root / name).exists())
                self.assertEqual(list(self.root.glob(f".{name}.staging-*")), [])

    def test_rejects_symlink_fifo_and_control_character_inputs(self) -> None:
        (self.qualification / "unsafe-link").symlink_to("report.json")
        with self.assertRaisesRegex(ReviewError, "symlink"):
            self.build("symlink")
        (self.qualification / "unsafe-link").unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.qualification / "unsafe-fifo")
            with self.assertRaisesRegex(ReviewError, "special file"):
                self.build("fifo")
            (self.qualification / "unsafe-fifo").unlink()
        (self.qualification / "unsafe\nname").write_text("unsafe\n", encoding="utf-8")
        with self.assertRaisesRegex(ReviewError, "control character"):
            self.build("control")

    def test_rejects_hard_link_alias_and_bounds_wide_inventory(self) -> None:
        outside = self.root / "outside-evidence.txt"
        outside.write_text("outside bytes\n", encoding="utf-8")
        os.link(outside, self.qualification / "unsafe-hardlink")
        with self.assertRaisesRegex(ReviewError, "multiply linked"):
            self.build("hardlink")
        (self.qualification / "unsafe-hardlink").unlink()
        with mock.patch.object(pack, "MAX_TREE_ENTRIES", 2):
            with self.assertRaisesRegex(ReviewError, "entry limit"):
                self.build("wide")

    def test_inventory_bound_counts_pending_ancestor_rows(self) -> None:
        fixture = self.root / "pending-ancestor"
        fixture.mkdir()
        deep = fixture / "00-deep"
        deep.mkdir()
        (deep / "one").write_text("one\n", encoding="utf-8")
        (deep / "two").write_text("two\n", encoding="utf-8")
        (fixture / "pending-a").mkdir()
        (fixture / "pending-b").mkdir()
        # Three root rows remain retained while recursion enters 00-deep. The
        # global discovery counter rejects its second child at the four-entry cap.
        with mock.patch.object(pack, "MAX_TREE_ENTRIES", 4):
            with self.assertRaisesRegex(ReviewError, "entry limit"):
                pack._snapshot_tree(fixture)

    def test_rejects_input_change_during_build_and_cleans_staging(self) -> None:
        original = pack._write_archive
        changed = False

        def change_after_archive(
            snapshot: object, destination: Path, tier: str
        ) -> dict[str, object]:
            nonlocal changed
            result = original(snapshot, destination, tier)
            if tier == "qualification" and not changed:
                changed = True
                (self.qualification / "report.json").write_text(
                    '{"status":"changed"}\n', encoding="utf-8"
                )
            return result

        output = self.root / "changing"
        with mock.patch.object(
            pack, "_write_archive", side_effect=change_after_archive
        ):
            with self.assertRaisesRegex(ReviewError, "changed"):
                self.build("changing")
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".changing.staging-*")), [])

    def test_rejects_signing_key_inside_evidence_root(self) -> None:
        embedded_key = self.qualification / "embedded-private-key"
        embedded_key.write_bytes(self.key.read_bytes())
        os.chmod(embedded_key, 0o600)
        output = self.root / "key-leak"
        with self.assertRaisesRegex(ReviewError, "signing-key handle"):
            pack.build_release_assets(
                self.qualification,
                self.closure,
                output,
                embedded_key,
                candidate_commit=COMMIT,
                candidate_tree=TREE,
                tag_name=pack.TAG_NAME,
                tag_object=TAG_OBJECT,
                tag_target=COMMIT,
            )
        self.assertFalse(output.exists())

    def test_rejects_tar_traversal_member(self) -> None:
        assets = self.build()

        def mutate(rows: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
            rows[1][0].name = f"{pack.ROOT_PREFIXES['qualification']}/../escape"

        self.rewrite_archive(assets, "qualification", mutate)
        with self.assertRaisesRegex(ReviewError, "order or path"):
            self.verify(assets)

    def test_rejects_tar_symlink_and_special_member_types(self) -> None:
        for member_type in (tarfile.SYMTYPE, tarfile.CHRTYPE):
            with self.subTest(member_type=member_type):
                assets = self.build(f"unsafe-{member_type.hex()}")

                def mutate(
                    rows: list[tuple[tarfile.TarInfo, bytes | None]],
                    member_type: bytes = member_type,
                ) -> None:
                    member, _ = rows[1]
                    member.type = member_type
                    member.size = 0
                    member.linkname = (
                        "../escape" if member_type == tarfile.SYMTYPE else ""
                    )
                    rows[1] = (member, None)

                self.rewrite_archive(assets, "qualification", mutate)
                with self.assertRaisesRegex(ReviewError, "unsafe type"):
                    self.verify(assets)

    def test_rejects_duplicate_tar_member(self) -> None:
        assets = self.build()

        def mutate(rows: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
            member, data = rows[-1]
            rows.append((copy.copy(member), data))

        self.rewrite_archive(assets, "qualification", mutate)
        with self.assertRaisesRegex(ReviewError, "duplicate member"):
            self.verify(assets)

    def test_rejects_manifest_directory_file_conflict(self) -> None:
        assets = self.build()
        document = self.manifest(assets)
        qualification = document["assets"][0]
        qualification["directories"].append("report.json")
        qualification["directories"].sort()
        self.write_manifest(assets, document)
        with self.assertRaisesRegex(ReviewError, "both a file and a directory"):
            self.verify(assets)


if __name__ == "__main__":
    unittest.main()
