"""Adversarial tests for the deterministic GitHub release-asset packager."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from collections.abc import Callable
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
        (self.qualification / "report.json").write_text(
            '{"status":"qualified"}\n', encoding="utf-8"
        )
        (self.qualification / "nested").mkdir()
        (self.qualification / "nested" / "evidence.bin").write_bytes(
            b"qualification evidence\x00\xff"
        )
        long_directory = self.qualification / ("long-directory-" + "x" * 96)
        long_directory.mkdir()
        (long_directory / ("long-file-" + "y" * 110 + ".txt")).write_text(
            "PAX path evidence\n", encoding="utf-8"
        )
        (self.qualification / "unicode-Δ.txt").write_text(
            "explicit UTF-8 path encoding\n", encoding="utf-8"
        )
        (self.closure / "decision.json").write_text(
            '{"decision":"GO"}\n', encoding="utf-8"
        )
        self.private_key = self.root / "signing-key"
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
                str(self.private_key),
            ],
            check=True,
        )
        agent = subprocess.run(
            ["ssh-agent", "-s"],
            check=True,
            capture_output=True,
            text=True,
        )
        agent_environment: dict[str, str] = {}
        for name in ("SSH_AUTH_SOCK", "SSH_AGENT_PID"):
            match = re.search(rf"{name}=([^;]+);", agent.stdout)
            if match is None:
                self.fail(f"ssh-agent did not report {name}")
            agent_environment[name] = match.group(1)
        self.environment_patch = mock.patch.dict(os.environ, agent_environment)
        self.environment_patch.start()
        self.addCleanup(self.stop_signing_agent)
        subprocess.run(
            ["ssh-add", str(self.private_key)],
            check=True,
            capture_output=True,
        )
        self.key = self.private_key.with_suffix(".pub")
        self.allowed_signers = self.root / "ALLOWED_SIGNERS"
        derive_external_allowed_signers(self.key, self.allowed_signers)
        self.seal_tier("qualification")
        self.seal_tier("closure")

    def stop_signing_agent(self) -> None:
        subprocess.run(
            ["ssh-agent", "-k"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.environment_patch.stop()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def tier_root(self, tier: str) -> Path:
        return self.qualification if tier == "qualification" else self.closure

    def inner_contract(self, tier: str) -> dict[str, object]:
        return pack.INNER_TIER_CONTRACTS[tier]

    def refresh_tier_checksum(self, tier: str) -> None:
        root = self.tier_root(tier)
        checksum = root / "SHA256SUMS"
        checksum.unlink(missing_ok=True)
        rows = []
        for path in sorted(target for target in root.rglob("*") if target.is_file()):
            relative = path.relative_to(root).as_posix()
            rows.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n"
            )
        checksum.write_text("".join(rows), encoding="utf-8")

    def write_inner_manifest_bytes(
        self,
        tier: str,
        manifest_bytes: bytes,
        *,
        namespace: str | None = None,
    ) -> None:
        root = self.tier_root(tier)
        contract = self.inner_contract(tier)
        manifest = root / str(contract["manifest"])
        signature = root / str(contract["signature"])
        manifest.write_bytes(manifest_bytes)
        signature.unlink(missing_ok=True)
        sign_file(
            manifest,
            self.key,
            namespace if namespace is not None else str(contract["namespace"]),
        )
        self.refresh_tier_checksum(tier)

    def seal_tier(
        self,
        tier: str,
        *,
        candidate_commit: str = COMMIT,
        candidate_tree: str = TREE,
    ) -> None:
        root = self.tier_root(tier)
        contract = self.inner_contract(tier)
        excluded = {
            str(contract["manifest"]),
            str(contract["signature"]),
            "SHA256SUMS",
        }
        artifacts = []
        for path in sorted(target for target in root.rglob("*") if target.is_file()):
            relative = path.relative_to(root).as_posix()
            if relative in excluded:
                continue
            data = path.read_bytes()
            artifacts.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data),
                }
            )
        document = {
            "schema": pack.INNER_MANIFEST_SCHEMA,
            "tier": tier,
            "candidate": {
                "commit": candidate_commit,
                "tree": candidate_tree,
            },
            "artifacts": artifacts,
        }
        self.write_inner_manifest_bytes(tier, canonical_json(document))

    def build(self, name: str = "assets") -> Path:
        return pack.build_release_assets(
            self.qualification,
            self.closure,
            self.root / name,
            self.key,
            self.allowed_signers,
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
        mutate: Callable[[list[tuple[tarfile.TarInfo, bytes | None]]], None],
        *,
        sync_file_inventory: bool = False,
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
                if sync_file_inventory:
                    prefix = f"{pack.ROOT_PREFIXES[tier]}/"
                    row["directories"] = sorted(
                        member.name.removeprefix(prefix)
                        for member, _data in rows
                        if member.isdir() and member.name != pack.ROOT_PREFIXES[tier]
                    )
                    row["files"] = sorted(
                        (
                            {
                                "path": member.name.removeprefix(prefix),
                                "sha256": hashlib.sha256(data).hexdigest(),
                                "size_bytes": len(data),
                            }
                            for member, data in rows
                            if member.isfile() and data is not None
                        ),
                        key=lambda record: record["path"],
                    )
        self.write_manifest(assets, document)

    def replace_inner_row(
        self,
        rows: list[tuple[tarfile.TarInfo, bytes | None]],
        tier: str,
        relative: str,
        data: bytes,
    ) -> None:
        expected = f"{pack.ROOT_PREFIXES[tier]}/{relative}"
        for index, (member, _old_data) in enumerate(rows):
            if member.name == expected:
                member.size = len(data)
                rows[index] = (member, data)
                return
        self.fail(f"inner archive lacks {expected}")

    def remove_inner_row(
        self,
        rows: list[tuple[tarfile.TarInfo, bytes | None]],
        tier: str,
        relative: str,
    ) -> None:
        expected = f"{pack.ROOT_PREFIXES[tier]}/{relative}"
        for index, (member, _data) in enumerate(rows):
            if member.name == expected:
                rows.pop(index)
                return
        self.fail(f"inner archive lacks {expected}")

    def refresh_inner_checksum_rows(
        self,
        rows: list[tuple[tarfile.TarInfo, bytes | None]],
        tier: str,
    ) -> None:
        prefix = f"{pack.ROOT_PREFIXES[tier]}/"
        checksum_rows = []
        for member, data in rows:
            if not member.isfile() or data is None:
                continue
            relative = member.name.removeprefix(prefix)
            if relative == "SHA256SUMS":
                continue
            checksum_rows.append((relative, hashlib.sha256(data).hexdigest()))
        checksum = "".join(
            f"{digest}  {relative}\n" for relative, digest in sorted(checksum_rows)
        ).encode("utf-8")
        self.replace_inner_row(rows, tier, "SHA256SUMS", checksum)

    def sign_inner_manifest_bytes(
        self,
        tier: str,
        manifest_bytes: bytes,
        *,
        namespace: str | None = None,
    ) -> bytes:
        contract = self.inner_contract(tier)
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            manifest = Path(directory) / str(contract["manifest"])
            manifest.write_bytes(manifest_bytes)
            signature = sign_file(
                manifest,
                self.key,
                namespace if namespace is not None else str(contract["namespace"]),
            )
            return signature.read_bytes()

    def rewrite_inner_manifest(
        self,
        assets: Path,
        tier: str,
        manifest_bytes: bytes,
        *,
        namespace: str | None = None,
    ) -> None:
        contract = self.inner_contract(tier)
        signature = self.sign_inner_manifest_bytes(
            tier,
            manifest_bytes,
            namespace=namespace,
        )

        def mutate(rows: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
            self.replace_inner_row(
                rows,
                tier,
                str(contract["manifest"]),
                manifest_bytes,
            )
            self.replace_inner_row(
                rows,
                tier,
                str(contract["signature"]),
                signature,
            )
            self.refresh_inner_checksum_rows(rows, tier)

        self.rewrite_archive(
            assets,
            tier,
            mutate,
            sync_file_inventory=True,
        )

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

    def test_cli_verify_reconstructs_inner_tiers_in_a_private_directory(
        self,
    ) -> None:
        assets = self.build()
        observed_roots: list[Path] = []
        original = pack._authenticate_inner_tier

        def record_root(
            root: Path,
            tier: str,
            allowed_signers: Path,
            *,
            expected_candidate: str,
            expected_tree: str,
        ) -> dict[str, object]:
            observed_roots.append(root)
            self.assertTrue(root.is_dir())
            self.assertFalse(pack._overlap(root, assets))
            return original(
                root,
                tier,
                allowed_signers,
                expected_candidate=expected_candidate,
                expected_tree=expected_tree,
            )

        arguments = [
            "verify",
            "--assets",
            str(assets),
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
        with (
            mock.patch.object(
                pack,
                "_authenticate_inner_tier",
                side_effect=record_root,
            ),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            self.assertEqual(pack.main(arguments), 0)
        self.assertEqual(len(observed_roots), 2)
        self.assertTrue(all(not root.exists() for root in observed_roots))

    def test_build_rejects_an_inner_candidate_mismatch(self) -> None:
        self.seal_tier("qualification", candidate_commit="4" * 40)
        output = self.root / "inner-candidate-mismatch"
        with self.assertRaisesRegex(
            ReviewError,
            "qualification tier manifest targets another candidate",
        ):
            self.build(output.name)
        self.assertFalse(output.exists())
        self.assertEqual(
            list(self.root.glob(f".{output.name}.staging-*")),
            [],
        )

    def test_build_rejects_inner_inventory_drift(self) -> None:
        (self.closure / "unlisted.json").write_text(
            '{"status":"unlisted"}\n',
            encoding="utf-8",
        )
        output = self.root / "inner-inventory-drift"
        with self.assertRaisesRegex(ReviewError, "omits retained files"):
            self.build(output.name)
        self.assertFalse(output.exists())

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
            "--allowed-signers",
            str(self.allowed_signers),
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
            self.allowed_signers,
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

    def test_extract_restores_fixed_prefixes_paths_and_bytes(
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

    def test_rejects_each_inner_tier_candidate_mismatch(self) -> None:
        for tier in pack.TIER_ORDER:
            with self.subTest(tier=tier):
                assets = self.build(f"{tier}-candidate-mismatch")
                contract = self.inner_contract(tier)
                manifest = self.tier_root(tier) / str(contract["manifest"])
                document = json.loads(manifest.read_text(encoding="utf-8"))
                document["candidate"]["commit"] = "4" * 40
                self.rewrite_inner_manifest(
                    assets,
                    tier,
                    canonical_json(document),
                )
                with self.assertRaisesRegex(
                    ReviewError,
                    f"{tier} tier manifest targets another candidate",
                ):
                    self.verify(assets)

    def test_rejects_missing_and_bad_inner_signatures(self) -> None:
        missing = self.build("missing-inner-signature")
        qualification_contract = self.inner_contract("qualification")

        def remove_signature(
            rows: list[tuple[tarfile.TarInfo, bytes | None]],
        ) -> None:
            self.remove_inner_row(
                rows,
                "qualification",
                str(qualification_contract["signature"]),
            )
            self.refresh_inner_checksum_rows(rows, "qualification")

        self.rewrite_archive(
            missing,
            "qualification",
            remove_signature,
            sync_file_inventory=True,
        )
        with self.assertRaisesRegex(ReviewError, "lacks fixed control files"):
            self.verify(missing)

        bad = self.build("bad-inner-signature")
        closure_contract = self.inner_contract("closure")

        def replace_signature(
            rows: list[tuple[tarfile.TarInfo, bytes | None]],
        ) -> None:
            self.replace_inner_row(
                rows,
                "closure",
                str(closure_contract["signature"]),
                b"invalid detached signature\n",
            )
            self.refresh_inner_checksum_rows(rows, "closure")

        self.rewrite_archive(
            bad,
            "closure",
            replace_signature,
            sync_file_inventory=True,
        )
        with self.assertRaisesRegex(
            ReviewError,
            "invalid galadriel-closure-manifest signature",
        ):
            self.verify(bad)

    def test_rejects_an_inner_signature_in_the_wrong_namespace(self) -> None:
        assets = self.build("wrong-inner-namespace")
        contract = self.inner_contract("qualification")
        manifest = (
            self.tier_root("qualification") / str(contract["manifest"])
        ).read_bytes()
        self.rewrite_inner_manifest(
            assets,
            "qualification",
            manifest,
            namespace="wrong-inner-namespace",
        )
        with self.assertRaisesRegex(
            ReviewError,
            "invalid galadriel-qualification-manifest signature",
        ):
            self.verify(assets)

    def test_rejects_malformed_and_noncanonical_inner_manifests(self) -> None:
        contract = self.inner_contract("closure")
        source_manifest = self.tier_root("closure") / str(contract["manifest"])
        document = json.loads(source_manifest.read_text(encoding="utf-8"))
        cases = (
            ("malformed", b"not JSON\n", "not valid bounded JSON"),
            (
                "noncanonical",
                json.dumps(document, indent=2).encode("utf-8"),
                "not a canonical JSON object",
            ),
        )
        for name, manifest_bytes, error in cases:
            with self.subTest(name=name):
                assets = self.build(f"{name}-inner-manifest")
                self.rewrite_inner_manifest(
                    assets,
                    "closure",
                    manifest_bytes,
                )
                with self.assertRaisesRegex(ReviewError, error):
                    self.verify(assets)

    def test_rejects_wrong_inner_manifest_schema_and_tier(self) -> None:
        contract = self.inner_contract("qualification")
        source = self.tier_root("qualification") / str(contract["manifest"])
        source_document = json.loads(source.read_text(encoding="utf-8"))
        cases = (
            ("schema", "unexpected.schema", "wrong schema"),
            ("tier", "closure", "wrong tier"),
        )
        for field, value, error in cases:
            with self.subTest(field=field):
                assets = self.build(f"wrong-inner-{field}")
                document = copy.deepcopy(source_document)
                document[field] = value
                self.rewrite_inner_manifest(
                    assets,
                    "qualification",
                    canonical_json(document),
                )
                with self.assertRaisesRegex(ReviewError, error):
                    self.verify(assets)

    def test_rejects_unordered_inner_artifact_inventory(self) -> None:
        assets = self.build("unordered-inner-inventory")
        contract = self.inner_contract("qualification")
        source = self.tier_root("qualification") / str(contract["manifest"])
        document = json.loads(source.read_text(encoding="utf-8"))
        document["artifacts"].reverse()
        self.rewrite_inner_manifest(
            assets,
            "qualification",
            canonical_json(document),
        )
        with self.assertRaisesRegex(ReviewError, "artifact inventory is not ordered"):
            self.verify(assets)

    def test_rejects_inner_artifact_digest_drift(self) -> None:
        assets = self.build("inner-artifact-drift")

        def change_artifact(
            rows: list[tuple[tarfile.TarInfo, bytes | None]],
        ) -> None:
            self.replace_inner_row(
                rows,
                "qualification",
                "report.json",
                b'{"status":"changed"}\n',
            )
            self.refresh_inner_checksum_rows(rows, "qualification")

        self.rewrite_archive(
            assets,
            "qualification",
            change_artifact,
            sync_file_inventory=True,
        )
        with self.assertRaisesRegex(ReviewError, "artifact digest mismatch"):
            self.verify(assets)

    def test_rejects_inner_checksum_drift_before_reconstruction_publication(
        self,
    ) -> None:
        assets = self.build("inner-checksum-drift")

        def change_checksum(
            rows: list[tuple[tarfile.TarInfo, bytes | None]],
        ) -> None:
            self.replace_inner_row(
                rows,
                "closure",
                "SHA256SUMS",
                b"0" * 64 + b"  decision.json\n",
            )

        self.rewrite_archive(
            assets,
            "closure",
            change_checksum,
            sync_file_inventory=True,
        )
        output = self.root / "checksum-drift-reconstruction"
        with self.assertRaisesRegex(ReviewError, "checksum inventory"):
            pack.extract_release_assets(
                assets,
                self.allowed_signers,
                output,
                **self.expectations(),
            )
        self.assertFalse(output.exists())

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
        embedded_key = self.qualification / "embedded-public-key"
        embedded_key.write_bytes(self.key.read_bytes())
        os.chmod(embedded_key, 0o600)
        output = self.root / "key-leak"
        with self.assertRaisesRegex(ReviewError, "signing-key handle"):
            pack.build_release_assets(
                self.qualification,
                self.closure,
                output,
                embedded_key,
                self.allowed_signers,
                candidate_commit=COMMIT,
                candidate_tree=TREE,
                tag_name=pack.TAG_NAME,
                tag_object=TAG_OBJECT,
                tag_target=COMMIT,
            )
        self.assertFalse(output.exists())

    def test_rejects_a_private_signing_key(self) -> None:
        output = self.root / "private-key-output"
        with self.assertRaisesRegex(ReviewError, "signing-key handle"):
            pack.build_release_assets(
                self.qualification,
                self.closure,
                output,
                self.private_key,
                self.allowed_signers,
                candidate_commit=COMMIT,
                candidate_tree=TREE,
                tag_name=pack.TAG_NAME,
                tag_object=TAG_OBJECT,
                tag_target=COMMIT,
            )
        self.assertFalse(output.exists())

    def test_rejects_a_signing_key_that_differs_from_the_trust_root(self) -> None:
        foreign_private = self.root / "foreign-signing-key"
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(foreign_private),
            ],
            check=True,
        )
        foreign_allowed = self.root / "FOREIGN_ALLOWED_SIGNERS"
        derive_external_allowed_signers(
            foreign_private.with_suffix(".pub"),
            foreign_allowed,
        )
        output = self.root / "foreign-trust-output"
        with self.assertRaisesRegex(
            ReviewError, "does not match independent trust root"
        ):
            pack.build_release_assets(
                self.qualification,
                self.closure,
                output,
                self.key,
                foreign_allowed,
                candidate_commit=COMMIT,
                candidate_tree=TREE,
                tag_name=pack.TAG_NAME,
                tag_object=TAG_OBJECT,
                tag_target=COMMIT,
            )
        self.assertFalse(output.exists())

    def test_build_enforces_the_four_kib_trust_root_bound(self) -> None:
        oversized = self.root / "OVERSIZED_ALLOWED_SIGNERS"
        oversized.write_bytes(b"x" * (pack.MAX_ALLOWED_SIGNERS_BYTES + 1))
        output = self.root / "oversized-trust-output"
        with self.assertRaisesRegex(ReviewError, "exceeds 4096 bytes"):
            pack.build_release_assets(
                self.qualification,
                self.closure,
                output,
                self.key,
                oversized,
                candidate_commit=COMMIT,
                candidate_tree=TREE,
                tag_name=pack.TAG_NAME,
                tag_object=TAG_OBJECT,
                tag_target=COMMIT,
            )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".oversized-trust-output.staging-*")), [])

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
