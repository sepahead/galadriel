"""Adversarial tests for held-root evidence artifact transactions."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import common  # noqa: E402
from common import ReviewError, RootedFileDigestRequest  # noqa: E402
import verify_evidence_manifest as evidence_manifest  # noqa: E402


class EvidenceBatchTransactionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_manifest(self, root: Path, paths: list[Path]) -> Path:
        """Write one manifest outside its artifact root."""

        rows = []
        for path in paths:
            data = path.read_bytes()
            rows.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data),
                }
            )
        manifest = self.workspace / f"{root.name}-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "galadriel.evidence-manifest.v1",
                    "artifacts": rows,
                }
            ),
            encoding="utf-8",
        )
        return manifest

    def requests_for(
        self, root: Path, paths: list[Path]
    ) -> tuple[RootedFileDigestRequest, ...]:
        """Build bounded requests in the supplied order."""

        return tuple(
            RootedFileDigestRequest(
                relative=path.relative_to(root).as_posix(),
                expected_size=path.stat().st_size,
                label=f"artifact {path.name}",
            )
            for path in paths
        )

    def digest_batch(
        self,
        root: Path,
        requests: tuple[RootedFileDigestRequest, ...],
    ) -> tuple[common.RootedFileDigest, ...]:
        """Run one small held-root transaction."""

        return common.digest_rooted_regular_files(
            root,
            requests,
            label="test artifacts",
            max_files=8,
            max_file_bytes=1024,
            max_aggregate_bytes=4096,
            max_path_bytes=256,
            max_component_bytes=64,
            max_depth=8,
            max_directory_entries=64,
        )

    def test_manifest_rejects_cross_row_root_replacement(self) -> None:
        """A root replacement cannot combine two root generations."""

        root = self.workspace / "live-root"
        root.mkdir()
        first = root / "first.bin"
        second = root / "second.bin"
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        manifest = self.write_manifest(root, [first, second])

        replacement = self.workspace / "replacement-root"
        replacement.mkdir()
        (replacement / first.name).write_bytes(first.read_bytes())
        (replacement / second.name).write_bytes(second.read_bytes())
        displaced = self.workspace / "displaced-root"
        real_digest = common._digest_from_root_descriptor
        real_open_root = common._open_root_directory
        digest_calls = 0

        def replace_after_first_read(*args: object, **kwargs: object) -> object:
            nonlocal digest_calls
            result = real_digest(*args, **kwargs)
            digest_calls += 1
            if digest_calls == 1:
                root.rename(displaced)
                replacement.rename(root)
            return result

        with (
            mock.patch.object(
                common,
                "_digest_from_root_descriptor",
                side_effect=replace_after_first_read,
            ),
            mock.patch.object(
                common,
                "_open_root_directory",
                wraps=real_open_root,
            ) as open_root,
            self.assertRaisesRegex(
                ReviewError,
                "root changed|root was replaced|lexical root",
            ),
        ):
            evidence_manifest.verify_manifest(manifest, root)
        self.assertGreaterEqual(digest_calls, 1)
        self.assertEqual(open_root.call_count, 1)

    def test_transaction_rechecks_each_touched_file_at_end(self) -> None:
        """The final identity pass rejects a file changed after its read."""

        root = self.workspace / "file-race-root"
        first_directory = root / "first"
        second_directory = root / "second"
        first_directory.mkdir(parents=True)
        second_directory.mkdir()
        first = first_directory / "artifact.bin"
        second = second_directory / "artifact.bin"
        first.write_bytes(b"original")
        second.write_bytes(b"stable")
        requests = self.requests_for(root, [first, second])
        real_verify = common._verify_rooted_file_identity
        verification_calls = 0

        def mutate_before_final_check(
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal verification_calls
            verification_calls += 1
            if verification_calls == 1:
                first.write_bytes(b"modified")
            real_verify(*args, **kwargs)

        with (
            mock.patch.object(
                common,
                "_verify_rooted_file_identity",
                side_effect=mutate_before_final_check,
            ),
            self.assertRaisesRegex(ReviewError, "changed during the transaction"),
        ):
            self.digest_batch(root, requests)
        self.assertEqual(verification_calls, 1)

    def test_transaction_rechecks_each_touched_directory_at_end(self) -> None:
        """The final identity pass rejects a changed ancestor directory."""

        root = self.workspace / "directory-race-root"
        outer = root / "outer"
        nested = outer / "nested"
        sibling = root / "sibling"
        nested.mkdir(parents=True)
        sibling.mkdir()
        first = nested / "artifact.bin"
        second = sibling / "artifact.bin"
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        requests = self.requests_for(root, [first, second])

        replacement = outer / "replacement"
        replacement.mkdir()
        (replacement / first.name).write_bytes(first.read_bytes())
        displaced = outer / "displaced"
        real_verify = common._verify_rooted_file_identity
        verification_calls = 0

        def replace_before_final_check(
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal verification_calls
            verification_calls += 1
            if verification_calls == 1:
                nested.rename(displaced)
                replacement.rename(nested)
            real_verify(*args, **kwargs)

        with (
            mock.patch.object(
                common,
                "_verify_rooted_file_identity",
                side_effect=replace_before_final_check,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "directory changed|path changed",
            ),
        ):
            self.digest_batch(root, requests)
        self.assertEqual(verification_calls, 1)

    def test_transaction_retains_ordered_digests_and_ignores_other_entries(
        self,
    ) -> None:
        """Unrelated root entries do not enter the declared transaction."""

        root = self.workspace / "bounded-root"
        nested = root / "nested"
        nested.mkdir(parents=True)
        first = root / "first.bin"
        second = nested / "second.bin"
        first.write_bytes(b"one")
        second.write_bytes(b"two")
        (root / "unrelated.bin").write_bytes(b"not declared")
        (root / "unrelated-directory").mkdir()
        (root / "unrelated-link").symlink_to(
            self.workspace,
            target_is_directory=True,
        )

        digests = self.digest_batch(
            root,
            self.requests_for(root, [second, first]),
        )

        self.assertEqual(
            [item.sha256 for item in digests],
            [
                hashlib.sha256(second.read_bytes()).hexdigest(),
                hashlib.sha256(first.read_bytes()).hexdigest(),
            ],
        )
        self.assertEqual([item.size_bytes for item in digests], [3, 3])

    def test_transaction_rejects_duplicate_paths_and_file_identities(
        self,
    ) -> None:
        """The batch retains both duplicate rejection boundaries."""

        root = self.workspace / "duplicate-root"
        root.mkdir()
        first = root / "first.bin"
        second = root / "second.bin"
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        first_request, second_request = self.requests_for(root, [first, second])

        with self.assertRaisesRegex(ReviewError, "duplicate path"):
            self.digest_batch(root, (first_request, first_request))

        real_digest = common._digest_from_root_descriptor
        first_identity: common.RootedPathIdentity | None = None
        digest_calls = 0

        def repeat_file_identity(*args: object, **kwargs: object) -> object:
            nonlocal digest_calls, first_identity
            validator = kwargs["observation_validator"]

            def substitute_identity(
                observation: common._RootedFileObservation,
            ) -> None:
                nonlocal digest_calls, first_identity
                digest_calls += 1
                if digest_calls == 1:
                    first_identity = observation.file_identity
                else:
                    assert first_identity is not None
                    observation = observation._replace(file_identity=first_identity)
                validator(observation)

            kwargs["observation_validator"] = substitute_identity
            return real_digest(*args, **kwargs)

        with (
            mock.patch.object(
                common,
                "_digest_from_root_descriptor",
                side_effect=repeat_file_identity,
            ),
            self.assertRaisesRegex(ReviewError, "duplicate file identity"),
        ):
            self.digest_batch(root, (first_request, second_request))

    def test_cleanup_preserves_primary_error_and_closes_all_descriptors(
        self,
    ) -> None:
        """A close error cannot replace an active validation error."""

        root = self.workspace / "primary-cleanup-root"
        root.mkdir()
        artifact = root / "artifact.bin"
        artifact.write_bytes(b"data")
        request = RootedFileDigestRequest(
            relative=artifact.name,
            expected_size=4,
            label="primary cleanup artifact",
            expected_sha256="0" * 64,
        )

        real_open = common.os.open
        real_dup = common.os.dup
        real_close = common.os.close
        directory_flags = common._rooted_descriptor_flags(directory=True)
        file_flags = common._rooted_descriptor_flags(directory=False)
        acquired: list[int] = []
        closed: list[int] = []
        injected = False

        def tracked_open(*args: object, **kwargs: object) -> int:
            descriptor = real_open(*args, **kwargs)
            acquired.append(descriptor)
            return descriptor

        def tracked_dup(descriptor: int) -> int:
            duplicate = real_dup(descriptor)
            acquired.append(duplicate)
            return duplicate

        def close_then_fail_once(descriptor: int) -> None:
            nonlocal injected
            closed.append(descriptor)
            real_close(descriptor)
            if not injected:
                injected = True
                raise OSError("injected cleanup failure")

        with (
            mock.patch.object(
                common,
                "_rooted_descriptor_flags",
                side_effect=lambda *, directory: (
                    directory_flags if directory else file_flags
                ),
            ),
            mock.patch.object(common.os, "open", side_effect=tracked_open),
            mock.patch.object(common.os, "dup", side_effect=tracked_dup),
            mock.patch.object(common.os, "close", side_effect=close_then_fail_once),
            self.assertRaisesRegex(ReviewError, "digest artifact.bin expected"),
        ):
            self.digest_batch(root, (request,))
        self.assertTrue(injected)
        self.assertEqual(Counter(acquired), Counter(closed))

    def test_cleanup_only_failure_is_reported_after_all_closes(self) -> None:
        """A cleanup-only error is visible after every descriptor closes."""

        root = self.workspace / "cleanup-only-root"
        root.mkdir()
        artifact = root / "artifact.bin"
        artifact.write_bytes(b"data")
        request = self.requests_for(root, [artifact])[0]

        real_open = common.os.open
        real_dup = common.os.dup
        real_close = common.os.close
        directory_flags = common._rooted_descriptor_flags(directory=True)
        file_flags = common._rooted_descriptor_flags(directory=False)
        acquired: list[int] = []
        closed: list[int] = []
        injected = False

        def tracked_open(*args: object, **kwargs: object) -> int:
            descriptor = real_open(*args, **kwargs)
            acquired.append(descriptor)
            return descriptor

        def tracked_dup(descriptor: int) -> int:
            duplicate = real_dup(descriptor)
            acquired.append(duplicate)
            return duplicate

        def close_then_fail_once(descriptor: int) -> None:
            nonlocal injected
            closed.append(descriptor)
            real_close(descriptor)
            if not injected:
                injected = True
                raise OSError("injected cleanup-only failure")

        with (
            mock.patch.object(
                common,
                "_rooted_descriptor_flags",
                side_effect=lambda *, directory: (
                    directory_flags if directory else file_flags
                ),
            ),
            mock.patch.object(common.os, "open", side_effect=tracked_open),
            mock.patch.object(common.os, "dup", side_effect=tracked_dup),
            mock.patch.object(common.os, "close", side_effect=close_then_fail_once),
            self.assertRaisesRegex(ReviewError, "descriptor cleanup failed"),
        ):
            self.digest_batch(root, (request,))
        self.assertTrue(injected)
        self.assertEqual(Counter(acquired), Counter(closed))


if __name__ == "__main__":
    unittest.main()
