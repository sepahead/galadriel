from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import release_audit, secure_deployment


class ReleaseAuditTests(unittest.TestCase):
    def test_secure_profile_json_parser_and_cli_fail_closed(self) -> None:
        invalid_documents = (
            b'{"value": NaN}',
            b'{"value": Infinity}',
            b'{"value": -Infinity}',
            b'{"value": 1e1000000}',
            b'{"value": 1e-1000000}',
            b'{"value": ' + b"9" * 5_000 + b"}",
            b"\xff",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "invalid.json"
            for document in invalid_documents:
                with self.subTest(document=document[:40]):
                    path.write_bytes(document)
                    with self.assertRaisesRegex(
                        secure_deployment.ProfileError, "cannot load"
                    ):
                        secure_deployment._load_json(path)

            hostile_key = "attacker-controlled-secret-field-name"
            path.write_text(
                "{"
                + json.dumps(hostile_key)
                + ": 1, "
                + json.dumps(hostile_key)
                + ": 2}",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                secure_deployment.ProfileError, "duplicate JSON object key"
            ) as caught:
                secure_deployment._load_json(path)
            self.assertNotIn(hostile_key, str(caught.exception))
            self.assertLess(len(str(caught.exception)), 512)

            path.write_bytes(b'{"value": ' + b"9" * 5_000 + b"}")
            output = root / "rendered"
            result = subprocess.run(
                [
                    sys.executable,
                    str(release_audit.ROOT / "scripts" / "secure_deployment.py"),
                    "render",
                    "--profile",
                    str(path),
                    "--output-dir",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("cannot load", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(output.exists())

        with self.assertRaisesRegex(
            secure_deployment.ProfileError, "cannot encode strict JSON"
        ):
            secure_deployment._json_bytes({"value": float("nan")})
        with self.assertRaisesRegex(
            secure_deployment.ProfileError, "cannot encode strict JSON"
        ):
            secure_deployment._json_bytes({"value": 10**128})

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            hostile_key = "attacker-controlled-secret-field-name"
            path.write_text(
                "{"
                + json.dumps(hostile_key)
                + ": 1, "
                + json.dumps(hostile_key)
                + ": 2}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                release_audit.AuditError, "duplicate JSON key"
            ) as caught:
                release_audit.load_json(path)
            self.assertNotIn(hostile_key, str(caught.exception))
            self.assertLess(len(str(caught.exception)), 512)

    def test_nonfinite_and_oversized_json_numbers_are_rejected(self) -> None:
        invalid_documents = (
            '{"value": NaN}',
            '{"value": Infinity}',
            '{"value": -Infinity}',
            '{"value": 1e1000000}',
            '{"value": 1e-1000000}',
            '{"value": ' + "9" * 5_000 + "}",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            for document in invalid_documents:
                with self.subTest(document=document[:40]):
                    path.write_text(document, encoding="utf-8")
                    with self.assertRaisesRegex(
                        release_audit.AuditError, "cannot load"
                    ):
                        release_audit.load_json(path)

        for value in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(canonical_value=value):
                with self.assertRaisesRegex(
                    release_audit.AuditError, "cannot encode canonical JSON"
                ):
                    release_audit.canonical_bytes({"value": value})
        with self.assertRaisesRegex(
            release_audit.AuditError, "cannot encode canonical JSON"
        ):
            release_audit.canonical_bytes({"value": 10**128})

    def test_canonical_json_is_order_independent_and_idempotent(self) -> None:
        first = {"z": [3, 2, 1], "a": {"right": 2, "left": 1}}
        second = {"a": {"left": 1, "right": 2}, "z": [3, 2, 1]}
        encoded = release_audit.canonical_bytes(first)
        self.assertEqual(encoded, release_audit.canonical_bytes(second))
        self.assertEqual(encoded, release_audit.canonical_bytes(json.loads(encoded)))

    def test_release_python_native_preflight_is_cross_bound(self) -> None:
        release_audit.validate_release_python_native_preflight()

        script = release_audit.ROOT / "repo_work/verify_release_python_runtime.sh"
        original_read_text = Path.read_text

        def drifted_digest(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            document = original_read_text(path, *args, **kwargs)
            if path == script:
                return document.replace(
                    "expected_tree_sha256=16b62407",
                    "expected_tree_sha256=06b62407",
                    1,
                )
            return document

        with patch.object(Path, "read_text", drifted_digest):
            with self.assertRaisesRegex(
                release_audit.AuditError,
                "another expected_tree_sha256",
            ):
                release_audit.validate_release_python_native_preflight()

        def weakened_body(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            document = original_read_text(path, *args, **kwargs)
            if path == script:
                return document.replace(
                    "pinned native file changed while hashed",
                    "pinned native file accepted after hashing",
                    1,
                )
            return document

        with patch.object(Path, "read_text", weakened_body):
            with self.assertRaisesRegex(
                release_audit.AuditError,
                "native preflight bytes differ",
            ):
                release_audit.validate_release_python_native_preflight()

        original_document = original_read_text(script, encoding="utf-8")
        unclean_document = original_document.replace(
            "cleanup\ntrap - EXIT\n"
            'builtin umask "$original_umask"\n'
            'builtin exec "$release_python" -E -s -S "$@"\n',
            'builtin exec "$release_python" -E -s -S "$@"\n',
            1,
        )

        def unclean_launch(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == script:
                return unclean_document
            return original_read_text(path, *args, **kwargs)

        with (
            patch.object(Path, "read_text", unclean_launch),
            patch.object(
                release_audit,
                "RELEASE_PYTHON_NATIVE_PREFLIGHT_SHA256",
                hashlib.sha256(unclean_document.encode("utf-8")).hexdigest(),
            ),
        ):
            with self.assertRaisesRegex(
                release_audit.AuditError,
                "does not clean and restore caller state",
            ):
                release_audit.validate_release_python_native_preflight()

        unrestored_document = original_document.replace(
            'builtin umask "$original_umask"\n',
            "",
            1,
        )

        def unrestored_umask(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == script:
                return unrestored_document
            return original_read_text(path, *args, **kwargs)

        with (
            patch.object(Path, "read_text", unrestored_umask),
            patch.object(
                release_audit,
                "RELEASE_PYTHON_NATIVE_PREFLIGHT_SHA256",
                hashlib.sha256(unrestored_document.encode("utf-8")).hexdigest(),
            ),
        ):
            with self.assertRaisesRegex(
                release_audit.AuditError,
                "does not clean and restore caller state",
            ):
                release_audit.validate_release_python_native_preflight()

        runbook = release_audit.ROOT / "release/0.9.0/RELEASE-RUNBOOK.md"

        def bypassed_launcher(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            document = original_read_text(path, *args, **kwargs)
            if path == runbook:
                return document.replace(
                    "release_python=repo_work/verify_release_python_runtime.sh",
                    "release_python=/unverified/python3",
                    1,
                )
            return document

        with patch.object(Path, "read_text", bypassed_launcher):
            with self.assertRaisesRegex(
                release_audit.AuditError,
                "runbook block requires the native launcher",
            ):
                release_audit.validate_release_python_native_preflight()

    def test_handoff_task_chain_is_complete_and_contiguous(self) -> None:
        tasks = release_audit.validate_tasks()
        self.assertEqual(len(tasks), 116)
        self.assertEqual(tasks[0]["id"], "T000")
        self.assertEqual(tasks[-1]["id"], "T115")
        self.assertEqual(tasks[-1]["dependencies"], ["T114"])

    def test_project_doi_or_zenodo_claim_is_rejected(self) -> None:
        inputs = copy.deepcopy(release_audit.load_json(release_audit.INPUTS))
        inputs["release"]["doi"] = "10.0000/not-issued"
        with self.assertRaisesRegex(release_audit.AuditError, "DOI or Zenodo"):
            release_audit.validate_inputs(inputs)

    def test_unpublished_candidate_has_no_release_date(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        runbook = (release_audit.RELEASE / "RELEASE-RUNBOOK.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("`DATE_BOUND_CANDIDATE`", runbook)
        metadata = release_audit.validate_project_metadata(inputs)
        self.assertIsNone(metadata["candidate_release_date"])
        self.assertEqual(
            metadata["source_preparation_state"],
            release_audit.UNPUBLISHED_SOURCE_PREPARATION_STATE,
        )

        incoherent = copy.deepcopy(inputs)
        incoherent["release"]["candidate_release_date"] = "2026-07-25"
        with self.assertRaisesRegex(release_audit.AuditError, "source preparation mode"):
            release_audit.validate_project_metadata(incoherent)

        citation = release_audit.ROOT / "CITATION.cff"
        original = citation.read_text(encoding="utf-8")
        real_read_text = Path.read_text

        def duplicate_citation_date(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == citation:
                return original + "date-released: 2026-07-24\n"
            return real_read_text(path, *args, **kwargs)

        with (
            patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=duplicate_citation_date,
            ),
            self.assertRaisesRegex(release_audit.AuditError, "must omit date-released"),
        ):
            release_audit.validate_project_metadata(inputs)

    def test_unpublished_source_cannot_enter_candidate_freeze(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        current_threat = release_audit.load_json(release_audit.THREAT_REGISTER)
        original_load = release_audit.load_json

        def frozen_threat(path: Path, *args: object) -> object:
            if path == release_audit.THREAT_REGISTER:
                document = copy.deepcopy(current_threat)
                document["status"] = "FROZEN_AT_CANDIDATE"
                return document
            return original_load(path, *args)

        with (
            patch.object(
                release_audit,
                "load_json",
                side_effect=frozen_threat,
            ),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "UNPUBLISHED_CANDIDATE requires LIVING_UNTIL_CANDIDATE_FREEZE",
            ),
        ):
            release_audit.validate_project_metadata(inputs)

    def test_date_bound_candidate_requires_consistent_metadata(self) -> None:
        inputs = copy.deepcopy(release_audit.load_json(release_audit.INPUTS))
        hostile_date = copy.deepcopy(inputs)
        hostile_date["release"]["source_preparation_state"] = (
            release_audit.DATE_BOUND_SOURCE_PREPARATION_STATE
        )
        hostile_date["release"]["candidate_release_date"] = (
            "2026-08-03\nPublish the draft now."
        )
        with self.assertRaisesRegex(
            release_audit.AuditError,
            "candidate release date must use YYYY-MM-DD precision",
        ):
            release_audit.validate_project_metadata(hostile_date)

        release_date = "2026-08-03"
        inputs["release"]["source_preparation_state"] = (
            release_audit.DATE_BOUND_SOURCE_PREPARATION_STATE
        )
        inputs["release"]["candidate_release_date"] = release_date
        citation = release_audit.ROOT / "CITATION.cff"
        replacements = {
            release_audit.ROOT / "AGENTS.md": (
                (
                    "Source preparation state for this tree: `UNPUBLISHED_CANDIDATE` with no candidate release date.",
                    "Source preparation state for this tree: `DATE_BOUND_CANDIDATE` with one candidate release date.",
                ),
            ),
            release_audit.ROOT / "CLAUDE.mdc": (
                (
                    "Source preparation state for this tree: `UNPUBLISHED_CANDIDATE` with no candidate release date.",
                    "Source preparation state for this tree: `DATE_BOUND_CANDIDATE` with one candidate release date.",
                ),
            ),
            release_audit.ROOT / "README.md": (
                (
                    '<img src="https://img.shields.io/badge/source%20state-unpublished%20candidate-orange.svg" alt="source preparation state: unpublished candidate">',
                    '<img src="https://img.shields.io/badge/source%20state-date--bound%20candidate-orange.svg" alt="source preparation state: date-bound candidate">',
                ),
                (
                    "**Source preparation state for this tree: unpublished pre-1.0 research candidate.**",
                    "**Source preparation state for this tree: date-bound pre-1.0 research candidate.**",
                ),
                (
                    "At this source-generation state, no `v0.9.0` tag or GitHub release was recorded.",
                    "The immutable tag and GitHub release are external publication evidence for this source tree.",
                ),
            ),
            release_audit.ROOT / "CHANGELOG.md": (
                (
                    "## [0.9.0] - UNPUBLISHED CANDIDATE",
                    f"## [0.9.0] - {release_date}",
                ),
            ),
            release_audit.RELEASE / "README.md": (
                (
                    "Source preparation state for this tree: `UNPUBLISHED_CANDIDATE` with no candidate release date.",
                    "Source preparation state for this tree: `DATE_BOUND_CANDIDATE` with one candidate release date.",
                ),
            ),
            release_audit.RELEASE / "RELEASE-NOTES.md": (
                (
                    "Source preparation state at generation: UNPUBLISHED CANDIDATE",
                    "Source preparation state at generation: DATE-BOUND CANDIDATE",
                ),
                (
                    "Candidate release date at generation: NOT SET",
                    f"Candidate release date at generation: {release_date}",
                ),
            ),
            release_audit.RELEASE / "RELEASE-RUNBOOK.md": (
                (
                    "The source preparation state is `UNPUBLISHED_CANDIDATE` with no candidate release date.",
                    f"The source preparation state is `DATE_BOUND_CANDIDATE` with candidate release date {release_date}.",
                ),
                (
                    "The source declares one unpublished candidate with no release date.",
                    "The source declares one date-bound candidate release date.",
                ),
            ),
            release_audit.RELEASE / "claims.json": (
                (
                    "Source preparation state for this tree is UNPUBLISHED_CANDIDATE with no candidate release date.",
                    f"Source preparation state for this tree is DATE_BOUND_CANDIDATE with candidate release date {release_date}.",
                ),
            ),
        }
        originals = {
            path: path.read_text(encoding="utf-8")
            for path in (citation, *replacements)
        }
        real_read_text = Path.read_text

        def dated_document(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == citation:
                return originals[path] + f"date-released: {release_date}\n"
            if path in replacements:
                document = originals[path]
                for before, after in replacements[path]:
                    self.assertEqual(document.count(before), 1)
                    document = document.replace(before, after)
                return document
            return real_read_text(path, *args, **kwargs)

        with patch.object(
            Path,
            "read_text",
            autospec=True,
            side_effect=dated_document,
        ):
            metadata = release_audit.validate_project_metadata(inputs)
        self.assertEqual(metadata["candidate_release_date"], release_date)
        self.assertEqual(
            metadata["source_preparation_state"],
            release_audit.DATE_BOUND_SOURCE_PREPARATION_STATE,
        )

        def dated_with_stale_status(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            document = dated_document(path, *args, **kwargs)
            if path == release_audit.ROOT / "SUPPORT.md":
                return document + "\nUNPUBLISHED_CANDIDATE\n"
            return document

        with (
            patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=dated_with_stale_status,
            ),
            self.assertRaisesRegex(
                release_audit.AuditError, "stale unpublished-mode marker"
            ),
        ):
            release_audit.validate_project_metadata(inputs)

    def test_release_facing_prose_requires_lifecycle_neutral_markers(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        cases = (
            (
                release_audit.ROOT / "AGENTS.md",
                "Before the threat register enters `FROZEN_AT_CANDIDATE`, the source **SHALL** be",
                "The threat register can enter `FROZEN_AT_CANDIDATE` at any time.",
            ),
            (
                release_audit.ROOT / "CLAUDE.mdc",
                "Before the threat register enters `FROZEN_AT_CANDIDATE`, the source **SHALL** be",
                "The threat register can enter `FROZEN_AT_CANDIDATE` at any time.",
            ),
            (
                release_audit.ROOT / "CITATION.cff",
                "If you use this research software",
                "If you use this research release",
            ),
            (
                release_audit.ROOT / "SECURITY.md",
                "This research source version has no remediation-time SLA.",
                "This unpublished research source candidate has no remediation-time SLA.",
            ),
            (
                release_audit.ROOT / "CONTRIBUTING.md",
                "Version 0.9.0 uses the review-gated GitHub research source release channel.",
                "Version 0.9.0 is an unpublished candidate for a review-gated GitHub research source release.",
            ),
            (
                release_audit.ROOT / "RELEASE-POLICY.md",
                "Before the threat register enters `FROZEN_AT_CANDIDATE`, the source **SHALL** be",
                "The threat register can enter `FROZEN_AT_CANDIDATE` at any time.",
            ),
            (
                release_audit.ROOT / "SUPPORT.md",
                "Galadriel 0.9.0 uses the review-gated GitHub research source release channel.",
                "Galadriel 0.9.0 is an unpublished candidate for a review-gated GitHub research source release.",
            ),
            (
                release_audit.ROOT / "docs" / "API-SURFACE.md",
                "Galadriel 0.9.0 uses the review-gated GitHub research source release channel.",
                "Galadriel 0.9.0 is an unpublished candidate for a review-gated GitHub research source release.",
            ),
            (
                release_audit.ROOT / "docs" / "CLAIMS.md",
                "Version 0.9.0 implements a bounded and fail-closed advisory component.",
                "The candidate implements a bounded and fail-closed advisory component.",
            ),
            (
                release_audit.ROOT / "docs" / "CLAIMS.md",
                "Dated read-only ecosystem inspections through 2026-08-03 do not change a claim",
                "Dated read-only ecosystem inspections through 2026-07-23 do not change a claim",
            ),
            (
                release_audit.RELEASE / "README.md",
                "# Galadriel 0.9.0 source release record",
                "# Galadriel 0.9.0 candidate release record",
            ),
            (
                release_audit.RELEASE / "RELEASE-NOTES.md",
                "Evidence is author-operated. The publication channel is review-gated.",
                "This is an author-operated candidate for a review-gated research source release.",
            ),
            (
                release_audit.RELEASE / "claims.json",
                "The checked procedures are not evidence that the release operator ran",
                "The candidate includes checked procedures. The release operator has not run",
            ),
            (
                release_audit.ROOT / "repo_work" / "README.md",
                "Before the threat register enters `FROZEN_AT_CANDIDATE`, the source **SHALL** be",
                "The threat register can enter `FROZEN_AT_CANDIDATE` at any time.",
            ),
        )
        real_read_text = Path.read_text

        for target, neutral, stale in cases:
            original = target.read_text(encoding="utf-8")
            self.assertEqual(original.count(neutral), 1)

            def stale_document(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> str:
                if path == target:
                    return original.replace(neutral, stale, 1)
                return real_read_text(path, *args, **kwargs)

            with self.subTest(path=target.relative_to(release_audit.ROOT)):
                with (
                    patch.object(
                        Path,
                        "read_text",
                        autospec=True,
                        side_effect=stale_document,
                    ),
                    self.assertRaisesRegex(
                        release_audit.AuditError,
                        "lifecycle-neutral marker|stale lifecycle wording",
                    ),
                ):
                    release_audit.validate_project_metadata(inputs)

    def test_publication_sequence_qualifies_date_before_tag(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        runbook = release_audit.RELEASE / "RELEASE-RUNBOOK.md"
        original = runbook.read_text(encoding="utf-8")
        real_read_text = Path.read_text
        date_marker = release_audit.PUBLICATION_SEQUENCE_MARKERS[1]
        tag_marker = release_audit.PUBLICATION_SEQUENCE_MARKERS[11]

        def tag_before_date(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == runbook:
                return original.replace(date_marker, "ORDER-SWAP", 1).replace(
                    tag_marker, date_marker, 1
                ).replace("ORDER-SWAP", tag_marker, 1)
            return real_read_text(path, *args, **kwargs)

        with (
            patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=tag_before_date,
            ),
            self.assertRaisesRegex(release_audit.AuditError, "date-bind, freeze"),
        ):
            release_audit.validate_project_metadata(inputs)

    def test_publication_sequence_preflights_and_checks_tagged_sources(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        runbook = release_audit.RELEASE / "RELEASE-RUNBOOK.md"
        original = runbook.read_text(encoding="utf-8")
        real_read_text = Path.read_text

        def rewrite_exact_line(document: str, marker: str, replacement: str) -> str:
            lines = document.splitlines(keepends=True)
            matches = [
                index for index, line in enumerate(lines) if line.strip() == marker
            ]
            self.assertEqual(len(matches), 1)
            index = matches[0]
            line = lines[index]
            indentation = line[: len(line) - len(line.lstrip())]
            ending = "\n" if line.endswith("\n") else ""
            lines[index] = f"{indentation}{replacement}{ending}"
            return "".join(lines)

        required_pairs = (
            (21, 24),  # complete trigger/effect preflight before remote push
            (23, 24),  # fail-closed preflight disposition before remote push
            (24, 29),  # remote push before public tagged-source checks
            (28, 29),  # post-push side-effect check before tagged-source checks
            (29, 30),  # tagged-source checks before viewer identity check
            (30, 33),  # authenticated viewer query before draft creation
            (32, 33),  # exact viewer identity before draft creation
            (33, 34),  # draft creation before release-identity capture
            (35, 36),  # release-identity capture before asset upload
            (36, 37),  # asset upload before asset-identity capture
            (43, 44),  # complete asset identity before authenticated download
            (44, 45),  # authenticated download before final API inspection
            (47, 77),  # exact release-ID endpoint before publication
            (48, 77),  # stable release identity before publication
            (50, 77),  # exact author account before publication
            (51, 77),  # exact tag before publication
            (52, 77),  # exact title before publication
            (56, 77),  # exact decoded body bytes before publication
            (57, 77),  # draft=true before publication
            (58, 77),  # non-prerelease unpublished state before publication
            (60, 77),  # stable API asset identities before publication
            (62, 77),  # exact asset uploaders before publication
            (63, 65),  # immediate re-download before byte comparison
            (65, 77),  # immediate byte comparison before publication
            (66, 77),  # no unexpected external side effect before publication
            (67, 77),  # UTC-date equality before publication
            (69, 77),  # candidate identities before publication
            (71, 77),  # no source change after tag before publication
            (74, 77),  # fail-closed disposition before publication
            (76, 77),  # exact release-ID binding before publication
            (77, 78),  # publication before authenticated metadata replay
            (78, 79),  # exact-ID query before release-identity replay
            (81, 82),  # metadata replay before published state check
            (82, 83),  # published state before timestamp check
            (84, 85),  # release date before side-effect check
            (86, 87),  # postpublication checks before anonymous verification
            (87, 88),  # authenticated replay before anonymous download
            (88, 89),  # anonymous download before local byte comparison
            (89, 90),  # byte comparison before reconstruction replay
            (90, 92),  # reconstruction before fresh-source replay
            (92, 93),  # fresh-source replay before cleanup stop rule
            (93, 94),  # fail-closed preservation before reference deletion
            (94, 95),  # deletion before absence confirmation
            (98, 99),  # final publication boundary before rollback procedure
        )

        for before_index, after_index in required_pairs:
            before = release_audit.PUBLICATION_SEQUENCE_MARKERS[before_index]
            after = release_audit.PUBLICATION_SEQUENCE_MARKERS[after_index]

            def reverse_pair(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> str:
                if path == runbook:
                    swapped = rewrite_exact_line(original, before, "ORDER-SWAP")
                    swapped = rewrite_exact_line(swapped, after, before)
                    return rewrite_exact_line(swapped, "ORDER-SWAP", after)
                return real_read_text(path, *args, **kwargs)

            with self.subTest(before=before, after=after):
                with (
                    patch.object(
                        Path,
                        "read_text",
                        autospec=True,
                        side_effect=reverse_pair,
                    ),
                    self.assertRaisesRegex(
                        release_audit.AuditError,
                        "inspect automation before remote push",
                    ),
                ):
                    release_audit.validate_project_metadata(inputs)

    def test_publication_sequence_rejects_removed_safety_controls(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        runbook = release_audit.RELEASE / "RELEASE-RUNBOOK.md"
        original = runbook.read_text(encoding="utf-8")
        real_read_text = Path.read_text

        def remove_exact_line(document: str, marker: str) -> str:
            lines = document.splitlines(keepends=True)
            matches = [
                index for index, line in enumerate(lines) if line.strip() == marker
            ]
            self.assertEqual(len(matches), 1)
            index = matches[0]
            line = lines[index]
            indentation = line[: len(line) - len(line.lstrip())]
            ending = "\n" if line.endswith("\n") else ""
            lines[index] = f"{indentation}CONTROL-REMOVED{ending}"
            return "".join(lines)

        control_indexes = (
            *range(16, 24),  # complete preflight scope, record, and stop rule
            *range(25, 29),  # complete post-push identity and side-effect checks
            *range(30, 44),  # viewer, draft, release, and asset identities
            *range(45, 78),  # complete immediate prepublication gate and stop rule
            *range(78, 99),  # postpublication replay, cleanup, and rollback handoff
            *range(100, 105),  # editable-text limit and immutable-identity withdrawal
        )

        for index in control_indexes:
            marker = release_audit.PUBLICATION_SEQUENCE_MARKERS[index]

            def remove_control(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> str:
                if path == runbook:
                    return remove_exact_line(original, marker)
                return real_read_text(path, *args, **kwargs)

            with self.subTest(marker=marker):
                with (
                    patch.object(
                        Path,
                        "read_text",
                        autospec=True,
                        side_effect=remove_control,
                    ),
                    self.assertRaisesRegex(
                        release_audit.AuditError,
                        "publication sequence omits exact marker",
                    ),
                ):
                    release_audit.validate_project_metadata(inputs)

    def test_publication_controls_must_be_visible_rendered_prose(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        runbook = release_audit.RELEASE / "RELEASE-RUNBOOK.md"
        original = runbook.read_text(encoding="utf-8")
        real_read_text = Path.read_text

        def wrap_block(
            document: str,
            first_marker: str,
            last_marker: str,
            opening: str,
            closing: str,
        ) -> str:
            lines = document.splitlines(keepends=True)
            first = next(
                index for index, line in enumerate(lines) if line.strip() == first_marker
            )
            last = next(
                index for index, line in enumerate(lines) if line.strip() == last_marker
            )
            self.assertLessEqual(first, last)
            return "".join(
                [*lines[:first], f"{opening}\n", *lines[first : last + 1], f"{closing}\n", *lines[last + 1 :]]
            )

        def insert_adjacent(
            document: str,
            marker: str,
            addition: str,
            *,
            after: bool,
        ) -> str:
            lines = document.splitlines(keepends=True)
            matches = [
                index for index, line in enumerate(lines) if line.strip() == marker
            ]
            self.assertEqual(len(matches), 1)
            index = matches[0] + int(after)
            return "".join([*lines[:index], f"{addition}\n", *lines[index:]])

        markers = release_audit.PUBLICATION_SEQUENCE_MARKERS
        cases = (
            (
                "commented preflight",
                wrap_block(original, markers[15], markers[23], "<!--", "-->"),
                "HTML comment delimiters",
            ),
            (
                "commented prepublication block",
                wrap_block(original, markers[30], markers[77], "<!--", "-->"),
                "HTML comment delimiters",
            ),
            (
                "fenced prepublication block",
                wrap_block(original, markers[30], markers[77], "```text", "```"),
                "publication sequence omits exact marker",
            ),
            (
                "fenced post-publication verification",
                wrap_block(original, markers[78], markers[87], "```text", "```"),
                "publication sequence omits exact marker",
            ),
            (
                "hidden div",
                wrap_block(original, markers[15], markers[23], '<div hidden="hidden">', "</div>"),
                "must not contain raw HTML",
            ),
            (
                "template",
                wrap_block(original, markers[30], markers[77], "<template>", "</template>"),
                "must not contain raw HTML",
            ),
            (
                "collapsed details",
                wrap_block(original, markers[30], markers[77], "<details>", "</details>"),
                "must not contain raw HTML",
            ),
            (
                "unclosed details before Publication",
                insert_adjacent(original, markers[8], "<details>", after=False),
                "must not contain raw HTML",
            ),
            (
                "unclosed hidden div before Publication",
                insert_adjacent(
                    original,
                    markers[8],
                    '<div hidden="hidden">',
                    after=False,
                ),
                "must not contain raw HTML",
            ),
            (
                "unclosed comment after final action",
                insert_adjacent(original, markers[77], "<!--", after=True),
                "HTML comment delimiters",
            ),
            (
                "fence splice after final action",
                insert_adjacent(original, markers[77], "```text", after=True),
                "publication sequence omits exact marker",
            ),
            (
                "unclosed fence before Publication",
                insert_adjacent(
                    original,
                    markers[8],
                    "``````````text",
                    after=False,
                ),
                "unterminated fenced code block",
            ),
            (
                "unclosed fence after final action",
                insert_adjacent(
                    original,
                    markers[77],
                    "``````````text",
                    after=True,
                ),
                "unterminated fenced code block",
            ),
        )
        for label, mutation, error_pattern in cases:

            def hidden_controls(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> str:
                if path == runbook:
                    return mutation
                return real_read_text(path, *args, **kwargs)

            with self.subTest(mutation=label):
                with (
                    patch.object(
                        Path,
                        "read_text",
                        autospec=True,
                        side_effect=hidden_controls,
                    ),
                    self.assertRaisesRegex(release_audit.AuditError, error_pattern),
                ):
                    release_audit.validate_project_metadata(inputs)

    def test_publication_rejects_alternate_active_mutations(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        runbook = release_audit.RELEASE / "RELEASE-RUNBOOK.md"
        original = runbook.read_text(encoding="utf-8")
        real_read_text = Path.read_text

        def insert_after(document: str, marker: str, addition: tuple[str, ...]) -> str:
            lines = document.splitlines(keepends=True)
            matches = [
                index for index, line in enumerate(lines) if line.strip() == marker
            ]
            self.assertEqual(len(matches), 1)
            index = matches[0] + 1
            inserted = [f"{line}\n" for line in addition]
            return "".join([*lines[:index], *inserted, *lines[index:]])

        markers = release_audit.PUBLICATION_SEQUENCE_MARKERS
        cases = (
            (
                "early publish imperative",
                insert_after(original, markers[30], ("Publish the draft now.",)),
                "early release-promotion imperative",
            ),
            (
                "early promote imperative",
                insert_after(original, markers[30], ("Promote the release immediately.",)),
                "early release-promotion imperative",
            ),
            (
                "early release imperative",
                insert_after(original, markers[30], ("Release the draft immediately.",)),
                "early release-promotion imperative",
            ),
            (
                "gh draft false equals",
                insert_after(original, markers[30], ("gh release edit v0.9.0 --draft=false",)),
                "active alternate release command",
            ),
            (
                "gh draft false separated",
                insert_after(original, markers[30], ("gh release edit v0.9.0 --draft false",)),
                "active alternate release command",
            ),
            (
                "fenced gh promotion",
                insert_after(
                    original,
                    markers[30],
                    ("```bash", "gh release edit v0.9.0 --draft=false", "```"),
                ),
                "active alternate release command",
            ),
            (
                "curl release promotion",
                insert_after(
                    original,
                    markers[30],
                    (
                        "curl -X PATCH https://api.github.com/repos/sepahead/galadriel/releases/1",
                    ),
                ),
                "active alternate release command",
            ),
            (
                "gh API release promotion",
                insert_after(
                    original,
                    markers[30],
                    (
                        "gh api --method PATCH /repos/sepahead/galadriel/releases/1 --field draft=false",
                    ),
                ),
                "active alternate release command",
            ),
            (
                "gh API input-file release promotion",
                insert_after(
                    original,
                    markers[30],
                    (
                        "gh api /repos/sepahead/galadriel/releases/1 --input mutation.json",
                    ),
                ),
                "active alternate release command",
            ),
            (
                "early push command",
                insert_after(original, markers[14], ("git push origin v0.9.0",)),
                "remote-ref mutation command",
            ),
            (
                "early push imperative",
                insert_after(original, markers[14], ("Push v0.9.0 to origin now.",)),
                "remote mutation imperative",
            ),
            (
                "early send imperative",
                insert_after(original, markers[14], ("Send the tag to origin now.",)),
                "remote mutation imperative",
            ),
            (
                "early upload imperative",
                insert_after(original, markers[14], ("Upload the release assets now.",)),
                "remote mutation imperative",
            ),
            (
                "early gh ref API",
                insert_after(
                    original,
                    markers[14],
                    ("gh api --method POST repos/sepahead/galadriel/git/refs",),
                ),
                "remote-ref mutation command",
            ),
            (
                "early curl ref API",
                insert_after(
                    original,
                    markers[14],
                    (
                        "curl -X POST https://api.github.com/repos/sepahead/galadriel/git/refs",
                    ),
                ),
                "remote-ref mutation command",
            ),
            (
                "fenced early push",
                insert_after(
                    original,
                    markers[14],
                    ("```bash", "git push origin v0.9.0", "```"),
                ),
                "remote-ref mutation command",
            ),
            (
                "fenced early gh ref API",
                insert_after(
                    original,
                    markers[14],
                    (
                        "```bash",
                        "gh api --method POST repos/sepahead/galadriel/git/refs",
                        "```",
                    ),
                ),
                "remote-ref mutation command",
            ),
        )
        for label, mutation, error_pattern in cases:

            def alternate_mutation(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> str:
                if path == runbook:
                    return mutation
                return real_read_text(path, *args, **kwargs)

            with self.subTest(mutation=label):
                with (
                    patch.object(
                        Path,
                        "read_text",
                        autospec=True,
                        side_effect=alternate_mutation,
                    ),
                    self.assertRaisesRegex(release_audit.AuditError, error_pattern),
                ):
                    release_audit.validate_project_metadata(inputs)

    def test_release_runbook_contract_rejects_unreviewed_instructions(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        runbook = release_audit.RELEASE / "RELEASE-RUNBOOK.md"
        original = runbook.read_text(encoding="utf-8")
        real_read_text = Path.read_text

        def insert_after(marker: str, addition: tuple[str, ...]) -> str:
            lines = original.splitlines(keepends=True)
            matches = [
                index for index, line in enumerate(lines) if line.strip() == marker
            ]
            self.assertEqual(len(matches), 1)
            index = matches[0] + 1
            inserted = [f"{line}\n" for line in addition]
            return "".join([*lines[:index], *inserted, *lines[index:]])

        markers = release_audit.PUBLICATION_SEQUENCE_MARKERS
        cases = (
            (
                "pre-Publication fenced git push",
                insert_after(
                    markers[7],
                    ("```bash", "git push origin v0.9.0", "```"),
                ),
            ),
            (
                "pre-Publication fenced gh promotion",
                insert_after(
                    markers[7],
                    ("```bash", "gh release edit v0.9.0 --draft=false", "```"),
                ),
            ),
            (
                "pre-Publication publish imperative",
                insert_after(markers[7], ("Publish the draft now.",)),
            ),
            (
                "pre-Publication GraphQL createRef",
                insert_after(
                    markers[7],
                    ('gh api graphql -f query="mutation { createRef(input: {}) }"',),
                ),
            ),
            (
                "git directory override push",
                insert_after(markers[14], ("git -C . push origin v0.9.0",)),
            ),
            (
                "git configuration override push",
                insert_after(
                    markers[14],
                    ("git -c core.sshCommand=ssh push origin v0.9.0",),
                ),
            ),
            (
                "split fenced git push",
                insert_after(
                    markers[14],
                    ("```bash", "git \\", "push origin v0.9.0", "```"),
                ),
            ),
            (
                "GraphQL createRef",
                insert_after(
                    markers[14],
                    ('gh api graphql -f query="mutation { createRef(input: {}) }"',),
                ),
            ),
            (
                "GraphQL updateRelease",
                insert_after(
                    markers[30],
                    (
                        'gh api graphql -f query="mutation { updateRelease(input: {isDraft: false}) { release { id } } }"',
                    ),
                ),
            ),
            (
                "make draft public",
                insert_after(markers[30], ("Make the draft public now.",)),
            ),
            (
                "finalize release",
                insert_after(markers[30], ("Finalize the GitHub release now.",)),
            ),
            (
                "Python release PATCH",
                insert_after(
                    markers[30],
                    (
                        'python3 -c \'import requests; requests.patch("https://api.github.com/repos/x/y/releases/1")\'',
                    ),
                ),
            ),
        )
        for label, mutation in cases:

            def unreviewed_instruction(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> str:
                if path == runbook:
                    return mutation
                return real_read_text(path, *args, **kwargs)

            with self.subTest(mutation=label):
                with (
                    patch.object(
                        Path,
                        "read_text",
                        autospec=True,
                        side_effect=unreviewed_instruction,
                    ),
                    self.assertRaisesRegex(
                        release_audit.AuditError,
                        "exact reviewed runbook contract",
                    ),
                ):
                    release_audit.validate_project_metadata(inputs)

    def test_local_tag_creation_is_an_irreversible_version_boundary(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        runbook = release_audit.RELEASE / "RELEASE-RUNBOOK.md"
        original = runbook.read_text(encoding="utf-8")
        real_read_text = Path.read_text
        boundary = "After any local `v0.9.0` tag exists, even if unpushed, do not repair the"

        def weaken_local_tag_boundary(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == runbook:
                return original.replace(boundary, "After the remote tag exists, stop.", 1)
            return real_read_text(path, *args, **kwargs)

        with (
            patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=weaken_local_tag_boundary,
            ),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "publication sequence omits exact marker",
            ),
        ):
            release_audit.validate_project_metadata(inputs)

    def test_ncp_claim_binds_roles_to_an_immutable_status_commit(self) -> None:
        claims = release_audit.validate_claims()
        claim = next(item for item in claims if item["id"] == "CLM-008")
        self.assertEqual(claim["tier"], "NOT_CLAIMED")
        for boundary in (
            release_audit.NCP_STATUS_COMMIT,
            release_audit.NCP_STATUS_URL,
            release_audit.NCP_TASK_LEDGER_URL,
            release_audit.NCP_ROLE_BLUEPRINT_URL,
            *release_audit.NCP_ROLE_SUBJECTS,
            "G03 is OPEN",
            "X02, which is OPEN",
            "Galadriel assessor",
            "derive StateUnusable",
            "optional non-authoritative requested effect",
            "NOT RUN",
        ):
            self.assertIn(boundary, claim["limitations"])
        self.assertNotIn("/main", claim["limitations"])

    def test_release_body_uses_absolute_tag_publication_targets(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        release_audit.validate_project_metadata(inputs)
        notes = release_audit.RELEASE / "RELEASE-NOTES.md"
        original = notes.read_text(encoding="utf-8")
        real_read_text = Path.read_text
        first_target = release_audit.RELEASE_NOTE_PUBLICATION_TARGETS[0]

        def relative_release_target(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == notes:
                return original.replace(first_target, "ecosystem-cut.json")
            return real_read_text(path, *args, **kwargs)

        with (
            patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=relative_release_target,
            ),
            self.assertRaisesRegex(release_audit.AuditError, "publication target"),
        ):
            release_audit.validate_project_metadata(inputs)

    def test_public_schema_ids_are_immutable_tag_targets(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        schema_path = release_audit.ROOT / release_audit.PUBLIC_JSON_SCHEMA_IDS[0][0]
        original = schema_path.read_text(encoding="utf-8")
        real_read_text = Path.read_text

        def mutable_schema_id(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == schema_path:
                return original.replace("/v0.9.0/", "/main/", 1)
            return real_read_text(path, *args, **kwargs)

        with (
            patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=mutable_schema_id,
            ),
            self.assertRaisesRegex(release_audit.AuditError, "immutable public \\$id"),
        ):
            release_audit.validate_project_metadata(inputs)

    def test_project_metadata_rejects_duplicate_public_schema_id(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        relative_path, expected_schema_id = release_audit.PUBLIC_JSON_SCHEMA_IDS[0]
        schema_path = release_audit.ROOT / relative_path
        original = schema_path.read_text(encoding="utf-8")
        id_line = f'  "$id": "{expected_schema_id}",\n'
        self.assertEqual(original.count(id_line), 1)
        duplicate_id = original.replace(id_line, id_line + id_line, 1)
        real_read_text = Path.read_text

        def duplicate_schema_id(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == schema_path:
                return duplicate_id
            return real_read_text(path, *args, **kwargs)

        with (
            patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=duplicate_schema_id,
            ),
            self.assertRaisesRegex(release_audit.AuditError, "duplicate JSON key"),
        ):
            release_audit.validate_project_metadata(inputs)

    def test_project_metadata_rejects_hostile_public_schema_types(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        relative_path, _ = release_audit.PUBLIC_JSON_SCHEMA_IDS[0]
        schema_path = release_audit.ROOT / relative_path
        real_read_text = Path.read_text

        for document, error_pattern in (
            ([], "must contain a JSON object"),
            ({"$id": 1}, "wrong immutable public \\$id"),
        ):
            with self.subTest(document=document):

                def hostile_schema_type(
                    path: Path,
                    *args: object,
                    **kwargs: object,
                ) -> str:
                    if path == schema_path:
                        return json.dumps(document) + "\n"
                    return real_read_text(path, *args, **kwargs)

                with (
                    patch.object(
                        Path,
                        "read_text",
                        autospec=True,
                        side_effect=hostile_schema_type,
                    ),
                    self.assertRaisesRegex(release_audit.AuditError, error_pattern),
                ):
                    release_audit.validate_project_metadata(inputs)

    def test_project_metadata_rejects_duplicate_clm_010_field(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        original = release_audit.CLAIMS.read_text(encoding="utf-8")
        limitations_line = (
            '      "limitations": "All workspace packages remain publish=false. '
            "Source preparation state for this tree is UNPUBLISHED_CANDIDATE with "
            "no candidate release date. GitHub publication is external evidence and "
            'is not inferred from this tracked claim."\n'
        )
        self.assertEqual(original.count(limitations_line), 1)
        duplicate_field = original.replace(
            limitations_line,
            limitations_line.rstrip("\n") + ",\n" + limitations_line,
            1,
        )
        real_read_text = Path.read_text

        def duplicate_clm_010_field(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            if path == release_audit.CLAIMS:
                return duplicate_field
            return real_read_text(path, *args, **kwargs)

        with (
            patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=duplicate_clm_010_field,
            ),
            self.assertRaisesRegex(release_audit.AuditError, "duplicate JSON key"),
        ):
            release_audit.validate_project_metadata(inputs)

    def test_project_metadata_rejects_hostile_claims_shapes(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        current = release_audit.load_json(release_audit.CLAIMS)
        original_load = release_audit.load_json
        claims_string = copy.deepcopy(current)
        claims_string["claims"] = "CLM-010"
        claims_with_scalar = copy.deepcopy(current)
        claims_with_scalar["claims"] = [1]
        hostile_cases = [
            ("root array", [], "claims must be an object"),
            ("root object without fields", {}, "claims: missing="),
            ("root string", "CLM-010", "claims must be an object"),
            ("claims string", claims_string, "claims matrix claims must be a list"),
            ("claims scalar entry", claims_with_scalar, "claim must be an object"),
        ]
        for label, value in (
            ("tier definitions scalar", 1),
            ("tier definitions array", [{}]),
        ):
            document = copy.deepcopy(current)
            document["tier_definitions"] = value
            hostile_cases.append(
                (label, document, "tier_definitions must be an object")
            )
        non_text_definition = copy.deepcopy(current)
        non_text_definition["tier_definitions"]["IMPLEMENTED"] = 1
        hostile_cases.append(
            (
                "non-text tier definition",
                non_text_definition,
                "tier definitions must be non-empty text",
            )
        )
        for field, value, error_pattern in (
            ("id", [], "invalid or duplicate claim ID"),
            ("tier", [], "tier must be text"),
            ("claim", [], "claim must be non-empty text"),
            ("scope", {}, "scope must be non-empty text"),
            ("limitations", 1, "limitations must be non-empty text"),
            ("evidence", 1, "evidence must be a list of paths"),
            ("evidence", [1], "claim evidence path is not text"),
        ):
            document = copy.deepcopy(current)
            document["claims"][0][field] = value
            hostile_cases.append((f"hostile {field}", document, error_pattern))

        for label, document, error_pattern in hostile_cases:
            with self.subTest(shape=label):

                def load_hostile_claims(path: Path, *args: object) -> object:
                    if path == release_audit.CLAIMS:
                        return document
                    return original_load(path, *args)

                with (
                    patch.object(
                        release_audit,
                        "load_json",
                        side_effect=load_hostile_claims,
                    ),
                    self.assertRaisesRegex(release_audit.AuditError, error_pattern),
                ):
                    release_audit.validate_project_metadata(inputs)

    def test_abbreviated_or_oversized_repository_revision_is_rejected(self) -> None:
        for revision in ("deadbeef", "0" * 41):
            with self.subTest(revision=revision):
                inputs = copy.deepcopy(release_audit.load_json(release_audit.INPUTS))
                inputs["repositories"][0]["commit"] = revision
                with self.assertRaisesRegex(release_audit.AuditError, "full revision"):
                    release_audit.validate_inputs(inputs)

    def test_source_ledger_never_claims_post_commit_completion(self) -> None:
        ledger = release_audit.validate_ledger(
            release_audit.validate_tasks(), release_audit.validate_claims()
        )
        self.assertEqual(
            ledger["status_counts"],
            {"OPEN": 107, "COMPLETE": 0, "NOT_CLAIMED": 9},
        )
        self.assertTrue(
            all(
                not task["post_commit_evidence"]
                and not task["post_commit_tests"]
                and not task["post_commit_findings"]
                for task in ledger["tasks"]
            )
        )

    def test_every_claim_has_a_frozen_tier_and_limit(self) -> None:
        claims = release_audit.validate_claims()
        self.assertGreater(len(claims), 0)
        self.assertTrue(
            all(claim["tier"] in release_audit.VALID_TIERS for claim in claims)
        )
        self.assertTrue(all(claim["limitations"] for claim in claims))
        self.assertFalse(
            any(claim["tier"] == "DEPLOYMENT_QUALIFIED" for claim in claims)
        )

    def test_threat_register_is_complete_and_bound_to_current_tasks(self) -> None:
        artifact = release_audit.validate_threat_register()
        document = release_audit.load_json(release_audit.THREAT_REGISTER)
        self.assertEqual(artifact["path"], "release/0.9.0/audit/threat-register.json")
        self.assertGreaterEqual(len(document["threats"]), 10)
        self.assertEqual(
            document["source"]["task_ledger_sha256"],
            release_audit.load_json(release_audit.TASKS)["source"][
                "task_ledger_sha256"
            ],
        )

    def test_threat_register_accepts_only_declared_lifecycle_states(self) -> None:
        current = release_audit.load_json(release_audit.THREAT_REGISTER)
        original_load = release_audit.load_json

        def load_with_status(path: Path, status: str) -> object:
            if path == release_audit.THREAT_REGISTER:
                document = copy.deepcopy(current)
                document["status"] = status
                return document
            return original_load(path)

        for status in sorted(release_audit.VALID_THREAT_REGISTER_STATUSES):
            with self.subTest(status=status):
                with patch.object(
                    release_audit,
                    "load_json",
                    side_effect=lambda path, status=status: load_with_status(
                        path, status
                    ),
                ):
                    release_audit.validate_threat_register()

        with patch.object(
            release_audit,
            "load_json",
            side_effect=lambda path: load_with_status(path, "UNSUPPORTED"),
        ):
            with self.assertRaisesRegex(
                release_audit.AuditError, "unsupported lifecycle status"
            ):
                release_audit.validate_threat_register()

    def test_threat_register_requires_a_top_level_object(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        original_load = release_audit.load_json

        def load_threat_array(path: Path, *args: object) -> object:
            if path == release_audit.THREAT_REGISTER:
                return []
            return original_load(path, *args)

        validators = (
            ("project metadata", lambda: release_audit.validate_project_metadata(inputs)),
            ("threat register", release_audit.validate_threat_register),
        )
        for label, validator in validators:
            with self.subTest(validator=label), patch.object(
                release_audit,
                "load_json",
                side_effect=load_threat_array,
            ), self.assertRaisesRegex(
                release_audit.AuditError,
                "threat register must be an object",
            ):
                validator()

    def test_ecosystem_cut_contains_each_observation_date(self) -> None:
        current = release_audit.load_json(release_audit.ECOSYSTEM_CUT)
        release_audit.validate_ecosystem_cut()
        original_load = release_audit.load_json

        def load_cut(document: object):
            return lambda path: (
                document if path == release_audit.ECOSYSTEM_CUT else original_load(path)
            )

        stale = copy.deepcopy(current)
        stale["inspected_at"] = "2026-08-02"
        with (
            patch.object(
                release_audit,
                "load_json",
                side_effect=load_cut(stale),
            ),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "inspected_at predates observation ECO-014",
            ),
        ):
            release_audit.validate_ecosystem_cut()

        wrong_status = copy.deepcopy(current)
        eco_014 = next(
            item for item in wrong_status["observations"] if item["id"] == "ECO-014"
        )
        eco_014["status"]["dependency_status"] = "COMPLETE"
        with (
            patch.object(
                release_audit,
                "load_json",
                side_effect=load_cut(wrong_status),
            ),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "incorrect NCP release-status snapshot",
            ),
        ):
            release_audit.validate_ecosystem_cut()

        mixed_precision = copy.deepcopy(current)
        mixed_precision["observations"][0]["timestamp_precision"] = "second"
        with (
            patch.object(
                release_audit,
                "load_json",
                side_effect=load_cut(mixed_precision),
            ),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "timestamp precision differs",
            ),
        ):
            release_audit.validate_ecosystem_cut()

        for hostile_why in (1, None, [], {}):
            with self.subTest(eco_014_why=hostile_why):
                hostile_rationale = copy.deepcopy(current)
                hostile_eco_014 = next(
                    item
                    for item in hostile_rationale["observations"]
                    if item["id"] == "ECO-014"
                )
                hostile_eco_014["why"] = hostile_why
                with (
                    patch.object(
                        release_audit,
                        "load_json",
                        side_effect=load_cut(hostile_rationale),
                    ),
                    self.assertRaisesRegex(
                        release_audit.AuditError,
                        "incorrect NCP status rationale",
                    ),
                ):
                    release_audit.validate_ecosystem_cut()

    def test_audit_date_covers_every_ecosystem_observation(self) -> None:
        inputs = copy.deepcopy(release_audit.load_json(release_audit.INPUTS))
        inspected_at, observation_dates = release_audit.validate_ecosystem_cut()
        release_audit.validate_audit_date_boundary(
            inputs,
            inspected_at,
            observation_dates,
        )
        inputs["audit_date"] = "2026-08-02"
        with self.assertRaisesRegex(
            release_audit.AuditError,
            "audit_date predates ecosystem inspected_at",
        ):
            release_audit.validate_audit_date_boundary(
                inputs,
                inspected_at,
                observation_dates,
            )

    def test_release_publication_channel_is_exact(self) -> None:
        inputs = copy.deepcopy(release_audit.load_json(release_audit.INPUTS))
        self.assertEqual(
            inputs["release"]["publication_channel"],
            release_audit.PUBLICATION_CHANNEL,
        )
        inputs["release"]["publication_channel"] = "another channel"
        with self.assertRaisesRegex(
            release_audit.AuditError,
            "publication channel differs",
        ):
            release_audit.validate_inputs(inputs)

    def test_build_is_deterministic_and_covers_all_tasks(self) -> None:
        first_audit, first_ledger = release_audit.build_outputs()
        second_audit, second_ledger = release_audit.build_outputs()
        self.assertEqual(first_audit, second_audit)
        self.assertEqual(first_ledger, second_ledger)
        self.assertEqual(
            first_audit["schema"],
            "galadriel.release-audit-manifest.v2",
        )
        self.assertEqual(first_ledger["source_task_count"], 116)
        self.assertEqual(sum(first_ledger["status_counts"].values()), 116)
        self.assertEqual(first_ledger["status_counts"]["COMPLETE"], 0)
        covered = {entry["path"] for entry in first_audit["artifacts"]}
        self.assertEqual(
            first_audit["artifact_self_exclusions"],
            sorted(release_audit.AUDIT_SELF_EXCLUSIONS),
        )
        self.assertEqual(
            covered,
            release_audit.tracked_repository_paths()
            - release_audit.AUDIT_SELF_EXCLUSIONS,
        )
        self.assertTrue(
            all(
                set(entry)
                == {
                    "path",
                    "purpose",
                    "git_mode",
                    "git_blob_id",
                    "sha256",
                    "size_bytes",
                }
                for entry in first_audit["artifacts"]
            )
        )
        ledger_entry = next(
            entry
            for entry in first_audit["artifacts"]
            if entry["path"] == "release/0.9.0/requirements-ledger.json"
        )
        ledger_bytes = release_audit.canonical_bytes(first_ledger)
        self.assertEqual(
            ledger_entry["sha256"], hashlib.sha256(ledger_bytes).hexdigest()
        )
        self.assertEqual(ledger_entry["size_bytes"], len(ledger_bytes))
        self.assertEqual(ledger_entry["git_mode"], "100644")
        self.assertEqual(
            ledger_entry["git_blob_id"],
            release_audit._git_blob_id(ledger_bytes),
        )

    def test_snapshot_build_does_not_reopen_repository_files(self) -> None:
        snapshot = release_audit.capture_repository_snapshot(allow_generated_drift=True)

        def unexpected_reopen(*args: object, **kwargs: object) -> object:
            raise AssertionError("semantic consumer reopened a repository path")

        with (
            patch.object(
                Path,
                "read_text",
                autospec=True,
                side_effect=unexpected_reopen,
            ),
            patch.object(
                Path,
                "read_bytes",
                autospec=True,
                side_effect=unexpected_reopen,
            ),
            patch.object(
                Path,
                "open",
                autospec=True,
                side_effect=unexpected_reopen,
            ),
            patch.object(
                Path,
                "is_file",
                autospec=True,
                side_effect=unexpected_reopen,
            ),
            patch.object(
                Path,
                "exists",
                autospec=True,
                side_effect=unexpected_reopen,
            ),
            patch.object(
                Path,
                "glob",
                autospec=True,
                side_effect=unexpected_reopen,
            ),
        ):
            audit, ledger = release_audit.build_outputs(snapshot)
        self.assertEqual(audit["schema"], "galadriel.release-audit-manifest.v2")
        self.assertEqual(ledger["schema"], "galadriel.requirements-ledger.v2")

    def test_workflow_actions_are_full_revisions_and_exactly_inventoried(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        recorded = {
            (entry["action"], entry["commit"]) for entry in inputs["github_actions"]
        }
        self.assertEqual(recorded, release_audit.workflow_action_refs())

        incomplete = copy.deepcopy(inputs)
        incomplete["github_actions"].pop()
        with self.assertRaisesRegex(
            release_audit.AuditError, "inventory differs from workflows"
        ):
            release_audit.validate_inputs(incomplete)


if __name__ == "__main__":
    unittest.main()
