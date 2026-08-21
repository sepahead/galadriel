#!/usr/bin/env python3
"""Run the exact Rust CREBAIN study through its schema and Decimal gates.

The command emits one canonical JSON receipt to stdout.  Candidate qualification
retains that receipt in its command log, including the digest and size of the
exact Rust JSON bytes.  It does not retain or publish the raw study document;
publication packaging remains a separate, explicitly identified step.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from decimal import DecimalException, localcontext
from pathlib import Path

import check_crebain_mgw_decimal_oracle as decimal_oracle
import check_crebain_mgw_schema as schema_checker


ROOT = Path(__file__).resolve().parents[1]
MAX_STDERR_BYTES = 1_048_576
TIMEOUT_SECONDS = 240


class CandidateGateError(RuntimeError):
    """The exact Rust-to-schema/Decimal candidate route failed."""


def _run_rust_study() -> bytes:
    environment = dict(os.environ)
    environment["CARGO_TERM_COLOR"] = "never"
    with (
        tempfile.NamedTemporaryFile(prefix="galadriel-crebain-json-") as stdout,
        tempfile.NamedTemporaryFile(prefix="galadriel-crebain-stderr-") as stderr,
    ):
        try:
            completed = subprocess.run(
                [
                    "cargo",
                    "run",
                    "--locked",
                    "--offline",
                    "-q",
                    "-p",
                    "galadriel-justify",
                    "--bin",
                    "galadriel-crebain-mgw",
                    "--",
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise CandidateGateError(
                f"Rust study exceeded {TIMEOUT_SECONDS} seconds"
            ) from error
        stdout.flush()
        stderr.flush()
        stdout_size = Path(stdout.name).stat().st_size
        stderr_size = Path(stderr.name).stat().st_size
        if stdout_size > schema_checker.MAX_INSTANCE_BYTES:
            raise CandidateGateError(
                f"Rust study emitted {stdout_size} bytes; maximum is "
                f"{schema_checker.MAX_INSTANCE_BYTES}"
            )
        if stderr_size > MAX_STDERR_BYTES:
            raise CandidateGateError(
                f"Rust study stderr emitted {stderr_size} bytes; maximum is "
                f"{MAX_STDERR_BYTES}"
            )
        stdout.seek(0)
        stderr.seek(0)
        rust_json = stdout.read()
        diagnostic = stderr.read().decode("utf-8", "replace").strip()
    if completed.returncode != 0:
        raise CandidateGateError(
            f"Rust study exited {completed.returncode}: {diagnostic[:4096]}"
        )
    if diagnostic:
        raise CandidateGateError(
            "Rust study emitted unexpected stderr: " + diagnostic[:4096]
        )
    return rust_json


def build_receipt() -> dict[str, object]:
    """Execute and cross-check one exact candidate study output."""

    rust_json = _run_rust_study()
    schema, schema_raw = schema_checker.load_schema()
    with tempfile.NamedTemporaryFile(suffix=".json") as instance_file:
        instance_file.write(rust_json)
        instance_file.flush()
        instance, loaded_raw = schema_checker.load_json_document(
            Path(instance_file.name), maximum_bytes=schema_checker.MAX_INSTANCE_BYTES
        )
    if loaded_raw != rust_json:
        raise CandidateGateError("exact Rust output changed while it was validated")
    schema_checker.validate_document(instance, schema)
    schema_checker.validate_machine_schema_binding(instance, schema_raw)
    schema_checker.validate_semantic_identity_bindings(instance)

    with localcontext() as context:
        context.prec = decimal_oracle.PRECISION
        oracle = decimal_oracle.build_oracle()
        oracle_digest = hashlib.sha256(decimal_oracle.canonical_bytes(oracle)).hexdigest()
        if oracle_digest != decimal_oracle.EXPECTED_ORACLE_SHA256:
            raise CandidateGateError(
                "Decimal oracle digest differs from its frozen coordinate identity"
            )
        comparison = decimal_oracle.compare_rust_output(oracle, rust_json)

    schema_identity = schema_checker.schema_identity(schema_raw)
    return {
        "schema": "galadriel.crebain-mgw-candidate-gate.v1",
        "rust_output_sha256": hashlib.sha256(rust_json).hexdigest(),
        "rust_output_bytes": len(rust_json),
        "machine_schema_sha256": schema_identity.sha256,
        "machine_schema_bytes": schema_identity.size_bytes,
        "decimal_oracle_sha256": oracle_digest,
        "averaged_atom_components_compared": comparison[
            "averaged_atom_components_compared"
        ],
        "subset_mutual_informations_compared": comparison[
            "subset_mutual_informations_compared"
        ],
        "pointwise_decimal_components_compared": comparison[
            "pointwise_decimal_components_compared"
        ],
        "maximum_abs_error_nats": comparison["maximum_abs_error_nats"],
        "tolerance_nats": comparison["tolerance_nats"],
        "schema_all_passed": True,
        "decimal_all_passed": comparison["all_passed"],
        "boundary": (
            "candidate execution subreceipt for exact Rust bytes, closed wire schema, "
            "and dependency-disjoint averaged-law Decimal comparison. Candidate commit "
            "and tree binding are supplied by the qualification envelope. Raw output "
            "publication, pointwise Decimal reproduction, field validity, and human "
            "replication are separate"
        ),
    }


def main() -> int:
    try:
        receipt = build_receipt()
    except (
        CandidateGateError,
        DecimalException,
        OSError,
        TypeError,
        ValueError,
        decimal_oracle.OracleError,
        schema_checker.ContractError,
    ) as error:
        print(f"CREBAIN candidate gate failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, allow_nan=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
