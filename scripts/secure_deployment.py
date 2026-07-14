#!/usr/bin/env python3
"""Render and verify Galadriel's exact-epoch Zenoh security profile.

The profile deliberately produces strict JSON, which is also valid Zenoh JSON5.
Only certificate *paths* are accepted; credentials and key bytes never belong in
the profile or generated evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import stat
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "deploy" / "galadriel-security-profile.example.json"
ENDPOINT_CORPUS = ROOT / "deploy" / "secure-client-endpoint-corpus.json"
REFERENCE_DIR = ROOT / "deploy" / "reference"
PROFILE_VERSION = "1"
APPLICATION_MAX_MESSAGE_BYTES = 65_536
TRANSPORT_MAX_MESSAGE_BYTES = 131_072
ZENOH_ENDPOINT_MAX_BYTES = 255
OUTPUT_NAMES = {
    "router": "zenoh-router.json5",
    "producer": "zenoh-producer.json5",
    "observer": "zenoh-observer.json5",
}
HANDOFF_NAME = "galadriel-handoff.json"
MANIFEST_NAME = "SHA256SUMS"
HANDOFF_FIELDS = {
    "profile_version",
    "realm",
    "epoch",
    "producer_id",
    "registry_canonical_sha256",
    "producer_cert_common_name",
    "observer_cert_common_name",
}
TOP_LEVEL_FIELDS = {
    "profile_version",
    "realm",
    "epoch",
    "producer_id",
    "registry_canonical_sha256",
    "producer_cert_common_name",
    "observer_cert_common_name",
    "router_listen_endpoint",
    "router_connect_endpoint",
    "transport_max_message_bytes",
    "certificates",
}
CERTIFICATE_FIELDS = {
    "root_ca_certificate",
    "router_private_key",
    "router_certificate",
    "producer_private_key",
    "producer_certificate",
    "observer_private_key",
    "observer_certificate",
}
PRIVATE_KEY_FIELDS = {
    "router_private_key",
    "producer_private_key",
    "observer_private_key",
}


class ProfileError(ValueError):
    """The deployment profile or rendered configuration is unsafe."""


class DuplicateJsonKeyError(ValueError):
    """A strict JSON object repeated one of its member names."""


def _utf8_len(value: str) -> int:
    return len(value.encode("utf-8"))


def _has_forbidden_control(value: str) -> bool:
    return any(unicodedata.category(char).startswith("C") for char in value)


def _valid_segment(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= _utf8_len(value) <= 64
        and not _has_forbidden_control(value)
        and not any(char.isspace() or char in "/*$#?" for char in value)
    )


def _require_exact_fields(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProfileError(f"{label} fields differ: missing={missing}, extra={extra}")
    return value


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise DuplicateJsonKeyError(f"duplicate JSON object key {key!r}")
        value[key] = member
    return value


def _require_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ProfileError(f"{label} must be a non-empty path without surrounding whitespace")
    if (
        _has_forbidden_control(value)
        or "-----BEGIN" in value
        or "\n" in value
        or "$" in value
    ):
        raise ProfileError(f"{label} must name a file; embedded credential material is forbidden")
    if value.startswith(("base64:", "data:")):
        raise ProfileError(f"{label} must be a file path, not inline data")
    return value


def _normalized_path_identity(path: str, label: str) -> str:
    try:
        return os.path.normcase(str(Path(path).expanduser().resolve(strict=False)))
    except (OSError, RuntimeError) as error:
        raise ProfileError(f"{label} cannot be resolved safely: {error}") from error


def _require_cn(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ProfileError(f"{label} must be a non-empty exact certificate common name")
    if _utf8_len(value) > 128 or _has_forbidden_control(value):
        raise ProfileError(f"{label} is too long or contains a control character")
    if any(char in value for char in "*$#?"):
        raise ProfileError(f"{label} must not contain wildcard-looking characters")
    return value


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ProfileError(f"{label} must be exactly 64 lowercase SHA-256 hex characters")
    return value


def _require_tls_endpoint(value: object, label: str, *, listener: bool) -> str:
    if not isinstance(value, str) or not value.startswith("tls/"):
        raise ProfileError(f"{label} must be one explicit tls/ endpoint")
    if not value.isascii() or len(value) > ZENOH_ENDPOINT_MAX_BYTES:
        raise ProfileError(
            f"{label} must be ASCII and at most {ZENOH_ENDPOINT_MAX_BYTES} bytes"
        )
    if value != value.strip() or _has_forbidden_control(value) or any(c in value for c in "*$#?"):
        raise ProfileError(f"{label} contains an unsafe character")
    authority = value.removeprefix("tls/")
    if not authority:
        raise ProfileError(f"{label} must include host and port")

    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0 or authority[closing + 1 :].count(":") != 1:
            raise ProfileError(f"{label} has an invalid bracketed IPv6 endpoint")
        host = authority[1:closing]
        port = authority[closing + 2 :]
        try:
            parsed_host: ipaddress.IPv4Address | ipaddress.IPv6Address | None = (
                ipaddress.IPv6Address(host)
            )
        except ipaddress.AddressValueError as error:
            raise ProfileError(f"{label} has an invalid IPv6 host") from error
    else:
        if authority.count(":") != 1:
            raise ProfileError(f"{label} must use host:port or [IPv6]:port")
        host, port = authority.rsplit(":", 1)
        try:
            parsed_host = ipaddress.ip_address(host)
        except ValueError:
            parsed_host = None
            labels = host.split(".")
            if (
                len(host) > 253
                or any(
                    not part
                    or len(part) > 63
                    or part[0] == "-"
                    or part[-1] == "-"
                    or any(
                        not (char.isascii() and (char.isalnum() or char == "-"))
                        for char in part
                    )
                    for part in labels
                )
            ):
                raise ProfileError(f"{label} has an invalid DNS host")

    if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65_535:
        raise ProfileError(f"{label} port must be a decimal integer in 1..=65535")
    if not listener and parsed_host is not None and parsed_host.is_unspecified:
        raise ProfileError(f"{label} client endpoint must name a verifiable router host")
    return value


def validate_profile(raw: object) -> dict[str, Any]:
    """Return a validated profile without accepting ignored/unknown fields."""

    profile = _require_exact_fields(raw, TOP_LEVEL_FIELDS, "profile")
    if profile["profile_version"] != PROFILE_VERSION:
        raise ProfileError(f"profile_version must be {PROFILE_VERSION!r}")

    realm = profile["realm"]
    if not isinstance(realm, str) or not realm or not all(
        _valid_segment(segment) for segment in realm.split("/")
    ):
        raise ProfileError("realm must contain only exact, non-wildcard NCP path segments")
    if not _valid_segment(profile["epoch"]):
        raise ProfileError("epoch must be one exact 1..=64-byte NCP path segment")
    if not _valid_segment(profile["producer_id"]):
        raise ProfileError("producer_id must be one exact 1..=64-byte NCP path segment")
    _require_sha256(
        profile["registry_canonical_sha256"], "registry_canonical_sha256"
    )

    producer_cn = _require_cn(profile["producer_cert_common_name"], "producer CN")
    observer_cn = _require_cn(profile["observer_cert_common_name"], "observer CN")
    if producer_cn == observer_cn:
        raise ProfileError("producer and observer certificates must have distinct common names")

    _require_tls_endpoint(profile["router_listen_endpoint"], "router listener", listener=True)
    _require_tls_endpoint(profile["router_connect_endpoint"], "router client endpoint", listener=False)
    if profile["transport_max_message_bytes"] != TRANSPORT_MAX_MESSAGE_BYTES:
        raise ProfileError(
            f"transport_max_message_bytes must be {TRANSPORT_MAX_MESSAGE_BYTES}; "
            f"the v1 application maximum remains {APPLICATION_MAX_MESSAGE_BYTES}"
        )

    certificates = _require_exact_fields(
        profile["certificates"], CERTIFICATE_FIELDS, "certificates"
    )
    normalized_paths: dict[str, str] = {}
    for field in sorted(CERTIFICATE_FIELDS):
        path = _require_path(certificates[field], f"certificates.{field}")
        normalized = _normalized_path_identity(path, f"certificates.{field}")
        if normalized in normalized_paths:
            raise ProfileError(
                f"certificates.{field} must not reuse the path from "
                f"certificates.{normalized_paths[normalized]}"
            )
        normalized_paths[normalized] = field

    # Return a deep copy so callers never confuse validation with permission to
    # mutate the source object behind a subsequent digest/evidence check.
    return copy.deepcopy(profile)


def validate_render_profile(raw: object) -> dict[str, Any]:
    """Validate production rendering and canonicalize every credential path."""

    profile = validate_profile(raw)
    certificates = profile["certificates"]
    file_identities: dict[tuple[int, int], str] = {}
    for field in sorted(CERTIFICATE_FIELDS):
        path = Path(certificates[field])
        if not path.is_absolute():
            raise ProfileError(
                f"certificates.{field} must be an absolute production path"
            )
        normalized = _normalized_path_identity(str(path), f"certificates.{field}")
        try:
            metadata = Path(normalized).stat()
        except OSError as error:
            raise ProfileError(
                f"certificates.{field} must exist for production rendering: {error}"
            ) from error
        if not stat.S_ISREG(metadata.st_mode):
            raise ProfileError(f"certificates.{field} must name a regular file")
        if field in PRIVATE_KEY_FIELDS and os.name == "posix":
            mode = stat.S_IMODE(metadata.st_mode)
            if mode & 0o077 or not mode & 0o400 or mode & 0o100:
                raise ProfileError(
                    f"certificates.{field} must be owner-readable, non-executable, "
                    "and deny all group/world permissions"
                )
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in file_identities:
            raise ProfileError(
                f"certificates.{field} aliases certificates."
                f"{file_identities[identity]}"
            )
        file_identities[identity] = field
        certificates[field] = normalized
    return validate_profile(profile)


def _routes(profile: dict[str, Any]) -> tuple[str, str]:
    prefix = f'{profile["realm"]}/session/{profile["epoch"]}/sensor'
    return f"{prefix}/galadriel-pid", f"{prefix}/galadriel-monitor"


def _handoff(profile: dict[str, Any]) -> dict[str, str]:
    return {
        "profile_version": profile["profile_version"],
        "realm": profile["realm"],
        "epoch": profile["epoch"],
        "producer_id": profile["producer_id"],
        "registry_canonical_sha256": profile["registry_canonical_sha256"],
        "producer_cert_common_name": profile["producer_cert_common_name"],
        "observer_cert_common_name": profile["observer_cert_common_name"],
    }


def render_handoff(raw: object) -> dict[str, str]:
    """Render the nonsecret application/transport identity handoff."""

    return _handoff(validate_profile(raw))


def _discovery_off() -> dict[str, Any]:
    return {
        "multicast": {"enabled": False},
        "gossip": {"enabled": False},
    }


def _client(profile: dict[str, Any], role: str) -> dict[str, Any]:
    certificates = profile["certificates"]
    return {
        "mode": "client",
        "connect": {
            "endpoints": [profile["router_connect_endpoint"]],
            "exit_on_failure": True,
        },
        "listen": {"endpoints": []},
        "scouting": _discovery_off(),
        "transport": {
            "link": {
                "rx": {"max_message_size": profile["transport_max_message_bytes"]},
                "tls": {
                    "root_ca_certificate": certificates["root_ca_certificate"],
                    "connect_private_key": certificates[f"{role}_private_key"],
                    "connect_certificate": certificates[f"{role}_certificate"],
                    # Zenoh 1.9 only loads and presents the configured client
                    # certificate when enable_mtls is true on the connector too.
                    # The listener's setting alone merely requires a certificate;
                    # omitting this client flag makes every generated connection
                    # fail with CertificateRequired.
                    "enable_mtls": True,
                    "verify_name_on_connect": True,
                    "close_link_on_expiration": True,
                },
            }
        },
    }


def render_profile(raw: object) -> dict[str, dict[str, Any]]:
    """Render one router and two least-privilege client configurations."""

    profile = validate_profile(raw)
    pid_route, monitor_route = _routes(profile)
    certificates = profile["certificates"]
    router = {
        "mode": "router",
        "connect": {"endpoints": []},
        "listen": {
            "endpoints": [profile["router_listen_endpoint"]],
            "exit_on_failure": True,
        },
        "scouting": _discovery_off(),
        "transport": {
            "link": {
                "rx": {"max_message_size": profile["transport_max_message_bytes"]},
                "tls": {
                    "root_ca_certificate": certificates["root_ca_certificate"],
                    "listen_private_key": certificates["router_private_key"],
                    "listen_certificate": certificates["router_certificate"],
                    "enable_mtls": True,
                    "close_link_on_expiration": True,
                },
            }
        },
        "access_control": {
            "enabled": True,
            "default_permission": "deny",
            "rules": [
                {
                    "id": "galadriel-producer-put-ingress",
                    "messages": ["put"],
                    "flows": ["ingress"],
                    "permission": "allow",
                    "key_exprs": [pid_route, monitor_route],
                },
                {
                    "id": "galadriel-observer-put-egress",
                    "messages": ["put"],
                    "flows": ["egress"],
                    "permission": "allow",
                    "key_exprs": [pid_route, monitor_route],
                },
                {
                    "id": "galadriel-observer-subscribe-ingress",
                    "messages": ["declare_subscriber"],
                    "flows": ["ingress"],
                    "permission": "allow",
                    "key_exprs": [pid_route, monitor_route],
                },
            ],
            "subjects": [
                {
                    "id": "galadriel-producer",
                    "cert_common_names": [profile["producer_cert_common_name"]],
                },
                {
                    "id": "galadriel-observer",
                    "cert_common_names": [profile["observer_cert_common_name"]],
                },
            ],
            "policies": [
                {
                    "rules": ["galadriel-producer-put-ingress"],
                    "subjects": ["galadriel-producer"],
                },
                {
                    "rules": [
                        "galadriel-observer-put-egress",
                        "galadriel-observer-subscribe-ingress",
                    ],
                    "subjects": ["galadriel-observer"],
                },
            ],
        },
    }
    return {
        "router": router,
        "producer": _client(profile, "producer"),
        "observer": _client(profile, "observer"),
    }


def _nested(value: object, *path: str) -> object:
    for part in path:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def check_rendered(raw_profile: object, rendered: object) -> list[str]:
    """Independently check the security invariants of rendered configurations."""

    errors: list[str] = []
    try:
        profile = validate_profile(raw_profile)
    except ProfileError as error:
        return [str(error)]
    if not isinstance(rendered, dict) or set(rendered) != set(OUTPUT_NAMES):
        return ["rendered output must contain exactly router, producer, and observer"]
    router = rendered["router"]
    producer = rendered["producer"]
    observer = rendered["observer"]
    if not all(isinstance(item, dict) for item in (router, producer, observer)):
        return ["every rendered output must be an object"]

    pid_route, monitor_route = _routes(profile)
    allowed_routes = [pid_route, monitor_route]
    certificates = profile["certificates"]

    if router.get("mode") != "router":
        errors.append("router mode must be router")
    if _nested(router, "connect", "endpoints") != []:
        errors.append("router must not connect to an upstream endpoint")
    if _nested(router, "listen", "endpoints") != [profile["router_listen_endpoint"]]:
        errors.append("router must listen on exactly the profiled TLS endpoint")
    if _nested(router, "listen", "exit_on_failure") is not True:
        errors.append("router listener must fail closed")

    for name, config in (("router", router), ("producer", producer), ("observer", observer)):
        if _nested(config, "scouting", "multicast", "enabled") is not False:
            errors.append(f"{name} multicast discovery must be disabled")
        if _nested(config, "scouting", "gossip", "enabled") is not False:
            errors.append(f"{name} gossip discovery must be disabled")
        if _nested(config, "transport", "link", "rx", "max_message_size") != TRANSPORT_MAX_MESSAGE_BYTES:
            errors.append(f"{name} receive message maximum must be {TRANSPORT_MAX_MESSAGE_BYTES}")

    router_tls = _nested(router, "transport", "link", "tls")
    if not isinstance(router_tls, dict):
        errors.append("router TLS settings are missing")
    else:
        expected_router_tls = {
            "root_ca_certificate": certificates["root_ca_certificate"],
            "listen_private_key": certificates["router_private_key"],
            "listen_certificate": certificates["router_certificate"],
            "enable_mtls": True,
            "close_link_on_expiration": True,
        }
        if router_tls != expected_router_tls:
            errors.append("router TLS settings differ from the strict mTLS profile")

    access = router.get("access_control")
    if not isinstance(access, dict):
        errors.append("router access_control is missing")
    else:
        if access.get("enabled") is not True or access.get("default_permission") != "deny":
            errors.append("router ACL must be enabled and default-deny")
        rules = access.get("rules")
        expected_rules = {
            "galadriel-producer-put-ingress": (["put"], ["ingress"]),
            "galadriel-observer-put-egress": (["put"], ["egress"]),
            "galadriel-observer-subscribe-ingress": (
                ["declare_subscriber"],
                ["ingress"],
            ),
        }
        if not isinstance(rules, list) or {rule.get("id") for rule in rules if isinstance(rule, dict)} != set(expected_rules):
            errors.append("router must contain exactly the three directional Galadriel ACL rules")
            rules = []
        policies = access.get("policies")
        subjects = access.get("subjects")
        expected_subjects = {
            "galadriel-producer": [profile["producer_cert_common_name"]],
            "galadriel-observer": [profile["observer_cert_common_name"]],
        }
        if not isinstance(subjects, list) or {
            subject.get("id"): subject.get("cert_common_names")
            for subject in subjects
            if isinstance(subject, dict)
        } != expected_subjects:
            errors.append("router subjects must map the two exact, distinct certificate CNs")
        expected_policies = [
            {
                "rules": ["galadriel-producer-put-ingress"],
                "subjects": ["galadriel-producer"],
            },
            {
                "rules": [
                    "galadriel-observer-put-egress",
                    "galadriel-observer-subscribe-ingress",
                ],
                "subjects": ["galadriel-observer"],
            },
        ]
        if policies != expected_policies:
            errors.append("router policies must bind each rule to only its intended subject")
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("id") not in expected_rules:
                continue
            expected_messages, expected_flows = expected_rules[rule["id"]]
            if rule.get("messages") != expected_messages:
                errors.append(f'{rule["id"]} has an unauthorized message verb')
            if rule.get("flows") != expected_flows:
                errors.append(f'{rule["id"]} has an unauthorized message flow')
            if rule.get("permission") != "allow":
                errors.append(f'{rule["id"]} must be an explicit allow rule')
            if rule.get("key_exprs") != allowed_routes:
                errors.append(f'{rule["id"]} must name only the two exact epoch routes')

    for role, config in (("producer", producer), ("observer", observer)):
        if config.get("mode") != "client":
            errors.append(f"{role} must use client mode")
        if _nested(config, "connect", "endpoints") != [profile["router_connect_endpoint"]]:
            errors.append(f"{role} must connect to exactly the profiled TLS router")
        if _nested(config, "connect", "exit_on_failure") is not True:
            errors.append(f"{role} connect must fail closed")
        if _nested(config, "listen", "endpoints") != []:
            errors.append(f"{role} must not listen")
        tls = _nested(config, "transport", "link", "tls")
        expected_tls = {
            "root_ca_certificate": certificates["root_ca_certificate"],
            "connect_private_key": certificates[f"{role}_private_key"],
            "connect_certificate": certificates[f"{role}_certificate"],
            "enable_mtls": True,
            "verify_name_on_connect": True,
            "close_link_on_expiration": True,
        }
        if tls != expected_tls:
            errors.append(f"{role} TLS settings differ from the strict mTLS profile")

    return errors


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _target_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _atomic_write(path: Path, payload: bytes, *, force: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
    except OSError as error:
        raise ProfileError(f"cannot stage {path}: {error}") from error
    temporary = Path(temporary_name)
    try:
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            if force:
                os.replace(temporary, path)
            else:
                try:
                    # Publishing a same-directory hard link is an atomic
                    # create-if-absent operation. Unlike rename/replace, it
                    # cannot overwrite a target created after preflight.
                    os.link(temporary, path, follow_symlinks=False)
                except FileExistsError as error:
                    raise ProfileError(
                        f"refusing to replace {path}; pass --force"
                    ) from error
        except OSError as error:
            raise ProfileError(f"cannot atomically write {path}: {error}") from error
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            # The primary write/replace outcome is authoritative. A private output
            # directory plus the dot-prefixed random name keeps a rare cleanup
            # failure from exposing credentials as a named deployment artifact.
            pass


def write_rendered(raw_profile: object, output_dir: Path, *, force: bool) -> dict[str, str]:
    profile = validate_render_profile(raw_profile)
    rendered = render_profile(profile)
    errors = check_rendered(profile, rendered)
    if errors:
        raise ProfileError("renderer produced invalid output: " + "; ".join(errors))
    payloads = {
        filename: _json_bytes(rendered[role])
        for role, filename in OUTPUT_NAMES.items()
    }
    payloads[HANDOFF_NAME] = _json_bytes(_handoff(profile))
    digests = {
        filename: hashlib.sha256(payload).hexdigest()
        for filename, payload in payloads.items()
    }
    manifest = "".join(
        f"{digest}  {filename}\n" for filename, digest in sorted(digests.items())
    )
    all_payloads = {**payloads, MANIFEST_NAME: manifest.encode("ascii")}

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ProfileError(f"cannot create output directory {output_dir}: {error}") from error
    if not force:
        conflicts = sorted(
            str(output_dir / filename)
            for filename in all_payloads
            if _target_exists(output_dir / filename)
        )
        if conflicts:
            raise ProfileError(
                "refusing to render because output targets already exist; pass --force: "
                + ", ".join(conflicts)
            )

    # The complete target set is preflighted above. Each replacement is atomic,
    # but the directory itself is intentionally not claimed to be transactional.
    # Operators verify SHA256SUMS before starting any process.
    for filename, payload in sorted(payloads.items()):
        _atomic_write(output_dir / filename, payload, force=force)
    # Publish the checksum manifest last so an interrupted forced refresh leaves
    # either the old manifest (which will fail against a mixed set) or the final
    # manifest for the fully written artifacts.
    _atomic_write(output_dir / MANIFEST_NAME, all_payloads[MANIFEST_NAME], force=force)
    return digests


def _load_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise ProfileError(f"cannot load {path}: {error}") from error


def _load_reference() -> dict[str, object]:
    return {
        role: _load_json(REFERENCE_DIR / filename)
        for role, filename in OUTPUT_NAMES.items()
    }


def _load_reference_handoff() -> dict[str, Any]:
    handoff = _load_json(REFERENCE_DIR / HANDOFF_NAME)
    return _require_exact_fields(handoff, HANDOFF_FIELDS, "reference handoff")


def _assert_mutation_rejected(
    profile: dict[str, Any], rendered: dict[str, dict[str, Any]], mutate, label: str
) -> None:
    candidate = copy.deepcopy(rendered)
    mutate(candidate)
    if not check_rendered(profile, candidate):
        raise ProfileError(f"mutation guard failed open: {label}")


def run_mutation_checks(profile: dict[str, Any], rendered: dict[str, dict[str, Any]]) -> int:
    """Exercise authorization, parsing, handoff, and output-integrity regressions."""

    mutations = [
        ("default allow", lambda c: c["router"]["access_control"].update(default_permission="allow")),
        ("ACL disabled", lambda c: c["router"]["access_control"].update(enabled=False)),
        (
            "producer sensor wildcard",
            lambda c: c["router"]["access_control"]["rules"][0]["key_exprs"].__setitem__(
                0, f'{profile["realm"]}/session/*/sensor/**'
            ),
        ),
        (
            "producer command grant",
            lambda c: c["router"]["access_control"]["rules"][0]["key_exprs"].append(
                f'{profile["realm"]}/session/{profile["epoch"]}/command/**'
            ),
        ),
        (
            "producer delete grant",
            lambda c: c["router"]["access_control"]["rules"][0]["messages"].append("delete"),
        ),
        (
            "producer publication egress grant",
            lambda c: c["router"]["access_control"]["rules"][0]["flows"].append("egress"),
        ),
        (
            "observer publication ingress grant",
            lambda c: c["router"]["access_control"]["rules"][1]["flows"].append("ingress"),
        ),
        (
            "observer write grant",
            lambda c: c["router"]["access_control"]["rules"][2]["messages"].append("put"),
        ),
        (
            "observer RPC grant",
            lambda c: c["router"]["access_control"]["rules"][2]["key_exprs"].append(
                f'{profile["realm"]}/rpc/*'
            ),
        ),
        (
            "shared certificate CN",
            lambda c: c["router"]["access_control"]["subjects"][1][
                "cert_common_names"
            ].__setitem__(0, profile["producer_cert_common_name"]),
        ),
        (
            "cross-bound policy",
            lambda c: c["router"]["access_control"]["policies"][0]["subjects"].append(
                "galadriel-observer"
            ),
        ),
        (
            "plaintext router listener",
            lambda c: c["router"]["listen"]["endpoints"].__setitem__(0, "tcp/0.0.0.0:7447"),
        ),
        (
            "mTLS disabled",
            lambda c: c["router"]["transport"]["link"]["tls"].update(enable_mtls=False),
        ),
        (
            "router discovery enabled",
            lambda c: c["router"]["scouting"]["multicast"].update(enabled=True),
        ),
        (
            "oversized router receive limit",
            lambda c: c["router"]["transport"]["link"]["rx"].update(
                max_message_size=1_073_741_824
            ),
        ),
        (
            "observer hostname verification disabled",
            lambda c: c["observer"]["transport"]["link"]["tls"].update(
                verify_name_on_connect=False
            ),
        ),
        (
            "observer mTLS disabled",
            lambda c: c["observer"]["transport"]["link"]["tls"].update(
                enable_mtls=False
            ),
        ),
        (
            "observer listener enabled",
            lambda c: c["observer"]["listen"]["endpoints"].append("tls/0.0.0.0:7448"),
        ),
        (
            "producer discovery enabled",
            lambda c: c["producer"]["scouting"]["gossip"].update(enabled=True),
        ),
    ]
    for label, mutation in mutations:
        _assert_mutation_rejected(profile, rendered, mutation, label)

    invalid_profiles = [
        ("wildcard epoch", lambda p: p.update(epoch="*")),
        ("wildcard producer", lambda p: p.update(producer_id="crebain-*")),
        ("shared CN", lambda p: p.update(observer_cert_common_name=p["producer_cert_common_name"])),
        ("plaintext connect", lambda p: p.update(router_connect_endpoint="tcp/router:7447")),
        (
            "invalid connect port",
            lambda p: p.update(router_connect_endpoint="tls/router:notaport"),
        ),
        (
            "endpoint-local TLS override",
            lambda p: p.update(
                router_connect_endpoint=(
                    "tls/router:7447#verify_name_on_connect=false"
                )
            ),
        ),
        (
            "endpoint-local transport metadata",
            lambda p: p.update(router_connect_endpoint="tls/router:7447?rel=0"),
        ),
        ("loose receive cap", lambda p: p.update(transport_max_message_bytes=1_073_741_824)),
        ("uppercase registry digest", lambda p: p.update(registry_canonical_sha256="A" * 64)),
        (
            "inline key bytes",
            lambda p: p["certificates"].update(
                producer_private_key="-----BEGIN PRIVATE KEY----- secret"
            ),
        ),
        (
            "shared role private-key path",
            lambda p: p["certificates"].update(
                observer_private_key=p["certificates"]["producer_private_key"]
            ),
        ),
    ]
    for label, mutation in invalid_profiles:
        candidate = copy.deepcopy(profile)
        mutation(candidate)
        try:
            validate_profile(candidate)
        except ProfileError:
            continue
        raise ProfileError(f"profile mutation guard failed open: {label}")

    endpoint_corpus = _require_exact_fields(
        _load_json(ENDPOINT_CORPUS), {"valid", "invalid"}, "endpoint corpus"
    )
    for classification in ["valid", "invalid"]:
        values = endpoint_corpus[classification]
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) for value in values
        ):
            raise ProfileError(f"endpoint corpus {classification} set must be non-empty strings")
        if len(values) != len(set(values)):
            raise ProfileError(f"endpoint corpus {classification} set contains duplicates")
    for endpoint in endpoint_corpus["valid"]:
        candidate = copy.deepcopy(profile)
        candidate["router_connect_endpoint"] = endpoint
        validate_profile(candidate)
    for endpoint in endpoint_corpus["invalid"]:
        candidate = copy.deepcopy(profile)
        candidate["router_connect_endpoint"] = endpoint
        try:
            validate_profile(candidate)
        except ProfileError:
            continue
        raise ProfileError(f"shared invalid endpoint passed profile validation: {endpoint!r}")

    production_profile = copy.deepcopy(profile)
    private_key_fixtures = [
        tempfile.NamedTemporaryFile(prefix="galadriel-private-key-")
        for _ in sorted(PRIVATE_KEY_FIELDS)
    ]
    for fixture in private_key_fixtures:
        fixture.write(b"private key fixture")
        fixture.flush()
        os.chmod(fixture.name, 0o600)
    production_path_fixtures = {
        "root_ca_certificate": DEFAULT_PROFILE,
        "router_certificate": Path(__file__).resolve(),
        "producer_certificate": REFERENCE_DIR / HANDOFF_NAME,
        "observer_certificate": REFERENCE_DIR / MANIFEST_NAME,
        **{
            field: Path(fixture.name)
            for field, fixture in zip(
                sorted(PRIVATE_KEY_FIELDS), private_key_fixtures, strict=True
            )
        },
    }
    for field, path in production_path_fixtures.items():
        production_profile["certificates"][field] = str(path.resolve())
    validate_render_profile(production_profile)
    invalid_render_paths = [
        (
            "relative production credential path",
            lambda p: p["certificates"].update(root_ca_certificate="ca.pem"),
        ),
        (
            "unprefixed base64 credential material",
            lambda p: p["certificates"].update(
                producer_private_key="c2VjcmV0LXByaXZhdGUta2V5"
            ),
        ),
    ]
    for label, mutation in invalid_render_paths:
        candidate = copy.deepcopy(production_profile)
        mutation(candidate)
        try:
            validate_render_profile(candidate)
        except ProfileError:
            continue
        raise ProfileError(f"render-path mutation guard failed open: {label}")

    with tempfile.TemporaryDirectory(prefix="galadriel-secure-alias-") as directory:
        original = Path(directory) / "original.pem"
        alias = Path(directory) / "alias.pem"
        original.write_bytes(b"credential fixture")
        os.link(original, alias)
        aliased = copy.deepcopy(production_profile)
        aliased["certificates"]["producer_private_key"] = str(original)
        aliased["certificates"]["observer_private_key"] = str(alias)
        try:
            validate_render_profile(aliased)
        except ProfileError:
            pass
        else:
            raise ProfileError("hard-linked credential alias guard failed open")

    if os.name == "posix":
        exposed_key = Path(production_profile["certificates"]["producer_private_key"])
        os.chmod(exposed_key, 0o644)
        try:
            try:
                validate_render_profile(production_profile)
            except ProfileError:
                pass
            else:
                raise ProfileError("group/world-readable private-key guard failed open")
        finally:
            os.chmod(exposed_key, 0o600)

    baseline_handoff = _json_bytes(_handoff(profile))
    alternate_producer = (
        "galadriel-handoff-producer"
        if profile["producer_id"] != "galadriel-handoff-producer"
        else "galadriel-handoff-producer-2"
    )
    digest = profile["registry_canonical_sha256"]
    alternate_digest = ("0" if digest[0] != "0" else "1") + digest[1:]
    handoff_mutations = [
        ("different valid producer", lambda p: p.update(producer_id=alternate_producer)),
        (
            "different valid registry digest",
            lambda p: p.update(registry_canonical_sha256=alternate_digest),
        ),
    ]
    for label, mutation in handoff_mutations:
        candidate = copy.deepcopy(profile)
        mutation(candidate)
        candidate = validate_profile(candidate)
        if _json_bytes(_handoff(candidate)) == baseline_handoff:
            raise ProfileError(f"handoff mutation guard failed open: {label}")

    try:
        json.loads(
            '{"outer":{"identity":"first","identity":"second"}}',
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except DuplicateJsonKeyError:
        pass
    else:
        raise ProfileError("duplicate JSON key guard failed open")

    with tempfile.TemporaryDirectory(prefix="galadriel-secure-preflight-") as directory:
        output_dir = Path(directory)
        conflict = output_dir / OUTPUT_NAMES["producer"]
        conflict.write_bytes(b"sentinel")
        try:
            write_rendered(production_profile, output_dir, force=False)
        except ProfileError:
            pass
        else:
            raise ProfileError("output-conflict preflight guard failed open")
        if sorted(path.name for path in output_dir.iterdir()) != [conflict.name]:
            raise ProfileError("output-conflict preflight left a partial rendered set")
        if conflict.read_bytes() != b"sentinel":
            raise ProfileError("output-conflict preflight replaced an existing target")

    with tempfile.TemporaryDirectory(prefix="galadriel-secure-no-replace-") as directory:
        target = Path(directory) / "concurrent-target.json5"
        target.write_bytes(b"concurrent creator")
        try:
            _atomic_write(target, b"replacement", force=False)
        except ProfileError:
            pass
        else:
            raise ProfileError("atomic no-replace guard failed open")
        if target.read_bytes() != b"concurrent creator":
            raise ProfileError("atomic no-replace guard overwrote a concurrent target")

    for fixture in private_key_fixtures:
        fixture.close()

    return (
        len(mutations)
        + len(invalid_profiles)
        + len(endpoint_corpus["valid"])
        + len(endpoint_corpus["invalid"])
        + len(invalid_render_paths)
        + len(handoff_mutations)
        + 5
    )


def check_reference(profile_path: Path) -> tuple[dict[str, str], int]:
    raw_profile = _load_json(profile_path)
    profile = validate_profile(raw_profile)
    expected = render_profile(profile)
    actual = _load_reference()
    if actual != expected:
        raise ProfileError(
            "committed reference configs drifted; render them again and review the security diff"
        )
    errors = check_rendered(profile, actual)
    if errors:
        raise ProfileError("reference configuration is unsafe: " + "; ".join(errors))
    if _load_reference_handoff() != _handoff(profile):
        raise ProfileError(
            "committed application handoff drifted from the exact deployment profile"
        )
    mutations = run_mutation_checks(profile, expected)

    digests = {
        filename: hashlib.sha256((REFERENCE_DIR / filename).read_bytes()).hexdigest()
        for filename in [*OUTPUT_NAMES.values(), HANDOFF_NAME]
    }
    expected_manifest = "".join(
        f"{digest}  {filename}\n" for filename, digest in sorted(digests.items())
    )
    try:
        actual_manifest = (REFERENCE_DIR / MANIFEST_NAME).read_text(encoding="ascii")
    except OSError as error:
        raise ProfileError(f"cannot read reference digest manifest: {error}") from error
    if actual_manifest != expected_manifest:
        raise ProfileError("reference SHA256SUMS does not match the committed artifacts")
    return digests, mutations


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="verify committed references and mutations")
    check_parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)

    render_parser = subparsers.add_parser("render", help="render a deployment profile")
    render_parser.add_argument("--profile", type=Path, required=True)
    render_parser.add_argument("--output-dir", type=Path, required=True)
    render_parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    try:
        if args.command == "check":
            digests, mutations = check_reference(args.profile)
            for filename, digest in sorted(digests.items()):
                print(f"{digest}  {filename}")
            print(f"secure deployment profile: PASS ({mutations} security regression checks)")
            return 0

        raw_profile = _load_json(args.profile)
        digests = write_rendered(raw_profile, args.output_dir, force=args.force)
        for filename, digest in sorted(digests.items()):
            print(f"{digest}  {filename}")
        return 0
    except ProfileError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
