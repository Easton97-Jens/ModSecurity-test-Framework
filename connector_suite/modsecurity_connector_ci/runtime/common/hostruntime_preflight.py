#!/usr/bin/env python3
"""Run a bounded, read-only host-runtime preflight.

The command deliberately never installs packages, changes the environment, or
starts a service.  It emits one machine-readable result and one short summary
for workflow artifact collection.  A result is PASS only when the required
identity checks and every requested prerequisite have concrete evidence.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse




from modsecurity_connector_ci.lib.runtime_path_utils import is_read_only_source_path, is_under, prepare_verified_runtime_artifact_root, read_runtime_artifact_text, runtime_artifact_path, runtime_or_source_artifact_path, verified_runtime_artifact_root, write_runtime_artifact_text_atomic


STATUSES = {"PASS", "FAIL", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE"}
MAX_TEXT = 240
MAX_CHECKS = 64
DEFAULT_TIMEOUT = 5.0
MAX_TIMEOUT = 60.0
LOCK_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
SAFE_BINARY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
SAFE_LOCK_PROVENANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
NO_ACTION_REQUIRED = "No action required."
RUNTIME_LOCK_INVALID = "runtime_lock_invalid"
RUNTIME_LOCK_LABEL = "runtime lock"
SAFE_COMMAND_ENV = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
SYSTEM_BINARY_ROOTS = tuple(
    Path(path).resolve(strict=False) for path in ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
)
LDD_PATH = Path("/usr/bin/ldd")


def _bounded(value: object, limit: int = MAX_TEXT) -> str:
    text = str(value).replace("\x00", "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _safe_name(value: str) -> str:
    return Path(value).name or "unknown"


def _check(name: str, status: str, reason: str, remediation: str) -> dict[str, str]:
    if status not in STATUSES:
        raise ValueError(f"invalid status: {status}")
    return {
        "name": _bounded(name, 80),
        "status": status,
        "reason_code": _bounded(reason, 100),
        "remediation": _bounded(remediation),
    }


def _run(argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=SAFE_COMMAND_ENV,
        )
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except OSError as exc:
        return 126, "", _bounded(exc)
    return result.returncode, _bounded(result.stdout), _bounded(result.stderr)


def _is_below_any(path: Path, roots: Sequence[Path]) -> bool:
    return any(path == root or is_under(path, root) for root in roots)


def _validated_binary_root(value: Path | None) -> Path | None:
    if value is None:
        return None
    if not value.is_absolute() or not value.is_dir():
        raise ValueError("binary root must be an existing private runtime directory")
    return verified_runtime_artifact_root(value)


def _trusted_binary(value: Path, runtime_root: Path, binary_root: Path | None) -> tuple[Path | None, str | None]:
    if not value.is_absolute() or not SAFE_BINARY_NAME.fullmatch(value.name):
        return None, "binary_path_untrusted"
    roots = [runtime_root, *SYSTEM_BINARY_ROOTS]
    if binary_root is not None:
        roots.append(binary_root)
    lexical = Path(os.path.abspath(value))
    if not _is_below_any(lexical, roots):
        return None, "binary_path_untrusted"
    if not lexical.is_file():
        return lexical, "binary_missing"
    try:
        resolved = lexical.resolve(strict=True)
    except OSError:
        return None, "binary_path_untrusted"
    if not _is_below_any(resolved, roots):
        return None, "binary_path_untrusted"
    if not os.access(resolved, os.X_OK):
        return resolved, "binary_not_executable"
    return resolved, None


def _parse_pair(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected NAME=VALUE")
    name, expected = value.split("=", 1)
    if not name or not expected:
        raise argparse.ArgumentTypeError("expected non-empty NAME=VALUE")
    return name, expected


def _bounded_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be numeric") from exc
    if not 0 < timeout <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(f"timeout must be between 0 and {MAX_TIMEOUT:g} seconds")
    return timeout


def _normal_os(value: str) -> str:
    return value.lower().replace("linux", "linux").replace("darwin", "macos")


def _normal_arch(value: str) -> str:
    aliases = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    return aliases.get(value.lower(), value.lower())


def _lock_result(profile: str, reason: str) -> tuple[dict[str, str], str, str, dict[str, list[Any]]]:
    return {"lock_profile": _bounded(profile, 120)}, "", reason, {}


def _lock_document(path: Path, artifact_root: Path | None) -> dict[str, Any] | None:
    try:
        if artifact_root is None:
            text = path.read_text(encoding="utf-8")
        else:
            text = read_runtime_artifact_text(artifact_root, path, RUNTIME_LOCK_LABEL)
        document = json.loads(text)
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def _lock_entry(document: dict[str, Any], profile: str) -> dict[str, Any] | None:
    profiles = document.get("profiles")
    if document.get("schema_version") != 1 or not isinstance(profiles, list) or len(profiles) > MAX_CHECKS:
        return None
    entry = next((item for item in profiles if isinstance(item, dict) and item.get("id") == profile), None)
    return entry if isinstance(entry, dict) else None


def _valid_lock_identity(entry: dict[str, Any]) -> bool:
    required = ("os", "arch", "version", "sha256", "asset_name", "download_url", "source_provenance")
    if any(not isinstance(entry.get(key), str) or not entry[key] for key in required):
        return False
    asset = entry["asset_name"]
    if Path(asset).name != asset or asset in {".", ".."} or not LOCK_SHA256.fullmatch(entry["sha256"]):
        return False
    url = entry["download_url"]
    parsed_url = urlparse(url)
    return (
        parsed_url.scheme == "https"
        and bool(parsed_url.hostname)
        and "\n" not in url
        and "\r" not in url
        and bool(SAFE_LOCK_PROVENANCE.fullmatch(entry["source_provenance"]))
    )


def _lock_metadata(path: Path, profile: str, entry: dict[str, Any]) -> dict[str, str]:
    return {
        "name": _safe_name(str(path)),
        "lock_profile": _bounded(profile, 120),
        "expected_version": _bounded(entry["version"], 80),
        "provenance": _bounded(entry["source_provenance"]),
        "asset_id": _bounded(entry["asset_name"], 120),
    }


def _normalized_requirements(entry: dict[str, Any]) -> dict[str, list[Any]] | None:
    requirements = entry.get("requirements", {})
    if not isinstance(requirements, dict):
        return None
    normalized: dict[str, list[Any]] = {}
    for key in ("headers", "sources", "tools", "configs", "fixtures", "ports"):
        values = requirements.get(key, [])
        if not isinstance(values, list) or len(values) > MAX_CHECKS:
            return None
        if key == "ports":
            valid = all(isinstance(value, int) for value in values)
        else:
            valid = all(isinstance(value, str) and value and "\n" not in value for value in values)
        if not valid:
            return None
        normalized[key] = values
    return normalized


def _load_runtime_lock(
    path: Path,
    profile: str,
    expected_os: str,
    expected_arch: str,
    artifact_root: Path | None,
) -> tuple[dict[str, str], str, str, dict[str, list[Any]]]:
    """Return safe lock metadata, expected version, and a stable error code."""
    if not path.is_file():
        return {}, "", "runtime_lock_missing", {}
    document = _lock_document(path, artifact_root)
    if document is None:
        return {}, "", RUNTIME_LOCK_INVALID, {}
    entry = _lock_entry(document, profile)
    if entry is None or not _valid_lock_identity(entry):
        return _lock_result(profile, RUNTIME_LOCK_INVALID)
    metadata = _lock_metadata(path, profile, entry)
    platform_matches = (
        _normal_os(entry["os"]) == _normal_os(expected_os)
        and _normal_arch(entry["arch"]) == _normal_arch(expected_arch)
    )
    if not platform_matches:
        return metadata, "", "runtime_lock_platform_mismatch", {}
    requirements = _normalized_requirements(entry)
    if requirements is None:
        return metadata, "", RUNTIME_LOCK_INVALID, {}
    return metadata, entry["version"], "", requirements


def _output_paths(args: argparse.Namespace, runtime_root: Path) -> tuple[Path, Path]:
    if args.output is not None:
        target = runtime_artifact_path(runtime_root, args.output, "preflight status output")
        if target.name != "status.json":
            raise ValueError("preflight status output must be named status.json")
        return target.parent, target
    target = runtime_artifact_path(
        runtime_root,
        args.output_dir / "status.json",
        "preflight output directory",
    )
    return target.parent, target


def _write_result(runtime_root: Path, output_dir: Path, target: Path, result: dict[str, Any]) -> None:
    write_runtime_artifact_text_atomic(
        runtime_root,
        target,
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        "preflight status output",
    )
    lines = [
        "# Host-runtime preflight",
        "",
        f"- Connector: `{result['connector']}`",
        f"- Profile: `{result['profile']}`",
        f"- Status: **{result['status']}**",
        f"- Reason: `{result['reason_code']}`",
        f"- Remediation: {result['remediation']}",
        "",
        "| Check | Status | Reason |",
        "| --- | --- | --- |",
    ]
    for item in result["checks"]:
        lines.append(f"| `{item['name']}` | `{item['status']}` | `{item['reason_code']}` |")
    write_runtime_artifact_text_atomic(
        runtime_root,
        output_dir / "summary.md",
        "\n".join(lines) + "\n",
        "preflight summary output",
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--output", type=Path, help="status JSON path (workflow-compatible alias)")
    parser.add_argument("--expected-version", default="")
    parser.add_argument("--runtime-lock", type=Path)
    parser.add_argument("--runtime-lock-root", type=Path)
    parser.add_argument("--lock-profile")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--binary-root", type=Path)
    parser.add_argument("--expected-os", default="linux")
    parser.add_argument("--expected-arch", default="amd64")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--tool", action="append", default=[])
    parser.add_argument("--port", action="append", type=int, default=[])
    parser.add_argument("--write-dir", action="append", default=[])
    parser.add_argument("--disk-path", action="append", default=[])
    parser.add_argument("--min-free-bytes", type=int, default=0)
    parser.add_argument("--config", action="append", default=[])
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--timeout", type=_bounded_timeout, default=DEFAULT_TIMEOUT)
    return parser


def _parse_args(argv: list[str] | None) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    parser = _argument_parser()
    args = parser.parse_args(argv)
    if args.output_dir is None and args.output is None:
        parser.error("one of --output-dir or --output is required")
    if args.output_dir is not None and args.output is not None:
        parser.error("--output-dir and --output are mutually exclusive")
    return parser, args


def _approved_lock_path(args: argparse.Namespace, runtime_root: Path) -> tuple[Path, Path | None]:
    if args.runtime_lock_root is not None:
        lock_root = verified_runtime_artifact_root(args.runtime_lock_root)
        return runtime_artifact_path(lock_root, args.runtime_lock, RUNTIME_LOCK_LABEL), lock_root
    lock_path = runtime_or_source_artifact_path(runtime_root, args.runtime_lock, RUNTIME_LOCK_LABEL)
    artifact_root = None if is_read_only_source_path(lock_path) else runtime_root
    return lock_path, artifact_root


def _append_lock_check(
    args: argparse.Namespace,
    runtime_root: Path,
    checks: list[dict[str, str]],
) -> tuple[dict[str, str], str, dict[str, list[Any]]]:
    if args.runtime_lock is None:
        reason = "runtime_lock_missing" if args.lock_profile else ""
        if reason:
            checks.append(
                _check(
                    "runtime-lock",
                    "BLOCKED",
                    reason,
                    "Provide the reviewed runtime lock and rerun the preflight.",
                )
            )
        return {}, reason, {}

    profile = args.lock_profile or args.profile
    try:
        lock_path, lock_artifact_root = _approved_lock_path(args, runtime_root)
    except ValueError:
        metadata = {
            "name": _safe_name(str(args.runtime_lock)),
            "lock_profile": _bounded(profile, 120),
        }
        reason = "runtime_lock_untrusted"
        checks.append(
            _check(
                "runtime-lock",
                "BLOCKED",
                reason,
                "Provide a reviewed lock below an approved source or runtime root.",
            )
        )
        return metadata, reason, {}

    metadata, locked_version, reason, requirements = _load_runtime_lock(
        lock_path,
        profile,
        args.expected_os,
        args.expected_arch,
        lock_artifact_root,
    )
    if not reason:
        args.expected_version = locked_version
        checks.append(_check("runtime-lock", "PASS", "runtime_lock_valid", NO_ACTION_REQUIRED))
        return metadata, reason, requirements

    metadata.setdefault("name", _safe_name(str(lock_path)))
    metadata.setdefault("lock_profile", _bounded(profile, 120))
    checks.append(
        _check(
            "runtime-lock",
            "BLOCKED",
            reason,
            "Provide a valid reviewed runtime lock and rerun the preflight.",
        )
    )
    return metadata, reason, requirements


def _apply_lock_requirements(args: argparse.Namespace, requirements: dict[str, list[Any]]) -> None:
    args.header = requirements.get("headers", []) + args.header
    args.source = requirements.get("sources", []) + args.source
    args.tool = requirements.get("tools", []) + args.tool
    args.config = requirements.get("configs", []) + args.config
    args.fixture = requirements.get("fixtures", []) + args.fixture
    args.port = requirements.get("ports", []) + args.port


def _identity_check(name: str, actual: str, expected: str, remediation: str) -> dict[str, str]:
    if actual == expected:
        return _check(name, "PASS", name.replace("identity.", "") + "_match", remediation)
    return _check(name, "BLOCKED", name.replace("identity.", "") + "_mismatch", remediation)


def _append_identity_checks(args: argparse.Namespace, checks: list[dict[str, str]]) -> str:
    actual_os = _normal_os(platform.system())
    actual_arch = _normal_arch(platform.machine())
    checks.extend(
        (
            _identity_check(
                "identity.os",
                actual_os,
                _normal_os(args.expected_os),
                "Run on the reviewed operating system.",
            ),
            _identity_check(
                "identity.arch",
                actual_arch,
                _normal_arch(args.expected_arch),
                "Run on the reviewed CPU architecture.",
            ),
        )
    )
    return actual_arch


def _binary_remediation(reason: str) -> str:
    remediations = {
        "binary_missing": "Build or provision the expected executable below an approved binary root.",
        "binary_not_executable": "Make the expected binary executable.",
    }
    return remediations.get(reason, "Provide the expected executable below an approved binary root.")


def _append_version_check(
    expected: str,
    code: int,
    output: str,
    checks: list[dict[str, str]],
) -> None:
    if not expected:
        checks.append(
            _check(
                "version",
                "BLOCKED",
                "expected_version_missing",
                "Provide the reviewed runtime version.",
            )
        )
    elif code == 124:
        checks.append(
            _check(
                "version",
                "BLOCKED",
                "version_timeout",
                "Make the binary version probe responsive.",
            )
        )
    elif code == 127:
        checks.append(
            _check(
                "version",
                "BLOCKED",
                "version_probe_missing",
                "Provide a runnable binary.",
            )
        )
    elif expected not in output:
        checks.append(
            _check(
                "version",
                "BLOCKED",
                "version_mismatch",
                "Provision the reviewed runtime version.",
            )
        )
    else:
        checks.append(_check("version", "PASS", "version_match", NO_ACTION_REQUIRED))


def _approved_binary(args: argparse.Namespace, runtime_root: Path) -> tuple[Path | None, str | None]:
    if args.binary is None:
        return None, "binary_missing"
    try:
        return _trusted_binary(
            args.binary,
            runtime_root,
            _validated_binary_root(args.binary_root),
        )
    except ValueError:
        return None, "binary_path_untrusted"


def _append_binary_checks(
    args: argparse.Namespace,
    runtime_root: Path,
    checks: list[dict[str, str]],
) -> tuple[Path | None, str]:
    binary, reason = _approved_binary(args, runtime_root)
    if reason is not None:
        checks.append(_check("binary", "BLOCKED", reason, _binary_remediation(reason)))
        if not args.expected_version:
            checks.append(
                _check(
                    "version",
                    "BLOCKED",
                    "expected_version_missing",
                    "Provide the reviewed runtime version.",
                )
            )
        return None, ""

    if binary is None:
        checks.append(
            _check(
                "binary",
                "BLOCKED",
                "binary_path_untrusted",
                _binary_remediation("binary_path_untrusted"),
            )
        )
        return None, ""
    checks.append(_check("binary", "PASS", "binary_present", NO_ACTION_REQUIRED))
    code, stdout, stderr = _run((str(binary), "--version"), args.timeout)
    output = stdout + " " + stderr
    _append_version_check(args.expected_version, code, output, checks)
    match = re.search(r"\b\d+(?:\.\d+){1,3}\b", output)
    return binary, match.group(0) if match else "unknown"


def _append_dynamic_library_check(
    binary: Path | None,
    timeout: float,
    checks: list[dict[str, str]],
) -> None:
    if binary is None:
        checks.append(
            _check(
                "dynamic-libraries",
                "BLOCKED",
                "binary_unavailable",
                "Provide the expected executable first.",
            )
        )
        return
    if not LDD_PATH.is_file() or not os.access(LDD_PATH, os.X_OK):
        checks.append(
            _check(
                "dynamic-libraries",
                "BLOCKED",
                "ldd_missing",
                "Install or expose ldd for read-only verification.",
            )
        )
        return
    code, stdout, stderr = _run((str(LDD_PATH), str(binary)), timeout)
    output = stdout + " " + stderr
    if code == 124:
        checks.append(
            _check(
                "dynamic-libraries",
                "BLOCKED",
                "ldd_timeout",
                "Make dependency inspection responsive.",
            )
        )
    elif "not found" in output:
        checks.append(
            _check(
                "dynamic-libraries",
                "BLOCKED",
                "dynamic_library_missing",
                "Provision all binary runtime libraries.",
            )
        )
    elif code != 0:
        checks.append(
            _check(
                "dynamic-libraries",
                "BLOCKED",
                "ldd_failed",
                "Inspect the binary's dynamic dependencies.",
            )
        )
    else:
        checks.append(_check("dynamic-libraries", "PASS", "dynamic_libraries_resolved", NO_ACTION_REQUIRED))


def _append_path_checks(
    kind: str,
    values: list[str],
    checks: list[dict[str, str]],
    *,
    predicate: str = "file",
) -> None:
    for value in values[:MAX_CHECKS]:
        path = Path(value)
        exists = path.is_file() if predicate == "file" else path.exists()
        checks.append(
            _check(
                f"{kind}:{_safe_name(value)}",
                "PASS" if exists else "BLOCKED",
                f"{kind}_present" if exists else f"{kind}_missing",
                NO_ACTION_REQUIRED if exists else f"Provide the required {kind}.",
            )
        )


def _append_tool_checks(values: list[str], checks: list[dict[str, str]]) -> None:
    for tool in values[:MAX_CHECKS]:
        found = shutil.which(tool)
        checks.append(
            _check(
                f"tool:{_safe_name(tool)}",
                "PASS" if found else "BLOCKED",
                "tool_present" if found else "tool_missing",
                NO_ACTION_REQUIRED if found else "Expose the required host tool.",
            )
        )


def _port_check(port: int, timeout: float) -> tuple[str, str, str]:
    if not 1 <= port <= 65535:
        return "BLOCKED", "port_invalid", "Use a TCP port between 1 and 65535."
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        return "BLOCKED", "port_in_use", "Stop the conflicting listener or select a free port."
    finally:
        sock.close()
    return "PASS", "port_free", NO_ACTION_REQUIRED


def _append_port_checks(values: list[int], timeout: float, checks: list[dict[str, str]]) -> None:
    for port in values[:MAX_CHECKS]:
        status, reason, remediation = _port_check(port, timeout)
        checks.append(_check(f"port:{port}", status, reason, remediation))


def _append_write_checks(values: list[str], checks: list[dict[str, str]]) -> None:
    for value in values[:MAX_CHECKS]:
        path = Path(value)
        writable = path.is_dir() and os.access(path, os.W_OK)
        checks.append(
            _check(
                f"write:{_safe_name(value)}",
                "PASS" if writable else "BLOCKED",
                "write_available" if writable else "write_unavailable",
                NO_ACTION_REQUIRED if writable else "Provide a writable evidence/build directory.",
            )
        )


def _append_disk_checks(
    values: list[str],
    minimum: int,
    checks: list[dict[str, str]],
) -> None:
    for value in values[:MAX_CHECKS]:
        try:
            enough = shutil.disk_usage(value).free >= minimum
        except OSError:
            enough = False
        checks.append(
            _check(
                f"disk:{_safe_name(value)}",
                "PASS" if enough else "BLOCKED",
                "disk_sufficient" if enough else "disk_insufficient",
                NO_ACTION_REQUIRED if enough else "Provide sufficient free disk space.",
            )
        )


def _append_prerequisite_checks(args: argparse.Namespace, checks: list[dict[str, str]]) -> None:
    _append_path_checks("header", args.header, checks)
    _append_path_checks("source", args.source, checks, predicate="any")
    _append_path_checks("config", args.config, checks)
    _append_path_checks("fixture", args.fixture, checks, predicate="any")
    _append_tool_checks(args.tool, checks)
    _append_port_checks(args.port, args.timeout, checks)
    _append_write_checks(args.write_dir, checks)
    _append_disk_checks(args.disk_path, args.min_free_bytes, checks)


def _bounded_checks(checks: list[dict[str, str]]) -> list[dict[str, str]]:
    if len(checks) <= MAX_CHECKS:
        return checks
    return checks[:MAX_CHECKS] + [
        _check("checks", "BLOCKED", "check_limit_reached", "Reduce the preflight input set.")
    ]


def _final_status(checks: list[dict[str, str]], lock_reason: str) -> tuple[str, str, str]:
    statuses = {item["status"] for item in checks}
    if "BLOCKED" in statuses:
        return "BLOCKED", lock_reason or "prerequisite_missing", "Resolve blocked prerequisites and rerun the preflight."
    if "FAIL" in statuses:
        return "BLOCKED", "preflight_unclassified_mismatch", "Resolve the preflight mismatch and rerun before host integration."
    if not checks or "PASS" not in statuses:
        return "NOT_RUN", "insufficient_evidence", "Provide the required host-runtime evidence and rerun."
    return "PASS", "preflight_pass", NO_ACTION_REQUIRED


def _result_payload(
    args: argparse.Namespace,
    checks: list[dict[str, str]],
    actual_arch: str,
    metadata: dict[str, str],
    actual_version: str,
    status: str,
    reason: str,
    remediation: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": 1,
        "evidence_kind": "preflight",
        "runtime_status": "NOT_RUN",
        "connector": _bounded(args.connector or args.profile, 80),
        "profile": _bounded(args.profile, 120),
        "status": status,
        "reason_code": reason,
        "remediation": remediation,
        "observed_at": int(time.time()),
        "host": {"os": _normal_os(platform.system()), "arch": actual_arch},
        "checks": checks,
    }
    if args.runtime_lock is not None:
        metadata.setdefault("expected_version", _bounded(args.expected_version, 80))
        metadata["actual_version"] = _bounded(actual_version, 80)
        result["runtime_lock"] = metadata
        result["lock_profile"] = metadata.get("lock_profile", "")
        result["expected_version"] = metadata.get("expected_version", "")
        result["actual_version"] = metadata.get("actual_version", "")
        result["provenance"] = metadata.get("provenance", "")
        result["asset_id"] = metadata.get("asset_id", "")
    return result


def _exit_code(status: str) -> int:
    if status == "PASS":
        return 0
    if status == "BLOCKED":
        return 77
    return 1


def main(argv: list[str] | None = None) -> int:
    _, args = _parse_args(argv)
    try:
        runtime_root = prepare_verified_runtime_artifact_root(args.runtime_root)
        output_dir, output_file = _output_paths(args, runtime_root)
    except ValueError as exc:
        print(f"BLOCKED: hostruntime preflight: {exc}", file=sys.stderr)
        return 77

    checks: list[dict[str, str]] = []
    metadata, lock_reason, requirements = _append_lock_check(args, runtime_root, checks)
    _apply_lock_requirements(args, requirements)
    actual_arch = _append_identity_checks(args, checks)
    binary, actual_version = _append_binary_checks(args, runtime_root, checks)
    _append_dynamic_library_check(binary, args.timeout, checks)
    _append_prerequisite_checks(args, checks)
    checks = _bounded_checks(checks)
    status, reason, remediation = _final_status(checks, lock_reason)
    result = _result_payload(
        args,
        checks,
        actual_arch,
        metadata,
        actual_version,
        status,
        reason,
        remediation,
    )
    _write_result(runtime_root, output_dir, output_file, result)
    print(json.dumps(result, sort_keys=True))
    return _exit_code(status)


if __name__ == "__main__":
    sys.exit(main())
