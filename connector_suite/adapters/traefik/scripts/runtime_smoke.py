#!/usr/bin/env python3
"""Run a real Traefik -> forwardAuth service -> libmodsecurity smoke."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import contextlib
import http.server
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


class MissingDependency(RuntimeError):
    """A required local executable is absent before the smoke starts."""


RUNTIME_ROOT_ENVIRONMENTS = ("BUILD_ROOT", "CONNECTOR_COMPONENT_CACHE")
RESULT_FILE_NAME = "result.json"
SERVICE_CONFIG_FILE_NAME = "traefik-forwardauth.conf"
OBSERVER_MODULE = "github.com/Easton97-Jens/ModSecurity-conector/connectors/traefik/response_observer"
FORWARDAUTH_P2_BODY_LIMIT = 4096


class TrustedExecutable:
    """A regular local executable validated below an owner-controlled root."""

    __slots__ = ("path",)

    def __init__(self, path: Path) -> None:
        object.__setattr__(self, "path", path)

    def __setattr__(self, name: str, value: object) -> None:
        del value
        raise AttributeError(f"{self.__class__.__name__} instances are immutable: {name}")

    def arguments(self, *values: str) -> tuple[str, ...]:
        """Build a shell-free command and reject malformed dynamic arguments."""

        if any(any(ord(character) < 0x20 or ord(character) == 0x7F for character in value) for value in values):
            raise MissingDependency("runtime command arguments must not contain control characters")
        return (str(self.path), *values)


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = b"traefik forwardauth upstream ok\n"
        response_headers: list[tuple[str, str]] = []
        if self.path == "/phase3-block":
            response_headers.append(("X-Modsec-Upstream", "block"))
        elif self.path == "/phase4-marker":
            body = b"no-crs-response-body-marker\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        for name, value in response_headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def directory_entry_is_protected_from_cross_user_replacement(
    parent_stat: os.stat_result, child_stat: os.stat_result
) -> bool:
    """Return whether an ancestor prevents another UID replacing its child."""

    if not stat.S_ISDIR(parent_stat.st_mode):
        return False
    parent_mode = stat.S_IMODE(parent_stat.st_mode)
    if parent_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0:
        return True
    return bool(parent_mode & stat.S_ISVTX) and child_stat.st_uid == os.geteuid()


def assert_path_ancestors_are_safe(
    path: Path, label: str, stop_at: Path | None = None
) -> None:
    """Reject a path replaceable through a cross-user writable ancestor."""

    child = path
    while child != child.parent:
        try:
            child_stat = child.lstat()
            parent_stat = child.parent.lstat()
        except OSError as exc:
            raise MissingDependency(f"{label} ancestor is unavailable: {child.parent}") from exc
        if not directory_entry_is_protected_from_cross_user_replacement(
            parent_stat, child_stat
        ):
            raise MissingDependency(
                f"{label} has an ancestor that permits cross-user replacement: {child.parent}"
            )
        if stop_at is not None and child.parent == stop_at:
            return
        child = child.parent


def require_trusted_runtime_root(path: Path, label: str, repo_root: Path) -> Path:
    """Require an existing user-owned root safe for executable runtime inputs."""

    if not path.is_absolute():
        raise MissingDependency(f"{label} must be an existing absolute directory: {path}")
    root = Path(os.path.abspath(path))
    if root == Path(root.anchor):
        raise MissingDependency(f"{label} is too broad for runtime inputs: {root}")
    try:
        root.relative_to(repo_root.resolve())
    except ValueError:
        pass
    else:
        raise MissingDependency(f"{label} must be outside the checkout: {root}")
    assert_no_symlink_components(root)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise MissingDependency(f"{label} is unavailable: {root}") from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        raise MissingDependency(f"{label} must be an existing directory: {root}")
    if root_stat.st_uid != os.geteuid():
        raise MissingDependency(f"{label} must be owned by the current user: {root}")
    if stat.S_IMODE(root_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise MissingDependency(f"{label} must not be group or world writable: {root}")
    assert_path_ancestors_are_safe(root, label)
    if not os.access(root, os.X_OK):
        raise MissingDependency(f"{label} is not searchable by the current user: {root}")
    return root


def require_runtime_root_from_environment(label: str, repo_root: Path) -> Path:
    """Resolve one mandatory runtime root without falling back to shared temporary storage."""

    value = os.environ.get(label, "")
    if not value:
        raise MissingDependency(f"{label} must be set to a trusted runtime root")
    return require_trusted_runtime_root(Path(value), label, repo_root)


def require_local_executable(path: Path, label: str, root: Path) -> TrustedExecutable:
    """Require a trusted regular executable below its validated runtime root."""

    if not path.is_absolute():
        raise MissingDependency(f"{label} must be an absolute local path: {path}")
    executable = Path(os.path.abspath(path))
    try:
        executable.relative_to(root)
    except ValueError as exc:
        raise MissingDependency(f"{label} must remain below {root}: {executable}") from exc
    assert_no_symlink_components(executable)
    try:
        executable_stat = executable.lstat()
    except OSError as exc:
        raise MissingDependency(f"{label} is unavailable: {executable}") from exc
    if not stat.S_ISREG(executable_stat.st_mode):
        raise MissingDependency(f"{label} must be a regular file: {executable}")
    if executable_stat.st_uid != os.geteuid():
        raise MissingDependency(f"{label} must be owned by the current user: {executable}")
    if stat.S_IMODE(executable_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise MissingDependency(f"{label} must not be group or world writable: {executable}")
    assert_path_ancestors_are_safe(executable, label, stop_at=root)
    if not os.access(executable, os.X_OK):
        raise MissingDependency(f"{label} is not executable: {executable}")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in str(executable)):
        raise MissingDependency(f"{label} must not contain control characters: {executable}")
    return TrustedExecutable(executable)


def require_private_result_root(path: Path, build_root: Path) -> Path:
    """Require an output leaf below the validated build root.

    The runner removes this directory before writing fresh runtime evidence, so
    accepting an arbitrary caller-supplied location would turn a smoke option
    into a recursive-delete capability. A missing leaf is safe to create only
    below the already validated, owner-controlled build root; an existing
    leaf must retain the same ownership and replacement protections.
    """

    if not path.is_absolute():
        raise MissingDependency(f"runtime smoke output root must be absolute: {path}")
    result_root = Path(os.path.abspath(path))
    try:
        result_root.relative_to(build_root)
    except ValueError as exc:
        raise MissingDependency(
            f"runtime smoke output root must remain below {build_root}: {result_root}"
        ) from exc
    if result_root == build_root:
        raise MissingDependency("runtime smoke output root must not be the build root")
    assert_no_symlink_components(result_root)

    existing_ancestor = result_root
    while not existing_ancestor.exists():
        existing_ancestor = existing_ancestor.parent
    ancestor_stat = existing_ancestor.lstat()
    if not stat.S_ISDIR(ancestor_stat.st_mode):
        raise MissingDependency(
            f"runtime smoke output ancestor must be a directory: {existing_ancestor}"
        )
    if ancestor_stat.st_uid != os.geteuid():
        raise MissingDependency(
            f"runtime smoke output ancestor must be owned by the current user: {existing_ancestor}"
        )
    if stat.S_IMODE(ancestor_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise MissingDependency(
            f"runtime smoke output ancestor must not be group or world writable: {existing_ancestor}"
        )
    assert_path_ancestors_are_safe(existing_ancestor, "runtime smoke output", stop_at=build_root)
    return result_root


def resolve_runtime_paths(
    args: argparse.Namespace, repo_root: Path
) -> tuple[Path, TrustedExecutable, TrustedExecutable]:
    """Resolve the build root and both local binaries before process startup."""

    build_root = require_runtime_root_from_environment(RUNTIME_ROOT_ENVIRONMENTS[0], repo_root)
    component_cache = require_runtime_root_from_environment(
        RUNTIME_ROOT_ENVIRONMENTS[1], repo_root
    )
    connector_binary = require_local_executable(
        args.connector_binary, "Traefik connector binary", build_root
    )
    # The Framework provisioner stages its verified host executable at this
    # exact build location. Other caller-selected build executables must not
    # become trusted host binaries merely because BUILD_ROOT is trusted.
    staged_host = build_root / "traefik-connector" / "bin" / "traefik"
    host_root = (
        build_root
        if args.traefik_binary == staged_host
        else component_cache
    )
    traefik_binary = require_local_executable(
        args.traefik_binary, "Traefik binary", host_root
    )
    return build_root, connector_binary, traefik_binary


def consume_no_crs_selected_cases(repo_root: Path) -> None:
    """Require the canonical plan before using the narrow host smoke.

    The shell helper intentionally records no PASS result: evidence finalization
    will retain selected catalog entries with no live case result as
    ``NOT_EXECUTED``.
    """
    if os.environ.get("MSCONNECTOR_NO_CRS_BASELINE", "") != "1":
        return
    consumer = (
        repo_root
        / "ci"
        / "runtime"
        / "lifecycle"
        / "consume-no-crs-selected-cases.sh"
    )
    if not consumer.is_file() or not os.access(consumer, os.X_OK):
        raise MissingDependency(f"No-CRS selected-case consumer is missing: {consumer}")
    completed = subprocess.run(
        [str(consumer), "traefik"],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "selected-case consumer failed"
        raise RuntimeError(detail)


def assert_no_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            raise MissingDependency(
                f"runtime smoke output path must not contain symlinks: {current}"
            )
        if not current.exists():
            break


def write_runtime_result(result_root: Path, payload: dict[str, object]) -> Path:
    """Write the fixed-name result only below the validated result root."""

    return write_fixed_runtime_text(
        result_root,
        RESULT_FILE_NAME,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )


def write_fixed_runtime_text(directory: Path, filename: str, contents: str) -> Path:
    """Write one fixed regular artifact beneath a private, non-symlink directory."""

    if filename not in {RESULT_FILE_NAME, SERVICE_CONFIG_FILE_NAME}:
        raise MissingDependency(f"unexpected runtime artifact name: {filename}")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    artifact_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    try:
        directory_descriptor = os.open(directory, directory_flags)
    except OSError as exc:
        raise MissingDependency(f"runtime artifact directory is unsafe: {directory}") from exc
    try:
        artifact_descriptor = os.open(filename, artifact_flags, 0o600, dir_fd=directory_descriptor)
    except OSError as exc:
        raise MissingDependency(f"runtime artifact path is unsafe: {directory / filename}") from exc
    finally:
        os.close(directory_descriptor)
    with os.fdopen(artifact_descriptor, "w", encoding="utf-8") as artifact:
        if not stat.S_ISREG(os.fstat(artifact.fileno()).st_mode):
            raise MissingDependency(f"runtime artifact is not a regular file: {directory / filename}")
        artifact.write(contents)
    return directory / filename


def verify_block_event(path: Path, expected_rule_id: str) -> dict[str, object]:
    if not path.is_file():
        raise RuntimeError(f"Common event JSONL is missing: {path}")
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise RuntimeError("Common event JSONL record is not an object")
            records.append(value)
    for record in records:
        if (
            record.get("connector") == "traefik"
            and record.get("transaction_id") == "traefik-forwardauth-block"
            and record.get("rule_id") == expected_rule_id
            and record.get("status") == "blocked"
            and record.get("http_status") == 403
        ):
            forbidden = {"request_body", "response_body", "body_payload", "body_snippet"}
            if forbidden.intersection(record):
                raise RuntimeError("Common event JSONL contains a forbidden body payload field")
            return record
    raise RuntimeError(
        f"Common event JSONL lacks the expected rule {expected_rule_id} blocked event"
    )


def verify_response_phase_events(path: Path) -> None:
    """Require P3 deny plus P4 Safe metadata without retaining body data."""

    if not path.is_file():
        raise RuntimeError(f"Common event JSONL is missing: {path}")
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise RuntimeError("Common event JSONL record is not an object")
            records.append(value)
    forbidden = {"request_body", "response_body", "body_payload", "body_snippet"}
    p3 = [
        record for record in records
        if record.get("connector") == "traefik"
        and record.get("transaction_id") == "traefik-forwardauth-p3-block"
        and record.get("rule_id") == "1000003"
        and record.get("phase") == "response_headers"
        and record.get("status") == "blocked"
        and record.get("actual_action") == "deny"
        and record.get("response_committed") is False
    ]
    p4 = [
        record for record in records
        if record.get("connector") == "traefik"
        and record.get("transaction_id") == "traefik-forwardauth-p4-safe"
        and record.get("rule_id") == "1000004"
        and record.get("phase") == "response_body"
        and record.get("status") == "blocked"
        and record.get("actual_action") == "log_only"
        and record.get("response_committed") is True
    ]
    if not p3 or not p4:
        raise RuntimeError("Common event JSONL lacks P3 deny or P4 Safe evidence")
    if any(forbidden.intersection(record) for record in [*p3, *p4]):
        raise RuntimeError("Common event JSONL contains a forbidden body payload field")


def write_concrete_service_config(
    template: Path, config_dir: Path, rules_file: Path, event_path: Path
) -> Path:
    """Materialize the fixed service config below the validated runtime root."""

    lines: list[str] = []
    for line in template.read_text(encoding="utf-8").splitlines():
        if line.startswith("rules_file="):
            line = f"rules_file={rules_file}"
        elif line.startswith("event_path="):
            line = f"event_path={event_path}"
        lines.append(line)
    return write_fixed_runtime_text(config_dir, SERVICE_CONFIG_FILE_NAME, "\n".join(lines) + "\n")


def dynamic_config(upstream_port: int, auth_port: int, companion_socket: Path) -> str:
    return f"""http:
  routers:
    smoke:
      entryPoints:
      - web
      rule: PathPrefix(`/`)
      middlewares:
      - modsecurity-forwardauth
      - modsecurity-response-observer
      service: upstream
  middlewares:
    modsecurity-forwardauth:
      forwardAuth:
        address: http://127.0.0.1:{auth_port}/authorize
        trustForwardHeader: false
        preserveRequestMethod: true
        # Keep the logical forwardAuth P2 contract explicit and bounded.
        forwardBody: true
        maxBodySize: 4096
        authRequestHeaders:
        - X-Modsec-Smoke
        - X-Request-Id
        - Content-Type
        - Content-Length
        authResponseHeaders:
        - X-Msconnector-Response-Handle
    modsecurity-response-observer:
      plugin:
        modsecurityResponseObserver:
          socketPath: {companion_socket}
          timeoutMillis: 5000
  services:
    upstream:
      loadBalancer:
        servers:
        - url: http://127.0.0.1:{upstream_port}
"""


def validate_forwardauth_p2_contract(dynamic_text: str) -> None:
    """Reject a forwardAuth host configuration that disables or loosens P2."""

    methods = re.findall(r"(?m)^\s{8}preserveRequestMethod:\s*(\S+)\s*$", dynamic_text)
    if methods != ["true"]:
        raise RuntimeError("forwardAuth requires preserveRequestMethod: true")
    forwarded = re.findall(r"(?m)^\s{8}trustForwardHeader:\s*(\S+)\s*$", dynamic_text)
    if forwarded != ["false"]:
        raise RuntimeError("forwardAuth requires trustForwardHeader: false")
    if "        forwardBody: true" not in dynamic_text:
        raise RuntimeError("forwardAuth P2 requires forwardBody: true")
    body_size = re.search(r"(?m)^\s{8}maxBodySize:\s*(\d+)\s*$", dynamic_text)
    if body_size is None:
        raise RuntimeError("forwardAuth P2 requires maxBodySize")
    if int(body_size.group(1)) != FORWARDAUTH_P2_BODY_LIMIT:
        raise RuntimeError("forwardAuth maxBodySize must equal 4096")


def http_status(url: str, headers: dict[str, str] | None = None) -> int:
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as exc:
        exc.read()
        return int(exc.code)


def wait_for_tcp(port: int, process: subprocess.Popen[bytes], label: str) -> None:
    deadline = time.monotonic() + 10
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited early with code {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError as exc:
            last_error = exc
        time.sleep(0.1)
    raise RuntimeError(f"{label} did not listen on port {port}: {last_error}")


def wait_for_traefik(port: int, process: subprocess.Popen[bytes]) -> int:
    """Wait for transport/provider startup and return the canonical allow result.

    The smoke router intentionally covers ``/`` and its forwardAuth/response
    companion path.  A synthetic ``/ready`` request would therefore exercise
    the transaction contract and can fail for reasons unrelated to process
    startup. Reuse the first routed canonical allow response after the provider
    becomes available, so startup never adds a different HTTP/WAF input.
    """

    deadline = time.monotonic() + 12
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Traefik exited early with code {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError as exc:
            last_error = exc
        time.sleep(0.2)
    else:
        raise RuntimeError(f"Traefik did not become ready: {last_error}")

    # The entrypoint can accept TCP before the file provider has installed the
    # router.  A 404 means only that the provider is still loading; any other
    # HTTP status proves that the configured route is live.  Do not require a
    # 2xx status because this probe itself traverses forwardAuth and the
    # response companion.
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Traefik exited early with code {process.returncode}")
        try:
            status = http_status(f"http://127.0.0.1:{port}/allowed",
                                 {"X-Request-Id": "traefik-forwardauth-allow"})
            if status != 404:
                return status
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("Traefik file-provider route did not become available")


def wait_for_private_socket(path: Path, process: subprocess.Popen[bytes]) -> None:
    """Require the connector-created observer socket before response traffic."""

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"forwardAuth service exited early with code {process.returncode}")
        try:
            socket_stat = path.lstat()
        except FileNotFoundError:
            time.sleep(0.1)
            continue
        if not stat.S_ISSOCK(socket_stat.st_mode):
            raise RuntimeError(f"companion path is not a Unix socket: {path}")
        if socket_stat.st_uid != os.geteuid() or stat.S_IMODE(socket_stat.st_mode) != 0o600:
            raise RuntimeError(f"companion socket ownership/mode is unsafe: {path}")
        return
    raise RuntimeError(f"response companion socket did not become ready: {path}")


def stage_response_observer(source: Path, runtime_root: Path) -> None:
    """Stage the repository-owned local plugin below the private Traefik root."""

    if not source.is_dir() or source.is_symlink():
        raise MissingDependency(f"response observer source is missing or symlinked: {source}")
    for candidate in source.rglob("*"):
        if candidate.is_symlink():
            raise MissingDependency(f"response observer source contains a symlink: {candidate}")
    destination = runtime_root / "plugins-local" / "src" / OBSERVER_MODULE
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, symlinks=False)
    os.chmod(runtime_root / "plugins-local", 0o700)
    os.chmod(runtime_root / "plugins-local" / "src", 0o700)
    for candidate in destination.rglob("*"):
        if candidate.is_dir():
            os.chmod(candidate, 0o700)
        else:
            os.chmod(candidate, 0o600)


def stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def parse_args() -> argparse.Namespace:
    script = Path(__file__).resolve()
    repo_root = connector_root()
    build_root = Path(os.environ.get("BUILD_ROOT", ""))
    component_cache = Path(os.environ.get("CONNECTOR_COMPONENT_CACHE", ""))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--connector-binary",
        type=Path,
        default=Path(
            os.environ.get(
                "TRAEFIK_CONNECTOR_BIN",
                str(build_root / "traefik-connector/traefik-forwardauth"),
            )
        ),
    )
    parser.add_argument(
        "--traefik-binary",
        type=Path,
        default=Path(os.environ.get("TRAEFIK_BIN", str(component_cache / "traefik/bin/traefik"))),
    )
    parser.add_argument(
        "--config-template",
        type=Path,
        default=repo_root / "connectors/traefik/config/traefik-forwardauth.conf",
    )
    parser.add_argument(
        "--result-root",
        type=Path,
        default=Path(
            os.environ.get(
                "TRAEFIK_CONNECTOR_RESULT_ROOT",
                str(build_root / "traefik-connector/runtime-smoke"),
            )
        ),
    )
    return parser.parse_args()


def private_companion_directory(result_root: Path, repo_root: Path) -> Path:
    selected = os.environ.get("MSCONNECTOR_PRIVATE_SOCKET_ROOT", "")
    if not selected:
        directory = result_root / "mrc"
    else:
        directory = require_trusted_runtime_root(Path(selected), "private socket root", repo_root)
        if stat.S_IMODE(directory.stat().st_mode) != 0o700:
            raise MissingDependency("private socket root must have mode 0700")
    if len(os.fsencode(directory / "traefik-forwardauth-companion.sock")) >= 108:
        raise MissingDependency("private companion socket path is too long")
    return directory


def prepare_smoke_inputs(args: argparse.Namespace, repo_root: Path):
    consume_no_crs_selected_cases(repo_root)
    build_root, connector_binary, traefik_binary = resolve_runtime_paths(args, repo_root)
    result_root = require_private_result_root(args.result_root, build_root)
    expected_rule_id = os.environ.get("MSCONNECTOR_EXPECTED_RULE_ID", "1000001")
    response_phase_smoke_value = os.environ.get("MSCONNECTOR_RESPONSE_PHASE_SMOKE", "0")
    if response_phase_smoke_value not in {"0", "1"}:
        raise MissingDependency("MSCONNECTOR_RESPONSE_PHASE_SMOKE must be 0 or 1")
    response_phase_smoke = response_phase_smoke_value == "1"
    template = args.config_template.resolve()
    rules_file = Path(
        os.environ.get(
            "MSCONNECTOR_RULES_FILE",
            str(source_path("common/rules/modsecurity_targeted_smoke.conf", root=repo_root)),
        )
    ).resolve()
    if not template.is_file():
        raise MissingDependency(f"connector config template is missing: {template}")
    if not rules_file.is_file():
        raise MissingDependency(f"targeted smoke rule is missing: {rules_file}")
    return (build_root, connector_binary, traefik_binary, result_root,
            expected_rule_id, response_phase_smoke, template, rules_file)


def prepare_smoke_workspace(repo_root: Path, result_root: Path,
                            template: Path, rules_file: Path):

    if result_root.exists():
        shutil.rmtree(result_root)
    result_root.mkdir(parents=True, exist_ok=True)
    log_dir = result_root / "logs"
    config_dir = result_root / "config"
    companion_dir = private_companion_directory(result_root, repo_root)
    log_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    companion_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(result_root, 0o700)
    os.chmod(companion_dir, 0o700)
    companion_socket = companion_dir / "traefik-forwardauth-companion.sock"
    stage_response_observer(repo_root / "connectors/traefik/response_observer", result_root)
    observer_build = repo_root / "connectors/traefik/build/build-response-observer.sh"
    if not observer_build.is_file() or not os.access(observer_build, os.X_OK):
        raise MissingDependency(f"response observer build script is unavailable: {observer_build}")
    observer_check = subprocess.run(
        [str(observer_build), "build"], cwd=repo_root, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    (log_dir / "response-observer-build.log").write_text(observer_check.stdout, encoding="utf-8")
    if observer_check.returncode != 0:
        raise MissingDependency(f"response observer build failed with code {observer_check.returncode}")
    traefik_config = config_dir / "traefik-dynamic.yml"
    event_path = log_dir / "events.jsonl"
    service_config = write_concrete_service_config(template, config_dir, rules_file, event_path)
    return log_dir, config_dir, companion_socket, traefik_config, event_path, service_config


def traefik_command(
    binary: TrustedExecutable, port: int, config: Path, access_log: Path
) -> tuple[str, ...]:
    """Load only the staged observer, including its authenticated UDS imports."""
    return binary.arguments(
        f"--entryPoints.web.address=127.0.0.1:{port}",
        f"--experimental.localPlugins.modsecurityResponseObserver.moduleName={OBSERVER_MODULE}",
        "--experimental.localPlugins.modsecurityResponseObserver.settings.useUnsafe=true",
        "--experimental.abortOnPluginFailure=true",
        f"--providers.file.filename={config}",
        "--providers.file.watch=false",
        "--api=false",
        "--log.level=ERROR",
        "--global.sendAnonymousUsage=false",
        "--accesslog=true",
        f"--accesslog.filepath={access_log}",
    )


def run(args: argparse.Namespace) -> int:
    repo_root = connector_root()
    (build_root, connector_binary, traefik_binary, result_root,
     expected_rule_id, response_phase_smoke, template, rules_file) = prepare_smoke_inputs(
        args, repo_root
    )
    log_dir, config_dir, companion_socket, traefik_config, event_path, service_config = prepare_smoke_workspace(
        repo_root, result_root, template, rules_file
    )

    upstream_port = free_port()
    auth_port = free_port()
    traefik_port = free_port()
    dynamic_text = dynamic_config(upstream_port, auth_port, companion_socket)
    validate_forwardauth_p2_contract(dynamic_text)
    traefik_config.write_text(dynamic_text, encoding="utf-8")

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", upstream_port), UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    service_process: subprocess.Popen[bytes] | None = None
    traefik_process: subprocess.Popen[bytes] | None = None
    allowed_status: int | None = None
    blocked_status: int | None = None
    p3_status: int | None = None
    p4_status: int | None = None
    blocked_event: dict[str, object] | None = None

    service_stdout_path = log_dir / "service.stdout.log"
    service_stderr_path = log_dir / "service.stderr.log"
    traefik_stdout_path = log_dir / "traefik.stdout.log"
    traefik_stderr_path = log_dir / "traefik.stderr.log"
    traefik_access_path = log_dir / "traefik-access.log"
    try:
        check = subprocess.run(
            connector_binary.arguments("--check-config", "--config", str(service_config)),
            cwd=repo_root,
            check=False,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        (log_dir / "config-check.stdout.log").write_text(check.stdout, encoding="utf-8")
        (log_dir / "config-check.stderr.log").write_text(check.stderr, encoding="utf-8")
        if check.returncode != 0:
            raise RuntimeError(f"connector config check failed with code {check.returncode}")

        with service_stdout_path.open("wb") as service_stdout, service_stderr_path.open("wb") as service_stderr:
            service_process = subprocess.Popen(
                connector_binary.arguments(
                    "--serve",
                    "--config",
                    str(service_config),
                    "--listen",
                    f"127.0.0.1:{auth_port}",
                ),
                cwd=repo_root,
                shell=False,
                env={
                    **os.environ,
                    "MSCONNECTOR_TRAEFIK_FORWARDAUTH_COMPANION_SOCKET": str(companion_socket),
                },
                stdout=service_stdout,
                stderr=service_stderr,
            )
            wait_for_tcp(auth_port, service_process, "Traefik forwardAuth service")

            command = traefik_command(
                traefik_binary, traefik_port, traefik_config, traefik_access_path
            )
            (config_dir / "traefik-command.txt").write_text(" ".join(command) + "\n", encoding="utf-8")
            with traefik_stdout_path.open("wb") as traefik_stdout, traefik_stderr_path.open("wb") as traefik_stderr:
                traefik_process = subprocess.Popen(
                    command,
                    cwd=result_root,
                    shell=False,
                    stdout=traefik_stdout,
                    stderr=traefik_stderr,
                )
                allowed_status = wait_for_traefik(traefik_port, traefik_process)
                wait_for_private_socket(companion_socket, service_process)
                blocked_status = http_status(
                    f"http://127.0.0.1:{traefik_port}/blocked",
                    {
                        "X-Modsec-Smoke": "block",
                        "X-Request-Id": "traefik-forwardauth-block",
                    },
                )
                if response_phase_smoke:
                    p3_status = http_status(
                        f"http://127.0.0.1:{traefik_port}/phase3-block",
                        {"X-Request-Id": "traefik-forwardauth-p3-block"},
                    )
                    p4_status = http_status(
                        f"http://127.0.0.1:{traefik_port}/phase4-marker",
                        {"X-Request-Id": "traefik-forwardauth-p4-safe"},
                    )

        if allowed_status != 200 or blocked_status != 403:
            raise RuntimeError(
                f"unexpected Traefik statuses: allowed={allowed_status}, blocked={blocked_status}"
            )
        if response_phase_smoke and (p3_status != 403 or p4_status != 200):
            raise RuntimeError(
                f"unexpected Traefik response-phase statuses: P3={p3_status}, P4 Safe={p4_status}"
            )
        if service_process.poll() is not None:
            raise RuntimeError(f"forwardAuth service exited with code {service_process.returncode}")
        if traefik_process.poll() is not None:
            raise RuntimeError(f"Traefik exited with code {traefik_process.returncode}")
        blocked_event = verify_block_event(event_path, expected_rule_id)
        if response_phase_smoke:
            verify_response_phase_events(event_path)

        result_path = write_runtime_result(
            result_root,
            {
                "allowed_request_status": allowed_status,
                "blocked_request_status": blocked_status,
                "common_runtime_path_verified": True,
                "connector": "traefik",
                "connector_binary": str(connector_binary.path),
                "crs_complete": False,
                "event_path": str(event_path),
                "companion_socket": str(companion_socket),
                "full_matrix_ready": False,
                "integration_mode": "forwardAuth",
                "intervention_status": 403,
                "modsecurity_rule_file": str(rules_file),
                "modsecurity_rule_id": str(blocked_event["rule_id"]),
                "modsecurity_rule_loaded": True,
                "production_ready": False,
                "request_body_verified": False,
                "response_body_verified": response_phase_smoke,
                "response_processing_supported": response_phase_smoke,
                "response_phase_smoke": response_phase_smoke,
                "p3_response_status": p3_status,
                "p4_safe_response_status": p4_status,
                "runtime_verified": True,
                "status": "PASS",
                "traefik_binary": str(traefik_binary.path),
            },
        )
        print(f"PASS: Traefik forwardAuth runtime smoke (200/403), result={result_path}")
        return 0
    except Exception as exc:
        result_path = write_runtime_result(
            result_root,
            {
                "allowed_request_status": allowed_status,
                "blocked_request_status": blocked_status,
                "common_runtime_path_verified": False,
                "connector": "traefik",
                "error": str(exc),
                "event_path": str(event_path),
                "companion_socket": str(companion_socket),
                "integration_mode": "forwardAuth",
                "request_body_verified": False,
                "response_body_verified": False,
                "response_processing_supported": False,
                "response_phase_smoke": response_phase_smoke,
                "p3_response_status": p3_status,
                "p4_safe_response_status": p4_status,
                "runtime_verified": False,
                "status": "FAIL",
            },
        )
        print(f"FAIL: Traefik forwardAuth runtime smoke: {exc}", file=sys.stderr)
        return 1
    finally:
        stop_process(traefik_process)
        stop_process(service_process)
        upstream.shutdown()
        upstream.server_close()


def main() -> int:
    args = parse_args()
    try:
        return run(args)
    except MissingDependency as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
