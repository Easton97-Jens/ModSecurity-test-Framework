#!/usr/bin/env python3
"""On-demand native H1 regressions for the fzipi review; never a default matrix.

The caller supplies a clean exact Parent checkout and a private artifact manifest
from its observed build. This runner does not build, install, escalate, rewrite
admission data, or claim another protocol/profile. Raw audit/server logs remain
under the task-owned output tree; result.json contains bounded metadata only.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import subprocess
import sys
import time

from modsecurity_test_framework.connector_context import test_root
from modsecurity_connector_ci.lib.runtime_path_utils import (
    canonical_project_roots, is_safe_runtime_root,
)
from modsecurity_connector_tests.run_nginx_body_buffer_fixture import (
    FixtureFailure, assert_exact_checkout, choose_port, create_output_directory,
    git_output, require_absolute_directory, require_regular_file,
    sha256_file, verify_trusted_directory, write_private,
)

LIMIT = 2 * 1024 * 1024
RULE_ID = "910001"
CUSTOM_PAGE = b"FZIPI-CUSTOM-403\n"
FIXTURE_BODY = b"P4-FIXTURE-BODY!"


@dataclass(frozen=True)
class AdmittedRunner:
    """Only checked artifact paths leave the CLI/admission boundary."""
    connector_root: Path
    head: str
    binary: Path
    module: Path | None
    output_root: Path
    identity: dict


@dataclass(frozen=True)
class RuntimePaths:
    """Fixed task-owned children; no CLI text is reused as a child name."""
    root: Path

    @property
    def private(self) -> Path:
        return self.root / "private"

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def logs(self) -> Path:
        return self.root / "server-logs"

    @property
    def docroot(self) -> Path:
        return self.root / "docroot"

    @property
    def audit(self) -> Path:
        return self.logs / "audit.json"

    @property
    def rules(self) -> Path:
        return self.private / "rules.conf"

    @property
    def config(self) -> Path:
        return self.private / "nginx.conf"


@dataclass(frozen=True)
class Scenario:
    name: str
    uri: str
    blocked_header: bool
    status: int
    body: bytes | None
    audit_count: int
    rule: str | None


SCENARIOS = (
    Scenario("phase2-error-page", "/block", True, 403, CUSTOM_PAGE, 1, RULE_ID),
    Scenario("try-files-same-policy", "/route-same", False, 200, b"SAME-POLICY\n", 1, None),
    Scenario("changed-target-policy", "/route-changed", False, 200, b"CHANGED-POLICY\n", 2, "910003"),
    Scenario("disabled-target-policy", "/route-off", False, 200, b"OFF-TARGET\n", 1, None),
    Scenario("ordinary-host-error-page", "/host403", True, 403, None, 1, RULE_ID),
    Scenario("replacement-stale-followups", "/rogue", False, 302, b"", 1, "910005"),
)


def checked_file(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise FixtureFailure(label + " must be canonical and absolute")
    require_absolute_directory(path.parent, label + " parent")
    try:
        verify_trusted_directory(path.parent)
    except ValueError as error:
        raise FixtureFailure(label + " has unsafe ancestry") from error
    return require_regular_file(path, label)


def product_files(root: Path) -> list[Path]:
    paths = list((root / "common/include").rglob("*.h"))
    paths += list((root / "common/src").glob("*.c"))
    paths += list((root / "common/src").glob("*.h"))
    paths += list((root / "connectors/nginx/src").glob("*.c"))
    paths += list((root / "connectors/nginx/src").glob("*.h"))
    paths += [root / "connectors/nginx/config",
              root / "connectors/nginx/metadata.c",
              root / "connectors/nginx/metadata.h",
              root / "connectors/profile_registry.c",
              root / "connectors/profile_registry.h"]
    return sorted(paths)


def nginx_path(path: Path, *, variable_aware: bool = False) -> str:
    """Quote one NGINX token; expanding directives cannot promise literal $."""
    value = os.fspath(path)
    if not path.is_absolute() or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise FixtureFailure("NGINX configuration paths must be absolute and contain no control characters")
    if variable_aware and "$" in value:
        raise FixtureFailure("a literal dollar sign is unsupported in a variable-aware NGINX path")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def modsecurity_audit_path(path: Path) -> str:
    """SecAuditLog has a distinct lexer: quotes are stripped, not unescaped.

    Its supported CONFIG_VALUE_PATH accepts spaces and literal backslashes but
    no quotes, dollar signs, controls or non-ASCII bytes. Do not apply NGINX's
    escape rules to this second language or change the resulting filename.
    """
    value = os.fspath(path)
    if not path.is_absolute() or re.fullmatch(r"[\w/.*: \\()-]+", value, flags=re.ASCII) is None:
        raise FixtureFailure("runtime path cannot be represented literally by SecAuditLog")
    return '"' + value + '"'


def validate_output_root(path: Path) -> Path:
    if not path.is_absolute() or path.resolve() != path or not is_safe_runtime_root(path):
        raise FixtureFailure("output-root must be a canonical external runtime path")
    if any(path.is_relative_to(source) or source.is_relative_to(path)
           for source in canonical_project_roots()):
        raise FixtureFailure("output-root overlaps a source checkout")
    if path.exists() or path.is_symlink():
        raise FixtureFailure("output-root must be a fresh task-owned directory")
    ancestor = path.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    try:
        verify_trusted_directory(ancestor)
    except ValueError as error:
        raise FixtureFailure("output-root has unsafe ancestry") from error
    nginx_path(path / "docroot", variable_aware=True)
    modsecurity_audit_path(path / "server-logs/audit.json")
    return path


def admit_artifacts(root: Path, head: str, binary: Path, module: Path | None,
                    manifest_path: Path) -> dict:
    if manifest_path.stat().st_size > LIMIT:
        raise FixtureFailure("artifact manifest is oversized")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("connector_head") != head:
        raise FixtureFailure("artifact build head does not match the admitted checkout")
    actual = {str(path.relative_to(root)): sha256_file(path) for path in product_files(root)}
    supplied = manifest.get("source_sha256")
    if not isinstance(supplied, dict) or any(supplied.get(name) != digest for name, digest in actual.items()):
        raise FixtureFailure("artifact manifest does not match every native/Common source input")
    binary_digest = sha256_file(binary)
    module_digest = sha256_file(module) if module else None
    if manifest.get("nginx_binary_sha256") != binary_digest or manifest.get("nginx_module_sha256") != module_digest:
        raise FixtureFailure("artifact bytes do not match the observed build manifest")
    fixture = test_root() / "connector_suite/modsecurity_connector_tests/nginx_body_buffer_fixture/ngx_http_body_buffer_fixture_module.c"
    fixture_digest = sha256_file(fixture)
    if manifest.get("fixture_source_sha256") != fixture_digest:
        raise FixtureFailure("static replacement fixture does not match its build source")
    return {
        "connector_head": head, "framework_head": git_output(test_root(), "rev-parse", "HEAD^{commit}"),
        "source_sha256": actual, "nginx_binary_sha256": binary_digest,
        "nginx_module_sha256": module_digest, "fixture_source_sha256": fixture_digest,
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "artifact_manifest_sha256": sha256_file(manifest_path),
    }


def admit(arguments: argparse.Namespace) -> AdmittedRunner:
    output = validate_output_root(arguments.output_root)
    binary = checked_file(arguments.nginx_binary, "NGINX binary")
    module = checked_file(arguments.nginx_module, "NGINX module") if arguments.nginx_module else None
    if module is not None:
        nginx_path(module)
    manifest = checked_file(arguments.artifact_manifest, "artifact manifest")
    root = require_absolute_directory(arguments.connector_root, "connector root")
    head = assert_exact_checkout(root, arguments.expected_head)
    identity = admit_artifacts(root, head, binary, module, manifest)
    return AdmittedRunner(root, head, binary, module, output, identity)


def valid_port(port: int) -> int:
    if type(port) is not int or not 1 <= port <= 65535:
        raise FixtureFailure("a valid integer loopback port is required")
    return port


def preflight(paths: RuntimePaths, port: int, *, prepared: bool) -> None:
    output = paths.private / ("preflight-paths" if prepared else "preflight-context")
    # The executable is the current Framework interpreter, not an operator
    # program name. Preserve its venv spelling rather than resolving its link.
    command = [sys.executable, "-P", "-m",
               "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
               "--execution-context-only", "--connector", "nginx",
               "--profile", "nginx-fzipi-review-h1",
               "--runtime-root=" + str(paths.root), "--output-dir=" + str(output),
               "--worker-user", "nobody", "--worker-group", "nogroup",
               "--require-root-master", "--require-chown", "--port=" + str(valid_port(port))]
    if prepared:
        command += ["--worker-read=" + str(paths.docroot / "ok.html"),
                    "--worker-write=" + str(paths.state),
                    "--worker-write=" + str(paths.logs),
                    "--worker-deny=" + str(paths.private)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    write_private(paths.private / (output.name + ".log"), result.stdout.encode() + result.stderr.encode())
    if result.returncode:
        raise FixtureFailure("same-context Framework preflight blocked; see private preflight receipt")


def read_server_file(path: Path, *, owner: int) -> str:
    """Read bounded server output with the role's exact owner and no-follow."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid != owner or before.st_mode & 0o022 or before.st_size > LIMIT):
            raise FixtureFailure("server output has unsafe identity, permissions, or size")
        chunks, length = [], 0
        while True:
            chunk = os.read(descriptor, min(65536, LIMIT + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
            if length > LIMIT:
                raise FixtureFailure("server output exceeded its bounded size")
        after, current = os.fstat(descriptor), path.lstat()
        if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or
                (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino) or
                after.st_uid != owner or after.st_nlink != 1 or after.st_mode & 0o022):
            raise FixtureFailure("server output identity changed during read")
        return b"".join(chunks).decode("utf-8", errors="strict")
    finally:
        os.close(descriptor)


def parse_audit(path: Path, *, allow_pending: bool = False) -> list[dict]:
    text = read_server_file(path, owner=65534)
    decoder, offset, entries = json.JSONDecoder(), 0, []
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError:
            if allow_pending:
                return entries
            raise
        if not isinstance(value, dict):
            raise FixtureFailure("native audit record is not an object")
        entries.append(value)
        if len(entries) > 32:
            raise FixtureFailure("native audit record count exceeded bounded scenario scope")
    return entries


def audit_for(entries: list[dict], case: str) -> list[dict]:
    return [entry for entry in entries if entry.get("transaction", {}).get("unique_id") == case]


def rule_ids(entries: list[dict]) -> list[str]:
    result = []
    for entry in entries:
        transaction = entry.get("transaction", {})
        for message in transaction.get("messages", []):
            identifier = message.get("details", {}).get("ruleId")
            if identifier is not None:
                result.append(str(identifier))
    return result


def write_configuration(root: Path, module: Path | None, port: int, rules: Path, *, extra: str = "") -> str:
    private, state, logs, docroot = [root / name for name in ("private", "state", "server-logs", "docroot")]
    load = f"load_module {nginx_path(module)};\n" if module else ""
    return load + f"""
user nobody nogroup;
worker_processes 1;
daemon off;
master_process on;
pid {nginx_path(private / 'nginx.pid')};
error_log {nginx_path(logs / 'error.log')} notice;
events {{ worker_connections 32; }}
http {{
    access_log off;
    client_body_temp_path {nginx_path(state / 'client')};
    proxy_temp_path {nginx_path(state / 'proxy')};
    fastcgi_temp_path {nginx_path(state / 'fastcgi')};
    uwsgi_temp_path {nginx_path(state / 'uwsgi')};
    scgi_temp_path {nginx_path(state / 'scgi')};
    server {{
        listen 127.0.0.1:{valid_port(port)};
        server_name localhost;
        root {nginx_path(docroot, variable_aware=True)};
        default_type text/plain;
        keepalive_timeout 0;
        modsecurity on;
        modsecurity_transaction_id "$http_x_case_id";
        modsecurity_phase4_mode safe;
        modsecurity_phase4_log {nginx_path(private / 'phase4.jsonl')};
        modsecurity_rules_file {nginx_path(rules)};
        error_page 403 /403.html;
        location = /block {{ }}
        location = /403.html {{
            internal;
            modsecurity on;
            add_header X-Fzipi-Preserved "$http_x_fzipi_block" always;
        }}
        location = /route-same {{ try_files /missing /ok.html; }}
        location = /ok.html {{ }}
        location = /route-changed {{ try_files /missing /changed.html; }}
        location = /changed.html {{
            modsecurity_rules 'SecAction "id:910003,phase:1,pass,log,msg:changed-policy"';
        }}
        location = /route-off {{ try_files /missing /off.html; }}
        location = /off.html {{ modsecurity off; }}
        location = /host403 {{ return 403; }}
        location = /rogue {{ body_buffer_fixture replaced-followup; }}
        {extra}
    }}
}}
"""


def nginx_command(admitted: AdmittedRunner, paths: RuntimePaths, config: Path,
                  *, configtest: bool = False) -> list[str]:
    checked_file(config, "generated NGINX config")
    if config.parent != paths.private:
        raise FixtureFailure("NGINX config must be a direct child of the private runtime")
    command = [str(admitted.binary)]
    if configtest:
        command.append("-t")
    return command + ["-p", str(paths.state), "-c", str(config)]


def configuration_check(admitted: AdmittedRunner, paths: RuntimePaths, config: Path,
                        log: Path, *, duplicate: bool = False) -> dict:
    result = subprocess.run(nginx_command(admitted, paths, config, configtest=True),
                            capture_output=True, text=True, timeout=15, check=False)
    output = result.stdout + result.stderr
    write_private(log, output.encode())
    valid = result.returncode != 0 and "is duplicate" in output if duplicate else result.returncode == 0
    if not valid:
        raise FixtureFailure("NGINX configuration scenario failed; private diagnostics retained")
    return {"status": "passed", "exit_code": result.returncode,
            "expected_duplicate_rejection": duplicate,
            "diagnostic_sha256": hashlib.sha256(output.encode()).hexdigest()}


def positive_pid(pid: int) -> int:
    if type(pid) is not int or pid <= 0:
        raise FixtureFailure("a positive integer process ID is required")
    return pid


def credentials(pid: int) -> dict:
    pid = positive_pid(pid)
    lines = (Path("/proc") / str(pid) / "status").read_text(encoding="ascii").splitlines()
    values = {}
    for line in lines:
        if line.startswith(("Uid:", "Gid:")):
            key, value = line.split(":", 1)
            values[key.lower()] = [int(item) for item in value.split()]
    return {"pid": pid, **values}


def runtime_credentials(process: subprocess.Popen) -> dict:
    master = credentials(process.pid)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        pid = positive_pid(process.pid)
        children = (Path("/proc") / str(pid) / "task" / str(pid) / "children").read_text(encoding="ascii").split()
        workers = [credentials(int(child)) for child in children]
        if workers and all(item.get("uid") == [65534] * 4 and item.get("gid") == [65534] * 4 for item in workers):
            if master.get("uid") != [0] * 4:
                raise FixtureFailure("observed NGINX master is not root")
            return {"master": master, "workers": workers}
        time.sleep(0.05)
    raise FixtureFailure("distinct nobody:nogroup runtime worker was not observed")


def request(port: int, path: str, case: str, *, blocked_header: bool = False) -> tuple[int, bytes, dict]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {"X-Case-Id": case}
        if blocked_header:
            headers["X-Fzipi-Block"] = "yes"
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(65537)
        if len(body) > 65536:
            raise FixtureFailure("response exceeded bounded fixture scope")
        return response.status, body, dict(response.getheaders())
    finally:
        connection.close()


def stop(process: subprocess.Popen) -> dict:
    if process.poll() is None:
        process.send_signal(signal.SIGQUIT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        absent = True
    else:
        absent = False
    return {"master_reaped": process.poll() is not None, "exit_code": process.returncode,
            "process_group_absent": absent}


def create_runtime(output: Path) -> RuntimePaths:
    create_output_directory(output, "output root")
    output.chmod(0o711)
    paths = RuntimePaths(output)
    paths.private.mkdir(mode=0o700)
    return paths


def require_worker_profile() -> None:
    if os.geteuid() != 0 or pwd.getpwnam("nobody").pw_uid != 65534 or grp.getgrnam("nogroup").gr_gid != 65534:
        raise FixtureFailure("the selected profile requires root master and nobody:nogroup")


def write_rules(paths: RuntimePaths) -> None:
    write_private(paths.rules, f"""
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html
SecAuditEngine On
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLogParts ABIJDEFHZ
SecAuditLog {modsecurity_audit_path(paths.audit)}
SecRule REQUEST_HEADERS:X-Fzipi-Block "@streq yes" "id:{RULE_ID},phase:2,deny,status:403,log,msg:header-block"
SecRule REQUEST_URI "@streq /rogue" "id:910005,phase:3,redirect:/replacement,log,msg:replacement"
""".encode())


def prepare_fixture(paths: RuntimePaths) -> None:
    for directory in (paths.state, paths.logs):
        directory.mkdir(mode=0o700)
        os.chown(directory, 65534, 65534)
    paths.docroot.mkdir(mode=0o711)
    documents = {"block": b"ALLOW-CONTROL\n", "403.html": CUSTOM_PAGE,
                 "ok.html": b"SAME-POLICY\n", "changed.html": b"CHANGED-POLICY\n",
                 "off.html": b"OFF-TARGET\n"}
    for name, content in documents.items():
        leaf = paths.docroot / name
        leaf.write_bytes(content)
        leaf.chmod(0o644)
    paths.audit.touch(mode=0o600)
    os.chown(paths.audit, 65534, 65534)


def check_configurations(admitted: AdmittedRunner, paths: RuntimePaths, port: int,
                         receipt: dict) -> None:
    write_private(paths.config, write_configuration(paths.root, admitted.module, port, paths.rules).encode())
    configuration_check(admitted, paths, paths.config, paths.private / "configtest.log")
    variants = {
        "duplicate-mode": ('location = /config-mode { modsecurity_phase4_mode off; modsecurity_phase4_mode strict; }', True),
        "inherited-safe-child-off": ('location = /config-mode { modsecurity_phase4_mode off; }', False),
        "inherited-safe-child-strict": ('location = /config-mode { modsecurity_phase4_mode strict; }', False),
    }
    for case, (extra, duplicate) in variants.items():
        config = paths.private / (case + ".conf")
        write_private(config, write_configuration(paths.root, admitted.module, port, paths.rules, extra=extra).encode())
        receipt["cases"][case] = configuration_check(admitted, paths, config,
                                                     paths.private / (case + ".log"), duplicate=duplicate)


def wait_for_listener(port: int, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 5
    while True:
        if process.poll() is not None:
            raise FixtureFailure("NGINX exited before listener readiness")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise FixtureFailure("NGINX listener readiness timed out")
            time.sleep(0.05)


@contextmanager
def managed_server(admitted: AdmittedRunner, paths: RuntimePaths, receipt: dict):
    startup_log = paths.private / "startup.log"
    write_private(startup_log, b"")
    with startup_log.open("wb") as startup:
        process = subprocess.Popen(nginx_command(admitted, paths, paths.config),
                                   stdout=startup, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            yield process
        finally:
            receipt["cleanup"] = stop(process)


def validate_client_result(scenario: Scenario, port: int, status_code: int,
                           body: bytes, headers: dict) -> None:
    if status_code != scenario.status or (scenario.body is not None and body != scenario.body):
        raise FixtureFailure("client-visible result failed: " + scenario.name)
    if scenario.name == "phase2-error-page" and headers.get("X-Fzipi-Preserved") != "yes":
        raise FixtureFailure("header did not survive the configured block error-page redirect")
    if scenario.name == "ordinary-host-error-page" and body == CUSTOM_PAGE:
        raise FixtureFailure("ordinary error-page routing bypassed the WAF")
    if scenario.name == "replacement-stale-followups" and (
        FIXTURE_BODY in body or headers.get("Location") not in (
            "/replacement", f"http://127.0.0.1:{port}/replacement")):
        raise FixtureFailure("replaced response leaked stale data or lost its redirect")


def await_audit(scenario: Scenario, audit: Path) -> list[dict]:
    deadline = time.monotonic() + 3
    while True:
        entries = audit_for(parse_audit(audit, allow_pending=True), scenario.name)
        if len(entries) >= scenario.audit_count or time.monotonic() >= deadline:
            return entries
        time.sleep(0.05)


def validate_audit_result(scenario: Scenario, entries: list[dict]) -> list[str]:
    ids = rule_ids(entries)
    if scenario.name == "phase2-error-page" and any(
        entry.get("transaction", {}).get("response", {}).get("http_code") != 403
        for entry in entries
    ):
        raise FixtureFailure("original native block status was lost from its audit")
    if len(entries) != scenario.audit_count or (scenario.rule is not None and ids.count(scenario.rule) != 1):
        raise FixtureFailure("native audit ownership or original rule decision failed: " + scenario.name)
    return ids


def run_scenarios(paths: RuntimePaths, port: int, receipt: dict) -> None:
    for scenario in SCENARIOS:
        status_code, body, headers = request(port, scenario.uri, scenario.name,
                                             blocked_header=scenario.blocked_header)
        validate_client_result(scenario, port, status_code, body, headers)
        ids = validate_audit_result(scenario, await_audit(scenario, paths.audit))
        receipt["cases"][scenario.name] = {
            "status": "passed", "http_status": status_code, "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(), "native_audit_records": scenario.audit_count,
            "rule_ids": ids, "preserved_trigger_header": scenario.name == "phase2-error-page",
        }


def verify_final_audit(paths: RuntimePaths, receipt: dict) -> None:
    entries = parse_audit(paths.audit)
    for scenario in SCENARIOS:
        observed = audit_for(entries, scenario.name)
        result = receipt["cases"][scenario.name]
        result["native_audit_records"] = len(observed)
        result["status"] = "failed"
        result["rule_ids"] = validate_audit_result(scenario, observed)
        result["status"] = "passed"


def verify_native_completion(paths: RuntimePaths, port: int, receipt: dict) -> None:
    verify_final_audit(paths, receipt)
    errors = read_server_file(paths.logs / "error.log", owner=0)
    if any(token in errors for token in ("zero size buf in writer", "the http output chain is empty",
                                         "invalid phase sequence", "native logging phase processing failed")):
        raise FixtureFailure("native writer/audit lifecycle diagnostic failed")
    if "stale-followup-callbacks=2 null-callback=1" not in errors:
        raise FixtureFailure("the stale handler follow-up callbacks did not execute")
    if not receipt["cleanup"].get("process_group_absent") or receipt["cleanup"].get("exit_code") != 0:
        raise FixtureFailure("NGINX did not stop and reap its owned worker cleanly")
    with socket.socket() as probe:
        probe.settimeout(0.2)
        receipt["cleanup"]["listener_closed"] = probe.connect_ex(("127.0.0.1", port)) != 0
    if not receipt["cleanup"]["listener_closed"]:
        raise FixtureFailure("owned listener remained open")


def verify_admission_unchanged(admitted: AdmittedRunner) -> None:
    assert_exact_checkout(admitted.connector_root, admitted.head)
    identity = admitted.identity
    if any(sha256_file(admitted.connector_root / name) != digest
           for name, digest in identity["source_sha256"].items()):
        raise FixtureFailure("admitted source changed during the native run")
    if sha256_file(admitted.binary) != identity["nginx_binary_sha256"] or (
            admitted.module is not None and sha256_file(admitted.module) != identity["nginx_module_sha256"]):
        raise FixtureFailure("admitted artifact changed during the native run")


def exercise_fixture(admitted: AdmittedRunner, paths: RuntimePaths, receipt: dict) -> None:
    require_worker_profile()
    port = choose_port()
    preflight(paths, port, prepared=False)
    prepare_fixture(paths)
    preflight(paths, port, prepared=True)
    write_rules(paths)
    check_configurations(admitted, paths, port, receipt)
    with managed_server(admitted, paths, receipt) as process:
        wait_for_listener(port, process)
        receipt["credentials"] = runtime_credentials(process)
        run_scenarios(paths, port, receipt)
    verify_native_completion(paths, port, receipt)
    verify_admission_unchanged(admitted)


def run_admitted(admitted: AdmittedRunner) -> int:
    paths = create_runtime(admitted.output_root)
    receipt = {"schema_version": 1, "profile": "native-nginx-h1-fzipi-review",
               "identity": admitted.identity, "status": "failed", "cases": {}, "cleanup": {}}
    try:
        exercise_fixture(admitted, paths, receipt)
        receipt["status"] = "passed"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        receipt["failure_class"] = type(error).__name__
        receipt["failure_reason"] = str(error)[:256]
    finally:
        write_private(paths.private / "result.json", (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"status": receipt["status"], "cases": len(receipt["cases"]),
                      "receipt": str(paths.private / "result.json")}))
    return 0 if receipt["status"] == "passed" else 1


def parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", required=True, type=Path)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--artifact-manifest", required=True, type=Path)
    parser.add_argument("--nginx-binary", required=True, type=Path)
    parser.add_argument("--nginx-module", type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    return run_admitted(admit(parse_arguments(argv)))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FixtureFailure, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)[:256]}))
        raise SystemExit(77)
