#!/usr/bin/env python3
"""Physical stock-native P1/config diagnostics; no body-lifecycle qualification.

Run as the existing controller's admitted nonroot identity. No identity,
namespace, sandbox, or product capability is modified here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import stat
import subprocess
import time


APPROVED_ROOTS = (Path("/mnt/artifacts"), Path("/mnt/fixtures"), Path("/task"),
                  Path(os.environ.get("I12_TEST_ROOT", "/__i12_external_root_requires_I12_TEST_ROOT__")).absolute())


def approved_input(path, basename=None):
    path = Path(path)
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not any(path.is_relative_to(root) for root in APPROVED_ROOTS)):
        raise ValueError("Input must be a physical absolute approved fixture path")
    if path.is_relative_to(APPROVED_ROOTS[-1]):
        for directory in (APPROVED_ROOTS[-1].parent, APPROVED_ROOTS[-1]):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError("External diagnostic input root must be private and current-user-owned")
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise ValueError("Input must be a single-link regular fixture file")
    if basename is not None and path.name != basename:
        raise ValueError("Unexpected fixture artifact name")
    if details.st_size > 16 * 1024 * 1024:
        raise ValueError("Fixture input exceeds 16 MiB")
    return path


def sha(path):
    return hashlib.sha256(approved_input(path).read_bytes()).hexdigest()


def fresh_output(path):
    path = Path(path).absolute()
    if path.resolve() != path or path.exists():
        raise ValueError("Fresh physical output directory without symlink ancestors required")
    path.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError("Output directory must be private")
    return path


def controls_match(receipt):
    codes = [row["exitcode"] for row in receipt["configuration_probes"]]
    return (len(codes) == 8 and codes[0] == 0 and all(code > 0 for code in codes[1:])
            and [row["status"] for row in receipt["clients"]] == [200, 403, 200])


def request(port, marker=False):
    data = b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    if marker:
        data += b"X-Modsec-Smoke: block\r\n"
    data += b"\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        client.sendall(data)
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 131072:
                raise ValueError("Diagnostic response exceeds 128 KiB limit")
    return data, b"".join(chunks)


def parser_cases(output):
    return [
        ("valid_rules_file", None, None),
        ("missing_rules_file", "rules_file", str(output / "absent-rules.conf")),
        ("invalid_rule_syntax", "rules_file", str(output / "invalid-rules.conf")),
        ("unknown_config_key", "invented_unknown_key", "on"),
        ("invalid_boolean", "enabled", "invalid"),
        ("invalid_status", "default_error_status", "12"),
        ("invalid_size", "max_header_count", "NaN"),
        ("unsafe_event_path", "event_path", str(output / "missing-parent/events.jsonl")),
    ]


def configuration_fixture(output, document, rules, port, case):
    name, key, value = case
    directory = output / name
    directory.mkdir()
    settings = {"enabled": "on", "rules_file": str(rules),
                "request_body_mode": "none", "response_body_mode": "none",
                "default_block_status": "403", "default_error_status": "500",
                "event_path": str(directory / "events.jsonl")}
    if key:
        settings[key] = value
    runtime = directory / "runtime.conf"
    runtime.write_text("".join(f"{k}={v}\n" for k, v in settings.items()))
    config = directory / "lighttpd.conf"
    config.write_text(
        'server.compat-module-load = "disable"\n'
        'server.modules = ( "mod_msconnector" )\n'
        f'server.document-root = "{document}"\n'
        'server.bind = "127.0.0.1"\n'
        f'server.port = {port}\n'
        f'server.errorlog = "{directory / "error.log"}"\n'
        'msconnector.enabled = "enable"\n'
        f'msconnector.config-file = "{runtime}"\n')
    return directory, runtime, config


def parser_first_cause(stderr):
    """Retain the first emitted Runtime check diagnostic, not the case label."""
    marker = "msconnector runtime config check failed: "
    for line in stderr.splitlines():
        if marker in line:
            return line.split(marker, 1)[1]
    return None


def parser_process_receipt(directory, case, record, parsed, host, rules, identity):
    """Record process/input facts at the invocation, never in the assembler."""
    if parsed.args != record["argv"] or parsed.returncode != record["exitcode"] or record["cwd"] != str(Path.cwd()):
        raise ValueError("Parser metadata differs from the actually waited invocation")
    selected_rules = Path(case[2]) if case[1] == "rules_file" else rules
    common = {**identity, "run_scoped_case_id": "I12::lighttpd-stock-native-control::" + case[0],
              "leg_id": "lighttpd-stock-native-control", "execution_kind": "configuration_parser",
              "execution_observed": True, "effective_config_sha256": record["host_config_sha256"]}
    try:
        selected_rules.lstat()
    except FileNotFoundError as error:
        if case[0] != "missing_rules_file" or selected_rules.parent.resolve() != selected_rules.parent:
            raise ValueError("Only the original missing-rules fixture may declare physical absence") from error
        absence = {**common, "type": "physical_path_absence", "exists": False, "measurement": "lstat",
                   "errno": error.errno, "rules_path": str(selected_rules), "symlink_components": []}
        path = directory / "rules-absence.json"
        path.write_text(json.dumps(absence, indent=2) + "\n")
        common.update(rules_sha256=None, rules_absence_sha256=sha(path), rules_path=str(selected_rules),
                      rules_exists=False, rules_lstat_errno=error.errno)
    else:
        common.update(rules_sha256=sha(selected_rules), rules_path=str(selected_rules), rules_exists=True)
    process = {**common, "argv": record["argv"], "cwd": record["cwd"], "waited_exit": record["exitcode"],
               "waited_signal": record["waited_signal"], "stdout": parsed.stdout.decode(),
               "stderr": parsed.stderr.decode(), "executable_sha256": sha(host),
               "first_cause": parser_first_cause(parsed.stderr.decode())}
    (directory / "parser-process.json").write_text(json.dumps(process, indent=2) + "\n")
    cleanup = {"parser_wait_completed": True, "waited_exit": record["exitcode"],
               "waited_signal": record["waited_signal"], "run_scoped_case_id": common["run_scoped_case_id"],
               "run_id": common["run_id"]}
    (directory / "parser-cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n")


def parser_probes(output, document, host, module, rules, port, identity=None):
    records = []
    for case in parser_cases(output):
        directory, runtime, config = configuration_fixture(output, document, rules, port, case)
        name = case[0]
        argv = ["rtk", "proxy", str(host), "-m", str(module.parent), "-tt", "-f", str(config)]
        parsed = subprocess.run(argv, capture_output=True, timeout=15)
        (directory / "config.stdout").write_bytes(parsed.stdout)
        (directory / "config.stderr").write_bytes(parsed.stderr)
        record = {"case_id": name, "argv": argv, "cwd": str(Path.cwd()),
                        "exitcode": parsed.returncode, "waited_signal": -parsed.returncode if parsed.returncode < 0 else None,
                        "runtime_sha256": sha(runtime), "host_config_sha256": sha(config),
                        "physical_stderr_sha256": sha(directory / "config.stderr"),
                        "qualification_scope": "configuration_parser_only",
                        "original_status_changed": False}
        if identity:
            parser_process_receipt(directory, case, record, parsed, host, rules, identity)
        records.append(record)
    return records


def matching_hosts(host):
    matches = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if os.readlink(proc / "exe") == str(host):
                matches.append(proc)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return matches


def await_host(process, host, output, port):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Host exited before request: {process.returncode}")
        # Find the actual lighttpd child of the RTK wrapper.
        matches = matching_hosts(host)
        if matches:
            actual = matches[0]
            (output / "host.status").write_bytes((actual / "status").read_bytes())
            (output / "host.maps").write_bytes((actual / "maps").read_bytes())
            try:
                request(port)
                break
            except ConnectionRefusedError:
                pass
        time.sleep(0.05)
    else:
        raise RuntimeError("Host readiness timeout")
    return actual


def stop_host(process, actual):
    if actual is not None:
        try:
            os.kill(int(actual.name), signal.SIGTERM)
        except ProcessLookupError:
            pass
    else:
        process.terminate()
    try:
        stopped = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        stopped = process.wait(timeout=5)
    return stopped


def host_controls(output, host, module, port):
    valid = output / "valid_rules_file"
    host_argv = ["rtk", "proxy", str(host), "-D", "-m", str(module.parent), "-f", str(valid / "lighttpd.conf")]
    clients = []
    stopped = None
    actual = None
    with (output / "host.stdout").open("xb") as stdout, (output / "host.stderr").open("xb") as stderr:
        process = subprocess.Popen(host_argv, stdout=stdout, stderr=stderr)
        try:
            actual = await_host(process, host, output, port)
            for name, marker in [("p1-allow", False), ("p1-deny", True), ("p1-neighbor", False)]:
                sent, received = request(port, marker)
                (output / f"{name}-request.http").write_bytes(sent)
                (output / f"{name}-response.http").write_bytes(received)
                clients.append({"name": name, "status": int(received.split(b" ", 2)[1]),
                                "physical_response_bytes": len(received),
                                "physical_response_sha256": hashlib.sha256(received).hexdigest(),
                                "peer_eof_observed": True})
        finally:
            stopped = stop_host(process, actual)
    return host_argv, clients, stopped, process.poll() is not None


def capture(output, host, module, rules, port=18951, source_manifest=None):
    host = approved_input(host, basename="lighttpd")
    module = approved_input(module, basename="mod_msconnector.so")
    rules = approved_input(rules)
    output = fresh_output(output)
    os.umask(0o077)
    document = output / "document-root"
    document.mkdir()
    (document / "index.html").write_text("diagnostic stock native\n")
    (output / "invalid-rules.conf").write_text("NotAValidModSecurityDirective\n")
    identity = None
    if source_manifest:
        source = json.loads(approved_input(source_manifest).read_text())
        identity = {"parent_sha": source["parent_sha"], "run_id": "diagnostic-parser-" + str(time.time_ns())}
    records = parser_probes(output, document, host, module, rules, port, identity)
    host_argv, clients, stopped, reaped = host_controls(output, host, module, port)
    receipt = {"schema": "lighttpd-stock-native-diagnostic-v1", "route": "lighttpd-stock-native-control",
               "uid": os.getuid(), "gid": os.getgid(), "host_argv": host_argv,
               "host_sha256": sha(host), "module_sha256": sha(module), "rules_sha256": sha(rules),
               "configuration_probes": records, "clients": clients,
               "host_wrapper_exitcode": stopped, "host_wrapper_reaped": reaped,
               "body_modes": {"request": "none", "response": "none"},
               "backend": {"applicable": False, "reason": "OPTIONS-star served by host; no upstream configured."},
               "finish_free_observation": None,
               "finish_free_missing_reason": "This parser/P1 helper does not configure or retain native API capture; no physical finish/free observation was supplied.",
               "full_lifecycle_qualified": False, "original_status_changed": False}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "host", "module", "rules"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--source-manifest", type=Path)
    args = parser.parse_args()
    receipt = capture(args.output, args.host, args.module, args.rules, source_manifest=args.source_manifest)
    print(json.dumps(receipt, indent=2))
    return 0 if controls_match(receipt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
