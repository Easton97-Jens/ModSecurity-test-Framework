"""Bounded root-only supplemental I12 capture, separate from canonical qualification.

Uses the existing hash-bound lighttpd source variant in a disposable source copy.
The only observer relocation changes its /task/ prefix to this run's exact cases
directory. Native FD ownership/mode/link/path-component checks stay intact.
No namespace, UID, AppArmor or read-only boundary is changed. True nonroot needs
the existing trusted controller and is deliberately a separate execution layer.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import socket
import subprocess
import sys
import threading
import time

TEXT_PLAIN = "text/plain"
EXTERNAL_ROOT = Path(os.environ.get("I12_TEST_ROOT", "/__i12_external_root_requires_I12_TEST_ROOT__")).absolute()
PROC_ROOT = Path("/proc")


def validate_storage(path, writing):
    if writing and path.is_relative_to(EXTERNAL_ROOT):
        for directory in (EXTERNAL_ROOT.parent, EXTERNAL_ROOT):
            storage = directory.lstat()
            if (not stat.S_ISDIR(storage.st_mode) or storage.st_uid != os.geteuid()
                    or storage.st_mode & 0o022):
                raise ValueError("Evidence storage must be caller-owned without shared write access")


def evidence_path(path: Path, *, writing: bool = False) -> Path:
    path = Path(path).absolute()
    resolved = path.resolve(strict=False)
    validate_storage(path, writing)
    if writing:
        if resolved != path or not any(path.is_relative_to(root) for root in (EXTERNAL_ROOT, Path("/task"))):
            raise ValueError("Evidence output must be a physical authorized external path")
    elif not any(resolved.is_relative_to(root) for root in (
        EXTERNAL_ROOT, connector_root(), Path("/usr"), PROC_ROOT)):
        raise ValueError("Evidence input is outside the declared source/image roots")
    return path


def sha(path: Path) -> str:
    return hashlib.sha256(evidence_path(path).read_bytes()).hexdigest()


def reset_private_output(fd: int) -> None:
    details = os.fstat(fd)
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid() or details.st_nlink != 1:
        raise ValueError("Evidence output must be a caller-owned single-link regular file")
    os.fchmod(fd, 0o600)
    os.ftruncate(fd, 0)


def write_json(path: Path, value: object) -> None:
    path = evidence_path(path, writing=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        reset_private_output(fd)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
    finally:
        os.close(fd)


def regular(path: Path) -> Path:
    path = path.absolute()
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError(f"symlink input: {component}")
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError(f"regular single-link input required: {path}")
    return path


def command(root: Path, label: str, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
    actual = ["rtk", "proxy", *map(str, argv)]
    result = subprocess.run(actual, capture_output=True, timeout=180, **kwargs)
    (root / (label + ".stdout")).write_bytes(result.stdout)
    (root / (label + ".stderr")).write_bytes(result.stderr)
    write_json(root / (label + ".command.json"), {
        "argv": actual, "returncode": result.returncode,
        "stdout_sha256": sha(root / (label + ".stdout")),
        "stderr_sha256": sha(root / (label + ".stderr")),
    })
    if result.returncode:
        raise RuntimeError(f"{label}: {result.returncode}: {result.stderr.decode(errors='replace')[-3000:]}")
    return result


def copy_source_folder(repo: Path, source: Path, folder: str, inputs: dict) -> None:
    source_folder = repo / folder
    for component in (source_folder, *source_folder.parents):
        if component.is_symlink():
            raise ValueError(f"symlink source directory: {component}")
    for original in sorted(source_folder.rglob("*")):
        if original.is_symlink():
            raise ValueError(f"symlink source input: {original}")
        if original.is_dir():
            continue
        regular(original)
        relative = original.relative_to(repo)
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        inputs[str(relative)] = sha(original)


def prepare(args: argparse.Namespace) -> tuple[Path, Path]:
    root, repo = args.output, args.repository
    source = root / "source"
    source.mkdir(mode=0o700)
    inputs = {}
    for folder in ("common", "connectors/lighttpd"):
        copy_source_folder(repo, source, folder, inputs)
    for relative in ("connectors/profile_registry.c", "connectors/profile_registry.h",
                     "ci/runtime/lifecycle/native-lifecycle-observer.c",
                     "ci/runtime/lifecycle/native-lifecycle-observer.h",
                     "ci/runtime/lifecycle/native-lifecycle-sdk.cpp"):
        original = regular(repo / relative)
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        inputs[relative] = sha(original)
    write_json(root / "current-inputs.json", inputs)
    write_json(source / ".i12-disposable-source-copy.json", {
        "format": "i12-disposable-source-copy-v1", "path": str(source),
        "disposable": True, "parent_sha": "8cc32dceb06121f589150a9794f28878c5e4ba2a",
    })
    command(root, "apply-existing-variant", [sys.executable, "-B",
        str(repo / "ci/runtime/lifecycle/i12/capture_sources.py"), "apply",
        "--profile", "lighttpd", "--source-copy", str(source)])
    host_observer = source / "lighttpd-host-observer.c"
    before = sha(host_observer)
    text = host_observer.read_text()
    old = 'strncmp(path,"/task/",6U)==0'
    prefix = str(root / "cases") + "/"
    if text.count(old) != 1:
        raise ValueError("unexpected host observer relocation base")
    host_observer.write_text(text.replace(old, f'strncmp(path,"{prefix}",{len(prefix)}U)==0'))
    write_json(root / "host-observer-relocation.json", {
        "before_sha256": before, "after_sha256": sha(host_observer),
        "old_prefix": "/task/", "new_exact_prefix": prefix,
        "permissions_ownership_single_link_nofollow_checks_preserved": True,
        "original_source_objects_unchanged": True,
    })
    build = root / "build"
    build.mkdir(mode=0o700)
    strict = ["-Wall", "-Wextra", "-Werror", "-fPIC", "-fno-lto", "-pthread"]
    includes = ["-I", str(source), "-I", str(source / "common/include"),
                "-I", str(source / "ci/runtime/lifecycle"), "-isystem", str(args.sdk / "include")]
    objects = []
    for name, relative, compiler, standard in (
        ("native", "ci/runtime/lifecycle/native-lifecycle-observer.c", "cc", "c17"),
        ("host", "lighttpd-host-observer.c", "cc", "c17"),
        ("bootstrap", "lighttpd-observer-fd-bootstrap.c", "cc", "c17"),
        ("sdk", "ci/runtime/lifecycle/native-lifecycle-sdk.cpp", "g++", "c++17"),
    ):
        target = build / (name + ".o")
        command(build, "compile-" + name, [compiler, "-std=" + standard, *strict, *includes,
            "-c", str(source / relative), "-o", str(target)])
        objects.append(str(target))
    symbols = json.loads(regular(args.reference_receipt).read_text())["wrapped_symbols"]
    if len(symbols) != 38 or len(set(symbols)) != 38 or any(
        re.fullmatch(r"[a-zA-Z_]\w*", name, flags=re.ASCII) is None for name in symbols
    ):
        raise ValueError("expected the existing exact 38-symbol capture ABI")
    wrapper = build / "observer-cc.py"
    wrapper.write_text(f"#!{sys.executable}\nimport subprocess,sys\n"
        f"extra={includes!r}\n"
        f"if '-c' not in sys.argv: extra += {objects!r} + "
        f"{['-Wl,--wrap=' + name for name in symbols]!r} + ['-lstdc++']\n"
        "raise SystemExit(subprocess.run(['rtk','proxy','cc',*sys.argv[1:],*extra]).returncode)\n")
    wrapper.chmod(0o500)
    environment = {**os.environ, "CC": str(wrapper), "BUILD_ROOT": str(build),
        "MODSECURITY_INCLUDE_DIR": str(args.sdk / "include"),
        "MODSECURITY_LIB_DIR": str(args.sdk / "lib"),
        "LIGHTTPD_CONNECTOR_OUT_DIR": str(build / "module"),
        "LIGHTTPD_MODULE_DIR": str(build / "module/modules"),
        "LIGHTTPD_SOURCE_DIR": str(args.core), "LIGHTTPD_BUILD_ROOT": str(args.core_build),
        "LIGHTTPD_MSCONNECTOR_CORE_MODE": "patched"}
    command(build, "native-module-build", ["/bin/sh", str(source / "connectors/lighttpd/build/build_module.sh")], env=environment)
    modules = build / "module/modules"
    shutil.copyfile(regular(args.proxy_module), modules / "mod_proxy.so")
    plugin = regular(args.core / "src/plugin.h")
    if "#define LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION 2" not in plugin.read_text():
        raise ValueError("exact patched stream hook ABI 2 required")
    write_json(root / "build-provenance.json", {
        "host": str(args.host), "host_sha256": sha(args.host),
        "host_build_info": str(args.host_build_info), "host_build_info_sha256": sha(args.host_build_info),
        "plugin_header_sha256": sha(plugin), "generated_config_sha256": sha(args.core_build / "config.h"),
        "repository_patch_sha256": sha(repo / "connectors/lighttpd/patches/0001-lighttpd-msconnector-stream-hooks.patch"),
        "module_sha256": sha(modules / "mod_msconnector.so"), "proxy_sha256": sha(modules / "mod_proxy.so"),
        "observer_objects": {p: sha(Path(p)) for p in objects}, "wrapped_symbols": symbols,
        "reference_receipt_sha256": sha(args.reference_receipt), "fresh_module_from_bound_current_inputs": True,
        "root_only": True, "nonroot_equivalence": False, "full_lifecycle_qualified": False,
    })
    return source, modules


def request(port: int, path: str, body: bytes, chunked: bool = False,
            content_type: str = TEXT_PLAIN, extra_headers: bool = False) -> dict:
    headers = (f"POST {path} HTTP/1.1\r\nHost: i12.lighttpd.test\r\n"
               f"Content-Type: {content_type}\r\nConnection: close\r\n")
    if extra_headers:
        headers += "".join(f"X-I12-Extra-{index}: value\r\n" for index in range(8))
    if chunked:
        wire = headers.encode() + b"Transfer-Encoding: chunked\r\n\r\n"
        wire += b"".join(f"{len(part):x}\r\n".encode() + part + b"\r\n" for part in (body[:3], body[3:]) if part)
        wire += b"0\r\n\r\n"
    else:
        wire = headers.encode() + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    received = bytearray()
    error = None
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        if chunked and body:
            split = wire.index(b"\r\n\r\n") + 4 + len(f"{min(3, len(body)):x}\r\n") + min(3, len(body)) + 2
            client.sendall(wire[:split])
            time.sleep(0.03)
            client.sendall(wire[split:])
        else:
            client.sendall(wire)
        try:
            while data := client.recv(65536):
                received.extend(data)
        except OSError as exc:
            error = {"type": type(exc).__name__, "errno": exc.errno, "message": str(exc)}
    return {"request_wire_hex": wire.hex(), "response_wire_hex": received.hex(),
        "request_entity_bytes": len(body), "transport_error": error,
        "status_line": bytes(received).split(b"\r\n", 1)[0].decode(errors="replace"),
        "physical_client_bytes": len(received)}


def snapshot_native(root: Path, row: dict) -> None:
    native = root / "native.jsonl"
    if not native.exists():
        return
    observations = [json.loads(line) for line in native.read_text().splitlines()]
    pids = {r["pid"] for r in observations if r.get("function") == "runtime_begin_request_stream"}
    if not pids:
        pids = {next(r["pid"] for r in reversed(observations) if r.get("edge") == "admitted")}
    row["native_processes"] = []
    for pid in sorted(pids):
        proc = PROC_ROOT / str(pid)
        try:
            token = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
            (root / f"native-{pid}.maps").write_bytes((proc / "maps").read_bytes())
            (root / f"native-{pid}.status").write_bytes((proc / "status").read_bytes())
            row["native_processes"].append({"pid": pid, "starttime": token,
                "exe": os.readlink(proc / "exe"), "exe_sha256": sha(proc / "exe"),
                "fd_count": len(list((proc / "fd").iterdir()))})
        except (OSError, ValueError) as exc:
            row.setdefault("snapshot_errors", []).append(str(exc))


def finish_process(process, row: dict) -> None:
    if process is None:
        return
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    row["launcher_returncode"] = process.returncode
    row["launcher_reaped"] = process.poll() is not None
    row["native_cleanup"] = []
    for native in row.get("native_processes", []):
        proc = PROC_ROOT / str(native["pid"])
        try:
            token = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
            gone = token != native["starttime"]
        except FileNotFoundError:
            gone = True
        row["native_cleanup"].append({**native, "same_starttime_pid_gone": gone})


def finish_server(server, thread, row: dict) -> None:
    if server is not None:
        if thread is not None and thread.is_alive():
            server.shutdown()
        server.server_close()
    if thread is not None:
        thread.join(timeout=5)
    row["backend_thread_stopped"] = thread is None or not thread.is_alive()


def wait_host_ready(process, port, row):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            row["reached_stage"] = "host_exited_before_readiness"
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except OSError:
            time.sleep(0.03)
    raise TimeoutError("host readiness timeout")


def run_case(args: argparse.Namespace, modules: Path, name: str, body: bytes,
             limit: int = 1048576, action: str = "Reject", mime: str = TEXT_PLAIN,
             phase4: str = "safe", chunked: bool = False,
             response_limit: int = 1048576, response_action: str = "Reject",
             content_type: str = TEXT_PLAIN, **scenario) -> dict:
    max_headers = scenario.pop("max_headers", 64)
    backend_eof = scenario.pop("backend_eof", False)
    if scenario:
        raise ValueError("Unsupported fixture options: " + str(sorted(scenario)))
    root = args.output / "cases" / name
    root.mkdir(mode=0o700)
    backend_rows = []
    class Backend(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            entity = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            payload = b"i12-response-payload-multipart"
            backend_rows.append({"monotonic_ns": time.monotonic_ns(), "path": self.path,
                "request_body_hex": entity.hex(), "headers": list(self.headers.items()),
                "response_body_hex": payload.hex(), "response_mime": mime})
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("X-I12-Response", "present")
            self.send_header("Content-Length", str(len(payload) + (5 if backend_eof else 0)))
            self.end_headers()
            self.wfile.write(payload[:5]); self.wfile.flush(); time.sleep(0.03)
            self.wfile.write(payload[5:]); self.wfile.flush()
        def log_message(self, *_):
            # Physical request/response records above replace unstructured stderr.
            pass
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        backend_port = reservation.getsockname()[1]
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    rules = root / "rules.conf"
    rules.write_text("\n".join([
        "SecRuleEngine On", "SecRequestBodyAccess On", f"SecRequestBodyLimit {limit}",
        f"SecRequestBodyNoFilesLimit {limit}", f"SecRequestBodyLimitAction {action}",
        "SecResponseBodyAccess On", "SecResponseBodyMimeType text/plain",
        f"SecResponseBodyLimit {response_limit}", f"SecResponseBodyLimitAction {response_action}",
        "SecAuditEngine On", "SecAuditLogType Serial", "SecAuditLogParts ABHZ",
        f'SecAuditLog "{root}/audit.log"', f'SecDebugLog "{root}/debug.log"', "SecDebugLogLevel 5",
        'SecRule REQUEST_URI "@contains p1-deny" "id:941201,phase:1,deny,status:403,log,msg:\'i12 P1\'"',
        'SecRule REQUEST_BODY "@contains deny-p2" "id:941202,phase:2,deny,status:403,log,msg:\'i12 P2\'"',
        'SecRule RESPONSE_HEADERS:X-I12-Response "@streq present" "id:941203,phase:3,pass,log,msg:\'i12 P3\'"',
        'SecRule REQUEST_URI "@contains p3-deny" "id:941205,phase:3,deny,status:405,log,msg:\'i12 P3 deny\'"',
        'SecRule RESPONSE_BODY "@contains payload" "id:941204,phase:4,deny,status:406,log,msg:\'i12 P4\'"', ""]))
    runtime = root / "runtime.conf"
    runtime.write_text("\n".join(["enabled=on", f"rules_file={rules}",
        "request_body_mode=streaming", "response_body_mode=streaming", f"phase4_mode={phase4}",
        "default_error_status=502", "default_block_status=403", f"max_header_count={max_headers}",
        f"event_path={root}/events.jsonl", ""]))
    hostconf = root / "lighttpd.conf"
    hostconf.write_text("\n".join(['server.compat-module-load = "disable"',
        'server.modules = ( "mod_proxy", "mod_msconnector" )', 'server.stream-response-body = 1',
        'msconnector.enabled = "enable"', f'msconnector.config-file = "{runtime}"',
        'msconnector.request-body-gate = "pre-upstream"', f'server.document-root = "{root}"',
        'server.bind = "127.0.0.1"', f"server.port = {port}", f'server.errorlog = "{root}/host-error.log"',
        f'proxy.server = ( "" => ( ( "host" => "127.0.0.1", "port" => {backend_port} ) ) )', ""]))
    for p in (rules, runtime, hostconf):
        p.chmod(0o600)
    environment = {**os.environ, "MSCONNECTOR_LIGHTTPD_NATIVE_OBSERVER": str(root / "native.jsonl"),
        "MSCONNECTOR_LIGHTTPD_HOST_OBSERVER": str(root / "host.jsonl"),
        "MSCONNECTOR_LIFECYCLE_RUN": "i12-lighttpd-20261015-patched",
        "MSCONNECTOR_LIFECYCLE_PROFILE": "lighttpd-patched-native", "MSCONNECTOR_LIFECYCLE_CASE": name}
    row = {"case": name, "uid": os.geteuid(), "gid": os.getegid(),
        "full_lifecycle_qualified": False, "oracle_evaluated": False}
    process = None
    server = None
    thread = None
    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", backend_port), Backend)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        checked = subprocess.run(["rtk", "proxy", str(args.host), "-tt", "-m", str(modules), "-f", str(hostconf)],
            env=environment, capture_output=True, timeout=20)
        row["configtest_returncode"] = checked.returncode
        (root / "configtest.stdout").write_bytes(checked.stdout)
        (root / "configtest.stderr").write_bytes(checked.stderr)
        if checked.returncode:
            row["reached_stage"] = "configuration_rejected"
            return row
        with (root / "host.stdout").open("xb") as stdout, (root / "host.stderr").open("xb") as stderr:
            argv = ["rtk", "proxy", str(args.host), "-D", "-m", str(modules), "-f", str(hostconf)]
            row["host_argv"] = argv
            process = subprocess.Popen(argv, env=environment, stdout=stdout, stderr=stderr,
                stdin=subprocess.DEVNULL, start_new_session=True)
            if not wait_host_ready(process, port, row):
                return row
            row["reached_stage"] = "host_requests_executed"
            row["main"] = request(port, "/" + name, body, chunked, content_type,
                                  extra_headers=max_headers < 64)
            time.sleep(0.05)
            snapshot_native(root, row)
            row["backend_main_count"] = len(backend_rows)
            row["neighbor"] = request(port, "/neighbor", b"ordinary-neighbor")
            time.sleep(0.05)
    except Exception as exc:
        row["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        finish_process(process, row)
        finish_server(server, thread, row)
        row["backend"] = backend_rows
        row["physical_files"] = {p.name: {"sha256": sha(p), "size": p.stat().st_size,
            "uid": p.stat().st_uid, "mode": oct(p.stat().st_mode & 0o777)}
            for p in root.iterdir() if p.is_file()}
        write_json(root / "receipt.json", row)
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "output", "host", "host-build-info", "proxy-module", "core", "core-build", "sdk", "reference-receipt"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    args.output = args.output.absolute()
    if os.geteuid() != 0 or not args.output.is_relative_to(EXTERNAL_ROOT / "runs"):
        parser.error("root supplemental capture and authorized external run output required")
    if args.output.exists() or args.output.resolve() != args.output:
        parser.error("new physical output directory required")
    os.umask(0o077)
    args.output.mkdir(parents=True, mode=0o700)
    write_json(args.output / "execution-scope.json", {"uid": os.geteuid(), "gid": os.getegid(),
        "proc_status": Path("/proc/self/status").read_text(),
        "apparmor": Path("/proc/self/attr/current").read_text(),
        "nonroot_equivalence": False, "full_lifecycle_qualified": False})
    args.host = regular(args.host)
    regular(args.host_build_info)
    command(args.output, "host-version", [str(args.host), "-v"])
    _, modules = prepare(args)
    (args.output / "cases").mkdir(mode=0o700)
    cases = [
        ("allow", b"ordinary-request", {}), ("p1-deny", b"ordinary-request", {}),
        ("p2-deny", b"deny-p2", {}), ("p2-chunked", b"ordinary-chunked-body", {"chunked": True}),
        ("empty-finalize", b"", {}), ("limit-reject", b"x" * 64, {"limit": 16}),
        ("limit-partial", b"x" * 64, {"limit": 16, "action": "ProcessPartial"}),
        ("mime-out", b"ordinary-request", {"mime": "application/octet-stream"}),
        ("strict-control", b"ordinary-request", {"phase4": "strict"}),
        ("p3-deny", b"ordinary-request", {}),
        ("response-limit-reject", b"ordinary-request", {"response_limit": 16}),
        ("response-limit-partial", b"ordinary-request", {"response_limit": 16, "response_action": "ProcessPartial"}),
        ("multipart", b"--i12\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--i12--\r\n",
            {"content_type": "multipart/form-data; boundary=i12"}),
        ("technical-header-limit", b"ordinary-request", {"max_headers": 8}),
        ("backend-eof", b"ordinary-request", {"backend_eof": True}),
    ]
    rows = [run_case(args, modules, name, body, **options) for name, body, options in cases]
    write_json(args.output / "captures.json", rows)
    print(json.dumps({"output": str(args.output), "case_count": len(rows), "full_lifecycle_qualified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
