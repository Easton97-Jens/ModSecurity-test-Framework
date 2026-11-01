#!/usr/bin/env python3
"""Real B09 error-page regression within the existing isolated hosted runtime.

The existing launcher owns artifact provisioning and root/worker separation.
This test adds only loopback fixtures and test-owned rules under that run root.
It is not a replacement for the protected broker or a full NGINX profile matrix.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import grp
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
import threading
import time

ROOT = connector_root()
RULE_ID = "9803911"
ORIGIN_BACKEND_PATH = "/origin"
MAX_LOG = 1024 * 1024
BODY = b"b09-protected-control\n"


class RegressionFailure(RuntimeError):
    """The actual host did not satisfy the scoped B09 expectation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RegressionFailure(message)


def checked_path(value: str, directory: bool) -> Path:
    path = Path(value)
    require(bool(value) and path.is_absolute() and ".." not in path.parts,
            "expected an absolute non-traversing path")
    require(re.fullmatch(r"[A-Za-z0-9_./-]+", value) is not None,
            "fixture path contains unsupported configuration characters")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        require(not stat.S_ISLNK(current.lstat().st_mode), "symlink in fixture input")
    require(path.is_dir() if directory else path.is_file(), "fixture input is absent")
    return path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def private_file(path: Path, text: str) -> None:
    with path.open("x", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(text)


def read_log(path: Path) -> str:
    require(path.stat().st_size <= MAX_LOG, "fixture log exceeded its bound")
    return path.read_text(encoding="utf-8", errors="replace")


class Backend(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.records: list[str] = []
        self.lock = threading.Lock()

    def observed(self) -> list[str]:
        with self.lock:
            return list(self.records)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = self.server
        if not isinstance(server, Backend):
            raise RuntimeError("unexpected test server")
        with server.lock:
            server.records.append(self.path)
        status = 418 if self.path == ORIGIN_BACKEND_PATH else 200
        payload = b"" if status == 418 else BODY
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_arguments: object) -> None:
        return


def request(port: int, path: str, marker: str = "allow") -> tuple[int, bytes]:
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers={"X-B09-Control": marker})
        response = connection.getresponse()
        payload = response.read(16385)
        require(len(payload) <= 16384, "unexpectedly large fixture response")
        return response.status, payload
    finally:
        connection.close()


def worker_identity(master: subprocess.Popen, uid: int, gid: int) -> list[int]:
    children = Path(f"/proc/{master.pid}/task/{master.pid}/children").read_text().split()
    require(len(children) == 1, "expected exactly one isolated NGINX worker")
    workers = [int(value) for value in children]
    for worker in workers:
        fields = {}
        for line in Path(f"/proc/{worker}/status").read_text().splitlines():
            if line.startswith(("Uid:", "Gid:")):
                key, values = line.split(":", 1)
                fields[key] = [int(value) for value in values.split()]
        require(fields.get("Uid") == [uid] * 4 and fields.get("Gid") == [gid] * 4,
                "NGINX worker did not adopt the separate non-root identity")
    return workers


def stop_master(master: subprocess.Popen, workers: list[int]) -> None:
    if master.poll() is None:
        master.send_signal(signal.SIGQUIT)
        try:
            master.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(master.pid, signal.SIGKILL)
            master.wait(timeout=5)
            raise RegressionFailure("NGINX did not stop gracefully")
    require(master.returncode == 0, "NGINX master exited abnormally")
    require(all(not Path(f"/proc/{pid}").exists() for pid in workers),
            "NGINX worker survived cleanup")


def config_text(work: Path, module: Path, user: str, group: str,
                frontend: int, backend: int) -> str:
    return f"""
load_module {module};
user {user} {group};
worker_processes 1;
daemon off;
master_process on;
pid {work}/nginx.pid;
error_log {work}/error.log info;
events {{ worker_connections 32; }}
http {{
    access_log {work}/access.log;
    client_body_temp_path {work}/client-temp;
    proxy_temp_path {work}/proxy-temp;
    proxy_buffering off;
    server {{
        listen 127.0.0.1:{frontend};
        server_name localhost;
        recursive_error_pages off;
        location = /health {{ return 200 "b09-ready"; }}
        location = /origin-off {{
            modsecurity off;
            proxy_intercept_errors on;
            error_page 418 = /target;
            proxy_pass http://127.0.0.1:{backend}/origin;
        }}
        location = /origin-on {{
            modsecurity on;
            modsecurity_rules_file {work}/allow.conf;
            proxy_intercept_errors on;
            error_page 418 = /target;
            proxy_pass http://127.0.0.1:{backend}/origin;
        }}
        location = /target {{
            internal;
            modsecurity on;
            modsecurity_use_error_log on;
            modsecurity_rules_file {work}/protected.conf;
            proxy_pass http://127.0.0.1:{backend}/protected;
        }}
    }}
}}
"""


def exercise(port: int, backend: Backend, error_log: Path) -> list[dict]:
    observations = []
    for origin in ("/origin-off", "/origin-on"):
        for marker in ("allow", "block", "block", "block", "allow"):
            before = len(backend.observed())
            offset = error_log.stat().st_size
            status, payload = request(port, origin, marker)
            visited = backend.observed()[before:]
            if marker == "block":
                require(status == 403, f"{origin}: P2 deny returned {status}, expected 403")
                require(visited == [ORIGIN_BACKEND_PATH], f"{origin}: denied target reached its content backend")
                native = read_log(error_log)[offset:]
                require(RULE_ID in native and "phase 2" in native.lower(),
                        f"{origin}: missing actual phase-2 rule decision")
            else:
                require(status == 200 and payload == BODY, f"{origin}: legitimate error page failed")
                require(visited == [ORIGIN_BACKEND_PATH, "/protected"],
                        f"{origin}: allowed error page did not reach the target once")
            observations.append({"origin": origin, "marker": marker, "status": status,
                                 "protected_backend_calls": visited.count("/protected")})
    require("internal redirection cycle" not in read_log(error_log).lower(),
            "error-page routing entered a recursion cycle")
    return observations


def main() -> int:
    master = None
    workers: list[int] = []
    backend = None
    thread = None
    try:
        require(os.geteuid() == 0 and os.environ.get("NGINX_HOSTED_FUNCTIONAL_A") == "1",
                "use the existing hosted root launcher with a separate worker")
        expected = os.environ.get("EXPECTED_PARENT_SHA", "")
        require(re.fullmatch(r"[0-9a-f]{40}", expected) is not None, "expected head is not an exact SHA")
        actual = subprocess.run(
            ["/usr/bin/git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT),
             "rev-parse", "--verify", "HEAD"],
            check=True, capture_output=True, text=True, timeout=15,
        ).stdout.strip()
        require(actual == expected, "checkout differs from the reviewed head")
        root = checked_path(os.environ.get("NGINX_FUNCTIONAL_A_ROOT", ""), True)
        require(str(root) == os.environ.get("VERIFIED_RUN_ROOT"), "fixture root differs from verified root")
        require(root.name == "nginx-hosted-functional-a", "unexpected fixture root")
        require(root.stat().st_uid == 0 and stat.S_IMODE(root.stat().st_mode) == 0o711,
                "fixture ancestor must remain root-owned mode 0711")
        user, group = os.environ["NGINX_WORKER_USER"], os.environ["NGINX_WORKER_GROUP"]
        require(all(re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", value) for value in (user, group)),
                "unexpected worker account syntax")
        account, grouping = pwd.getpwnam(user), grp.getgrnam(group)
        require(account.pw_uid > 0 and account.pw_gid == grouping.gr_gid > 0,
                "worker identity must differ from the root launcher")
        binary = checked_path(os.environ["NGINX_BINARY"], False)
        module = checked_path(os.environ["NGINX_MODULE"], False)
        library = checked_path(os.environ["NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY"], False)
        artifacts = {"nginx": digest(binary), "module": digest(module), "libmodsecurity": digest(library)}
        work = root / "b09-error-page"
        work.mkdir(mode=0o700)
        work.chmod(0o711)
        for name in ("client-temp", "proxy-temp"):
            directory = work / name
            directory.mkdir(mode=0o700)
            os.chown(directory, account.pw_uid, grouping.gr_gid)
        request_limit = os.environ["NGINX_REQUEST_BODY_LIMIT"]
        request_no_files_limit = os.environ["NGINX_REQUEST_BODY_NO_FILES_LIMIT"]
        request_limit_action = os.environ["NGINX_REQUEST_BODY_LIMIT_ACTION"]
        require(all(re.fullmatch(r"[1-9]\d*", value, flags=re.ASCII) is not None
                    for value in (request_limit, request_no_files_limit)),
                "explicit positive native request limits are required")
        require(request_limit_action in ("Reject", "ProcessPartial"),
                "explicit native request limit action is required")
        rules = ("SecRuleEngine On\nSecRequestBodyAccess On\n"
                 f"SecRequestBodyLimit {request_limit}\n"
                 f"SecRequestBodyNoFilesLimit {request_no_files_limit}\n"
                 f"SecRequestBodyLimitAction {request_limit_action}\n"
                 "SecResponseBodyAccess Off\nSecAuditEngine Off\n")
        private_file(work / "allow.conf", rules)
        private_file(work / "protected.conf", rules +
                     'SecRule REQUEST_HEADERS:X-B09-Control "@streq block" '
                     f'"id:{RULE_ID},phase:2,deny,status:403,log,msg:\'B09 controlled P2\'"\n')
        for name in ("error.log", "access.log"):
            private_file(work / name, "")
        backend = Backend()
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        require(port > 1023, "fixture listener must be unprivileged")
        private_file(work / "nginx.conf",
                     config_text(work, module, user, group, port, backend.server_port))
        env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
               "LD_LIBRARY_PATH": str(library.parent)}
        command = [str(binary), "-p", str(work) + "/", "-c", str(work / "nginx.conf")]
        with (work / "process.log").open("xb") as log:
            os.fchmod(log.fileno(), 0o600)
            config = subprocess.run([*command, "-t"], env=env, stdout=log,
                                    stderr=subprocess.STDOUT, check=False, timeout=30)
            require(config.returncode == 0, "real NGINX configuration test failed")
            master = subprocess.Popen(command, env=env, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 10
            ready = False
            while time.monotonic() < deadline:
                require(master.poll() is None, "NGINX exited before readiness")
                try:
                    ready = request(port, "/health") == (200, b"b09-ready")
                except OSError:
                    ready = False
                if ready:
                    break
                time.sleep(0.05)
            require(ready, "NGINX did not become ready")
            workers = worker_identity(master, account.pw_uid, grouping.gr_gid)
            observations = exercise(port, backend, work / "error.log")
            worker_identity(master, account.pw_uid, grouping.gr_gid)
            stop_master(master, workers)
        require(artifacts == {"nginx": digest(binary), "module": digest(module),
                              "libmodsecurity": digest(library)}, "runtime artifact identity changed")
        receipt = {"status": "passed", "parent_sha": expected, "artifacts": artifacts,
                   "rule_id": RULE_ID, "rules_sha256": digest(work / "protected.conf"),
                   "cases": observations, "separate_nonroot_worker": True,
                   "graceful_cleanup": True,
                   "scope": "B09 HTTP/1 one-hop error-page routing; not full profile promotion"}
        private_file(work / "result.json", json.dumps(receipt, indent=2) + "\n")
        print("NGINX_B09_RESULT " + json.dumps(receipt, sort_keys=True))
        return 0
    except (RegressionFailure, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"NGINX B09 integration failed: {error}", file=sys.stderr)
        return 1
    finally:
        if master is not None and master.poll() is None:
            stop_master(master, workers)
        if backend is not None:
            backend.shutdown()
            backend.server_close()
        if thread is not None:
            thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
