#!/usr/bin/env python3
"""Opt-in native Apache HTTP/2 multiplexing and transaction cleanup evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

from modsecurity_test_framework.connector_context import connector_root, load_source, test_root
from tests.runners.protocol_acceptance_client import build_client

FRAMEWORK = test_root()
LIFECYCLE = FRAMEWORK / "connector_suite/modsecurity_connector_ci/runtime/lifecycle"
DRIVER = load_source(LIFECYCLE / "run-protocol-acceptance.py")
HOST = DRIVER.HOST
PROVISIONER = load_source(FRAMEWORK / "connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.py")
CASES = {"apache_h2_" + ("phase4_" + name if name in {"safe", "strict"} else name): name for name in (
    "allow", "phase1", "phase2", "phase3", "safe", "strict", "client_cancel", "upstream_reset")}
MAX_CAPTURE = 8 * 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "unsafe hash input")
        result = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "hash input changed")
        return result


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def read_jsonl(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "missing/unsafe JSONL evidence")
    require(path.stat().st_size <= MAX_CAPTURE, "oversized evidence")
    raw = HOST.bounded_capture(path)
    require(not raw or raw.endswith(b"\n"), "incomplete JSONL evidence")
    rows = [json.loads(line) for line in raw.splitlines()]
    require(all(type(row) is dict for row in rows), "non-object evidence")
    return rows


class PostHandler(DRIVER.Handler):
    def do_POST(self):
        count = int(self.headers.get("Content-Length", "0"))
        require(0 <= count <= 1024 * 1024, "upstream request body bound")
        require(len(self.rfile.read(count)) == count, "incomplete upstream request body")
        self.do_GET()


class CleanupGate(threading.Event):
    """Client observation requests release; native pool cleanup authorizes it."""
    def __init__(self):
        super().__init__()
        self.requested = threading.Event()

    def set(self):
        self.requested.set()

    def allow(self):
        super().set()


class Upstream(DRIVER.Upstream):
    def __init__(self, scenario, paths):
        super().__init__(scenario.replace("_", "-"), paths)
        self.RequestHandlerClass = PostHandler
        self.peer_release = CleanupGate()
        self.target_stream = None
        self.proof["native_cleanup_gate"] = {"released": False, "forced": False, "error": None}

    def observe(self, row):
        if row.get("name") == "target" and type(row.get("stream_id")) is int:
            with self.lock:
                self.target_stream = row["stream_id"]
        super().observe(row)


def observe_cleanup_gate(backend, runtime, paths, stop):
    try:
        while not stop.wait(0.01):
            records = read_jsonl(runtime / "worker/native-cleanup.jsonl")
            target = [row for row in records if row.get("uri") == paths["target"]]
            require(len(target) <= 1, "duplicate live target cleanup")
            if target and backend.peer_release.requested.is_set():
                allow_peer_after_cleanup(backend, target[0], paths)
                return
    except (OSError, ValueError) as exc:
        with backend.lock:
            backend.proof["native_cleanup_gate"]["error"] = str(exc)


def allow_peer_after_cleanup(backend, target, paths):
    with backend.lock:
        require(target.get("transaction_id") == paths["target"] and target.get("stream_id") == backend.target_stream,
                "live native cleanup stream/transaction mismatch")
        require(target.get("context_seen") is True and target.get("native_context_cleared") is True,
                "live target native cleanup missing")
        backend.proof["native_cleanup_gate"].update(
            released=True, target_stream=target["stream_id"], target_cleanup_ns=target["monotonic_ns"],
            peer_released_ns=time.monotonic_ns())
        backend.peer_release.allow()


def rules(scenario):
    text = "SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\n"
    for phase in range(1, 5):
        text += f'SecAction "id:{1199100 + phase},phase:{phase},pass,log,msg:\'Apache H2 phase marker\'"\n'
    if scenario == "phase1":
        text += 'SecRule REQUEST_URI "@endsWith /target" "id:1199201,phase:1,deny,status:403,log,msg:\'Apache H2 P1 deny\'"\n'
    if scenario == "phase2":
        text += 'SecRule ARGS:acceptance "@streq deny" "id:1199202,phase:2,deny,status:403,log,msg:\'Apache H2 P2 deny\'"\n'
    text += 'SecRule RESPONSE_HEADERS:X-Modsec-Upstream "@streq block" "id:1199203,phase:3,deny,status:403,log,msg:\'Apache H2 P3 deny\'"\n'
    text += 'SecRule RESPONSE_BODY "@contains no-crs-response-body-marker" "id:1199204,phase:4,deny,status:403,log,msg:\'Apache H2 P4 deny\'"\n'
    return text


def configuration(runtime, prefix, module, observer, port, upstream, scenario):
    modules = (("mpm_event", "mod_mpm_event.so"), ("unixd", "mod_unixd.so"),
               ("authz_core", "mod_authz_core.so"), ("log_config", "mod_log_config.so"),
               ("socache_shmcb", "mod_socache_shmcb.so"), ("ssl", "mod_ssl.so"),
               ("http2", "mod_http2.so"), ("proxy", "mod_proxy.so"), ("proxy_http", "mod_proxy_http.so"))
    lines = [f'ServerRoot "{runtime}"', f'PidFile "{runtime}/httpd.pid"',
             f'Listen 127.0.0.1:{port}', 'ServerName 127.0.0.1',
             f'DefaultRuntimeDir "{runtime}/run"', f'ErrorLog "{runtime}/error.log"',
             'LogLevel warn', 'User nobody', 'Group nogroup', 'Mutex pthread default',
             'ServerLimit 1', 'StartServers 1', 'ThreadsPerChild 4', 'ThreadLimit 4',
             'MaxRequestWorkers 4', 'MinSpareThreads 4', 'MaxSpareThreads 4',
             'KeepAlive On', 'MaxKeepAliveRequests 100', 'Timeout 12']
    lines.extend(f'LoadModule {name}_module "{prefix}/modules/{file}"' for name, file in modules)
    lines += [f'LoadModule acceptance_observer_module "{observer}"',
              f'LoadModule security3_module "{module}"',
              'Protocols h2', 'H2Direct Off', 'SSLEngine on', 'SSLProtocol -all +TLSv1.3',
              'SSLSessionCache none', f'SSLCertificateFile "{runtime}/tls.crt"',
              f'SSLCertificateKeyFile "{runtime}/tls.key"',
              'ProxyRequests Off', f'ProxyPass "/" "http://127.0.0.1:{upstream}/" connectiontimeout=2 timeout=12 flushpackets=on',
              'modsecurity on', f'modsecurity_rules_file "{runtime}/rules.conf"',
              f'modsecurity_phase4_mode {"strict" if scenario == "strict" else "safe"}',
              f'modsecurity_phase4_log "{runtime}/worker/native-events.jsonl"',
              'modsecurity_transaction_id_expr "%{REQUEST_URI}"',
              'LogFormat "{\\\"uri\\\":\\\"%U\\\",\\\"status\\\":%>s,\\\"protocol\\\":\\\"%H\\\",\\\"stream_id\\\":\\\"%{H2_STREAM_ID}e\\\",\\\"stream_tag\\\":\\\"%{H2_STREAM_TAG}e\\\"}" acceptance',
              f'CustomLog "{runtime}/access.jsonl" acceptance']
    return "\n".join(lines) + "\n"


def compile_observer(prefix, output):
    source = Path(__file__).with_name("apache_h2_observer.c")
    shutil.copyfile(source, output / source.name)
    command = [str(prefix / "bin/apxs"), "-c", "-Wc,-std=c17", "-Wc,-Wall", "-Wc,-Wextra", "-Wc,-Werror", source.name]
    with (output / "observer-build.log").open("xb") as log:
        result = subprocess.run(command, cwd=output, stdout=log, stderr=subprocess.STDOUT, timeout=60)
    require(result.returncode == 0, "test-only Apache observer compilation failed")
    return output / ".libs/apache_h2_observer.so"


def selected_sources(args):
    source_state = {}
    for root, expected in ((connector_root(), args.parent_sha), (FRAMEWORK, args.framework_sha)):
        actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        require(actual == expected, "selected revision differs from actual source HEAD")
        source_state[str(root)] = {"head": actual, "porcelain": subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=normal"], text=True).splitlines()}
    mrts = subprocess.check_output(["git", "-C", str(FRAMEWORK), "rev-parse", "HEAD:tools/MRTS"], text=True).strip()
    require(mrts == args.mrts_sha, "MRTS pin mismatch")
    record = json.loads(args.component_record.read_text())
    if "connector_builds" in record:
        matches = [item for item in record["connector_builds"] if item.get("connector") == "apache"]
        require(len(matches) == 1, "ambiguous Apache build record")
        record = matches[0]
    require(record.get("status") in {"built", "reused", "present"}, "Apache component was not built")
    native_manifest = Path(record["build_path"]).parent / PROVISIONER.CACHE_MANIFEST_FILENAME
    plan = json.loads(native_manifest.read_text())
    require(plan.get("connector_build_id") == record.get("connector_build_id") and
            plan.get("output_paths") == record.get("output_paths"), "Apache runtime/cache record mismatch")
    plan["root"] = str(native_manifest.parent)
    record.update(plan)
    record["selected_source_state"] = source_state
    expected_hash = PROVISIONER.hash_input_paths(PROVISIONER.connector_input_paths(connector_root(), FRAMEWORK, "apache"))
    require(record.get("source_hash") == expected_hash, "Apache build source admission mismatch")
    require(PROVISIONER.connector_manifest_ready(record), "Apache native build/cache manifest is incomplete")
    require(Path(record["output_paths"]["binary"]).resolve() == (args.httpd_prefix / "bin/httpd").resolve(), "foreign Apache binary")
    require(Path(record["output_paths"]["module"]).resolve() == args.module.resolve(), "foreign Apache module")
    return record


def preflight(output):
    command = [sys.executable, "-P", "-m", "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
               "--execution-context-only", "--connector", "apache", "--profile", "apache-h2-acceptance",
               "--runtime-root", str(output), "--output-dir", str(output / "preflight"),
               "--worker-user", "nobody", "--worker-group", "nogroup", "--require-root-master", "--require-chown"]
    require(subprocess.run(command, timeout=20).returncode == 0, "Apache host execution-context preflight failed")


def admitted_library_dirs(args, record):
    modsecurity = Path(record["modsecurity_lib_dir"]).resolve(strict=True)
    allowed = {modsecurity, (args.httpd_prefix / "lib").resolve(), (Path(record["pcre2_prefix"]) / "lib").resolve()}
    if record.get("expat_lib_dir"):
        allowed.add(Path(record["expat_lib_dir"]).resolve())
    selected = {path.resolve(strict=True) for path in args.library_dir}
    require(modsecurity in selected and selected <= allowed, "unadmitted Apache shared-library directory")
    library = (modsecurity / "libmodsecurity.so").resolve(strict=True)
    require(modsecurity in library.parents, "foreign libmodsecurity link target")
    return sorted(selected | {(args.httpd_prefix / "lib").resolve()}), library


def client_completions(rows):
    completed = {name: [row for row in rows if row.get("event") == "completed" and row.get("name") == name]
                 for name in ("target", "peer", "followup")}
    require(all(len(items) == 1 for items in completed.values()), "missing/duplicate client completion")
    result = {name: values[0] for name, values in completed.items()}
    require(all(row.get("http_version") == 3 for row in result.values()), "HTTP/2 client negotiation missing")
    connections = {row.get("conn_id") for row in result.values()}
    require(len(connections) == 1 and None not in connections, "client physical connection changed")
    streams = [row.get("stream_id") for row in result.values()]
    require(all(type(stream) is int and stream > 0 for stream in streams) and len(set(streams)) == 3,
            "missing/duplicate actual client stream identity")
    for name in ("peer", "followup"):
        require(result[name].get("curl_code") == 0 and result[name].get("status") == 200,
                "allowed peer or same-connection follow-up failed")
    return result


def native_stream_binding(path, completion, access, cleanup):
    observed = [row for row in cleanup if row.get("uri") == path and row.get("transaction_id") == path]
    require(len(observed) == 1, "missing/duplicate/foreign native transaction cleanup")
    row = observed[0]
    require(row.get("context_seen") is True and row.get("native_context_cleared") is True,
            "actual native transaction cleanup was not observed")
    require(row.get("stream_id") == completion["stream_id"], "native/client stream mismatch")
    logs = [item for item in access if item.get("uri") == path]
    require(len(logs) == 1 and logs[0].get("protocol") == "HTTP/2.0", "native H2 access record missing")
    require(str(logs[0].get("stream_id")) == str(row["stream_id"]), "access/cleanup stream mismatch")
    tag = row.get("stream_tag", "")
    require(type(tag) is str and re.fullmatch(r"[0-9]+-[0-9]+-[0-9]+", tag) and
            tag.rsplit("-", 1)[1] == str(row["stream_id"]) and logs[0].get("stream_tag") == tag,
            "native H2 session/stream tag mismatch")
    require(logs[0].get("status") == completion.get("status"), "native/client HTTP status mismatch")
    # mod_http2's h2_conn_ctx.id is the native session identity. Secondary
    # worker conn_rec ids can differ on a same-session follow-up request.
    return tag.rsplit("-", 1)[0]


def native_intervention(native, target, scenario):
    blocked_phase = {"phase1": 1, "phase2": 2, "phase3": 3, "safe": 4, "strict": 4}.get(scenario)
    if blocked_phase:
        matched = [item for item in native if item.get("transaction_id") == target and
                   str(item.get("rule_id")) == str(1199200 + blocked_phase)]
        require(matched, "native phase/rule/transaction binding missing")
        expected_action = {"safe": "log_only", "strict": "abort_connection"}.get(scenario, "deny")
        require(any(item.get("actual_action") == expected_action and item.get("requested_action") == "deny"
                    for item in matched), "native intervention action mismatch")


def native_allowed_phases(native, paths, error_log):
    for name in ("peer", "followup"):
        observed_rules = {str(item.get("rule_id")) for item in native if item.get("transaction_id") == paths[name]}
        require({"1199101", "1199102"} <= observed_rules,
                "allowed stream phase lifecycle markers incomplete")
        # Apache's callback intentionally emits rule_match JSON only for P1/P2.
        # P3/P4 phase markers are bound to the actual native engine log instead.
        for phase in (3, 4):
            markers = [line for line in error_log.splitlines() if
                       f'[id "{1199100 + phase}"]' in line and
                       f'[uri "{paths[name]}"]' in line and f'[unique_id "{paths[name]}"]' in line]
            require(len(markers) == 1, "allowed native response phase marker missing/duplicate")


def validate_native(output, paths, completed, scenario):
    native = read_jsonl(output / "native-events.jsonl")
    access = read_jsonl(output / "access.jsonl")
    cleanup = read_jsonl(output / "native-cleanup.jsonl")
    require(native and len(access) == 3 and len(cleanup) == 3, "native evidence count incomplete")
    server_connections = {native_stream_binding(path, completed[name], access, cleanup) for name, path in paths.items()}
    require(len(server_connections) == 1 and None not in server_connections, "server physical connection changed")
    require(all(item.get("transaction_id") in paths.values() for item in native), "foreign native transaction")
    require(all(item.get("connector") == "apache" and item.get("integration_mode") == "native-httpd-module"
                and item.get("uri") == item.get("transaction_id") for item in native), "foreign native profile/request")
    native_intervention(native, paths["target"], scenario)
    native_allowed_phases(native, paths, HOST.bounded_capture(output / "error.log").decode("utf-8"))
    return {"server_connection_id": next(iter(server_connections)), "native_cleanup_count": len(cleanup)}


def validate_cleanup_barrier(output, paths, scenario, rows, reset):
    barrier = reset
    if scenario == "client_cancel":
        cancelled = [row for row in rows if row.get("event") == "cancelled" and row.get("name") == "target"]
        require(len(cancelled) == 1, "missing/ambiguous cancel barrier")
        barrier = cancelled[0]
    if barrier is not None:
        peer = next(row for row in read_jsonl(output / "native-cleanup.jsonl") if row["uri"] == paths["peer"])
        require(type(peer.get("monotonic_ns")) is int and type(barrier.get("monotonic_ns")) is int and
                peer["monotonic_ns"] > barrier["monotonic_ns"], "peer native cleanup preceded reset/cancel barrier")


def validate_live_cleanup_gate(output, paths, rows):
    gate = json.loads((output / "upstream.json").read_text()).get("native_cleanup_gate", {})
    require(gate.get("released") is True and gate.get("forced") is False and gate.get("error") is None,
            "live native target cleanup did not authorize peer release")
    target = next(row for row in read_jsonl(output / "native-cleanup.jsonl") if row["uri"] == paths["target"])
    peer_data = next(row for row in rows if row.get("name") == "peer" and row.get("event") == "first_data")
    peer_done = next(row for row in rows if row.get("name") == "peer" and row.get("event") == "completed")
    followup = next(row for row in rows if row.get("name") == "followup" and row.get("event") == "request_started")
    require(gate.get("target_stream") == target["stream_id"] and
            gate.get("target_cleanup_ns") == target["monotonic_ns"], "live cleanup witness mismatch")
    ordered = [target["monotonic_ns"], gate.get("peer_released_ns"), peer_data.get("monotonic_ns"),
               peer_done.get("monotonic_ns"), followup.get("monotonic_ns")]
    require(all(type(value) is int and value > 0 for value in ordered) and
            all(left < right for left, right in zip(ordered, ordered[1:])),
            "native target cleanup was not observed before peer completion and follow-up")


def validate_bundle(output, case_id, paths):
    scenario = CASES[case_id]
    receipt = json.loads((output / "receipt.json").read_text())
    require(receipt.get("case_id") == case_id, "foreign bundle case identity")
    for name, expected in receipt.get("sha256", {}).items():
        require(Path(name).name == name and digest(output / name) == expected, "bundle digest mismatch")
    require({"client.jsonl", "native-events.jsonl", "native-cleanup.jsonl", "cleanup.json", "access.jsonl", "upstream.json", "error.log"}
            <= set(receipt.get("sha256", {})), "required bundle digest missing")
    rows = read_jsonl(output / "client.jsonl")
    completed = client_completions(rows)
    generic_scenario = {"allow": "streaming", "phase1": "multiplex", "phase2": "multiplex"}.get(scenario, scenario.replace("_", "-"))
    _completed, _streams, _connections, reset = DRIVER.CONTRACT._client(rows, paths, "h2", generic_scenario)
    DRIVER.CONTRACT._upstream({"upstream.json": (output / "upstream.json").read_bytes()}, paths, generic_scenario, rows, reset)
    target = completed["target"]
    if scenario in {"phase1", "phase2", "phase3"}:
        require(target.get("curl_code") == 0 and target.get("status") == 403, "phase deny did not produce 403")
    elif scenario in {"strict", "upstream_reset"}:
        require(target.get("curl_code") != 0 and target.get("debug_failure"), "server stream reset not observed")
    elif scenario == "client_cancel":
        require(any(row.get("event") == "cancelled" and row.get("name") == "target" for row in rows), "client cancellation missing")
    else:
        require(target.get("curl_code") == 0 and target.get("status") == 200, "allowed/safe stream did not complete")
    proof = validate_native(output, paths, completed, scenario)
    validate_cleanup_barrier(output, paths, scenario, rows, reset)
    validate_live_cleanup_gate(output, paths, rows)
    cleanup = json.loads((output / "cleanup.json").read_text())
    require(cleanup.get("verified") is True, "owned Apache/upstream cleanup incomplete")
    return proof


def stop_host(process, handles, roles, port):
    master_killed = False
    if process is not None and process.poll() is None:
        HOST.bind_owned_children(process, handles)
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            master_killed = True
            process.kill()
            process.wait(timeout=3)
    forced, running = HOST.retire_bound_children(handles)
    for handle in handles.values():
        os.close(handle)
    return {"verified": HOST.valid_roles(roles) and not master_killed and not forced and not running and not HOST.listener_open(port),
            "roles": roles, "forced_child_cleanup": forced, "listener_open": HOST.listener_open(port)}


def protocol_command(args, runtime, client, port, scenario, paths):
    client_scenario = {"strict": "server-reset", "upstream_reset": "server-reset",
                       "phase1": "multiplex", "phase2": "multiplex",
                       "allow": "streaming", "client_cancel": "client-cancel"}.get(scenario, scenario)
    command = [str(client), "--protocol", "h2", "--base-url", f"https://127.0.0.1:{port}",
               "--ca", str(runtime / "tls.crt"), "--scenario", client_scenario]
    for name, path in paths.items():
        command.extend(("--" + name + "-path", path))
    if scenario == "phase2":
        (args.output / "request-body.fixture").write_bytes(b"acceptance=deny")
        command += ["--method", "POST", "--body-file", str(args.output / "request-body.fixture")]
    return command


def await_native_cleanup(runtime):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if len(read_jsonl(runtime / "worker/native-cleanup.jsonl")) == 3:
            break
        time.sleep(0.02)


def run_host_requests(args, runtime, backend, client, state):
    scenario = CASES[args.case_id]
    observer, port, paths, environment = (state[name] for name in ("observer", "port", "paths", "environment"))
    with DRIVER.MODERN.tls_material(runtime):
        (runtime / "rules.conf").write_text(rules(scenario))
        config = configuration(runtime, args.httpd_prefix, args.module, observer, port, backend.server_port, scenario)
        (runtime / "httpd.conf").write_text(config)
        (args.output / "httpd.conf").write_text(config)
        shutil.copyfile(runtime / "tls.crt", args.output / "tls.crt")
        argv = [str(args.httpd_prefix / "bin/httpd"), "-f", str(runtime / "httpd.conf")]
        with (args.output / "configtest.log").open("xb") as log:
            result = subprocess.run([*argv, "-t"], env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=15)
            require(result.returncode == 0, "Apache H2 configuration rejected")
        with (args.output / "startup.stdout").open("xb") as stdout, (args.output / "startup.stderr").open("xb") as stderr:
            state["process"] = subprocess.Popen([*argv, "-DFOREGROUND"], env=environment, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL)
            state["roles"] = HOST.observe_roles(state["process"], args.run_id, port, args.output, state["handles"])
            command = protocol_command(args, runtime, client, port, scenario, paths)
            DRIVER.execute_client(command, args.output, backend)
            await_native_cleanup(runtime)


def retire_resources(args, runtime, backend, thread, port, state):
    state["monitor_stop"].set()
    state["monitor"].join(timeout=2)
    cleanup = stop_host(state["process"], state["handles"], state["roles"], port)
    backend.release.set()
    if not backend.peer_release.is_set():
        backend.proof["native_cleanup_gate"]["forced"] = True
        backend.peer_release.allow()
    backend.shutdown()
    backend.server_close()
    thread.join(timeout=3)
    cleanup["verified"] = cleanup["verified"] and not thread.is_alive() and not state["monitor"].is_alive() and not HOST.listener_open(backend.server_port)
    for source, target in (("worker/native-events.jsonl", "native-events.jsonl"),
                           ("worker/native-cleanup.jsonl", "native-cleanup.jsonl"),
                           ("access.jsonl", "access.jsonl"), ("error.log", "error.log")):
        if (runtime / source).is_file():
            (args.output / target).write_bytes(HOST.bounded_capture(runtime / source))
    shutil.rmtree(runtime)
    return cleanup


def execute(args):
    os.umask(0o077)
    require(args.case_id in CASES and re.fullmatch(r"[A-Za-z0-9_.-]{1,48}", args.run_id), "invalid case/run identity")
    require(args.output.is_absolute() and not args.output.exists() and
            HOST.BASE.AUTHORIZED_STORAGE_ROOT in args.output.parents and
            args.output.resolve() == args.output, "output must be a fresh absolute external path")
    args.output.mkdir(parents=True, mode=0o700)
    record = selected_sources(args)
    library_dirs, modsecurity_library = admitted_library_dirs(args, record)
    source_paths = (Path(__file__), Path(__file__).with_name("apache_h2_observer.c"),
                    FRAMEWORK / "tests/runners/protocol_acceptance_client.c",
                    FRAMEWORK / "tests/runners/protocol_acceptance_client.py",
                    FRAMEWORK / "tests/runners/protocol_acceptance_contract.py",
                    LIFECYCLE / "run-protocol-acceptance.py")
    source_hashes = {str(path.relative_to(FRAMEWORK)): digest(path) for path in source_paths}
    preflight(args.output)
    client = build_client(args.curl_prefix, args.client_build_root)
    observer = compile_observer(args.httpd_prefix, args.output)
    runtime = Path(tempfile.mkdtemp(prefix="apache-h2-owned-", dir="/var/tmp/codex/ModSecurity-conector"))
    os.chown(runtime, 0, 65534)
    # Common's no-follow descriptor walk opens each directory for reading.
    # Grant only this owned root's worker group access; shared roots stay intact.
    runtime.chmod(0o750)
    (runtime / "run").mkdir(mode=0o700)
    (runtime / "worker").mkdir(mode=0o700)
    os.chown(runtime / "worker", 65534, 65534)
    for name in ("native-events.jsonl", "native-cleanup.jsonl"):
        path = runtime / "worker" / name
        path.touch(mode=0o600)
        os.chown(path, 65534, 65534)
    scenario = CASES[args.case_id]
    paths = {name: f"/apache-h2/{args.run_id}/{name}" for name in ("target", "peer", "followup")}
    backend = Upstream(scenario, paths)
    thread = threading.Thread(target=backend.serve_forever, daemon=False)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    environment = dict(os.environ, APACHE_ACCEPTANCE_OBSERVER_LOG=str(runtime / "worker/native-cleanup.jsonl"))
    environment["LD_LIBRARY_PATH"] = ":".join(map(str, library_dirs))
    state, error = {"process": None, "handles": {}, "roles": {}, "observer": observer, "port": port,
                    "paths": paths, "environment": environment, "monitor_stop": threading.Event()}, None
    state["monitor"] = threading.Thread(target=observe_cleanup_gate,
        args=(backend, runtime, paths, state["monitor_stop"]), daemon=False)
    thread.start()
    state["monitor"].start()
    try:
        run_host_requests(args, runtime, backend, client, state)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        error = str(exc)
    finally:
        cleanup = retire_resources(args, runtime, backend, thread, port, state)
    write_json(args.output / "cleanup.json", cleanup)
    write_json(args.output / "upstream.json", backend.proof)
    write_json(args.output / "roles.json", state["roles"])
    receipt = {"case_id": args.case_id, "run_id": args.run_id, "parent_sha": args.parent_sha,
               "framework_sha": args.framework_sha, "mrts_sha": args.mrts_sha,
               "source_hash": record["source_hash"], "artifacts": {
                   "httpd": digest(args.httpd_prefix / "bin/httpd"), "module": digest(args.module),
                   "observer": digest(observer), "client": digest(client), "libmodsecurity": digest(modsecurity_library)},
               "source_sha256": source_hashes, "selected_source_state": record["selected_source_state"]}
    receipt["sha256"] = {path.name: digest(path) for path in args.output.iterdir() if path.is_file()}
    write_json(args.output / "receipt.json", receipt)
    require(all(digest(FRAMEWORK / path) == expected for path, expected in source_hashes.items()), "executing runner/client sources changed during host run")
    if error:
        raise ValueError(error)
    return validate_bundle(args.output, args.case_id, paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("httpd-prefix", "module", "component-record", "curl-prefix", "client-build-root", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--library-dir", type=Path, action="append", default=[])
    parser.add_argument("--case-id", choices=sorted(CASES), required=True)
    for name in ("run-id", "parent-sha", "framework-sha", "mrts-sha"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        proof = execute(args)
        result = {"status": "PASS", "case_id": args.case_id, "proof": proof}
        code = 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {"status": "FAIL", "case_id": args.case_id, "reason": str(exc)}
        code = 1
    if args.output.is_dir() and not (args.output / "source-result.json").exists():
        write_json(args.output / "source-result.json", result)
    print(json.dumps(result), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
