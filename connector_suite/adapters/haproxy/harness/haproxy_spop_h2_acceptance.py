#!/usr/bin/env python3
"""Opt-in native SPOP request owner + MRC1/HTX response owner over real H2."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from connector_suite.adapters.envoy.harness.envoy_h2_acceptance import load_json, read_text
from tests.runners.native_h2_probe import WireClient, frame
from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_artifact_root

CASES = ("allow", "phase1", "phase2", "phase3", "phase4_safe", "phase4_strict", "client_cancel", "upstream_reset")
ACCESS_LOG = "access.log"
NATIVE_LOG = "native.log"
AGENT_LOG = "agent.log"
TLS_PEM = "tls.pem"
TLS_CERTIFICATE = "tls.crt"


def require(value, message):
    if not value:
        raise ValueError(message)


def rows(path):
    text = read_text(path)
    require(text.endswith("\n"), "incomplete native writer record")
    return [load_json(line) for line in text.splitlines() if line.startswith("{")]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


def admit_spoa_manifest(receipt, parent, framework, receipt_path):
    require(receipt.get("test_only_observer") is True, "native SPOP observer manifest required")
    source_root = parent / "connectors/haproxy"
    relevant = lambda path: path.suffix in (".c", ".h", ".sh", ".py") or path.name == "Makefile"
    expected = {str(path.relative_to(source_root)): digest(path) for path in source_root.rglob("*")
                if path.is_file() and not path.is_symlink() and relevant(path)}
    actual = receipt.get("production_source_sha256", {})
    require({name: value for name, value in actual.items() if relevant(Path(name))} == expected,
            "closed SPOP product source identity mismatch")
    shared = {str(path.relative_to(parent)): digest(path) for path in
              [*(parent / "common").rglob("*.c"), *(parent / "common").rglob("*.h"),
               parent / "connectors/profile_registry.c", parent / "connectors/profile_registry.h"]}
    actual_shared = receipt.get("shared_source_sha256", {})
    require({name: value for name, value in actual_shared.items() if Path(name).suffix in (".c", ".h")} == shared,
            "closed SPOP shared source identity mismatch")
    helper = framework / "ci/provisioning/prepare-haproxy-spop-h2-test-build.py"
    spec = importlib.util.spec_from_file_location("spop_h2_observer_builder", helper)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    for name, transform in (("haproxy_spop_response_companion_backend.c", builder.observe_backend),
                             ("haproxy_modsecurity_binding.c", builder.observe_binding),
                             ("haproxy_spop_diagnostic_runtime.c", builder.observe_runtime)):
        key = "src/" + name
        expected_observed = hashlib.sha256(transform((source_root / key).read_text()).encode()).hexdigest()
        require(receipt.get("observed_source_sha256", {}).get(key) == expected_observed
                and digest(receipt_path.parent / "source/connectors/haproxy" / key) == expected_observed,
                "SPOP native observer transformation mismatch")
    binary = Path(receipt["binary"])
    require(binary == receipt_path.parent / "build/haproxy-spoa-runtime/haproxy-modsecurity-spoa"
            and not any(path.is_symlink() for path in (binary, *binary.parents)), "unexpected SPOP artifact path")
    descriptor = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1,
                "owned regular SPOP artifact required")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == receipt.get("binary_sha256"), "SPOP binary hash mismatch")
    finally:
        os.close(descriptor)
    library = Path(receipt["modsecurity_library"])
    require(digest(library) == receipt.get("modsecurity_library_sha256"), "SPOP runtime library changed")
    return binary


def configuration(root, port, upstream_port, spoa_port, socket_path, strict):
    return f'''global
    log stdout format raw local0
    nbthread 1
    tune.bufsize 65536
defaults
    mode http
    log global
    timeout connect 2s
    timeout client 10s
    timeout server 10s
frontend combined_h2
    bind 127.0.0.1:{port} ssl crt {root}/tls.pem alpn h2 ssl-min-ver TLSv1.3
    log-format "{{\\"uri\\":\\"%HPO\\",\\"status\\":%ST,\\"bytes\\":%B,\\"termination\\":\\"%tsc\\",\\"transaction_id\\":\\"haproxy-htx-%rt\\",\\"spop_transaction_id\\":\\"%ID\\",\\"client_port\\":%cp,\\"alpn\\":\\"%[ssl_fc_alpn]\\",\\"http_major\\":%[fc_http_major]}}"
    unique-id-format %[uuid()]
    option http-buffer-request
    filter spoe engine modsecurity config {root}/spoe.cfg
    filter modsecurity-htx response-companion-socket {socket_path} response-companion-timeout-ms 2000 response-companion-uid {os.geteuid()} response-companion-gid {os.getegid()} phase4-mode {"strict" if strict else "safe"}
    http-request send-spoe-group modsecurity request-check
    http-request deny status 403 if {{ var(txn.modsec.blocked) -m bool }}
    default_backend app
backend app
    server app 127.0.0.1:{upstream_port}
backend be_spoa
    mode spop
    timeout connect 1s
    timeout server 3s
    server agent 127.0.0.1:{spoa_port}
'''


def spoe_configuration():
    return '''[modsecurity]
spoe-agent modsecurity-agent
    groups request-check
    option var-prefix modsec
    register-var-names blocked action status redirect_url rule_id phase error response_handle
    max-frame-size 65532
    option continue-on-error
    timeout hello 1s
    timeout idle 3s
    timeout processing 2s
    use-backend be_spoa
spoe-group request-check
    messages check-request
spoe-message check-request
    args request_id=unique-id client_ip=src client_port=src_port server_ip=dst server_port=dst_port method=method path=path uri=url host=req.hdr(host) headers_bin=req.hdrs_bin headers=req.hdrs body=req.body body_len=req.body_size http_version=req.ver
'''


def agent_configuration(root, port, socket_path):
    return f'''listen=127.0.0.1:{port}
log-file={root}/spoa.log
decision-log={root}/decision.jsonl
audit-log={root}/audit.jsonl
rules-file={root}/rules.conf
mode=block
fail-mode=closed
runtime-mode=production
response-companion=native-htx
response-phases=true
response-companion-socket={socket_path}
response-companion-uid={os.geteuid()}
response-companion-gid={os.getegid()}
response-body-timeout=2000
spoe-timeout=2000
max-transactions=64
'''


def observed_handoffs(text):
    return re.findall(r"spop-h2-test: event=handoff transaction_id=([^ ]+) handle_sha256=([a-f0-9]{64}) lease=(\d+)", text)


def _validate_wire_body(case, wire, upstream):
    bodies = wire.get("body_bytes", {})
    require(bodies.get("1") == bodies.get("5") == 26, "peer/followup response body missing/incomplete")
    expected_body = {"allow": 26, "phase1": 0, "phase2": 0, "phase3": 93,
                     "phase4_safe": 45, "phase4_strict": 18, "client_cancel": 18, "upstream_reset": 18}[case]
    require(bodies.get("3", 0) == expected_body, "target response body missing/incomplete")
    if case not in ("phase1", "phase2", "phase3"):
        require(upstream.get("first_byte_before_eos") is True, "actual first-byte/EOS barrier missing")
        observation = upstream.get("first_byte_observation", {})
        first_frames = [row for row in wire.get("frames", []) if row.get("type") == 0 and row.get("stream_id") == 3
                        and row.get("size", 0) > 0]
        target_request = next((row for row in wire.get("requests", []) if row.get("stream_id") == 3), {})
        metadata = upstream.get("paths", {}).get(target_request.get("path"), {})
        require(first_frames and observation.get("stream_id") == 3 and observation.get("target_eos_held") is True
                and observation.get("target_eos_sent") is False and observation.get("target_response_finished") is False,
                "paused target metadata missing at first wire DATA")
        first_ns = first_frames[0].get("monotonic_ns", 0)
        observed_ns = observation.get("monotonic_ns", 0)
        written = metadata.get("first_chunk_written_monotonic", 0)
        released = metadata.get("released_monotonic", 0)
        require(isinstance(first_ns, int) and isinstance(observed_ns, int)
                and 0 < written * 1_000_000_000 <= first_ns <= observed_ns <= released * 1_000_000_000
                and observation.get("wire_data_monotonic_ns") == first_ns,
                "wire DATA/paused upstream release chronology mismatch")


def _validate_response_owner(case, role, value, native, spoa):
    transaction = value["spop_transaction_id"]
    htx = value["transaction_id"]
    early_request_deny = role == "target" and case in ("phase1", "phase2")
    if early_request_deny:
        # SPOP denies before the HTX mapper or MRC1 claim can start. Bind
        # the actual unclaimed filter-context detach to the native host
        # stream; do not invent a companion transaction or terminal close.
        stream_number = htx.removeprefix("haproxy-htx-")
        detached = re.findall(r"modsecurity-htx-test: context_detached host_stream_id=" + stream_number
                              + r" handle_present=0 native_released=1 companion_closed=0\b", native)
        require(len(detached) == 1, "unclaimed HTX context was not retired exactly once")
        require(not any(row[0] == transaction for row in observed_handoffs(spoa)), "early deny unexpectedly handed off a response lease")
        require(not re.search(r"modsecurity-htx-test: claim transaction_id=" + re.escape(htx) + r"\b", native),
                "early deny unexpectedly claimed a response lease")
    else:
        htx_cleanup = re.findall(r"modsecurity-htx-test: cleanup transaction_id=" + re.escape(htx)
                                 + r" native_released=1 companion_closed=1\b", native)
        require(len(htx_cleanup) == 1, "native HTX/companion cleanup missing or duplicated")
        handoffs = [row for row in observed_handoffs(spoa) if row[0] == transaction]
        require(len(handoffs) == 1, "SPOP handoff correlation missing/duplicated")
        _, handle_hash, lease = handoffs[0]
        require(len(re.findall(r"spop-h2-test: event=claim transaction_id=none handle_sha256=" + handle_hash
                               + r" lease=" + lease + r"\b", spoa)) == 1, "actual owner lease claim missing")
        require(len(re.findall(r"modsecurity-htx-test: claim transaction_id=" + re.escape(htx)
                               + r" handle_sha256=" + handle_hash + r"\b", native)) == 1,
                "cross-process handle claim mismatch")


def _validate_role(wire, value, stream, spoa, decisions, sent):
    require(value.get("http_major") == 2 and value.get("alpn") == "h2", "native H1 fallback")
    require(wire.get("status", {}).get(stream) == value.get("status"), "wire/native status mismatch")
    require(re.fullmatch(r"haproxy-htx-\d+", value.get("transaction_id", "")) is not None, "invalid native HTX ID")
    require(re.fullmatch(r"[a-f0-9-]{36}", value.get("spop_transaction_id", "")) is not None, "invalid server-issued SPOP ID")
    transaction = value["spop_transaction_id"]
    require(any(row.get("transaction_id") == transaction and row.get("modsecurity_processed") is True for row in decisions),
            "real SPOP engine request evaluation missing")
    native_path = value["uri"]
    if not native_path.startswith("/"):
        parsed = urlsplit(native_path)
        require(parsed.scheme == "https" and parsed.hostname == "127.0.0.1" and parsed.port is not None
                and not parsed.fragment and parsed.username is None, "unexpected native absolute-form URI")
        native_path = parsed.path + ("?" + parsed.query if parsed.query else "")
    require(next(row for row in sent if row["stream_id"] == int(stream)).get("path") == native_path, "wire/native role mapping mismatch")
    released = re.findall(r"spop-h2-test: event=cleanup transaction_id=" + re.escape(transaction)
                          + r" native_cleanup_returned=1 contract_cleared=1\b", spoa)
    require(len(released) == 1, "native SPOP cleanup missing or duplicated")


def _validate_rule(case, selected, native, spoa, decisions):
    expected_rule = {"phase1": 1100001, "phase2": 1100101, "phase3": 1100201, "phase4_safe": 1100301, "phase4_strict": 1100301}.get(case)
    if expected_rule and case not in ("phase4_safe", "phase4_strict"):
        expected_phase = {"phase1": 1, "phase2": 2, "phase3": "response_headers"}[case]
        native_decisions = [row for row in decisions if row.get("transaction_id") == selected["target"]["spop_transaction_id"]
                            and row.get("rule_id") not in (None, 0, "", "0")]
        require(len(native_decisions) == 1 and str(native_decisions[0].get("rule_id")) == str(expected_rule)
                and native_decisions[0].get("phase") == expected_phase, "native SPOP rule correlation missing/duplicated/wrong phase")
    if case in ("phase4_safe", "phase4_strict"):
        expected_action = "log_only" if case == "phase4_safe" else "abort_connection"
        owner = selected["target"]["spop_transaction_id"]
        require(len(re.findall(r"spop-h2-test: event=owner_eos transaction_id=" + re.escape(owner)
                              + r" phase=4 rule_id=1100301 status=403 disruptive=1\b", spoa)) == 1,
                "native owner EOS rule correlation missing/duplicated")
        # Current owner-to-MRC1 bridge intentionally omits RuleID. Join the
        # original owner decision through the uniquely claimed hashed handle;
        # keep native host action and actual wire reset as separate witnesses.
        require(re.search(r"response-companion phase-4 intervention; transaction_id="
                + re.escape(selected["target"]["transaction_id"]) + r" rule_id= requested=deny host_action="
                + expected_action + r"\b", native) is not None, "native HTX host-action witness missing")


def _validate_stream_terminals(case, wire, selected, sent):
    require(selected["target"]["status"] == (403 if case in ("phase1", "phase2", "phase3") else 200), "wrong target status")
    for role, stream in (("peer", "1"), ("followup", "5")):
        require(selected[role]["status"] == 200 and wire.get("terminal", {}).get(stream, {}).get("type") in (0, 1)
                and wire["terminal"][stream].get("flags", 0) & 1, "unrelated stream damaged/incomplete")
    if case not in ("phase4_strict", "upstream_reset", "client_cancel"):
        require(wire.get("terminal", {}).get("3", {}).get("type") in (0, 1)
                and wire["terminal"]["3"].get("flags", 0) & 1, "normal target response reset/incomplete")
    if case in ("phase4_strict", "upstream_reset"):
        require(wire.get("terminal", {}).get("3", {}).get("type") == 3 and wire["terminal"]["3"].get("reset_code") == 8,
                "actual target RST_STREAM missing")
    if case == "client_cancel":
        require(len([row for row in wire.get("frames", []) if row.get("type") == "client_rst_stream" and row.get("stream_id") == 3
                     and row.get("reset_code") == 8]) == 1, "actual target client cancellation missing")
    if case == "phase2":
        target_request = next(row for row in sent if row["stream_id"] == 3)
        require(target_request.get("method") == "POST" and target_request.get("body_bytes") == 26, "real P2 request entity missing")


def validate_case(case, wire, access, native, spoa, decisions, upstream, cleanup):
    require(case in CASES and len(access) == 3, "unknown case or incomplete native access")
    require(cleanup.get("verified") is True and cleanup.get("socket_removed") is True and cleanup.get("tls_removed") is True, "cleanup failed")
    require(wire.get("alpn") == "h2" and wire.get("tls_verified") is True, "TLS/H2 fallback")
    require(upstream.get("driver_error") is None, "upstream fixture failed")
    require(wire.get("tls_version") == "TLSv1.3", "unexpected TLS protocol")
    _validate_wire_body(case, wire, upstream)

    selected = {}
    sent = wire.get("requests", [])
    require(len(sent) == 3 and {row.get("stream_id") for row in sent} == {1, 3, 5}, "missing/reused actual wire stream")
    for role, stream in (("peer", "1"), ("target", "3"), ("followup", "5")):
        candidates = [row for row in access if row.get("uri", "").endswith("/" + role)]
        require(len(candidates) == 1, "missing/duplicate role")
        value = candidates[0]
        _validate_role(wire, value, stream, spoa, decisions, sent)
        _validate_response_owner(case, role, value, native, spoa)
        selected[role] = value
    handoffs = observed_handoffs(spoa)
    expected_owners = {row["spop_transaction_id"] for role, row in selected.items()
                       if not (role == "target" and case in ("phase1", "phase2"))}
    require(len(handoffs) == len(expected_owners) and {row[0] for row in handoffs} == expected_owners
            and len({row[1] for row in handoffs}) == len(handoffs), "foreign/reused cross-process response handle")
    require(len({row["client_port"] for row in selected.values()}) == 1, "physical connection replaced")
    require(len({row["transaction_id"] for row in selected.values()}) == len({row["spop_transaction_id"] for row in selected.values()}) == 3,
            "transaction reused across streams")
    _validate_stream_terminals(case, wire, selected, sent)
    require(set(re.findall(r"spop-h2-test: event=cleanup transaction_id=([^ ]+)", spoa))
            == {row["spop_transaction_id"] for row in selected.values()}, "foreign native SPOP transaction")
    require(upstream.get("target_cleanup_before_peer_release") is True and upstream.get("all_cleanup_before_tls_close") is True,
            "cleanup was deferred beyond active-peer/TLS barrier")
    _validate_rule(case, selected, native, spoa, decisions)
    return {"case_id": "haproxy_spop_htx_h2_" + case, "status": "PASS", "transactions": selected,
            "native_cleanup_count": 3, "cross_process_handle_correlation": True}


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def close_wire(client, error):
    """Retain writer failure while permitting all independent host cleanup."""
    if client:
        try:
            client.close()
        except (OSError, ValueError) as exception:
            return error or f"wire evidence writer failed: {exception}"
    return error


def access_rows(root):
    return rows(root / ACCESS_LOG) if (root / ACCESS_LOG).exists() else []


def native_completed(root, case, role):
    values = [row for row in access_rows(root) if row.get("uri", "").endswith("/" + role)]
    if len(values) != 1:
        return False
    native = read_text(root / NATIVE_LOG)
    agent = read_text(root / AGENT_LOG)
    row = values[0]
    agent_done = f"event=cleanup transaction_id={row['spop_transaction_id']} native_cleanup_returned=1 contract_cleared=1" in agent
    if role == "target" and case in ("phase1", "phase2"):
        number = row["transaction_id"].removeprefix("haproxy-htx-")
        host_done = f"context_detached host_stream_id={number} handle_present=0 native_released=1 companion_closed=0" in native
    else:
        host_done = f"cleanup transaction_id={row['transaction_id']} native_released=1 companion_closed=1" in native
    return agent_done and host_done


def wait_native(predicate, message, processes, client, timeout):
    deadline = time.monotonic() + timeout
    while not predicate():
        require(time.monotonic() < deadline and all(process.poll() is None for _, process in processes), message)
        if client:
            client.poll()
        else:
            time.sleep(0.02)


def exercise(client, case, paths, upstream, wait, completed):
    # The SPOP ownership boundary accepts one complete bounded body
    # sample. HTTP/2 END_STREAM is not represented in its NOTIFY ABI;
    # an explicit zero Content-Length proves this empty sample.
    client.request(1, paths["peer"], "peer", headers=(("content-length", "0"),))
    wait(lambda: paths["peer"] in upstream.proof["paths"] and client.status.get(1) == 200,
         "allowed peer not active")
    client.request(3, paths["target"], "target", body=b"no-crs-request-body-marker" if case == "phase2" else b"", phase1=case == "phase1",
                   headers=() if case == "phase2" else (("content-length", "0"),))
    if case in ("phase1", "phase2", "phase3"):
        client.wait(lambda: 3 in client.terminal)
    else:
        client.wait(lambda: client.bytes.get(3, 0) > 0)
        require(not upstream.release.is_set() and 3 not in client.terminal, "first-byte/EOS barrier failed")
        upstream.proof["first_byte_before_eos"] = True
        data = next(row for row in client.records if row.get("type") == 0 and row.get("stream_id") == 3 and row.get("size", 0) > 0)
        target_metadata = upstream.proof["paths"][paths["target"]]
        require(not target_metadata.get("eos_sent") and not target_metadata.get("response_finished"), "upstream target already ended at first wire DATA")
        upstream.proof["first_byte_observation"] = {"stream_id": 3, "wire_data_monotonic_ns": data["monotonic_ns"],
            "monotonic_ns": time.monotonic_ns(), "target_eos_held": True,
            "target_eos_sent": bool(target_metadata.get("eos_sent")), "target_response_finished": bool(target_metadata.get("response_finished"))}

        if case == "client_cancel":
            client.socket.sendall(frame(3, 0, 3, (8).to_bytes(4, "big")))
            client.records.append({"type": "client_rst_stream", "stream_id": 3, "reset_code": 8})
        else:
            upstream.release.set()
            client.wait(lambda: 3 in client.terminal)
    wait(lambda: completed("target"), "target native SPOP/companion cleanup missing while peer held")
    require(1 not in client.terminal and not upstream.peer_release.is_set(), "allowed peer ended before target cleanup")
    upstream.proof["target_cleanup_before_peer_release"] = True
    upstream.release.set()
    upstream.peer_release.set()
    client.wait(lambda: 1 in client.terminal)
    client.request(5, paths["followup"], "followup", headers=(("content-length", "0"),))
    client.wait(lambda: 5 in client.terminal)
    wait(lambda: all(completed(role) for role in ("peer", "target", "followup")), "native cleanup missing before TLS close")
    upstream.proof["all_cleanup_before_tls_close"] = True


def cleanup_native(client, error, upstream, processes, thread, thread_started, root, socket_path, socket_root, shared, port, agent_port):
    error = close_wire(client, error)
    upstream.release.set(); upstream.peer_release.set()
    for _, process in reversed(processes):
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=3)
            error = error or "native host forced shutdown"
    if thread_started:
        upstream.shutdown()
    upstream.server_close()
    if thread_started:
        thread.join(timeout=3)
    (root / TLS_PEM).unlink(missing_ok=True)
    if socket_path.exists():
        metadata = socket_path.lstat()
        require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.geteuid(), "refusing foreign UDS cleanup")
        socket_path.unlink()
    cleanup = {"verified": all(process.poll() is not None for _, process in processes) and not thread.is_alive()
               and not shared.HOST.listener_open(port) and not shared.HOST.listener_open(agent_port),
               "process_returncodes": {name: process.returncode for name, process in processes},
               "socket_removed": not socket_path.exists(), "tls_removed": not any((root / name).exists() for name in (TLS_PEM, TLS_CERTIFICATE, "tls.key"))}
    upstream.proof["driver_error"] = error or upstream.proof["driver_error"]
    write(root / "cleanup.json", cleanup)
    write(root / "upstream.json", upstream.proof)
    socket_root.rmdir()
    return cleanup, error


def run_case(args, case, root, socket_root, shared):
    root.mkdir(mode=0o700)
    socket_root.mkdir(mode=0o700)
    socket_path = socket_root / "m.sock"
    require(len(os.fsencode(socket_path)) < 100, "private UDS path too long")
    subprocess.run([sys.executable, "-P", "-m", "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
                    "--execution-context-only", "--connector", "haproxy", "--profile", "haproxy-spoe-spop-h2",
                    "--runtime-root", str(root), "--output-dir", str(root / "preflight"),
                    "--uds-root", str(socket_root), "--uds-path", str(socket_path)], check=True,
                   stdout=(root / "preflight.log").open("xb"), stderr=subprocess.STDOUT)
    scenario = shared.SCENARIOS[case]
    paths = {role: f"/acceptance/spop-{case}/{role}" for role in ("peer", "target", "followup")}
    port, agent_port = free_port(), free_port()
    upstream = shared.STREAM.Upstream(scenario, paths)
    thread = threading.Thread(target=upstream.serve_forever, daemon=False)
    thread_started = False
    processes, client = [], None
    error = None
    def wait(predicate, message, timeout=4):
        wait_native(predicate, message, processes, client, timeout)
    def access():
        return rows(root / ACCESS_LOG) if (root / ACCESS_LOG).exists() else []
    def completed(role):
        return native_completed(root, case, role)
    try:
        thread.start()
        thread_started = True
        rules = (args.framework_root / "tests/rules/protocol-acceptance.conf").read_text()
        rules += '\nSecRule REQUEST_HEADERS:X-Modsec-Smoke "@streq block" "id:1100001,phase:1,deny,status:403,log,t:none"\n'
        rules += '\nSecRule REQUEST_BODY "@contains no-crs-request-body-marker" "id:1100101,phase:2,deny,status:403,log,t:none"\n'
        (root / "rules.conf").write_text(rules)
        (root / "spoe.cfg").write_text(spoe_configuration())
        (root / "agent.conf").write_text(agent_configuration(root, agent_port, socket_path))
        with shared.STREAM.MODERN.tls_material(root):
            (root / TLS_PEM).write_bytes((root / "tls.key").read_bytes() + (root / TLS_CERTIFICATE).read_bytes())
            (root / "haproxy.cfg").write_text(configuration(root, port, upstream.server_port, agent_port, socket_path, case == "phase4_strict"))
            subprocess.run([str(args.haproxy), "-c", "-f", str(root / "haproxy.cfg")], check=True,
                           stdout=(root / "config-check.log").open("xb"), stderr=subprocess.STDOUT)
            for name, command in (("agent", [str(args.spoa), "--config", str(root / "agent.conf")]),
                                   ("haproxy", [str(args.haproxy), "-db", "-f", str(root / "haproxy.cfg")])):
                output = (root / (ACCESS_LOG if name == "haproxy" else "agent.stdout.log")).open("xb")
                log = (root / (NATIVE_LOG if name == "haproxy" else AGENT_LOG)).open("xb")
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=log)
                output.close(); log.close()
                processes.append((name, process))
                if name == "agent":
                    wait(lambda: socket_path.is_socket(), "native MRC1 listener missing")
            def listening():
                with socket.socket() as probe:
                    return probe.connect_ex(("127.0.0.1", port)) == 0
            wait(listening, "native HAProxy listener missing")
            client = WireClient(port, root / TLS_CERTIFICATE, root / "wire.json")
            exercise(client, case, paths, upstream, wait, completed)
    except (OSError, ValueError, subprocess.SubprocessError) as exception:
        error = str(exception)
    finally:
        cleanup, error = cleanup_native(client, error, upstream, processes, thread, thread_started, root,
                                        socket_path, socket_root, shared, port, agent_port)
    require(error is None, error or "host failed")
    result = validate_case(case, load_json(read_text(root / "wire.json")), access(), read_text(root / NATIVE_LOG),
                           read_text(root / AGENT_LOG), rows(root / "decision.jsonl"), upstream.proof, cleanup)
    write(root / "result.json", result)
    return result


def reserve_runtime_root(directory):
    require(".." not in directory.parts and directory.is_relative_to(Path("/var/tmp/codex/ModSecurity-conector"))
            and not directory.exists() and not any(parent.is_symlink() for parent in directory.parents),
            "fresh task-owned external root required")
    previous_mask = os.umask(0o077)
    try:
        return verified_runtime_artifact_root(directory)
    finally:
        os.umask(previous_mask)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("connector-root", "framework-root", "runtime-root", "socket-root", "haproxy", "spoa", "haproxy-provenance", "spoa-provenance"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--connector-revision", required=True)
    parser.add_argument("--framework-revision", required=True)
    parser.add_argument("--case", choices=CASES)
    args = parser.parse_args()
    for checkout, revision in ((args.connector_root, args.connector_revision), (args.framework_root, args.framework_revision)):
        require(subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip() == revision, "selected source revision mismatch")
    require(args.framework_root.resolve() == Path(__file__).resolve().parents[4], "Framework driver source selection mismatch")
    os.environ.update(CONNECTOR_ROOT=str(args.connector_root), CONNECTOR_REVISION=args.connector_revision,
                      TEST_ROOT=str(args.framework_root), FRAMEWORK_REVISION=args.framework_revision,
                      PYTHONPATH=f"{args.framework_root}:{args.framework_root / 'connector_suite'}")
    sys.path.insert(0, str(args.framework_root / "connector_suite"))
    from connector_suite.adapters.haproxy.harness import haproxy_h2_acceptance as shared
    require(shared.admit_manifest(load_json(read_text(args.haproxy_provenance)), args.connector_root,
                                  args.framework_root, args.haproxy_provenance) == args.haproxy,
            "HAProxy selected artifact differs from admitted native artifact")
    require(admit_spoa_manifest(load_json(read_text(args.spoa_provenance)), args.connector_root,
                               args.framework_root, args.spoa_provenance) == args.spoa,
            "SPOP selected artifact differs from admitted native artifact")
    root, sockets = args.runtime_root.absolute(), args.socket_root.absolute()
    for directory in (root, sockets):
        reserve_runtime_root(directory)
    report = {"profile": "haproxy-spop-htx-h2", "results": [], "status": "FAIL",
              "source_revisions": {"parent": args.connector_revision, "framework": args.framework_revision},
              "uid_contract": {"uid": os.geteuid(), "gid": os.getegid(), "selection": "existing combined profile inherits launcher credentials"},
              "artifact_admission": {name: {"manifest": str(path), "manifest_sha256": digest(path),
                   "historical_build_parent": load_json(read_text(path))["parent_sha"],
                   "current_product_source_equivalence": True} for name, path in
                   (("haproxy", args.haproxy_provenance), ("spoa", args.spoa_provenance))},
              "driver_sha256": digest(Path(__file__)), "full_acceptance_campaign": "NOT_RUN",
              "request_sample_contract": "Empty HTTP/2 bodies carry explicit Content-Length:0; SPOP NOTIFY has no trusted HTTP END_STREAM marker.",
              "phase4_evidence_contract": "Native owner EOS UUID/phase/rule/status is logged before MRC1 serialization and joined through unique SHA256(handle)/lease to HTX host action and independent wire. Current MRC1 owner bridge omits forwarded RuleID. Strict native HTX shutdown returns without Common OUTCOME; no observed Common abort is invented."}
    for case in (args.case,) if args.case else CASES:
        try:
            report["results"].append(run_case(args, case, root / case, sockets / case, shared))
        except (OSError, ValueError, subprocess.SubprocessError) as exception:
            report["results"].append({"case_id": "haproxy_spop_htx_h2_" + case, "status": "FAIL", "error": str(exception)})
    report["status"] = "PASS" if report["results"] and all(row["status"] == "PASS" for row in report["results"]) else "FAIL"
    write(root / "report.json", report)
    if not any(sockets.iterdir()):
        sockets.rmdir()
    print(json.dumps({"status": report["status"], "report": str(root / 'report.json')}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
