#!/usr/bin/env python3
"""Opt-in real native HTX H2 cases with independent wire/lifecycle witnesses."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import threading
import time

from modsecurity_test_framework.connector_context import load_source
from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_artifact_root
from tests.runners.native_h2_probe import WireClient, frame
from connector_suite.adapters.envoy.harness.envoy_h2_acceptance import load_json

LIFECYCLE = Path(__file__).resolve().parents[3] / "modsecurity_connector_ci/runtime/lifecycle"
STREAM = load_source(LIFECYCLE / "run-protocol-acceptance.py")
HOST = STREAM.HOST
BUILDER = load_source(Path(__file__).resolve().parents[4] / "ci/provisioning/prepare-haproxy-h2-test-build.py")
NATIVE_LOG = 'native.log'
TLS_CERTIFICATE = 'tls.crt'
TLS_COMBINED = 'tls.pem'
HOST_CONFIGURATION = 'haproxy.cfg'
ACCESS_LOG = 'access.log'
WIRE_EVIDENCE = 'wire.json'
COMMON_EVIDENCE = 'common.jsonl'
CASES = ("allow", "phase1", "phase2", "phase3", "phase4_safe", "phase4_strict", "client_cancel", "upstream_reset")
SCENARIOS = {"allow": "streaming", "phase1": "multiplex", "phase2": "phase2", "phase3": "phase3",
             "phase4_safe": "safe", "phase4_strict": "strict", "client_cancel": "client-cancel",
             "upstream_reset": "upstream-reset"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def read(path):
    # Use the already bounded, no-follow, duplicate-key-rejecting evidence API.
    from connector_suite.adapters.envoy.harness.envoy_h2_acceptance import read_text
    return read_text(path)


def rows(path):
    from connector_suite.adapters.envoy.harness.envoy_h2_acceptance import load_json
    text = read(path)
    require(text.endswith("\n") and text.strip(), "complete nonempty JSONL required")
    result = [load_json(line) for line in text.splitlines()]
    require(all(isinstance(row, dict) for row in result), "JSONL object rows required")
    return result


def admit_manifest(manifest, parent, framework, manifest_path):
    require(manifest.get("schema_version") == 1 and manifest.get("test_only_observer") is True,
            "native test observer manifest required")
    require(manifest.get("parent_source_sha256") == BUILDER.parent_source_hashes(parent),
            "closed current product source identity mismatch")
    require(digest(framework / "ci/provisioning/prepare-haproxy-h2-test-build.py") == manifest.get("observer_source_sha256"),
            "observer source changed")
    binary = Path(manifest["binary"])
    expected = manifest_path.parent / "overlay/worktree/haproxy"
    require(binary == expected and not any(path.is_symlink() for path in (binary, *binary.parents)),
            "unexpected native binary location or symlink")
    descriptor = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1,
                "owned regular native artifact required")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == manifest.get("binary_sha256"),
                    "host artifact mismatch")
    finally:
        os.close(descriptor)
    library = Path(manifest["modsecurity_library"])
    require(library.is_absolute() and digest(library) == manifest.get("modsecurity_library_sha256"),
            "native runtime library changed")
    product_filter = parent / "connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c"
    require(digest(product_filter) == manifest.get("production_filter_sha256"), "production filter identity mismatch")
    expected_observer = BUILDER.observe_filter(product_filter.read_text()).encode()
    require(hashlib.sha256(expected_observer).hexdigest() == manifest.get("observed_filter_sha256")
            and digest(binary.parent / "src/haproxy_modsecurity_htx_filter.c") == manifest["observed_filter_sha256"],
            "native test observer differs from its admitted transformation")
    return binary


def configuration(root, port, upstream, strict):
    return f'''global
    log stdout format raw local0
    user nobody
    group nogroup
    nbthread 1
defaults
    mode http
    log global
    timeout connect 2s
    timeout client 10s
    timeout server 10s
frontend h2_acceptance
    bind 127.0.0.1:{port} ssl crt {root}/tls.pem alpn h2 ssl-min-ver TLSv1.3
    log-format "{{\\"uri\\":\\"%HPO\\",\\"status\\":%ST,\\"transaction_id\\":\\"haproxy-htx-%rt\\",\\"client_port\\":%cp,\\"alpn\\":\\"%[ssl_fc_alpn]\\",\\"http_major\\":%[fc_http_major],\\"bytes\\":%B,\\"termination\\":\\"%tsc\\"}}"
    filter modsecurity-htx rules-file {root}/rules.conf phase4-mode {"strict" if strict else "safe"} events-file {root}/common.jsonl
    default_backend acceptance_upstream
backend acceptance_upstream
    server upstream 127.0.0.1:{upstream}
'''


def observe_target_cleanup(client, upstream, paths, root):
    deadline = time.monotonic() + 3
    while True:
        native = read(root / NATIVE_LOG)
        admitted = re.findall(r"modsecurity-htx-test: admitted transaction_id=(haproxy-htx-\d+)\b", native)
        require(len(admitted) <= 2, "foreign/duplicated native stream admission")
        if len(admitted) == 2:
            transaction = admitted[1]
            witness = f"modsecurity-htx-test: cleanup transaction_id={transaction} native_released=1 companion_closed=1"
            if witness in native:
                require(1 not in client.terminal and not upstream.proof["paths"][paths["peer"]].get("response_finished"),
                        "peer finished before request-local cleanup")
                upstream.proof["target_cleanup_while_peer_held"] = {
                    "transaction_id": transaction, "witness": witness,
                    "monotonic_ns": time.monotonic_ns(), "peer_terminal": False,
                    "peer_eos_sent": upstream.proof["paths"][paths["peer"]].get("eos_sent")}
                return
        require(time.monotonic() < deadline, "target native cleanup waited for peer/physical close")
        client.poll()


def exercise(client, upstream, paths, scenario, root):
    client.request(1, paths["peer"], "held-peer")
    deadline = time.monotonic() + 5
    while paths["peer"] not in upstream.proof["paths"]:
        require(time.monotonic() < deadline, "native upstream never admitted held peer")
        client.poll()
    client.request(3, paths["target"], "target", body=b"no-crs-request-body-marker" if scenario == "phase2" else b"")
    if scenario in ("multiplex", "phase2", "phase3"):
        client.wait(lambda: 3 in client.terminal)
        require(1 not in client.terminal, "peer ended before target denial")
        observe_target_cleanup(client, upstream, paths, root)
        upstream.proof["peer_held_until_target_observed"] = True
        upstream.peer_release.set()
    else:
        client.wait(lambda: client.bytes.get(3, 0) > 0)
        target = upstream.proof["paths"].get(paths["target"], {})
        require(not target.get("eos_sent") and not upstream.release.is_set() and 3 not in client.terminal,
                "first-byte observation did not precede actual upstream EOS")
        upstream.proof["first_byte_before_eos"] = True
        if scenario == "client-cancel":
            client.socket.sendall(frame(3, 0, 3, (8).to_bytes(4, "big")))
            client.records.append({"type": "client_rst_stream", "stream_id": 3,
                                   "reset_code": 8, "monotonic_ns": time.monotonic_ns()})
            upstream.proof["client_cancel_sent_before_release"] = True
        if scenario == "client-cancel":
            # Keep both response producers paused until the native target
            # stream is actually retired, so ordinary EOS cannot win the race.
            observe_target_cleanup(client, upstream, paths, root)
        upstream.release.set()
        if scenario != "client-cancel":
            client.wait(lambda: 3 in client.terminal)
            observe_target_cleanup(client, upstream, paths, root)
        require(1 not in client.terminal, "held peer finished before target terminal")
        upstream.proof["peer_held_until_target_observed"] = True
        upstream.peer_release.set()
    client.wait(lambda: 1 in client.terminal)
    client.request(5, paths["followup"], "followup")
    client.wait(lambda: 5 in client.terminal)


def select_native_transactions(case, access, native_text, run_id):
    selected = {}
    for role in ("target", "peer", "followup"):
        path = f"/acceptance/{run_id}-{case}/{role}"
        found = [row for row in access if row.get("uri") == path]
        require(len(found) == 1, "native access missing or duplicate")
        row = found[0]
        require(row.get("alpn") == "h2" and row.get("http_major") == 2, "native H2 fallback")
        transaction = row.get("transaction_id")
        require(isinstance(transaction, str) and re.fullmatch(r"haproxy-htx-\d+", transaction), "invalid native transaction")
        starts = re.findall(r"modsecurity-htx-test: admitted transaction_id=" + re.escape(transaction) + r"\b", native_text)
        ends = re.findall(r"modsecurity-htx-test: cleanup transaction_id=" + re.escape(transaction)
                          + r" native_released=(\d+) companion_closed=(\d+)\b", native_text)
        require(len(starts) == len(ends) == 1 and ends[0] == ("1", "1"), "actual native cleanup missing/duplicated/failed")
        selected[role] = row
    require(len(access) == 3 and len({row["transaction_id"] for row in selected.values()}) == 3,
            "foreign/reused native transactions")
    identities = {row["transaction_id"] for row in selected.values()}
    for marker in ("admitted", "cleanup"):
        observed = re.findall(r"modsecurity-htx-test: " + marker + r" transaction_id=(haproxy-htx-\d+)\b", native_text)
        require(len(observed) == 3 and set(observed) == identities, "foreign or duplicated native lifecycle")
    require(len({row.get("client_port") for row in selected.values()}) == 1, "physical connection changed")
    return selected


def validate_wire_requests(case, wire, selected):
    sent = wire.get("requests", [])
    require(len(sent) == 3 and {row.get("stream_id") for row in sent} == {1, 3, 5},
            "actual wire request identities missing/reused")
    statuses = wire.get("status", {})
    for role, stream in (("peer", "1"), ("target", "3"), ("followup", "5")):
        request = next(row for row in sent if row.get("stream_id") == int(stream))
        require(request.get("path") == selected[role]["uri"], "wire/native exact URI mismatch")
        require(request.get("method") == ("POST" if case == "phase2" and role == "target" else "GET"),
                "wire request method mismatch")
        require(statuses.get(stream) == selected[role]["status"], "independent wire/native status mismatch")
    return sent


def validate_unrelated_streams(wire, selected):
    terminals = wire.get("terminal", {})
    for role, stream in (("peer", "1"), ("followup", "5")):
        require(selected[role]["status"] == 200 and terminals.get(stream, {}).get("type") in (0, 1), "unrelated stream failed")
        require(isinstance(wire.get("body_bytes", {}).get(stream), int) and wire["body_bytes"][stream] > 0,
                "unrelated stream payload missing")


def validate_upstream_proof(case, selected, upstream, native_text):
    require(upstream.get("peer_held_until_target_observed") is True, "missing peer barrier")
    early_cleanup = upstream.get("target_cleanup_while_peer_held", {})
    require(early_cleanup.get("transaction_id") == selected["target"]["transaction_id"]
            and early_cleanup.get("peer_terminal") is False and early_cleanup.get("peer_eos_sent") is False
            and early_cleanup.get("witness") in native_text,
            "target cleanup lacks independent active-peer/native identity binding")
    require(all(not value.get("write_error") and not value.get("writer_error")
                for value in upstream.get("paths", {}).values()), "upstream writer failed")
    expected_paths = {selected[role]["uri"] for role in ("peer", "followup")}
    if case not in ("phase1", "phase2"):
        expected_paths.add(selected["target"]["uri"])
    require(set(upstream.get("paths", {})) == expected_paths, "upstream request suppression/correlation mismatch")
    require(all(value.get("arrivals") == 1 for value in upstream["paths"].values()), "duplicate upstream request")
    require(all(upstream["paths"][selected[role]["uri"]].get("eos_sent") is True
                and upstream["paths"][selected[role]["uri"]].get("response_finished") is True
                for role in ("peer", "followup")), "unrelated upstream response incomplete")


def validate_target_outcome(case, wire, upstream, selected):
    terminals = wire.get("terminal", {})
    expected = 403 if case in ("phase1", "phase2", "phase3") else 200
    require(selected["target"]["status"] == expected, "wrong target native status")
    if case in ("allow", "phase4_safe", "phase4_strict", "client_cancel", "upstream_reset"):
        require(upstream.get("first_byte_before_eos") is True, "full response buffering or missing barrier")
        require(isinstance(wire.get("body_bytes", {}).get("3"), int) and wire["body_bytes"]["3"] > 0,
                "target wire payload missing before EOS")
    if case in ("phase4_strict", "upstream_reset"):
        require(terminals.get("3", {}).get("type") == 3 and terminals["3"].get("reset_code", 0) > 0,
                "actual target RST_STREAM missing")
    elif case == "client_cancel":
        require(upstream.get("client_cancel_sent_before_release") is True
                and any(row.get("type") == "client_rst_stream" and row.get("stream_id") == 3 for row in wire["frames"]),
                "actual client cancellation missing")
    else:
        require(terminals.get("3", {}).get("type") in (0, 1), "unexpected target reset")


def validate_phase4_decisions(case, decisions, selected, native_text):
    require(all(row.get("eos_seen") is True and row.get("response_committed") is True
                and row.get("late_intervention") is True for row in decisions), "P4 EOS/commit proof missing")
    action = {"phase4_safe": "log_only", "phase4_strict": "abort_connection"}[case]
    # The Common record explicitly reports only an engine request.
    # Join it to the separate original host-action diagnostic and wire.
    require(all(row.get("requested_action") == "deny" and row.get("actual_action") == ""
                and row.get("transport_result") == "not_observable" for row in decisions),
            "engine request and host action were conflated")
    witness = ("modsecurity-htx: response-body late intervention observed; transaction_id="
               + selected["target"]["transaction_id"] + " phase=4 status=403 rule_id=1100301"
               + " requested_action=deny resolved_policy_action=" + action + " host_action=" + action)
    require(native_text.count(witness) == 1, "actual native late host action missing/ambiguous")


def validate_rule_decisions(case, common, selected, sent, native_text):
    expected_rule = {"phase1": 1100001, "phase2": 1100101, "phase3": 1100201,
                     "phase4_safe": 1100301, "phase4_strict": 1100301}.get(case)
    if not expected_rule:
        return
    decisions = [row for row in common if row.get("transaction_id") == selected["target"]["transaction_id"]
                 and str(row.get("rule_id")) == str(expected_rule)]
    require(decisions, "native rule correlation missing")
    phase = {"phase1": "request_headers", "phase2": "request_body", "phase3": "response_headers",
             "phase4_safe": "response_body", "phase4_strict": "response_body"}[case]
    require(all(row.get("connector") == "haproxy" and row.get("integration_mode") == "native-htx"
                and row.get("phase") == phase for row in decisions), "native phase/profile crossover")
    if case == "phase2":
        request = next(row for row in sent if row["stream_id"] == 3)
        require(request.get("body_bytes") == len(b"no-crs-request-body-marker"), "actual P2 body missing")
    if case.startswith("phase4"):
        validate_phase4_decisions(case, decisions, selected, native_text)


def validate_case(case, wire, access, native_text, common, upstream, cleanup, run_id):
    require(case in CASES, "unknown case")
    require(cleanup.get("verified") is True and cleanup.get("tls_removed") is True, "cleanup failed")
    require(wire.get("alpn") == "h2" and wire.get("tls_verified") is True, "H2 TLS fallback")
    require(upstream.get("driver_error") is None, "upstream driver error")
    selected = select_native_transactions(case, access, native_text, run_id)
    sent = validate_wire_requests(case, wire, selected)
    validate_unrelated_streams(wire, selected)
    validate_upstream_proof(case, selected, upstream, native_text)
    validate_target_outcome(case, wire, upstream, selected)
    validate_rule_decisions(case, common, selected, sent, native_text)
    require(all(row.get("transaction_id") in {v["transaction_id"] for v in selected.values()} for row in common),
            "foreign native decision")
    require(all(str(row.get("rule_id", "")) in ("", "0", "None") or row.get("transaction_id") == selected["target"]["transaction_id"]
                for row in common), "rule crossed streams")
    return {"case_id": "haproxy_htx_h2_" + case, "run_id": run_id, "status": "PASS", "transactions": selected,
            "actual_h2": True, "physical_connection_reused": True, "native_cleanup_count": 3}


def close_wire_client(client, error):
    if client is not None:
        try:
            client.close()
        except (OSError, ValueError) as exc:
            error = error or f"wire evidence writer failed: {exc}"
    return error


def stop_owned_host(process, handles):
    forced = False
    if process is not None and process.poll() is None:
        HOST.bind_owned_children(process, handles)
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            forced = True
    children_forced, running = HOST.retire_bound_children(handles)
    for handle in handles.values():
        os.close(handle)
    return forced, children_forced, running


def finish_runtime(client, upstream, process, thread, thread_started, port, roles, handles, root, error):
    error = close_wire_client(client, error)
    upstream.release.set()
    upstream.peer_release.set()
    forced, children_forced, running = stop_owned_host(process, handles)
    if thread_started:
        upstream.shutdown()
    upstream.server_close()
    if thread_started:
        thread.join(timeout=3)
    (root / TLS_COMBINED).unlink(missing_ok=True)
    cleanup = {"verified": bool(roles) and not (forced or children_forced or running or thread.is_alive() or HOST.listener_open(port)),
               "master_stopped": process is None or process.poll() is not None,
               "bound_workers_running": running, "upstream_stopped": not thread.is_alive(),
               "tls_removed": not any((root / name).exists() for name in (TLS_COMBINED, "tls.key", TLS_CERTIFICATE))}
    upstream.proof["driver_error"] = error or upstream.proof["driver_error"]
    write(root / "cleanup.json", cleanup)
    write(root / "roles.json", roles)
    write(root / "upstream.json", upstream.proof)
    return cleanup, error


def run_case(args, case, root):
    root.mkdir(mode=0o700)
    preflight = [sys.executable, "-P", "-m", "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
                 "--execution-context-only", "--connector", "haproxy", "--profile", "haproxy-htx",
                 "--runtime-root", str(root), "--output-dir", str(root / "preflight"),
                 "--worker-user", "nobody", "--worker-group", "nogroup", "--require-root-master", "--require-chown"]
    subprocess.run(preflight, check=True, timeout=20)
    scenario = SCENARIOS[case]
    paths = {role: f"/acceptance/{args.run_id}-{case}/{role}" for role in ("target", "peer", "followup")}
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    upstream = STREAM.Upstream(scenario, paths)
    thread = threading.Thread(target=upstream.serve_forever, daemon=False)
    thread_started = False
    process, client, roles, handles = None, None, {}, {}
    error = None
    try:
        thread.start()
        thread_started = True
        rules = (args.framework_root / "tests/rules/protocol-acceptance.conf").read_text()
        if case == "phase1":
            rules += '\nSecRule REQUEST_URI "@endsWith /target" "id:1100001,phase:1,deny,status:403,log,t:none"\n'
        if case == "phase2":
            rules += '\nSecRule REQUEST_BODY "@contains no-crs-request-body-marker" "id:1100101,phase:2,deny,status:403,log,t:none"\n'
        (root / "rules.conf").write_text(rules)
        with STREAM.MODERN.tls_material(root):
            (root / TLS_COMBINED).write_bytes((root / "tls.key").read_bytes() + (root / TLS_CERTIFICATE).read_bytes())
            (root / HOST_CONFIGURATION).write_text(configuration(root, port, upstream.server_port, case == "phase4_strict"))
            check = subprocess.run([str(args.haproxy), "-c", "-f", str(root / HOST_CONFIGURATION)],
                                   check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            (root / "configtest.stdout").write_bytes(check.stdout)
            (root / "configtest.stderr").write_bytes(check.stderr)
            require(check.returncode == 0, "native configuration rejected; inspect configtest.stderr")
            with (root / ACCESS_LOG).open("xb") as out, (root / NATIVE_LOG).open("xb") as err:
                process = subprocess.Popen([str(args.haproxy), "-W", "-db", "-f", str(root / HOST_CONFIGURATION)],
                                           stdin=subprocess.DEVNULL, stdout=out, stderr=err)
                deadline = time.monotonic() + 5
                while not roles:
                    require(time.monotonic() < deadline and process.poll() is None, "native host startup failed")
                    HOST.bind_owned_children(process, handles)
                    roles = HOST.observed_owned_roles(process, HOST.process_info(process.pid),
                                                     [str(pid) for pid in handles], handles, port, "htx-" + case) or {}
                    time.sleep(0.02)
                client = WireClient(port, root / TLS_CERTIFICATE, root / WIRE_EVIDENCE)
                exercise(client, upstream, paths, scenario, root)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        error = str(exc)
    finally:
        cleanup, error = finish_runtime(client, upstream, process, thread, thread_started,
                                        port, roles, handles, root, error)
    require(error is None, error or "runtime failed")
    access = [load_json(line) for line in read(root / ACCESS_LOG).splitlines() if line.startswith("{")]
    common = (rows(root / COMMON_EVIDENCE) if (root / COMMON_EVIDENCE).exists()
              and read(root / COMMON_EVIDENCE).strip() else [])
    report = validate_case(case, load_json(read(root / WIRE_EVIDENCE)), access, read(root / NATIVE_LOG), common, upstream.proof, cleanup, args.run_id)
    report["sha256"] = {name: digest(root / name) for name in
                        (WIRE_EVIDENCE, ACCESS_LOG, NATIVE_LOG, HOST_CONFIGURATION, "rules.conf",
                         "upstream.json", "roles.json", "cleanup.json")}
    if (root / COMMON_EVIDENCE).exists():
        report["sha256"][COMMON_EVIDENCE] = digest(root / COMMON_EVIDENCE)
    write(root / "result.json", report)
    return report


def prepare_private_runtime_root(value):
    root = value.absolute()
    require(".." not in value.parts, "runtime traversal is forbidden")
    require(root.is_relative_to(Path("/var/tmp/codex/ModSecurity-conector"))
            and not any(path.is_symlink() for path in (root, *root.parents)), "private external runtime required")
    require(not root.exists(), "fresh runtime root required")
    os.umask(0o077)
    return verified_runtime_artifact_root(root)


def canonical_revision(root, selector):
    # Callers supply source-owned canonical roots and fixed selectors only.
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", selector], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", required=True, type=Path)
    parser.add_argument("--framework-root", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--build-manifest", required=True, type=Path)
    parser.add_argument("--case", choices=CASES, action="append")
    args = parser.parse_args()
    require(args.framework_root.resolve() == Path(__file__).resolve().parents[4], "executing Framework root mismatch")
    require(args.connector_root.resolve() == HOST.BASE.PARENT_ROOT.resolve(), "selected Parent context mismatch")
    manifest = load_json(read(args.build_manifest))
    args.haproxy = admit_manifest(manifest, args.connector_root, args.framework_root, args.build_manifest)
    root = prepare_private_runtime_root(args.runtime_root)
    args.run_id = secrets.token_hex(12)
    report = {"profile": "haproxy-native-htx", "status": "FAIL", "results": []}
    report["run_id"] = args.run_id
    report["parent_sha"] = canonical_revision(HOST.BASE.PARENT_ROOT.resolve(), "HEAD")
    report["framework_sha"] = canonical_revision(Path(__file__).resolve().parents[4], "HEAD")
    report["mrts_sha"] = canonical_revision(Path(__file__).resolve().parents[4], "HEAD:tools/MRTS")
    report["binary_sha256"] = manifest["binary_sha256"]
    report["build_manifest_sha256"] = digest(args.build_manifest)
    report["framework_source_sha256"] = {name: digest(args.framework_root / name) for name in (
        "tests/runners/native_h2_probe.py", "tests/rules/protocol-acceptance.conf",
        "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-protocol-acceptance.py",
        "connector_suite/adapters/haproxy/harness/haproxy_h2_acceptance.py")}
    try:
        selected = args.case or list(CASES)
        require(len(selected) == len(set(selected)) and selected, "duplicate/empty selection")
        for case in selected:
            try:
                report["results"].append(run_case(args, case, root / case))
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                report["results"].append({"case_id": "haproxy_htx_h2_" + case, "status": "FAIL", "error": str(exc)})
        require(len(report["results"]) == len(selected), "missing results")
        require(report["framework_source_sha256"] == {name: digest(args.framework_root / name)
                for name in report["framework_source_sha256"]}, "Framework source changed during execution")
        report["status"] = "PASS" if all(row["status"] == "PASS" for row in report["results"]) else "FAIL"
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report["error"] = str(exc)
    finally:
        write(root / "report.json", report)
    print(json.dumps(report))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
