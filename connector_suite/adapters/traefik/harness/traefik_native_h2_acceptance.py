#!/usr/bin/env python3
"""Explicit opt-in Traefik local-plugin TLS/H2 lifecycle qualification."""

from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

from tests.runners.native_h2_probe import WireClient, frame
from connector_suite.adapters.composite_harness.companion_h2_acceptance import (
    validate_target_eos,
)
from connector_suite.adapters.envoy.harness.envoy_h2_acceptance import (
    Fixture,
    private_runtime_root,
    read_records,
    require,
    write_json,
)

FRAMEWORK = Path(__file__).resolve().parents[4]
OBSERVER_SOURCE = "native_h2_observer.c"

CASES = (
    "allow",
    "phase1",
    "phase2",
    "phase3",
    "phase4_safe",
    "phase4_strict",
    "client_cancel",
    "upstream_reset",
)
HELD = ("phase4_safe", "phase4_strict", "client_cancel", "upstream_reset")


def load_smoke():
    path = (
        FRAMEWORK / "connector_suite/adapters/traefik/scripts/runtime_native_smoke.py"
    )
    spec = importlib.util.spec_from_file_location("traefik_native_smoke", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def records(path):
    return read_records(path) if path.exists() else []


def cleanup_for(path, transaction):
    rows = [
        row
        for row in records(path)
        if row.get("transaction_id") == transaction
        and row.get("event") == "transaction_cleanup"
    ]
    require(len(rows) <= 1, "duplicate native transaction cleanup")
    return rows


def exercise(port, ca, root, fixture, case, events):
    for event in (
        fixture.peer_release,
        fixture.target_release,
        fixture.peer_started,
        fixture.target_paused,
    ):
        event.clear()
    ids = {
        role: f"traefik-native-h2-{case}-{role}"
        for role in ("peer", "target", "followup")
    }
    client = WireClient(port, ca, root / f"wire-{case}.json")
    try:
        client.request(1, f"/{case}/peer", ids["peer"])
        client.wait(
            lambda: client.bytes.get(1, 0) > 0 and fixture.peer_started.is_set()
        )
        client.request(
            3,
            f"/{case}/target",
            ids["target"],
            b"no-crs-request-body-marker" if case == "phase2" else b"",
            case == "phase1",
        )
        if case in HELD:
            client.wait(
                lambda: client.bytes.get(3, 0) > 0 and fixture.target_paused.is_set()
            )
            require(
                1 not in client.terminal and 3 not in client.terminal,
                "first byte/EOS isolation failed",
            )
            client.records.append(
                {
                    "type": "first_byte_before_eos",
                    "peer_held": True,
                    "target_eos_held": True,
                    "monotonic_ns": time.monotonic_ns(),
                }
            )
            if case == "client_cancel":
                client.socket.sendall(frame(3, 0, 3, struct.pack("!I", 8)))
                client.records.append(
                    {
                        "type": "client_rst_stream",
                        "stream_id": 3,
                        "reset_code": 8,
                        "monotonic_ns": time.monotonic_ns(),
                    }
                )
            else:
                fixture.target_release.set()
        if case != "client_cancel":
            client.wait(lambda: 3 in client.terminal)
        client.wait(lambda: bool(cleanup_for(events, ids["target"])))
        require(
            1 not in client.terminal and not fixture.peer_release.is_set(),
            "peer released before native target cleanup",
        )
        client.records.append(
            {
                "type": "native_completion_observed",
                "transaction_id": ids["target"],
                "peer_held": True,
                "target_eos_held": not fixture.target_release.is_set(),
                "monotonic_ns": time.monotonic_ns(),
            }
        )
        fixture.target_release.set()
        fixture.peer_release.set()
        client.wait(lambda: 1 in client.terminal)
        client.request(5, f"/{case}/followup", ids["followup"])
        client.wait(lambda: 5 in client.terminal)
        client.wait(lambda: bool(cleanup_for(events, ids["followup"])))
    finally:
        fixture.peer_release.set()
        fixture.target_release.set()
        client.close()
    return case


def validate_native_cleanup(case, wire, events):
    requests = wire.get("requests", [])
    require(
        len(requests) == 3 and {row["stream_id"] for row in requests} == {1, 3, 5},
        "three unique actual streams required",
    )
    selected = {}
    for role, stream in (("peer", 1), ("target", 3), ("followup", 5)):
        transaction = f"traefik-native-h2-{case}-{role}"
        sent = [row for row in requests if row["stream_id"] == stream]
        require(
            len(sent) == 1
            and sent[0]["transaction_id"] == transaction
            and sent[0]["path"] == f"/{case}/{role}",
            "wire transaction/path mismatch",
        )
        body_size = 26 if role == "target" and case == "phase2" else 0
        require(
            sent[0].get("method") == ("POST" if body_size else "GET")
            and sent[0].get("body_bytes") == body_size,
            "actual wire method/entity mismatch",
        )
        closed = [
            row
            for row in events
            if row.get("transaction_id") == transaction
            and row.get("event") == "transaction_cleanup"
        ]
        require(len(closed) == 1, "missing/duplicate native cleanup")
        require(
            closed[0].get("connector") == "traefik"
            and closed[0].get("integration_mode") == "native-traefik-middleware"
            and closed[0].get("event_hash", 0) > 0
            and closed[0].get("sequence", 0) > 0,
            "native cleanup identity/integrity fields missing",
        )
        selected[role] = closed[0]
    return selected


def validate_terminals(case, wire):
    for stream in (1, 5):
        terminal = wire["terminal"].get(str(stream), {})
        require(
            wire["status"].get(str(stream)) == 200
            and wire["body_bytes"].get(str(stream)) == 10
            and terminal.get("type") in (0, 1)
            and terminal.get("flags", 0) & 1,
            "active peer/followup isolation failed",
        )
    target = wire["terminal"].get("3", {})
    if case in ("phase4_strict", "upstream_reset"):
        require(
            target.get("type") == 3 and target.get("reset_code") == 2,
            "native server RST_STREAM(INTERNAL_ERROR) required",
        )
    elif case != "client_cancel":
        require(
            target.get("type") in (0, 1) and target.get("flags", 0) & 1,
            "normal target END_STREAM missing",
        )
    require(
        wire["status"].get("3")
        == (403 if case in ("phase1", "phase2", "phase3") else 200),
        "target HTTP status mismatch",
    )


def validate_decision(case, events):
    rules = {
        "phase1": 1100001,
        "phase2": 1100101,
        "phase3": 1100201,
        "phase4_safe": 1100301,
        "phase4_strict": 1100301,
    }
    if case in rules:
        decisions = [
            row
            for row in events
            if row.get("transaction_id") == f"traefik-native-h2-{case}-target"
            and row.get("event") == "engine_decision"
        ]
        phase = {
            "phase1": "request_headers",
            "phase2": "request_body",
            "phase3": "response_headers",
        }.get(case, "response_body")
        require(
            len(decisions) == 1
            and str(decisions[0].get("rule_id")) == str(rules[case])
            and decisions[0].get("phase") == phase
            and decisions[0].get("requested_action") == "deny"
            and decisions[0].get("http_status") == 403
            and decisions[0].get("connector") == "traefik"
            and decisions[0].get("integration_mode") == "native-traefik-middleware"
            and decisions[0].get("uri") == f"/{case}/target"
            and decisions[0].get("method") == ("POST" if case == "phase2" else "GET"),
            "native rule/phase/transaction mapping missing",
        )
        if case == "phase2":
            require(
                decisions[0].get("body_bytes_seen") == 26,
                "native P2 actual entity proof missing",
            )


def validate_barriers(case, wire):
    barriers = [
        row for row in wire["frames"] if row.get("type") == "native_completion_observed"
    ]
    require(
        len(barriers) == 1
        and barriers[0].get("transaction_id") == f"traefik-native-h2-{case}-target"
        and barriers[0].get("peer_held") is True,
        "native cleanup/active peer barrier missing",
    )
    if case == "client_cancel":
        require(
            barriers[0].get("target_eos_held") is True,
            "cancellation cleanup followed upstream EOS",
        )
    expected_bytes = {
        "allow": 10,
        "phase4_safe": 33,
        "phase4_strict": 33,
        "client_cancel": 6,
        "upstream_reset": 6,
    }.get(case, 17)
    require(
        wire.get("body_bytes", {}).get("3", 0) == expected_bytes,
        "target bounded response byte count mismatch",
    )
    if case in HELD:
        first = [
            row for row in wire["frames"] if row.get("type") == "first_byte_before_eos"
        ]
        data = [
            row
            for row in wire["frames"]
            if row.get("type") == 0
            and row.get("stream_id") == 3
            and row.get("size", 0) > 0
        ]
        require(
            len(first) == 1
            and first[0].get("peer_held") is True
            and first[0].get("target_eos_held") is True
            and data
            and 0
            < data[0]["monotonic_ns"]
            <= first[0]["monotonic_ns"]
            < barriers[0]["monotonic_ns"],
            "first-byte/EOS/cleanup chronology missing",
        )


def validate_phase4(case, events, selected):
    if case == "phase4_strict":
        require(
            selected["target"].get("response_committed") is True,
            "Strict native committed state missing",
        )
        require(
            not any(
                row.get("transaction_id") == f"traefik-native-h2-{case}-target"
                and row.get("actual_action") == "log_only"
                for row in events
            ),
            "Strict mislabeled as Safe log_only",
        )
    if case == "phase4_safe":
        require(
            any(
                row.get("transaction_id") == f"traefik-native-h2-{case}-target"
                and row.get("actual_action") == "log_only"
                for row in events
            ),
            "Safe acknowledgement missing",
        )


def validate_access(case, wire, access):
    selected = [
        row for row in access if row.get("RequestPath", "").startswith(f"/{case}/")
    ]
    require(len(selected) == 3, "native access case cardinality mismatch")
    require(
        len({row.get("ClientAddr") for row in selected}) == 1
        and all(row.get("ClientAddr") for row in selected),
        "native physical connection missing/changed",
    )
    require(
        len({row.get("RequestCount") for row in selected}) == 3
        and all(type(row.get("RequestCount")) is int for row in selected),
        "native request identities reused/missing",
    )
    for request in wire["requests"]:
        rows = [row for row in selected if row.get("RequestPath") == request["path"]]
        require(len(rows) == 1, "native role path missing/duplicated")
        row = rows[0]
        require(
            row.get("request_X-Acceptance-Id") == request["transaction_id"]
            and row.get("RequestMethod") == request["method"]
            and row.get("RequestContentSize") == request["body_bytes"],
            "native request identity/method/entity mismatch",
        )
        stream = str(request["stream_id"])
        require(
            row.get("DownstreamStatus") == wire["status"].get(stream)
            and row.get("DownstreamContentSize") == wire["body_bytes"].get(stream, 0),
            "native response status/byte mapping mismatch",
        )
        require(
            row.get("RequestProtocol") == "HTTP/2.0"
            and row.get("TLSVersion") == "1.3"
            and row.get("RequestScheme") == "https",
            "native protocol/TLS witness missing",
        )
    return selected


def validate_native_upstream(case, upstream, wire):
    require(
        upstream and not any(row.get("event") == "fixture_error" for row in upstream),
        "native upstream writer missing/failed",
    )
    expected = {
        f"traefik-native-h2-{case}-{role}" for role in ("peer", "target", "followup")
    }
    require(
        all(row.get("transaction_id") in expected for row in upstream),
        "foreign native upstream request",
    )
    barrier = next(
        row for row in wire["frames"] if row.get("type") == "native_completion_observed"
    )
    for role in ("peer", "target", "followup"):
        selected = [
            row
            for row in upstream
            if row.get("transaction_id") == f"traefik-native-h2-{case}-{role}"
        ]
        # This streaming middleware can open the upstream HTTP request before
        # P2 finishes. Its body denial is not a buffered authorization admission.
        count = 0 if role == "target" and case == "phase1" else 1
        require(
            sum(row.get("event") == "upstream_request" for row in selected) == count,
            "native upstream request mapping/cardinality mismatch",
        )
        if role == "target":
            validate_target_eos(case, selected)
            if case == "upstream_reset":
                require(
                    sum(
                        row.get("event") == "upstream_abort"
                        and row.get("eos_sent") is False
                        for row in selected
                    )
                    == 1,
                    "actual native upstream reset missing",
                )
        else:
            validate_completed_upstream_role(role, selected, barrier)


def validate_completed_upstream_role(role, selected, barrier):
    eos = [
        row
        for row in selected
        if row.get("event") == "upstream_eos" and row.get("eos_sent") is True
    ]
    require(len(eos) == 1, "native peer/followup upstream EOS missing")
    if role == "peer":
        paused = [
            row
            for row in selected
            if row.get("event") == "upstream_paused" and row.get("eos_sent") is False
        ]
        require(
            len(paused) == 1
            and paused[0].get("monotonic_ns", 0)
            < barrier.get("monotonic_ns", 0)
            < eos[0].get("monotonic_ns", 0),
            "native upstream live peer/cleanup chronology missing",
        )


def validate(case, wire, events, upstream, access):
    require(case in CASES, "unknown case")
    require(
        wire.get("alpn") == "h2"
        and wire.get("tls_verified") is True
        and wire.get("tls_version") == "TLSv1.3",
        "actual verified TLS/H2 required",
    )
    selected = validate_native_cleanup(case, wire, events)
    validate_terminals(case, wire)
    validate_decision(case, events)
    validate_barriers(case, wire)
    validate_phase4(case, events, selected)
    case_upstream = [
        row
        for row in upstream
        if row.get("transaction_id", "").startswith(f"traefik-native-h2-{case}-")
    ]
    validate_native_upstream(case, case_upstream, wire)
    native_access = validate_access(case, wire, access)
    return {
        "case_id": f"traefik_native_h2_{case}",
        "status": "PASS",
        "transactions": selected,
        "native_access": native_access,
    }


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_identity(parent):
    paths = {}
    for base in (parent / "common", parent / "connectors/traefik"):
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in (
                ".c",
                ".h",
                ".go",
                ".mod",
                ".sum",
                ".sh",
            ):
                paths["parent:" + str(path.relative_to(parent))] = digest(path)
    paths["parent:connectors/profile_registry.c"] = digest(
        parent / "connectors/profile_registry.c"
    )
    for path in (
        Path(__file__),
        Path(__file__).with_name(OBSERVER_SOURCE),
        Path(__file__).with_name("native-h2-rules.conf"),
        FRAMEWORK / "tests/runners/native_h2_probe.py",
        FRAMEWORK / "connector_suite/adapters/traefik/scripts/runtime_native_smoke.py",
        FRAMEWORK / "connector_suite/adapters/envoy/harness/envoy_h2_acceptance.py",
        FRAMEWORK
        / "connector_suite/adapters/composite_harness/companion_h2_acceptance.py",
    ):
        paths["framework:" + str(path.relative_to(FRAMEWORK))] = digest(path)
    return paths


def configure_tls(args, artifacts):
    ca, key = args.root / "tls.crt", args.root / "tls.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(ca),
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    static = (
        artifacts.static_config.read_text()
        + "accessLog:\n  format: json\n  filePath: "
        + str(args.root / "access.jsonl")
        + "\n  fields:\n    headers:\n      defaultMode: drop\n      names:\n        X-Acceptance-Id: keep\n"
    )
    artifacts.static_config.write_text(static)
    dynamic = artifacts.dynamic_config.read_text().replace(
        "      service: upstream", "      service: upstream\n      tls: {}"
    )
    dynamic = dynamic.replace(
        "          engineMode: uds",
        "          engineMode: uds\n          phase4Mode: " + args.mode,
    ).replace(
        "transactionIDHeader: X-Request-Id", "transactionIDHeader: X-Acceptance-Id"
    )
    dynamic += (
        "tls:\n  certificates:\n    - certFile: "
        + str(ca)
        + "\n      keyFile: "
        + str(key)
        + "\n"
    )
    artifacts.dynamic_config.write_text(dynamic)
    # The real service always emits native decisions; the plugin policy owns
    # the distinction between Safe acknowledgement and Strict host abort.
    artifacts.engine_config.write_text(
        artifacts.engine_config.read_text().replace(
            "transaction_id_header=x-request-id",
            "transaction_id_header=x-acceptance-id",
        )
    )
    return ca


def await_tls(port, ca):
    # Listener binding precedes asynchronous file-provider TLS loading.
    # Readiness proves verified TLS/ALPN, never changes transport.
    deadline = time.monotonic() + 8
    while True:
        try:
            context = ssl.create_default_context(cafile=str(ca))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(["h2"])
            with context.wrap_socket(
                socket.create_connection(("127.0.0.1", port), 1),
                server_hostname="127.0.0.1",
            ) as connection:
                require(
                    connection.selected_alpn_protocol() == "h2",
                    "TLS readiness did not negotiate H2",
                )
            break
        except OSError:
            require(
                time.monotonic() < deadline,
                "TLS file-provider readiness deadline exceeded",
            )
            time.sleep(0.05)


def compile_observer(args, smoke):
    observer = args.root / "observer.o"
    command = [
        "cc",
        "-std=c17",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(smoke.REPO_ROOT),
        "-I",
        str(smoke.REPO_ROOT / "common/include"),
        "-I",
        str(args.modsecurity_prefix / "include"),
        "-c",
        str(Path(__file__).with_name(OBSERVER_SOURCE)),
        "-o",
        str(observer),
    ]
    completed = subprocess.run(command, check=True)
    write_json(
        args.root / "observer-compile.json",
        {
            "command": command,
            "exit_code": completed.returncode,
            "source_sha256": digest(Path(__file__).with_name(OBSERVER_SOURCE)),
            "object_sha256": digest(observer),
        },
    )
    os.environ["TRAEFIK_ENGINE_SERVICE_LDFLAGS"] = (
        str(observer)
        + " -Wl,--wrap=msconnector_runtime_transaction_begin_request_stream -Wl,--wrap=fputs"
    )
    return observer


def artifact_identity(args, observer):
    return {
        "traefik": digest(args.traefik),
        "engine": digest(args.root / "engine-build/traefik-engine-service"),
        "observer": digest(observer),
        "libmodsecurity": digest(
            (args.modsecurity_prefix / "lib/libmodsecurity.so").resolve()
        ),
    }


def stop_checked_process(process):
    if process is None:
        return {
            "started": False,
            "stopped": True,
            "returncode": None,
            "forced_kill": False,
        }
    forced = False
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forced = True
            process.kill()
            process.wait(timeout=5)
    return {
        "started": True,
        "stopped": process.poll() is not None,
        "returncode": process.returncode,
        "forced_kill": forced,
    }


def require_healthy_writers(terminal):
    require(
        all(
            value["started"]
            and value["stopped"]
            and value["returncode"] == 0
            and not value["forced_kill"]
            for value in terminal.values()
        ),
        "native host/engine writer exited unsuccessfully",
    )


def collect_results(cases, root, event_path):
    access, events, upstream = (
        records(root / "access.jsonl"),
        records(event_path),
        records(root / "upstream.jsonl"),
    )
    expected = {
        f"traefik-native-h2-{case}-{role}"
        for case in cases
        for role in ("peer", "target", "followup")
    }
    require(
        cases and len(cases) == len(set(cases)),
        "missing/duplicate native case selection",
    )
    require(len(access) == len(expected), "native access cardinality mismatch")
    require(
        events and all(row.get("transaction_id") in expected for row in events),
        "foreign/empty native transaction evidence",
    )
    require(
        upstream and all(row.get("transaction_id") in expected for row in upstream),
        "foreign/empty native upstream evidence",
    )
    results = []
    for case in cases:
        wire = json.loads((root / f"wire-{case}.json").read_text())
        results.append(validate(case, wire, events, upstream, access))
    return results


def selected_cases(mode):
    if mode == "strict":
        return ("phase4_strict",)
    return tuple(case for case in CASES if case != "phase4_strict")


def verify_source_heads(identities):
    for identity in identities.values():
        require(
            subprocess.check_output(
                ["git", "-C", identity["root"], "rev-parse", "HEAD"], text=True
            ).strip()
            == identity["head"],
            "source HEAD changed during run/cleanup",
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--traefik", type=Path, required=True)
    parser.add_argument("--modsecurity-prefix", type=Path, required=True)
    parser.add_argument("--socket-parent", type=Path, required=True)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--fault-event-writer", action="store_true")
    parser.add_argument("--expect-parent")
    parser.add_argument("--expect-framework")
    parser.add_argument("--mode", choices=("safe", "strict"), required=True)
    args = parser.parse_args()
    smoke = load_smoke()
    os.environ["MSCONNECTOR_RULES_FILE"] = str(
        FRAMEWORK / "connector_suite/adapters/traefik/harness/native-h2-rules.conf"
    )
    identities = {}
    for label, source, expected in (
        ("parent", smoke.REPO_ROOT, args.expect_parent),
        ("framework", FRAMEWORK, args.expect_framework),
    ):
        head = subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
        ).strip()
        require(
            expected is None or expected == head, "unexpected committed source head"
        )
        dirty = subprocess.check_output(
            [
                "git",
                "-C",
                str(source),
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            text=True,
        )
        require(
            not args.require_clean or not dirty,
            "final-pair qualification requires clean sources",
        )
        identities[label] = {
            "root": str(source),
            "head": head,
            "clean": not bool(dirty),
        }
    before = source_identity(smoke.REPO_ROOT)
    args.root = private_runtime_root(args.root)
    os.environ.update(
        TRAEFIK_NATIVE_RUNTIME_ROOT=str(args.root),
        TRAEFIK_ENGINE_SOCKET_PARENT=str(args.socket_parent),
        TRAEFIK_BIN=str(args.traefik),
        MODSECURITY_INCLUDE_DIR=str(args.modsecurity_prefix / "include"),
        MODSECURITY_LIB_DIR=str(args.modsecurity_prefix / "lib"),
    )
    inputs = smoke.collect_native_runtime_inputs()
    artifacts = smoke.stage_native_runtime(inputs)
    os.environ["TRAEFIK_NATIVE_H2_OBSERVER_RUN_ID"] = hashlib.sha256(
        str(args.root).encode("utf-8")
    ).hexdigest()[:32]
    os.environ["TRAEFIK_NATIVE_H2_FAULT_EVENT_WRITER"] = (
        "1" if args.fault_event_writer else "0"
    )
    observer = compile_observer(args, smoke)
    setup = None
    fixture = None
    processes = smoke.NativeProcesses()
    results = []
    built_artifacts = None
    try:
        setup = smoke.start_native_runtime_setup(inputs, artifacts)
        preflight = subprocess.run(
            [
                sys.executable,
                "-P",
                "-m",
                "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
                "--execution-context-only",
                "--connector",
                "traefik",
                "--profile",
                "traefik-native-h2",
                "--runtime-root",
                str(args.root),
                "--output-dir",
                str(args.root / "preflight"),
                "--uds-path",
                str(setup.engine_socket),
                "--uds-root",
                str(args.socket_parent),
            ],
            check=False,
        )
        require(preflight.returncode == 0, "actual launcher context preflight failed")
        setup.upstream.shutdown()
        setup.upstream.server_close()
        fixture = Fixture(
            ("127.0.0.1", setup.upstream_port), args.root / "upstream.jsonl"
        )
        thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        thread.start()
        ca = configure_tls(args, artifacts)
        with smoke.running_traefik_host(
            inputs,
            artifacts,
            setup,
            processes,
            engine_description="native H2 engine",
            host_description="native TLS/H2 Yaegi host",
        ):
            built_artifacts = artifact_identity(args, observer)
            await_tls(setup.traefik_port, ca)
            for case in selected_cases(args.mode):
                results.append(
                    exercise(
                        setup.traefik_port,
                        ca,
                        args.root,
                        fixture,
                        case,
                        artifacts.event_path,
                    )
                )
    finally:
        terminal = {
            "traefik": stop_checked_process(processes.traefik),
            "engine": stop_checked_process(processes.engine),
        }
        stopped = [value["stopped"] for value in terminal.values()]
        if fixture is not None:
            fixture.peer_release.set()
            fixture.target_release.set()
            fixture.shutdown()
            fixture.server_close()
            thread.join(3)
        socket_clean = smoke.remove_private_engine_socket_dir(
            setup.engine_socket_dir if setup else None, inputs.engine_socket_parent
        )
        fixture_clean = fixture is None or (
            not thread.is_alive() and not fixture.handlers
        )
        write_json(
            args.root / "cleanup.json",
            {
                "processes": stopped,
                "socket": socket_clean,
                "fixture": fixture_clean,
                "terminal_states": terminal,
            },
        )
        require(
            all(stopped) and socket_clean and fixture_clean,
            "task-owned process/socket/fixture cleanup failed",
        )
    require_healthy_writers(terminal)
    final_artifacts = artifact_identity(args, observer)
    require(
        built_artifacts == final_artifacts,
        "native built artifact changed during run/cleanup",
    )
    require(
        before == source_identity(smoke.REPO_ROOT),
        "source/build input changed during run/cleanup",
    )
    verify_source_heads(identities)
    validated = collect_results(results, args.root, artifacts.event_path)
    result_payload = {
        "status": "PASS",
        "mode": args.mode,
        "cases": validated,
        "source": identities,
        "source_sha256": before,
        "artifacts": final_artifacts,
        "terminal_states": terminal,
    }
    result_payload["raw_sha256"] = {
        str(path.relative_to(args.root)): digest(path)
        for path in args.root.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and (path.suffix in (".json", ".jsonl", ".yaml", ".conf", ".crt", ".log"))
    }
    write_json(args.root / "acceptance.json", result_payload)


if __name__ == "__main__":
    main()
