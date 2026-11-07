#!/usr/bin/env python3
"""Opt-in TLS/H2 acceptance of retained authorization/response companions.

Each case uses peer/target/follow-up streams on one verified TLS connection.
The peer remains paused until the native retained target transaction is closed.
No HTTP/1 fallback or response payload is persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import resource
import socket
import struct
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from connector_suite.adapters.envoy.harness import envoy_h2_acceptance as native
from tests.runners.native_h2_probe import WireClient, frame

PROFILES = {
    "envoy_ext_authz_h2": "envoy-ext-authz",
    "traefik_forwardauth_h2": "traefik-forwardauth",
}
CASES = (*native.CASES, native.STRICT_CASE)
RULES = {
    "phase1": "1100001",
    "phase2": "1100101",
    "phase3": "1100201",
    "phase4_safe": "1100301",
    "phase4_strict": "1100301",
}


class ObservedHandler(native.Handler):
    def do_GET(self):
        try:
            super().do_GET()
        except Exception:
            self.server.record("fixture_error", self.headers.get("x-acceptance-id", ""))
            raise

    do_POST = do_GET


HOST_CONFIG = "host.yaml"
ACCESS_LOG = "access.jsonl"
SOCKET_NAME = "companion.sock"
COMPLETION_BARRIER = "native_completion_observed"


def events(root):
    path = root / native.COMPLETION_LOG
    return native.read_records(path) if path.exists() else []


def ids_for_phase(root, phase):
    return {row["decision_id"] for row in events(root) if row.get("phase") == phase}


def wait_event(client, root, predicate):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        selected = [row for row in events(root) if predicate(row)]
        if selected:
            return selected
        client.poll()
    raise ValueError("native companion lifecycle barrier timed out with active peer")


def exercise(port, cert, root, fixture, case, adapter):
    for event in (
        fixture.peer_release,
        fixture.target_release,
        fixture.peer_started,
        fixture.target_paused,
    ):
        event.clear()
    client = WireClient(port, cert, root / f"wire-{case}.json")
    mapping = {}
    try:
        previous = ids_for_phase(root, "P1")
        client.request(1, f"/{case}/peer", f"{adapter}-{case}-peer")
        client.wait(
            lambda: client.bytes.get(1, 0) > 0 and fixture.peer_started.is_set()
        )
        peer_ids = ids_for_phase(root, "P1") - previous
        native.require(
            len(peer_ids) == 1, "peer retained identity missing or duplicated"
        )
        mapping["peer"] = peer_ids.pop()
        before_target = ids_for_phase(root, "P1")
        client.request(
            3,
            f"/{case}/target",
            f"{adapter}-{case}-target",
            b"no-crs-request-body-marker" if case == "phase2" else b"",
            case == "phase1",
        )
        wait_event(
            client,
            root,
            lambda row: (
                row.get("phase") == "P1" and row.get("decision_id") not in before_target
            ),
        )
        target_ids = ids_for_phase(root, "P1") - before_target
        native.require(
            len(target_ids) == 1, "target retained identity missing or duplicated"
        )
        mapping["target"] = target_ids.pop()
        if case in native.HELD_CASES:
            client.wait(
                lambda: client.bytes.get(3, 0) > 0 and fixture.target_paused.is_set()
            )
            native.require(
                3 not in client.terminal and 1 not in client.terminal,
                "first byte/EOS barrier failed",
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
                    {"type": "client_rst_stream", "stream_id": 3, "reset_code": 8}
                )
            else:
                fixture.target_release.set()
        if case != "client_cancel":
            client.wait(lambda: 3 in client.terminal)
        wait_event(
            client,
            root,
            lambda row: (
                row.get("phase") == "terminal"
                and row.get("decision_id") == mapping["target"]
            ),
        )
        native.require(
            1 not in client.terminal and not fixture.peer_release.is_set(),
            "peer ended before target cleanup",
        )
        client.records.append(
            {
                "type": COMPLETION_BARRIER,
                "decision_id": mapping["target"],
                "peer_held": True,
                "target_eos_held": not fixture.target_release.is_set(),
                "monotonic_ns": time.monotonic_ns(),
            }
        )
        fixture.target_release.set()
        fixture.peer_release.set()
        client.wait(lambda: 1 in client.terminal)
        before_followup = ids_for_phase(root, "P1")
        client.request(5, f"/{case}/followup", f"{adapter}-{case}-followup")
        client.wait(lambda: 5 in client.terminal)
        wait_event(
            client,
            root,
            lambda row: (
                row.get("phase") == "terminal"
                and row.get("decision_id") not in before_followup
            ),
        )
        followup_ids = ids_for_phase(root, "P1") - before_followup
        native.require(
            len(followup_ids) == 1, "follow-up retained identity missing or duplicated"
        )
        mapping["followup"] = followup_ids.pop()
    finally:
        fixture.target_release.set()
        fixture.peer_release.set()
        client.close()
    native.write_json(root / f"mapping-{case}.json", mapping)


def select_host(adapter, request, access):
    if adapter.startswith("envoy"):
        rows = [
            row for row in access if row.get("request_id") == request["transaction_id"]
        ]
        native.require(
            len(rows) == 1 and rows[0].get("protocol") == "HTTP/2",
            "native Envoy request/protocol mismatch",
        )
        host = rows[0]
        stream = host.get("stream_id")
        native.require(
            isinstance(stream, str) and len(stream) == 36,
            "native Envoy stream UUID missing",
        )
        return host, str(host.get("connection_id")), stream, int(host["status"])
    rows = [row for row in access if row.get("RequestPath") == request["path"]]
    native.require(
        len(rows) == 1 and rows[0].get("RequestProtocol") == "HTTP/2.0",
        "native Traefik request/protocol mismatch",
    )
    host = rows[0]
    native.require(
        host.get("request_X-Acceptance-Id") == request["transaction_id"]
        and host.get("RequestMethod") == request["method"],
        "native Traefik request identity/method mismatch",
    )
    return (
        host,
        host.get("ClientAddr"),
        host.get("RequestCount"),
        int(host["DownstreamStatus"]),
    )


def validate_retained(adapter, case, role, retained):
    pipeline = (
        ("envoy.ext_authz", "envoy.ext_proc", "envoy_ext_authz_ext_proc_grpc")
        if adapter.startswith("envoy")
        else (
            "traefik.forwardAuth",
            "traefik.native_uds",
            "traefik_forwardauth_private_uds",
        )
    )
    native.require(
        all(
            (row.get("request_path"), row.get("response_path"), row.get("transport"))
            == pipeline
            for row in retained
        ),
        "retained handoff profile mismatch",
    )
    absent = set()
    if role == "target":
        absent = {
            "phase1": {"P2", "P3", "P4"},
            "phase2": {"P3", "P4"},
            "phase3": {"P4"},
            "client_cancel": {"P4"},
            "upstream_reset": {"P4"},
        }.get(case, set())
    for phase in ("P1", "P2", "P3", "P4"):
        native.require(
            sum(row.get("phase") == phase for row in retained)
            == (0 if phase in absent else 1),
            "retained phase missing/duplicated/out of order",
        )
    ordered = [
        row.get("phase")
        for row in retained
        if row.get("phase") in ("P1", "P2", "P3", "P4", "terminal")
    ]
    expected = [phase for phase in ("P1", "P2", "P3", "P4") if phase not in absent] + [
        "terminal"
    ]
    native.require(ordered == expected, "retained phase chronology changed")


def validate_request_lifecycle(
    adapter, case, role, stream, request, wire, records, decision_id
):
    retained = [row for row in records if row.get("decision_id") == decision_id]
    binding = hashlib.sha256(
        (request["method"] + "\x00" + request["path"]).encode()
    ).hexdigest()
    native.require(
        all(
            row.get("request_sha256") == binding
            for row in retained
            if row.get("phase") != "reservation"
        ),
        "wire/native retained request binding crossed or missing",
    )
    native.require(
        retained
        and all(
            row.get("connector")
            == ("envoy" if adapter.startswith("envoy") else "traefik")
            for row in retained
        ),
        "cross-profile retained identity",
    )
    validate_retained(adapter, case, role, retained)
    terminals = [row for row in retained if row.get("phase") == "terminal"]
    native.require(
        len(terminals) == 1 and terminals[0].get("cleanup_outcome") == "closed",
        "missing/duplicate/failed actual retained cleanup",
    )
    if role != "target":
        native.require(
            wire.get("status", {}).get(str(stream)) == 200
            and wire.get("body_bytes", {}).get(str(stream)) == 10,
            "peer/follow-up contaminated",
        )
        native.require(
            wire.get("terminal", {}).get(str(stream), {}).get("flags", 0) & 1,
            "peer/follow-up not complete",
        )


def validate_requests(adapter, case, wire, records, mapping, access):
    native.require(adapter in PROFILES and case in CASES, "unknown opt-in profile/case")
    native.require(
        wire.get("alpn") == "h2"
        and wire.get("tls_verified") is True
        and wire.get("tls_version") == "TLSv1.3",
        "verified TLS1.3/H2 proof missing",
    )
    native.require(
        set(mapping) == {"peer", "target", "followup"}
        and len(set(mapping.values())) == 3,
        "retained transaction identity is not one-to-one",
    )
    native.require(
        {row.get("decision_id") for row in records} == set(mapping.values()),
        "foreign retained lifecycle",
    )
    native.require(len(access) == 3, "native host result count mismatch")
    connections = set()
    host_streams = set()
    joins = {}
    native.require(
        len(wire.get("requests", [])) == 3
        and {row.get("stream_id") for row in wire["requests"]} == {1, 3, 5},
        "wire request set incomplete",
    )
    for role, stream in (("peer", 1), ("target", 3), ("followup", 5)):
        request = next(row for row in wire["requests"] if row["stream_id"] == stream)
        native.require(
            request.get("path") == f"/{case}/{role}"
            and request.get("transaction_id") == f"{adapter}-{case}-{role}",
            "wire identity mismatch",
        )
        body_size = 26 if role == "target" and case == "phase2" else 0
        native.require(
            request.get("method") == ("POST" if body_size else "GET")
            and request.get("body_bytes") == body_size,
            "wire method/entity mismatch",
        )
        _, connection, native_stream, status = select_host(adapter, request, access)
        connections.add(connection)
        host_streams.add(native_stream)
        joins[role] = {
            "wire_stream_id": stream,
            "request_id": request["transaction_id"],
            "native_stream_id": native_stream,
            "retained_decision_id": mapping[role],
        }
        if case != "client_cancel" or role != "target":
            native.require(
                status == wire.get("status", {}).get(str(stream)),
                "wire/native response mapping mismatch",
            )
        validate_request_lifecycle(
            adapter, case, role, stream, request, wire, records, mapping[role]
        )
    native.require(
        len(connections) == 1 and None not in connections and "None" not in connections,
        "native physical connection changed",
    )
    native.require(
        len(host_streams) == 3 and None not in host_streams,
        "duplicate native stream identity",
    )
    return joins


def validate_rule(case, common, records, mapping):
    target = [row for row in records if row.get("decision_id") == mapping["target"]]
    if case in RULES:
        phase = {"phase1": "P1", "phase2": "P2", "phase3": "P3"}.get(case, "P4")
        decisions = [
            row
            for row in target
            if row.get("phase") == phase
            and row.get("rule_id") == RULES[case]
            and row.get("requested_action") == "deny"
        ]
        native.require(
            len(decisions) == 1,
            "target native rule/phase mapping missing or duplicated",
        )
        raw = [
            row
            for row in common
            if row.get("event") == "engine_decision"
            and row.get("transaction_id") == mapping["target"]
            and str(row.get("rule_id")) == RULES[case]
            and row.get("uri") == f"/{case}/target"
        ]
        native.require(
            len(raw) == 1, "Common rule/request/retained identity mapping missing"
        )
        native.require(
            raw[0].get("connector") == "envoy"
            and raw[0].get("integration_mode") == "ext_proc",
            "unexpected shared native engine backend identity",
        )
        if case == "phase2":
            native.require(
                raw[0].get("body_bytes_seen") == 26 and raw[0].get("method") == "POST",
                "native P2 actual entity not observed",
            )


def validate_first_data(case, wire, barrier):
    first = [
        row
        for row in wire.get("frames", [])
        if row.get("type") == "first_byte_before_eos"
    ]
    data = [
        row
        for row in wire.get("frames", [])
        if row.get("type") == 0 and row.get("stream_id") == 3 and row.get("size", 0) > 0
    ]
    native.require(
        len(first) == 1
        and first[0].get("peer_held") is True
        and first[0].get("target_eos_held") is True
        and data
        and 0
        < data[0].get("monotonic_ns", 0)
        <= first[0].get("monotonic_ns", 0)
        < barrier.get("monotonic_ns", 0),
        "actual first DATA/EOS/cleanup chronology missing",
    )
    native.require(
        wire.get("body_bytes", {}).get("3")
        == (6 if case in ("client_cancel", "upstream_reset") else 33),
        "target prefix/full byte count mismatch",
    )


def validate_terminal(case, wire, records, mapping):
    target = [row for row in records if row.get("decision_id") == mapping["target"]]
    native.require(
        wire.get("status", {}).get("3")
        == (403 if case in ("phase1", "phase2", "phase3") else 200),
        "wrong target wire status",
    )
    barriers = [
        row for row in wire.get("frames", []) if row.get("type") == COMPLETION_BARRIER
    ]
    native.require(
        len(barriers) == 1
        and barriers[0].get("decision_id") == mapping["target"]
        and barriers[0].get("peer_held") is True,
        "live isolation/cleanup barrier missing",
    )
    if case in native.HELD_CASES:
        validate_first_data(case, wire, barriers[0])
    if case in ("client_cancel", "upstream_reset"):
        native.require(
            any(
                row.get("phase") == "terminal"
                and row.get("reason") == "companion_transport_closed"
                for row in target
            ),
            "typed observed companion transport cleanup missing",
        )
    if case == "client_cancel":
        native.require(
            barriers[0].get("target_eos_held") is True,
            "target EOS released before cancellation cleanup",
        )
        native.require(
            any(
                row.get("type") == "client_rst_stream" and row.get("reset_code") == 8
                for row in wire["frames"]
            ),
            "actual client reset missing",
        )
    elif case in ("upstream_reset", "phase4_strict"):
        terminal = wire.get("terminal", {}).get("3", {})
        expected_reset = (
            2  # Both pinned native hosts observed INTERNAL_ERROR on this response path.
        )
        native.require(
            terminal.get("type") == 3 and terminal.get("reset_code") == expected_reset,
            "real pinned server stream reset missing",
        )
        if case == "phase4_strict":
            native.require(
                any(
                    row.get("phase") == "host_action_request"
                    and row.get("actual_host_action")
                    in (
                        "strict_immediate_response_sent",
                        "strict_stream_abort_requested",
                    )
                    for row in target
                ),
                "Strict native abort request missing",
            )
    else:
        native.require(
            wire.get("terminal", {}).get("3", {}).get("flags", 0) & 1,
            "target END_STREAM missing",
        )
    if case == "phase4_safe":
        native.require(
            any(
                row.get("phase") == "host_action"
                and row.get("actual_host_action") == "log_only"
                for row in target
            ),
            "Safe late action not recorded",
        )
        native.require(
            wire.get("body_bytes", {}).get("3") == 33, "Safe response incomplete"
        )


def validate_target_eos(case, selected):
    if case not in ("allow", "phase4_safe", "phase4_strict"):
        return
    eos = [row for row in selected if row.get("event") == "upstream_eos"]
    native.require(
        len(eos) == 1 and eos[0].get("eos_sent") is True,
        "target upstream EOS missing/duplicated/unconfirmed",
    )
    native.require(
        not any(
            row.get("event") in ("upstream_abort", "upstream_disconnected")
            for row in selected
        ),
        "upstream reset/disconnect confounds target response outcome",
    )


def validate_peer_chronology(selected, wire):
    paused = [
        row
        for row in selected
        if row.get("event") == "upstream_paused" and row.get("eos_sent") is False
    ]
    eos = [row for row in selected if row.get("event") == "upstream_eos"]
    barrier = next(
        row for row in wire["frames"] if row.get("type") == COMPLETION_BARRIER
    )
    native.require(
        len(paused) == 1
        and paused[0].get("monotonic_ns", 0)
        < barrier.get("monotonic_ns", 0)
        < eos[0].get("monotonic_ns", 0),
        "upstream active peer/cleanup chronology missing",
    )


def validate_upstream(adapter, case, upstream, wire):
    native.require(
        upstream and not any(row.get("event") == "fixture_error" for row in upstream),
        "upstream fixture writer missing/failed",
    )
    native.require(
        all(
            row.get("transaction_id")
            in {f"{adapter}-{case}-{role}" for role in ("peer", "target", "followup")}
            for row in upstream
        ),
        "foreign upstream request",
    )
    for role in ("peer", "target", "followup"):
        selected = [
            row
            for row in upstream
            if row.get("transaction_id") == f"{adapter}-{case}-{role}"
        ]
        request_count = sum(row.get("event") == "upstream_request" for row in selected)
        expected_count = 0 if role == "target" and case in ("phase1", "phase2") else 1
        native.require(
            request_count == expected_count, "upstream request mapping/count mismatch"
        )
        if role == "target":
            validate_target_eos(case, selected)
        if role != "target":
            native.require(
                sum(row.get("event") == "upstream_eos" for row in selected) == 1,
                "peer/follow-up upstream EOS missing/duplicated",
            )
        if role == "peer":
            validate_peer_chronology(selected, wire)
        if role == "target" and case == "upstream_reset":
            native.require(
                sum(
                    row.get("event") == "upstream_abort"
                    and row.get("eos_sent") is False
                    for row in selected
                )
                == 1,
                "actual upstream reset missing",
            )


def validate_case(adapter, case, wire, records, mapping, access, common, upstream):
    joins = validate_requests(adapter, case, wire, records, mapping, access)
    validate_rule(case, common, records, mapping)
    validate_terminal(case, wire, records, mapping)
    validate_upstream(adapter, case, upstream, wire)
    return {"case_id": f"{adapter}_{case}", "status": "PASS", "transactions": joins}


def envoy_config(args, root, listen, auth, admin, upstream):
    text = (
        args.connector_root
        / "connectors/envoy/config/envoy-ext-authz-composite.yaml.in"
    ).read_text()
    for name, value in {
        "LISTEN_PORT": listen,
        "AUTHZ_PORT": auth,
        "ADMIN_PORT": admin,
        "UPSTREAM_PORT": upstream,
        "TLS_CERTIFICATE": root / native.TLS_CERTIFICATE,
        "TLS_PRIVATE_KEY": root / native.TLS_PRIVATE_KEY,
        "EXT_PROC_METADATA_NAMESPACE": "envoy.filters.http.ext_authz",
    }.items():
        text = text.replace(f"@{name}@", str(value))
    text = text.replace(
        "          stat_prefix:",
        """          codec_type: HTTP2
          access_log:
          - name: envoy.access_loggers.file
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: ACCESS_LOG
              log_format:
                json_format:
                  request_id: "%REQ(X-ACCEPTANCE-ID)%"
                  protocol: "%PROTOCOL%"
                  connection_id: "%CONNECTION_ID%"
                  stream_id: "%STREAM_ID%"
                  status: "%RESPONSE_CODE%"
          stat_prefix:""".replace("ACCESS_LOG", json.dumps(str(root / ACCESS_LOG))),
    )
    text = text.replace(
        "          common_tls_context:\n",
        "          common_tls_context:\n            alpn_protocols: [h2]\n            tls_params:\n              tls_minimum_protocol_version: TLSv1_3\n",
        1,
    )
    output = root / HOST_CONFIG
    output.write_text(text)
    subprocess.run(
        [
            str(args.host),
            "--mode",
            "validate",
            "-c",
            str(output),
            "--disable-hot-restart",
        ],
        check=True,
        stdout=(root / "validate.log").open("wb"),
        stderr=subprocess.STDOUT,
    )
    return [
        str(args.host),
        "-c",
        str(output),
        "--disable-hot-restart",
        "--concurrency",
        "2",
        "--log-level",
        "error",
    ]


def traefik_config(args, root, listen, auth, upstream):
    import yaml

    module = "github.com/Easton97-Jens/ModSecurity-conector/connectors/traefik/composite_middleware"
    source = args.connector_root / "connectors/traefik/composite_middleware"
    native.require(
        not any(path.is_symlink() for path in source.rglob("*")),
        "plugin source contains symlinks",
    )
    plugin = root / "plugins-local/src" / module
    shutil.copytree(source, plugin)
    native.write_json(
        root / "plugin-source.json",
        {
            str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source.rglob("*")
            if path.is_file()
        },
    )
    dynamic = (
        args.connector_root
        / "connectors/traefik/config/traefik-forwardauth-composite-dynamic.yaml"
    ).read_text()
    for key, value in {
        "AUTH_ADDRESS": f"127.0.0.1:{auth}",
        "COMPOSITE_SOCKET": root / SOCKET_NAME,
        "UPSTREAM_ADDRESS": f"127.0.0.1:{upstream}",
        "UPSTREAM_CERTIFICATE": root / native.TLS_CERTIFICATE,
    }.items():
        dynamic = dynamic.replace(f"__{key}__", str(value))
    config = yaml.safe_load(dynamic)
    config["http"]["routers"]["connector-composite"]["tls"] = {}
    config["http"]["serversTransports"]["composite-upstream-transport"][
        "serverName"
    ] = "127.0.0.1"
    config["tls"] = {
        "certificates": [
            {
                "certFile": str(root / native.TLS_CERTIFICATE),
                "keyFile": str(root / native.TLS_PRIVATE_KEY),
            }
        ],
        "options": {"default": {"minVersion": "VersionTLS13", "alpnProtocols": ["h2"]}},
    }
    native.write_json(root / "dynamic.yaml", config)
    native.write_json(
        root / HOST_CONFIG,
        {
            "entryPoints": {"web": {"address": f"127.0.0.1:{listen}"}},
            "providers": {
                "file": {"filename": str(root / "dynamic.yaml"), "watch": False}
            },
            "experimental": {
                "localPlugins": {
                    "msconnector-composite": {
                        "moduleName": module,
                        "settings": {"envs": []},
                    }
                }
            },
            "accessLog": {
                "filePath": str(root / ACCESS_LOG),
                "format": "json",
                "fields": {
                    "headers": {
                        "defaultMode": "drop",
                        "names": {"X-Acceptance-Id": "keep"},
                    }
                },
            },
            "log": {"level": "ERROR"},
        },
    )
    return [str(args.host), f"--configFile={root / HOST_CONFIG}"]


def wait_tls(port, cert, processes):
    import ssl

    context = ssl.create_default_context(cafile=str(cert))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        native.require(
            all(process.poll() is None for _, process in processes),
            "native host process exited",
        )
        try:
            with (
                socket.create_connection(("127.0.0.1", port), 0.2) as connection,
                context.wrap_socket(connection, server_hostname="127.0.0.1") as tls,
            ):
                native.require(
                    tls.selected_alpn_protocol() == "h2",
                    "native listener did not negotiate H2",
                )
                return
        except OSError:
            time.sleep(0.1)
    raise ValueError("verified TLS/H2 host readiness deadline exceeded")


def admit_build(args, report):
    receipt = native.load_json(native.read_text(args.build_receipt))
    native.require(
        receipt.get("status") == "PASS"
        and receipt.get("build_exit") == 0
        and receipt.get("source_unchanged") is True,
        "native build admission failed",
    )
    native.require(
        receipt.get("binary") == str(args.service)
        and hashlib.sha256(args.service.read_bytes()).hexdigest()
        == receipt.get("binary_sha256"),
        "native service artifact changed after build",
    )
    sources = receipt.get("source_sha256", {})
    native.require(
        isinstance(sources, dict) and len(sources) >= 150,
        "compiled source admission incomplete",
    )
    tracked = subprocess.check_output(
        [
            "git",
            "-C",
            str(args.connector_root),
            "ls-files",
            "common",
            "connectors/envoy",
            "connectors/traefik/composite_middleware",
        ],
        text=True,
    ).splitlines()
    expected_paths = {
        name
        for name in tracked
        if Path(name).suffix in (".c", ".h", ".go", ".mod", ".sum", ".sh", ".env")
        or Path(name).name == "Makefile"
    }
    native.require(
        set(sources) == expected_paths, "compiled source closure is not complete"
    )
    for relative, expected in sources.items():
        path = Path(relative)
        native.require(
            not path.is_absolute() and ".." not in path.parts,
            "unsafe compiled source path",
        )
        native.require(
            hashlib.sha256((args.connector_root / path).read_bytes()).hexdigest()
            == expected,
            "compiled source differs from selected source",
        )
    library = Path(receipt["libmodsecurity"])
    native.require(
        hashlib.sha256(library.read_bytes()).hexdigest()
        == receipt.get("libmodsecurity_sha256"),
        "native engine library changed",
    )
    native.require(
        len(args.host_sha256) == 64
        and hashlib.sha256(args.host.read_bytes()).hexdigest() == args.host_sha256,
        "native host differs from admitted pinned artifact",
    )
    report["build_admission"] = {
        "receipt": str(args.build_receipt),
        "sha256": hashlib.sha256(args.build_receipt.read_bytes()).hexdigest(),
        "compiled_source_count": len(sources),
        "build_origin_revision": receipt["parent_revision"],
    }


def completion_writer_fault():
    """Bound only the selected fault-test service, never the launcher/host."""
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))


def validate_host_version(args, report):
    is_envoy = args.adapter.startswith("envoy")
    pin_file = (
        args.connector_root / "connectors/envoy/config/envoy-ext-proc-versions.env"
        if is_envoy
        else args.framework_root / "ci/lib/common.sh"
    )
    name = "ENVOY_RELEASE=" if is_envoy else "TRAEFIK_VERSION="
    releases = [
        line.split("=", 1)[1].strip('"')
        for line in pin_file.read_text().splitlines()
        if line.startswith(name)
    ]
    native.require(len(releases) == 1, "native host release pin missing/ambiguous")
    version = subprocess.check_output(
        [str(args.host), "--version" if is_envoy else "version"], text=True
    )
    expected = f"/{releases[0]}/" if is_envoy else f"Version:      {releases[0]}"
    native.require(
        expected in version, "native host release differs from selected source pin"
    )
    report["native_host_release"] = releases[0]


def validate_executable(path):
    """Bind executable selection to the file admitted by hash, never PATH lookup."""
    native.require(
        path.is_absolute() and path.is_file() and os.access(path, os.X_OK),
        "native executable must be an absolute executable file",
    )


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", choices=PROFILES, required=True)
    for name in (
        "connector-root",
        "framework-root",
        "runtime-root",
        "host",
        "service",
        "build-receipt",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--connector-revision", required=True)
    parser.add_argument("--framework-revision", required=True)
    parser.add_argument("--host-sha256", required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--completion-writer-fault", action="store_true")
    args = parser.parse_args()
    validate_executable(args.host)
    validate_executable(args.service)
    return args


def validate_sources(args, report):
    for checkout, revision in (
        (args.connector_root, args.connector_revision),
        (args.framework_root, args.framework_revision),
    ):
        native.require(
            subprocess.check_output(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
            ).strip()
            == revision,
            "source revision mismatch",
        )
        dirty = bool(
            subprocess.check_output(
                [
                    "git",
                    "-C",
                    str(checkout),
                    "status",
                    "--porcelain",
                    "--untracked-files=normal",
                ],
                text=True,
            ).strip()
        )
        native.require(
            not args.require_clean or not dirty, "final source checkout is dirty"
        )
        report.setdefault("source_worktree_dirty", {})[str(checkout)] = dirty


def report_preimage(path, expected=None):
    if not path.exists() and not path.is_symlink():
        return None
    metadata = path.lstat()
    native.require(
        stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
        "final report preimage is not a private regular file",
    )
    content = native.read_text(path).encode("utf-8")
    if expected is not None:
        native.require(
            native.load_json(content.decode("utf-8")) == expected,
            "foreign final report preimage",
        )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        hashlib.sha256(content).hexdigest(),
    )


def publish_final_report(root, report, preimage):
    destination = root / "report.json"
    pending = root / "final-report.pending.json"
    # Exclusive creation leaves an existing foreign pending object untouched.
    native.write_json(pending, report)
    try:
        native.require(
            report_preimage(destination) == preimage,
            "final report preimage changed before publication",
        )
        os.replace(pending, destination)
    finally:
        pending.unlink(missing_ok=True)


def finalize_report(args, root, report):
    """Publish success only after cleanup and unchanged source/artifact admission."""
    try:
        preimage = report_preimage(root / "report.json", report)
    except Exception as exc:
        report.update(status="FAIL", results=[], error=f"{type(exc).__name__}: {exc}")
        return
    try:
        if report["status"] == "VALIDATED":
            native.require(
                report.get("cleanup") == "PASS" and report.get("uds_cleanup") == "PASS",
                "final native cleanup failed",
            )
            validate_sources(args, report)
            admit_build(args, report)
            report["status"] = "PASS"
    except Exception as exc:
        report["status"] = "FAIL"
        report["error"] = f"{type(exc).__name__}: {exc}"
    if report["status"] != "PASS":
        report["status"] = "FAIL"
        report["results"] = []
    try:
        publish_final_report(root, report, preimage)
    except Exception as exc:
        report.update(status="FAIL", results=[], error=f"{type(exc).__name__}: {exc}")


def main():
    args = parse_arguments()
    os.environ.update(
        TEST_ROOT=str(args.framework_root),
        CONNECTOR_ROOT=str(args.connector_root),
        CONNECTOR_REVISION=args.connector_revision,
        FRAMEWORK_REVISION=args.framework_revision,
    )
    root = native.private_runtime_root(args.runtime_root)
    state = SimpleNamespace(processes=[], ports=[], fixture=None, thread=None)
    report = {
        "profile": PROFILES[args.adapter],
        "status": "FAIL",
        "cleanup": "NOT_RUN",
        "results": [],
        "source_revisions": {
            "parent": args.connector_revision,
            "framework": args.framework_revision,
        },
    }
    try:
        validate_sources(args, report)
        admit_build(args, report)
        env = os.environ | {
            "PYTHONPATH": f"{args.framework_root}:{args.framework_root / 'connector_suite'}"
        }
        preflight = [
            sys.executable,
            "-P",
            "-m",
            "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
            "--execution-context-only",
            "--connector",
            "envoy" if args.adapter.startswith("envoy") else "traefik",
            "--profile",
            PROFILES[args.adapter],
            "--runtime-root",
            str(root),
            "--output-dir",
            str(root / "preflight"),
        ]
        if args.adapter.startswith("traefik"):
            preflight.extend(("--uds-path", str(root / SOCKET_NAME)))
        subprocess.run(
            preflight,
            env=env,
            check=True,
            stdout=(root / "preflight.log").open("wb"),
            stderr=subprocess.STDOUT,
        )
        validate_host_version(args, report)
        cert, key = native.prepare_tls(root)
        native.start_fixture(state, cert, key, root)
        state.fixture.RequestHandlerClass = ObservedHandler
        listen, auth, admin = native.free_port(), native.free_port(), native.free_port()
        state.ports.extend((listen, auth, admin))
        runtime = root / "common.conf"
        runtime.write_text(
            f"enabled=on\nrules_file={args.framework_root}/tests/rules/no-crs-baseline.conf\ntransaction_id_header=x-acceptance-id\nrequest_body_mode=streaming\nresponse_body_mode=streaming\nphase4_mode={'strict' if args.case == 'phase4_strict' else 'safe'}\ndefault_block_status=403\ndefault_error_status=500\nuse_error_log=off\nevent_path={root}/common.jsonl\n"
        )
        is_envoy = args.adapter.startswith("envoy")
        command = (
            envoy_config(args, root, listen, auth, admin, state.fixture.server_port)
            if is_envoy
            else traefik_config(args, root, listen, auth, state.fixture.server_port)
        )
        service = [
            str(args.service),
            "--mode",
            "envoy" if is_envoy else "traefik",
            "--listen" if is_envoy else "--forwardauth-listen",
            f"127.0.0.1:{auth}",
            "--runtime-config",
            str(runtime),
            "--event-log",
            str(root / native.COMPLETION_LOG),
        ]
        if not is_envoy:
            service.extend(("--uds", str(root / SOCKET_NAME)))
        if args.case == "phase4_strict":
            service.extend(("--late-action-policy", "strict"))
        with (root / "service.log").open("wb") as log:
            child = subprocess.Popen(
                service,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                preexec_fn=completion_writer_fault
                if args.completion_writer_fault
                else None,
            )
        state.processes.append(("service", child))
        native.wait_host_listener(auth, state.processes)
        with (root / "host.log").open("wb") as log:
            host = subprocess.Popen(
                command, env=env, cwd=root, stdout=log, stderr=subprocess.STDOUT
            )
        state.processes.append(("host", host))
        native.wait_host_listener(listen, state.processes)
        wait_tls(listen, cert, state.processes)
        exercise(listen, cert, root, state.fixture, args.case, args.adapter)
        native.flush_native_writers(state.processes)
        records = events(root)
        wire = native.load_json(native.read_text(root / f"wire-{args.case}.json"))
        mapping = native.load_json(native.read_text(root / f"mapping-{args.case}.json"))
        access = native.read_records(root / ACCESS_LOG)
        common = (
            native.read_records(root / "common.jsonl")
            if (root / "common.jsonl").exists()
            else []
        )
        upstream = native.read_records(root / "upstream.jsonl")
        report["results"] = [
            validate_case(
                args.adapter,
                args.case,
                wire,
                records,
                mapping,
                access,
                common,
                upstream,
            )
        ]
        report["backend_identity"] = {
            "connector": "envoy",
            "integration_mode": "ext_proc",
            "role": "shared native CGo engine; logical profile proven by separate host and retained handoff",
        }
        report["source_revisions"] = {
            "parent": args.connector_revision,
            "framework": args.framework_revision,
        }
        report["artifact_hashes"] = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (args.host, args.service)
        }
        admit_build(args, report)
        report["status"] = "VALIDATED"
    except Exception as exc:
        report["status"] = "FAIL"
        report["results"] = []
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        native.reap_processes(state.processes)
        if (root / SOCKET_NAME).exists() or (root / SOCKET_NAME).is_symlink():
            report["status"] = "FAIL"
            report["uds_cleanup"] = "FAIL"
        else:
            report["uds_cleanup"] = "PASS"
        native.cleanup_run(root, state, report)
        finalize_report(args, root, report)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
