"""Closed NGINX modern-protocol inputs and independently reopened evidence.

Native event bytes stay unchanged. Client negotiation, stream identifiers and
wire transport are separate host facts; none is attributed to Common events.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

MODE = "native-nginx-http-module"
LIMIT = 262144
CASES = {
    "transport_http2_if_supported": ("h2", 4, 200, None),
    **{name: ("h2", 1, 403, 1100001) for name in (
        "protocol_h2_negotiated", "protocol_h2_no_http1_fallback", "h2_phase1_deny")},
    **{name: ("h3", 1, 403, 1100001) for name in (
        "protocol_h3_negotiated", "protocol_h3_quic_transport", "protocol_h3_no_h2_fallback", "h3_phase1_deny")},
    **{f"{protocol}_phase{phase}_{suffix}": (protocol, phase, status, rule)
       for protocol in ("h2", "h3")
       for phase, suffix, status, rule in ((2, "deny", 403, 1100101),
                                          (3, "deny", 403, 1100201),
                                          (4, "safe", 200, 1100301))},
    "protocol_h3_alt_svc_advertised": ("h3", 3, 200, None),
}
RESULTS = {case: "transport_http2" if case == "transport_http2_if_supported" else
           "late_intervention_log_only_safe" if case.endswith("_phase4_safe") else case
           for case in CASES}
LEAVES = frozenset({"observation.json", "native-events.jsonl", "access.jsonl", "client.json",
                    "quic.json", "cleanup.json", "roles.json"})


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def invocation(case):
    case_id = case.get("case_id")
    if case_id not in CASES:
        return None
    protocol, phase, status, rule = CASES[case_id]
    require(case.get("request", {}).get("protocol_profile") == protocol
            and case.get("phase") == phase and case.get("expected_rule_id") == rule
            and case.get("expected_status") in (None, status)
            and case.get("expected_result") == RESULTS[case_id], "protocol catalog contract changed")
    return {"operation": "native_protocol", "source_case_ids": [case_id],
            "mapping": "run-nginx-protocol-cases.py"}


def client_facts(raw, protocol):
    """Parse actual curl output; an option or advertised ALPN is insufficient."""
    version = str(raw.get("http_version", ""))
    negotiated = {"2": "h2", "3": "h3"}.get(version)
    trace = raw.get("trace", "")
    require(isinstance(trace, str) and len(trace) <= LIMIT, "bounded client trace required")
    alpn = re.findall(r"ALPN(?:,|:)\s*server accepted\s+(h[23])\b", trace)
    # Curl's actual HTTP/3 stream-open message can coexist with a TLS backend
    # that omits its ALPN status. Do not infer ALPN from that message.
    streams = re.findall(r"\[HTTP/[23]\]\s*\[(\d+)\]\s*(?:OPENED stream|:method:)", trace)
    require(negotiated == protocol, "forced protocol was not negotiated (fallback rejected)")
    require(alpn and set(alpn) == {protocol}, "actual accepted TLS ALPN is missing or mismatched")
    require(streams and len(set(streams)) == 1, "actual single client stream identity missing or ambiguous")
    require(raw.get("exit_code") == 0, "protocol client failed")
    return {"requested_protocol": protocol, "downstream_protocol": protocol,
            "negotiated_protocol": negotiated, "alpn": protocol, "stream_id": int(streams[0]),
            "transport": "quic_udp" if protocol == "h3" else "tls_tcp", "fallback_used": False}


def quic_datagram(frame, port):
    """Read only loopback IPv4 UDP/QUIC long-header metadata, never payload."""
    if len(frame) < 14 + 20 + 8 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    if (ip[0] >> 4 != 4 or ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17
            or ip[12:16] != b"\x7f\x00\x00\x01" or ip[16:20] != b"\x7f\x00\x00\x01"
            or int.from_bytes(ip[6:8], "big") & 0x3fff):
        return None
    udp = ip[ihl:]
    source, destination = int.from_bytes(udp[:2], "big"), int.from_bytes(udp[2:4], "big")
    if port not in (source, destination):
        return None
    data = udp[8:]
    if len(data) < 7 or data[0] & 0xc0 != 0xc0:
        return None
    version, length = int.from_bytes(data[1:5], "big"), data[5]
    if version == 0 or not 1 <= length <= 20 or len(data) < 7 + length:
        return None
    return {"direction": "request" if destination == port else "response",
            "quic_version": f"0x{version:08x}", "connection_id": "sha256:" + digest(data[6:6 + length]),
            "udp_bytes": len(udp)}


def read_leaf(root, leaf):
    require(leaf in LEAVES | {"receipt.json"}, "unknown protocol evidence leaf")
    require(root.is_absolute() and ".." not in root.parts, "absolute protocol evidence root required")
    for parent in (root, *root.parents):
        require(not parent.is_symlink(), "protocol evidence cannot traverse a symlink")
    directory = root.stat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.geteuid()
            and not stat.S_IMODE(directory.st_mode) & 0o077, "private owned protocol bundle directory required")
    fd = os.open(root / leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1
                and not stat.S_IMODE(metadata.st_mode) & 0o077 and metadata.st_size <= LIMIT,
                "protocol evidence must be bounded private single-link regular file")
        raw = stream.read(LIMIT + 1)
    require(len(raw) <= LIMIT, "protocol evidence grew beyond bound")
    return raw


def validate_bundle(root, *, case_id, run_id, identities=None):
    """Reopen original bytes and verify causal request/event/access bindings."""
    require(case_id in CASES, "unsupported protocol operation; no reset/multiplex promotion")
    raw_receipt = read_leaf(root, "receipt.json")
    receipt = json.loads(raw_receipt)
    require(receipt.get("case_id") == case_id and receipt.get("run_id") == run_id
            and receipt.get("integration_mode") == MODE, "protocol receipt identity mismatch")
    for key in ("parent_sha", "framework_sha", "mrts_sha"):
        require(isinstance(receipt.get(key), str) and re.fullmatch(r"[0-9a-f]{40}", receipt[key]),
                "exact protocol source revisions required")
        if identities is not None:
            require(receipt[key] == identities[key], "protocol receipt revision differs from authority")
    framework = Path(__file__).resolve().parents[2]
    sources = {"contract_sha256": Path(__file__),
               "driver_sha256": framework / "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-nginx-protocol-cases.py",
               "rules_sha256": framework / "tests/rules/no-crs-baseline.conf"}
    require(all(receipt.get(key) == digest(path.read_bytes()) for key, path in sources.items()),
            "protocol executor/contract/rules source differs from exact checked-in authority")
    require(all(isinstance(receipt.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", receipt[key])
                for key in ("binary_sha256", "module_sha256")), "actual protocol artifact SHA256 required")
    require(set(receipt.get("sha256", {})) == LEAVES, "closed protocol evidence inventory required")
    raws = {leaf: read_leaf(root, leaf) for leaf in LEAVES}
    require(all(digest(raw) == receipt["sha256"][leaf] for leaf, raw in raws.items()),
            "protocol evidence digest mismatch")
    value = {leaf: json.loads(raw) for leaf, raw in raws.items() if not leaf.endswith(".jsonl")}
    observed, client = value["observation.json"], value["client.json"]
    protocol, phase, status, rule = CASES[case_id]
    require(observed.get("case_id") == case_id and observed.get("run_id") == run_id,
            "protocol observation identity mismatch")
    require(observed.get("driver_error") is None, "original protocol driver failed")
    facts = client_facts(client, protocol)
    require(client.get("http_code") == status and observed.get("actual_status") == status,
            "actual protocol wire status differs from contract")
    accesses = [json.loads(line) for line in raws["access.jsonl"].splitlines() if line.strip()]
    require(len(accesses) == 2, "exact allow plus contract request access records required")
    transactions = []
    for index, (access, expected) in enumerate(zip(accesses, (200, status), strict=True)):
        expected_path = "/no-crs/protocol/allow" if index == 0 else observed.get("request_path")
        require(access.get("uri") == expected_path and access.get("status") == expected
                and access.get("protocol") == {"h2": "HTTP/2.0", "h3": "HTTP/3.0"}[protocol]
                and access.get("alpn") == protocol, "native access/client protocol or request binding mismatch")
        require(isinstance(access.get("transaction_id"), str)
                and access["transaction_id"].startswith(run_id + "-"), "native transaction/run binding missing")
        transactions.append(access["transaction_id"])
    require(len(set(transactions)) == 2, "allow and contract request transaction collision")
    require(value["roles.json"].get("master_uid") == 0 and value["roles.json"].get("worker_uid") == 65534,
            "observed isolated native roles required")
    cleanup = value["cleanup.json"]
    require(cleanup.get("verified") is True and cleanup.get("udp_listener_open") is False,
            "protocol process/TCP/UDP cleanup not verified")
    native = [json.loads(line) for line in raws["native-events.jsonl"].splitlines() if line.strip()]
    def original_allow(transaction, path):
        return [row for row in native if row.get("transaction_id") == transaction
                and row.get("uri") == path and row.get("method") == "GET"
                and row.get("connector") == "nginx" and row.get("integration_mode") == MODE
                and row.get("run_id") in (None, run_id) and row.get("transport_case_id") in (None, case_id)
                and row.get("event") == "request_headers_complete" and row.get("status") == "ok"
                and row.get("requested_action") == "allow"
                and row.get("phase") in (1, "1", "request_headers")]
    require(original_allow(transactions[0], "/no-crs/protocol/allow"),
            "actual allow request lacks original native P1 completion")
    transaction_events = [row for row in native if row.get("transaction_id") == transactions[1]
                and row.get("connector") == "nginx" and row.get("integration_mode") == MODE
                and row.get("run_id") in (None, run_id) and row.get("transport_case_id") in (None, case_id)]
    require(any(row.get("uri") == observed.get("request_path") for row in transaction_events),
            "original native event for actual contract request/transaction is missing")
    matching = [row for row in transaction_events if str(row.get("rule_id")) == str(rule)
                and row.get("phase") in (phase, str(phase),
                    {1: "request_headers", 2: "request_body", 3: "response_headers", 4: "response_body"}[phase])]
    if rule is None:
        matching = original_allow(transactions[1], observed.get("request_path"))
    elif phase in (1, 2):
        matching = [row for row in matching if row.get("uri") == observed.get("request_path")
                    and row.get("event") in {f"phase{phase}_intervention", "engine_decision"}
                    and row.get("status") == "blocked" and row.get("requested_action") == "deny"
                    and row.get("http_status") == 403 and row.get("actual_action") in ("", "deny")]
    elif phase == 3:
        # Current native Phase-3 intervention omits request URI. Its exact
        # transaction and rule/phase bind it to the original same-transaction
        # URI witness above; no URI is copied into the intervention event.
        matching = [row for row in matching if row.get("event") == "phase3_intervention"
                    and row.get("status") == "blocked" and row.get("requested_action") == "deny"
                    and row.get("actual_action") == "deny" and row.get("http_status") == 403
                    and row.get("visible_http_status") == 403 and row.get("response_committed") is False]
    elif phase == 4:
        matching = [row for row in matching if row.get("uri") == observed.get("request_path")
                    and row.get("event") == "phase4_intervention" and row.get("status") == "blocked"
                    and row.get("requested_action") == "deny" and row.get("actual_action") == "log_only"
                    and row.get("http_status") == 403 and row.get("visible_http_status") == 200
                    and row.get("response_committed") is True and row.get("headers_sent") is True
                    and row.get("late_intervention") is True and row.get("late_intervention_mode") == "safe"
                    and row.get("connection_aborted") is False]
    require(matching, "native intervention/allow semantic witness is missing or contradicts wire outcome")
    if case_id == "protocol_h3_alt_svc_advertised":
        require(client.get("alt_svc_h3") is True, "actual Alt-Svc response header missing")
    quic = value["quic.json"]
    if protocol == "h3":
        packets = quic.get("datagrams", [])
        require({row.get("direction") for row in packets} == {"request", "response"},
                "actual bidirectional QUIC/UDP evidence missing")
        require(all(re.fullmatch(r"sha256:[0-9a-f]{64}", row.get("connection_id", ""))
                    and row.get("quic_version") in {"0x00000001", "0x6b3343cf"} for row in packets),
                "unsupported QUIC version or unhashed connection ID")
        facts.update(quic_connection_id_present=True, quic_version=packets[0]["quic_version"])
    return {"facts": facts, "transaction_ids": transactions, "native_events": native,
            "observed_result": RESULTS[case_id],
            "matching_events": matching, "actual_status": status, "receipt": receipt,
            "raws": dict(raws, **{"receipt.json": raw_receipt})}
