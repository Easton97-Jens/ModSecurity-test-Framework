"""Independent, fail-closed checks for opt-in native protocol acceptance bundles.

This registry is a preparation surface. It does not add catalog cases, select
default tests, or promote connector capabilities. Original client, access and
native event records remain independent witnesses.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

MODE = "native-nginx-http-module"
LIMIT = 8 * 1024 * 1024
SOURCE_PATHS = frozenset({
    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-protocol-acceptance.py",
    "tests/runners/protocol_acceptance_contract.py",
    "tests/runners/protocol_acceptance_client.py",
    "tests/runners/protocol_acceptance_client.c",
    "tests/rules/protocol-acceptance.conf",
})
LEAVES = frozenset({"client.jsonl", "upstream.json", "access.jsonl",
                    "native-events.jsonl", "roles.json", "cleanup.json", "quic.json",
                    "nginx.conf", "rules.conf"})
CASES = {}
for _protocol in ("h2", "h3"):
    for _suffix, _scenario, _expectation in (
        ("parallel_stream_transaction_isolation", "multiplex", "protocol_transaction_isolation"),
        ("deny_does_not_abort_unrelated_stream" if _protocol == "h2" else "deny_does_not_abort_unrelated_stream_preparation",
         "multiplex", "protocol_unrelated_stream_healthy"),
        ("parallel_cleanup_balanced", "multiplex", "protocol_parallel_cleanup_balanced"),
        ("first_byte_before_response_end", "streaming", "first_byte_before_response_end"),
        ("no_full_response_buffering", "streaming", "no_full_response_buffering"),
        ("client_rst_stream" if _protocol == "h2" else "client_stream_cancel",
         "client-cancel", "protocol_client_stream_reset"),
        ("upstream_reset", "upstream-reset", "protocol_upstream_reset"),
        ("phase3_deny", "phase3", f"{_protocol}_phase3_deny"),
        ("phase4_safe", "safe", "late_intervention_log_only_safe"),
        ("phase4_strict", "strict", "protocol_server_stream_reset"),
        ("server_rst_stream" if _protocol == "h2" else "server_stream_reset",
         "strict", "protocol_server_stream_reset"),
    ):
        CASES[f"{_protocol}_{_suffix}"] = {
            "protocol": _protocol, "scenario": _scenario, "expectation": _expectation}
CASES["h2c_prior_knowledge_preparation"] = {
    "protocol": "h2c", "scenario": "multiplex", "expectation": "h2c_without_tls_alpn"}
CASES["h3_reset_does_not_abort_unrelated_stream"] = {
    "protocol": "h3", "scenario": "strict", "expectation": "protocol_unrelated_stream_healthy"}
CASES["phase4_strict_http2_stream_reset"] = {
    "protocol": "h2", "scenario": "strict", "expectation": "protocol_server_stream_reset"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(root, leaf):
    require(root.is_absolute() and ".." not in root.parts, "absolute bundle root required")
    require(not any(path.is_symlink() for path in (root, *root.parents)), "symlink bundle root")
    metadata = root.stat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
            and not metadata.st_mode & 0o077, "private owned bundle directory required")
    fd = os.open(root / leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and metadata.st_uid == os.geteuid() and metadata.st_size <= LIMIT,
                "bounded owned regular evidence leaf required")
        return stream.read(LIMIT + 1)


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: require(False, "nonfinite JSON number"))


def _rows(raw):
    require(raw.endswith(b"\n") and raw.strip(), "complete nonempty JSONL required")
    rows = [_json(line) for line in raw.splitlines()]
    require(all(isinstance(row, dict) for row in rows), "JSONL object rows required")
    return rows


def _listeners(config):
    # Split complete directives first so a missing semicolon cannot cause
    # repeated scans of the remaining configuration for each listen prefix.
    listeners = []
    for statement in config.split(b";")[:-1]:
        match = re.search(rb"\blisten\s++127\.0\.0\.1:\d++", statement)
        if match:
            listeners.append(statement[match.end():])
    return listeners


def _effective_config(root, case, source_root, raws):
    rules = (source_root / "tests/rules/protocol-acceptance.conf").read_bytes()
    if case["scenario"] == "multiplex":
        rules += b'\nSecRule REQUEST_URI "@endsWith /target" "id:1100001,phase:1,deny,status:403,log,t:none,msg:\'protocol acceptance P1\'"\n'
    require(raws["rules.conf"] == rules, "effective rules differ from fixed source contract")
    config = raws["nginx.conf"]
    for directive in (b"modsecurity on;", b"proxy_buffering off;", b"http2 on;",
                      b"modsecurity_phase4_mode " + (b"strict" if case["scenario"] == "strict" else b"safe") + b";",
                      f'modsecurity_rules_file "{root}/rules.conf";'.encode(),
                      f'load_module "{root}/nginx-module.so";'.encode(),
                      f'modsecurity_phase4_log "{root}/native-events.jsonl";'.encode()):
        require(config.count(directive) == 1, "effective config directive missing/ambiguous")
    listens = _listeners(config)
    require(listens and (all(b"ssl" not in value and b"quic" not in value for value in listens)
                         if case["protocol"] == "h2c" else any(b"ssl" in value for value in listens)),
            "effective listener TLS contract mismatch")
    require((any(b"quic" in value for value in listens)) == (case["protocol"] == "h3"),
            "effective listener QUIC contract mismatch")


def _receipt(root, case_id, run_id, identities):
    receipt = _json(_read(root, "receipt.json"))
    case = CASES[case_id]
    require(receipt.get("schema_version") == 1 and receipt.get("case_id") == case_id
            and receipt.get("run_id") == run_id, "receipt identity mismatch")
    require(receipt.get("protocol") == case["protocol"] and receipt.get("scenario") == case["scenario"],
            "receipt case contract mismatch")
    require(receipt.get("profile") == MODE, "native host profile identity required")
    for key in ("parent_sha", "framework_sha", "mrts_sha"):
        require(re.fullmatch(r"[0-9a-f]{40}", str(receipt.get(key, ""))), "revision identity required: " + key)
    source_hashes = receipt.get("source_sha256", {})
    require(set(source_hashes) == SOURCE_PATHS, "closed acceptance source map required")
    source_root = Path(__file__).resolve().parents[2]
    for name in SOURCE_PATHS:
        require(source_hashes[name] == digest((source_root / name).read_bytes()), "source hash mismatch: " + name)
    artifacts = receipt.get("artifact_sha256", {})
    require(set(artifacts) == {"nginx_binary", "module", "client_binary"}
            and all(re.fullmatch(r"[0-9a-f]{64}", str(value)) for value in artifacts.values()),
            "compiled artifact identities required")
    for key, leaf in (("nginx_binary", "nginx-binary"), ("module", "nginx-module.so"), ("client_binary", "protocol-client")):
        fd = os.open(root / leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1,
                    "owned regular artifact snapshot required")
            require(hashlib.file_digest(stream, "sha256").hexdigest() == artifacts[key], "artifact hash mismatch: " + key)
    if identities is not None:
        require(isinstance(identities, dict) and identities, "nonempty explicit identities required")
        for key, value in identities.items():
            require(receipt.get(key) == value, "external identity mismatch: " + key)
    leaves = LEAVES
    require(set(receipt.get("sha256", {})) == leaves, "exact evidence leaf hash map required")
    raws = {leaf: _read(root, leaf) for leaf in leaves}
    require(all(receipt["sha256"][leaf] == digest(raw) for leaf, raw in raws.items()), "evidence hash mismatch")
    _effective_config(root, case, source_root, raws)
    return receipt, raws


def _client_lifetime(rows, events, path, protocol):
    begun = [row for row in events if row.get("event") == "request_started"]
    ended = [row for row in events if row.get("event") == "completed"]
    require(len(begun) == len(ended) == 1 and begun[0].get("path") == path,
            "exactly three named requests must start and complete")
    require(rows.index(begun[0]) < rows.index(ended[0]), "completion precedes request")
    require(all(row.get("event") in {"request_started", "first_data", "debug_observation", "completed", "cancelled"}
                for row in events), "unknown client/error event")
    start, end = begun[0].get("monotonic_ns"), ended[0].get("monotonic_ns")
    require(type(start) is int and type(end) is int and 0 < start < end, "client monotonic lifetime required")
    require(ended[0].get("http_version") == (30 if protocol == "h3" else 3), "client protocol fallback")
    connection = ended[0].get("conn_id")
    require(type(connection) is int and connection >= 0, "actual libcurl connection identity required")
    return start, end, ended[0], connection


def _client_stream(events, start, end, connection):
    observations = [row for row in events if row.get("event") == "debug_observation" and "stream_id" in row]
    ids = {row["stream_id"] for row in observations}
    require(len(ids) == 1 and all(type(value) is int and value >= 0 for value in ids), "actual client stream identity required")
    stream = next(iter(ids))
    require(all(re.search(r"\[HTTP/[23]\]\s*\[" + str(stream) + r"\]", row.get("observation", ""))
                for row in observations), "stream identity missing original debug witness")
    require(all(row.get("conn_id", connection) == connection for row in observations), "client connection observation mismatch")
    observed_times = [row.get("monotonic_ns") for row in observations]
    require(all(type(value) is int and start <= value < end for value in observed_times), "actual stream opening lifetime required")
    return stream, min(observed_times)


def _client_reset(events, name, scenario, protocol, stream, completion):
    failures = [row for row in events if row.get("debug_failure")]
    reset_witnesses = []
    reset_source = None
    for row in failures:
        match = re.fullmatch(r"HTTP/([23]) stream (\d+) reset by server \(error (0x[0-9a-fA-F]+) [A-Z0-9_]+\)",
                             row["debug_failure"] if isinstance(row["debug_failure"], str) else "")
        require(name == "target" and scenario in {"strict", "upstream-reset"} and match is not None
                and int(match[1]) == (3 if protocol == "h3" else 2)
                and int(match[2]) == stream and int(match[3], 16) > 0,
                "unexpected client failure or reset identity mismatch")
        if row.get("event") == "debug_observation":
            reset_witnesses.append(row["debug_failure"])
            reset_source = row
    if scenario in {"strict", "upstream-reset"} and name == "target":
        require(len(reset_witnesses) == 1 and completion.get("error") in reset_witnesses
                and completion.get("debug_failure") in reset_witnesses,
                "reset scenario requires original libcurl server-reset witness")
    return reset_source


def _client_cancellation(events, name, scenario, completion):
    cancelled = [row for row in events if row.get("event") == "cancelled"]
    expect_cancel = name == "target" and scenario == "client-cancel"
    require(bool(cancelled) == expect_cancel and bool(completion.get("cancelled")) == expect_cancel,
            "unexpected or missing client cancellation")
    if expect_cancel:
        require(len(cancelled) == 1 and cancelled[0].get("method") == "curl_multi_remove_handle"
                and any(row.get("event") == "first_data" for row in events)
                and cancelled[0].get("peer_active") is True
                and completion.get("curl_code") is None, "client cancel lacks delivered data/removal/live peer")
    expected_error = name == "target" and scenario in {"client-cancel", "upstream-reset", "strict"}
    if not expected_error:
        require(completion.get("curl_code") == 0 and not completion.get("error"), "unexpected client transfer error")
    elif not expect_cancel:
        require(type(completion.get("curl_code")) is int and completion["curl_code"] != 0,
                "abort/reset contract requires an actual client error")


def _client_overlap(rows, paths, connections, streams, starts, ends, opened):
    require(len(rows) > 0 and all(row.get("name") in paths for row in rows), "foreign or empty client requests")
    require(connections["target"] == connections["peer"] and streams["target"] != streams["peer"],
            "first two requests must use distinct streams on one connection")
    require(max(starts["target"], starts["peer"]) < min(ends["target"], ends["peer"]), "requests did not overlap")
    require(max(opened["target"], opened["peer"]) < min(ends["target"], ends["peer"]),
            "actual streams were not simultaneously open")
    require(starts["followup"] > max(ends["target"], ends["peer"]), "followup must follow both transfers")
    require(connections["followup"] == connections["target"], "healthy followup did not reuse connection")


def _client_reset_overlap(rows, reset_source, opened, ends):
    reset_time = reset_source.get("monotonic_ns")
    require(type(reset_time) is int and max(opened["target"], opened["peer"]) < reset_time
            < min(ends["target"], ends["peer"]), "server reset did not occur with both actual streams active")
    peer_data = [row for row in rows if row.get("name") == "peer" and row.get("event") == "first_data"]
    require(peer_data and all(type(row.get("monotonic_ns")) is int and row["monotonic_ns"] >= reset_time
                              for row in peer_data), "peer response was not held until actual reset")


def _client(rows, paths, protocol, scenario):
    completions, streams, connections, starts, ends, opened = {}, {}, {}, {}, {}, {}
    reset_source = None
    for name, path in paths.items():
        events = [row for row in rows if row.get("name") == name]
        start, end, completion, connection = _client_lifetime(rows, events, path, protocol)
        starts[name], ends[name], completions[name] = start, end, completion
        connections[name] = connection
        stream, opened[name] = _client_stream(events, start, end, connection)
        streams[name] = stream
        observed_reset = _client_reset(events, name, scenario, protocol, stream, completion)
        if observed_reset is not None:
            reset_source = observed_reset
        alpn = [row["alpn"] for row in events if "alpn" in row]
        require(not alpn if protocol == "h2c" else not alpn or set(alpn) == {protocol}, "client ALPN mismatch")
        _client_cancellation(events, name, scenario, completion)
    _client_overlap(rows, paths, connections, streams, starts, ends, opened)
    if scenario in {"strict", "upstream-reset"}:
        _client_reset_overlap(rows, reset_source, opened, ends)
    return completions, streams, connections, reset_source


def _access_endpoint(row):
    endpoint = row.get("transport_endpoint")
    require(isinstance(endpoint, str) and re.fullmatch(r"127\.0\.0\.1:\d{1,5}", endpoint, re.ASCII)
            and 0 < int(endpoint.rsplit(":", 1)[1]) <= 65535, "actual H3 transport endpoint required")
    return endpoint


def _access_status(row, name, scenario, completion):
    status = row.get("status")
    require(type(status) is int and 100 <= status <= 599, "server native status required")
    if name != "target":
        require(status == completion.get("status") == 200, "unrelated request was not healthy")
    else:
        wanted = 403 if scenario in {"multiplex", "phase3"} else 200
        require(status == completion.get("status") == wanted, "wire/server target status mismatch")


def _access(raw, paths, protocol, scenario, completed):
    access = _rows(raw["access.jsonl"])
    require(len(access) == 3, "exactly three original access records required")
    transactions, access_connections, endpoints = {}, {}, {}
    for name, path in paths.items():
        rows = [row for row in access if row.get("uri") == path]
        require(len(rows) == 1, "access request mapping missing/ambiguous")
        row = rows[0]
        transaction = row.get("transaction_id")
        require(isinstance(transaction, str) and transaction, "access transaction identity missing")
        transactions[name] = transaction
        require(row.get("protocol") == ("HTTP/3.0" if protocol == "h3" else "HTTP/2.0"), "server protocol mismatch")
        require(row.get("alpn") == ("" if protocol == "h2c" else protocol), "server ALPN mismatch")
        require(row.get("connection_id") not in (None, ""), "server connection identity missing")
        access_connections[name] = row["connection_id"]
        if protocol == "h3":
            endpoints[name] = _access_endpoint(row)
        _access_status(row, name, scenario, completed[name])
    require(len(set(transactions.values())) == 3, "transaction identity reused between streams")
    if protocol == "h3":
        # NGINX's HTTP/3 $connection identifies a per-stream fake connection.
        # Actual network reuse is proved by libcurl's native connection ID,
        # the observed UDP peer endpoint and bidirectional QUIC metadata.
        require(len(set(endpoints.values())) == 1, "H3 transport endpoint crossover")
    else:
        require(len(set(access_connections.values())) == 1, "server/client connection reuse differs")
    return transactions, access_connections


def _native_request_identity(events, path, connection, stream):
    for row in events:
        require(not row.get("uri") or row["uri"] == path, "native request crossover")
        if row.get("connection_id") not in (None, ""):
            require(row["connection_id"] == "nginx-" + str(connection),
                    "native/access connection mismatch")
        if row.get("stream_id") not in (None, ""):
            require(str(row["stream_id"]) == str(stream), "native/client stream mismatch")


def _native_response_phase(row, scenario):
    if scenario == "phase3":
        return (row.get("phase") == "response_headers"
                and row.get("original_http_status") == 200 and row.get("visible_http_status") == 403
                and row.get("response_committed") is False and row.get("headers_sent") is False)
    if scenario in {"safe", "strict"}:
        return (row.get("phase") == "response_body" and row.get("headers_sent") is True
                and row.get("response_committed") is True and row.get("late_intervention") is True
                and row.get("connection_aborted") is (scenario == "strict")
                and row.get("visible_http_status") == 200)
    return True


def _native_action(row, scenario, action):
    return (row.get("status") == "blocked" and row.get("requested_action") == "deny"
            and (row.get("actual_action") == action or scenario == "multiplex" and row.get("actual_action") == "")
            and row.get("http_status") == 403 and _native_response_phase(row, scenario))


def _native_intervention(rules, scenario):
    phase = {"multiplex": 1, "phase3": 3, "safe": 4, "strict": 4}[scenario]
    matches = [row for row in rules if row.get("event") == f"phase{phase}_intervention"
               or phase == 1 and row.get("event") == "engine_decision"
               and row.get("phase") == "request_headers"]
    require(matches, "original native intervention missing")
    action = {"safe": "log_only", "strict": "abort_connection"}.get(scenario, "deny")
    require(any(_native_action(row, scenario, action) for row in matches),
            "native requested/actual action and status contract mismatch")


def _native_rules(events, name, scenario):
    rules = [row for row in events if str(row.get("rule_id", "")) not in ("", "0", "None")]
    expected_rule = {"multiplex": "1100001", "phase3": "1100201", "safe": "1100301", "strict": "1100301"}.get(scenario)
    if name != "target" or expected_rule is None:
        require(not rules, "rule crossed into unrelated stream")
    else:
        require(rules and all(str(row.get("rule_id")) == expected_rule for row in rules), "target rule witness mismatch")
        _native_intervention(rules, scenario)


def _native(raw, paths, transactions, access_connections, streams, scenario, identity):
    run_id, case_id = identity
    native = _rows(raw["native-events.jsonl"])
    require(all(row.get("transaction_id") in transactions.values() for row in native), "foreign native transaction")
    for name, transaction in transactions.items():
        events = [row for row in native if row.get("transaction_id") == transaction]
        require(events and any(row.get("uri") == paths[name] for row in events), "native URI/transaction binding missing")
        require(all(row.get("connector") == "nginx" and row.get("integration_mode") == MODE
                    and row.get("run_id") in (None, "", run_id)
                    and row.get("transport_case_id") in (None, "", case_id) for row in events), "native source identity mismatch")
        cleanup = [row for row in events if row.get("event") == "transaction_cleanup"]
        require(len(cleanup) == 1 and events[-1] == cleanup[0], "one final native cleanup per transaction required")
        require(all(re.search(r"(?:^|;)" + token + r"(?:;|$)", cleanup[0].get("reason", ""))
                    for token in ("common_return=0", "common_complete=1", "native_cleanup_completed=1"))
                and cleanup[0].get("status") == "ok", "native cleanup did not return successfully")
        require(cleanup[0].get("run_id") == run_id and cleanup[0].get("transport_case_id") == case_id,
                "native cleanup lacks actual run/case provenance")
        _native_request_identity(events, paths[name], access_connections[name], streams[name])
        _native_rules(events, name, scenario)
    return native


def _native_overlap(native, transactions, scenario):
    def position(name, event):
        found = [index for index, row in enumerate(native)
                 if row.get("transaction_id") == transactions[name] and row.get("event") == event]
        require(len(found) == 1, "unique native multiplex lifetime witness required")
        return found[0]
    peer_start = position("peer", "request_headers_complete")
    if scenario == "multiplex":
        require(peer_start < position("target", "engine_decision")
                < position("target", "transaction_cleanup") < position("peer", "transaction_cleanup"),
                "native transactions did not overlap across target denial")
    elif scenario == "strict":
        require(peer_start < position("target", "phase4_intervention") < position("peer", "transaction_cleanup"),
                "native peer did not remain active across strict intervention")
    else:
        target_first = next(index for index, row in enumerate(native) if row.get("transaction_id") == transactions["target"])
        require(peer_start < target_first, "native peer was not active before upstream-reset target")


def _upstream_first_byte(target, client_rows):
    require(target.get("first_byte_observed_before_eos") is True,
            "first byte was not independently observed before upstream EOS")
    require(any(row.get("event") == "first_data" and row.get("name") == "target" for row in client_rows),
            "client first-byte witness missing")
    observation = target.get("first_byte_observation", {})
    require(observation.get("upstream_paused") is True and observation.get("eos_sent") is False
            and observation.get("response_finished") is False
            and type(observation.get("observed_bytes")) is int and observation["observed_bytes"] > 0,
            "first-byte barrier snapshot does not precede EOS")
    first = next(row for row in client_rows if row.get("event") == "first_data" and row.get("name") == "target")
    event_time = observation.get("client_event_monotonic")
    observed_time = observation.get("observation_monotonic")
    released_time = target.get("released_monotonic")
    require(all(type(value) in (int, float) for value in (event_time, observed_time, released_time))
            and 0 < event_time <= observed_time <= released_time
            and abs(event_time - first["monotonic_ns"] / 1_000_000_000) < 0.001,
            "first-byte source event/barrier timing mismatch")
    if target.get("eos_sent"):
        require(type(target.get("eos_monotonic")) in (int, float)
                and released_time <= target["eos_monotonic"], "upstream EOS preceded release")


def _upstream_entry(entries, path, name, scenario):
    denied = name == "target" and scenario == "multiplex"
    if denied:
        require(path not in entries or entries[path].get("arrivals") == 0, "phase1 denied request reached upstream")
    else:
        require(path in entries and entries[path].get("arrivals") == 1, "upstream request missing/duplicated")
    if path in entries:
        require(not entries[path].get("writer_error") and not entries[path].get("write_error"), "upstream writer error")
        if entries[path].get("expected_disconnect"):
            require(name == "target" and scenario in {"client-cancel", "upstream-reset", "strict", "phase3"}
                    or name == "peer" and scenario == "strict", "unexpected upstream disconnect")


def _upstream_entries(upstream, paths, scenario):
    entries = upstream.get("paths", {})
    require(set(entries) <= set(paths.values()) and paths["peer"] in entries and paths["followup"] in entries,
            "upstream path mapping mismatch")
    for name, path in paths.items():
        _upstream_entry(entries, path, name, scenario)
    return entries


def _upstream(raw, paths, scenario, client_rows, reset_source):
    upstream = _json(raw["upstream.json"])
    require(upstream.get("driver_error") is None and upstream.get("peer_held_until_target_observed") is True,
            "upstream barrier failed or writer error")
    if scenario in {"strict", "upstream-reset"}:
        reset_observation = upstream.get("reset_observation", {})
        require(upstream.get("peer_held_until_reset_observed") is True
                and reset_observation.get("peer_response_finished") is False
                and reset_observation.get("client_event_monotonic_ns") == reset_source["monotonic_ns"],
                "upstream peer/reset barrier lacks actual client event binding")
    entries = _upstream_entries(upstream, paths, scenario)
    if scenario in {"streaming", "safe", "client-cancel", "upstream-reset", "strict"}:
        _upstream_first_byte(entries[paths["target"]], client_rows)
    if scenario in {"streaming", "safe"}:
        require(entries[paths["target"]].get("eos_sent") is True, "normal streaming upstream never completed")
    if scenario == "upstream-reset":
        require(entries[paths["target"]].get("upstream_aborted") is True
                and entries[paths["target"]].get("eos_sent") is False, "actual upstream abort before EOS required")


def _cleanup(raw, protocol):
    roles = _json(raw["roles.json"])
    require(roles.get("master_uid") == 0 and roles.get("worker_uid") == 65534, "native isolated roles missing")
    cleanup = _json(raw["cleanup.json"])
    require(cleanup.get("verified") is True and cleanup.get("udp_listener_open") is False
            and cleanup.get("upstream_stopped") is True and cleanup.get("client_stopped") is True,
            "task listeners/threads cleanup unverified")
    if protocol == "h3":
        from tests.runners.nginx_protocol import add_quic_facts
        add_quic_facts({}, _json(raw["quic.json"]), protocol)


def validate_bundle(root, case_id, run_id, identities=None):
    """Reopen a closed bundle; raise ValueError for missing/contradictory proof."""
    require(case_id in CASES, "unknown acceptance case (zero-case success forbidden)")
    require(isinstance(run_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,96}", run_id), "safe nonempty run identity required")
    root = Path(root)
    _, raw = _receipt(root, case_id, run_id, identities)
    case = CASES[case_id]
    protocol, scenario = case["protocol"], case["scenario"]
    paths = {name: f"/acceptance/{run_id}/{name}" for name in ("target", "peer", "followup")}
    client_rows = _rows(raw["client.jsonl"])
    completed, streams, connections, reset_source = _client(client_rows, paths, protocol, scenario)
    transactions, access_connections = _access(raw, paths, protocol, scenario, completed)
    native = _native(raw, paths, transactions, access_connections, streams, scenario, (run_id, case_id))
    if scenario in {"multiplex", "strict", "upstream-reset"}:
        _native_overlap(native, transactions, scenario)
    _upstream(raw, paths, scenario, client_rows, reset_source)
    _cleanup(raw, protocol)
    return {"case_id": case_id, "run_id": run_id, **case, "transactions": transactions,
            "client_connection_id": connections["target"], "stream_ids": streams,
            "network_connection_reused": True, "server_stream_reset": scenario == "strict",
            "server_reset_witness": completed["target"].get("debug_failure") if scenario == "strict" else None,
            "first_byte_before_eos": scenario in {"streaming", "safe", "client-cancel", "upstream-reset", "strict"},
            "validated": True}
