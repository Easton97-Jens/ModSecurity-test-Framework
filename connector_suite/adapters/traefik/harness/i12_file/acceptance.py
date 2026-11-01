"""Pre-run physical HTTP-file stimuli and oracles; never qualify native File APIs.

This contract is independent of host observations. Its nine executions retain
the four original obligations and require separate native lifecycle evidence.
"""

import copy
import hashlib
import json

SCHEMA = "traefik-physical-file-acceptance-v1"
BACKEND_BODY = b"i12-file-independent-backend\n"
BACKEND_BODY_SHA256 = hashlib.sha256(BACKEND_BODY).hexdigest()
BENIGN_FILE = "benign.txt"
REQUEST_MARKER_FILE = "request-marker.txt"
REQUEST_OUTSIDE_SAMPLE_FILE = "request-outside-sample.txt"
RESPONSE_MARKER_FILE = "response-marker.txt"
MARKER_CONTROL = "marker"
CAPACITY_CONTROL = "capacity"
FORWARDAUTH_PREFIX = "traefik-forwardauth"
FORWARDAUTH_REQUEST_ROUTE = "traefik-forwardauth-request"
NATIVE_ROUTE = "traefik-native-uds"
BASE_RULES = [
    "SecRuleEngine On", "SecRequestBodyAccess On", "SecRequestBodyLimit 2097152",
    "SecRequestBodyNoFilesLimit 2097152", "SecRequestBodyLimitAction Reject",
    "SecResponseBodyAccess On", "SecResponseBodyLimit 2097152",
    "SecResponseBodyLimitAction Reject", "SecResponseBodyMimeType text/plain",
    'SecRule REQUEST_BODY "@contains no-crs-request-body-marker" "id:1100101,phase:2,deny,status:403,log,t:none"',
    'SecRule RESPONSE_BODY "@contains no-crs-response-body-marker" "id:1100301,phase:4,deny,status:403,log,t:none"',
]
FIXTURES = {
    BENIGN_FILE: (60, "6316ee68a2062be39c1eb8675a0a9082e5d433ff357ea7b225b94fa7d70ddd54"),
    REQUEST_MARKER_FILE: (55, "895e5fc9cc86f989b1b971800fe7113ddf3be8d0944180091c36e375a9f72a8b"),
    REQUEST_OUTSIDE_SAMPLE_FILE: (4199, "d0385cccf0749495eecb521407198b204b165a1086e55fc6549c857dbe6824fc"),
    RESPONSE_MARKER_FILE: (56, "56f2d9ee2d8bffc7c427fe02ebe56dbff0f69b46524b879e7d2d89ccd66b80de"),
}
ROUTES = [
    ("traefik-native-uds", "request", "native-request", "traefik-native"),
    ("traefik-native-uds", "response", "native-response", "traefik-native"),
    ("traefik-forwardauth-request", "request", "auth-request", "traefik-forwardauth"),
    ("traefik-forwardauth-response-companion", "response", "auth-response", "traefik-forwardauth"),
]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def fixture_name(direction, control):
    if control == CAPACITY_CONTROL:
        return REQUEST_OUTSIDE_SAMPLE_FILE
    if control == MARKER_CONTROL:
        return REQUEST_MARKER_FILE if direction == "request" else RESPONSE_MARKER_FILE
    return BENIGN_FILE


def client_status(capacity, denied):
    if capacity:
        return 401
    return 403 if denied else 200


def backend_arrivals(route, capacity, denied):
    if denied and route == NATIVE_ROUTE:
        return "measure-accept-headers-prefix"
    return 0 if capacity or denied else 1


def authorization_sample(route, capacity):
    if capacity:
        return "absent"
    if route == FORWARDAUTH_REQUEST_ROUTE:
        return "exact-request-file"
    return "separate-host-capture-required"


def native_rule(denied, response_marker):
    if denied:
        return 1100101, 2
    if response_marker:
        return 1100301, 4
    return None, None


def frozen_expectation(route, direction, control):
    """Literal rules/host contract, frozen before the reader or host starts."""
    capacity = control == CAPACITY_CONTROL
    denied = direction == "request" and control == MARKER_CONTROL
    response_marker = direction == "response" and control == MARKER_CONTROL
    fixture = fixture_name(direction, control)
    body = FIXTURES[fixture] if direction == "response" else (len(BACKEND_BODY), BACKEND_BODY_SHA256)
    rule_id, phase = native_rule(denied, response_marker)
    intervention = 403 if denied or response_marker else None
    entity = None if capacity or denied else {"bytes": body[0], "sha256": body[1]}
    deny_entity = "actual-bytes-required-no-invented-template" if denied or capacity else None
    return {
        "source": "predeclared physical HTTP-file rule/host-capacity contract",
        "client_status": client_status(capacity, denied),
        "authorization_transport": "default-MRC1" if route.startswith(FORWARDAUTH_PREFIX) else None,
        "backend_target_arrivals": backend_arrivals(route, capacity, denied),
        "authorization_sample": authorization_sample(route, capacity),
        "native_transaction": "absent" if capacity else "separate-complete-lifecycle-required",
        "native_rule_id": rule_id, "native_phase": phase,
        "native_intervention_status": intervention,
        "client_entity": entity, "deny_response_entity": deny_entity,
        "phase4_mode": "safe", "native_file_api": False,
        "native_eos_from_tcp_eof": False, "qualification": "unqualified",
        "claim": "physical regular-file reads transported over native byte APIs",
        "native_request_backend_exclusion_inferred": False,
    }


def controls_for(route):
    controls = ["benign", MARKER_CONTROL]
    if route == FORWARDAUTH_REQUEST_ROUTE:
        controls.append(CAPACITY_CONTROL)
    return controls


def case_for(route, direction, label, capture, control):
    key = "file-" + label + "-" + control
    filename = fixture_name(direction, control)
    size, sha256 = FIXTURES[filename]
    expectation = frozen_expectation(route, direction, control)
    forwardauth = None
    if capture == "traefik-forwardauth":
        forwardauth = {"forwardBody": True, "maxBodySize": 4096, "maxResponseBodySize": 32768,
                       "transport": "default-MRC1"}
    return {
        "id": "I12::" + route + "::NEED-" + direction + "-file",
        "route": route, "direction": direction, "control": control,
        "key": key, "acceptance_key": key, "transaction_id": "tf-" + key,
        "capture_variant": capture, "physical_reader": "client" if direction == "request" else "backend",
        "uri": "/no-crs/request-body" if direction == "request" else "/no-crs/allow",
        "file_spec": {"relative_path": filename, "size": size, "sha256": sha256, "read_size": 24},
        "policy": {"phase4_mode": "safe"}, "rules_lines": list(BASE_RULES),
        "host_forwardauth": forwardauth,
        "expected": expectation, "expected_sha256": digest(expectation),
        "rules_sha256": hashlib.sha256(("\n".join(BASE_RULES) + "\n").encode()).hexdigest(),
        "qualification": "unqualified", "execution_status": "not_run", "native_file_api": False,
    }


def cases():
    """Return fresh literal data; no filesystem reads or observed outcome inputs."""
    result = [case_for(route, direction, label, capture, control)
              for route, direction, label, capture in ROUTES
              for control in controls_for(route)]
    return copy.deepcopy(result)


def build():
    executions = cases()
    return {"schema": SCHEMA, "original_id_count": 4, "execution_count": 9,
            "cases": executions, "cases_sha256": digest(executions),
            "strict": {"scope": "configuration-negative-only", "runtime_claim": False,
                       "expected": "route capability rejection; no target traffic"},
            "qualification_promotions": 0, "native_file_api": False,
            "required_separate_evidence": [
                "parent wait status for actual file reader PID", "file/read/close and raw HTTP receipts",
                "actual sample bytes and independent backend arrival/exclusion",
                "native chunk callbacks/EOS/first cause and once-only Finish/Free",
                "actual commit and client entity bytes", "observer correlation/abort and physical UDS ends",
                "healthy neighbors before/after and descriptor/process/socket cleanup",
            ]}
