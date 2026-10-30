#!/usr/bin/env python3
"""Prepare separate native-HTX private-host inputs from the immutable I12 capture.

Preparation never starts a host or qualifies an oracle. Each generated fixture
needs its own sealed controller spec and independent lifecycle review.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths

LAUNCH_FILE = 'launch.py'
CLIENT_FILE = 'client.py'
BACKEND_FILE = 'backend.py'
OPENSSL_CONFIG = 'openssl.cnf'
CSV_MIME = 'text/csv'
PLAIN_MIME = 'text/plain'
CAPTURE_HASHES = {
    LAUNCH_FILE: "033e35075bba6f5138217059b8e92a7c1ac495af261365897fa81523bef577eb",
    CLIENT_FILE: "d06126fb153f9675f538f48151bcbd7e8f767e4f639baa70c1f5d37f42410e63",
    BACKEND_FILE: "1644799f27594796741fc611589abed79eca35d13166938a7012a0779abad85c",
    OPENSSL_CONFIG: "31092455fc7e54d448735380895b9bee2097458bcf2ff10233766f66ee18494f",
}
BASE_REQUEST = b"haproxy-lifecycle-main\n"
BASE_RESPONSE = b"haproxy-lifecycle-response\n"
COMMON_EVENTS_PATH = "/task/common-events.jsonl"
NATIVE_FILTER_DIRECTIVE = "filter modsecurity-htx rules-file /task/rules.conf phase4-mode safe"
MAIN_PATH = "/i12-main"
DIAGNOSTIC_CASES = frozenset(("p1-deny", "p2-deny", "p3-deny", "p4-safe"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("capture boundary changed: " + repr(before))
    return text.replace(before, after)


def cases():
    result = {
        "request-empty": {"request": b""},
        "request-file": {"request_file": True},
        "request-streaming": {"request_streaming": True},
        "request-content-type-missing": {"request_type": None},
        "request-charset-present": {"request_type": "text/plain; charset=utf-8"},
        "request-charset-missing": {},
        "request-csv": {"request_type": CSV_MIME, "request": b"id,value\n1,marker\n"},
        "request-marker-at-payload-end": {"request": b"a" * 70000 + b"I12_END"},
        "response-empty": {"response": b""},
        "response-single-chunk": {},
        "response-file": {"response_file": True},
        "response-streaming": {"response_streaming": True},
        "response-content-type-present": {},
        "response-content-type-missing": {"response_type": None},
        "response-charset-present": {"response_type": "text/plain; charset=utf-8"},
        "response-charset-missing": {},
        "response-mime-scope-in": {},
        "response-mime-scope-out": {"response_type": "application/octet-stream", "response_inspected": False},
        "response-csv": {"response_type": CSV_MIME, "response": b"id,value\n1,marker\n", "mime": CSV_MIME},
        "response-marker-at-payload-end": {"response": b"a" * 70000 + b"I12_END"},
        "request-reject": {"request_limit": 16, "request_action": "Reject", "expected_status": 403},
        "request-process-partial": {"request_limit": 16, "request_action": "ProcessPartial", "request_inspected": BASE_REQUEST[:16]},
        "response-reject": {"response_limit": 16, "response_action": "Reject", "expected_status": 200, "response_inspected": False},
        "response-process-partial": {"response_limit": 16, "response_action": "ProcessPartial", "response_inspected": BASE_RESPONSE[:16]},
        "p1-deny": {"deny_phase": 1, "expected_status": 403},
        "p2-deny": {"deny_phase": 2, "expected_status": 403},
        "p3-deny": {"deny_phase": 3, "expected_status": 403},
        "p3-redirect": {"redirect_phase": 3, "expected_status": 302,
                        "expected_location": "https://haproxy-i12.invalid/redirect-target",
                        "response_inspected": False, "native_requested_status": 302},
        "p4-safe": {"deny_phase": 4},
    }
    for value in result.values():
        value.setdefault("request", BASE_REQUEST)
        value.setdefault("response", BASE_RESPONSE)
    return result


def body_probe(variable, body, rule, phase):
    # Independent native transformation proves inspected bytes, including prefix
    # limits, rather than mistaking connector append counters for SDK contents.
    # SHA1 matches libModSecurity 3.0.14 t:sha1 for a non-security byte predicate.
    # Artifact identities and all trust/provenance bindings use SHA256.
    hashed = hashlib.sha1(body, usedforsecurity=False).hexdigest()
    return (f'SecRule {variable} "@streq {hashed}" '
            f'"id:{rule},phase:{phase},pass,log,t:sha1,t:hexEncode,msg:\'I12_NATIVE_EXACT_BYTES_{rule}\'"\n')


def prepare_launch(launch, name, case, request, response):
    launch = replace_once(launch, NATIVE_FILTER_DIRECTIVE,
                          NATIVE_FILTER_DIRECTIVE + " events-file " + COMMON_EVENTS_PATH)
    launch = replace_once(launch, "SecRequestBodyLimit 1024", "SecRequestBodyLimit " + str(case.get("request_limit", 1048576)))
    launch = replace_once(launch, "SecRequestBodyNoFilesLimit 1024", "SecRequestBodyNoFilesLimit 1048576")
    launch = replace_once(launch, "SecResponseBodyLimit 1024", "SecResponseBodyLimit " + str(case.get("response_limit", 1048576)))
    launch = replace_once(launch, "SecRequestBodyLimitAction Reject", "SecRequestBodyLimitAction " + case.get("request_action", "Reject"))
    launch = replace_once(launch, "SecResponseBodyLimitAction Reject", "SecResponseBodyLimitAction " + case.get("response_action", "Reject"))
    launch = replace_once(launch, "SecResponseBodyMimeType text/plain", "SecResponseBodyMimeType " + case.get("mime", PLAIN_MIME))
    extra = body_probe("REQUEST_BODY", case.get("request_inspected", request), 1999471, 2)
    inspected_response = case.get("response_inspected", response)
    if inspected_response is not False:
        extra += body_probe("RESPONSE_BODY", inspected_response, 1999472, 4)
    if case.get("deny_phase"):
        phase = case["deny_phase"]
        variable = "REQUEST_URI" if phase < 3 else "RESPONSE_HEADERS:X-I12-Main"
        pattern = MAIN_PATH if phase < 3 else "main"
        extra += f'SecRule {variable} "@contains {pattern}" "id:1999473,phase:{phase},deny,status:403,log,msg:\'I12_NATIVE_P{phase}_DENY\'"\n'
    if case.get("redirect_phase"):
        extra += 'SecRule RESPONSE_HEADERS:X-I12-Main "@streq main" "id:1999474,phase:3,redirect:https://haproxy-i12.invalid/redirect-target,status:302,log,msg:\'I12_NATIVE_P3_REDIRECT\'"\n'
    extra += case.get("rules_extra", "")
    launch = replace_once(launch, "SecAction \"id:1999404,phase:4,pass,log,msg:'I12_HAP_P4'\"\n", "SecAction \"id:1999404,phase:4,pass,log,msg:'I12_HAP_P4'\"\n" + extra)
    diagnostic = name in DIAGNOSTIC_CASES
    selected_id = ("DIAG::haproxy-native-htx::" + name if diagnostic else "I12::haproxy-native-htx::NEED-" + name)
    selected_id = case.get("original_id", selected_id)
    launch = replace_once(launch, "MSCONNECTOR_LIFECYCLE_CASE='NEED-request-eos-once'",
                          "MSCONNECTOR_LIFECYCLE_CASE=" + repr(selected_id))
    launch = replace_once(launch, "'selected_id':'I12::haproxy-native-htx::NEED-request-eos-once'",
                          "'selected_id':" + repr(selected_id))
    launch = replace_once(launch, "20261014-haproxy-htx-01", "20261015-htx-" + name)
    # A failed main client is retained and the healthy neighbor still runs.
    # A driver zero exit is explicitly not a full lifecycle qualification.
    launch = replace_once(launch, "if result.returncode:raise RuntimeError(label+' failed')", "if result.returncode and label!='main-client':raise RuntimeError(label+' failed')")
    return launch, diagnostic, selected_id, inspected_response


def prepare_client(client, case, request):
    body_expr = "Path('/mnt/fixtures/request-body.bin').read_bytes()" if case.get("request_file") else repr(request)
    client = replace_once(client, "body=('haproxy-lifecycle-'+name+'\\n').encode()", "body=" + body_expr + " if name=='main' else b'neighbor'")
    request_type = case.get("request_type", PLAIN_MIME)
    client = replace_once(client, "Content-Type: text/plain\\r\\n", "" if request_type is None else "Content-Type: " + request_type + "\\r\\n")
    if "request_wire" in case:
        boundary = "context=ssl.create_default_context(cafile='/task/tls.crt')"
        client = replace_once(client, boundary, "request=" + repr(case["request_wire"]) + " if name=='main' else request\n" + boundary)
    if case.get("request_streaming"):
        pieces = chunk_expressions("body", case.get("request_chunk_sizes", [8, len(request) - 8]))
        client = replace_once(client, "connection.sendall(request);", "\n    pieces=[request[:-len(body)]," + ",".join(pieces) + "]\n    for piece in pieces:\n        connection.sendall(piece);time.sleep(.1)\n    ")
    expected = case.get("expected_status", 200)
    client = replace_once(client, "if row['status']!=200", f"if row['status']!=({expected} if name=='main' else 200)")
    if "expected_location" in case:
        # Compare actual parsed header multiplicity, independently of status.
        check = ("def redirect_location_matches(row, name):\n"
                 "    locations=[value.strip(' \\t') for key,value in row['headers'] if key.lower()=='location']\n"
                 "    return locations==([" + repr(case["expected_location"]) + "] if name=='main' else [])\n")
        client = check + client
        client = replace_once(client, "or not row['body_complete']:",
                              "or not row['body_complete'] or not redirect_location_matches(row,name):")
    return client_first_byte_barrier(client, case)


def prepare_backend(backend, case, response):
    response_expr = "Path('/mnt/fixtures/response-body.bin').read_bytes()" if case.get("response_file") else repr(response)
    backend = replace_once(backend, "response=b'haproxy-lifecycle-response\\n'", "response=" + response_expr + " if self.path=='/i12-main' else b'healthy\\n'")
    backend = replace_once(backend, "self.send_response(200);", "self.send_response(200);self.send_header('X-I12-Main','main' if self.path=='/i12-main' else 'neighbor');")
    if "request_path" in case:
        backend = backend.replace(MAIN_PATH, case["request_path"])
    for header in case.get("response_headers", []):
        statement = "\n        if self.path==" + repr(case.get("request_path", MAIN_PATH)) + ":\n            self.send_header(" + repr(header["name"]) + "," + repr(header["value"]) + ");\n        "
        backend = replace_once(backend, "self.end_headers();", statement + "self.end_headers();")
    if case.get("request_method") == "GET":
        backend = replace_once(backend, "    def log_message(self,*args):pass", "    do_GET = do_POST\n    def log_message(self,*args):pass")
    content_type = case.get("response_type", PLAIN_MIME)
    backend = replace_once(backend, "self.send_header('Content-Type','text/plain');", "" if content_type is None else "self.send_header('Content-Type'," + repr(content_type) + ");")
    if case.get("response_streaming"):
        pieces = chunk_expressions("response", case.get("response_chunk_sizes", [8, 8, len(response) - 16]))
        backend = replace_once(backend, "self.wfile.write(response);self.wfile.flush();", "\n        for chunk in [" + ",".join(pieces) + "]:\n            self.wfile.write(chunk);self.wfile.flush();time.sleep(.1)\n        ")
    return backend_first_byte_barrier(backend, case)


def client_first_byte_barrier(client, case):
    if not case.get("first_byte_barrier"):
        return client
    size = case["first_chunk_size"]
    inserted = """data+=chunk
        if name=='main' and b'\\r\\n\\r\\n' in data:
            prefix=data.split(b'\\r\\n\\r\\n',1)[1]
            barrier=Path('/task/client-first-body.json')
            if len(prefix)>=FIRST_CHUNK_SIZE and not barrier.exists():
                observed={'wall_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns(),'actual_body_bytes':len(prefix),'actual_body_sha256':hashlib.sha256(prefix).hexdigest(),'source':'actual_SSLSocket_recv_body_before_backend_release'}
                with barrier.open('x') as marker:marker.write(json.dumps(observed)+'\\n')
""".replace("FIRST_CHUNK_SIZE", str(size))
    return replace_once(client, "data+=chunk", inserted.rstrip())


def backend_first_byte_barrier(backend, case):
    if not case.get("first_byte_barrier"):
        return backend
    path = repr(case["request_path"])
    size = case["first_chunk_size"]
    inserted = """
        if self.path==MAIN_PATH:
            prefix=response[:FIRST_CHUNK_SIZE]
            before=time.time_ns();written=self.wfile.write(prefix);self.wfile.flush()
            paused={'kind':'upstream_first_chunk_and_pause','path':self.path,'before_wall_ns':before,'after_wall_ns':time.time_ns(),'actual_write_result':written,'first_chunk_size':len(prefix),'first_chunk_sha256':hashlib.sha256(prefix).hexdigest(),'remaining_bytes_not_sent':len(response)-len(prefix)}
            with Path('/task/backend.jsonl').open('a') as out:out.write(json.dumps(paused)+'\\n')
            barrier=Path('/task/client-first-body.json');deadline=time.monotonic()+8
            while not barrier.exists():
                if time.monotonic()>deadline:raise TimeoutError('client did not receive first body chunk before backend release')
                time.sleep(.01)
            observed=json.loads(barrier.read_text())
            if observed['actual_body_bytes']!=len(prefix) or observed['actual_body_sha256']!=hashlib.sha256(prefix).hexdigest():raise RuntimeError('physical client prefix differs before release')
            released={'kind':'upstream_barrier_release','path':self.path,'wall_ns':time.time_ns(),'client_observation':observed,'remaining_bytes_before_release':len(response)-len(prefix)}
            with Path('/task/backend.jsonl').open('a') as out:out.write(json.dumps(released)+'\\n')
            written=self.wfile.write(response[len(prefix):]);self.wfile.flush()
            with Path('/task/backend.jsonl').open('a') as out:out.write(json.dumps({'kind':'upstream_remaining_write_return','path':self.path,'wall_ns':time.time_ns(),'actual_write_result':written})+'\\n')
        else:
            self.wfile.write(response);self.wfile.flush();
        """.replace("MAIN_PATH", path).replace("FIRST_CHUNK_SIZE", str(size))
    return replace_once(backend, "self.wfile.write(response);self.wfile.flush();", inserted)


def chunk_expressions(variable, sizes):
    offset = 0
    expressions = []
    for index, size in enumerate(sizes):
        if size < 0:
            raise ValueError("negative chunk size")
        end = offset + size
        start_text = str(offset) if offset else ""
        end_text = "" if index == len(sizes) - 1 else str(end)
        expressions.append(variable + "[" + start_text + ":" + end_text + "]")
        offset = end
    return expressions


def case_contract(case, request, response, diagnostic, selected_id, inspected_response):
    contract = {"schema": "i12-haproxy-native-case-v1", "original_id": None if diagnostic else selected_id,
                "diagnostic_id": selected_id if diagnostic else None,
                "original_obligation_eligible": not diagnostic,
                "capture_variant": "haproxy-direct", "capture_input_hashes": CAPTURE_HASHES,
                "request_bytes": len(request), "request_sha256": digest(request),
                "response_bytes": len(response), "response_sha256": digest(response),
                "expected_native_request_sha1": hashlib.sha1(case.get("request_inspected", request), usedforsecurity=False).hexdigest(),
                "expected_native_response_sha1": None if inspected_response is False else hashlib.sha1(inspected_response, usedforsecurity=False).hexdigest(),
                "native_response_probe_applicable": inspected_response is not False,
                "neighbor_request_bytes": 8, "neighbor_response_bytes": 8,
                "settings": {key: value for key, value in case.items() if not isinstance(value, bytes)},
                "native_probe_rules": [1999471] + ([1999472] if inspected_response is not False else []),
                "full_lifecycle_pass": None, "private_host_execution_required": True,
                "native_EOS_not_derived_from_HTTP": True}
    if "original_id" in case:
        contract["original_requirement_binding"] = case["original_requirement_binding"]
        contract["request_method"] = case.get("request_method", "POST")
        contract["request_path"] = case.get("request_path", MAIN_PATH)
    return contract


def materialize(capture, output, name, case):
    original = {}
    for filename, expected in CAPTURE_HASHES.items():
        data = (capture / filename).read_bytes()
        if digest(data) != expected:
            raise ValueError("immutable capture hash differs: " + filename)
        original[filename] = data.decode()
    output.mkdir(parents=True)
    request = case["request"]
    response = case["response"]
    launch, diagnostic, selected_id, inspected_response = prepare_launch(original[LAUNCH_FILE], name, case, request, response)
    client = prepare_client(original[CLIENT_FILE], case, request)
    backend = prepare_backend(original[BACKEND_FILE], case, response)
    for filename, text in {LAUNCH_FILE: launch, CLIENT_FILE: client, BACKEND_FILE: backend}.items():
        compile(text, filename, "exec")
        (output / filename).write_text(text)
    (output / OPENSSL_CONFIG).write_text(original[OPENSSL_CONFIG])
    (output / "request-body.bin").write_bytes(request)
    (output / "response-body.bin").write_bytes(response)
    contract = case_contract(case, request, response, diagnostic, selected_id, inspected_response)
    (output / "case-contract.json").write_text(json.dumps(contract, indent=2) + "\n")
    files = {p.name: digest(p.read_bytes()) for p in output.iterdir()}
    for path in output.iterdir():
        path.chmod(0o444)
    output.chmod(0o555)
    ledger = output.with_name(output.name + "-ledger.json")
    ledger.write_text(json.dumps({"files": files, "symlinks": {}}, indent=2, sort_keys=True) + "\n")
    ledger.chmod(0o444)
    return {"name": name, "source": str(output), "ledger": str(ledger), "ledger_sha256": digest(ledger.read_bytes())}


def fresh_output(path):
    authorized = Path("/var") / "tmp" / "codex" / "ModSecurity-conector"
    storage = authorized.stat()
    if storage.st_uid not in (0, os.geteuid()) or storage.st_mode & 0o022:
        raise ValueError("external storage must have a trusted owner and private writes")
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute external output required")
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("output symlinks are forbidden")
    path.resolve().relative_to(authorized)
    path = i12_paths.new_directory(path)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output = fresh_output(args.output)
    records = [materialize(args.capture, args.output / name, name, case) for name, case in cases().items()]
    (args.output / "fixture-index.json").write_text(json.dumps(records, indent=2) + "\n")
    print(json.dumps({"prepared": len(records), "hosts_started": 0}))


if __name__ == "__main__":
    main()
