#!/usr/bin/env python3
"""Retain real phase1 callbacks for two fixed native event boundary contracts."""
from modsecurity_test_framework.connector_context import load_source
import copy
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent




def load(_name, path):
    module = load_source(path)
    return module


HOST = load("event_boundary_owned_host", HERE / "run-nginx-valid-rules.py")
SOURCE_RESULT = "source-result.json"
EVENT_VARIANTS = {
    "event_metadata_truncation": ("long-query",),
    "event_json_limit": ("at255", "over256"),
}


def configuration(output, port, upstream_port, projection, path, mode, run_id):
    if (mode != "safe" or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id)
            or not re.fullmatch(r"/no-crs/events/(?:at255|over256|long-query)/x+(?:\?probe=non-sensitive)?", path)):
        raise ValueError("closed fixed event-boundary configuration required")
    return (f'load_module "{output}/nginx-module.so";\n'
            'user nobody nogroup;\nworker_processes 1;\ndaemon off;\n'
            f'pid "{output}/nginx.pid";\nerror_log "{output}/nginx-error.log";\n'
            'events {}\nhttp { access_log off; modsecurity on;\n'
            f'modsecurity_transaction_id "{run_id}-$connection-$connection_requests";\n'
            f'modsecurity_rules_file "{output}/rules.conf";\n'
            'modsecurity_phase4_mode safe;\n'
            f'modsecurity_phase4_log "{output}/phase4-events.jsonl";\n'
            f'server {{ listen 127.0.0.1:{port}; root "{projection}";\n'
            f'location /no-crs/events/ {{ proxy_pass http://127.0.0.1:{upstream_port}; '
            'proxy_http_version 1.1; proxy_buffering off; } } }\n')


def native_callbacks(raw, path):
    # The unchanged strict Common/central validator still validates raw fields.
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if any(not isinstance(event, dict) for event in events):
        raise ValueError("native boundary JSONL must contain objects")
    return [event for event in events if event.get("event") == "rule_match"
            and event.get("connector") == "nginx" and event.get("phase") == "request_headers"
            and event.get("integration_mode") == "native-nginx-http-module"
            and event.get("method") == "GET" and event.get("rule_id") == "1100402"]


def variants_for(case_id):
    if not isinstance(case_id, str) or case_id not in EVENT_VARIANTS:
        raise ValueError("unknown closed event boundary identity")
    return EVENT_VARIANTS[case_id]


def run(args):
    _, _, output = HOST.BASE.validate_inputs(args)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", args.run_id):
        raise ValueError("bounded event parent run identity required")
    variants = variants_for(args.case_id)
    framework = HOST.BASE.absolute_path(args.framework_root)
    input_path = framework / "tests/runners/nginx_event_boundary_operations.py"
    contracts = load("event_boundary_closed_inputs", input_path)
    runtime = load("event_boundary_shared_runtime", HERE / "run-nginx-phase4-cases.py")
    output.mkdir(mode=0o700)
    children, succeeded = [], True
    for variant in variants:
        child_args = copy.copy(args)
        child_args.output_root = str(output / variant)
        child_args.run_id = args.run_id + "-" + variant
        spec = contracts.operation(args.case_id, variant)
        completed = runtime.run_operation(child_args, spec, input_path=input_path,
            configuration_factory=configuration, upstream_path=Path(__file__), observation_factory=native_callbacks,
            receipt_metadata={"variant": variant, "request_headers": spec["request_headers"]})
        child_output = Path(child_args.output_root)
        retained = HOST.bounded_capture(child_output / SOURCE_RESULT)
        children.append({"variant": variant, "directory": variant, "run_id": child_args.run_id,
                         "receipt_sha256": HOST.BASE.digest(retained)})
        succeeded = succeeded and completed
    row = {"schema_version": 1, "case_id": args.case_id, "run_id": args.run_id,
           "operation": "native_event_boundary_request", "parent_sha": args.parent_sha,
           "framework_sha": args.framework_sha, "mrts_sha": args.mrts_sha, "children": children,
           "uri_buffer_bytes": contracts.URI_BUFFER_BYTES, "writer_buffer_bytes": contracts.WRITER_BUFFER_BYTES,
           "driver_sha256": HOST.BASE.digest(Path(__file__).read_bytes()),
           "closed_inputs_sha256": HOST.BASE.digest(input_path.read_bytes()),
           "closed_input_dependencies_sha256": {name: HOST.BASE.digest((input_path.parent / name).read_bytes())
               for name in ("nginx_common_input_faults.py", "nginx_mime_operations.py")},
           "canonical_status": "NOT_EXECUTED", "contract_validation_pending": True}
    HOST.write_json(output / SOURCE_RESULT, row)
    return succeeded


def main():
    parser = HOST.BASE.argument_parser()
    parser.description = __doc__
    for action in parser._actions:
        if action.dest == "case_id":
            action.choices = ("event_metadata_truncation", "event_json_limit")
    parser.add_argument("--projection-parent", required=True)
    parser.add_argument("--framework-root", required=True)
    try:
        return 0 if run(parser.parse_args()) else 1
    except (OSError, ValueError, AttributeError) as exc:
        print("event boundary native input failure: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
