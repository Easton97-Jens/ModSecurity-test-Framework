#!/usr/bin/env python3
"""Run four closed MIME requests using the shared owned native host runtime."""
from modsecurity_test_framework.connector_context import load_source
import importlib.util
import json
from pathlib import Path
import re
import sys
import threading
from http.server import HTTPServer

HERE = Path(__file__).resolve().parent




def load(_name, path):
    module = load_source(path)
    return module


HOST = load("mime_owned_host", HERE / "run-nginx-valid-rules.py")
BACKEND_PATH = HERE.parent / "common/response-header-test-backend.py"
BACKEND = load("mime_existing_backend", BACKEND_PATH)
RESPONSE_HEADER_FIXTURE = "response-header-fixture.json"


def configuration(output, port, upstream_port, projection, path, mode, run_id):
    if mode != "safe" or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id):
        raise ValueError("closed MIME configuration requires safe mode and bounded run identity")
    cases = {"phase4_in_scope_content_type": "text/plain",
             "phase4_content_type_with_charset": "text/plain; charset=utf-8",
             "phase4_out_of_scope_content_type": "image/png", "phase4_missing_content_type": ""}
    case = path.removeprefix("/no-crs/content-type/")
    if case not in cases or path != "/no-crs/content-type/" + case:
        raise ValueError("closed MIME request path required")
    return (f'load_module "{output}/nginx-module.so";\n'
            'user nobody nogroup;\nworker_processes 1;\ndaemon off;\n'
            f'pid "{output}/nginx.pid";\nerror_log "{output}/nginx-error.log";\n'
            'events {}\nhttp { access_log off; modsecurity on;\n'
            f'modsecurity_transaction_id "{run_id}-$connection-$connection_requests";\n'
            f'modsecurity_rules_file "{output}/rules.conf";\n'
            'modsecurity_phase4_mode safe;\n'
            f'modsecurity_phase4_log "{output}/phase4-events.jsonl";\n'
            f'types {{ }}\ndefault_type "{cases[case]}";\n'
            f'server {{ listen 127.0.0.1:{port}; root "{projection}";\n'
            f'location = {path} {{ proxy_pass http://127.0.0.1:{upstream_port}; '
            'proxy_http_version 1.1; proxy_buffering off; } } }\n')


class MimeUpstream:
    """Bounded one-request adapter for the existing declarative header backend."""
    def __init__(self, chunks, *, pause, spec, output):
        if pause is not False or tuple(chunks) != (b"no-crs-response-body-marker",):
            raise ValueError("MIME backend accepts exactly the closed single-body trigger")
        self.spec, self.output = spec, output
        self.release, self.paused = threading.Event(), threading.Event()
        self.finished, self.eos_sent = threading.Event(), threading.Event()
        self.sizes, self.error = [], "none"

    def __enter__(self):
        fixture_path = self.output / RESPONSE_HEADER_FIXTURE
        fixture_path.write_text(json.dumps(self.spec["backend_fixture"], sort_keys=True) + "\n")
        fixture = BACKEND.load_fixture_file(fixture_path, [self.output])
        owner = self

        class ScopedHandler(BACKEND.Handler):
            body_bytes = b"no-crs-response-body-marker"

            def setup(self):
                super().setup()
                self.connection.settimeout(5)

            def do_GET(self):
                if self.path != owner.spec["request_path"]:
                    owner.error = "unexpected_request_path"
                    self.send_error(404)
                    return
                try:
                    self._send_fixture(include_body=True)
                    owner.sizes.append(len(self.body_bytes))
                    owner.eos_sent.set()
                except OSError:
                    owner.error = "response_write_failed"

            def do_HEAD(self):
                owner.error = "unexpected_request_method"
                self.send_error(405)

            do_POST = do_HEAD

        ScopedHandler.fixture = fixture
        self.server = HTTPServer(("127.0.0.1", 0), ScopedHandler)
        self.server.timeout = 5
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.serve, daemon=False)
        self.thread.start()
        return self

    def serve(self):
        try:
            self.server.handle_request()
            if not self.eos_sent.is_set() and self.error == "none":
                self.error = "request_not_completed"
        finally:
            self.finished.set()

    def observations(self):
        if not self.finished.is_set():
            raise ValueError("MIME upstream observation requires actual completed operation")
        return {"chunk_sizes_sent": list(self.sizes), "eos_sent": self.eos_sent.is_set(),
                "error_class": self.error, "body_payload_persisted": False}

    def __exit__(self, *args):
        self.thread.join(timeout=6)
        self.server.server_close()
        if self.thread.is_alive():
            raise RuntimeError("MIME backend thread did not retire")


def run(args):
    framework = HOST.BASE.absolute_path(args.framework_root)
    input_path = framework / "tests/runners/nginx_mime_operations.py"
    contracts = load("mime_closed_inputs", input_path)
    operation = contracts.operation(args.case_id)
    runtime_path = HERE / "run-nginx-phase4-cases.py"
    if not runtime_path.is_file():
        raise ValueError("shared owned Phase-4 runtime must be integrated before MIME invocation")
    runtime = load("mime_shared_phase4_runtime", runtime_path)
    outcome = runtime.run_operation(args, operation, input_path=input_path,
        upstream_factory=MimeUpstream, upstream_kwargs={"spec": operation, "output": Path(args.output_root)},
        configuration_factory=configuration, upstream_path=Path(__file__),
        extra_capture_leaves=(RESPONSE_HEADER_FIXTURE,),
        receipt_metadata={"backend_contract_sha256": HOST.BASE.digest(BACKEND_PATH.read_bytes()),
            "backend_omission_contract_sha256": HOST.BASE.digest(
                (HERE.parent / "common/response_fixture_omission.py").read_bytes())})
    return outcome


def main():
    parser = HOST.BASE.argument_parser()
    parser.description = __doc__
    for action in parser._actions:
        if action.dest == "case_id":
            action.choices = ("phase4_in_scope_content_type", "phase4_content_type_with_charset",
                              "phase4_out_of_scope_content_type", "phase4_missing_content_type")
    parser.add_argument("--projection-parent", required=True)
    parser.add_argument("--framework-root", required=True)
    try:
        return 0 if run(parser.parse_args()) else 1
    except (OSError, ValueError, AttributeError) as exc:
        print("MIME native input failure: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
