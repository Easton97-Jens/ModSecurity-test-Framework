"""Compile unchanged productive HTX caller bodies with controlled host/native seams.

This checks host API calls, never client transport effects. Common policy code
is linked unchanged. Mutation copies live outside the source checkout.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path
from pathlib import Path
import hashlib
import json
import os
import runpy
from modsecurity_connector_tests.c_source_contract import function_definition
import subprocess
import tempfile
import unittest

ROOT = connector_root()
OVERLAY = source_path('connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c', root=ROOT)

MATERIALIZER = runpy.run_path(str(test_root() / "ci/checks/analysis/native-cfamily-recipes.py"))["materialize_host_includes"]


class HAProxyI10HostCallers(unittest.TestCase):
    def compile_and_run(self, source):
        # Extract declarations and complete productive functions without changing
        # their bodies. Unrelated HTX parser/registration APIs are outside this seam.
        fixture = (source_path('tests/haproxy_i10_host_caller_test.c', root=ROOT)).read_text()
        # Optional pinned-host input exercises the unchanged upstream inline
        # API bodies rather than the self-contained controlled fixture copies.
        api_source = os.environ.get("HAPROXY_I10_API_SOURCE")
        if api_source:
            api_root = Path(api_source)
            self.assertEqual((api_root / "VERSION").read_text().strip(), "3.2.25")
            definitions = []
            for header, names in (
                ("connection.h", ("conn_xprt_ready", "conn_get_mux_name", "conn_xprt_shutw", "conn_xprt_shutw_hard")),
                ("stconn.h", ("__sc_conn", "sc_conn")),
            ):
                upstream = (api_root / "include/haproxy" / header).read_text()
                definitions.extend(function_definition(upstream, name) for name in names)
            start = fixture.index("/* HAPROXY_TRANSPORT_API_BEGIN */")
            end = fixture.index("/* HAPROXY_TRANSPORT_API_END */", start)
            fixture = fixture[:start] + "\n".join(definitions) + "\n" + fixture[end:]
        c_source = fixture
        temp_root = Path(os.environ.get("TMPDIR", "/var/tmp/codex/ModSecurity-conector/tmp"))
        temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="haproxy-i10-", dir=temp_root) as directory:
            temp = Path(directory)
            MATERIALIZER(source, temp)
            harness = source_path('tests/haproxy_i10_host_caller_test.c', root=ROOT)
            if api_source:
                harness = temp / "caller.c"
                harness.write_text(c_source)
            binary = temp / "caller"
            sources = ["event_jsonl.c", "transaction_state.c", "transaction_id.c", "log_sanitize.c", "rule_id.c", "late_intervention.c", "decision_action.c", "block_statuses.c",
                       "http_status.c", "error.c", "decision.c", "intervention.c", "event.c", "json_escape.c", "status.c"]
            command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-Wl,--gc-sections",
                       "-I", str(temp), "-I", str(source_path('common/include', root=ROOT)),
                       "-I", str(source_path('common/runtime', root=ROOT)),
                       "-I", str(source_path('connectors/haproxy/src', root=ROOT)),
                       str(harness), *(str(source_path('common/src', root=ROOT) / s) for s in sources),
                       "-o", str(binary)]
            if os.environ.get("HAPROXY_I10_SANITIZERS") == "1":
                command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            compiled = subprocess.run(command, capture_output=True, text=True)
            observed = subprocess.run([str(binary)], capture_output=True, text=True, cwd=temp, timeout=30) if compiled.returncode == 0 else None
            receipt_root = os.environ.get("HAPROXY_I10_CALLER_RECEIPTS")
            if receipt_root:
                receipt = Path(receipt_root)
                receipt.mkdir(parents=True, exist_ok=True)
                key = hashlib.sha256(str(temp).encode()).hexdigest()[:16]
                (receipt / (key + ".c")).write_text(c_source)
                record = dict(argv=command, cwd=str(ROOT), compile_exit=compiled.returncode,
                    compile_stdout=compiled.stdout, compile_stderr=compiled.stderr,
                    fixture_sha256=hashlib.sha256(c_source.encode()).hexdigest(),
                    upstream_api_source=api_source,
                    exit=observed.returncode if observed else None,
                    stdout=observed.stdout if observed else None, stderr=observed.stderr if observed else None,
                    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest() if binary.exists() else None)
                (receipt / (key + ".json")).write_text(json.dumps(record, indent=2) + "\n")
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            return observed

    def test_productive_host_callers_mode_commit_reentry_matrix(self):
        result = self.compile_and_run(OVERLAY.read_text())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_redirect_boundary_negative_controls(self):
        source = OVERLAY.read_text()
        mutations = {
            "wrong-location": ("rule.rdr_str = location;", "location[0]='X'; rule.rdr_str = location;"),
            "redirect-coerced-to-deny": ("rule.code = decision->status;", "rule.code = 403;"),
            "skipped-reply-accepted": ("http_apply_redirect_rule(&rule, s, s->txn) == 1", "http_apply_redirect_rule(&rule, s, s->txn) != 0"),
            "redirect-native-finish-ignored": ("if (haproxy_modsecurity_htx_finish_context(ctx) != 0) { return 0; }", "(void)ctx;"),
            "redirect-result-lifetime-copy-omitted": ("memcpy(host_decision.redirect_url, result.redirect_url, length + 1U);", "host_decision.redirect_url[0]=0;"),
            "redirect-outcome-coerced-to-deny": ("host_action = MSCONNECTOR_DECISION_ACTION_REDIRECT;", "host_action = MSCONNECTOR_DECISION_ACTION_DENY;"),
            "earlier-error-ignored": ("ctx != NULL && !ctx->lifecycle.fail_closed &&", "ctx != NULL &&"),
        }
        for name, (old,new) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(old,source)
                result=self.compile_and_run(source.replace(old,new,1))
                self.assertNotEqual(result.returncode,0,name + " unexpectedly survived")

    def test_strict_transport_negative_controls(self):
        source = OVERLAY.read_text()
        mutations = {
            "hard-shutdown-omitted": ("conn_xprt_shutw_hard(connection);", "(void)connection;"),
            "hard-replaced-with-clean": ("conn_xprt_shutw_hard(connection);", "conn_xprt_shutw(connection);"),
            "hard-after-mux-clean": ("conn_xprt_shutw_hard(connection);", "sc_shutdown(s->scf); conn_xprt_shutw_hard(connection);"),
            "h2-transport-closed": ('mux != NULL && strcmp(mux, "H1") == 0', 'mux != NULL && (strcmp(mux, "H1") == 0 || strcmp(mux, "H2") == 0)'),
            "not-ready-transport-used": ("connection != NULL && conn_xprt_ready(connection) &&", "connection != NULL &&"),
            "null-endpoint-dereferenced": ("s->scf != NULL && s->scf->sedesc != NULL", "s->scf != NULL"),
        }
        for name, (old, new) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(old, source)
                result = self.compile_and_run(source.replace(old, new, 1))
                self.assertNotEqual(result.returncode, 0, name + " unexpectedly survived")

    def test_negative_controls_detect_actual_boundary_regressions(self):
        source = OVERLAY.read_text()
        mutations = {
            "queued-response-not-purged": ("channel_htx_erase(&s->res, htxbuf(&s->res.buf));", "(void)s->res;"),
            "stream-not-aborted": ("stream_abort(s);", "(void)s;"),
            "frontend-not-shutdown": ("sc_shutdown(s->scf);", "(void)s->scf;"),
            "strict-terminal-success": ("haproxy_modsecurity_htx_abort_response_stream(s);\n            unregister_data_filter(s, msg->chn, filter);\n            return -1;", "haproxy_modsecurity_htx_abort_response_stream(s);\n            unregister_data_filter(s, msg->chn, filter);\n            return 1;"),
            "normal-deny-fabricates-cancel": (
                "if (ok == 1) {\n        memset(&result, 0, sizeof(result));",
                "if (0) {\n        memset(&result, 0, sizeof(result));"),
            "invalid-nested-success-ignored": ("|| result.success != 1", "|| result.success == 123"),
            "invalid-result-success-accepted": ("result->success == 1 &&", "result->success != 0 &&"),
            "invalid-release-accepted": ("if (ok != 1) {\n        haproxy_modsecurity_htx_companion_cancel_and_close(ctx, &error);\n        return 0;", "if (ok == 0) {\n        haproxy_modsecurity_htx_companion_cancel_and_close(ctx, &error);\n        return 0;"),
            "invalid-open-accepted": ("if (ok == 1) {\n        ok = msconnector_response_companion_client_claim(", "if (ok != 0) {\n        ok = msconnector_response_companion_client_claim("),
            "invalid-claim-accepted": ("return ok == 1;\n}\n\nstatic int haproxy_modsecurity_htx_companion_commit", "return ok != 0;\n}\n\nstatic int haproxy_modsecurity_htx_companion_commit"),
            "ignored-cleanup-ack": ("return ok == 1 && cleanup_ok == 1;", "return ok == 1 || cleanup_ok == 1;"),
            "duplicate-host-action": ("if (ctx->lifecycle.host_failure_applied)", "if (0)"),
            "terminal-request-success": ("if (ctx->lifecycle.fail_closed) {\n        return -1;", "if (0) {\n        return -1;"),
            "ignored-commit": ("ctx->transaction, 1, 0) != 0", "ctx->transaction, 1, 0) == 123"),
            "invalid-common-eos-success": ("&ctx->companion.client, &result, &error) != 1", "&ctx->companion.client, &result, &error) == 0"),
            "duplicate-response-reply": ("if (ctx->response.headers_committed) {", "if (0) {"),
            "ignored-outcome-ack": ("if (!haproxy_modsecurity_htx_companion_record_precommit_outcome(ctx,", "if (0 && !haproxy_modsecurity_htx_companion_record_precommit_outcome(ctx,"),
            "ignored-terminal-finish": ("if (haproxy_modsecurity_htx_finish_context(ctx) != 0)", "if (haproxy_modsecurity_htx_finish_context(ctx) == 123)"),
            "false-abort-observation": ("if (connection_aborted) {", "if (connection_aborted && 0) {"),
        }
        for name, (old, new) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(old, source)
                result = self.compile_and_run(source.replace(old, new))
                self.assertNotEqual(result.returncode, 0, name + " unexpectedly survived")


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
