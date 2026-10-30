"""Contracts for the separately built native NGINX response-buffer fixture.

These checks protect fixture wiring only. The native runner is the behavioral
proof because it builds a dedicated test binary and traverses the real NGINX
filter chain.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import ast
import importlib.util
import unittest
import tempfile
from pathlib import Path


ROOT = connector_root()
FIXTURE = source_path('tests/nginx_body_buffer_fixture', root=ROOT)
MODULE = FIXTURE / "ngx_http_body_buffer_fixture_module.c"
RUNNER = source_path('tests/run_nginx_body_buffer_fixture.py', root=ROOT)


def load_runner():
    module = load_source(RUNNER)
    return module


RUNNER_MODULE = load_runner()


class NginxBodyBufferFixtureContractTest(unittest.TestCase):
    @staticmethod
    def _positive_events() -> list[dict[str, object]]:
        return [
            {
                "uri": "/" + mode,
                "event": "phase4_intervention",
                "phase": "response_body",
                "rule_id": "1250001",
                "body_bytes_seen": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + extra,
                "body_bytes_inspected": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + extra,
                "body_truncated": False,
                "truncated": False,
                "eos_seen": True,
            }
            for kind in ("memory", "file", "mixed")
            for mode, extra in ((kind + "-within", 0), (kind + "-over-limit", 1))
        ]

    @classmethod
    def _telemetry_events(cls) -> list[dict[str, object]]:
        return [
            dict(
                row,
                event=event,
                phase=phase,
                rule_id="",
                body_bytes_seen=(
                    row["body_bytes_seen"] if event != "transaction_cleanup" else 0
                ),
                body_bytes_inspected=(
                    row["body_bytes_inspected"] if event != "transaction_cleanup" else 0
                ),
                eos_seen=event == "phase4_completion",
            )
            for row in cls._positive_events()
            for event, phase in (
                ("phase4_append", "response_body"),
                ("phase4_completion", "response_body"),
                ("transaction_cleanup", "logging"),
            )
        ]

    def test_output_root_rejects_shared_ancestor_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            shared = Path(temporary) / "shared"
            shared.mkdir(mode=0o777)
            shared.chmod(0o777)
            destination = shared / "new-fixture"
            with self.assertRaises(RUNNER_MODULE.FixtureFailure):
                RUNNER_MODULE.require_absolute_directory(destination, "output root", create=True)
            self.assertFalse(destination.exists())
            self.assertEqual(shared.stat().st_mode & 0o777, 0o777)

    def test_output_root_creates_private_leaf_and_preserves_existing_safe_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "new-fixture"
            self.assertEqual(
                RUNNER_MODULE.require_absolute_directory(destination, "output root", create=True),
                destination,
            )
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            destination.chmod(0o750)
            RUNNER_MODULE.require_absolute_directory(destination, "output root", create=True)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o750)

    def test_fixture_configuration_keeps_the_test_module_separate(self) -> None:
        config = (FIXTURE / "config").read_text(encoding="utf-8")
        self.assertIn("ngx_http_body_buffer_fixture_module", config)
        self.assertIn("ngx_http_body_buffer_fixture_module.c", config)
        self.assertIn("ngx_module_type=HTTP_FILTER", config)
        self.assertIn("HTTP_FILTER_MODULES", config)
        self.assertIn("ngx_http_modsecurity_module", config)
        self.assertIn('"$ngx_module_link" = ADDON', config)
        self.assertNotIn("connectors/nginx/src", config)

    def test_native_module_emits_each_required_real_buffer_state(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        for mode in (
            "memory-within",
            "memory-over-limit",
            "file-within",
            "file-over-limit",
            "mixed-within",
            "mixed-over-limit",
            "invalid-metadata",
            "missing-source",
            "read-error",
            "short-read",
            "allocation-failure",
        ):
            self.assertIn(f'"{mode}"', source)
        self.assertIn("buffer->memory = 1", source)
        self.assertIn("buffer->in_file = 1", source)
        self.assertIn("buffer->last_buf = 1", source)
        self.assertIn("buffer->last_in_chain = 1", source)
        self.assertIn("ngx_http_output_filter(r, &output)", source)
        self.assertIn("ngx_http_body_buffer_fixture_body_filter", source)
        self.assertIn("ngx_http_body_buffer_fixture_next_body_filter", source)
        self.assertIn("ngx_http_body_buffer_fixture_init", source)
        self.assertIn("connector-boundary mode=%V", source)
        self.assertIn('representation = "file-only"', source)
        self.assertIn("invalid-metadata", source)
        self.assertIn("missing-source", source)
        self.assertIn("short_file", source)
        self.assertIn("body-buffer-fixture mode=%V", source)
        self.assertIn("body_buffer_fixture_short_file", source)
        self.assertIn("body_buffer_fixture_mixed_file", source)
        self.assertIn("file_length = (off_t) FIXTURE_BODY_LENGTH", source)

    def test_runner_rebuilds_exact_head_modules_and_checks_forwarding(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        ast.parse(source, filename=str(RUNNER))
        self.assertEqual(RUNNER_MODULE.EXPECTED_NGINX_ROOT, "nginx-1.31.6")
        self.assertIn("assert_exact_checkout", source)
        self.assertIn("fixture requires a clean exact checkout", source)
        self.assertIn("pwd.getpwuid(os.geteuid())", source)
        self.assertIn('f"user {nginx_user} {nginx_group};"', source)
        self.assertIn("--add-module=", source)
        self.assertNotIn("--add-dynamic-module=", source)
        self.assertIn("--with-ld-opt=-Wl,--wrap=ngx_pnalloc", source)
        self.assertIn("connectors' / 'nginx", source)
        self.assertIn("nginx_body_buffer_fixture", source)
        self.assertNotIn("ngx_http_modsecurity_module.so", source)
        self.assertIn('if body != b""', source)
        self.assertIn("require_healthy_worker", source)
        self.assertIn("connector_boundary_representation", source)
        self.assertIn("FIXTURE_MIXED_FORWARDED_PAYLOAD", source)
        self.assertIn("forwarding_representation", source)
        self.assertIn('"  sendfile on;"', source)
        self.assertIn("short_body_file", source)
        self.assertIn("mixed_body_file", source)
        self.assertIn("positive_phase4_event_accounting", source)
        self.assertIn('row.get("rule_id") != "1250001"', source)
        self.assertIn('row.get("body_bytes_seen")', source)
        self.assertIn('row.get("eos_seen") is not True', source)
        self.assertIn("phase4_event_log_sha256", source)
        self.assertIn("require_static_fixture_filter_order", source)
        self.assertIn("connector_then_fixture_then_postpone", source)
        self.assertIn("not_representable_on_this_64_bit_off_t_size_t_runtime", source)

    def test_allocation_fault_is_static_fixture_only(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("ngx_http_body_buffer_fixture_fail_allocation", source)
        self.assertIn("ngx_http_body_buffer_fixture_allocation_wrapper_hits", source)
        self.assertIn("volatile sig_atomic_t", source)
        self.assertIn("size == 32768U", source)
        self.assertIn("__wrap_ngx_pnalloc", source)
        self.assertIn("__real_ngx_pnalloc", source)
        self.assertNotIn("setenv(", source)
        self.assertNotIn("getenv(", source)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertNotIn("LD_PRELOAD", runner)
        self.assertIn(
            "test_only_static_ngx_pnalloc_wrap_32768_byte_scratch",
            runner,
        )
        self.assertIn("allocation-wrapper-hits=1", runner)
        product = (source_path('connectors/nginx/src/ngx_http_modsecurity_body_filter.c', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("MSCONNECTOR_NGINX_BODY_FIXTURE_FAIL_ALLOC", product)

    def test_positive_event_accounting_is_retained_with_the_rule_binding(self) -> None:
        paths = {
            "/memory-within": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES,
            "/memory-over-limit": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + 1,
            "/file-within": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES,
            "/file-over-limit": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + 1,
            "/mixed-within": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES,
            "/mixed-over-limit": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + 1,
        }
        events = self._positive_events()
        retained = RUNNER_MODULE.validate_positive_events(events)
        self.assertEqual(set(retained), set(paths))
        self.assertEqual(retained["/mixed-over-limit"]["rule_id"], "1250001")
        self.assertEqual(
            retained["/file-over-limit"]["body_bytes_seen"],
            RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + 1,
        )

    def test_positive_event_accounting_rejects_a_mixed_file_backing_match_gap(self) -> None:
        events = [
            row for row in self._positive_events()
            if str(row["uri"]).endswith("-within")
        ]
        next(row for row in events if row["uri"] == "/mixed-within")["rule_id"] = ""
        with self.assertRaises(RUNNER_MODULE.FixtureFailure):
            RUNNER_MODULE.validate_positive_events(events)

    def test_positive_events_coexist_with_retained_same_uri_telemetry(self) -> None:
        events = self._positive_events() + self._telemetry_events()
        original = [dict(row) for row in events]
        accounting = RUNNER_MODULE.validate_positive_events(events)
        self.assertEqual(len(accounting), 6)
        self.assertEqual(events, original)

    def test_telemetry_alone_cannot_prove_positive_accounting(self) -> None:
        events = self._telemetry_events()
        with self.assertRaises(RUNNER_MODULE.FixtureFailure):
            RUNNER_MODULE.validate_positive_events(events)

    def test_positive_identity_and_accounting_mismatches_fail(self) -> None:
        for field, value in (
            ("phase", "logging"),
            ("rule_id", "other"),
            ("body_bytes_seen", 0),
            ("body_bytes_seen", True),
            ("body_bytes_inspected", 0),
            ("body_bytes_inspected", True),
            ("eos_seen", False),
            ("eos_seen", 1),
            ("body_truncated", True),
            ("body_truncated", 1),
            ("truncated", True),
            ("truncated", 1),
            ("event", "phase4_append"),
        ):
            with self.subTest(field=field):
                events = self._positive_events()
                events[0][field] = value
                with self.assertRaises(RUNNER_MODULE.FixtureFailure):
                    RUNNER_MODULE.validate_positive_events(events)

    def test_duplicate_or_mismatched_positive_event_fails(self) -> None:
        for mismatch in (False, True):
            with self.subTest(mismatch=mismatch):
                events = self._positive_events()
                duplicate = dict(events[0])
                if mismatch:
                    duplicate["rule_id"] = "other"
                events.append(duplicate)
                with self.assertRaises(RUNNER_MODULE.FixtureFailure):
                    RUNNER_MODULE.validate_positive_events(events)

    def test_configtest_failure_summary_is_bounded_and_classified(self) -> None:
        output = (
            "nginx: [emerg] bind() to 127.0.0.1:45823 failed "
            "(98: Address already in use)\nprivate-fixture-content\n"
        )
        summary = RUNNER_MODULE.configtest_failure_summary(output)
        self.assertRegex(
            summary,
            r"^configtest_output_sha256=[0-9a-f]{64} "
            r"configtest_failure_class=listener_address_in_use$",
        )
        self.assertNotIn("private-fixture-content", summary)

    def test_configtest_failure_classification_handles_known_setup_errors(self) -> None:
        self.assertEqual(
            RUNNER_MODULE.classify_configtest_failure(
                "nginx: [emerg] chown(/tmp/client_body_temp, 65534) failed"
            ),
            "client_body_temp_ownership",
        )
        self.assertEqual(
            RUNNER_MODULE.classify_configtest_failure(
                "nginx: [emerg] open() failed (13: Permission denied)"
            ),
            "permission_denied",
        )
        self.assertEqual(
            RUNNER_MODULE.classify_configtest_failure(
                "nginx: [emerg] unknown directive \"modsecurity\""
            ),
            "unknown_directive",
        )
        self.assertEqual(
            RUNNER_MODULE.classify_configtest_failure("opaque fixture failure"),
            "unclassified",
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
