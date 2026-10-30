"""Local contract tests for the patched lighttpd pre-upstream P2 gate.

The state model below mirrors the observable host obligation: request bytes may
be inspected incrementally, but an upstream release is legal only after the
single P2 EOS decision.  It is intentionally independent of a lighttpd build;
the real host run remains a separate evidence requirement.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


ROOT = connector_root()
MODULE = source_path('connectors/lighttpd/module/mod_msconnector.c', root=ROOT)
CONFIG = source_path('connectors/lighttpd/config/lighttpd-native.conf', root=ROOT)


class PreUpstreamGate:
    """Small executable model of the patched host's P2 release boundary."""

    def __init__(self, limit: int) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        self.limit = limit
        self.seen = 0
        self.terminal = False
        self.decision: str | None = None
        self.upstream = bytearray()
        self.cleaned = False

    def append(self, chunk: bytes) -> None:
        if self.terminal:
            raise RuntimeError("append after terminal P2")
        if self.seen + len(chunk) > self.limit:
            self.terminal = True
            self.decision = "limit"
            self.cleanup()
            return
        self.seen += len(chunk)

    def eos(self, decision: str = "allow") -> None:
        if self.terminal:
            raise RuntimeError("duplicate P2 EOS")
        self.terminal = True
        self.decision = decision
        if decision == "allow":
            self.upstream.extend(b"release-once")
        self.cleanup()

    def cancel(self) -> None:
        if not self.terminal:
            self.terminal = True
            self.decision = "cancel"
        self.cleanup()

    def cleanup(self) -> None:
        self.cleaned = True


class PatchedP2GateContractTest(unittest.TestCase):
    def test_source_uses_explicit_gate_and_never_enables_request_stream_flag(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        prepare = source.split("static handler_t mod_msconnector_prepare_request_body", 1)[1]
        prepare = prepare.split("static handler_t mod_msconnector_handle_request_body", 1)[0]
        self.assertIn('"pre-upstream"', source)
        self.assertIn("msconnector.request-body-gate", source)
        self.assertIn("r->con->reqbody_read(r)", prepare)
        self.assertNotRegex(prepare, r"stream_request_body\s*\|=")
        self.assertIn("request_body_finished", prepare)
        # Native limits belong to the engine. The connector's gate buffers
        # until native P2 admission instead of inventing its own BODY_LIMIT.
        self.assertNotIn("request_body_limit", source)
        self.assertNotIn("MSCONNECTOR_ERROR_BODY_TOO_LARGE", source)
        self.assertIn('msconnector.request-body-gate = "pre-upstream"', CONFIG.read_text(encoding="utf-8"))
        self.assertIn("return ctx->request_body_finished ? HANDLER_GO_ON : HANDLER_WAIT_FOR_EVENT;", prepare)

    def test_runtime_config_documents_the_explicit_pre_upstream_mode(self) -> None:
        config = CONFIG.read_text(encoding="utf-8")
        self.assertIn("request_body_mode=streaming", config)
        self.assertIn('msconnector.request-body-gate = "pre-upstream"', config)

    def test_chunked_body_is_delayed_until_eos_then_released_once(self) -> None:
        gate = PreUpstreamGate(limit=8)
        gate.append(b"abc")
        gate.append(b"def")
        self.assertEqual(gate.upstream, b"")
        self.assertFalse(gate.terminal)
        gate.eos()
        self.assertEqual(gate.upstream, b"release-once")
        self.assertTrue(gate.cleaned)

    def test_deny_limit_and_engine_error_never_release_upstream(self) -> None:
        for decision in ("deny", "engine-error"):
            gate = PreUpstreamGate(limit=8)
            gate.append(b"body")
            gate.eos(decision)
            self.assertEqual(gate.upstream, b"")
            self.assertTrue(gate.cleaned)

        limited = PreUpstreamGate(limit=4)
        limited.append(b"12345")
        self.assertEqual(limited.decision, "limit")
        self.assertEqual(limited.upstream, b"")
        self.assertTrue(limited.cleaned)

    def test_cancel_cleanup_and_connection_reuse_do_not_cross_transactions(self) -> None:
        first = PreUpstreamGate(limit=8)
        first.append(b"partial")
        first.cancel()
        self.assertEqual(first.upstream, b"")
        self.assertTrue(first.cleaned)

        reused = PreUpstreamGate(limit=8)
        reused.append(b"new")
        reused.eos()
        self.assertEqual(reused.upstream, b"release-once")

    def test_parallel_transactions_have_independent_release_boundaries(self) -> None:
        left = PreUpstreamGate(limit=8)
        right = PreUpstreamGate(limit=8)
        left.append(b"left")
        right.append(b"right")
        right.eos("deny")
        self.assertEqual(right.upstream, b"")
        self.assertEqual(left.upstream, b"")
        left.eos()
        self.assertEqual(left.upstream, b"release-once")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
