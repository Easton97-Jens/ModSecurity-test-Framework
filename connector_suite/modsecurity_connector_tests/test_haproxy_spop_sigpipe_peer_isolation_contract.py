"""Focused contracts for HAProxy SPOP peer failure and admission handling."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest

from modsecurity_connector_tests._haproxy_spop_contract_helpers import assert_worker_result_order


ROOT = connector_root()
SOURCE = (
    source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
).read_text(encoding="utf-8")


class HAProxySPOPSigpipePeerIsolationContractTests(unittest.TestCase):
    def test_protocol_writes_use_local_sigpipe_suppression(self) -> None:
        self.assertIn("send(fd, p, len, MSG_NOSIGNAL | MSG_DONTWAIT)", SOURCE)
        self.assertNotIn("signal(SIGPIPE, SIG_IGN)", SOURCE)
        self.assertNotIn("sigaction(SIGPIPE", SOURCE)
        self.assertIn("if (rc < 0)", SOURCE)

    def test_peer_worker_closes_and_releases_admission_on_every_exit(self) -> None:
        worker = SOURCE.split("static void *spop_connection_thread", 1)[1].split(
            "static int accept_loop", 1
        )[0]
        self.assertIn("connection_rc = handle_connection", worker)
        self.assertIn("if (connection_rc != 0)", worker)
        self.assertIn("log_peer_failure_rate_limited(task->log)", worker)
        self.assertIn("close(task->fd)", worker)
        self.assertIn("if (task->gate->active > 0U)", worker)
        self.assertIn("task->gate->active--", worker)
        self.assertIn("pthread_cond_broadcast(&task->gate->changed)", worker)
        self.assertIn("free(task)", worker)

    def test_accept_loop_is_bounded_and_does_not_run_protocol_inline(self) -> None:
        accept_loop = SOURCE.split("static int accept_loop", 1)[1].split(
            "static int client_expect_frame", 1
        )[0]
        spawn = SOURCE.split("static int spawn_spop_connection_worker", 1)[1].split(
            "static int accept_loop", 1
        )[0]
        self.assertIn("SPOP_MIN_WORKER_COUNT", SOURCE)
        self.assertIn("if (gate->active >= gate->limit)", spawn)
        self.assertIn(
            '"event=spop-peer-capacity-rejected action=close reason=worker-capacity"',
            spawn,
        )
        self.assertIn("pthread_create(&thread, detached_attributes", spawn)
        self.assertNotIn("handle_connection(fd, state, log", accept_loop)
        self.assertIn("close(fd);", spawn)
        self.assertIn("while (gate.active != 0U)", accept_loop)
        assert_worker_result_order(
            self, SOURCE, "worker_result == SPOP_CONNECTION_WORKER_FATAL"
        )

    def test_peer_failure_event_is_rate_limited_and_preserves_peer_cleanup(self) -> None:
        self.assertIn("static uint64_t last_peer_failure_log_ms = 0U", SOURCE)
        self.assertIn("static void log_peer_failure_rate_limited", SOURCE)
        self.assertIn(
            '"event=spop-peer-session-failed action=close "',
            SOURCE,
        )
        self.assertIn('"reason=protocol-or-write-error"', SOURCE)
        self.assertIn("now - last_peer_failure_log_ms >= 1000U", SOURCE)

    def test_peer_close_and_follow_up_handshake_are_runtime_regressions(self) -> None:
        self.assertIn("run_spop_peer_close_write_self_test", SOURCE)
        self.assertIn("shutdown(sockets[1], SHUT_RD)", SOURCE)
        self.assertIn("client healthcheck handshake PASS", SOURCE)
        self.assertIn("client notify set-var ack disconnect PASS", SOURCE)
        self.assertIn("finish_ms - start_ms > 1000U", SOURCE)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
