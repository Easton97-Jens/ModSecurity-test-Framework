"""Static lifecycle contracts for the native Traefik UDS engine service."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


ROOT = connector_root()
SOURCE = (
    source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
).read_text(encoding="utf-8")


class TraefikEngineServiceShutdownContractTests(unittest.TestCase):
    def test_peer_writes_and_worker_admission_are_bounded(self) -> None:
        self.assertIn("TRAEFIK_ENGINE_DEFAULT_MAX_WORKERS 64U", SOURCE)
        self.assertIn("TRAEFIK_ENGINE_HARD_MAX_WORKERS 256U", SOURCE)
        self.assertIn("TRAEFIK_ENGINE_SOCKET_TIMEOUT_SECONDS", SOURCE)
        self.assertIn("clock_gettime(CLOCK_MONOTONIC, &deadline)", SOURCE)
        self.assertIn("poll(&descriptor, 1U, timeout)", SOURCE)
        self.assertIn("send(socket_fd, data + offset, size - offset,\n            MSG_NOSIGNAL | MSG_DONTWAIT)", SOURCE)
        self.assertIn("errno != EAGAIN &&", SOURCE)
        self.assertIn("errno != EWOULDBLOCK", SOURCE)
        self.assertNotIn("SIGPIPE", SOURCE)
        self.assertIn("worker_result == TRAEFIK_ENGINE_WORKER_CAPACITY", SOURCE)
        self.assertIn("(void)close(client);\n                continue;", SOURCE)

    def test_worker_cleanup_uses_stable_admission_slot(self) -> None:
        self.assertIn("traefik_engine_worker_slot *slot;", SOURCE)
        self.assertIn("worker->slot = slot;", SOURCE)
        self.assertIn("slot = worker->slot;", SOURCE)
        self.assertIn(
            "(void)close(socket_fd);\n"
            "        slot->socket_fd = -1;\n"
            "        slot->in_use = 0;",
            SOURCE,
        )
        self.assertNotIn(
            "if (service->worker_slots[index].socket_fd == socket_fd)",
            SOURCE,
        )

    def test_shutdown_cancels_workers_and_never_waits_forever(self) -> None:
        self.assertIn(
            "shutdown(service->worker_slots[index].socket_fd, SHUT_RDWR)",
            SOURCE,
        )
        self.assertIn("pthread_cond_timedwait", SOURCE)
        self.assertIn("service->cleanup_pending = 1", SOURCE)
        self.assertIn(
            "service->cleanup_pending && service->worker_count == 0U",
            SOURCE,
        )
        self.assertNotIn("_exit(1);", SOURCE)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
