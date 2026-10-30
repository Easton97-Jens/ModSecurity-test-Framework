"""Regression contracts for the bounded HAProxy SPOP peer runtime."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest

from modsecurity_connector_tests._haproxy_spop_contract_helpers import assert_worker_result_order


ROOT = connector_root()
SOURCE = (
    source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
).read_text(encoding="utf-8")
EXAMPLE = (
    source_path('examples/haproxy/compatibility-spoe/modsecurity-agent.conf', root=ROOT)
).read_text(encoding="utf-8")
HARNESS = (source_path('connectors/haproxy/harness/run_haproxy_smoke.sh', root=ROOT)).read_text(
    encoding="utf-8"
)
COMMON_TRANSPORT = (
    source_path('common/runtime/response_companion_transport.c', root=ROOT)
).read_text(encoding="utf-8")
COMMON_RUNTIME = (
    source_path('common/runtime/msconnector_runtime.c', root=ROOT)
).read_text(encoding="utf-8")


class HAProxySPOPPeerIsolationContractTests(unittest.TestCase):
    def test_peer_writes_are_bounded_and_not_globally_sigpipe_ignored(self) -> None:
        self.assertIn("send(fd, p, len, MSG_NOSIGNAL | MSG_DONTWAIT)", SOURCE)
        self.assertIn("write_full_until(fd, &net_len, sizeof(net_len), deadline)", SOURCE)
        self.assertIn("write_full_until(fd, frame.data, frame.len, deadline)", SOURCE)
        self.assertIn("errno == EAGAIN", SOURCE)
        self.assertIn("errno == EWOULDBLOCK", SOURCE)
        self.assertNotIn("SIG_IGN", SOURCE)
        self.assertNotIn("sigaction(SIGPIPE", SOURCE)

    def test_blocking_accepted_socket_hits_deadline_and_followup_succeeds(self) -> None:
        deadline_test = SOURCE.split(
            "static int open_write_deadline_sockets", 1
        )[1].split("static int run_spop_write_deadline_self_test", 1)[0]
        deadline_wrapper = SOURCE.split(
            "static int run_spop_write_deadline_self_test", 1
        )[1].split("static int run_spop_peer_close_write_self_test", 1)[0]
        self.assertIn("*server_fd = accept(*listener_fd, 0, 0)", deadline_test)
        self.assertIn("(flags & O_NONBLOCK) != 0", deadline_test)
        self.assertNotIn("F_SETFL", deadline_test)
        self.assertIn("MSG_NOSIGNAL | MSG_DONTWAIT", deadline_test)
        self.assertIn("send_frame_timeout(context->server_fd,", deadline_test)
        self.assertIn("send_frame_timeout(context->followup[0],", deadline_test)
        self.assertIn(
            "recv_frame(context->followup[1], &context->frame, 100U)",
            deadline_test,
        )
        self.assertIn("alarm(2U)", deadline_test)
        self.assertIn("child = fork()", deadline_wrapper)
        self.assertIn("WIFEXITED(status)", deadline_wrapper)

    def test_peer_isolation_has_bounded_deadlines_and_admission(self) -> None:
        self.assertIn("SPOP_OWNER_CALLER_WAIT_MS 1000U", SOURCE)
        self.assertIn("SPOP_OWNER_QUEUE_CAPACITY 128U", SOURCE)
        self.assertIn("send_frame_timeout(fd,", SOURCE)
        self.assertIn("recv_frame(fd, &frame, timeout_ms)", SOURCE)
        self.assertIn("read_full_until", SOURCE)

    def test_accept_loop_closes_each_peer_after_protocol_processing(self) -> None:
        accept_loop = SOURCE.split("static int accept_loop", 1)[1].split(
            "static int client_expect_frame", 1
        )[0]
        spawn = SOURCE.split("static int spawn_spop_connection_worker", 1)[1].split(
            "static int accept_loop", 1
        )[0]
        worker = SOURCE.split("static void *spop_connection_thread", 1)[1].split(
            "static int spawn_spop_connection_worker", 1
        )[0]
        self.assertIn("handle_connection(task->fd, task->state, task->log", worker)
        self.assertIn("if (connection_rc != 0)", worker)
        self.assertIn("log_peer_failure_rate_limited(task->log)", worker)
        self.assertIn("close(task->fd)", worker)
        self.assertIn("task->gate->active--", worker)
        self.assertIn("pthread_cond_broadcast(&task->gate->changed)", worker)
        self.assertIn("pthread_attr_setdetachstate", accept_loop)
        self.assertIn("PTHREAD_CREATE_DETACHED", accept_loop)
        self.assertIn("if (gate->active >= gate->limit)", spawn)
        self.assertIn(
            '"event=spop-peer-capacity-rejected action=close reason=worker-capacity"',
            spawn,
        )
        self.assertIn("last_capacity_rejection_log_ms", SOURCE)
        self.assertIn("pthread_create(&thread", spawn)
        self.assertIn("close(fd)", spawn)
        self.assertIn("gate->active--", spawn)
        self.assertIn("pthread_cond_broadcast(&gate->changed)", spawn)
        assert_worker_result_order(self, SOURCE, "SPOP_CONNECTION_WORKER_FATAL")

    def test_peer_admission_has_a_safe_minimum_and_bounded_pool(self) -> None:
        self.assertIn("#define SPOP_MIN_WORKER_COUNT 2U", SOURCE)
        self.assertIn("#define SPOP_MAX_WORKER_COUNT 64U", SOURCE)
        self.assertIn("config->worker_count = 8U", SOURCE)
        self.assertIn("config->worker_count < SPOP_MIN_WORKER_COUNT", SOURCE)
        self.assertIn("SPOP_MAX_TRANSACTION_SLOTS_TOTAL / config->worker_count", SOURCE)

    def test_peer_close_write_self_test_requires_normal_process_survival(self) -> None:
        self.assertIn("run_spop_peer_close_write_self_test", SOURCE)
        self.assertIn("shutdown(sockets[1], SHUT_RD)", SOURCE)
        self.assertIn("WIFEXITED(status)", SOURCE)
        self.assertIn("finish_ms - start_ms > 1000U", SOURCE)

    def test_runtime_self_test_covers_reset_slow_peer_and_follow_up_hello(self) -> None:
        self.assertIn("client healthcheck handshake PASS", SOURCE)
        self.assertIn("client notify set-var ack disconnect PASS", SOURCE)
        self.assertIn("read_full_until", SOURCE)

    def test_running_owner_timeout_uses_bounded_controlled_restart(self) -> None:
        self.assertIn("SPOP_OWNER_SHUTDOWN_WAIT_MS 1000U", SOURCE)
        self.assertIn("SPOP_OWNER_RESTART_EXIT_CODE 75", SOURCE)
        self.assertIn("spop_owner_queue_request_restart(queue)", SOURCE)
        self.assertIn("spop_owner_queue_cancel_pending_locked(queue)", SOURCE)
        self.assertIn("event=spop-owner-timeout action=controlled-restart", SOURCE)
        self.assertIn("shutdown(queue->listener_fd, SHUT_RDWR)", SOURCE)
        self.assertIn("pthread_cond_timedwait(&queue->owner_stopped", SOURCE)
        self.assertIn("clock_gettime(CLOCK_MONOTONIC, deadline)", SOURCE)
        self.assertNotIn("pthread_cancel", SOURCE)

    def test_unquiesced_owner_exits_without_releasing_stack_backed_state(self) -> None:
        cleanup = SOURCE.split("static void stop_response_transport_or_exit", 1)[1].split(
            "static int initialize_native_response_companion", 1
        )[0]
        self.assertGreaterEqual(
            cleanup.count("_Exit(SPOP_OWNER_RESTART_EXIT_CODE)"), 2
        )
        self.assertIn("use-after-return/use-after-close", cleanup)

    def test_restart_disposition_is_read_before_queue_lock_destruction(self) -> None:
        cleanup = SOURCE.split("static void stop_response_transport_or_exit", 1)[1].split(
            "static int initialize_native_response_companion", 1
        )[0]
        snapshot = cleanup.index(
            "restart_required = spop_owner_queue_requires_restart(state)"
        )
        destroy = cleanup.index("spop_owner_queue_destroy(state)", snapshot)
        self.assertLess(snapshot, destroy)
        self.assertIn("if (restart_required)", cleanup)
        self.assertIn("return SPOP_OWNER_RESTART_EXIT_CODE", cleanup)
        self.assertNotIn("return restart_required", cleanup)

        server = SOURCE.split("static int run_agent_server", 1)[1].split(
            "static void print_usage", 1
        )[0]
        post_cleanup = server.split("destroy_agent_runtime", 1)[1]
        self.assertNotIn("spop_owner_queue_requires_restart", post_cleanup)

    def test_restart_disposition_is_independent_of_queue_mutex_lifetime(self) -> None:
        queue_type = SOURCE.split("typedef struct spop_owner_queue", 1)[1].split(
            "} spop_owner_queue;", 1
        )[0]
        self.assertIn("atomic_int restart_required;", queue_type)

        queue_init = SOURCE.split("static int spop_owner_queue_init", 1)[1].split(
            "static void spop_owner_queue_set_listener", 1
        )[0]
        self.assertIn("atomic_init(&queue->restart_required, 0);", queue_init)

        accessor = SOURCE.split(
            "static int spop_owner_queue_requires_restart", 1
        )[1].split("static int spop_owner_queue_destroy", 1)[0]
        initialized_guard = accessor.index("if (!queue->initialized)")
        atomic_load = accessor.index("atomic_load_explicit")
        self.assertLess(initialized_guard, atomic_load)
        self.assertIn("return 0;", accessor[initialized_guard:atomic_load])
        self.assertIn("atomic_load_explicit(&queue->restart_required", accessor)
        self.assertIn("memory_order_acquire", accessor)
        self.assertNotIn("pthread_mutex", accessor)

    def test_owner_queue_is_invalidated_before_every_lock_destruction(self) -> None:
        queue_lifecycle = SOURCE.split("static int spop_owner_queue_init", 1)[1].split(
            "static int spop_owner_queue_submit", 1
        )[0]
        lifecycle_lines = [line.strip() for line in queue_lifecycle.splitlines()]
        for index, line in enumerate(lifecycle_lines):
            if line == "pthread_mutex_destroy(&queue->lock);":
                with self.subTest(destroy_line=index):
                    self.assertIn(
                        "queue->initialized = 0;",
                        lifecycle_lines[max(0, index - 6) : index],
                    )

    def test_response_transport_shutdown_is_outer_bounded_and_terminal(self) -> None:
        bounded_stop = SOURCE.split("static int spop_transport_stop_bounded", 1)[
            1
        ].split("static int destroy_agent_runtime", 1)[0]
        self.assertIn("pthread_cond_timedwait", bounded_stop)
        self.assertIn("event=spop-response-transport-shutdown-timeout", bounded_stop)
        self.assertGreaterEqual(
            bounded_stop.count("_Exit(SPOP_OWNER_RESTART_EXIT_CODE)"), 3
        )

    def test_owned_companion_socket_is_removed_before_blocking_waits(self) -> None:
        stop = COMMON_TRANSPORT.split(
            "int msconnector_response_companion_transport_stop", 1
        )[1]
        remove_socket = stop.index("response_companion_remove_owned_socket(transport)")
        join_listener = stop.index("pthread_join(transport->listener.listener_thread")
        wait_workers = stop.index("pthread_cond_wait(")
        self.assertLess(remove_socket, join_listener)
        self.assertLess(remove_socket, wait_workers)

    def test_owner_self_test_proves_terminal_rejection_and_fresh_instance(self) -> None:
        owner_test = SOURCE.split("static int run_spop_owner_queue_self_test", 1)[1].split(
            "static int run_spop_body_limit_self_test", 1
        )[0]
        fresh_state_test = SOURCE.split(
            "static int run_spop_owner_queue_fresh_state_self_test", 1
        )[1].split("static int run_spop_owner_queue_self_test", 1)[0]
        self.assertIn("!spop_owner_queue_requires_restart(&state)", owner_test)
        self.assertIn("spop_owner_queue_destroy(&state) == 0", owner_test)
        self.assertIn("shutdown_elapsed - shutdown_started", owner_test)
        self.assertIn("agent_state state", fresh_state_test)
        self.assertIn("spop_owner_queue_init(&state)", fresh_state_test)
        self.assertIn("spop_owner_queue_submit(&state", fresh_state_test)
        self.assertIn("spop_owner_queue_destroy(&state)", fresh_state_test)

    def test_safe_example_does_not_reintroduce_a_single_peer_bottleneck(self) -> None:
        self.assertIn("worker-count=8", EXAMPLE)

    def test_response_companion_checks_every_private_directory_ancestor(self) -> None:
        parent_check = COMMON_TRANSPORT.split(
            "static int response_companion_private_parent_is_safe", 1
        )[1].split("static int response_companion_set_nonblocking", 1)[0]
        ancestor_check = COMMON_RUNTIME.split(
            "int msconnector_runtime_private_directory_ancestors_are_safe", 1
        )[1].split("typedef struct msconnector_runtime_owned_config", 1)[0]

        self.assertIn(
            "return msconnector_runtime_private_directory_ancestors_are_safe(parent);",
            parent_check,
        )
        self.assertIn('while (strcmp(child_path, "/") != 0)', ancestor_check)
        owner_guard = "(parent_stat.st_uid != geteuid() && parent_stat.st_uid != 0)"
        writable_mode_guard = "(parent_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0"
        self.assertIn(owner_guard, ancestor_check)
        self.assertIn(writable_mode_guard, ancestor_check)
        self.assertLess(
            ancestor_check.index(owner_guard),
            ancestor_check.index(writable_mode_guard),
        )
        self.assertIn("S_ISVTX", ancestor_check)
        self.assertIn("child_stat.st_uid != geteuid()", ancestor_check)

    def test_closed_spoe_profiles_do_not_continue_on_agent_error(self) -> None:
        for profile in ("strict", "safe", "off", "all"):
            with self.subTest(profile=profile):
                profile_root = source_path('examples/haproxy/spoe-spop', root=ROOT) / profile
                spoe_config = (profile_root / "spoe.cfg").read_text(encoding="utf-8")
                agent_config = (profile_root / "spoa-agent.conf").read_text(
                    encoding="utf-8"
                )
                self.assertIn("fail-mode=closed", agent_config)
                self.assertNotIn("option continue-on-error", spoe_config)

    def test_spoe_samples_use_total_framing_metadata(self) -> None:
        producers = list((source_path('examples/haproxy/spoe-spop', root=ROOT)).glob("*/spoe.cfg"))
        producers.extend(
            ROOT / name
            for name in (
                "examples/haproxy/compatibility-spoe/spoe-modsecurity.conf",
                "connectors/haproxy/harness/run_haproxy_smoke.sh",
                "connectors/haproxy/harness/combined_spop_htx/run_combined_spop_htx.sh",
            )
        )
        for producer in producers:
            with self.subTest(producer=producer):
                text = producer.read_text(encoding="utf-8")
                # req.body_len is the buffered prefix, not the total. The
                # protocol version disambiguates unframed HTTP/1 empty input
                # from HTTP/2 and /3 samples without a trusted HTTP EOM.
                self.assertIn("body_len=req.body_size", text)
                self.assertIn("http_version=req.ver", text)
                self.assertNotIn("body_len=req.body_len", text)

    def test_closed_defaults_preserve_explicit_error_status_mapping(self) -> None:
        self.assertNotIn("option continue-on-error", EXAMPLE)
        self.assertIn("fail-mode=closed", EXAMPLE)
        self.assertIn("deny status 503", HARNESS)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
