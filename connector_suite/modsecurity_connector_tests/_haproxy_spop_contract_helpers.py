"""Shared structural assertions for HAProxy SPOP contract tests."""

from modsecurity_connector_tests.c_source_contract import function_definition


def assert_worker_result_order(testcase, source: str, fatal_marker: str) -> None:
    """Verify worker-result handling preserves accept-loop control flow."""
    accept_loop = function_definition(source, "accept_loop")
    result_handler = function_definition(source, "process_spop_worker_result")
    testcase.assertIn("SPOP_CONNECTION_WORKER_CAPACITY_REJECTED", result_handler)
    testcase.assertIn("SPOP_CONNECTION_WORKER_STOPPED", result_handler)
    testcase.assertIn(fatal_marker, result_handler)
    testcase.assertIn("SPOP_ACCEPT_ITERATION_CONTINUE", result_handler)
    testcase.assertIn("SPOP_ACCEPT_ITERATION_STOP", result_handler)
    testcase.assertIn("int loop_running = 1;", accept_loop)
    testcase.assertIn("while (loop_running && !stop_requested &&", accept_loop)
    testcase.assertIn("continue;", accept_loop)
    testcase.assertIn("handled++;", accept_loop)

    capacity = result_handler.index("SPOP_CONNECTION_WORKER_CAPACITY_REJECTED")
    stopped = result_handler.index("SPOP_CONNECTION_WORKER_STOPPED")
    fatal = result_handler.index(fatal_marker)
    capacity_return = result_handler.index(
        "return SPOP_ACCEPT_ITERATION_CONTINUE;", capacity
    )
    iteration_continue = accept_loop.index(
        "iteration_result == SPOP_ACCEPT_ITERATION_CONTINUE"
    )
    iteration_stop = accept_loop.index("iteration_result == SPOP_ACCEPT_ITERATION_STOP")
    handled = accept_loop.index("handled++;")

    testcase.assertLess(capacity, capacity_return)
    testcase.assertLess(
        iteration_continue,
        accept_loop.index("continue;", iteration_continue),
    )
    testcase.assertLess(iteration_continue, handled)
    testcase.assertLess(
        iteration_stop,
        accept_loop.index("loop_running = 0;", iteration_stop),
    )
    testcase.assertLess(
        accept_loop.index("loop_running = 0;", iteration_stop),
        accept_loop.index("continue;", iteration_stop),
    )
    testcase.assertLess(iteration_stop, handled)
    testcase.assertLess(
        capacity_return,
        result_handler.index("SPOP_ACCEPT_ITERATION_STOP", stopped),
    )
    testcase.assertLess(fatal, result_handler.index("loop_rc = 1;"))
