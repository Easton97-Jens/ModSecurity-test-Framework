from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = connector_root()
SOURCE = (
    source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
).read_text(encoding="utf-8")
COMMON_RUNTIME = (
    source_path('common/runtime/msconnector_runtime.c', root=ROOT)
).read_text(encoding="utf-8")


class TraefikEngineServiceContractTest(unittest.TestCase):
    def test_frame_input_uses_one_nonblocking_monotonic_deadline(self):
        self.assertIn("clock_gettime(CLOCK_MONOTONIC, &deadline)", SOURCE)
        self.assertIn("recv(socket_fd, data + offset, size - offset,\n            MSG_DONTWAIT)", SOURCE)
        self.assertIn("descriptor.events = POLLIN", SOURCE)
        self.assertNotIn("SO_RCVTIMEO", SOURCE)

    def test_poll_terminal_events_are_errors_for_both_directions(self):
        terminal_events = "(POLLERR | POLLHUP | POLLNVAL)"
        wait_start = SOURCE.index("static int traefik_engine_wait_for_socket_event")
        send_start = SOURCE.index("static int traefik_engine_send_deadline")
        receive_start = SOURCE.index("static int traefik_engine_receive_all")
        wait_path = SOURCE[wait_start:send_start]
        send_path = SOURCE[send_start:receive_start]
        receive_end = SOURCE.index("static void traefik_engine_frame_reset", receive_start)
        receive_path = SOURCE[receive_start:receive_end]
        self.assertIn(terminal_events, wait_path)
        self.assertIn("traefik_engine_deadline_remaining_milliseconds", wait_path)
        self.assertIn("traefik_engine_wait_for_socket_event(socket_fd, POLLOUT", send_path)
        self.assertIn("return 0;", send_path)
        self.assertIn("traefik_engine_wait_for_socket_event(socket_fd, POLLIN", receive_path)
        self.assertIn("return -1;", receive_path)

    def test_shutdown_defers_service_finalization_until_workers_are_idle(self):
        self.assertIn("int cleanup_pending;", SOURCE)
        self.assertIn("service->cleanup_pending = 1", SOURCE)
        self.assertIn("traefik_engine_finalize_service(service)", SOURCE)
        self.assertIn("service->cleanup_pending && service->worker_count == 0U", SOURCE)

    def test_worker_slot_close_and_invalidation_share_the_worker_lock(self):
        worker_start = SOURCE.index("static void *traefik_engine_worker(")
        worker_end = SOURCE.index("typedef enum traefik_engine_worker_start_result", worker_start)
        worker = SOURCE[worker_start:worker_end]
        lock = worker.index("pthread_mutex_lock(&service->worker_lock)")
        close = worker.index("(void)close(socket_fd);")
        invalidate_fd = worker.index("slot->socket_fd = -1;")
        invalidate_use = worker.index("slot->in_use = 0;")
        self.assertLess(lock, close)
        self.assertLess(close, invalidate_fd)
        self.assertLess(invalidate_fd, invalidate_use)
        shutdown_start = SOURCE.index("static void traefik_engine_shutdown_active_workers_locked")
        shutdown_end = SOURCE.index("static void traefik_engine_wait_for_workers", shutdown_start)
        shutdown = SOURCE[shutdown_start:shutdown_end]
        self.assertIn("socket_fd >= 0", shutdown)

    def test_admission_reports_capacity_without_a_racy_recheck(self):
        self.assertIn("TRAEFIK_ENGINE_WORKER_CAPACITY = 0", SOURCE)
        self.assertIn("worker_result == TRAEFIK_ENGINE_WORKER_CAPACITY", SOURCE)
        self.assertNotIn("traefik_engine_worker_capacity_reached", SOURCE)
        self.assertIn("MSG_NOSIGNAL", SOURCE)

    def test_private_directory_ancestor_policy_reuses_common_runtime(self):
        self.assertIn(
            "return msconnector_runtime_private_directory_ancestors_are_safe(path);",
            SOURCE,
        )
        self.assertNotIn(
            "traefik_engine_private_directory_ancestors_are_safe",
            SOURCE,
        )
        self.assertNotIn("traefik_engine_parent_protects_child", SOURCE)
        self.assertIn("realpath(path, NULL)", COMMON_RUNTIME)
        self.assertIn("strcmp(path, canonical_path) != 0", COMMON_RUNTIME)
        self.assertIn(
            "(parent_stat.st_uid != geteuid() && parent_stat.st_uid != 0)",
            COMMON_RUNTIME,
        )

    def test_socket_deadlines_and_normal_frames_execute_in_c17_harness(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("requires a C compiler")

        harness = r'''
#define _POSIX_C_SOURCE 200809L
#define TRAEFIK_ENGINE_SOCKET_TIMEOUT_SECONDS 1
#define main traefik_engine_service_program_main
#include "__ENGINE_SOURCE__"
#undef main

#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

static double monotonic_seconds(void)
{
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static void write_all(int fd, const unsigned char *data, size_t size)
{
    size_t offset = 0U;
    while (offset < size) {
        ssize_t written = write(fd, data + offset, size - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        assert(written > 0);
        offset += (size_t)written;
    }
}

static void read_all(int fd, unsigned char *data, size_t size)
{
    size_t offset = 0U;
    while (offset < size) {
        ssize_t received = read(fd, data + offset, size - offset);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        assert(received > 0);
        offset += (size_t)received;
    }
}

static void sleep_milliseconds(long milliseconds)
{
    struct timespec delay = {
        .tv_sec = milliseconds / 1000L,
        .tv_nsec = (milliseconds % 1000L) * 1000000L
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static void make_header(unsigned char *header, uint32_t payload_size)
{
    memcpy(header, "MSE1", 4U);
    header[4] = TRAEFIK_ENGINE_PROTOCOL_VERSION;
    header[5] = TRAEFIK_ENGINE_PROTOCOL_REQUEST_EOS;
    header[6] = 0U;
    header[7] = 0U;
    traefik_engine_write_u32(header + 8U, payload_size);
}

static void test_fragmented_frame_has_one_deadline(void)
{
    int sockets[2];
    unsigned char header[TRAEFIK_ENGINE_PROTOCOL_HEADER_SIZE];
    unsigned char payload[2] = {0x11U, 0x22U};
    traefik_engine_frame frame = {0};
    pid_t child;
    int status;
    double started;
    double elapsed;

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    make_header(header, sizeof(payload));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        signal(SIGPIPE, SIG_IGN);
        close(sockets[0]);
        write_all(sockets[1], header, sizeof(header));
        sleep_milliseconds(100L);
        write_all(sockets[1], payload, 1U);
        sleep_milliseconds(1100L);
        (void)write(sockets[1], payload + 1U, 1U);
        close(sockets[1]);
        _exit(0);
    }
    close(sockets[1]);
    started = monotonic_seconds();
    assert(traefik_engine_receive_frame(sockets[0], &frame) == -1);
    elapsed = monotonic_seconds() - started;
    assert(elapsed >= 0.8 && elapsed < 1.8);
    traefik_engine_frame_reset(&frame);
    close(sockets[0]);
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
}

static void test_nonreading_peer_hits_write_deadline(void)
{
    int sockets[2];
    int send_buffer = 1024;
    unsigned char payload[TRAEFIK_ENGINE_PROTOCOL_MAX_FRAME_PAYLOAD];
    double started;
    double elapsed;

    memset(payload, 0x5a, sizeof(payload));
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF,
        &send_buffer, sizeof(send_buffer)) == 0);
    started = monotonic_seconds();
    assert(traefik_engine_send_frame(sockets[0],
        TRAEFIK_ENGINE_PROTOCOL_RESPONSE_CHUNK, payload, sizeof(payload)) == 0);
    elapsed = monotonic_seconds() - started;
    assert(elapsed >= 0.7 && elapsed < 1.8);
    close(sockets[0]);
    close(sockets[1]);
}

struct frame_reader_args {
    int fd;
    unsigned char expected[TRAEFIK_ENGINE_PROTOCOL_MAX_FRAME_PAYLOAD];
};

static void *read_large_frame(void *argument)
{
    struct frame_reader_args *args = argument;
    unsigned char header[TRAEFIK_ENGINE_PROTOCOL_HEADER_SIZE];

    read_all(args->fd, header, sizeof(header));
    assert(memcmp(header, "MSE1", 4U) == 0);
    assert(header[5] == TRAEFIK_ENGINE_PROTOCOL_RESPONSE_CHUNK);
    assert(traefik_engine_read_u32(header + 8U) == sizeof(args->expected));
    read_all(args->fd, args->expected, sizeof(args->expected));
    return NULL;
}

static void test_partial_writes_complete_with_concurrent_reader(void)
{
    int sockets[2];
    int send_buffer = 1024;
    struct frame_reader_args reader = {.fd = -1};
    pthread_t reader_thread;
    unsigned char payload[sizeof(reader.expected)];

    memset(payload, 0x7c, sizeof(payload));
    memcpy(reader.expected, payload, sizeof(payload));
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    reader.fd = sockets[1];
    assert(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF,
        &send_buffer, sizeof(send_buffer)) == 0);
    assert(pthread_create(&reader_thread, NULL, read_large_frame, &reader) == 0);
    assert(traefik_engine_send_frame(sockets[0],
        TRAEFIK_ENGINE_PROTOCOL_RESPONSE_CHUNK, payload, sizeof(payload)) == 1);
    assert(pthread_join(reader_thread, NULL) == 0);
    assert(memcmp(reader.expected, payload, sizeof(payload)) == 0);
    close(sockets[0]);
    close(sockets[1]);
}

static void test_closed_peer_does_not_raise_sigpipe(void)
{
    int sockets[2];
    unsigned char payload[32] = {0};

    signal(SIGPIPE, SIG_DFL);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    close(sockets[1]);
    assert(traefik_engine_send_frame(sockets[0],
        TRAEFIK_ENGINE_PROTOCOL_RESPONSE_CHUNK, payload, sizeof(payload)) == 0);
    close(sockets[0]);
}

static void test_normal_frame_round_trip(void)
{
    int sockets[2];
    unsigned char payload[3] = {0xa1U, 0xb2U, 0xc3U};
    unsigned char received[sizeof(payload)];
    unsigned char header[TRAEFIK_ENGINE_PROTOCOL_HEADER_SIZE];
    traefik_engine_frame frame = {0};

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(traefik_engine_send_frame(sockets[0],
        TRAEFIK_ENGINE_PROTOCOL_REQUEST_CHUNK, payload, sizeof(payload)) == 1);
    read_all(sockets[1], header, sizeof(header));
    assert(header[5] == TRAEFIK_ENGINE_PROTOCOL_REQUEST_CHUNK);
    read_all(sockets[1], received, sizeof(received));
    assert(memcmp(received, payload, sizeof(payload)) == 0);
    close(sockets[0]);
    assert(traefik_engine_receive_frame(sockets[1], &frame) == 0);
    traefik_engine_frame_reset(&frame);
    close(sockets[1]);
}

int main(void)
{
    test_fragmented_frame_has_one_deadline();
    test_nonreading_peer_hits_write_deadline();
    test_partial_writes_complete_with_concurrent_reader();
    test_closed_peer_does_not_raise_sigpipe();
    test_normal_frame_round_trip();
    return 0;
}
'''.replace("__ENGINE_SOURCE__", str(
            source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
        ))

        with tempfile.TemporaryDirectory(prefix="traefik-engine-test-") as directory:
            source = Path(directory) / "harness.c"
            binary = Path(directory) / "harness"
            source.write_text(harness, encoding="utf-8")
            command = [
                compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
                "-Wno-unused-function", "-ffunction-sections", "-fdata-sections",
                "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)),
                "-pthread", str(source), "-Wl,--gc-sections",
                "-o", str(binary),
            ]
            compile_result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run([str(binary)], timeout=4.0,
                capture_output=True, text=True)
            self.assertEqual(run_result.returncode, 0, run_result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
