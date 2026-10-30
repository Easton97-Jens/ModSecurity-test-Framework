#if defined(__GNUC__)
#define SPOP_MAYBE_UNUSED __attribute__((unused))
#else
#define SPOP_MAYBE_UNUSED
#endif

enum self_test_metadata_mask {
    SELF_TEST_METADATA_READY = 1U,
    SELF_TEST_METADATA_PID = 2U,
    SELF_TEST_METADATA_PORT = 4U,
    SELF_TEST_METADATA_ALL = 7U
};

typedef struct self_test_cleanup_context {
    int *listen_fd;
    pid_t child;
    int *status;
    int terminate;
    int *ready_fd;
    int *pid_fd;
    int *port_fd;
    const char *ready_path;
    const char *pid_path;
    const char *port_path;
    unsigned int owned_metadata;
    FILE **log;
} self_test_cleanup_context;

typedef struct spop_owner_queue_self_test_context {
    pthread_t worker;
    int ran;
} spop_owner_queue_self_test_context;

typedef struct spop_owner_queue_gate_context {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int started;
    int release;
    int destroyed;
} spop_owner_queue_gate_context;

typedef struct spop_owner_queue_submit_thread {
    agent_state *state;
    spop_owner_queue_gate_context *context;
    int rc;
    unsigned int timeout_ms;
} spop_owner_queue_submit_thread;

typedef struct spop_owner_queue_gate_task {
    spop_owner_queue_gate_context *gate;
} spop_owner_queue_gate_task;

typedef struct spop_write_deadline_context {
    int listener_fd;
    int server_fd;
    int client_fd;
    int followup[2];
    spop_buffer payload;
    spop_frame frame;
} spop_write_deadline_context;

typedef struct spop_self_test_context {
    char log_path[4096];
    char ready_path[4096];
    char pid_path[4096];
    char port_path[4096];
    unsigned int port;
    int listen_fd;
    pid_t child;
    int status;
    FILE *log;
    int ready_fd;
    int pid_fd;
    int port_fd;
    int owned_metadata;
    int result;
    pid_t child_to_reap;
    int terminate_child;
} spop_self_test_context;

/* Framework-owned native regression definitions. Product source is supplied explicitly by the runner. */

static int write_fd_contents(int fd, const char *contents) {
    size_t length;
    size_t offset = 0U;

    if (fd < 0 || contents == 0 ||
            bounded_cstring_length(contents, 4096U, &length) != 0) {
        return -1;
    }
    while (offset < length) {
        ssize_t written = write(fd, contents + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int write_unsigned_fd(int fd, unsigned int value) {
    char contents[32];

    if (snprintf(contents, sizeof(contents), "%u\n", value) < 0) {
        return -1;
    }
    return write_fd_contents(fd, contents);
}

static int write_process_id_fd(int fd, pid_t process_id) {
    char contents[32];

    if (snprintf(contents, sizeof(contents), "%ld\n", (long)process_id) < 0) {
        return -1;
    }
    return write_fd_contents(fd, contents);
}

static int SPOP_MAYBE_UNUSED claim_self_test_metadata_file(const char *path) {
    if (path == 0 || path[0] == '\0' || strlen(path) >= 4096U) {
        return -1;
    }
    return open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
}

static int close_self_test_fd(int *fd) {
    int rc;

    if (fd == 0 || *fd < 0) {
        return 0;
    }
    rc = close(*fd);
    *fd = -1;
    return rc;
}

static int SPOP_MAYBE_UNUSED cleanup_self_test_metadata(const char *ready_path,
        const char *pid_path, const char *port_path, unsigned int mask,
        FILE *log) {
    const char *paths[3] = {ready_path, pid_path, port_path};
    const unsigned int bits[3] = {SELF_TEST_METADATA_READY,
        SELF_TEST_METADATA_PID, SELF_TEST_METADATA_PORT};

    int cleanup_failed = 0;

    for (size_t i = 0U; i < 3U; ++i) {
        if ((mask & bits[i]) != 0U && paths[i] != 0 &&
                unlink(paths[i]) != 0 && errno != ENOENT) {
            if (log != 0) {
                log_line(log, "self-test metadata cleanup failed path=%s errno=%d",
                    paths[i], errno);
            }
            cleanup_failed = 1;
        }
    }
    if (log != 0 && !cleanup_failed) {
        log_line(log, "self-test metadata cleanup PASS");
    } else if (log != 0) {
        log_line(log, "self-test metadata cleanup FAILED partial=1");
    }
    return cleanup_failed ? -1 : 0;
}

static int reap_self_test_child_after_kill(pid_t child, int *status)
{
    pid_t result;

    (void)kill(child, SIGKILL);
    for (;;) {
        result = waitpid(child, status, 0);
        if (result == child) {
            /* The forced termination is still a confirmed reap. */
            return 0;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0 && errno == ECHILD) {
            return -2;
        }
        return -1;
    }
}

static int wait_self_test_child_bounded(pid_t child, int *status, int terminate) {
    uint64_t deadline = monotonic_milliseconds() + 2000U;

    if (child <= 0 || status == 0) {
        return -1;
    }
    if (terminate) {
        (void)kill(child, SIGTERM);
    }
    for (;;) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) {
            return 0;
        }
        if (result < 0) {
            if (errno == ECHILD) {
                return -2;
            }
            if (errno != EINTR) {
                return -1;
            }
        }
        if (monotonic_milliseconds() >= deadline) {
            return reap_self_test_child_after_kill(child, status);
        }
        {
            struct timespec pause = {0, 10000000L};
            (void)nanosleep(&pause, 0);
        }
    }
}

static int finish_self_test_resources(self_test_cleanup_context *context) {
    int failed = 0;

    if (context == 0) {
        return -1;
    }
    if (context->listen_fd != 0 && *context->listen_fd >= 0) {
        int descriptor = *context->listen_fd;
        /* Mark consumed before close: on Linux a failed close may already
         * release the descriptor, so retrying could close a reused FD. */
        *context->listen_fd = -1;
        if (close(descriptor) != 0) {
            failed = 1;
        }
        *context->listen_fd = -1;
    }
    if (close_self_test_fd(context->ready_fd) != 0) {
        failed = 1;
    }
    if (close_self_test_fd(context->pid_fd) != 0) {
        failed = 1;
    }
    if (close_self_test_fd(context->port_fd) != 0) {
        failed = 1;
    }
    if (context->child > 0) {
        int wait_result = wait_self_test_child_bounded(context->child,
            context->status, context->terminate);
        if (wait_result != 0 || !WIFEXITED(*context->status) ||
                WEXITSTATUS(*context->status) != 0) {
            failed = 1;
        }
    }
    if (cleanup_self_test_metadata(context->ready_path, context->pid_path,
            context->port_path, context->owned_metadata,
            context->log != 0 ? *context->log : 0) != 0) {
        failed = 1;
    }
    if (context->log != 0 && *context->log != 0) {
        if (fclose(*context->log) != 0) {
            failed = 1;
        }
        *context->log = 0;
    }
    return failed ? -1 : 0;
}

static int append_typed_ipv4(spop_buffer *buf, const char *value) {
    struct in_addr address;

    if (buf == 0 || value == 0 || inet_pton(AF_INET, value, &address) != 1 ||
            append_byte(buf, SPOP_DATA_IPV4) != 0) {
        return -1;
    }
    return append_bytes(buf, (const unsigned char *)&address, sizeof(address),
        sizeof(address));
}

static int append_kv_bool(spop_buffer *buf, const char *key, int value) {
    return append_string(buf, key) == 0 && append_typed_bool(buf, value) == 0 ? 0 : -1;
}

static int build_notify_request_payload(
        spop_buffer *payload,
        const char *method,
        const char *path,
        const char *uri,
        const char *host,
        const char *test_header) {
    payload->len = 0;
    if (append_string(payload, "check-request") != 0 ||
            append_byte(payload, 9U) != 0 ||
            append_string(payload, "method") != 0 ||
            append_typed_string(payload, method) != 0 ||
            append_string(payload, "path") != 0 ||
            append_typed_string(payload, path) != 0 ||
            append_string(payload, "uri") != 0 ||
            append_typed_string(payload, uri) != 0 ||
            append_string(payload, "host") != 0 ||
            append_typed_string(payload, host) != 0 ||
            append_string(payload, "client_ip") != 0 ||
            append_typed_ipv4(payload, "127.0.0.1") != 0 ||
            append_string(payload, "server_ip") != 0 ||
            append_typed_ipv4(payload, "127.0.0.1") != 0 ||
            append_string(payload, "client_port") != 0 ||
            append_typed_uint32(payload, 41000U) != 0 ||
            append_string(payload, "server_port") != 0 ||
            append_typed_uint32(payload, 8080U) != 0 ||
            append_string(payload, "test_header") != 0 ||
            append_typed_string(payload, test_header) != 0) {
        return -1;
    }
    return 0;
}

static int self_test_rejects_oversized_endpoint_port(void) {
    spop_buffer payload;
    notify_request request;

    payload.len = 0U;
    if (append_string(&payload, "check-request") != 0 ||
            append_byte(&payload, 1U) != 0 ||
            append_string(&payload, "client_port") != 0 ||
            append_typed_uint32(&payload, 65536U) != 0) {
        return -1;
    }
    if (parse_notify_payload(payload.data, payload.len, &request) == 0) {
        free_notify_request(&request);
        return -1;
    }
    return 0;
}

static int payload_has_set_var_blocked_true(const spop_buffer *payload) {
    size_t pos = 0;
    const unsigned char *name;
    size_t name_len;

    if (payload->len < 4U) {
        return 0;
    }
    if (payload->data[pos] != SPOP_ACT_SET_VAR) {
        return 0;
    }
    ++pos;
    if (payload->data[pos] != 3U) {
        return 0;
    }
    ++pos;
    if (payload->data[pos] != SPOP_SCOPE_TXN) {
        return 0;
    }
    ++pos;
    if (read_string_ref(payload->data, payload->len, &pos, &name, &name_len) != 0) {
        return 0;
    }
    if (!KEY_EQUALS_LITERAL(name, name_len, "blocked") || pos >= payload->len) {
        return 0;
    }
    return payload->data[pos] == (SPOP_DATA_BOOL | SPOP_BOOL_TRUE);
}

static int self_test_rejects_fin_unset_frame(void) {
    int sockets[2] = {-1, -1};
    spop_buffer empty;
    spop_frame frame;
    int result = -1;

    empty.len = 0U;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return -1;
    }
    if (send_frame_with_flags(sockets[0], SPOP_FRM_NOTIFY, 0U, 1U, 1U,
            &empty) == 0 &&
        recv_frame(sockets[1], &frame, SPOP_LEGACY_TIMEOUT_MS) != 0) {
        result = 0;
    }
    close(sockets[0]);
    close(sockets[1]);
    return result;
}

static int send_haproxy_hello(int fd, int healthcheck) {
    spop_buffer payload;

    payload.len = 0;
    if (append_kv_string(&payload, "supported-versions", "2.0,1.2") != 0 ||
        append_kv_uint32(&payload, "max-frame-size", SPOP_FRAME_MAX) != 0 ||
        append_kv_empty_string(&payload, "capabilities") != 0 ||
        append_kv_bool(&payload, "healthcheck", healthcheck) != 0) {
        return -1;
    }
    return send_frame(fd, SPOP_FRM_HAPROXY_HELLO, 0, 0, &payload);
}

static void run_spop_owner_queue_self_test_task(void *opaque)
{
    spop_owner_queue_self_test_context *context =
        (spop_owner_queue_self_test_context *)opaque;

    context->worker = pthread_self();
    context->ran = 1;
}

static void run_spop_owner_queue_gate_task(void *opaque)
{
    spop_owner_queue_gate_task *task = (spop_owner_queue_gate_task *)opaque;
    spop_owner_queue_gate_context *gate = task->gate;

    pthread_mutex_lock(&gate->lock);
    gate->started = 1;
    pthread_cond_broadcast(&gate->changed);
    while (!gate->release) {
        pthread_cond_wait(&gate->changed, &gate->lock);
    }
    pthread_mutex_unlock(&gate->lock);
}

static void destroy_spop_owner_queue_gate_task(void *opaque)
{
    spop_owner_queue_gate_task *task = (spop_owner_queue_gate_task *)opaque;

    if (task != 0 && task->gate != 0) {
        pthread_mutex_lock(&task->gate->lock);
        task->gate->destroyed++;
        pthread_cond_broadcast(&task->gate->changed);
        pthread_mutex_unlock(&task->gate->lock);
    }
    free(task);
}

static void *spop_owner_queue_submit_gate_thread(void *opaque)
{
    spop_owner_queue_submit_thread *thread =
        (spop_owner_queue_submit_thread *)opaque;
    spop_owner_queue_gate_task *task =
        (spop_owner_queue_gate_task *)calloc(1U, sizeof(*task));

    if (task == 0) {
        thread->rc = -1;
        return 0;
    }
    task->gate = thread->context;
    thread->rc = spop_owner_queue_submit(thread->state,
        run_spop_owner_queue_gate_task, task,
        destroy_spop_owner_queue_gate_task, 0, 0, thread->timeout_ms);
    return 0;
}

static int run_spop_owner_queue_fresh_state_self_test(void)
{
    agent_state state;
    spop_owner_queue_self_test_context context;

    memset(&state, 0, sizeof(state));
    memset(&context, 0, sizeof(context));
    if (spop_owner_queue_init(&state) != 0) {
        return -1;
    }
    if (spop_owner_queue_submit(&state, run_spop_owner_queue_self_test_task,
            &context, 0, 0, 0, SPOP_OWNER_CALLER_WAIT_MS) != 0 ||
            !context.ran) {
        spop_owner_queue_destroy(&state);
        return -1;
    }
    if (spop_owner_queue_destroy(&state) != 0) {
        return -1;
    }
    return 0;
}

static int run_spop_owner_queue_self_test(void)
{
    agent_state state;
    spop_owner_queue_self_test_context context;
    spop_owner_queue_gate_context gate;
    spop_owner_queue_submit_thread first;
    spop_owner_queue_submit_thread second;
    pthread_t first_thread;
    pthread_t second_thread;
    uint64_t shutdown_started;
    uint64_t shutdown_elapsed;
    int rc;

    memset(&state, 0, sizeof(state));
    memset(&context, 0, sizeof(context));
    if (spop_owner_queue_init(&state) != 0) {
        return -1;
    }
    rc = spop_owner_queue_submit(&state, run_spop_owner_queue_self_test_task,
        &context, 0, 0, 0, SPOP_OWNER_CALLER_WAIT_MS);
    if (rc == 0 && (!context.ran ||
            !pthread_equal(context.worker, state.owner_queue.owner))) {
        rc = -1;
    }

    /* A running native-call stand-in that exceeds its caller deadline makes
     * the queue terminal.  The task remains quarantined, queued work is
     * cancelled, and shutdown returns after a bounded grace period without
     * freeing state that the owner still reaches. */
    memset(&gate, 0, sizeof(gate));
    if (pthread_mutex_init(&gate.lock, 0) != 0) {
        spop_owner_queue_destroy(&state);
        return -1;
    }
    if (pthread_cond_init(&gate.changed, 0) != 0) {
        pthread_mutex_destroy(&gate.lock);
        spop_owner_queue_destroy(&state);
        return -1;
    }
    first.state = &state;
    first.context = &gate;
    first.rc = 0;
    first.timeout_ms = 25U;
    second = first;
    if (pthread_create(&first_thread, 0,
            spop_owner_queue_submit_gate_thread, &first) != 0) {
        pthread_cond_destroy(&gate.changed);
        pthread_mutex_destroy(&gate.lock);
        spop_owner_queue_destroy(&state);
        return -1;
    }
    pthread_mutex_lock(&gate.lock);
    while (!gate.started) {
        pthread_cond_wait(&gate.changed, &gate.lock);
    }
    pthread_mutex_unlock(&gate.lock);
    if (pthread_create(&second_thread, 0,
            spop_owner_queue_submit_gate_thread, &second) != 0) {
        pthread_mutex_lock(&gate.lock);
        gate.release = 1;
        pthread_cond_broadcast(&gate.changed);
        pthread_mutex_unlock(&gate.lock);
        pthread_join(first_thread, 0);
        pthread_cond_destroy(&gate.changed);
        pthread_mutex_destroy(&gate.lock);
        spop_owner_queue_destroy(&state);
        return -1;
    }
    pthread_join(first_thread, 0);
    pthread_join(second_thread, 0);
    if (first.rc == 0 || second.rc == 0 ||
            !spop_owner_queue_requires_restart(&state)) {
        rc = -1;
    }
    memset(&context, 0, sizeof(context));
    if (spop_owner_queue_submit(&state, run_spop_owner_queue_self_test_task,
            &context, 0, 0, 0, SPOP_OWNER_CALLER_WAIT_MS) == 0 || context.ran) {
        rc = -1;
    }
    shutdown_started = monotonic_milliseconds();
    if (shutdown_started == 0U || spop_owner_queue_destroy(&state) == 0) {
        rc = -1;
    }
    shutdown_elapsed = monotonic_milliseconds();
    if (shutdown_elapsed == 0U || shutdown_elapsed < shutdown_started ||
            shutdown_elapsed - shutdown_started >
                (uint64_t)SPOP_OWNER_SHUTDOWN_WAIT_MS + UINT64_C(500)) {
        rc = -1;
    }
    pthread_mutex_lock(&gate.lock);
    gate.release = 1;
    pthread_cond_broadcast(&gate.changed);
    pthread_mutex_unlock(&gate.lock);
    if (spop_owner_queue_destroy(&state) != 0) {
        rc = -1;
    }
    pthread_mutex_lock(&gate.lock);
    if (gate.destroyed != 2) {
        rc = -1;
    }
    pthread_mutex_unlock(&gate.lock);
    pthread_cond_destroy(&gate.changed);
    pthread_mutex_destroy(&gate.lock);

    /* A fresh process state represents the supervisor restart.  Its owner
     * must accept a legitimate task after the terminal instance is gone. */
    if (run_spop_owner_queue_fresh_state_self_test() != 0) {
        rc = -1;
    }
    return rc;
}

static int run_spop_request_id_validation_self_test(void)
{
    static const unsigned char valid[] = {
        SPOP_DATA_STR, 36U,
        '5', '5', '0', 'e', '8', '4', '0', '0', '-',
        'e', '2', '9', 'b', '-', '4', '1', 'd', '4', '-',
        'a', '7', '1', '6', '-', '4', '4', '6', '6', '5',
        '5', '4', '4', '0', '0', '0', '0', '0'
    };
    static const unsigned char embedded_nul[] = {
        SPOP_DATA_STR, 3U, 'A', '\0', 'X'
    };
    static const unsigned char control[] = {
        SPOP_DATA_STR, 3U, 'A', 1U, 'X'
    };
    static const unsigned char empty[] = {SPOP_DATA_STR, 0U};
    unsigned char overlong[131U];
    const unsigned char *cases[] = {embedded_nul, control, empty, overlong};
    size_t lengths[] = {sizeof(embedded_nul), sizeof(control), sizeof(empty), sizeof(overlong)};
    char output[128];
    int present;
    size_t pos;

    pos = 0U;
    present = 0;
    memset(output, 0, sizeof(output));
    if (read_typed_request_id(valid, sizeof(valid), &pos, output,
            sizeof(output), &present) != 0 || !present ||
            strcmp(output, "550e8400-e29b-41d4-a716-446655440000") != 0) {
        return -1;
    }
    memset(overlong, 'x', sizeof(overlong));
    overlong[0] = SPOP_DATA_STR;
    overlong[1] = 0x80U;
    overlong[2] = 0x01U;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        pos = 0U;
        present = 0;
        memset(output, 0, sizeof(output));
        if (read_typed_request_id(cases[index], lengths[index], &pos, output,
                sizeof(output), &present) == 0 || pos != 0U || present) {
            return -1;
        }
    }
    return 0;
}

static int self_test_rejects_sample_at_admission(notify_request *request)
{
    agent_state state;
    haproxy_modsecurity_decision decision;
    int processed = 0;
    spop_ack_decision_origin origin = SPOP_ACK_FAILURE_DECISION;
    const char *text = NULL;
    char handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE] = {0};
    memset(&state, 0, sizeof(state));
    memset(&decision, 0, sizeof(decision));
    request->has_client_ip = 1;
    request->has_server_ip = 1;
    strcpy(request->client_ip, "127.0.0.1");
    strcpy(request->server_ip, "127.0.0.1");
    process_production_request_notify(&state, request, &decision,
        &processed, &origin, &text, handle);
    return !processed && decision.disruptive && decision.status == 503 &&
        !decision.body_limit && text != NULL &&
        strcmp(text, "admission-failure") == 0 && handle[0] == '\0' ? 0 : -1;
}

static int run_spop_sample_framing_self_test(void)
{
    static const char *lengths[] = {"4", "", "-1", "+4", "4,4", "4 ",
        "184467440737095516160", "5"};
    for (size_t index = 0U; index < sizeof(lengths) / sizeof(lengths[0]); ++index) {
        notify_request request;
        memset(&request, 0, sizeof(request));
        request.has_headers_bin = 1;
        request.has_body = 1;
        request.has_body_len_arg = 1;
        request.body_len = 4U;
        request.http_metadata.advertised_body_len = 4U;
        int result = add_request_header(&request,
            (const unsigned char *)"Content-Length", 14U,
            (const unsigned char *)lengths[index], strlen(lengths[index]));
        int complete = notify_request_has_complete_body_sample(&request);
        if (result != 0 || complete != (index == 0U)) {
            free_notify_request(&request);
            return -1;
        }
        if (index == 0U) {
            result = add_request_header(&request,
                (const unsigned char *)"Content-Length", 14U,
                (const unsigned char *)"4", 1U);
            complete = notify_request_has_complete_body_sample(&request);
        }
        free_notify_request(&request);
        if (result != 0 || complete) {
            return -1;
        }
    }
    return 0;
}

static int run_spop_sample_typed_arguments_self_test(void)
{
    static const unsigned char invalid_types[] = {0U, SPOP_DATA_BOOL,
        SPOP_DATA_STR, SPOP_DATA_BIN};
    for (size_t index = 0U; index < sizeof(invalid_types); ++index) {
        notify_request request;
        unsigned char input[] = {invalid_types[index], 0U};
        size_t pos = 0U;
        memset(&request, 0, sizeof(request));
        int body_result = parse_notify_body_argument(&request, input,
            sizeof(input), &pos, 0);
        free_notify_request(&request);
        if (body_result == 0 && index < 2U) {
            return -1;
        }
        pos = 0U;
        if (parse_notify_body_length_argument(&request,
                (const unsigned char *)"body_len", 8U, input,
                sizeof(input), &pos) == 0) {
            return -1;
        }
    }
    return 0;
}

static int run_spop_incomplete_request_sample_self_test(void)
{
    notify_request request;
    memset(&request, 0, sizeof(request));
    if (notify_request_has_complete_body_sample(&request) ||
            self_test_rejects_sample_at_admission(&request) != 0) {
        return -1;
    }
    request.has_headers_bin = 1;
    request.has_body = 1;
    request.has_body_len_arg = 1;
    if (notify_request_has_complete_body_sample(&request)) {
        return -1;
    }
    request.http_metadata.has_http_version = 1;
    strcpy(request.http_metadata.http_version, "2.0");
    if (notify_request_has_complete_body_sample(&request)) {
        return -1;
    }
    strcpy(request.http_metadata.http_version, "1.1");
    /* Explicit empty HTTP/1 input with complete unframed headers is legitimate. */
    if (!notify_request_has_complete_body_sample(&request)) {
        return -1;
    }
    request.body_len = 4U;
    request.http_metadata.advertised_body_len = 4U;
    /* Matching prefix lengths alone do not establish complete framing. */
    if (notify_request_has_complete_body_sample(&request)) {
        return -1;
    }
    request.body_len = 0U;
    request.http_metadata.advertised_body_len = 0U;
    if (add_request_header(&request, (const unsigned char *)"Transfer-Encoding",
            17U, (const unsigned char *)"chunked", 7U) != 0 ||
            notify_request_has_complete_body_sample(&request)) {
        free_notify_request(&request);
        return -1;
    }
    free_notify_request(&request);
    return run_spop_sample_framing_self_test() == 0 &&
        run_spop_sample_typed_arguments_self_test() == 0 ? 0 : -1;
}

static int run_spop_notify_failure_self_test(void)
{
    static const unsigned char truncated[] = {5U, 'c', 'h', 'e', 'c'};
    static const unsigned char missing_count[] = {
        13U, 'c', 'h', 'e', 'c', 'k', '-', 'r', 'e', 'q', 'u', 'e', 's', 't'
    };
    static const unsigned char zero_count[] = {
        13U, 'c', 'h', 'e', 'c', 'k', '-', 'r', 'e', 'q', 'u', 'e', 's', 't', 0U
    };
    notify_request request;

    memset(&request, 0, sizeof(request));
    if (parse_notify_payload(0, 0U, &request) == 0 ||
            parse_notify_payload(truncated, sizeof(truncated), &request) == 0 ||
            parse_notify_payload(missing_count, sizeof(missing_count), &request) == 0) {
        free_notify_request(&request);
        return -1;
    }
    free_notify_request(&request);
    memset(&request, 0, sizeof(request));
    if (parse_notify_payload(zero_count, sizeof(zero_count), &request) != 0 ||
            !request.has_notify || strcmp(request.message_name, "check-request") != 0) {
        free_notify_request(&request);
        return -1;
    }
    free_notify_request(&request);
    return 0;
}

static ssize_t recv_without_interrupt(int fd, void *buffer, size_t length,
        int flags)
{
    ssize_t received;

    do {
        received = recv(fd, buffer, length, flags);
    } while (received < 0 && errno == EINTR);
    return received;
}

static int open_write_deadline_sockets(int *listener_fd, int *server_fd,
        int *client_fd, struct sockaddr_in *address,
        socklen_t *address_size)
{
    *listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*listener_fd < 0 ||
            bind(*listener_fd, (struct sockaddr *)address,
                sizeof(*address)) != 0 ||
            listen(*listener_fd, 1) != 0 ||
            getsockname(*listener_fd, (struct sockaddr *)address,
                address_size) != 0) {
        return -1;
    }
    *client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*client_fd < 0 ||
            connect(*client_fd, (struct sockaddr *)address,
                sizeof(*address)) != 0) {
        return -1;
    }
    *server_fd = accept(*listener_fd, 0, 0);
    if (*server_fd < 0 || close(*listener_fd) != 0) {
        return -1;
    }
    *listener_fd = -1;
    return 0;
}

static int fill_write_deadline_socket(int server_fd,
        const unsigned char *filler, size_t filler_len)
{
    ssize_t written;

    for (;;) {
        written = send(server_fd, filler, filler_len,
            MSG_NOSIGNAL | MSG_DONTWAIT);
        if (written > 0) {
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    return written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
}

static int wait_write_deadline_socket_writable(int server_fd, int client_fd,
        unsigned char *drain, size_t drain_len, struct pollfd *descriptor)
{
    for (unsigned int attempt = 0U; attempt < 64U; ++attempt) {
        if (recv_without_interrupt(client_fd, drain, drain_len,
                MSG_DONTWAIT) <= 0) {
            return -1;
        }
        memset(descriptor, 0, sizeof(*descriptor));
        descriptor->fd = server_fd;
        descriptor->events = POLLOUT;
        if (poll(descriptor, 1U, 0) > 0 &&
                (descriptor->revents & POLLOUT) != 0) {
            return 0;
        }
    }
    return -1;
}

static int prepare_spop_write_deadline_child(
        spop_write_deadline_context *context)
{
    int flags;
    int send_buffer = 4096;
    unsigned char filler[4096];
    unsigned char drain[8192];
    struct sockaddr_in address;
    socklen_t address_size = sizeof(address);
    struct pollfd descriptor;

    if (signal(SIGALRM, SIG_DFL) == SIG_ERR) {
        return -1;
    }
    (void)alarm(2U);
    memset(filler, 'x', sizeof(filler));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (open_write_deadline_sockets(&context->listener_fd,
            &context->server_fd, &context->client_fd,
            &address, &address_size) != 0) {
        return -1;
    }
    flags = fcntl(context->server_fd, F_GETFL, 0);
    if (flags < 0 || (flags & O_NONBLOCK) != 0 ||
            setsockopt(context->server_fd, SOL_SOCKET, SO_SNDBUF, &send_buffer,
                sizeof(send_buffer)) != 0) {
        return -1;
    }
    if (fill_write_deadline_socket(context->server_fd, filler,
            sizeof(filler)) != 0) {
        return -1;
    }
    if (wait_write_deadline_socket_writable(context->server_fd,
            context->client_fd, drain,
            sizeof(drain), &descriptor) != 0) {
        return -1;
    }
    return 0;
}

static int verify_spop_write_deadline(spop_write_deadline_context *context)
{
    uint64_t started;
    uint64_t finished;

    memset(context->payload.data, 0x5a, sizeof(context->payload.data));
    context->payload.len = SPOP_FRAME_MAX - 16U;
    started = monotonic_milliseconds();
    if (started == 0U || send_frame_timeout(context->server_fd,
            SPOP_FRM_ACK, 1U, 1U, &context->payload, 50U) == 0) {
        return -1;
    }
    finished = monotonic_milliseconds();
    if (finished == 0U || finished < started || finished - started > 1000U) {
        return -1;
    }
    if (close(context->server_fd) != 0) {
        context->server_fd = -1;
        return -1;
    }
    context->server_fd = -1;
    if (close(context->client_fd) != 0) {
        context->client_fd = -1;
        return -1;
    }
    context->client_fd = -1;
    context->payload.len = 0U;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, context->followup) != 0 ||
            send_frame_timeout(context->followup[0], SPOP_FRM_ACK, 7U, 9U,
                &context->payload, 100U) != 0 ||
            recv_frame(context->followup[1], &context->frame, 100U) != 0 ||
            context->frame.type != SPOP_FRM_ACK ||
            context->frame.stream_id != 7U || context->frame.frame_id != 9U) {
        return -1;
    }
    return 0;
}

static void cleanup_spop_write_deadline_context(
        const spop_write_deadline_context *context)
{
    if (context->listener_fd >= 0) {
        (void)close(context->listener_fd);
    }
    if (context->server_fd >= 0) {
        (void)close(context->server_fd);
    }
    if (context->client_fd >= 0) {
        (void)close(context->client_fd);
    }
    if (context->followup[0] >= 0) {
        (void)close(context->followup[0]);
    }
    if (context->followup[1] >= 0) {
        (void)close(context->followup[1]);
    }
    (void)alarm(0U);
}

static int run_spop_write_deadline_child(void)
{
    spop_write_deadline_context context = {
        .listener_fd = -1,
        .server_fd = -1,
        .client_fd = -1,
        .followup = {-1, -1}
    };
    int rc = -1;

    if (prepare_spop_write_deadline_child(&context) == 0 &&
            verify_spop_write_deadline(&context) == 0) {
        rc = 0;
    }
    cleanup_spop_write_deadline_context(&context);
    return rc;
}

static int run_spop_write_deadline_self_test(void)
{
    pid_t child = fork();
    int status;

    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        _exit(run_spop_write_deadline_child() == 0 ? 0 : 1);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
        return -1;
    }
    return 0;
}

static int run_spop_peer_close_write_self_test(void)
{
    int sockets[2] = {-1, -1};
    pid_t child;
    int status;
    spop_buffer payload = {0};

    child = fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
                shutdown(sockets[1], SHUT_RD) != 0) {
            _exit(1);
        }
        /* A raw socket write can terminate this child with SIGPIPE. The
         * protocol helper must instead return a per-peer error. */
        if (send_frame_timeout(sockets[0], SPOP_FRM_AGENT_HELLO, 0U, 0U,
                &payload, 100U) == 0) {
            _exit(1);
        }
        close(sockets[0]);
        close(sockets[1]);
        _exit(0);
    }
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
        return -1;
    }
    return 0;
}

static int connect_localhost(unsigned int port) {
    int fd;
    struct sockaddr_in addr;
    struct timeval tv;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int client_expect_frame(int fd, unsigned int type, uint64_t stream_id, uint64_t frame_id) {
    spop_frame frame;
    if (recv_frame(fd, &frame, 3000U) != 0 || frame.type != type ||
        frame.stream_id != stream_id || frame.frame_id != frame_id) {
        return -1;
    }
    return 0;
}

static int client_expect_ack_set_var(int fd, uint64_t stream_id, uint64_t frame_id) {
    spop_frame frame;
    spop_buffer payload;

    if (recv_frame(fd, &frame, 3000U) != 0 || frame.type != SPOP_FRM_ACK ||
            frame.stream_id != stream_id || frame.frame_id != frame_id ||
            frame.payload_len > sizeof(payload.data)) {
        return -1;
    }
    payload.len = frame.payload_len;
    memcpy(payload.data, frame.payload, payload.len);
    return payload_has_set_var_blocked_true(&payload) ? 0 : -1;
}

static int client_expect_malformed_ack(int fd, uint64_t stream_id, uint64_t frame_id)
{
    haproxy_modsecurity_decision decision;
    spop_buffer expected;
    spop_frame frame;

    runtime_init_decision(&decision, 2, "deny", 400,
        "invalid SPOP NOTIFY payload");
    decision.disruptive = 1;
    if (build_decision_ack_payload(&expected, &decision,
            safe_decision_reason_code(&decision, 0, "malformed-notify"), 1, 0) != 0 ||
            recv_frame(fd, &frame, 3000U) != 0 || frame.type != SPOP_FRM_ACK ||
            frame.stream_id != stream_id || frame.frame_id != frame_id ||
            frame.payload_len != expected.len ||
            memcmp(frame.payload, expected.data, expected.len) != 0) {
        return -1;
    }
    return 0;
}

static int run_spop_malformed_notify_socket_self_test(void)
{
    int sockets[2] = {-1, -1};
    int rc;
    unsigned char byte;
    spop_buffer empty;
    spop_buffer notify_payload;
    agent_state production_state;

    empty.len = 0U;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
            send_haproxy_hello(sockets[1], 0) != 0 ||
            send_frame(sockets[1], SPOP_FRM_NOTIFY, 1U, 1U, &empty) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    rc = handle_connection(sockets[0], 0, stderr, 0, 0, 2000U);
    if (rc == 0 || client_expect_frame(sockets[1], SPOP_FRM_AGENT_HELLO, 0, 0) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    close(sockets[0]);
    if (recv(sockets[1], &byte, sizeof(byte), 0) != 0) {
        close(sockets[1]);
        return -1;
    }
    close(sockets[1]);
    sockets[0] = -1;
    sockets[1] = -1;

    memset(&production_state, 0, sizeof(production_state));
    config_init(&production_state.config);
    if (config_set(&production_state.config, "mode", "detect-only") != 0) {
        return -1;
    }
    production_state.engine = (haproxy_modsecurity_engine *)(uintptr_t)1U;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
            send_haproxy_hello(sockets[1], 0) != 0 ||
            send_frame(sockets[1], SPOP_FRM_NOTIFY, 1U, 1U, &empty) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    /* Match the production owner lifecycle even when the decision sink is
     * omitted: mandatory event admission still uses its initialized lock. */
    if (pthread_mutex_init(&production_state.decision_log_lock, NULL) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    production_state.decision_log_lock_initialized = 1;
    rc = handle_connection(sockets[0], &production_state, stderr, 0, 0, 2000U);
    if (pthread_mutex_destroy(&production_state.decision_log_lock) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    production_state.decision_log_lock_initialized = 0;
    if (rc == 0 || client_expect_frame(sockets[1], SPOP_FRM_AGENT_HELLO, 0, 0) != 0 ||
            client_expect_malformed_ack(sockets[1], 1U, 1U) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    close(sockets[0]);
    if (recv(sockets[1], &byte, sizeof(byte), 0) != 0) {
        close(sockets[1]);
        return -1;
    }
    close(sockets[1]);
    sockets[0] = -1;
    sockets[1] = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
            build_notify_request_payload(&notify_payload, "GET", "/", "/",
                "localhost", "block") != 0 ||
            send_haproxy_hello(sockets[1], 0) != 0 ||
            send_frame(sockets[1], SPOP_FRM_NOTIFY, 1U, 1U, &notify_payload) != 0 ||
            send_frame(sockets[1], SPOP_FRM_HAPROXY_DISCONNECT, 0U, 0U, &empty) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    rc = handle_connection(sockets[0], 0, stderr, 0, 0, 2000U);
    if (rc != 0 || client_expect_frame(sockets[1], SPOP_FRM_AGENT_HELLO, 0, 0) != 0 ||
            client_expect_ack_set_var(sockets[1], 1U, 1U) != 0 ||
            client_expect_frame(sockets[1], SPOP_FRM_AGENT_DISCONNECT, 0, 0) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    close(sockets[0]);
    close(sockets[1]);
    return 0;
}

static int run_client_self_test(unsigned int port, FILE *log) {
    int fd;
    int slow_fd;
    uint64_t start_ms;
    uint64_t finish_ms;
    spop_buffer empty;
    spop_buffer notify_payload;

    /* Keep one incomplete HELLO open while a following peer completes a
     * valid health-check. The latter must not wait for the former's two-second
     * frame deadline; this proves per-peer admission instead of one global
     * accept/HELLO loop. */
    slow_fd = connect_localhost(port);
    if (slow_fd < 0 || send(slow_fd, "\0", 1U, MSG_NOSIGNAL) != 1) {
        if (slow_fd >= 0) {
            close(slow_fd);
        }
        return -1;
    }
    start_ms = monotonic_milliseconds();
    fd = connect_localhost(port);
    if (fd < 0) {
        close(slow_fd);
        return -1;
    }
    if (send_haproxy_hello(fd, 1) != 0 ||
        client_expect_frame(fd, SPOP_FRM_AGENT_HELLO, 0, 0) != 0) {
        close(fd);
        close(slow_fd);
        return -1;
    }
    finish_ms = monotonic_milliseconds();
    if (start_ms == 0U || finish_ms == 0U || finish_ms < start_ms ||
            finish_ms - start_ms > 1000U) {
        close(fd);
        close(slow_fd);
        return -1;
    }
    log_line(log, "client healthcheck handshake PASS");
    close(fd);

    fd = connect_localhost(port);
    if (fd < 0) {
        close(slow_fd);
        return -1;
    }
    empty.len = 0;
    if (build_notify_request_payload(&notify_payload, "GET",
            "/haproxy-binding-self-test", "/haproxy-binding-self-test",
            "localhost", "block") != 0) {
        close(fd);
        close(slow_fd);
        return -1;
    }
    if (send_haproxy_hello(fd, 0) != 0 ||
        client_expect_frame(fd, SPOP_FRM_AGENT_HELLO, 0, 0) != 0 ||
        send_frame(fd, SPOP_FRM_NOTIFY, 1, 1, &notify_payload) != 0 ||
        client_expect_ack_set_var(fd, 1, 1) != 0 ||
        send_frame(fd, SPOP_FRM_HAPROXY_DISCONNECT, 0, 0, &empty) != 0 ||
        client_expect_frame(fd, SPOP_FRM_AGENT_DISCONNECT, 0, 0) != 0) {
        close(fd);
        close(slow_fd);
        return -1;
    }
    log_line(log, "client notify set-var ack disconnect PASS");
    close(fd);
    close(slow_fd);
    return 0;
}

static int run_spop_protocol_self_tests(void)
{
    if (self_test_rejects_oversized_endpoint_port() != 0 ||
            self_test_rejects_fin_unset_frame() != 0 ||
            run_spop_owner_queue_self_test() != 0 ||
            run_spop_request_id_validation_self_test() != 0 ||
            run_spop_notify_failure_self_test() != 0 ||
            run_spop_incomplete_request_sample_self_test() != 0 ||
            run_spop_malformed_notify_socket_self_test() != 0 ||
            run_spop_write_deadline_self_test() != 0 ||
            run_spop_peer_close_write_self_test() != 0) {
        return -1;
    }
    return 0;
}

static void close_spop_self_test_child_metadata(spop_self_test_context *context)
{
    int close_rc = 0;

    close_rc |= close_self_test_fd(&context->ready_fd);
    close_rc |= close_self_test_fd(&context->pid_fd);
    close_rc |= close_self_test_fd(&context->port_fd);
    if (close_rc != 0) {
        fprintf(stderr, "SPOP protocol self-test child metadata close failed\n");
        _exit(SPOP_RUNTIME_CLEANUP_FAILURE);
    }
}

static void run_spop_self_test_child(spop_self_test_context *context)
{
    const spop_accept_loop_config accept_config = {
        context->listen_fd, 0, context->log, 3, 0, 0, 2000U, 8U
    };
    int status;

    close_spop_self_test_child_metadata(context);
    status = accept_loop(&accept_config);
    exit(status);
}

static int prepare_spop_self_test(spop_self_test_context *context,
        const char *tmp_root, const char *log_root)
{
    if (mkdir_p(tmp_root) != 0 || mkdir_p(log_root) != 0) {
        fprintf(stderr, "failed to create tmp/log roots\n");
        return -1;
    }
    snprintf(context->log_path, sizeof(context->log_path),
        "%s/spop-diagnostic-runtime.log", log_root);
    snprintf(context->ready_path, sizeof(context->ready_path),
        "%s/spop-diagnostic-runtime.ready", tmp_root);
    snprintf(context->pid_path, sizeof(context->pid_path),
        "%s/spop-diagnostic-runtime.pid", tmp_root);
    snprintf(context->port_path, sizeof(context->port_path),
        "%s/spop-diagnostic-runtime.port", tmp_root);
    context->log = open_private_file(context->log_path, 0);
    if (context->log == 0) {
        fprintf(stderr, "failed to open log: %s\n", context->log_path);
        return -1;
    }
    context->listen_fd = bind_localhost("127.0.0.1", 0, &context->port);
    if (context->listen_fd < 0) {
        fprintf(stderr, "failed to bind SPOP protocol self-test listener\n");
        return -1;
    }
    context->ready_fd = claim_self_test_metadata_file(context->ready_path);
    if (context->ready_fd >= 0) {
        context->owned_metadata |= SELF_TEST_METADATA_READY;
    }
    context->pid_fd = claim_self_test_metadata_file(context->pid_path);
    if (context->pid_fd >= 0) {
        context->owned_metadata |= SELF_TEST_METADATA_PID;
    }
    context->port_fd = claim_self_test_metadata_file(context->port_path);
    if (context->port_fd >= 0) {
        context->owned_metadata |= SELF_TEST_METADATA_PORT;
    }
    if (context->ready_fd < 0 || context->pid_fd < 0 ||
            context->port_fd < 0 ||
            write_unsigned_fd(context->port_fd, context->port) != 0) {
        return -1;
    }
    return 0;
}

static int start_spop_self_test_server(spop_self_test_context *context)
{
    int close_rc = 0;

    context->child = fork();
    if (context->child < 0) {
        context->result = 77;
        return -1;
    }
    context->child_to_reap = context->child;
    if (context->child == 0) {
        run_spop_self_test_child(context);
    }
    if (close(context->listen_fd) != 0) {
        context->listen_fd = -1;
        context->terminate_child = 1;
        fprintf(stderr, "SPOP protocol self-test listener close failed\n");
        context->result = 1;
        return -1;
    }
    context->listen_fd = -1;
    if (write_process_id_fd(context->pid_fd, context->child) != 0 ||
            write_fd_contents(context->ready_fd, "ready\n") != 0) {
        context->terminate_child = 1;
        fprintf(stderr, "SPOP protocol self-test failed\n");
        context->result = 1;
        return -1;
    }
    close_rc |= close_self_test_fd(&context->ready_fd);
    close_rc |= close_self_test_fd(&context->pid_fd);
    close_rc |= close_self_test_fd(&context->port_fd);
    if (close_rc != 0) {
        context->terminate_child = 1;
        fprintf(stderr, "SPOP protocol self-test metadata close failed\n");
        context->result = 1;
        return -1;
    }
    return 0;
}

static int verify_spop_self_test_server(spop_self_test_context *context)
{
    int wait_result;

    if (run_client_self_test(context->port, context->log) != 0) {
        context->terminate_child = 1;
        fprintf(stderr, "SPOP protocol self-test failed\n");
        context->result = 1;
        return -1;
    }
    wait_result = wait_self_test_child_bounded(context->child,
        &context->status, 0);
    if (wait_result == 0 || wait_result == -2) {
        context->child_to_reap = -1;
    }
    if (wait_result != 0) {
        fprintf(stderr, "SPOP protocol self-test child wait failed\n");
        context->result = 1;
        return -1;
    }
    context->child_to_reap = -1;
    if (!WIFEXITED(context->status) || WEXITSTATUS(context->status) != 0) {
        context->result = 1;
        return -1;
    }
    return 0;
}

static int run_self_test(const char *tmp_root, const char *log_root) {
    spop_self_test_context context = {
        .listen_fd = -1,
        .child = -1,
        .ready_fd = -1,
        .pid_fd = -1,
        .port_fd = -1,
        .child_to_reap = -1
    };
    self_test_cleanup_context cleanup_context;

    if (run_spop_protocol_self_tests() != 0) {
        fprintf(stderr, "SPOP protocol self-test failed\n");
        return 1;
    }
    if (prepare_spop_self_test(&context, tmp_root, log_root) != 0) {
        context.result = 77;
        goto cleanup;
    }
    if (start_spop_self_test_server(&context) != 0 ||
            verify_spop_self_test_server(&context) != 0) {
        goto cleanup;
    }
cleanup:
    cleanup_context = (self_test_cleanup_context){
        &context.listen_fd, context.child_to_reap, &context.status,
        context.terminate_child, &context.ready_fd, &context.pid_fd,
        &context.port_fd, context.ready_path, context.pid_path,
        context.port_path, (unsigned int)context.owned_metadata, &context.log
    };
    if (finish_self_test_resources(&cleanup_context) != 0) {
        fprintf(stderr, "SPOP protocol self-test cleanup failed\n");
        return SPOP_RUNTIME_CLEANUP_FAILURE;
    }
    if (context.result != 0) {
        return context.result;
    }
    printf("haproxy_modsecurity_spoa_protocol_self_test: PASS\n");
    printf("scope: SPOP handshake and typed set-var ACK compatibility; production ModSecurity coverage is verified by live HAProxy smoke tests\n");
    printf("log: %s\n", context.log_path);
    printf("port_file: %s\n", context.port_path);
    return 0;
}

static int run_runtime_self_test_command(int argc, char **argv) {
    const char *tmp_root = 0;
    const char *log_root = 0;
    int index = 2;

    while (index < argc) {
        const char *option = argv[index++];
        const char *value = 0;

        if (next_command_value(argc, argv, &index, &value) != 0) {
            print_usage(argv[0]);
            return 2;
        }
        if (strcmp(option, "--tmp-root") == 0) {
            tmp_root = value;
        } else if (strcmp(option, "--log-root") == 0) {
            log_root = value;
        } else {
            print_usage(argv[0]);
            return 2;
        }
    }
    if (tmp_root == 0 || log_root == 0) {
        print_usage(argv[0]);
        return 2;
    }
    return run_self_test(tmp_root, log_root);
}
