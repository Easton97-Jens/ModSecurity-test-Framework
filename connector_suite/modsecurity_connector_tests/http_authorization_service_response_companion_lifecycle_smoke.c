/*
 * Dynamic lifecycle regression for an authorization service that hands a
 * live transaction to a response companion. The production implementation is
 * included to exercise its private ownership state machine without adding
 * test-only hooks; the existing detached-worker fixture supplies a bounded
 * fake Common runtime and HTTP mapper.
 */
#define main detached_worker_smoke_main
#include "http_authorization_service_detached_worker_smoke.c"
#undef main

#include <assert.h>
#include <sys/wait.h>

#include "common/runtime/http_authorization_service.c"

static pthread_mutex_t companion_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t companion_changed = PTHREAD_COND_INITIALIZER;
static msconnector_runtime_transaction *companion_transaction;
static int companion_handoff_calls;
static int companion_shutdown_calls;
static int companion_shutdown_entered;
static int companion_shutdown_permitted;
static int companion_shutdown_should_fail;
static int companion_transaction_finished;

static int runtime_destroy_count(void)
{
    int result = -1;

    if (pthread_mutex_lock(&test_lock) == 0) {
        result = runtime_destroyed;
        (void)pthread_mutex_unlock(&test_lock);
    }
    return result;
}

static void reset_fake_runtime(void)
{
    assert(pthread_mutex_lock(&test_lock) == 0);
    authorization_stop = 0;
    memset(&fake_runtime, 0, sizeof(fake_runtime));
    runtime_entered = 0;
    runtime_release = 1;
    runtime_destroyed = 0;
    assert(pthread_cond_broadcast(&test_changed) == 0);
    assert(pthread_mutex_unlock(&test_lock) == 0);
}

static void reset_companion(int should_fail)
{
    assert(pthread_mutex_lock(&companion_lock) == 0);
    assert(companion_transaction == NULL);
    companion_handoff_calls = 0;
    companion_shutdown_calls = 0;
    companion_shutdown_entered = 0;
    companion_shutdown_permitted = 0;
    companion_shutdown_should_fail = should_fail;
    companion_transaction_finished = 0;
    assert(pthread_mutex_unlock(&companion_lock) == 0);
}

static int wait_for_companion_shutdown(void)
{
    struct timespec deadline;
    int result = 0;

    assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += TEST_WAIT_SECONDS;
    assert(pthread_mutex_lock(&companion_lock) == 0);
    while (!companion_shutdown_entered && result == 0) {
        result = pthread_cond_timedwait(&companion_changed, &companion_lock,
            &deadline);
    }
    result = companion_shutdown_entered;
    assert(pthread_mutex_unlock(&companion_lock) == 0);
    return result;
}

static int companion_has_retained_transaction(void)
{
    int result;

    assert(pthread_mutex_lock(&companion_lock) == 0);
    result = companion_transaction != NULL;
    assert(pthread_mutex_unlock(&companion_lock) == 0);
    return result;
}

static void permit_companion_shutdown(void)
{
    assert(pthread_mutex_lock(&companion_lock) == 0);
    companion_shutdown_permitted = 1;
    assert(pthread_cond_broadcast(&companion_changed) == 0);
    assert(pthread_mutex_unlock(&companion_lock) == 0);
}

static int companion_handoff(
    const msconnector_runtime *runtime,
    msconnector_runtime_transaction *transaction,
    void *userdata,
    char response_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE],
    msconnector_error *error)
{
    (void)userdata;
    if (runtime != &fake_runtime || transaction == NULL || response_handle == NULL) {
        return 0;
    }
    assert(pthread_mutex_lock(&companion_lock) == 0);
    if (companion_transaction != NULL) {
        assert(pthread_mutex_unlock(&companion_lock) == 0);
        return 0;
    }
    companion_transaction = transaction;
    ++companion_handoff_calls;
    assert(pthread_cond_broadcast(&companion_changed) == 0);
    assert(pthread_mutex_unlock(&companion_lock) == 0);
    (void)snprintf(response_handle,
        MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE, "%s",
        "companion-fixture-handle");
    if (error != NULL) {
        msconnector_error_init(error);
    }
    return 1;
}

static int companion_shutdown(void *userdata, msconnector_error *error)
{
    msconnector_runtime_transaction *transaction;

    (void)userdata;
    assert(pthread_mutex_lock(&companion_lock) == 0);
    ++companion_shutdown_calls;
    companion_shutdown_entered = 1;
    assert(pthread_cond_broadcast(&companion_changed) == 0);
    while (!companion_shutdown_should_fail && !companion_shutdown_permitted) {
        assert(pthread_cond_wait(&companion_changed, &companion_lock) == 0);
    }
    if (companion_shutdown_should_fail) {
        assert(pthread_mutex_unlock(&companion_lock) == 0);
        if (error != NULL) {
            msconnector_error_init(error);
        }
        return 0;
    }
    transaction = companion_transaction;
    companion_transaction = NULL;
    assert(pthread_mutex_unlock(&companion_lock) == 0);
    if (transaction == NULL || !msconnector_runtime_transaction_finish(transaction,
            error)) {
        return 0;
    }
    msconnector_runtime_transaction_destroy(&transaction);
    assert(pthread_mutex_lock(&companion_lock) == 0);
    companion_transaction_finished = 1;
    assert(pthread_cond_broadcast(&companion_changed) == 0);
    assert(pthread_mutex_unlock(&companion_lock) == 0);
    return 1;
}

static const char *const companion_original_uri_headers[] = {
    "X-Original-Uri"
};

static msconnector_http_authorization_profile companion_fixture_profile(void)
{
    return (msconnector_http_authorization_profile){
        .connector_name = "detached-worker-smoke",
        .integration_mode = "detached-worker-smoke",
        .transaction_profile = &test_transaction_profile,
        .original_uri_headers = companion_original_uri_headers,
        .original_uri_header_count = sizeof(companion_original_uri_headers) /
            sizeof(companion_original_uri_headers[0]),
        .map_request = map_request,
        .map_response = NULL,
    };
}

static authorization_service *new_service(
    const msconnector_http_authorization_profile *service_profile)
{
    authorization_service *service = calloc(1U, sizeof(*service));
    authorization_cli cli = {0};

    cli.connection_timeout_ms = TEST_TIMEOUT_MS;
    cli.max_connections = 2UL;
    if (service == NULL || !authorization_service_init(service, &fake_runtime,
            service_profile, &cli)) {
        free(service);
        return NULL;
    }
    return service;
}

static authorization_worker *install_worker(authorization_service *service)
{
    authorization_worker *worker = calloc(1U, sizeof(*worker));

    if (worker == NULL || service == NULL ||
        pthread_mutex_lock(&service->worker_lock) != 0) {
        free(worker);
        return NULL;
    }
    worker->service = service;
    worker->socket_fd = -1;
    worker->next = service->workers;
    service->workers = worker;
    ++service->active_workers;
    assert(pthread_mutex_unlock(&service->worker_lock) == 0);
    return worker;
}

typedef struct companion_server_args {
    char listen_spec[64];
    int result;
    const msconnector_http_authorization_profile *service_profile;
} companion_server_args;

static void *run_companion_service(void *argument)
{
    companion_server_args *args = argument;
    char *argv[] = {
        "companion-lifecycle-smoke",
        "--serve",
        "--config",
        "ignored.conf",
        "--listen",
        args->listen_spec,
        "--max-requests",
        "1",
        "--connection-timeout-ms",
        "25",
        NULL,
    };

    args->result = msconnector_http_authorization_service_main(10, argv,
        args->service_profile);
    return NULL;
}

static int start_companion_service(
    const msconnector_http_authorization_profile *service_profile,
    companion_server_args *args,
    pthread_t *server,
    int *client_fd,
    int *server_started)
{
    static const char request[] = "GET /ok HTTP/1.1\r\nHost: smoke.test\r\n"
        "Connection: keep-alive\r\n\r\n";
    unsigned short port = 0U;

    if (args == NULL || server == NULL || client_fd == NULL ||
        server_started == NULL ||
        !reserve_loopback_port(&port) ||
        snprintf(args->listen_spec, sizeof(args->listen_spec), "127.0.0.1:%u",
            (unsigned int)port) < 0) {
        return 0;
    }
    *server_started = 0;
    args->result = -1;
    args->service_profile = service_profile;
    if (pthread_create(server, NULL, run_companion_service, args) != 0) {
        return 0;
    }
    *server_started = 1;
    *client_fd = connect_loopback(port);
    if (*client_fd < 0 ||
        send(*client_fd, request, sizeof(request) - 1U, MSG_NOSIGNAL) !=
            (ssize_t)(sizeof(request) - 1U) ||
        !wait_for_flag(&runtime_entered) || !runtime_setup_was_configured()) {
        return 0;
    }
    return 1;
}

static int run_successful_companion_lifecycle(void)
{
    msconnector_http_authorization_profile companion_profile =
        companion_fixture_profile();
    companion_server_args args = {{0}, -1, NULL};
    pthread_t server;
    int client_fd = -1;
    int server_started = 0;
    int result = 0;

    companion_profile.handoff_response_companion = companion_handoff;
    companion_profile.shutdown_response_companion = companion_shutdown;
    reset_fake_runtime();
    reset_companion(0);
    if (!start_companion_service(&companion_profile, &args, &server, &client_fd,
            &server_started)) {
        goto done;
    }
    server_started = 1;
    if (!wait_for_companion_shutdown() || !companion_has_retained_transaction() ||
        runtime_destroy_count() != 0) {
        goto done;
    }
    /* The request worker has drained before the owner invokes this callback,
     * but Common runtime must remain live until the retained transaction is
     * actually quiesced by the companion. */
    permit_companion_shutdown();
    if (pthread_join(server, NULL) != 0) {
        server_started = 0;
        goto done;
    }
    server_started = 0;
    assert(pthread_mutex_lock(&companion_lock) == 0);
    result = args.result == 0 && companion_handoff_calls == 1 &&
        companion_shutdown_calls == 1 && companion_transaction == NULL &&
        companion_transaction_finished == 1;
    assert(pthread_mutex_unlock(&companion_lock) == 0);
    result = result && runtime_destroy_count() == 1;

done:
    authorization_stop = 1;
    permit_companion_shutdown();
    if (client_fd >= 0) {
        (void)close(client_fd);
    }
    if (server_started) {
        (void)pthread_join(server, NULL);
    }
    authorization_stop = 0;
    return result;
}

static int run_failed_companion_lifecycle_child(void)
{
    msconnector_http_authorization_profile companion_profile =
        companion_fixture_profile();
    companion_server_args args = {{0}, -1, NULL};
    pthread_t server;
    int client_fd = -1;
    int server_started = 0;
    int result;

    companion_profile.handoff_response_companion = companion_handoff;
    companion_profile.shutdown_response_companion = companion_shutdown;
    reset_fake_runtime();
    reset_companion(1);
    if (!start_companion_service(&companion_profile, &args, &server, &client_fd,
            &server_started) || !wait_for_companion_shutdown() ||
        pthread_join(server, NULL) != 0) {
        authorization_stop = 1;
        permit_companion_shutdown();
        if (client_fd >= 0) {
            (void)close(client_fd);
        }
        if (server_started) {
            (void)pthread_join(server, NULL);
        }
        return 0;
    }
    server_started = 0;
    if (client_fd >= 0) {
        (void)close(client_fd);
    }
    assert(pthread_mutex_lock(&companion_lock) == 0);
    result = args.result == 1 && companion_handoff_calls == 1 &&
        companion_shutdown_calls == 1 && companion_transaction != NULL &&
        companion_transaction_finished == 0;
    assert(pthread_mutex_unlock(&companion_lock) == 0);
    /* Intentionally leave this service and transaction quarantined. A release
     * after failed companion shutdown would make this scenario fail. */
    return result && runtime_destroy_count() == 0;
}

static int test_failed_companion_quarantines_service(void)
{
    pid_t child = fork();
    int wait_status = 0;

    if (child < 0) {
        return 0;
    }
    if (child == 0) {
        _exit(run_failed_companion_lifecycle_child() ? 0 : 1);
    }
    return waitpid(child, &wait_status, 0) == child &&
        WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
}

typedef struct release_race {
    authorization_service *service;
    authorization_worker *worker;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int ready;
    int go;
    int owner_result;
} release_race;

static void race_wait_for_start(release_race *race)
{
    assert(pthread_mutex_lock(&race->lock) == 0);
    ++race->ready;
    assert(pthread_cond_broadcast(&race->changed) == 0);
    while (!race->go) {
        assert(pthread_cond_wait(&race->changed, &race->lock) == 0);
    }
    assert(pthread_mutex_unlock(&race->lock) == 0);
}

static void *race_owner_release(void *argument)
{
    release_race *race = argument;

    race_wait_for_start(race);
    race->owner_result = authorization_mark_response_companion_quiesced(
        race->service);
    if (race->owner_result > 0) {
        authorization_service_release(race->service);
    }
    return NULL;
}

static void *race_worker_release(void *argument)
{
    release_race *race = argument;

    race_wait_for_start(race);
    authorization_worker_release(race->worker);
    return NULL;
}

static int test_concurrent_owner_worker_release(void)
{
    msconnector_http_authorization_profile companion_profile =
        companion_fixture_profile();
    authorization_service *service;
    authorization_worker *worker;
    release_race race = {
        .service = NULL,
        .worker = NULL,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
        .ready = 0,
        .go = 0,
        .owner_result = -1,
    };
    pthread_t owner;
    pthread_t worker_thread;
    int result;

    reset_fake_runtime();
    companion_profile.handoff_response_companion = companion_handoff;
    companion_profile.shutdown_response_companion = companion_shutdown;
    service = new_service(&companion_profile);
    worker = install_worker(service);
    if (service == NULL || worker == NULL ||
        pthread_mutex_lock(&service->worker_lock) != 0) {
        return 0;
    }
    service->deferred_cleanup = 1;
    assert(pthread_mutex_unlock(&service->worker_lock) == 0);
    race.service = service;
    race.worker = worker;
    if (pthread_create(&owner, NULL, race_owner_release, &race) != 0 ||
        pthread_create(&worker_thread, NULL, race_worker_release, &race) != 0) {
        return 0;
    }
    assert(pthread_mutex_lock(&race.lock) == 0);
    while (race.ready != 2) {
        assert(pthread_cond_wait(&race.changed, &race.lock) == 0);
    }
    race.go = 1;
    assert(pthread_cond_broadcast(&race.changed) == 0);
    assert(pthread_mutex_unlock(&race.lock) == 0);
    if (pthread_join(owner, NULL) != 0 || pthread_join(worker_thread, NULL) != 0) {
        return 0;
    }
    result = (race.owner_result == 0 || race.owner_result == 1) &&
        runtime_destroy_count() == 1;
    assert(pthread_cond_destroy(&race.changed) == 0);
    assert(pthread_mutex_destroy(&race.lock) == 0);
    return result;
}

static int test_no_companion_deferred_release(void)
{
    msconnector_http_authorization_profile no_companion_profile =
        companion_fixture_profile();
    authorization_service *service;
    authorization_worker *worker;

    reset_fake_runtime();
    service = new_service(&no_companion_profile);
    worker = install_worker(service);
    if (service == NULL || worker == NULL ||
        authorization_defer_uninterruptible_worker(service,
            &no_companion_profile) != 1 ||
        runtime_destroy_count() != 0) {
        return 0;
    }
    authorization_worker_release(worker);
    return runtime_destroy_count() == 1;
}

int main(void)
{
    if (!run_successful_companion_lifecycle() ||
        !test_failed_companion_quarantines_service() ||
        !test_concurrent_owner_worker_release() ||
        !test_no_companion_deferred_release()) {
        (void)fprintf(stderr, "response-companion lifecycle contract failed\n");
        return 1;
    }
    (void)puts("http authorization response-companion lifecycle smoke: passed");
    return 0;
}
