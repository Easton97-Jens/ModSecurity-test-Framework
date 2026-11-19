/* Exercise Traefik worker-slot ownership with real detached worker threads. */
/* Test assertions may carry required side effects; keep assert() active
 * even when a build defines NDEBUG. */
#undef NDEBUG
#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/* TEST_REQUIRE() always evaluates its argument (unlike assert() under
 * NDEBUG), so fixture I/O, resource release and the operation under test
 * still run and are checked. */
#ifndef TEST_REQUIRE
#define TEST_REQUIRE(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "%s:%d: requirement failed: %s\n", \
        __FILE__, __LINE__, #condition); \
    abort(); } } while (0)
#endif
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int test_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
    void *(*start)(void *), void *argument);
static int test_close(int socket_fd);

#define pthread_create test_pthread_create
#define close test_close
#define main traefik_engine_service_program_main
#include "connectors/traefik/src/traefik_engine_service.c"
#undef main
#undef close
#undef pthread_create

static int force_pthread_create_failure;
static pthread_mutex_t race_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t race_condition = PTHREAD_COND_INITIALIZER;
static traefik_engine_service *race_service;
static int race_target_fd = -1;
static int race_enabled;
static int race_close_ready;
static int race_shutdown_entered;
static int race_replacement[2] = {-1, -1};

static void sleep_milliseconds(long milliseconds)
{
    struct timespec delay = {
        .tv_sec = milliseconds / 1000L,
        .tv_nsec = (milliseconds % 1000L) * 1000000L
    };

    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        /* Retry only the unslept interval after an interrupt. */
    }
}

static void wait_for_worker_count(traefik_engine_service *service,
    size_t expected)
{
    for (size_t attempt = 0U; attempt < 300U; ++attempt) {
        size_t count;

        TEST_REQUIRE(pthread_mutex_lock(&service->worker_lock) == 0);
        count = service->worker_count;
        TEST_REQUIRE(pthread_mutex_unlock(&service->worker_lock) == 0);
        if (count == expected) {
            return;
        }
        sleep_milliseconds(10L);
    }
    assert(0 && "worker count did not reach the expected value");
}

static size_t worker_count(traefik_engine_service *service)
{
    size_t count;

    TEST_REQUIRE(pthread_mutex_lock(&service->worker_lock) == 0);
    count = service->worker_count;
    TEST_REQUIRE(pthread_mutex_unlock(&service->worker_lock) == 0);
    return count;
}

static void init_service(traefik_engine_service *service, size_t max_workers)
{
    memset(service, 0, sizeof(*service));
    service->max_workers = max_workers;
    service->worker_slots = calloc(max_workers, sizeof(*service->worker_slots));
    assert(service->worker_slots != NULL);
    for (size_t index = 0U; index < max_workers; ++index) {
        service->worker_slots[index].socket_fd = -1;
    }
    TEST_REQUIRE(pthread_mutex_init(&service->worker_lock, NULL) == 0);
    TEST_REQUIRE(pthread_cond_init(&service->workers_idle, NULL) == 0);
}

static void destroy_service(traefik_engine_service *service)
{
    assert(service->worker_count == 0U);
    free(service->worker_slots);
    TEST_REQUIRE(pthread_cond_destroy(&service->workers_idle) == 0);
    TEST_REQUIRE(pthread_mutex_destroy(&service->worker_lock) == 0);
}

static void shutdown_workers(traefik_engine_service *service)
{
    TEST_REQUIRE(pthread_mutex_lock(&service->worker_lock) == 0);
    traefik_engine_shutdown_active_workers_locked(service);
    TEST_REQUIRE(pthread_mutex_unlock(&service->worker_lock) == 0);
}

static int test_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
    void *(*start)(void *), void *argument)
{
    if (force_pthread_create_failure) {
        force_pthread_create_failure = 0;
        return EAGAIN;
    }
    return pthread_create(thread, attributes, start, argument);
}

static int test_close(int socket_fd)
{
    int result;

    if (!race_enabled || socket_fd != race_target_fd) {
        return close(socket_fd);
    }
    result = close(socket_fd);
    assert(result == 0);
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, race_replacement) == 0);
    if (race_replacement[0] != race_target_fd) {
        TEST_REQUIRE(dup2(race_replacement[0], race_target_fd) == race_target_fd);
        TEST_REQUIRE(close(race_replacement[0]) == 0);
        race_replacement[0] = race_target_fd;
    }
    TEST_REQUIRE(pthread_mutex_lock(&race_lock) == 0);
    race_close_ready = 1;
    TEST_REQUIRE(pthread_cond_broadcast(&race_condition) == 0);
    while (!race_shutdown_entered) {
        struct timespec deadline;

        TEST_REQUIRE(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
        deadline.tv_nsec += 200000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            ++deadline.tv_sec;
            deadline.tv_nsec -= 1000000000L;
        }
        if (pthread_cond_timedwait(&race_condition, &race_lock, &deadline) == ETIMEDOUT) {
            break;
        }
    }
    TEST_REQUIRE(pthread_mutex_unlock(&race_lock) == 0);
    return result;
}

static void *race_shutdown_worker(void *argument)
{
    traefik_engine_service *service = argument;

    TEST_REQUIRE(pthread_mutex_lock(&race_lock) == 0);
    while (!race_close_ready) {
        TEST_REQUIRE(pthread_cond_wait(&race_condition, &race_lock) == 0);
    }
    TEST_REQUIRE(pthread_mutex_unlock(&race_lock) == 0);
    TEST_REQUIRE(pthread_mutex_lock(&service->worker_lock) == 0);
    TEST_REQUIRE(pthread_mutex_lock(&race_lock) == 0);
    race_shutdown_entered = 1;
    TEST_REQUIRE(pthread_cond_broadcast(&race_condition) == 0);
    TEST_REQUIRE(pthread_mutex_unlock(&race_lock) == 0);
    traefik_engine_shutdown_active_workers_locked(service);
    TEST_REQUIRE(pthread_mutex_unlock(&service->worker_lock) == 0);
    return NULL;
}

static void test_worker_cap_reuse_and_pthread_rollback(void)
{
    traefik_engine_service service;
    int first[2];
    int second[2];
    int third[2];
    int failed_start[2];
    int fourth[2];

    init_service(&service, 2U);
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, first) == 0);
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, second) == 0);
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, third) == 0);
    TEST_REQUIRE(traefik_engine_start_worker(&service, first[0]) ==
        TRAEFIK_ENGINE_WORKER_STARTED);
    TEST_REQUIRE(traefik_engine_start_worker(&service, second[0]) ==
        TRAEFIK_ENGINE_WORKER_STARTED);
    wait_for_worker_count(&service, 2U);
    TEST_REQUIRE(traefik_engine_start_worker(&service, third[0]) ==
        TRAEFIK_ENGINE_WORKER_CAPACITY);
    assert(worker_count(&service) == 2U);
    TEST_REQUIRE(close(third[0]) == 0);
    TEST_REQUIRE(close(third[1]) == 0);

    /* A deliberately slow/non-reading peer occupies one bounded worker only. */
    TEST_REQUIRE(close(first[1]) == 0);
    wait_for_worker_count(&service, 1U);
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, failed_start) == 0);
    force_pthread_create_failure = 1;
    TEST_REQUIRE(traefik_engine_start_worker(&service, failed_start[0]) ==
        TRAEFIK_ENGINE_WORKER_ERROR);
    assert(worker_count(&service) == 1U);
    TEST_REQUIRE(close(failed_start[0]) == 0);
    TEST_REQUIRE(close(failed_start[1]) == 0);

    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fourth) == 0);
    TEST_REQUIRE(traefik_engine_start_worker(&service, fourth[0]) ==
        TRAEFIK_ENGINE_WORKER_STARTED);
    wait_for_worker_count(&service, 2U);
    shutdown_workers(&service);
    TEST_REQUIRE(close(second[1]) == 0);
    TEST_REQUIRE(close(fourth[1]) == 0);
    wait_for_worker_count(&service, 0U);
    destroy_service(&service);
}

static void test_cli_max_workers_boundaries(void)
{
    traefik_engine_cli_options options;
    char *valid[] = {
        "traefik-engine-service", "--serve", "--config", "engine.conf",
        "--socket", "engine.sock", "--max-workers", "2"
    };
    char *missing_value[] = {
        "traefik-engine-service", "--serve", "--config", "engine.conf",
        "--socket", "engine.sock", "--max-workers"
    };
    char *zero_workers[] = {
        "traefik-engine-service", "--serve", "--config", "engine.conf",
        "--socket", "engine.sock", "--max-workers", "0"
    };
    char *overflow_workers[] = {
        "traefik-engine-service", "--serve", "--config", "engine.conf",
        "--socket", "engine.sock", "--max-workers", "257"
    };

    assert(traefik_engine_parse_cli(8, valid, &options) == 1);
    assert(options.max_workers == 2U);
    assert(traefik_engine_parse_cli(7, missing_value, &options) == 0);
    assert(traefik_engine_parse_cli(8, zero_workers, &options) == 0);
    assert(traefik_engine_parse_cli(8, overflow_workers, &options) == 0);
}

static void test_fd_reuse_never_reaches_shutdown(void)
{
    traefik_engine_service service;
    pthread_t shutdown_thread;
    int original[2];
    unsigned char byte = 0x5aU;

    init_service(&service, 1U);
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, original) == 0);
    race_service = &service;
    race_target_fd = original[0];
    race_enabled = 1;
    race_close_ready = 0;
    race_shutdown_entered = 0;
    race_replacement[0] = -1;
    race_replacement[1] = -1;
    TEST_REQUIRE(traefik_engine_start_worker(&service, original[0]) ==
        TRAEFIK_ENGINE_WORKER_STARTED);
    TEST_REQUIRE(pthread_create(&shutdown_thread, NULL, race_shutdown_worker, &service) == 0);
    TEST_REQUIRE(close(original[1]) == 0);
    wait_for_worker_count(&service, 0U);
    TEST_REQUIRE(pthread_join(shutdown_thread, NULL) == 0);
    assert(race_shutdown_entered == 1);
    assert(race_replacement[0] == race_target_fd && race_replacement[1] >= 0);
    TEST_REQUIRE(send(race_replacement[1], &byte, sizeof(byte), MSG_NOSIGNAL) ==
        (ssize_t)sizeof(byte));
    TEST_REQUIRE(close(race_replacement[0]) == 0);
    TEST_REQUIRE(close(race_replacement[1]) == 0);
    race_enabled = 0;
    race_target_fd = -1;
    race_service = NULL;
    destroy_service(&service);
}

int main(void)
{
    test_cli_max_workers_boundaries();
    test_worker_cap_reuse_and_pthread_rollback();
    test_fd_reuse_never_reaches_shutdown();
    return 0;
}
