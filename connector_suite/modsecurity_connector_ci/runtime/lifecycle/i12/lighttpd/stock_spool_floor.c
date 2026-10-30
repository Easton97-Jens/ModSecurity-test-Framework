/* Test-only existing fstatvfs/fallocate seam at the actual default64MiB floor.
 * This is an injected syscall boundary, not a claim that host storage is full.
 * Product translation unit and directory safety checks are unchanged. */
#define fstatvfs i12_fstatvfs
#define posix_fallocate i12_fallocate
#include "stock_sidecar.c"
#undef fstatvfs
#undef posix_fallocate
#include <assert.h>

static fsblkcnt_t before_blocks;
static fsblkcnt_t after_blocks;
static unsigned int calls;
static unsigned int allocations;

int i12_fstatvfs(int fd, struct statvfs *value) {
    assert(fd >= 0);
    memset(value, 0, sizeof(*value));
    value->f_frsize = 4096;
    value->f_bavail = calls++ % 2 == 0 ? before_blocks : after_blocks;
    return 0;
}

int i12_fallocate(int fd, off_t offset, off_t length) {
    assert(fd >= 0 && offset == 0 && length == 1);
    ++allocations;
    return 0;
}

static sidecar_exchange_state exchange(const sidecar_options *options, sidecar_spool_budget *budget) {
    sidecar_exchange_state state;
    memset(&state, 0, sizeof(state));
    state.dependencies.options = options;
    state.dependencies.spool_budget = budget;
    state.payload.request_spool_fd = -1;
    state.payload.request_headers.content_length = 1;
    state.deadline.at_ms = sidecar_now_ms() + 10000;
    return state;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    assert(SIDECAR_DEFAULT_SPOOL_CAPACITY == 268435456);
    assert(SIDECAR_DEFAULT_SPOOL_FREE_RESERVE == 67108864);
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(directory >= 0);
    sidecar_options options = {.spool_directory_fd = directory};
    sidecar_spool_budget budget = {.lock = PTHREAD_MUTEX_INITIALIZER,
        .capacity = SIDECAR_DEFAULT_SPOOL_CAPACITY,
        .free_reserve = SIDECAR_DEFAULT_SPOOL_FREE_RESERVE};
    sidecar_exchange_state state = exchange(&options, &budget);
    before_blocks = 16384; after_blocks = 16384; calls = 0;
    assert(!sidecar_admit_request_spool(&state));
    assert(allocations == 0 && state.failure_status == 503 && budget.reserved == 0);
    /* Rounded reservation4096 plus remaining floor64MiB is admitted. */
    before_blocks = 16385; after_blocks = 16384; calls = 0;
    state = exchange(&options, &budget);
    assert(sidecar_admit_request_spool(&state));
    assert(allocations == 1 && budget.reserved == 4096);
    int admitted = state.payload.request_spool_fd;
    sidecar_release_request_spool(&state);
    assert(budget.reserved == 0 && fcntl(admitted, F_GETFD) == -1 && errno == EBADF);
    /* A post-allocation floor loss releases both descriptor and budget. */
    before_blocks = 16385; after_blocks = 16383; calls = 0;
    state = exchange(&options, &budget);
    assert(!sidecar_admit_request_spool(&state));
    assert(allocations == 2 && budget.reserved == 0 && state.payload.request_spool_fd == -1);
    before_blocks = 16385; after_blocks = 16384; calls = 0;
    state = exchange(&options, &budget);
    assert(sidecar_admit_request_spool(&state));
    sidecar_release_request_spool(&state);
    assert(budget.reserved == 0);
    assert(close(directory) == 0);
    assert(pthread_mutex_destroy(&budget.lock) == 0);
    puts("{\"layer\":\"injected-existing-syscall-seam\",\"default_capacity\":268435456,\"default_reserve\":67108864,\"before_floor_reject\":true,\"exact_floor_accept\":true,\"after_floor_reject_cleanup\":true,\"readmit\":true}");
    return 0;
}
