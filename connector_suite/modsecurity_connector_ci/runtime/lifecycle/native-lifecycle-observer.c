/* Test-only GNU ld --wrap observer. Never link into release artifacts.
 * A supervisor must retain and validate admission, paired calls and final
 * receipts for every participating PID. Absence is unknown, never zero.
 * invalid=false is measurement health, not lifecycle qualification: nonzero
 * final live_mappings means cleanup remains incomplete/unqualified.
 * Native MIME selection and host EOS are deliberately not inferred here. */
#define _GNU_SOURCE
#include "msconnector/transaction_contract.h"
#include "native-lifecycle-observer.h"
#include "common/runtime/msconnector_runtime.h"
#include <modsecurity/transaction.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAP_CAPACITY 256U
#define BYTE_BUDGET (16U * 1024U * 1024U)
struct mapping {
    const void *key;
    int native;
    char id[MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH];
    char canonical[64];
    char input_id[MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH];
    const char *id_origin;
    uint64_t allocation_scope_call;
    int allocation_join_verified;
    int allocation_kind;
    const void *joined_common;
    const void *joined_native;
    const void *joined_runtime;
    const void *joined_entry;
};
/* Associations come from observed nested allocation calls, never from equal
 * looking IDs or the layout of an opaque runtime transaction. */
struct allocation_scope {
    uint64_t call;
    const void *common;
    const void *native;
    unsigned int common_count;
    unsigned int native_count;
    int kind;
    struct allocation_scope *parent;
};
static _Thread_local struct allocation_scope *active_allocation;
#define HOST_SCOPE_CAPACITY 8U
static _Thread_local struct allocation_scope host_scopes[HOST_SCOPE_CAPACITY];
static _Thread_local unsigned int host_scope_depth;
/* Undefined weak symbol keeps generic/fake-native builds fully opaque. */
extern int msconnector_lifecycle_sdk_transaction_id(void *, const void *, char *, size_t)
    __attribute__((weak));
struct budget { atomic_uint bytes; atomic_int invalid; };
struct observed_finalization {
    int known;
    int handle_cleared;
    int finished;
    int cleanup_started;
    int cleanup_complete;
    int status;
    int association_retired;
};
struct observed_subject {
    const void *key;
    int native;
    int phase;
    int input_known;
    size_t input_size;
    int data_present;
    const char *runtime_eos_handoff;
    int response_status_known;
    int response_status;
    int intervention_known;
    int intervention_status;
    int intervention_disruptive;
    int framing_known;
    size_t content_length;
    size_t buffered_body_size;
    size_t remaining;
    struct observed_finalization finalize;
};
static struct mapping mappings[MAP_CAPACITY];
static struct budget *budget;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int output_fd = -1;
static uint64_t sequence;
static unsigned int pending;
static dev_t admitted_device;
static ino_t admitted_inode;
static char run[400] = "null";
static char profile[400] = "null";
static char fixture[800] = "null";

static struct observed_subject subject(const void *key, int native, int phase) {
    const struct observed_subject value = {.key = key, .native = native, .phase = phase};
    return value;
}

static void invalid(void) {
    if (budget != NULL) atomic_store(&budget->invalid, 1);
}

/* Bounded JSON strings; control characters, quotes and slashes are escaped.
 * IDs and trusted fixture metadata are the only strings written. */
static int quoted(char *out, size_t capacity, const char *value, size_t limit) {
    size_t used = 0U;
    if (value == NULL) { (void)snprintf(out, capacity, "null"); return 0; }
    size_t length = strnlen(value, limit + 1U);
    if (length > limit || capacity < 3U) return -1;
    out[used++] = '"';
    for (size_t i = 0U; i < length; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (c < 32U || c >= 127U || c == '"' || c == '\\') {
            if (capacity - used < 7U) return -1;
            (void)snprintf(out + used, capacity - used, "\\u%04x", (unsigned int)c);
            used += 6U;
        } else {
            if (capacity - used < 2U) return -1;
            out[used++] = (char)c;
        }
    }
    if (capacity - used < 2U) return -1;
    out[used++] = '"'; out[used] = '\0';
    return 0;
}

static struct mapping *lookup(const void *key, int native) {
    if (key == NULL) return NULL;
    for (size_t i = 0U; i < MAP_CAPACITY; ++i)
        if (mappings[i].key == key && mappings[i].native == native) return &mappings[i];
    return NULL;
}

static void remember(const void *key, int native, const char *id, const char *canonical) {
    if (key == NULL) return;
    if (lookup(key, native) != NULL) { invalid(); return; }
    for (size_t i = 0U; i < MAP_CAPACITY; ++i) {
        if (mappings[i].key != NULL) continue;
        mappings[i].key = key; mappings[i].native = native;
        if (active_allocation != NULL) {
            mappings[i].allocation_scope_call = active_allocation->call;
            mappings[i].allocation_kind = active_allocation->kind;
        }
        mappings[i].id_origin = "common_public_contract";
        if (native != 0) {
            mappings[i].id_origin = "unknown";
            if (id != NULL) mappings[i].id_origin = "caller_argument";
        }
        if (id != NULL && strnlen(id, sizeof(mappings[i].id)) < sizeof(mappings[i].id))
            (void)snprintf(mappings[i].id, sizeof(mappings[i].id), "%s", id);
        if (canonical != NULL && strnlen(canonical, sizeof(mappings[i].canonical)) < sizeof(mappings[i].canonical))
            (void)snprintf(mappings[i].canonical, sizeof(mappings[i].canonical), "%s", canonical);
        return;
    }
    invalid();
}

static void forget(const void *key, int native) {
    struct mapping *entry = lookup(key, native);
    if (entry != NULL) memset(entry, 0, sizeof(*entry));
}

struct serialized_identity {
    char id[6U * MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH + 3U];
    char canonical[400];
    char input_id[6U * MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH + 3U];
};

static void serialize_identity(const struct mapping *entry, struct serialized_identity *identity) {
    if (entry == NULL) return;
    if (entry->id[0] != '\0' &&
        quoted(identity->id, sizeof(identity->id), entry->id, sizeof(entry->id) - 1U) != 0) invalid();
    if (entry->canonical[0] != '\0' &&
        quoted(identity->canonical, sizeof(identity->canonical), entry->canonical, 63U) != 0) invalid();
    if (entry->input_id[0] != '\0' &&
        quoted(identity->input_id, sizeof(identity->input_id), entry->input_id, sizeof(entry->input_id) - 1U) != 0) invalid();
}

static int admitted_descriptor_still_valid(void) {
    struct stat descriptor_status;
    int descriptor_flags = fcntl(output_fd, F_GETFL);
    if (fstat(output_fd, &descriptor_status) != 0 ||
        descriptor_status.st_dev != admitted_device || descriptor_status.st_ino != admitted_inode ||
        descriptor_flags < 0 || (descriptor_flags & O_APPEND) == 0) {
        invalid();
        return 0;
    }
    return 1;
}

static const char *serialize_allocation(const struct mapping *entry, char *allocation, size_t capacity) {
    uint64_t allocation_call = entry == NULL ? 0U : entry->allocation_scope_call;
    if (allocation_call == 0U && active_allocation != NULL)
        allocation_call = active_allocation->call;
    if (allocation_call != 0U)
        (void)snprintf(allocation, capacity, "%" PRIu64, allocation_call);
    int allocation_kind = entry == NULL ? 0 : entry->allocation_kind;
    if (allocation_kind == 0 && active_allocation != NULL) allocation_kind = active_allocation->kind;
    if (allocation_kind == 2) return "\"runtime\"";
    if (allocation_kind == 3) return "\"host\"";
    return "null";
}

static void serialize_contract_state(const struct mapping *entry,
    const struct observed_subject *observed, char *state, size_t capacity) {
    /* Only an already admitted, successfully initialized Common object is
     * inspected. Native opaque handles and init's uninitialized entry are
     * never dereferenced. Each edge reports its own observed public state. */
    if (entry != NULL && observed->native == 0) {
        const msconnector_transaction_contract *contract = observed->key;
        (void)snprintf(state, capacity,
            "{\"status\":%d,\"response_committed\":%d,\"active_phase\":%d,"
            "\"last_completed_phase\":%d,\"completed_phase_mask\":%u,"
            "\"cleanup_started\":%d,\"cleanup_complete\":%d,"
            "\"completed_at_ms\":%" PRIu64 ",\"cleanup_at_ms\":%" PRIu64 "}",
            (int)contract->status, contract->response_committed, contract->active_phase,
            contract->last_completed_phase, contract->completed_phase_mask,
            contract->cleanup_started, contract->cleanup_complete,
            contract->completed_at_ms, contract->cleanup_at_ms);
    }
}

struct observed_clocks {
    uint64_t monotonic_ns;
    uint64_t wall_ns;
    uint64_t wall_sample_end_ns;
};

static void observe_clocks(struct observed_clocks *clocks) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        clocks->monotonic_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    else invalid();
    if (clock_gettime(CLOCK_REALTIME, &now) == 0)
        clocks->wall_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    else invalid();
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        clocks->wall_sample_end_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    else invalid();
}

struct serialized_subject {
    char eos_handoff[80];
    char response_status[32];
    char intervention_status[32];
    char intervention_disruptive[32];
    char input_size[32];
    const char *input_kind;
    char framing[256];
    char finalize[256];
};

static struct serialized_subject serialize_subject(const struct observed_subject *observed) {
    struct serialized_subject value = {
        .eos_handoff = "null",
        .response_status = "null",
        .intervention_status = "null",
        .intervention_disruptive = "null",
        .input_size = "null",
        .input_kind = "null",
        .framing = "null",
        .finalize = "null",
    };
    struct serialized_subject *serialized = &value;
    if (observed->runtime_eos_handoff != NULL &&
        quoted(serialized->eos_handoff, sizeof(serialized->eos_handoff), observed->runtime_eos_handoff, 40U) != 0) invalid();
    if (observed->response_status_known)
        (void)snprintf(serialized->response_status, sizeof(serialized->response_status), "%d", observed->response_status);
    if (observed->intervention_known) {
        (void)snprintf(serialized->intervention_status, sizeof(serialized->intervention_status), "%d", observed->intervention_status);
        (void)snprintf(serialized->intervention_disruptive, sizeof(serialized->intervention_disruptive), "%d", observed->intervention_disruptive);
    }
    if (observed->input_known) {
        (void)snprintf(serialized->input_size, sizeof(serialized->input_size), "%zu", observed->input_size);
        serialized->input_kind = observed->data_present ? "\"non_null_buffer\"" : "\"null_buffer\"";
    }
    if (observed->framing_known)
        (void)snprintf(serialized->framing, sizeof(serialized->framing),
            "{\"content_length\":%zu,\"buffered_body_size\":%zu,\"remaining\":%zu}",
            observed->content_length, observed->buffered_body_size, observed->remaining);
    if (observed->finalize.known)
        (void)snprintf(serialized->finalize, sizeof(serialized->finalize),
            "{\"handle_cleared\":%d,\"finished\":%d,\"cleanup_started\":%d,"
            "\"cleanup_complete\":%d,\"status\":%d,\"association_retired\":%d}",
            observed->finalize.handle_cleared, observed->finalize.finished,
            observed->finalize.cleanup_started, observed->finalize.cleanup_complete,
            observed->finalize.status, observed->finalize.association_retired);
    return value;
}

/* Caller holds process-local lock. One bounded O_APPEND write per record;
 * a partial/error write permanently invalidates the entire inherited run. */
static void event(const char *function, const char *edge, uint64_t call,
                  const struct observed_subject *observed, const char *result,
                  const char *argument_committed) {
    if (output_fd < 0 || budget == NULL) return;
    if (!admitted_descriptor_still_valid()) return;
    struct serialized_identity identity = {"null", "null", "null"};
    char record[8192];
    const struct mapping *entry = lookup(observed->key, observed->native);
    serialize_identity(entry, &identity);
    char allocation[32] = "null";
    const char *kind = serialize_allocation(entry, allocation, sizeof(allocation));
    char state[512] = "null";
    serialize_contract_state(entry, observed, state, sizeof(state));
    struct observed_clocks clocks = {0};
    observe_clocks(&clocks);
    unsigned int live = 0U;
    for (size_t i = 0U; i < MAP_CAPACITY; ++i) if (mappings[i].key != NULL) ++live;
    struct serialized_subject serialized = serialize_subject(observed);
    int length = snprintf(record, sizeof(record),
        "{\"schema\":\"native-lifecycle-v1\",\"pid\":%ld,\"uid\":%ld,\"gid\":%ld,"
        "\"sequence\":%" PRIu64 ",\"monotonic_ns\":%" PRIu64 ",\"call\":%" PRIu64 ","
        "\"run\":%s,\"profile\":%s,\"case\":%s,\"function\":\"%s\",\"edge\":\"%s\","
        "\"transaction_id\":%s,\"canonical_transaction_id\":%s,\"phase\":%d,\"result\":%s,\"invalid\":%s,"
        "\"transaction_id_origin\":\"%s\",\"input_transaction_id\":%s,"
        "\"argument_committed\":%s,\"contract_state\":%s,"
        "\"input_size\":%s,\"input_kind\":%s,\"argument_eos\":null,"
        "\"pending_calls\":%u,\"live_mappings\":%u,\"native_mime_selection\":null,\"host_eos\":null,"
        "\"allocation_scope_call\":%s,\"allocation_join_verified\":%s,\"runtime_eos_handoff\":%s,"
        "\"argument_response_status\":%s,\"intervention_status\":%s,\"intervention_disruptive\":%s,"
        "\"allocation_scope_kind\":%s,\"wall_ns\":%" PRIu64 ",\"wall_sample_end_monotonic_ns\":%" PRIu64 ",\"host_framing\":%s,\"runtime_finalize_snapshot\":%s}\n",
        (long)getpid(), (long)geteuid(), (long)getegid(), ++sequence, clocks.monotonic_ns, call,
        run, profile, fixture, function, edge, identity.id, identity.canonical, observed->phase, result,
        atomic_load(&budget->invalid) ? "true" : "false",
        entry == NULL ? "unknown" : entry->id_origin, identity.input_id,
        argument_committed == NULL ? "null" : argument_committed, state,
        serialized.input_size, serialized.input_kind, pending, live, allocation,
        entry != NULL && entry->allocation_join_verified ? "true" : "false", serialized.eos_handoff, serialized.response_status,
        serialized.intervention_status, serialized.intervention_disruptive, kind, clocks.wall_ns, clocks.wall_sample_end_ns, serialized.framing, serialized.finalize);
    if (length <= 0 || (size_t)length >= sizeof(record)) { invalid(); return; }
    unsigned int previous = atomic_load(&budget->bytes);
    do {
        if (previous > BYTE_BUDGET || (unsigned int)length > BYTE_BUDGET - previous) { invalid(); return; }
    } while (!atomic_compare_exchange_weak(&budget->bytes, &previous, previous + (unsigned int)length));
    if (write(output_fd, record, (size_t)length) != (ssize_t)length) invalid();
}

static uint64_t enter_subject(const char *name, const struct observed_subject *observed, const char *argument) {
    int saved = errno;
    (void)pthread_mutex_lock(&lock);
    uint64_t call = sequence + 1U;
    ++pending;
    event(name, "enter", call, observed, "null", argument);
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    return call;
}

static uint64_t enter_argument(const char *name, const void *key, int native, int phase, const char *argument) {
    const struct observed_subject observed = subject(key, native, phase);
    return enter_subject(name, &observed, argument);
}

static uint64_t enter(const char *name, const void *key, int native, int phase) {
    return enter_argument(name, key, native, phase, NULL);
}

static void returned_subject(const char *name, uint64_t call, const struct observed_subject *observed,
                     int result, int remove, const char *argument) {
    int saved = errno;
    char number[32];
    if (strcmp(name, "native_cleanup") == 0 || strcmp(name, "runtime_destroy") == 0)
        (void)snprintf(number, sizeof(number), "null");
    else (void)snprintf(number, sizeof(number), "%d", result);
    (void)pthread_mutex_lock(&lock);
    event(name, "return", call, observed, number, argument);
    if (pending == 0U) invalid(); else --pending;
    if (remove) forget(observed->key, observed->native);
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
}

static void returned(const char *name, uint64_t call, const void *key, int native,
                     int phase, int result, int remove) {
    const struct observed_subject observed = subject(key, native, phase);
    returned_subject(name, call, &observed, result, remove, NULL);
}

static void before_fork(void) { (void)pthread_mutex_lock(&lock); }
static void after_fork(void) { (void)pthread_mutex_unlock(&lock); }
static void child_fork(void) {
    /* In-flight calls in other parent threads cannot be completed in child.
     * Their absence is explicit rather than treated as child-owned calls. */
    if (pending != 0U) invalid();
    sequence = 0U; pending = 0U;
    active_allocation = NULL; host_scope_depth = 0U;
    const struct observed_subject observed = subject(NULL, 0, 0);
    event("observer", "fork", 0U, &observed, "null", NULL);
    (void)pthread_mutex_unlock(&lock);
}

__attribute__((constructor)) static void admission(void) {
    int saved = errno;
    const char *value = getenv("MSCONNECTOR_LIFECYCLE_FD");
    char *end = NULL;
    if (value == NULL || *value == '\0') { errno = saved; return; }
    errno = 0;
    long candidate = strtol(value, &end, 10);
    struct stat status;
    if (errno != 0 || end == value || *end != '\0' || candidate < 3L || candidate > 1048576L ||
        fstat((int)candidate, &status) != 0 || !S_ISREG(status.st_mode) ||
        (status.st_mode & 07777U) != 0600U || status.st_nlink != 1U ||
        status.st_uid != geteuid()) goto rejected;
    int flags = fcntl((int)candidate, F_GETFL);
    if (flags < 0 || (flags & O_APPEND) == 0 || (flags & O_ACCMODE) == O_RDONLY) goto rejected;
    budget = mmap(NULL, sizeof(*budget), PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (budget == MAP_FAILED) { budget = NULL; goto rejected; }
    atomic_init(&budget->bytes, 0U); atomic_init(&budget->invalid, 0);
#if ATOMIC_INT_LOCK_FREE != 2
    /* C guarantees equal lock-free properties for corresponding signed and
     * unsigned atomic types. Retain runtime admission when not guaranteed. */
    if (!atomic_is_lock_free(&budget->bytes) || !atomic_is_lock_free(&budget->invalid)) goto rejected;
#endif
    output_fd = (int)candidate;
    admitted_device = status.st_dev; admitted_inode = status.st_ino;
    if (quoted(run, sizeof(run), getenv("MSCONNECTOR_LIFECYCLE_RUN"), 64U) != 0 ||
        quoted(profile, sizeof(profile), getenv("MSCONNECTOR_LIFECYCLE_PROFILE"), 64U) != 0 ||
        quoted(fixture, sizeof(fixture), getenv("MSCONNECTOR_LIFECYCLE_CASE"), 128U) != 0) invalid();
    if (pthread_atfork(before_fork, after_fork, child_fork) != 0) invalid();
    const struct observed_subject observed = subject(NULL, 0, 0);
    event("observer", "admitted", 0U, &observed, "null", NULL);
    errno = saved;
    return;
rejected:
    output_fd = -1;
    static const char rejected_message[] = "native-lifecycle-observer: admission rejected\n";
    (void)write(STDERR_FILENO, rejected_message, sizeof(rejected_message) - 1U);
    errno = saved;
}

int msconnector_lifecycle_observer_snapshot(msconnector_lifecycle_observer_state *state) {
    int saved = errno;
    if (state == NULL || output_fd < 0 || budget == NULL) { errno = saved; return 0; }
    (void)pthread_mutex_lock(&lock);
    const struct observed_subject observed = subject(NULL, 0, 0);
    event("observer", "snapshot", 0U, &observed, "null", NULL);
    state->live_mappings = 0U;
    for (size_t index = 0U; index < MAP_CAPACITY; ++index)
        if (mappings[index].key != NULL) ++state->live_mappings;
    state->pending_calls = pending;
    state->invalid = atomic_load(&budget->invalid);
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    return 1;
}

__attribute__((destructor)) static void final_receipt(void) {
    int saved = errno;
    (void)pthread_mutex_lock(&lock);
    if (pending != 0U) invalid();
    const struct observed_subject observed = subject(NULL, 0, 0);
    event("observer", "final", 0U, &observed, "null", NULL);
    if (budget != NULL && atomic_load(&budget->invalid)) {
        static const char invalid_message[] = "native-lifecycle-observer: evidence invalid\n";
        (void)write(STDERR_FILENO, invalid_message, sizeof(invalid_message) - 1U);
    }
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
}

extern int __real_msconnector_transaction_contract_init(msconnector_transaction_contract *, const msconnector_transaction_profile *, const char *, const char *, const char *, msconnector_transaction_mode, uint64_t);
int __wrap_msconnector_transaction_contract_init(msconnector_transaction_contract *c, const msconnector_transaction_profile *p, const char *id, const char *connector, const char *host, msconnector_transaction_mode mode, uint64_t now) {
    uint64_t call = enter("common_init", NULL, 0, 0);
    int result = __real_msconnector_transaction_contract_init(c, p, id, connector, host, mode, now);
    int saved = errno;
    (void)pthread_mutex_lock(&lock);
    if (result == 0 && c != NULL) {
        remember(c, 0, c->transaction_id, c->canonical_transaction_id);
        if (active_allocation != NULL) {
            active_allocation->common = c;
            ++active_allocation->common_count;
        }
    }
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    returned("common_init", call, c, 0, 0, result, 0);
    return result;
}

#define COMMON_TIME_WRAPPER(suffix, label, remove) \
extern int __real_msconnector_transaction_contract_##suffix(msconnector_transaction_contract *, uint64_t); \
int __wrap_msconnector_transaction_contract_##suffix(msconnector_transaction_contract *c, uint64_t now) { \
    uint64_t call = enter(label, c, 0, 0); \
    int result = __real_msconnector_transaction_contract_##suffix(c, now); \
    returned(label, call, c, 0, 0, result, remove && \
        (result == MSCONNECTOR_TRANSACTION_TRANSITION_OK || \
         result == MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP)); return result; \
}
COMMON_TIME_WRAPPER(finish, "common_finish", 0)
COMMON_TIME_WRAPPER(cleanup, "common_cleanup", 1)

extern int __real_msconnector_transaction_contract_complete_phase(msconnector_transaction_contract *, enum msconnector_phase, uint64_t);
int __wrap_msconnector_transaction_contract_complete_phase(msconnector_transaction_contract *c, enum msconnector_phase phase, uint64_t now) {
    uint64_t call = enter("common_complete_phase", c, 0, (int)phase);
    int result = __real_msconnector_transaction_contract_complete_phase(c, phase, now);
    returned("common_complete_phase", call, c, 0, (int)phase, result, 0); return result;
}
extern int __real_msconnector_transaction_contract_set_response_committed(msconnector_transaction_contract *, int);
int __wrap_msconnector_transaction_contract_set_response_committed(msconnector_transaction_contract *c, int committed) {
    int saved = errno;
    char argument[32];
    (void)snprintf(argument, sizeof(argument), "%d", committed);
    errno = saved;
    uint64_t call = enter_argument("common_set_response_committed", c, 0, 0, argument);
    int result = __real_msconnector_transaction_contract_set_response_committed(c, committed);
    const struct observed_subject observed = subject(c, 0, 0);
    returned_subject("common_set_response_committed", call, &observed, result, 0, argument); return result;
}
extern int __real_msconnector_transaction_contract_record_response_metadata(msconnector_transaction_contract *, int, const char *, size_t, size_t);
int __wrap_msconnector_transaction_contract_record_response_metadata(msconnector_transaction_contract *c, int status, const char *type, size_t count, size_t bytes) {
    uint64_t call = enter("common_record_response_metadata", c, 0, 0);
    int result = __real_msconnector_transaction_contract_record_response_metadata(c, status, type, count, bytes);
    returned("common_record_response_metadata", call, c, 0, 0, result, 0); return result;
}

extern Transaction *__real_msc_new_transaction(ModSecurity *, RulesSet *, void *);
extern __typeof__(msc_new_transaction_with_id) __real_msc_new_transaction_with_id;
static Transaction *constructed(Transaction *transaction, const char *id, uint64_t call, const char *name, ModSecurity *engine) {
    int saved = errno;
    char actual_id[MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH];
    int extracted = 0;
    if (transaction != NULL && &msconnector_lifecycle_sdk_transaction_id != NULL)
        extracted = msconnector_lifecycle_sdk_transaction_id(engine, transaction, actual_id, sizeof(actual_id));
    (void)pthread_mutex_lock(&lock);
    if (extracted < 0) invalid();
    const char *observed_id = id;
    if (extracted == 1) observed_id = actual_id;
    else if (extracted < 0) observed_id = NULL;
    remember(transaction, 1, observed_id, NULL);
    if (transaction != NULL && active_allocation != NULL) {
        active_allocation->native = transaction;
        ++active_allocation->native_count;
    }
    struct mapping *entry = lookup(transaction, 1);
    if (entry != NULL) {
        if (extracted == 1) entry->id_origin = "sdk_public_m_id";
        if (id != NULL && strnlen(id, sizeof(entry->input_id)) < sizeof(entry->input_id))
            (void)snprintf(entry->input_id, sizeof(entry->input_id), "%s", id);
        else if (id != NULL) invalid();
    }
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    returned(name, call, transaction, 1, 0, transaction != NULL, 0);
    return transaction;
}
Transaction *__wrap_msc_new_transaction(ModSecurity *m, RulesSet *r, void *data) {
    uint64_t call = enter("native_new", NULL, 1, 0);
    Transaction *transaction = __real_msc_new_transaction(m, r, data);
    return constructed(transaction, NULL, call, "native_new", m);
}
Transaction *__wrap_msc_new_transaction_with_id(ModSecurity *m, RulesSet *r, msconnector_lifecycle_native_id_argument id, void *data) {
    uint64_t call = enter("native_new_with_id", NULL, 1, 0);
    Transaction *transaction = __real_msc_new_transaction_with_id(m, r, id, data);
    return constructed(transaction, id, call, "native_new_with_id", m);
}
#define NATIVE_WRAPPER(suffix, phase) \
extern int __real_msc_##suffix(Transaction *); \
int __wrap_msc_##suffix(Transaction *transaction) { \
    uint64_t call = enter("native_" #suffix, transaction, 1, phase); \
    int result = __real_msc_##suffix(transaction); \
    returned("native_" #suffix, call, transaction, 1, phase, result, 0); return result; \
}
NATIVE_WRAPPER(process_request_body, 2)
NATIVE_WRAPPER(process_response_body, 4)
NATIVE_WRAPPER(process_logging, 0)

/* Actual native header-phase calls, not Common phase-state projections.
 * Weak declarations preserve legacy observer-only links without these APIs.
 * Protocol/header/URI strings are deliberately never copied to the trace. */
extern int __real_msc_process_request_headers(Transaction *) __attribute__((weak));
int __wrap_msc_process_request_headers(Transaction *transaction) {
    uint64_t call = enter("native_process_request_headers", transaction, 1, 1);
    int result = __real_msc_process_request_headers(transaction);
    returned("native_process_request_headers", call, transaction, 1, 1, result, 0);
    return result;
}
extern int __real_msc_process_response_headers(Transaction *, int, const char *) __attribute__((weak));
int __wrap_msc_process_response_headers(Transaction *transaction, int status, const char *protocol) {
    struct observed_subject observed = subject(transaction, 1, 3);
    observed.response_status_known = 1; observed.response_status = status;
    uint64_t call = enter_subject("native_process_response_headers", &observed, NULL);
    int result = __real_msc_process_response_headers(transaction, status, protocol);
    returned_subject("native_process_response_headers", call, &observed, result, 0, NULL);
    return result;
}
extern int __real_msc_intervention(Transaction *, ModSecurityIntervention *) __attribute__((weak));
int __wrap_msc_intervention(Transaction *transaction, ModSecurityIntervention *intervention) {
    struct observed_subject observed = subject(transaction, 1, 0);
    uint64_t call = enter_subject("native_intervention", &observed, NULL);
    int result = __real_msc_intervention(transaction, intervention);
    int saved = errno;
    /* The selected SDK C implementation returns a C++ bool (exactly 0/1).
     * False or invalid ABI returns do not authorize inspecting caller-owned
     * uninitialized output. URL/log pointers are never examined. */
    if (result == 1 && intervention != NULL) {
        observed.intervention_known = 1;
        observed.intervention_status = intervention->status;
        observed.intervention_disruptive = intervention->disruptive;
    }
    errno = saved;
    returned_subject("native_intervention", call, &observed, result, 0, NULL);
    return result;
}

/* Native append APIs have a byte count, but no EOS argument. In particular
 * null/zero input is an actual append call, never evidence of host EOS. */
#define NATIVE_APPEND_WRAPPER(direction, phase_value) \
extern int __real_msc_append_##direction##_body(Transaction *, const unsigned char *, size_t); \
int __wrap_msc_append_##direction##_body(Transaction *transaction, const unsigned char *data, size_t size) { \
    struct observed_subject observed = subject(transaction, 1, phase_value); \
    observed.input_known = 1; observed.input_size = size; observed.data_present = data != NULL; \
    uint64_t call = enter_subject("native_append_" #direction "_body", &observed, NULL); \
    int result = __real_msc_append_##direction##_body(transaction, data, size); \
    returned_subject("native_append_" #direction "_body", call, &observed, result, 0, NULL); \
    return result; \
}
NATIVE_APPEND_WRAPPER(request, 2)
NATIVE_APPEND_WRAPPER(response, 4)
extern void __real_msc_transaction_cleanup(Transaction *);
void __wrap_msc_transaction_cleanup(Transaction *transaction) {
    uint64_t call = enter("native_cleanup", transaction, 1, 0);
    __real_msc_transaction_cleanup(transaction);
    returned("native_cleanup", call, transaction, 1, 0, 0, 1);
}

/* Weak real declarations leave generic observer controls usable without
 * linking the runtime. A host which calls a wrapped runtime API must link its
 * real implementation. Same-object references are not promised intercepted. */
static void associate_runtime(const void *transaction, const struct allocation_scope *scope) {
    if (transaction == NULL) return;
    (void)pthread_mutex_lock(&lock);
    remember(transaction, 2, NULL, NULL);
    struct mapping *runtime = lookup(transaction, 2);
    struct mapping *common = lookup(scope->common, 0);
    struct mapping *native = lookup(scope->native, 1);
    if (runtime != NULL && scope->common_count == 1U && scope->native_count == 1U &&
        common != NULL && native != NULL && common->allocation_scope_call == scope->call &&
        native->allocation_scope_call == scope->call) {
        runtime->allocation_join_verified = 1;
        runtime->joined_common = scope->common;
        runtime->joined_native = scope->native;
        common->allocation_join_verified = 1;
        native->allocation_join_verified = 1;
    }
    (void)pthread_mutex_unlock(&lock);
}

/* Caller holds the observer lock. Every key was observed at a genuine typed
 * runtime callback; no opaque object layout or capability data is inspected. */
static struct mapping *verified_runtime(const void *transaction,
    const void *common_key, const void *native_key, int require_live) {
    struct mapping *runtime = lookup(transaction, 2);
    if (runtime == NULL || !runtime->allocation_join_verified ||
        runtime->joined_common != common_key || runtime->joined_native != native_key ||
        common_key == NULL || native_key == NULL) return NULL;
    if (require_live) {
        const struct mapping *common = lookup(common_key, 0);
        const struct mapping *native = lookup(native_key, 1);
        if (common == NULL || native == NULL || !common->allocation_join_verified ||
            !native->allocation_join_verified ||
            common->allocation_scope_call != runtime->allocation_scope_call ||
            native->allocation_scope_call != runtime->allocation_scope_call) return NULL;
    }
    return runtime;
}

uint64_t msconnector_lifecycle_runtime_scope_call(
    const msconnector_runtime_transaction *transaction) {
    int saved = errno;
    (void)pthread_mutex_lock(&lock);
    const struct mapping *runtime = lookup(transaction, 2);
    uint64_t call = runtime != NULL && runtime->allocation_kind == 2 &&
        verified_runtime(transaction, runtime->joined_common, runtime->joined_native, 1) != NULL
        ? runtime->allocation_scope_call : 0U;
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    return call;
}

int msconnector_lifecycle_authorization_request_eos(
    const msconnector_runtime_transaction *transaction, size_t content_length,
    size_t buffered_body_size, size_t remaining) {
    int saved = errno;
    struct observed_subject observed = subject(transaction, 2, 2);
    observed.framing_known = 1; observed.content_length = content_length;
    observed.buffered_body_size = buffered_body_size; observed.remaining = remaining;
    uint64_t call = enter_subject("authorization_request_eos", &observed, NULL);
    (void)pthread_mutex_lock(&lock);
    const struct mapping *runtime = lookup(transaction, 2);
    int result = runtime != NULL && runtime->allocation_join_verified &&
        verified_runtime(transaction, runtime->joined_common, runtime->joined_native, 1) != NULL &&
        remaining == 0U && buffered_body_size <= content_length;
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    returned_subject("authorization_request_eos", call, &observed, result, 0, NULL);
    return result;
}

static int associate_companion(const void *key, int kind,
    const struct mapping *runtime, const void *transaction, const void *entry_key) {
    const struct mapping *common = lookup(runtime->joined_common, 0);
    remember(key, kind, NULL, NULL);
    struct mapping *joined = lookup(key, kind);
    if (joined == NULL || common == NULL) return 0;
    (void)snprintf(joined->id, sizeof(joined->id), "%s", common->id);
    (void)snprintf(joined->canonical, sizeof(joined->canonical), "%s", common->canonical);
    joined->id_origin = "observed_common_association";
    joined->allocation_scope_call = runtime->allocation_scope_call;
    joined->allocation_kind = runtime->allocation_kind;
    joined->allocation_join_verified = 1;
    joined->joined_common = runtime->joined_common;
    joined->joined_native = runtime->joined_native;
    joined->joined_runtime = transaction;
    joined->joined_entry = entry_key;
    return 1;
}

int msconnector_lifecycle_companion_registered(const void *entry,
    const msconnector_runtime_transaction *transaction,
    const msconnector_transaction_contract *common, const Transaction *native) {
    int saved = errno;
    uint64_t call = enter("companion_registered", entry, 4, 0);
    (void)pthread_mutex_lock(&lock);
    const struct mapping *runtime = verified_runtime(transaction, common, native, 1);
    int result = runtime != NULL && entry != NULL && lookup(entry, 4) == NULL;
    if (result) result = associate_companion(entry, 4, runtime, transaction, entry);
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    returned("companion_registered", call, entry, 4, 0, result, 0);
    return result;
}

int msconnector_lifecycle_companion_claimed(
    const msconnector_runtime_response_companion_session *session,
    const void *entry, const msconnector_runtime_transaction *transaction,
    const msconnector_transaction_contract *common, const Transaction *native) {
    int saved = errno;
    uint64_t call = enter("companion_claimed", session, 5, 0);
    (void)pthread_mutex_lock(&lock);
    const struct mapping *runtime = verified_runtime(transaction, common, native, 1);
    const struct mapping *registered = lookup(entry, 4);
    int result = runtime != NULL && registered != NULL &&
        registered->allocation_join_verified && registered->joined_runtime == transaction &&
        registered->joined_common == common && registered->joined_native == native &&
        session != NULL && lookup(session, 5) == NULL;
    if (result) result = associate_companion(session, 5, runtime, transaction, entry);
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    returned("companion_claimed", call, session, 5, 0, result, 0);
    return result;
}

int msconnector_lifecycle_companion_retired(
    const msconnector_runtime_transaction *transaction,
    const msconnector_transaction_contract *common, const Transaction *native) {
    int saved = errno;
    uint64_t call = enter("companion_retired", transaction, 2, 0);
    (void)pthread_mutex_lock(&lock);
    const struct mapping *runtime = verified_runtime(transaction, common, native, 0);
    int result = runtime != NULL && lookup(common, 0) == NULL && lookup(native, 1) == NULL;
    if (result) {
        for (size_t index = 0U; index < MAP_CAPACITY; ++index) {
            struct mapping *entry = &mappings[index];
            if ((entry->native == 4 || entry->native == 5) &&
                entry->joined_runtime == transaction && entry->joined_common == common &&
                entry->joined_native == native) memset(entry, 0, sizeof(*entry));
        }
    }
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    returned("companion_retired", call, transaction, 2, 0, result, 0);
    if (result) {
        (void)pthread_mutex_lock(&lock);
        forget(transaction, 2);
        (void)pthread_mutex_unlock(&lock);
    }
    errno = saved;
    return result;
}

uint64_t msconnector_lifecycle_host_begin(void) {
    int saved = errno;
    if (host_scope_depth == HOST_SCOPE_CAPACITY) {
        invalid();
        errno = saved;
        return 0U;
    }
    uint64_t call = enter("host_allocation", NULL, 3, 0);
    struct allocation_scope *scope = &host_scopes[host_scope_depth++];
    *scope = (struct allocation_scope){call, NULL, NULL, 0U, 0U, 3, active_allocation};
    active_allocation = scope;
    errno = saved;
    return call;
}

int msconnector_lifecycle_host_end(uint64_t call, const void *host_context,
    const msconnector_transaction_contract *common, const Transaction *native,
    int construction_result) {
    int saved = errno;
    if (host_scope_depth == 0U || active_allocation != &host_scopes[host_scope_depth - 1U] ||
        call == 0U || active_allocation->call != call) {
        invalid();
        errno = saved;
        return 0;
    }
    struct allocation_scope *scope = active_allocation;
    int verified = 0;
    (void)pthread_mutex_lock(&lock);
    struct mapping *common_entry = lookup(common, 0);
    struct mapping *native_entry = lookup(native, 1);
    if (construction_result == 1 && host_context != NULL && scope->common_count == 1U &&
        scope->native_count == 1U && scope->common == common && scope->native == native &&
        common_entry != NULL && native_entry != NULL && lookup(host_context, 3) == NULL &&
        common_entry->allocation_scope_call == call && native_entry->allocation_scope_call == call) {
        remember(host_context, 3, NULL, NULL);
        struct mapping *host = lookup(host_context, 3);
        if (host != NULL) {
            host->joined_common = common;
            host->joined_native = native;
            host->allocation_join_verified = 1;
            common_entry->allocation_join_verified = 1;
            native_entry->allocation_join_verified = 1;
            verified = 1;
        }
    }
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    returned("host_allocation", call, host_context, 3, 0, verified, 0);
    active_allocation = scope->parent;
    memset(scope, 0, sizeof(*scope));
    --host_scope_depth;
    errno = saved;
    return verified;
}

uint64_t msconnector_lifecycle_host_scope_call(const void *host_context) {
    int saved = errno;
    (void)pthread_mutex_lock(&lock);
    const struct mapping *host = lookup(host_context, 3);
    uint64_t call = host != NULL && host->allocation_join_verified ? host->allocation_scope_call : 0U;
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    return call;
}

int msconnector_lifecycle_host_retire(const void *host_context) {
    int saved = errno;
    uint64_t call = enter("host_association_retire", host_context, 3, 0);
    (void)pthread_mutex_lock(&lock);
    const struct mapping *host = lookup(host_context, 3);
    int retired = host != NULL && host->allocation_join_verified &&
        lookup(host->joined_common, 0) == NULL && lookup(host->joined_native, 1) == NULL;
    (void)pthread_mutex_unlock(&lock);
    errno = saved;
    returned("host_association_retire", call, host_context, 3, 0, retired, retired);
    errno = saved;
    return retired;
}

#define RUNTIME_BEGIN_WRAPPER(suffix, label) \
extern int __real_msconnector_runtime_transaction_##suffix(msconnector_runtime *, const msconnector_request *, const char *, msconnector_runtime_transaction **, msconnector_decision *, msconnector_error *) __attribute__((weak)); \
int __wrap_msconnector_runtime_transaction_##suffix(msconnector_runtime *runtime, const msconnector_request *request, const char *host_id, msconnector_runtime_transaction **out, msconnector_decision *decision, msconnector_error *error) { \
    uint64_t call = enter(label, NULL, 2, 1); \
    struct allocation_scope scope = {call, NULL, NULL, 0U, 0U, 2, NULL}; \
    struct allocation_scope *previous = active_allocation; \
    if (previous != NULL) invalid(); \
    active_allocation = &scope; \
    int result = __real_msconnector_runtime_transaction_##suffix(runtime, request, host_id, out, decision, error); \
    int saved = errno; \
    const void *transaction = result == 1 && out != NULL ? *out : NULL; \
    if (transaction != NULL) associate_runtime(transaction, &scope); \
    errno = saved; \
    returned(label, call, transaction, 2, 1, result, 0); \
    active_allocation = previous; \
    return result; \
}
RUNTIME_BEGIN_WRAPPER(begin, "runtime_begin")
RUNTIME_BEGIN_WRAPPER(begin_request_stream, "runtime_begin_request_stream")

#define RUNTIME_APPEND_WRAPPER(direction, phase_value) \
extern int __real_msconnector_runtime_transaction_append_##direction##_body_chunk(msconnector_runtime_transaction *, const unsigned char *, size_t, msconnector_error *) __attribute__((weak)); \
int __wrap_msconnector_runtime_transaction_append_##direction##_body_chunk(msconnector_runtime_transaction *transaction, const unsigned char *data, size_t size, msconnector_error *error) { \
    struct observed_subject observed = subject(transaction, 2, phase_value); \
    observed.input_known = 1; observed.input_size = size; observed.data_present = data != NULL; \
    uint64_t call = enter_subject("runtime_append_" #direction "_body_chunk", &observed, NULL); \
    int result = __real_msconnector_runtime_transaction_append_##direction##_body_chunk(transaction, data, size, error); \
    returned_subject("runtime_append_" #direction "_body_chunk", call, &observed, result, 0, NULL); \
    return result; \
}
RUNTIME_APPEND_WRAPPER(request, 2)
RUNTIME_APPEND_WRAPPER(response, 4)

/* An actual finish-body call observes a host-to-runtime EOS handoff attempt.
 * Its result and nested native calls remain separate; it does not certify
 * what the host read or what the native engine finalized successfully. */
#define RUNTIME_FINISH_BODY_WRAPPER(direction, phase_value) \
extern int __real_msconnector_runtime_transaction_finish_##direction##_body(msconnector_runtime_transaction *, msconnector_decision *, msconnector_error *) __attribute__((weak)); \
int __wrap_msconnector_runtime_transaction_finish_##direction##_body(msconnector_runtime_transaction *transaction, msconnector_decision *decision, msconnector_error *error) { \
    struct observed_subject observed = subject(transaction, 2, phase_value); \
    observed.runtime_eos_handoff = #direction "_body_finish"; \
    uint64_t call = enter_subject("runtime_finish_" #direction "_body", &observed, NULL); \
    int result = __real_msconnector_runtime_transaction_finish_##direction##_body(transaction, decision, error); \
    returned_subject("runtime_finish_" #direction "_body", call, &observed, result, 0, NULL); \
    return result; \
}
RUNTIME_FINISH_BODY_WRAPPER(request, 2)
RUNTIME_FINISH_BODY_WRAPPER(response, 4)

extern int __real_msconnector_runtime_transaction_process_response_headers(msconnector_runtime_transaction *, const msconnector_response *, msconnector_decision *, msconnector_error *) __attribute__((weak));
int __wrap_msconnector_runtime_transaction_process_response_headers(msconnector_runtime_transaction *transaction, const msconnector_response *response, msconnector_decision *decision, msconnector_error *error) {
    uint64_t call = enter("runtime_process_response_headers", transaction, 2, 3);
    int result = __real_msconnector_runtime_transaction_process_response_headers(transaction, response, decision, error);
    returned("runtime_process_response_headers", call, transaction, 2, 3, result, 0);
    return result;
}

extern int __real_msconnector_runtime_transaction_finish(msconnector_runtime_transaction *, msconnector_error *) __attribute__((weak));
int __wrap_msconnector_runtime_transaction_finish(msconnector_runtime_transaction *transaction, msconnector_error *error) {
    uint64_t call = enter("runtime_finish", transaction, 2, 0);
    int result = __real_msconnector_runtime_transaction_finish(transaction, error);
    returned("runtime_finish", call, transaction, 2, 0, result, 0);
    return result;
}

/* Consuming checked finalize is distinct from best-effort destroy. Snapshot
 * fields are read only on actual selected-ABI success; the runtime remains
 * opaque, including after free. Failed/ambiguous joins are never retired. */
extern int __real_msconnector_runtime_transaction_finalize_and_snapshot(
    msconnector_runtime_transaction **, msconnector_runtime_transaction_snapshot *,
    msconnector_error *) __attribute__((weak));
int __wrap_msconnector_runtime_transaction_finalize_and_snapshot(
    msconnector_runtime_transaction **transaction,
    msconnector_runtime_transaction_snapshot *snapshot, msconnector_error *error) {
    const void *key = transaction == NULL ? NULL : *transaction;
    struct observed_subject observed = subject(key, 2, 0);
    uint64_t call = enter_subject("runtime_finalize_and_snapshot", &observed, NULL);
    int result = __real_msconnector_runtime_transaction_finalize_and_snapshot(transaction, snapshot, error);
    int saved = errno;
    int retired = 0;
    if (result == 1 && transaction != NULL && snapshot != NULL) {
        observed.finalize.known = 1;
        observed.finalize.handle_cleared = *transaction == NULL;
        observed.finalize.finished = snapshot->finished;
        observed.finalize.cleanup_started = snapshot->contract.cleanup_started;
        observed.finalize.cleanup_complete = snapshot->contract.cleanup_complete;
        observed.finalize.status = (int)snapshot->contract.status;
        (void)pthread_mutex_lock(&lock);
        const struct mapping *runtime = lookup(key, 2);
        retired = runtime != NULL && runtime->allocation_join_verified &&
            runtime->allocation_kind == 2 && observed.finalize.handle_cleared &&
            observed.finalize.finished && observed.finalize.cleanup_started &&
            observed.finalize.cleanup_complete &&
            observed.finalize.status == MSCONNECTOR_TRANSACTION_STATUS_CLEANED &&
            lookup(runtime->joined_common, 0) == NULL && lookup(runtime->joined_native, 1) == NULL;
        (void)pthread_mutex_unlock(&lock);
        observed.finalize.association_retired = retired;
    }
    errno = saved;
    returned_subject("runtime_finalize_and_snapshot", call, &observed, result, retired, NULL);
    errno = saved;
    return result;
}

extern void __real_msconnector_runtime_transaction_destroy(msconnector_runtime_transaction **) __attribute__((weak));
void __wrap_msconnector_runtime_transaction_destroy(msconnector_runtime_transaction **transaction) {
    /* Retain only the opaque pointer value before the real consuming call. */
    const void *key = transaction == NULL ? NULL : *transaction;
    uint64_t call = enter("runtime_destroy", key, 2, 0);
    __real_msconnector_runtime_transaction_destroy(transaction);
    returned("runtime_destroy", call, key, 2, 0, 0, 1);
}

/* Companion APIs are genuine external TU calls, separate from ordinary
 * same-runtime-object calls which GNU ld --wrap may not intercept. */
extern int __real_msconnector_runtime_response_companion_handoff_with_handle(
    msconnector_runtime_response_companion_registry *, msconnector_runtime_transaction *,
    uint64_t, char *, msconnector_error *) __attribute__((weak));
int __wrap_msconnector_runtime_response_companion_handoff_with_handle(
    msconnector_runtime_response_companion_registry *registry,
    msconnector_runtime_transaction *transaction, uint64_t ttl_ms,
    char *handle, msconnector_error *error) {
    uint64_t call = enter("companion_handoff", transaction, 2, 0);
    int result = __real_msconnector_runtime_response_companion_handoff_with_handle(
        registry, transaction, ttl_ms, handle, error);
    returned("companion_handoff", call, transaction, 2, 0, result, 0);
    return result;
}
extern int __real_msconnector_runtime_response_companion_claim_handle(
    msconnector_runtime_response_companion_registry *, const char *,
    msconnector_runtime_response_companion_session *, msconnector_error *) __attribute__((weak));
int __wrap_msconnector_runtime_response_companion_claim_handle(
    msconnector_runtime_response_companion_registry *registry, const char *handle,
    msconnector_runtime_response_companion_session *session, msconnector_error *error) {
    uint64_t call = enter("companion_claim", session, 5, 0);
    int result = __real_msconnector_runtime_response_companion_claim_handle(registry, handle, session, error);
    returned("companion_claim", call, session, 5, 0, result, 0);
    return result;
}
extern int __real_msconnector_runtime_response_companion_revoke_handle(
    msconnector_runtime_response_companion_registry *, const char *, msconnector_error *) __attribute__((weak));
int __wrap_msconnector_runtime_response_companion_revoke_handle(
    msconnector_runtime_response_companion_registry *registry, const char *handle,
    msconnector_error *error) {
    uint64_t call = enter("companion_revoke", NULL, 4, 0);
    int result = __real_msconnector_runtime_response_companion_revoke_handle(registry, handle, error);
    returned("companion_revoke", call, NULL, 4, 0, result, 0);
    return result;
}
#define COMPANION_SESSION_API(suffix, phase_number, eos, signature, arguments) \
extern int __real_msconnector_runtime_response_companion_session_##suffix signature __attribute__((weak)); \
int __wrap_msconnector_runtime_response_companion_session_##suffix signature { \
    struct observed_subject observed = subject(session, 5, phase_number); \
    observed.runtime_eos_handoff = eos; \
    uint64_t call = enter_subject("companion_session_" #suffix, &observed, NULL); \
    int result = __real_msconnector_runtime_response_companion_session_##suffix arguments; \
    returned_subject("companion_session_" #suffix, call, &observed, result, 0, NULL); \
    return result; \
}
COMPANION_SESSION_API(process_response_headers, 3, NULL,
    (msconnector_runtime_response_companion_session *session, const msconnector_response *response,
     msconnector_decision *decision, msconnector_error *error), (session, response, decision, error))
COMPANION_SESSION_API(finish_response_body, 4, "companion_response_body_finish",
    (msconnector_runtime_response_companion_session *session, msconnector_decision *decision,
     msconnector_error *error), (session, decision, error))
COMPANION_SESSION_API(set_response_commit_state, 0, NULL,
    (msconnector_runtime_response_companion_session *session, int headers_sent, int body_started,
     msconnector_error *error), (session, headers_sent, body_started, error))
COMPANION_SESSION_API(record_host_action, 0, NULL,
    (msconnector_runtime_response_companion_session *session, const msconnector_decision *decision,
     msconnector_decision_action actual_action, int visible_http_status, const char *transport_result,
     int connection_aborted, msconnector_error *error),
    (session, decision, actual_action, visible_http_status, transport_result, connection_aborted, error))
COMPANION_SESSION_API(fail, 0, NULL,
    (msconnector_runtime_response_companion_session *session, msconnector_transaction_error_class error_class,
     msconnector_error *error), (session, error_class, error))
COMPANION_SESSION_API(cancel, 0, NULL,
    (msconnector_runtime_response_companion_session *session, int upstream_disconnect,
     msconnector_error *error), (session, upstream_disconnect, error))
COMPANION_SESSION_API(release, 0, NULL,
    (msconnector_runtime_response_companion_session *session, msconnector_error *error), (session, error))
#undef COMPANION_SESSION_API
extern int __real_msconnector_runtime_response_companion_session_append_response_body_chunk(
    msconnector_runtime_response_companion_session *, const unsigned char *, size_t,
    msconnector_error *) __attribute__((weak));
int __wrap_msconnector_runtime_response_companion_session_append_response_body_chunk(
    msconnector_runtime_response_companion_session *session, const unsigned char *data,
    size_t size, msconnector_error *error) {
    struct observed_subject observed = subject(session, 5, 4);
    observed.input_known = 1; observed.input_size = size; observed.data_present = data != NULL;
    uint64_t call = enter_subject("companion_session_append_response_body_chunk", &observed, NULL);
    int result = __real_msconnector_runtime_response_companion_session_append_response_body_chunk(
        session, data, size, error);
    returned_subject("companion_session_append_response_body_chunk", call, &observed, result, 0, NULL);
    return result;
}
