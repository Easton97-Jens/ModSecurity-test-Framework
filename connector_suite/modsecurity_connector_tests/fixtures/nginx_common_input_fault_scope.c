/* Unit-only simulated process/resolver/owner controls around the actual fixture;
 * the delegated Common validator below is compiled from real product source.
 * This executable is never a native runtime evidence producer. */
#define getuid controlled_getuid
#define getpid controlled_getpid
#define getppid controlled_getppid
#define dlsym controlled_dlsym
#define fstat controlled_fstat
#include "nginx_common_input_fault.c"
#undef getuid
#undef getpid
#undef getppid
#undef dlsym
#undef fstat

static uid_t fake_uid;
static int foreign_owner;
static pid_t fake_pid = 123;
static pid_t fake_parent = 123;
uid_t controlled_getuid(void) { return fake_uid; }
pid_t controlled_getpid(void) { return fake_pid; }
pid_t controlled_getppid(void) { return fake_parent; }
int actual_common_guard(const msconnector_request_mapper_contract *, const msconnector_request *, char *, size_t);
int fstat(int fd, struct stat *info);
int controlled_fstat(int fd, struct stat *info)
{
    int result = fstat(fd, info);
    if (result == 0 && foreign_owner) { info->st_uid = 65534; }
    return result;
}

static void *unit_transaction(void *engine, void *rules, const char *id, void *opaque)
{
    (void)engine; (void)rules; (void)id;
    return opaque;
}

_Static_assert(_Generic(&unit_transaction, new_transaction_fn: 1, default: 0),
    "Controlled callback must match the native const-ID function pointer.");
_Static_assert(_Generic(&msc_new_transaction_with_id, new_transaction_fn: 1, default: 0),
    "Interposed export must match the native const-ID function pointer.");

void *controlled_dlsym(void *handle, const char *name)
{
    union { void *pointer; validate_fn validate; new_transaction_fn transaction; } value;
    (void)handle;
    if (strcmp(name, "msc_new_transaction_with_id") == 0) { value.transaction = unit_transaction; }
    else { value.validate = actual_common_guard; }
    return value.pointer;
}

int main(int argc, char **argv)
{
    msconnector_request_mapper_contract contract;
    msconnector_header header = {"Host", 4U, "localhost", 9U};
    msconnector_request request = {0};
    char error[128] = {0};
    const char transaction[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char foreign[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    char uri[128];
    if (argc != 4) { return 2; }
    foreign_owner = strcmp(argv[2], "owner") == 0;
    (void)setenv("MSCONNECTOR_OWNED_INPUT_FAULT", argv[1], 1);
    (void)setenv("MSCONNECTOR_OWNED_INPUT_TXID", transaction, 1);
    if (strcmp(argv[2], "legacy") == 0) {
        (void)unsetenv("MSCONNECTOR_OWNED_INPUT_FD");
        (void)setenv("MSCONNECTOR_OWNED_INPUT_LEDGER", argv[3], 1);
    } else {
        (void)setenv("MSCONNECTOR_OWNED_INPUT_FD", argv[3], 1);
    }
    bind_owned_invocation();
    fake_uid = 65534; fake_pid = 124;
    if (strcmp(argv[2], "uid") == 0) { fake_uid = 0; }
    if (strcmp(argv[2], "parent") == 0) { fake_parent = 999; }
    (void)msc_new_transaction_with_id(NULL, NULL,
        strcmp(argv[2], "transaction") == 0 ? foreign : transaction, &contract);
    if (strcmp(argv[2], "foreign-after-match") == 0) {
        (void)msc_new_transaction_with_id(NULL, NULL, foreign, &contract);
    }
    msconnector_request_mapper_contract_init(&contract);
    (void)snprintf(uri, sizeof(uri), "/no-crs/input-fault/%s", argv[1]);
    request.method = strcmp(argv[2], "method") == 0 ? "GET" : "POST";
    request.uri = strcmp(argv[2], "uri") == 0 ? "/different" : uri;
    request.client.address = "127.0.0.1"; request.server.address = "127.0.0.1";
    request.headers = &header; request.header_count = 1U;
    int first = msconnector_request_mapper_validate_output(&contract, &request, error, sizeof(error));
    int second = msconnector_request_mapper_validate_output(&contract, &request, error, sizeof(error));
    printf("%d %d\n", first, second);
    if (ledger >= 0) { close(ledger); }
    return 0;
}
