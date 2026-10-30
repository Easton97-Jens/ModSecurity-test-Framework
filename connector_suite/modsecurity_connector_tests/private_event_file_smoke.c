/*
 * Focused private event-file descriptor control.
 *
 * Run from the repository root with an explicitly registered external test
 * root (an existing owned mode0700 directory), for example:
 *
 *   MSCONNECTOR_EVENT_FILE_TEST_ROOT=/var/tmp/codex/... \
 *     cc -std=c17 -Wall -Wextra -Werror -Icommon/include \
 *     tests/private_event_file_smoke.c common/src/event.c \
 *     common/src/event_jsonl.c common/src/json_escape.c common/src/status.c \
 *     common/src/http_status.c common/src/transaction_state.c -o <external-bin> && \
 *     MSCONNECTOR_EVENT_FILE_TEST_ROOT=/var/tmp/codex/... <external-bin>
 */

#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "msconnector/event_jsonl.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define TEST_PATH_SIZE 4096U

#if !defined(_WIN32)
#define TEST_UNPRIVILEGED_UID ((uid_t)65534)
#define TEST_UNPRIVILEGED_GID ((gid_t)65534)
#define TEST_ROOT_DIRECTORY_MODE ((mode_t)0750)
#define TEST_ROOT_PARENT_SAFE_MODE ((mode_t)0750)
#define TEST_ROOT_PARENT_WRITABLE_MODE ((mode_t)0770)

typedef struct private_event_file_test_paths {
    int base_fd;
    int root_fd;
    int private_fd;
    char root_name[sizeof("event-sink-XXXXXX")];
    char root[TEST_PATH_SIZE];
    char private_directory[TEST_PATH_SIZE];
    char unsafe_directory[TEST_PATH_SIZE];
    char event_path[TEST_PATH_SIZE];
    char symlink_path[TEST_PATH_SIZE];
    char ancestor_symlink[TEST_PATH_SIZE];
    char ancestor_event_path[TEST_PATH_SIZE];
    char fifo_path[TEST_PATH_SIZE];
    char unsafe_path[TEST_PATH_SIZE];
    char traversal_path[TEST_PATH_SIZE];
    char root_owned_directory[TEST_PATH_SIZE];
    char root_owned_event_path[TEST_PATH_SIZE];
    char root_owned_leaf_path[TEST_PATH_SIZE];
} private_event_file_test_paths;

static int join_path(char *destination, size_t destination_size,
    const char *parent, const char *name)
{
    int written = snprintf(destination, destination_size, "%s/%s", parent,
        name);

    return written >= 0 && (size_t)written < destination_size;
}

static int expect_rejected(const char *path)
{
    int fd = -1;

    if (msconnector_open_private_event_file(path, &fd)) {
        (void)close(fd);
        return 0;
    }
    return fd == -1;
}

static int create_permissive_fixture(int private_fd)
{
    struct stat status;
    int fd = openat(private_fd, "events.jsonl",
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int valid = fd >= 0 && fstat(fd, &status) == 0 &&
        S_ISREG(status.st_mode) && status.st_uid == geteuid() &&
        (status.st_mode & 0777) == 0600;

    if (!valid) {
        const int saved_errno = errno;
        if (fd >= 0) {
            (void)close(fd);
        }
        errno = saved_errno;
        return 0;
    }
    /* Deliberately make the isolated fixture group-readable so the production
     * opener's mode-repair path is exercised without process-wide umask or a
     * permissive create mode. */
    if (fchmod(fd, (status.st_mode & 0777) | S_IRGRP) != 0 ||
        fstat(fd, &status) != 0 || (status.st_mode & 0777) != 0640) {
        const int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return 0;
    }
    if (close(fd) != 0) {
        return 0;
    }
    return 1;
}

static int check_regular_event_file(const char *path)
{
    struct stat status;
    int fd = -1;
    int valid = msconnector_open_private_event_file(path, &fd) &&
        fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
        status.st_uid == geteuid() && (status.st_mode & 0777) == 0600 &&
        (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0 && write(fd, "{}\n", 3) == 3;

    if (fd >= 0 && close(fd) != 0) {
        valid = 0;
    }
    return valid;
}

static int check_repaired_event_file(const char *path)
{
    struct stat status;
    int fd = -1;
    int valid = msconnector_open_private_event_file(path, &fd) &&
        fstat(fd, &status) == 0 && (status.st_mode & 0777) == 0600 &&
        (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0;

    if (fd >= 0 && close(fd) != 0) {
        valid = 0;
    }
    return valid;
}

static int check_rejected_paths(const char *symlink_path,
    const char *ancestor_event_path, const char *fifo_path,
    const char *unsafe_path, const char *traversal_path,
    const char *private_directory)
{
    return expect_rejected(symlink_path) &&
        expect_rejected(ancestor_event_path) && expect_rejected(fifo_path) &&
        expect_rejected(unsafe_path) && expect_rejected(traversal_path) &&
        expect_rejected(private_directory);
}

static int drop_to_unprivileged_test_user(void)
{
    return setgid(TEST_UNPRIVILEGED_GID) == 0 &&
        setuid(TEST_UNPRIVILEGED_UID) == 0 &&
        geteuid() == TEST_UNPRIVILEGED_UID;
}

static int wait_for_test_child(pid_t child)
{
    int status;

    return child > 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int close_test_descriptor(int *descriptor)
{
    int result = 1;

    if (*descriptor >= 0) {
        if (close(*descriptor) != 0) {
            result = 0;
        }
        *descriptor = -1;
    }
    return result;
}

static int directory_open_flags(void)
{
    int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW;

#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
    return flags;
}

static int open_test_directory_at(int parent_fd, const char *name)
{
    return openat(parent_fd, name, directory_open_flags());
}

/* Validate the supplied base before the first filesystem mutation. Held
 * descriptors prevent symlink traversal; only root-owned sticky ancestors
 * may be shared writable. The final base remains privately owned. */
static int open_private_test_base(const char *base)
{
    char copy[TEST_PATH_SIZE];
    char *state = NULL;
    int directory;
    struct stat details;
    size_t length;

    if (base == NULL || base[0] != '/') { return -1; }
    length = strlen(base);
    if (length == 0 || length >= sizeof(copy) || base[length - 1] == '/' ||
        strstr(base, "//") != NULL) { return -1; }
    memcpy(copy, base, length + 1U);
    directory = open("/", directory_open_flags());
    if (directory < 0) { return -1; }
    for (const char *part = strtok_r(copy, "/", &state); part != NULL;
         part = strtok_r(NULL, "/", &state)) {
        int next;
        if (strcmp(part, ".") == 0 || strcmp(part, "..") == 0) { goto rejected; }
        next = open_test_directory_at(directory, part);
        if (next < 0) { goto rejected; }
        (void)close(directory);
        directory = next;
        if (fstat(directory, &details) != 0 ||
            (details.st_uid != 0 && details.st_uid != geteuid()) ||
            ((details.st_mode & 0022) != 0 &&
             !(details.st_uid == 0 && (details.st_mode & S_ISVTX) != 0))) {
            goto rejected;
        }
    }
    if (fstat(directory, &details) == 0 && details.st_uid == geteuid() &&
        (details.st_mode & 0777) == 0700) { return directory; }
rejected:
    (void)close(directory);
    return -1;
}

static int create_unsafe_directory(int root_fd)
{
    int directory_fd = -1;
    int result = 0;

    if (mkdirat(root_fd, "unsafe", 0700) != 0) {
        return 0;
    }
    directory_fd = open_test_directory_at(root_fd, "unsafe");
    if (directory_fd >= 0 &&
        fchmod(directory_fd, TEST_ROOT_PARENT_WRITABLE_MODE) == 0) {
        result = 1;
    }
    if (!close_test_descriptor(&directory_fd)) {
        result = 0;
    }
    return result;
}

static int create_unprivileged_event_fixture(int parent_fd, const char *name)
{
    pid_t child = fork();

    if (child == 0) {
        int fd;
        struct stat status;

        if (!drop_to_unprivileged_test_user()) {
            _exit(1);
        }
        fd = openat(parent_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
            0600);
        if (fd < 0 || fstat(fd, &status) != 0 ||
            !S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
            (status.st_mode & 0777) != 0600) {
            if (fd >= 0) {
                (void)close(fd);
            }
            _exit(1);
        }
        if (close(fd) != 0) {
            _exit(1);
        }
        _exit(0);
    }
    return wait_for_test_child(child);
}

static int check_event_file_as_unprivileged(int root_fd, const char *path,
    int expected_open)
{
    pid_t child = fork();

    if (child == 0) {
        /* Anchor the real public relative-path API before dropping identity;
         * private outer output ancestors must not mask the parent controls. */
        if (fchdir(root_fd) != 0 || !drop_to_unprivileged_test_user()) {
            _exit(1);
        }
        if ((expected_open && check_regular_event_file(path)) ||
            (!expected_open && expect_rejected(path))) {
            _exit(0);
        }
        _exit(1);
    }
    return wait_for_test_child(child);
}

enum root_parent_preparation {
    ROOT_PARENT_PREPARATION_FAILED = 0,
    ROOT_PARENT_PREPARATION_SKIPPED = 1,
    ROOT_PARENT_PREPARATION_READY = 2,
};

static int test_user_mapping_unavailable(int error_number)
{
    return error_number == EINVAL || error_number == EPERM;
}

static int prepare_root_owned_parent(int held_root_fd, int *root_fd,
    int *parent_fd)
{
    *root_fd = fcntl(held_root_fd, F_DUPFD_CLOEXEC, 3);
    if (*root_fd < 0) {
        (void)fprintf(stderr, "root-owned fixture root open failed: %s\n",
            strerror(errno));
        return ROOT_PARENT_PREPARATION_FAILED;
    }
    if (fchown(*root_fd, (uid_t)0, TEST_UNPRIVILEGED_GID) != 0) {
        const int saved_errno = errno;

        if (test_user_mapping_unavailable(saved_errno)) {
            (void)fprintf(stderr,
                "root-owned parent control skipped: uid mapping is unavailable\n");
            return ROOT_PARENT_PREPARATION_SKIPPED;
        }
        (void)fprintf(stderr, "root-owned fixture root fchown failed: %s\n",
            strerror(saved_errno));
        return ROOT_PARENT_PREPARATION_FAILED;
    }
    if (fchmod(*root_fd, TEST_ROOT_DIRECTORY_MODE) != 0) {
        (void)fprintf(stderr, "root-owned fixture root fchmod failed: %s\n",
            strerror(errno));
        return ROOT_PARENT_PREPARATION_FAILED;
    }
    if (mkdirat(*root_fd, "root-owned", 0700) != 0) {
        (void)fprintf(stderr, "root-owned fixture mkdir failed: %s\n",
            strerror(errno));
        return ROOT_PARENT_PREPARATION_FAILED;
    }
    *parent_fd = open_test_directory_at(*root_fd, "root-owned");
    if (*parent_fd < 0) {
        (void)fprintf(stderr, "root-owned fixture parent open failed: %s\n",
            strerror(errno));
        return ROOT_PARENT_PREPARATION_FAILED;
    }
    if (fchown(*parent_fd, TEST_UNPRIVILEGED_UID,
            TEST_UNPRIVILEGED_GID) != 0) {
        const int saved_errno = errno;

        if (test_user_mapping_unavailable(saved_errno)) {
            (void)fprintf(stderr,
                "root-owned parent control skipped: uid mapping is unavailable\n");
            return ROOT_PARENT_PREPARATION_SKIPPED;
        }
        (void)fprintf(stderr, "root-owned fixture parent fchown failed: %s\n",
            strerror(saved_errno));
        return ROOT_PARENT_PREPARATION_FAILED;
    }
    if (fchmod(*parent_fd, 0700) != 0) {
        (void)fprintf(stderr, "unprivileged parent fixture setup failed: %s\n",
            strerror(errno));
        return ROOT_PARENT_PREPARATION_FAILED;
    }
    return ROOT_PARENT_PREPARATION_READY;
}

static int transition_root_owned_parent(int parent_fd)
{
    return fchown(parent_fd, (uid_t)0, TEST_UNPRIVILEGED_GID) == 0 &&
        fchmod(parent_fd, TEST_ROOT_PARENT_SAFE_MODE) == 0;
}

static int check_writable_root_owned_parent(int parent_fd, int root_fd,
    const char *event_path)
{
    /* The production guard rejects both group- and other-writable parents.
     * This private fixture uses group write so it exercises that shared guard
     * without granting unrelated identities access to a test directory. */
    if (fchmod(parent_fd, TEST_ROOT_PARENT_WRITABLE_MODE) != 0) {
        return 0;
    }
    if (!check_event_file_as_unprivileged(root_fd, event_path, 0)) {
        return 0;
    }
    return fchmod(parent_fd, TEST_ROOT_PARENT_SAFE_MODE) == 0;
}

static int create_root_owned_event_leaf(int parent_fd)
{
    int leaf_fd = openat(parent_fd, "root-owned.jsonl",
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    if (leaf_fd < 0) {
        return 0;
    }
    return close_test_descriptor(&leaf_fd);
}

static int check_root_owned_parent_controls(int held_root_fd,
    const char *event_path, const char *root_owned_path)
{
    int root_fd = -1;
    int parent_fd = -1;
    int preparation;
    int result = 0;

    if (geteuid() != 0) {
        return 1;
    }
    preparation = prepare_root_owned_parent(held_root_fd, &root_fd, &parent_fd);
    if (preparation == ROOT_PARENT_PREPARATION_SKIPPED) {
        result = 1;
        goto cleanup;
    }
    if (preparation != ROOT_PARENT_PREPARATION_READY) {
        goto cleanup;
    }
    if (!create_unprivileged_event_fixture(parent_fd, "events.jsonl")) {
        (void)fprintf(stderr, "unprivileged event fixture creation failed\n");
        goto cleanup;
    }
    if (!transition_root_owned_parent(parent_fd)) {
        (void)fprintf(stderr, "root-owned parent fixture transition failed\n");
        goto cleanup;
    }
    if (!check_event_file_as_unprivileged(root_fd, event_path, 1)) {
        (void)fprintf(stderr, "root-owned secure parent was rejected\n");
        goto cleanup;
    }
    if (!check_writable_root_owned_parent(parent_fd, root_fd, event_path)) {
        (void)fprintf(stderr, "writable root-owned parent was accepted\n");
        goto cleanup;
    }
    if (!create_root_owned_event_leaf(parent_fd)) {
        goto cleanup;
    }
    if (!check_event_file_as_unprivileged(root_fd, root_owned_path, 0)) {
        goto cleanup;
    }
    result = 1;

cleanup:
    if (!close_test_descriptor(&parent_fd)) {
        result = 0;
    }
    if (!close_test_descriptor(&root_fd)) {
        result = 0;
    }
    return result;
}

static int initialize_test_paths(const char *base,
    private_event_file_test_paths *paths)
{
    (void)memset(paths, 0, sizeof(*paths));
    paths->base_fd = paths->root_fd = paths->private_fd = -1;
    if (base == NULL || base[0] == '\0' ||
        strlen(base) + sizeof("/event-sink-XXXXXX") > sizeof(paths->root)) {
        (void)fprintf(stderr,
            "MSCONNECTOR_EVENT_FILE_TEST_ROOT must be a bounded external root\n");
        return -1;
    }
    paths->base_fd = open_private_test_base(base);
    if (paths->base_fd < 0) { return -1; }
    (void)snprintf(paths->root, sizeof(paths->root), "%s/event-sink-XXXXXX",
        base);
    if (mkdtemp(paths->root) == NULL) {
        (void)close_test_descriptor(&paths->base_fd);
        return 0;
    }
    memcpy(paths->root_name, strrchr(paths->root, '/') + 1U,
        sizeof(paths->root_name));
    {
        int root_fd = open_test_directory_at(paths->base_fd, paths->root_name);
        struct stat opened;
        struct stat named;
        if (root_fd < 0 || fstat(root_fd, &opened) != 0 ||
            opened.st_uid != geteuid() || (opened.st_mode & 0777) != 0700 ||
            fstatat(paths->base_fd, paths->root_name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(named.st_mode) || opened.st_dev != named.st_dev ||
            opened.st_ino != named.st_ino) {
            (void)close_test_descriptor(&root_fd);
            return 0;
        }
        paths->root_fd = root_fd;
    }
    return join_path(paths->private_directory, sizeof(paths->private_directory),
               paths->root, "private") &&
        join_path(paths->unsafe_directory, sizeof(paths->unsafe_directory),
            paths->root, "unsafe") &&
        join_path(paths->event_path, sizeof(paths->event_path),
            paths->private_directory, "events.jsonl") &&
        join_path(paths->symlink_path, sizeof(paths->symlink_path),
            paths->private_directory, "event-link.jsonl") &&
        join_path(paths->ancestor_symlink, sizeof(paths->ancestor_symlink),
            paths->root, "private-link") &&
        join_path(paths->ancestor_event_path,
            sizeof(paths->ancestor_event_path), paths->ancestor_symlink,
            "events.jsonl") &&
        join_path(paths->fifo_path, sizeof(paths->fifo_path),
            paths->private_directory, "event.fifo") &&
        join_path(paths->unsafe_path, sizeof(paths->unsafe_path),
            paths->unsafe_directory, "events.jsonl") &&
        join_path(paths->traversal_path, sizeof(paths->traversal_path),
            paths->private_directory, "../escape.jsonl") &&
        join_path(paths->root_owned_directory,
            sizeof(paths->root_owned_directory), paths->root, "root-owned") &&
        join_path(paths->root_owned_event_path,
            sizeof(paths->root_owned_event_path), paths->root_owned_directory,
            "events.jsonl") &&
        join_path(paths->root_owned_leaf_path,
            sizeof(paths->root_owned_leaf_path), paths->root_owned_directory,
            "root-owned.jsonl");
}

static int setup_test_directories(private_event_file_test_paths *paths)
{
    if (paths->root_fd < 0 || mkdirat(paths->root_fd, "private", 0700) != 0 ||
        !create_unsafe_directory(paths->root_fd)) { return 0; }
    paths->private_fd = open_test_directory_at(paths->root_fd, "private");
    return paths->private_fd >= 0;
}

static int remove_test_entry(int directory, const char *name, int flags)
{
    return unlinkat(directory, name, flags) == 0 || errno == ENOENT;
}

static int cleanup_test_paths(private_event_file_test_paths *paths)
{
    int result = 1;
    struct stat opened;
    struct stat named;
    if (paths->root_fd >= 0) {
        int owned = open_test_directory_at(paths->root_fd, "root-owned");
        if (owned >= 0) {
            if (!remove_test_entry(owned, "root-owned.jsonl", 0)) { result = 0; }
            if (!remove_test_entry(owned, "events.jsonl", 0)) { result = 0; }
            if (!close_test_descriptor(&owned)) { result = 0; }
        } else if (errno != ENOENT) { result = 0; }
        if (paths->private_fd >= 0) {
            if (!remove_test_entry(paths->private_fd, "event-link.jsonl", 0)) { result = 0; }
            if (!remove_test_entry(paths->private_fd, "event.fifo", 0)) { result = 0; }
            if (!remove_test_entry(paths->private_fd, "events.jsonl", 0)) { result = 0; }
        }
        if (!remove_test_entry(paths->root_fd, "root-owned", AT_REMOVEDIR)) { result = 0; }
        if (!remove_test_entry(paths->root_fd, "private-link", 0)) { result = 0; }
        if (!remove_test_entry(paths->root_fd, "unsafe", AT_REMOVEDIR)) { result = 0; }
        if (!remove_test_entry(paths->root_fd, "private", AT_REMOVEDIR)) { result = 0; }
        if (fstat(paths->root_fd, &opened) != 0 ||
            fstatat(paths->base_fd, paths->root_name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(named.st_mode) || opened.st_dev != named.st_dev ||
            opened.st_ino != named.st_ino ||
            !remove_test_entry(paths->base_fd, paths->root_name, AT_REMOVEDIR)) { result = 0; }
    } else if (paths->root_name[0] != '\0') { result = 0; }
    if (!close_test_descriptor(&paths->private_fd)) { result = 0; }
    if (!close_test_descriptor(&paths->root_fd)) { result = 0; }
    if (!close_test_descriptor(&paths->base_fd)) { result = 0; }
    return result;
}

static int run_private_event_file_smoke(void)
{
    const char *base = getenv("MSCONNECTOR_EVENT_FILE_TEST_ROOT");
    private_event_file_test_paths paths;
    int paths_initialized;
    int result = 1;

    paths_initialized = initialize_test_paths(base, &paths);
    if (paths_initialized < 0) {
        return 2;
    }
    if (paths_initialized == 0 || !setup_test_directories(&paths)) {
        (void)fprintf(stderr, "private event-file test path setup failed\n");
        goto cleanup;
    }
    if (!check_regular_event_file(paths.event_path)) {
        (void)fprintf(stderr, "private regular event-file control failed\n");
        goto cleanup;
    }
    if (unlinkat(paths.private_fd, "events.jsonl", 0) != 0 ||
        !create_permissive_fixture(paths.private_fd) ||
        !check_repaired_event_file(paths.event_path)) {
        (void)fprintf(stderr, "existing event-file permission repair failed\n");
        goto cleanup;
    }
    if (symlinkat("events.jsonl", paths.private_fd, "event-link.jsonl") != 0 ||
        symlinkat(paths.private_directory, paths.root_fd, "private-link") != 0 ||
        mkfifoat(paths.private_fd, "event.fifo", 0600) != 0 ||
        !check_rejected_paths(paths.symlink_path, paths.ancestor_event_path,
            paths.fifo_path, paths.unsafe_path, paths.traversal_path,
            paths.private_directory)) {
        (void)fprintf(stderr, "unsafe event-file path was accepted\n");
        goto cleanup;
    }
    if (!check_root_owned_parent_controls(paths.root_fd,
            "root-owned/events.jsonl", "root-owned/root-owned.jsonl")) {
        (void)fprintf(stderr, "root-owned event parent control failed\n");
        goto cleanup;
    }

    result = 0;

cleanup:
    if (!cleanup_test_paths(&paths)) { result = 1; }
    if (result == 0) { puts("private event-file descriptor controls: passed"); }
    return result;
}
#endif

int main(void)
{
#if defined(_WIN32)
    int fd = -1;

    if (msconnector_open_private_event_file("C:\\event.jsonl", &fd)) {
        return 1;
    }
    puts("private event-file Windows fail-closed control: passed");
    return 0;
#else
    return run_private_event_file_smoke();
#endif
}
