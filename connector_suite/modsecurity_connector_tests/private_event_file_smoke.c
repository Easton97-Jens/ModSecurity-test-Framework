/*
 * Focused private event-file descriptor control.
 *
 * Run from the repository root with an explicitly registered external test
 * root, for example:
 *
 *   MSCONNECTOR_EVENT_FILE_TEST_ROOT=/var/tmp/codex/... \
 *     cc -std=c17 -Wall -Wextra -Werror -Icommon/include \
 *     tests/private_event_file_smoke.c common/src/event.c \
 *     common/src/event_jsonl.c common/src/json_escape.c common/src/status.c \
 *     common/src/http_status.c common/src/transaction_state.c -o <external-bin> && \
 *     MSCONNECTOR_EVENT_FILE_TEST_ROOT=/var/tmp/codex/... <external-bin>
 */

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

static int create_permissive_fixture(const char *path)
{
    struct stat status;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
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

static int open_test_directory(const char *path)
{
    return open(path, directory_open_flags());
}

static int open_test_directory_at(int parent_fd, const char *name)
{
    return openat(parent_fd, name, directory_open_flags());
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

static int check_event_file_as_unprivileged(const char *path, int expected_open)
{
    pid_t child = fork();

    if (child == 0) {
        if (!drop_to_unprivileged_test_user()) {
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

static int prepare_root_owned_parent(const char *root, int *root_fd,
    int *parent_fd)
{
    *root_fd = open_test_directory(root);
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

static int check_writable_root_owned_parent(int parent_fd,
    const char *event_path)
{
    /* The production guard rejects both group- and other-writable parents.
     * This private fixture uses group write so it exercises that shared guard
     * without granting unrelated identities access to a test directory. */
    if (fchmod(parent_fd, TEST_ROOT_PARENT_WRITABLE_MODE) != 0) {
        return 0;
    }
    if (!check_event_file_as_unprivileged(event_path, 0)) {
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

static int check_root_owned_parent_controls(const char *root,
    const char *event_path, const char *root_owned_path)
{
    int root_fd = -1;
    int parent_fd = -1;
    int preparation;
    int result = 0;

    if (geteuid() != 0) {
        return 1;
    }
    preparation = prepare_root_owned_parent(root, &root_fd, &parent_fd);
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
    if (!check_event_file_as_unprivileged(event_path, 1)) {
        (void)fprintf(stderr, "root-owned secure parent was rejected\n");
        goto cleanup;
    }
    if (!check_writable_root_owned_parent(parent_fd, event_path)) {
        (void)fprintf(stderr, "writable root-owned parent was accepted\n");
        goto cleanup;
    }
    if (!create_root_owned_event_leaf(parent_fd)) {
        goto cleanup;
    }
    if (!check_event_file_as_unprivileged(root_owned_path, 0)) {
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
    if (base == NULL || base[0] == '\0' ||
        strlen(base) + sizeof("/event-sink-XXXXXX") > sizeof(paths->root)) {
        (void)fprintf(stderr,
            "MSCONNECTOR_EVENT_FILE_TEST_ROOT must be a bounded external root\n");
        return -1;
    }
    (void)snprintf(paths->root, sizeof(paths->root), "%s/event-sink-XXXXXX",
        base);
    if (mkdtemp(paths->root) == NULL) {
        return 0;
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

static int setup_test_directories(const private_event_file_test_paths *paths)
{
    int root_fd = open_test_directory(paths->root);
    int result = 0;

    if (root_fd >= 0 && mkdirat(root_fd, "private", 0700) == 0 &&
        create_unsafe_directory(root_fd)) {
        result = 1;
    }
    if (!close_test_descriptor(&root_fd)) {
        result = 0;
    }
    return result;
}

static void cleanup_test_paths(const private_event_file_test_paths *paths)
{
    if (paths->root_owned_leaf_path[0] != '\0') {
        (void)unlink(paths->root_owned_leaf_path);
    }
    if (paths->root_owned_event_path[0] != '\0') {
        (void)unlink(paths->root_owned_event_path);
    }
    if (paths->root_owned_directory[0] != '\0') {
        (void)rmdir(paths->root_owned_directory);
    }
    if (paths->symlink_path[0] != '\0') {
        (void)unlink(paths->symlink_path);
    }
    if (paths->ancestor_symlink[0] != '\0') {
        (void)unlink(paths->ancestor_symlink);
    }
    if (paths->fifo_path[0] != '\0') {
        (void)unlink(paths->fifo_path);
    }
    if (paths->event_path[0] != '\0') {
        (void)unlink(paths->event_path);
    }
    if (paths->unsafe_directory[0] != '\0') {
        (void)rmdir(paths->unsafe_directory);
    }
    if (paths->private_directory[0] != '\0') {
        (void)rmdir(paths->private_directory);
    }
    if (paths->root[0] != '\0') {
        (void)rmdir(paths->root);
    }
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
    if (unlink(paths.event_path) != 0 ||
        !create_permissive_fixture(paths.event_path) ||
        !check_repaired_event_file(paths.event_path)) {
        (void)fprintf(stderr, "existing event-file permission repair failed\n");
        goto cleanup;
    }
    if (symlink("events.jsonl", paths.symlink_path) != 0 ||
        symlink(paths.private_directory, paths.ancestor_symlink) != 0 ||
        mkfifo(paths.fifo_path, 0600) != 0 ||
        !check_rejected_paths(paths.symlink_path, paths.ancestor_event_path,
            paths.fifo_path, paths.unsafe_path, paths.traversal_path,
            paths.private_directory)) {
        (void)fprintf(stderr, "unsafe event-file path was accepted\n");
        goto cleanup;
    }
    if (!check_root_owned_parent_controls(paths.root,
            paths.root_owned_event_path, paths.root_owned_leaf_path)) {
        (void)fprintf(stderr, "root-owned event parent control failed\n");
        goto cleanup;
    }

    result = 0;
    puts("private event-file descriptor controls: passed");

cleanup:
    cleanup_test_paths(&paths);
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
