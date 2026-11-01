/* Test-only own-worker maps capture after the real successful setuid. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAP_LIMIT (60U * 1024U)
static int output = -1;
static pid_t owner;
static dev_t device;
static ino_t inode;

__attribute__((constructor)) static void admit(void)
{
    const char *fd = getenv("MSCONNECTOR_OWNED_SELF_MAP_FD");
    const char *uid = getenv("MSCONNECTOR_OWNED_SELF_MAP_UID");
    struct stat info;
    char *end = NULL;
    long number;
    if (getuid() != 0 || geteuid() != 0 || fd == NULL || uid == NULL || strcmp(uid, "65534") != 0) return;
    size_t length = strnlen(fd, 11U);
    if (length == 0U || length > 10U || strspn(fd, "0123456789") != length) return;
    number = strtol(fd, &end, 10);
    if (*end != '\0' || number < 3 || number > INT_MAX) return;
    int flags = fcntl((int)number, F_GETFL);
    if (flags < 0 || (flags & O_APPEND) == 0 || (flags & O_ACCMODE) == O_RDONLY ||
        fstat((int)number, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 ||
        info.st_nlink != 1 || (info.st_mode & 07777U) != 0600U || info.st_size != 0) return;
    output = (int)number;
    owner = getpid();
    device = info.st_dev;
    inode = info.st_ino;
}

static ssize_t read_bounded(const char *path, char *buffer, size_t capacity)
{
    int descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    size_t used = 0U;
    if (descriptor < 0) return -1;
    while (used < capacity) {
        ssize_t count = read(descriptor, buffer + used, capacity - used);
        if (count < 0) { close(descriptor); return -1; }
        if (count == 0) { close(descriptor); return (ssize_t)used; }
        used += (size_t)count;
    }
    close(descriptor);
    return -1; /* Complete EOF inside the bound is required. */
}

static unsigned long long starttime(void)
{
    char raw[4096];
    ssize_t count = read_bounded("/proc/self/stat", raw, sizeof(raw) - 1U);
    if (count <= 0) return 0U;
    raw[count] = '\0';
    char *last = strrchr(raw, ')');
    if (last == NULL) return 0U;
    char *save = NULL;
    const char *field = strtok_r(last + 1, " ", &save);
    for (unsigned int index = 0U; index < 19U; ++index) {
        if (field == NULL) return 0U;
        field = strtok_r(NULL, " ", &save);
    }
    if (field == NULL) return 0U;
    size_t length = strnlen(field, sizeof(raw));
    if (length == 0U || length >= sizeof(raw) || strspn(field, "0123456789") != length) return 0U;
    return strtoull(field, NULL, 10);
}

static void capture(void)
{
    struct stat info;
    int flags = fcntl(output, F_GETFL);
    if (output < 3 || getppid() != owner || getuid() != 65534 || geteuid() != 65534 ||
        getgid() != 65534 || getegid() != 65534 || flags < 0 || (flags & O_APPEND) == 0 ||
        fstat(output, &info) != 0 || info.st_dev != device || info.st_ino != inode ||
        info.st_nlink != 1 || info.st_uid != 0 || (info.st_mode & 07777U) != 0600U || info.st_size != 0) return;
    unsigned long long started = starttime();
    if (started == 0U) return;
    char *record = malloc(MAP_LIMIT + 1024U);
    if (record == NULL) return;
    ssize_t size = read_bounded("/proc/self/maps", record + 1024U, MAP_LIMIT);
    if (size <= 0) { free(record); return; }
    int header = snprintf(record, 1024U,
        "{\"version\":1,\"pid\":%ld,\"ppid\":%ld,\"uid\":%lu,\"gid\":%lu,\"starttime\":%llu,\"bytes\":%zu}\n",
        (long)getpid(), (long)getppid(), (unsigned long)getuid(), (unsigned long)getgid(), started, (size_t)size);
    if (header > 0 && header < 1024) {
        memmove(record + header, record + 1024U, (size_t)size);
        ssize_t written = write(output, record, (size_t)header + (size_t)size);
        if (written != header + size) {
            static const char message[] = "worker-self-maps: incomplete capture\n";
            (void)write(STDERR_FILENO, message, sizeof(message) - 1U);
        }
    }
    free(record);
}

int setuid(uid_t uid)
{
    int (*original)(uid_t);
    *(void **)(&original) = dlsym(RTLD_NEXT, "setuid");
    if (original == NULL) { errno = ENOSYS; return -1; }
    int result = original(uid);
    int saved = errno;
    if (result == 0 && uid == 65534 && output >= 3) capture();
    errno = saved;
    return result;
}
