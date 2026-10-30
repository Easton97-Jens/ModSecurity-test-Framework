/* Shared private capture output boundary; keep beside copied observer sources. */
#ifndef LIGHTTPD_I12_TRANSPORT_OBSERVATION_FILE_H
#define LIGHTTPD_I12_TRANSPORT_OBSERVATION_FILE_H

#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int observation_file(const char *path) {
    char copy[PATH_MAX];
    if (path == NULL || strncmp(path, "/task/", 6U) != 0 || strlen(path) >= sizeof(copy)) return -1;
    memcpy(copy, path + 6U, strlen(path + 6U) + 1U);
    int parent = open("/task", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const char *part = copy;
    for (;;) {
        struct stat details;
        const char *slash = strchr(part, '/');
        if (slash != NULL) copy[slash - copy] = '\0';
        if (parent < 0 || fstat(parent, &details) != 0 || details.st_uid != geteuid() ||
            (details.st_mode & 0777U) != 0700U || *part == '\0' ||
            strcmp(part, ".") == 0 || strcmp(part, "..") == 0) break;
        if (slash == NULL) {
            int fd = openat(parent, part, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
            (void)close(parent);
            if (fd >= 0 && (fstat(fd, &details) != 0 || !S_ISREG(details.st_mode) ||
                details.st_uid != geteuid() || (details.st_mode & 0777U) != 0600U || details.st_nlink != 1)) {
                (void)close(fd);
                return -1;
            }
            return fd;
        }
        int next = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        (void)close(parent);
        parent = next;
        part = slash + 1;
    }
    if (parent >= 0) (void)close(parent);
    return -1;
}

#endif
