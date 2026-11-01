/* Test-only GNU link wrap of the genuine Common private sink operation.
 * Keeps -Bsymbolic-functions and every productive admission check unchanged.
 * No phase or host association can be inferred from this path-only API. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "msconnector/event_jsonl.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static _Atomic unsigned records;
static int safe_root(const char *root) {
    char resolved[4096]; struct stat st;
    return root != NULL && root[0] == '/' && realpath(root,resolved) != NULL &&
        strcmp(root,resolved) == 0 && lstat(root,&st) == 0 && S_ISDIR(st.st_mode) &&
        st.st_uid == geteuid() && (st.st_mode & 0022) == 0;
}
static int private_path(const char *path) {
    const char *root=getenv("I12_SINK_ROOT");
    if (root == NULL || !safe_root(root) || path == NULL) return 0;
    size_t length=strlen(root);
    return strncmp(path,root,length) == 0 && path[length] == '/' &&
        strstr(path,"/../") == NULL && strstr(path,"/./") == NULL;
}
static int admitted(const char *path) {
    const char *marker=getenv("I12_SINK_MARKER");
    const char *target=getenv("I12_SINK_PATH");
    const char *mode=getenv("I12_SINK_FAULT");
    const char expected[]="I12_APACHE_SINK_FAULT_V1\n"; char value[sizeof(expected)]={0};
    struct stat st; int saved=errno; int ok=0;
    if (!private_path(marker) || target == NULL || mode == NULL || path == NULL || strcmp(path,target) ||
        (!private_path(target) && strcmp(target,"/dev/full")) ||
        (strcmp(mode,"observe") && strcmp(mode,"closed-descriptor") && strcmp(mode,"physical-enospc"))) goto done;
    int fd=(int)syscall(SYS_openat,AT_FDCWD,marker,O_RDONLY|O_CLOEXEC|O_NOFOLLOW,0);
    if (fd<0) goto done;
    if (fstat(fd,&st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 0777) == 0600 &&
        syscall(SYS_read,fd,value,sizeof(value)) == (long)sizeof(expected)-1 &&
        !memcmp(value,expected,sizeof(expected)-1)) ok=1;
    (void)syscall(SYS_close,fd);
done: errno=saved; return ok;
}
static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC,&now) != 0) return 0;
    return (uint64_t)now.tv_sec*UINT64_C(1000000000)+(uint64_t)now.tv_nsec;
}
static int quoted_path(char *out,size_t capacity,const char *path) {
    size_t used=0; size_t length=strnlen(path,241);
    if (length>240) { (void)snprintf(out,capacity,"null"); return 1; }
    out[used++]='"';
    for (size_t i=0;i<length;++i) {
        unsigned char c=(unsigned char)path[i];
        if (c<32 || c>=127 || c=='"' || c=='\\') {
            if (capacity-used<7) return -1;
            (void)snprintf(out+used,capacity-used,"\\u%04x",(unsigned)c);
            used+=6;
        } else {
            if (capacity-used<2) return -1;
            out[used++]=(char)c;
        }
    }
    out[used++]='"';out[used]='\0';return 0;
}
extern int __real_msconnector_open_private_event_file(const char *,int *);
int __wrap_msconnector_open_private_event_file(const char *path,int *out_fd) {
    int initial=errno; int scoped=admitted(path); uint64_t entered=monotonic_ns();
    errno=initial;
    int result=__real_msconnector_open_private_event_file(path,out_fd);
    int saved=errno; uint64_t returned=monotonic_ns();
    unsigned observation=scoped?atomic_fetch_add(&records,1)+1:0;
    if (observation && observation<=1024) {
        /* out_fd is output-only: reading its uninitialized entry value would be
         * undefined. Common's public failure contract guarantees -1 on return. */
        int fd=out_fd != NULL?*out_fd:-1;
        char line[3072]; char resource[1500]; char valid[16]="null"; char descriptor[32]="null";
        int truncated=quoted_path(resource,sizeof(resource),path);
        if (out_fd != NULL) {
            (void)snprintf(descriptor,sizeof(descriptor),"%d",fd);
            (void)snprintf(valid,sizeof(valid),"%s",fd>=0 && fcntl(fd,F_GETFD)>=0?"true":"false");
        }
        int length=snprintf(line,sizeof(line),"I12_APACHE_COMMON {\"schema\":\"apache-common-sink-boundary-v1\","
            "\"pid\":%ld,\"tid\":%ld,\"uid\":%ld,\"gid\":%ld,\"sequence\":%u,"
            "\"function\":\"msconnector_open_private_event_file\",\"entered_ns\":%" PRIu64 ",\"return_ns\":%" PRIu64 ","
            "\"result\":%d,\"errno_at_return\":%d,\"out_fd_present\":%s,\"out_fd\":%s,"
            "\"fd_valid_before\":null,\"fd_valid_after\":%s,\"resource_path\":%s,\"resource_path_truncated\":%s,"
            "\"phase\":null,\"allocation_scope_call\":null,\"native_transaction\":null,"
            "\"real_function_address\":\"%p\",\"operation\":\"actual_common_private_open\",\"apr_open_observed\":false}\n",
            (long)getpid(),syscall(SYS_gettid),(long)geteuid(),(long)getegid(),observation,
            entered,returned,result,saved,out_fd?"true":"false",descriptor,valid,resource,truncated?"true":"false",
            (void *)&__real_msconnector_open_private_event_file);
        if (truncated>=0 && length>0 && (size_t)length<sizeof(line))
            (void)syscall(SYS_write,STDERR_FILENO,line,(size_t)length);
    }
    errno=saved; return result;
}
