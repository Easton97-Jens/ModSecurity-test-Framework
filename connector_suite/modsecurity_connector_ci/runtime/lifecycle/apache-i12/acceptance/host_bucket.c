/* Test-only extension; GNU --wrap=apache_lifecycle_observe. No bucket reads,
 * payload capture, shared observer edits, or productive return substitutions. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "mod_security3.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define RECORD_LIMIT 4096U
struct budget { atomic_uint records; atomic_int overflow; };
static struct budget *budget;
static int directory_fd=-1;
static int marker_fd=-1;
static char run_id[129];
static char case_id[193];
static const char marker[]="I12_APACHE_HOST_BUCKET_V1\n";
extern uint64_t msconnector_lifecycle_host_scope_call(const void *);
extern void __real_apache_lifecycle_observe(const char *,msc_t *,request_rec *,const apr_bucket *);

static uint64_t now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC,&value)!=0) return 0;
    return (uint64_t)value.tv_sec*UINT64_C(1000000000)+(uint64_t)value.tv_nsec;
}
static int safe(const char *s,size_t capacity,const char *allowed) {
    return s && strnlen(s,capacity)<capacity && strspn(s,allowed)==strlen(s);
}
static int private_owner(const struct stat *st,mode_t type,mode_t permissions) {
    return (st->st_mode&S_IFMT)==type && (st->st_mode&07777)==permissions &&
        (st->st_uid==0 || st->st_uid==geteuid()) && (type==S_IFDIR || st->st_nlink==1);
}
static int guard(void) {
    struct stat st; char data[sizeof(marker)];
    return budget && run_id[0] && case_id[0] && directory_fd>=0 && marker_fd>=0 &&
        fstat(directory_fd,&st)==0 && private_owner(&st,S_IFDIR,0700) &&
        fstat(marker_fd,&st)==0 && private_owner(&st,S_IFREG,0600) &&
        syscall(SYS_pread64,marker_fd,data,sizeof(data),0)==(long)sizeof(marker)-1 &&
        !memcmp(data,marker,sizeof(marker)-1);
}
__attribute__((constructor)) static void admit(void) {
    int saved=errno; char resolved[4096]; struct stat st;
    const char *root=getenv("I12_APACHE_BUCKET_ROOT");
    const char *run=getenv("I12_APACHE_BUCKET_RUN");
    const char *fixture=getenv("I12_APACHE_BUCKET_CASE");
    const char allowed[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
    if (!root || root[0]!='/' || !realpath(root,resolved) || strcmp(root,resolved) ||
        !safe(run,sizeof(run_id),allowed) || !*run ||
        !safe(fixture,sizeof(case_id),allowed) || !*fixture) goto done;
    directory_fd=open(root,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (directory_fd<0 || fstat(directory_fd,&st)!=0 || !private_owner(&st,S_IFDIR,0700)) goto done;
    marker_fd=openat(directory_fd,"host-bucket.enable",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (marker_fd<0) goto done;
    budget=mmap(NULL,sizeof(*budget),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if (budget==MAP_FAILED) { budget=NULL; goto done; }
    atomic_init(&budget->records,0); atomic_init(&budget->overflow,0);
    if (!atomic_is_lock_free(&budget->records) || !atomic_is_lock_free(&budget->overflow)) { budget=NULL; goto done; }
    strcpy(run_id,run); strcpy(case_id,fixture);
done: errno=saved;
}
static int reserve(void) {
    unsigned count=atomic_load(&budget->records);
    while (count<RECORD_LIMIT) {
        if (atomic_compare_exchange_weak(&budget->records,&count,count+1)) return 1;
    }
    if (!atomic_exchange(&budget->overflow,1)) {
        const char line[]="{\"schema\":\"apache-host-bucket-v1\",\"kind\":\"record_limit_reached\",\"invalid\":true,\"limit\":4096}\n";
        (void)syscall(SYS_write,STDERR_FILENO,line,sizeof(line)-1);
    }
    return 0;
}
static int snapshot_fields(char *fields,size_t capacity,const char *kind,msc_t *msr,
    const request_rec *r,const apr_bucket *bucket,uint64_t *snapshot) {
    char quoted_kind[100]="null";
    char uri[300]="null";
    char type[100]="null";
    char length[40]="null";
    char scope[32]="null";
    if (safe(kind,65,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"))
        (void)snprintf(quoted_kind,sizeof(quoted_kind),"\"%s\"",kind);
    if (r && safe(r->uri,257,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-."))
        (void)snprintf(uri,sizeof(uri),"\"%s\"",r->uri);
    int present=bucket && bucket->type;
    if (present && safe(bucket->type->name,65,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"))
        (void)snprintf(type,sizeof(type),"\"%s\"",bucket->type->name);
    if (present && bucket->length!=(apr_size_t)-1)
        (void)snprintf(length,sizeof(length),"%zu",(size_t)bucket->length);
    uint64_t actual_scope=msconnector_lifecycle_host_scope_call(msr);
    if (actual_scope) (void)snprintf(scope,sizeof(scope),"%" PRIu64,actual_scope);
    *snapshot=now();
    const char *is_file="null";
    const char *is_mmap="null";
    const char *is_heap="null";
    const char *is_metadata="null";
    const char *is_eos="null";
    if (present) {
        is_file=APR_BUCKET_IS_FILE(bucket)?"true":"false";
        is_mmap=APR_BUCKET_IS_MMAP(bucket)?"true":"false";
        is_heap=APR_BUCKET_IS_HEAP(bucket)?"true":"false";
        is_metadata=APR_BUCKET_IS_METADATA(bucket)?"true":"false";
        is_eos=APR_BUCKET_IS_EOS(bucket)?"true":"false";
    }
    int n=snprintf(fields,capacity,"\"observer_kind\":%s,\"request_uri\":%s,"
            "\"host_context_key\":\"%p\",\"request_key\":\"%p\",\"bucket_key\":\"%p\","
            "\"allocation_scope_call\":%s,\"scope_lookup_result\":%" PRIu64 ","
            "\"actual_bucket_present\":%s,\"bucket_type_name\":%s,\"bucket_length\":%s,"
            "\"is_file\":%s,\"is_mmap\":%s,\"is_heap\":%s,\"is_metadata\":%s,\"is_eos\":%s,"
            "\"snapshot_stage\":\"existing_observer_entry\",\"observer_reads_bucket\":false,\"payload_captured\":false",
            quoted_kind,uri,(void *)msr,(const void *)r,(const void *)bucket,scope,actual_scope,
            present?"true":"false",type,length,
            is_file,is_mmap,is_heap,is_metadata,is_eos);
    return n>=0 && (size_t)n<capacity;
}
void __wrap_apache_lifecycle_observe(const char *kind,msc_t *msr,request_rec *r,const apr_bucket *bucket) {
    int initial=errno; char fields[1600]={0}; uint64_t snapshot=0; int ready=guard();
    if (ready) {
        ready=snapshot_fields(fields,sizeof(fields),kind,msr,r,bucket,&snapshot);
    }
    /* Forward every argument exactly once, including when admission fails.
     * Instrumentation before or after the real call cannot change its errno. */
    errno=initial; __real_apache_lifecycle_observe(kind,msr,r,bucket); int saved=errno;
    if (ready && guard() && reserve()) {
        char line[2048];
        int n=snprintf(line,sizeof(line),"{\"schema\":\"apache-host-bucket-v1\",\"kind\":\"bucket_snapshot\","
            "\"pid\":%ld,\"tid\":%ld,\"uid\":%ld,\"run_id\":\"%s\",\"case_id\":\"%s\","
            "\"snapshot_ns\":%" PRIu64 ",\"observer_return_ns\":%" PRIu64 ",\"errno_at_observer_return\":%d,"
            "\"invalid\":false,%s}\n",(long)getpid(),syscall(SYS_gettid),(long)geteuid(),run_id,case_id,
            snapshot,now(),saved,fields);
        if (n>0 && (size_t)n<sizeof(line)) (void)syscall(SYS_write,STDERR_FILENO,line,(size_t)n);
    }
    errno=saved;
}
