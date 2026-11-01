/* Apache-only test observer. Actual RTLD_NEXT returns are never changed.
 * Plaintext HTTP/1 CL-framed loopback traffic only. No body/header/log payload
 * is emitted. This supplements the existing native/host capture, not its joins. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <apr_network_io.h>
#include <apr_portable.h>
#include <apr_version.h>
#include <modsecurity/transaction.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define CAPACITY 128U
#define HEADER_BYTES 8192U
#define RECORD_LIMIT 16384U
struct budget { atomic_uint records; atomic_int invalid; };
struct request { uint64_t sequence; char method[16]; char uri[256]; };
struct parser { char header[HEADER_BYTES]; size_t used; uint64_t remaining; int unsupported; };
struct connection {
    dev_t device; ino_t inode; int fd; int occupied;
    unsigned short local_port; unsigned short peer_port;
    uint64_t requests; uint64_t responses; struct request queue[8]; unsigned head; unsigned count;
    struct parser input; struct parser output; int status;
};
struct native { const Transaction *key; int phase; char id[256]; const char *id_source; };
static struct connection connections[CAPACITY];
static struct native natives[CAPACITY];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct budget *budget;
static int output_fd = -1;
static dev_t output_device; static ino_t output_inode;
static uint64_t sequence;
static _Thread_local unsigned internal;
static _Thread_local unsigned apr_depth;
static _Thread_local unsigned syscall_seen;
static _Thread_local uint64_t parent_call;
static _Thread_local uint64_t wire_call;
static _Thread_local int apr_fd=-1;
static _Thread_local char renderer_identity[900]="null";

static uint64_t now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
static void invalid(void) { if (budget != NULL) atomic_store(&budget->invalid, 1); }
static int safe_string(const char *value, size_t bound, const char *allowed) {
    return value != NULL && strnlen(value, bound) < bound && strspn(value, allowed) == strlen(value);
}
static void *symbol(const char *name) {
    ++internal; void *result = dlsym(RTLD_NEXT, name); --internal;
    if (result == NULL) {
        const char message[] = "apache-host-io: required real symbol missing\n";
        (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message)-1U); _exit(78);
    }
    return result;
}
static int output_valid(void) {
    struct stat info; int flags = fcntl(output_fd, F_GETFL);
    return output_fd >= 0 && fstat(output_fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_nlink == 1 && (info.st_mode & 07777) == 0600 &&
        info.st_dev == output_device && info.st_ino == output_inode && flags >= 0 && (flags & O_APPEND);
}
static void emit(const char *kind, const char *fields) {
    if (output_fd < 0 || budget == NULL) return;
    if (!output_valid() || atomic_fetch_add(&budget->records, 1) >= RECORD_LIMIT) { invalid(); return; }
    char record[3072];
    int length = snprintf(record, sizeof(record),
        "{\"schema\":\"apache-host-io-v1\",\"pid\":%ld,\"tid\":%ld,\"uid\":%ld,"
        "\"sequence\":%" PRIu64 ",\"monotonic_ns\":%" PRIu64 ",\"kind\":\"%s\","
        "\"invalid\":%s,%s}\n", (long)getpid(), syscall(SYS_gettid), (long)geteuid(),
        ++sequence, now(), kind, atomic_load(&budget->invalid) ? "true":"false", fields);
    if (length <= 0 || (size_t)length >= sizeof(record) ||
        syscall(SYS_write, output_fd, record, (size_t)length) != length) invalid();
}
static void image_identity(void *address,char *output,size_t capacity) {
    Dl_info image={0}; struct stat info;
    strcpy(output,"null");
    if (!dladdr(address,&image) || !safe_string(image.dli_fname,512,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-+.") || stat(image.dli_fname,&info)!=0) return;
    int length=snprintf(output,capacity,"{\"image\":\"%s\",\"device\":%ju,\"inode\":%ju,\"size\":%jd,"
        "\"address\":\"%p\",\"image_offset\":%ju}",image.dli_fname,(uintmax_t)info.st_dev,
        (uintmax_t)info.st_ino,(intmax_t)info.st_size,address,
        (uintmax_t)((uintptr_t)address-(uintptr_t)image.dli_fbase));
    if (length<0 || (size_t)length>=capacity) strcpy(output,"null");
}
/* The trace is collected on this actual outgoing return stack. Compact frame
 * addresses and dladdr image bases retain bounded provenance without payload.
 * Only an exact resolved Apache symbol can identify its default renderer. */
static void outgoing_stack(uint64_t call) {
    void *frames[48]; int count=backtrace(frames,48);
    char trace[1900]={0}; size_t used=0; int truncated=0;
    strcpy(renderer_identity,"null");
    for (int index=0;index<count;++index) {
        Dl_info image={0}; int resolved=dladdr(frames[index],&image);
        if (resolved && image.dli_sname && !strcmp(image.dli_sname,"ap_send_error_response")) {
            char identity[750]; image_identity(frames[index],identity,sizeof(identity));
            if (strcmp(identity,"null")) (void)snprintf(renderer_identity,sizeof(renderer_identity),
                "{\"symbol\":\"ap_send_error_response\",\"frame_index\":%d,\"symbol_offset\":%ju,\"loaded_image\":%s}",
                index,(uintmax_t)((uintptr_t)frames[index]-(uintptr_t)image.dli_saddr),identity);
        }
        if (index>=16) continue;
        int length=snprintf(trace+used,sizeof(trace)-used,"%s[\"%p\",\"%p\",%ju]",index?",":"",
            frames[index],resolved?image.dli_fbase:NULL,
            resolved?(uintmax_t)((uintptr_t)frames[index]-(uintptr_t)image.dli_fbase):0);
        if (length<0 || (size_t)length>=sizeof(trace)-used) { truncated=1; break; }
        used+=(size_t)length;
    }
    char fields[2800];
    int length=snprintf(fields,sizeof(fields),"\"call\":%" PRIu64 ",\"captured_depth\":%d,"
        "\"retained_frame_limit\":16,\"frame_columns\":[\"address\",\"dladdr_image_base\",\"image_offset\"],"
        "\"frames\":[%s],\"trace_truncated\":%s,\"renderer_identity\":%s,"
        "\"scope\":\"actual successful outgoing socket return call stack\"",call,count,
        truncated?"":trace,(truncated || count>16)?"true":"false",renderer_identity);
    if (length>0 && (size_t)length<sizeof(fields)) emit("outgoing_return_stack",fields); else invalid();
}
static int private_directory(const char *root) {
    char resolved[4096]; struct stat info;
    return root != NULL && root[0] == '/' && realpath(root, resolved) != NULL && !strcmp(root,resolved) &&
        lstat(root,&info) == 0 && S_ISDIR(info.st_mode) && (info.st_uid == 0 || info.st_uid == geteuid()) &&
        (info.st_mode & 07777) == 0700;
}
static int marker_valid(int directory) {
    const char expected[] = "I12_APACHE_HOST_IO_V1\n"; char data[sizeof(expected)]; struct stat info;
    int fd = openat(directory,"host-io.enable",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) return 0;
    int ok = fstat(fd,&info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1 &&
        (info.st_uid == 0 || info.st_uid == geteuid()) && (info.st_mode & 07777) == 0600 &&
        syscall(SYS_read,fd,data,sizeof(data)) == (long)sizeof(expected)-1 &&
        !memcmp(data,expected,sizeof(expected)-1);
    (void)syscall(SYS_close,fd); return ok;
}
static void before_fork(void) { (void)pthread_mutex_lock(&lock); }
static void after_fork(void) { (void)pthread_mutex_unlock(&lock); }
static void child_fork(void) {
    memset(connections,0,sizeof(connections)); memset(natives,0,sizeof(natives)); sequence=0;
    internal=0; apr_depth=0; parent_call=0; syscall_seen=0; (void)pthread_mutex_unlock(&lock);
}
__attribute__((constructor)) static void admit(void) {
    int saved=errno; ++internal;
    const char *root=getenv("I12_APACHE_IO_ROOT");
    if (!private_directory(root)) goto done;
    int directory=open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (directory < 0) goto done;
    if (!marker_valid(directory)) { (void)syscall(SYS_close,directory); goto done; }
    int fd=openat(directory,"host-io.jsonl",O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    (void)syscall(SYS_close,directory); struct stat info;
    if (fd < 0) goto done;
    if (fstat(fd,&info) != 0 || !S_ISREG(info.st_mode) || info.st_nlink != 1 ||
        (info.st_uid != 0 && info.st_uid != geteuid()) || (info.st_mode & 07777) != 0600) {
        (void)syscall(SYS_close,fd); goto done;
    }
    budget=mmap(NULL,sizeof(*budget),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if (budget == MAP_FAILED) { budget=NULL; (void)syscall(SYS_close,fd); goto done; }
    atomic_init(&budget->records,0); atomic_init(&budget->invalid,0);
    if (!atomic_is_lock_free(&budget->records) || !atomic_is_lock_free(&budget->invalid)) {
        (void)syscall(SYS_close,fd); goto done;
    }
    output_fd=fd; output_device=info.st_dev; output_inode=info.st_ino;
    if (pthread_atfork(before_fork,after_fork,child_fork) != 0) invalid();
    emit("admitted","\"plaintext_http1_only\":true,\"native_join\":\"existing_capture_required\"");
done: --internal; errno=saved;
}
__attribute__((destructor)) static void finish(void) {
    int saved=errno; ++internal; (void)pthread_mutex_lock(&lock);
    emit("final","\"observer_destructor_reached\":true,\"process_exit_confirmed\":false");
    if (output_fd >= 0) (void)syscall(SYS_close,output_fd);
    output_fd=-1; (void)pthread_mutex_unlock(&lock); --internal; errno=saved;
}
static int loopback(int fd, struct sockaddr_in *local, struct sockaddr_in *peer, struct stat *info) {
    socklen_t size=sizeof(*peer);
    int type=0; socklen_t type_size=sizeof(type);
    if (getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&type_size) != 0 || type != SOCK_STREAM) return 0;
    if (fd < 0 || fstat(fd,info) != 0 || !S_ISSOCK(info->st_mode) ||
        getpeername(fd,(struct sockaddr *)peer,&size) != 0 || peer->sin_family != AF_INET ||
        (ntohl(peer->sin_addr.s_addr) >> 24) != 127) return 0;
    size=sizeof(*local);
    return getsockname(fd,(struct sockaddr *)local,&size) == 0 && local->sin_family == AF_INET &&
        (ntohl(local->sin_addr.s_addr) >> 24) == 127;
}
static struct connection *connection(int fd) {
    struct sockaddr_in local; struct sockaddr_in peer; struct stat info;
    if (fstat(fd,&info) != 0 || !S_ISSOCK(info.st_mode)) return NULL;
    struct connection *available=NULL;
    for (size_t i=0;i<CAPACITY;++i) {
        struct connection *entry=&connections[i];
        if (entry->occupied && entry->device == info.st_dev && entry->inode == info.st_ino) return entry;
        if (!entry->occupied && available == NULL) available=entry;
    }
    if (!loopback(fd,&local,&peer,&info)) return NULL;
    if (available == NULL) { invalid(); return NULL; }
    *available=(struct connection){.device=info.st_dev,.inode=info.st_ino,.fd=fd,.occupied=1,
        .local_port=ntohs(local.sin_port),.peer_port=ntohs(peer.sin_port)};
    return available;
}
static void wire_record(struct connection *c,const char *kind) {
    char fields[2200];
    char status[16]="null";
    char uri[300]="null";
    char method[40]="null";
    char request[32]="null";
    if (c->status) (void)snprintf(status,sizeof(status),"%d",c->status);
    if (c->count) {
        struct request *r=&c->queue[c->head];
        (void)snprintf(request,sizeof(request),"%" PRIu64,r->sequence);
        if (r->uri[0]) (void)snprintf(uri,sizeof(uri),"\"%s\"",r->uri);
        if (r->method[0]) (void)snprintf(method,sizeof(method),"\"%s\"",r->method);
    }
    const char *framing="null";
    if (!strcmp(kind,"response_headers_sent")) framing=c->output.unsupported?"false":"true";
    (void)snprintf(fields,sizeof(fields),"\"fd\":%d,\"socket_inode\":%ju,\"local_port\":%u,\"peer_port\":%u,"
        "\"request_sequence\":%s,\"request_uri\":%s,\"request_method\":%s,\"response_sequence\":%" PRIu64 ","
        "\"http_status\":%s,\"body_framing_supported\":%s,\"renderer_identity\":%s,"
        "\"actual_successful_socket_bytes\":true,\"parent_call\":%" PRIu64,
        c->fd,(uintmax_t)c->inode,c->local_port,c->peer_port,request,uri,method,c->responses,status,framing,renderer_identity,wire_call);
    emit(kind,fields);
}
static int content_length(const char *header,uint64_t *remaining) {
    const char *p=strstr(header,"\r\n"); int found=0;
    if (!p) return 0;
    for (p+=2;*p && strncmp(p,"\r\n",2);) {
        const char *end=strstr(p,"\r\n"); if (!end) return 0;
        if (!strncasecmp(p,"Transfer-Encoding:",18)) return 0;
        if (!strncasecmp(p,"Content-Length:",15)) {
            const char *number=p+15; while (*number==' ' || *number=='\t') ++number;
            char *last=NULL; errno=0; unsigned long long value=strtoull(number,&last,10);
            if (found || errno || last==number || last!=end || *number<'0' || *number>'9') return 0;
            *remaining=(uint64_t)value; found=1;
        }
        p=end+2;
    }
    return found;
}
static void input_header(struct connection *c) {
    char method[16];
    char uri[256];
    char protocol[16];
    if (sscanf(c->input.header,"%15s %255s %15s",method,uri,protocol) != 3 ||
        (strcmp(protocol,"HTTP/1.1") && strcmp(protocol,"HTTP/1.0")) || c->count == 8) {
        c->input.unsupported=1; return;
    }
    struct request *r=&c->queue[(c->head+c->count)%8]; memset(r,0,sizeof(*r));
    r->sequence=++c->requests; ++c->count;
    if (safe_string(method,sizeof(method),"ABCDEFGHIJKLMNOPQRSTUVWXYZ")) strcpy(r->method,method);
    if (safe_string(uri,sizeof(uri),"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-.")) strcpy(r->uri,uri);
    /* No CL means a zero-body request only for methods without entity data. */
    if (!content_length(c->input.header,&c->input.remaining) &&
        (strcasestr(c->input.header,"\r\nTransfer-Encoding:") ||
         (strcmp(method,"GET") && strcmp(method,"HEAD")))) c->input.unsupported=1;
    wire_record(c,"request_headers_received");
}
static void output_header(struct connection *c) {
    int status=0;
    if (sscanf(c->output.header,"HTTP/1.%*1[01] %3d",&status) != 1 || status<100 || status>599) {
        c->output.unsupported=1; return;
    }
    c->status=status;
    int no_body=status<200 || status==204 || status==304 ||
        (c->count && !strcmp(c->queue[c->head].method,"HEAD"));
    if (!no_body && !content_length(c->output.header,&c->output.remaining)) c->output.unsupported=1;
    wire_record(c,"response_headers_sent");
    if (status<200) c->status=0;
}
static void feed_status_line(struct connection *c,const struct parser *p) {
    if (c->status || p->used<2 || p->header[p->used-1]!='\n') return;
    int status=0;
    if (sscanf(p->header,"HTTP/1.%*1[01] %3d",&status)!=1 || status<100 || status>599) return;
    c->status=status;
    if (status>=200) ++c->responses;
    wire_record(c,"response_status_line_sent");
}
static void feed(struct connection *c,int incoming,const unsigned char *data,size_t size) {
    struct parser *p=incoming?&c->input:&c->output;
    for (size_t i=0;i<size && !p->unsupported;++i) {
        if (p->remaining) { --p->remaining; continue; }
        if (p->used == 0 && !incoming && c->status>=200 && c->count) {
            c->head=(c->head+1)%8; --c->count; c->status=0;
        }
        if (p->used+1>=sizeof(p->header)) { p->unsupported=1; invalid(); break; }
        p->header[p->used++]=(char)data[i]; p->header[p->used]='\0';
        if (!incoming) feed_status_line(c,p);
        if (p->used>=4 && !memcmp(p->header+p->used-4,"\r\n\r\n",4)) {
            if (incoming) input_header(c); else output_header(c);
            p->used=0;
        }
    }
}
static uint64_t call_number(void) {
    uint64_t result; (void)pthread_mutex_lock(&lock); result=++sequence;
    (void)pthread_mutex_unlock(&lock); return result;
}
struct transport_call {
    const char *name;
    void *real;
    int fd;
    int incoming;
    int apr;
    long result;
    int return_errno;
    size_t requested;
    size_t reported;
    int bytes_known;
    const struct iovec *vectors;
    int count;
    uint64_t call;
    uint64_t entered;
    int parse;
};
static void feed_transport(struct connection *c,const struct transport_call *t) {
    if (!t->parse || !t->bytes_known || !t->reported) return;
    size_t remaining=t->reported;
    wire_call=t->call;
    for (int i=0;i<t->count;++i) {
        if (!remaining) break;
        size_t n=t->vectors[i].iov_len<remaining?t->vectors[i].iov_len:remaining;
        feed(c,t->incoming,t->vectors[i].iov_base,n); remaining-=n;
    }
    if (remaining) c->output.unsupported=1;
    wire_call=0;
}
static void transport(const struct transport_call *t) {
    if (output_fd<0 || internal) return;
    int saved=errno; ++internal; (void)pthread_mutex_lock(&lock);
    struct connection *c=connection(t->fd);
    if (c != NULL) {
        if (!t->incoming && t->bytes_known && t->reported) outgoing_stack(t->call);
        else strcpy(renderer_identity,"null");
        Dl_info image={0}; char object[600]="null";
        if (dladdr(t->real,&image) && safe_string(image.dli_fname,512,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-+."))
            (void)snprintf(object,sizeof(object),"\"%s\"",image.dli_fname);
        char fields[1536];
        char requested_bytes[32];
        if (!t->apr && t->result<0 && (!strcmp(t->name,"writev") || !strcmp(t->name,"readv")))
            strcpy(requested_bytes,"null");
        else (void)snprintf(requested_bytes,sizeof(requested_bytes),"%zu",t->requested);
        (void)snprintf(fields,sizeof(fields),"\"function\":\"%s\",\"layer\":\"%s\",\"call\":%" PRIu64 ","
            "\"parent_call\":%" PRIu64 ",\"entered_ns\":%" PRIu64 ",\"return_ns\":%" PRIu64 ","
            "\"fd\":%d,\"socket_inode\":%ju,\"local_port\":%u,\"peer_port\":%u,"
            "\"result\":%ld,\"errno_at_return\":%d,\"requested_bytes\":%s,\"reported_bytes\":%zu,"
            "\"written_bytes_known\":%s,\"real_symbol_object\":%s,\"real_symbol_address\":\"%p\","
            "\"apr_version\":\"%s\",\"stream_accounted_here\":%s",t->name,t->apr?"apr":"libc",t->call,parent_call,
            t->entered,now(),t->fd,(uintmax_t)c->inode,c->local_port,c->peer_port,t->result,t->return_errno,requested_bytes,t->reported,
            t->bytes_known?"true":"false",object,t->real,apr_version_string(),t->parse?"true":"false");
        emit("transport_return",fields);
        feed_transport(c,t);
        strcpy(renderer_identity,"null");
    }
    (void)pthread_mutex_unlock(&lock); --internal; errno=saved;
}
static void prepare_transport(int fd) {
    if (output_fd<0 || internal) return;
    int saved=errno; ++internal; (void)pthread_mutex_lock(&lock);
    (void)connection(fd); (void)pthread_mutex_unlock(&lock); --internal; errno=saved;
}
static size_t vector_size(const struct iovec *v,int count) {
    size_t size=0; if (!v || count<0 || count>1024) return 0;
    for (int i=0;i<count;++i) {
        if (v[i].iov_len>SIZE_MAX-size) return 0;
        size+=v[i].iov_len;
    }
    return size;
}
#define BUFFER_WRAPPER(name, signature, arguments, fd_arg, incoming, parse_bytes) \
ssize_t name signature { \
    int initial=errno; ssize_t (*real_call) signature=symbol(#name); \
    if (internal || output_fd<0) { errno=initial; return real_call arguments; } \
    prepare_transport(fd_arg); uint64_t entered=now(); uint64_t call=call_number(); errno=initial; \
    ssize_t result=real_call arguments; int saved=errno; \
    if (apr_depth && fd==apr_fd) syscall_seen=1; \
    struct iovec vector={(void *)buffer,size}; \
    transport(&(const struct transport_call){#name,(void *)&*real_call,fd_arg,incoming,0,result,saved,size,result>0?(size_t)result:0,result>=0, \
        &vector,1,call,entered,parse_bytes}); errno=saved; return result; \
}
BUFFER_WRAPPER(send,(int fd,const void *buffer,size_t size,int flags),(fd,buffer,size,flags),fd,0,!(flags&MSG_OOB))
BUFFER_WRAPPER(recv,(int fd,void *buffer,size_t size,int flags),(fd,buffer,size,flags),fd,1,!(flags&(MSG_PEEK|MSG_TRUNC|MSG_OOB)))
BUFFER_WRAPPER(write,(int fd,const void *buffer,size_t size),(fd,buffer,size),fd,0,1)
BUFFER_WRAPPER(read,(int fd,void *buffer,size_t size),(fd,buffer,size),fd,1,1)
#define VECTOR_WRAPPER(name, incoming) \
ssize_t name(int fd,const struct iovec *vectors,int count) { \
    int initial=errno; ssize_t (*real_call)(int,const struct iovec *,int)=symbol(#name); \
    if (internal || output_fd<0) { errno=initial; return real_call(fd,vectors,count); } \
    prepare_transport(fd); uint64_t entered=now(); uint64_t call=call_number(); errno=initial; ssize_t result=real_call(fd,vectors,count); int saved=errno; \
    if (apr_depth && fd==apr_fd) syscall_seen=1; \
    /* A failed kernel call may have rejected the iovec address itself. */ \
    size_t requested=result>=0?vector_size(vectors,count):0; \
    transport(&(const struct transport_call){#name,(void *)&*real_call,fd,incoming,0,result,saved,requested,result>0?(size_t)result:0, \
        result>=0,result>=0?vectors:NULL,result>=0?count:0,call,entered,result>=0}); errno=saved; return result; \
}
VECTOR_WRAPPER(writev,0)
VECTOR_WRAPPER(readv,1)
static int socket_fd(apr_socket_t *socket) {
    apr_os_sock_t fd=-1; if (apr_os_sock_get(&fd,socket)!=APR_SUCCESS) return -1;
    prepare_transport(fd); return fd;
}
struct apr_scope { uint64_t parent; unsigned seen; int fd; };
static struct apr_scope apr_enter(uint64_t call,int fd) {
    struct apr_scope previous={parent_call,syscall_seen,apr_fd};
    ++apr_depth; syscall_seen=0; parent_call=call; apr_fd=fd; return previous;
}
static int apr_leave(struct apr_scope previous) {
    int parse=!syscall_seen; --apr_depth;
    syscall_seen=previous.seen | syscall_seen; parent_call=previous.parent; apr_fd=previous.fd;
    return parse;
}
#define APR_BUFFER(name, incoming, qualifier) \
apr_status_t name(apr_socket_t *socket,qualifier char *buffer,apr_size_t *size) { \
    int initial=errno; void *real_address=symbol(#name); apr_status_t (*real_call)(apr_socket_t *,qualifier char *,apr_size_t *)=real_address; \
    size_t requested=size?*size:0; int fd=socket_fd(socket); uint64_t entered=now(); uint64_t call=call_number(); struct apr_scope scope=apr_enter(call,fd); \
    errno=initial; apr_status_t result=real_call(socket,buffer,size); int saved=errno; int parse=apr_leave(scope); \
    struct iovec vector={(void *)buffer,requested}; \
    transport(&(const struct transport_call){#name,real_address,fd,incoming,1,result,saved,requested,size?*size:0,result==APR_SUCCESS, \
        &vector,1,call,entered,parse}); errno=saved; return result; \
}
APR_BUFFER(apr_socket_send,0,const)
APR_BUFFER(apr_socket_recv,1,)
typedef apr_status_t (*apr_sendv_function)(apr_socket_t *socket, const struct iovec *vectors,
    apr_int32_t count, apr_size_t *size);
typedef apr_status_t (*apr_sendfile_function)(apr_socket_t *socket, apr_file_t *file,
    apr_hdtr_t *headers, apr_off_t *offset, apr_size_t *size, apr_int32_t flags);
apr_status_t apr_socket_sendv(apr_socket_t *socket,const struct iovec *vectors,apr_int32_t count,apr_size_t *size) {
    int initial=errno; void *real_address=symbol("apr_socket_sendv"); apr_sendv_function real_call=real_address;
    int fd=socket_fd(socket); size_t requested=vector_size(vectors,count); uint64_t entered=now(); uint64_t call=call_number(); struct apr_scope scope=apr_enter(call,fd);
    errno=initial; apr_status_t result=real_call(socket,vectors,count,size); int saved=errno; int parse=apr_leave(scope);
    const struct transport_call observed={"apr_socket_sendv",real_address,fd,0,1,result,saved,requested,size?*size:0,result==APR_SUCCESS,
        vectors,count,call,entered,parse};
    transport(&observed); errno=saved; return result;
}
apr_status_t apr_socket_sendfile(apr_socket_t *socket,apr_file_t *file,apr_hdtr_t *headers,
    apr_off_t *offset,apr_size_t *size,apr_int32_t flags) {
    int initial=errno; void *real_address=symbol("apr_socket_sendfile"); apr_sendfile_function real_call=real_address;
    int fd=socket_fd(socket); size_t requested=size?*size:0; uint64_t entered=now(); uint64_t call=call_number(); struct apr_scope scope=apr_enter(call,fd);
    errno=initial; apr_status_t result=real_call(socket,file,headers,offset,size,flags); int saved=errno; (void)apr_leave(scope);
    const struct transport_call observed={"apr_socket_sendfile",real_address,fd,0,1,result,saved,requested,size?*size:0,result==APR_SUCCESS,
        NULL,0,call,entered,0};
    transport(&observed); errno=saved; return result;
}
static struct native *native_entry(const Transaction *key) {
    struct native *empty=NULL;
    for (size_t i=0;i<CAPACITY;++i) {
        if (natives[i].key==key) return &natives[i];
        if (!natives[i].key && !empty) empty=&natives[i];
    }
    if (empty) empty->key=key; else invalid();
    return empty;
}
ModSecurity *msc_init(void) {
    int initial=errno; void *real_address=symbol("msc_init"); ModSecurity *(*real_call)(void)=real_address;
    void *caller=__builtin_extract_return_addr(__builtin_return_address(0));
    uint64_t entered=now(); errno=initial; ModSecurity *engine=real_call(); int saved=errno; uint64_t returned=now();
    if (output_fd>=0) {
        ++internal;
        const char *(*who)(ModSecurity *)=symbol("msc_who_am_i");
        const char *sdk=engine?who(engine):NULL;
        char version[300]="null"; char real_image[750]; char caller_image[750]; char fields[2200];
        if (safe_string(sdk,256,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /_-.()+"))
            (void)snprintf(version,sizeof(version),"\"%s\"",sdk);
        image_identity(real_address,real_image,sizeof(real_image));
        image_identity(caller,caller_image,sizeof(caller_image));
        (void)pthread_mutex_lock(&lock);
        (void)snprintf(fields,sizeof(fields),"\"function\":\"msc_init\",\"engine_key\":\"%p\","
            "\"result_nonnull\":%s,\"entered_ns\":%" PRIu64 ",\"return_ns\":%" PRIu64 ","
            "\"errno_at_return\":%d,\"sdk_who_am_i\":%s,\"real_sdk_image\":%s,\"actual_caller_image\":%s",
            (void *)engine,engine?"true":"false",entered,returned,saved,version,real_image,caller_image);
        emit("native_engine_init_return",fields);
        (void)pthread_mutex_unlock(&lock); --internal;
    }
    errno=saved; return engine;
}
typedef __typeof__(_Generic(&msc_new_transaction_with_id,
    Transaction *(*)(ModSecurity *,RulesSet *,char *,void *):(char *)0,
    Transaction *(*)(ModSecurity *,RulesSet *,const char *,void *):(const char *)0)) native_id_argument;
static void created(Transaction *transaction,ModSecurity *engine,const char *caller_id) {
    if (output_fd<0 || !transaction) return;
    int saved=errno; ++internal;
    int (*accessor)(void *,const void *,char *,size_t)=dlsym(RTLD_DEFAULT,"msconnector_lifecycle_sdk_transaction_id");
    char id[256]={0}; const char *origin="unknown";
    if (accessor && accessor(engine,transaction,id,sizeof(id))==1) origin="sdk_public_m_id";
    else if (safe_string(caller_id,sizeof(id),"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:")) {
        strcpy(id,caller_id); origin="caller_argument";
    }
    if (!safe_string(id,sizeof(id),"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:")) id[0]='\0';
    (void)pthread_mutex_lock(&lock); struct native *entry=native_entry(transaction);
    if (entry) { strcpy(entry->id,id); entry->id_source=origin; }
    char fields[1200];
    char quoted[300]="null";
    char version[300]="null";
    const char *(*who)(ModSecurity *)=dlsym(RTLD_NEXT,"msc_who_am_i");
    const char *sdk=who?who(engine):NULL;
    if (safe_string(sdk,256,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /_-.()+"))
        (void)snprintf(version,sizeof(version),"\"%s\"",sdk);
    if (id[0]) (void)snprintf(quoted,sizeof(quoted),"\"%s\"",id);
    (void)snprintf(fields,sizeof(fields),"\"transaction_key\":\"%p\",\"transaction_id\":%s,\"transaction_id_source\":\"%s\",\"sdk_version\":%s",
        (void *)transaction,quoted,origin,version);
    emit("native_transaction_created",fields); (void)pthread_mutex_unlock(&lock); --internal; errno=saved;
}
Transaction *msc_new_transaction(ModSecurity *engine,RulesSet *rules,void *data) {
    int initial=errno; Transaction *(*real_call)(ModSecurity *,RulesSet *,void *)=symbol("msc_new_transaction");
    errno=initial; Transaction *transaction=real_call(engine,rules,data); int saved=errno;
    created(transaction,engine,NULL); errno=saved; return transaction;
}
Transaction *msc_new_transaction_with_id(ModSecurity *engine,RulesSet *rules,native_id_argument id,void *data) {
    int initial=errno; __typeof__(&msc_new_transaction_with_id) real_call=symbol("msc_new_transaction_with_id");
    errno=initial; Transaction *transaction=real_call(engine,rules,id,data); int saved=errno;
    created(transaction,engine,id); errno=saved; return transaction;
}
static void native_phase(const Transaction *key,int phase) {
    if (output_fd<0) return;
    (void)pthread_mutex_lock(&lock); struct native *entry=native_entry(key);
    if (entry) entry->phase=phase;
    (void)pthread_mutex_unlock(&lock);
}
/* Optional Apache-test observer.  A plain host-I/O build has no multipart
 * dependency; the combined acceptance build supplies both weak symbols in
 * the same preload image. */
extern void i12_apache_observe_multipart(void *) __attribute__((weak));
extern void i12_apache_observe_multipart_cleanup(void *) __attribute__((weak));
struct append_call {
    Transaction *transaction;
    const char *direction;
    size_t input_size;
    size_t before;
    size_t after;
    int result;
    int saved;
    uint64_t entered;
    uint64_t returned;
};
static void appended(const struct append_call *call) {
    ++internal; (void)pthread_mutex_lock(&lock);
    struct native *entry=native_entry(call->transaction);
    char id[300]="null"; char fields[1500];
    if (entry && entry->id[0]) (void)snprintf(id,sizeof(id),"\"%s\"",entry->id);
    (void)snprintf(fields,sizeof(fields),"\"function\":\"msc_append_%s_body\",\"transaction_key\":\"%p\","
        "\"transaction_id\":%s,\"transaction_id_source\":\"%s\",\"phase\":%d,"
        "\"phase_is_append_boundary_not_process_execution\":true,\"input_size\":%zu,\"result\":%d,"
        "\"errno_at_return\":%d,\"entered_ns\":%" PRIu64 ",\"return_ns\":%" PRIu64 ","
        "\"sdk_body_length_before\":%zu,\"sdk_body_length_after\":%zu,"
        "\"length_semantics\":\"raw public SDK body length getter; not Common offered bytes\"",
        call->direction,(void *)call->transaction,id,entry && entry->id_source?entry->id_source:"unknown",
        entry?entry->phase:0,call->input_size,call->result,call->saved,call->entered,call->returned,call->before,call->after);
    emit("native_body_append_return",fields);
    (void)pthread_mutex_unlock(&lock); --internal;
}
#define NATIVE_BODY_APPEND(direction, boundary_phase) \
int msc_append_##direction##_body(Transaction *transaction,const unsigned char *data,size_t size) { \
    int initial=errno; int (*real_call)(Transaction *,const unsigned char *,size_t)=symbol("msc_append_" #direction "_body"); \
    if (output_fd<0 || internal || transaction==NULL) { errno=initial; return real_call(transaction,data,size); } \
    size_t (*length)(Transaction *)=symbol("msc_get_" #direction "_body_length"); \
    ++internal; size_t before=length(transaction); --internal; \
    native_phase(transaction,boundary_phase); uint64_t entered=now(); errno=initial; \
    int result=real_call(transaction,data,size); int saved=errno; uint64_t returned=now(); \
    ++internal; size_t after=length(transaction); --internal; \
    appended(&(const struct append_call){transaction,#direction,size,before,after,result,saved,entered,returned}); errno=saved; return result; \
}
NATIVE_BODY_APPEND(request,2)
NATIVE_BODY_APPEND(response,4)
#define PHASE(name, phase) \
int name(Transaction *transaction) { \
    int initial=errno; int (*real_call)(Transaction *)=symbol(#name); native_phase(transaction,phase); \
    errno=initial; int result=real_call(transaction); return result; \
}
PHASE(msc_process_request_headers,1)
int msc_process_request_body(Transaction *transaction) {
    int initial=errno; int (*real_call)(Transaction *)=symbol("msc_process_request_body");
    native_phase(transaction,2); errno=initial;
    int result=real_call(transaction); int saved=errno;
    if (!internal && transaction && &i12_apache_observe_multipart != NULL) {
        ++internal; i12_apache_observe_multipart(transaction); --internal;
    }
    errno=saved; return result;
}
PHASE(msc_process_response_body,4)
int msc_process_response_headers(Transaction *transaction,int status,const char *protocol) {
    int initial=errno; int (*real_call)(Transaction *,int,const char *)=symbol("msc_process_response_headers");
    native_phase(transaction,3); errno=initial; return real_call(transaction,status,protocol);
}
static unsigned rule_id(const char *log) {
    if (!log || strnlen(log,16385)>16384) return 0;
    const char *p=strstr(log,"[id \""); if (!p || strstr(p+5,"[id \"")) return 0;
    p+=5; unsigned value=0; unsigned count=0;
    while (*p>='0' && *p<='9') {
        ++count;
        if (count>10) break;
        unsigned digit=(unsigned)(*p-'0');
        ++p;
        if (value>(UINT32_MAX-digit)/10) return 0;
        value=value*10+digit;
    }
    return count && p[0]=='"' && p[1]==']'?value:0;
}
int msc_intervention(Transaction *transaction,ModSecurityIntervention *intervention) {
    int initial=errno; void *real_address=symbol("msc_intervention");
    int (*real_call)(Transaction *,ModSecurityIntervention *)=real_address;
    uint64_t entered=now(); errno=initial; int result=real_call(transaction,intervention); int saved=errno;
    if (output_fd>=0) {
        ++internal; (void)pthread_mutex_lock(&lock); struct native *entry=native_entry(transaction);
        char fields[1400]; char status[16]="null"; char disruptive[16]="null"; char id[32]="null";
        char phase[16]="null"; char txid[300]="null";
        if (entry && entry->id[0]) (void)snprintf(txid,sizeof(txid),"\"%s\"",entry->id);
        if (entry && entry->phase) (void)snprintf(phase,sizeof(phase),"%d",entry->phase);
        if (result==1 && intervention) {
            (void)snprintf(status,sizeof(status),"%d",intervention->status);
            (void)snprintf(disruptive,sizeof(disruptive),"%d",intervention->disruptive);
            unsigned actual=rule_id(intervention->log); if (actual) (void)snprintf(id,sizeof(id),"%u",actual);
        }
        Dl_info image={0}; char object[600]="null";
        if (dladdr(real_address,&image) && safe_string(image.dli_fname,512,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-+."))
            (void)snprintf(object,sizeof(object),"\"%s\"",image.dli_fname);
        (void)snprintf(fields,sizeof(fields),"\"function\":\"msc_intervention\",\"transaction_key\":\"%p\","
            "\"transaction_id\":%s,\"transaction_id_source\":\"%s\",\"phase\":%s,\"entered_ns\":%" PRIu64 ",\"return_ns\":%" PRIu64 ",\"result\":%d,"
            "\"errno_at_return\":%d,\"native_status\":%s,\"native_disruptive\":%s,\"native_log_rule_id\":%s,"
            "\"real_symbol_object\":%s,\"real_symbol_address\":\"%p\",\"raw_log_captured\":false",
            (void *)transaction,txid,entry && entry->id_source?entry->id_source:"unknown",phase,entered,now(),result,saved,status,disruptive,id,object,real_address);
        emit("native_intervention_return",fields); (void)pthread_mutex_unlock(&lock); --internal;
    }
    errno=saved; return result;
}
void msc_transaction_cleanup(Transaction *transaction) {
    int initial=errno; void (*real_call)(Transaction *)=symbol("msc_transaction_cleanup");
    errno=initial; real_call(transaction); int saved=errno;
    if (!internal && transaction && &i12_apache_observe_multipart_cleanup != NULL) {
        ++internal; i12_apache_observe_multipart_cleanup(transaction); --internal;
    }
    if (output_fd>=0) { (void)pthread_mutex_lock(&lock); struct native *entry=native_entry(transaction);
        if (entry) memset(entry,0,sizeof(*entry));
        (void)pthread_mutex_unlock(&lock); }
    errno=saved;
}
