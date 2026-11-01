/* Test-only callbacks for EXTERNAL instrumented Apache source copies.
 * No allocator or SDK failure is fabricated. Controlled native returns are
 * labeled separately from an independently recorded original real API return.
 * See build_fault_boundary.py's generated header and integration receipt. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <httpd.h>
#include <apr_tables.h>
#include <modsecurity/transaction.h>
#include "msconnector/request_helpers.h"
#include "msconnector/request_mapper_contract.h"
#include "msconnector/transaction_contract.h"
#include "msconnector/native_result.h"
#include <arpa/inet.h>
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

struct shared_state { atomic_int fired; atomic_uint records; atomic_uint response_appends; };
static struct shared_state *state;
static int root_fd=-1;
static int marker_fd=-1;
static int output_fd=-1;
static dev_t device; static ino_t inode;
static char principal[193];
static char mode[48];
static const char marker[]="I12_APACHE_FAULT_BOUNDARY_V1\n";
static uint64_t now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC,&value)!=0) return 0;
    return (uint64_t)value.tv_sec*UINT64_C(1000000000)+(uint64_t)value.tv_nsec;
}
static int owned_private(const struct stat *st,mode_t type,mode_t permissions) {
    return (st->st_mode&S_IFMT)==type && (st->st_mode&07777)==permissions &&
        (st->st_uid==0 || st->st_uid==geteuid()) && (type==S_IFDIR || st->st_nlink==1);
}
static int marker_valid(void) {
    struct stat st; char value[sizeof(marker)]; int ok=0;
    if (root_fd<0 || fstat(root_fd,&st)!=0 || !owned_private(&st,S_IFDIR,0700)) return 0;
    if (marker_fd<0) return 0;
    if (fstat(marker_fd,&st)==0 && owned_private(&st,S_IFREG,0600) &&
        syscall(SYS_pread64,marker_fd,value,sizeof(value),0)==(long)sizeof(marker)-1 &&
        !memcmp(value,marker,sizeof(marker)-1)) ok=1;
    return ok;
}
static int output_valid(void) {
    struct stat st; int flags=fcntl(output_fd,F_GETFL);
    return output_fd>=0 && fstat(output_fd,&st)==0 && owned_private(&st,S_IFREG,0600) &&
        st.st_dev==device && st.st_ino==inode && flags>=0 && (flags&O_APPEND);
}
__attribute__((constructor)) static void admit(void) {
    int saved=errno; struct stat st; char resolved[4096];
    const char *root=getenv("I12_APACHE_FAULT_ROOT");
    const char *id=getenv("I12_APACHE_FAULT_ID");
    const char *kind=getenv("I12_APACHE_FAULT_MODE");
    if (!root || root[0]!='/' || !realpath(root,resolved) || strcmp(root,resolved) ||
        !id || !*id || strnlen(id,sizeof(principal))>=sizeof(principal) ||
        strspn(id,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")!=strlen(id) ||
        !kind || (strcmp(kind,"null-body") && strcmp(kind,"null-headers") &&
        strcmp(kind,"invalid-native-return") && strcmp(kind,"finish-failure") &&
        strcmp(kind,"technical-precommit") && strcmp(kind,"technical-postcommit") &&
        strcmp(kind,"timeout-decision-precommit") && strcmp(kind,"timeout-decision-postcommit") &&
        strcmp(kind,"mapping-failure"))) goto done;
    root_fd=open(root,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (root_fd<0) goto done;
    /* Keep the admitted marker descriptor across Apache's normal privilege
     * drop. Revalidate its actual bytes/mode/inode link count on every fault. */
    marker_fd=openat(root_fd,"fault-boundary.enable",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (!marker_valid()) goto done;
    output_fd=openat(root_fd,"fault-boundary.jsonl",O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if (output_fd<0 || fstat(output_fd,&st)!=0 || !owned_private(&st,S_IFREG,0600)) goto done;
    device=st.st_dev; inode=st.st_ino;
    state=mmap(NULL,sizeof(*state),PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    if (state==MAP_FAILED) { state=NULL; goto done; }
    atomic_init(&state->fired,0); atomic_init(&state->records,0); atomic_init(&state->response_appends,0);
    if (!atomic_is_lock_free(&state->fired) || !atomic_is_lock_free(&state->records) || !atomic_is_lock_free(&state->response_appends)) { state=NULL; goto done; }
    strcpy(principal,id); strcpy(mode,kind);
done: errno=saved;
}
static int loopback(const apr_sockaddr_t *address) {
    uint32_t value;
    if (!address || address->family!=APR_INET || !address->ipaddr_ptr || address->ipaddr_len!=4) return 0;
    memcpy(&value,address->ipaddr_ptr,sizeof(value)); return (ntohl(value)>>24)==127;
}
static int selected(const request_rec *r,const char *kind) {
    if (!state || !principal[0] || strcmp(kind,mode) || !r || r->main || r->prev ||
        !r->connection || !loopback(r->connection->client_addr) ||
        !loopback(r->connection->local_addr) || !r->headers_in || !marker_valid() || !output_valid()) return 0;
    const apr_array_header_t *headers=apr_table_elts(r->headers_in);
    const apr_table_entry_t *items=headers?(const apr_table_entry_t *)headers->elts:NULL;
    unsigned matches=0;
    for (int i=0;items && i<headers->nelts;++i) {
        if (items[i].key && !strcasecmp(items[i].key,"X-I12-ID")) {
            if (!items[i].val || strcmp(items[i].val,principal)) return 0;
            ++matches;
        }
    }
    return matches==1;
}
static int emit(const char *kind,const char *fields) {
    if (!output_valid() || !state || atomic_fetch_add(&state->records,1)>=128) return 0;
    char line[2048];
    int n=snprintf(line,sizeof(line),"{\"schema\":\"apache-fault-boundary-v1\",\"kind\":\"%s\","
        "\"pid\":%ld,\"tid\":%ld,\"monotonic_ns\":%" PRIu64 ",\"principal_id\":\"%s\","
        "\"mode\":\"%s\",%s}\n",kind,(long)getpid(),syscall(SYS_gettid),now(),principal,mode,fields);
    return n>0 && (size_t)n<sizeof(line) && syscall(SYS_write,output_fd,line,(size_t)n)==n;
}
static int claim(void) {
    int expected=0; return atomic_compare_exchange_strong(&state->fired,&expected,1);
}
/* Insert ONLY after a successful actual apr_bucket_read and before the
 * productive (len > 0 && data == NULL) branch. No SDK call sees this NULL. */
int i12_apache_fault_after_bucket_read(request_rec *r,const char **data,apr_size_t length,int actual_read_result) {
    int saved=errno; int changed=0;
    if (actual_read_result==APR_SUCCESS && data && *data && length && selected(r,"null-body") && claim()) {
        char fields[512];
        (void)snprintf(fields,sizeof(fields),"\"boundary\":\"apache_input_filter_process_bucket\","
            "\"operation\":\"controlled_input_after_actual_successful_bucket_read\","
            "\"request_key\":\"%p\",\"actual_read_result\":%d,"
            "\"original_data_present\":true,\"original_size\":%zu,\"effective_data_present\":false,"
            "\"effective_size\":%zu,\"original_errno\":%d,\"return_value_injected\":false",
            (void *)r,actual_read_result,(size_t)length,(size_t)length,saved);
        if (emit("controlled_input",fields)) { *data=NULL; changed=1; }
    }
    errno=saved; return changed;
}
/* On the selected request only, validate a malformed bounded Common request
 * view with the REAL public validator. Apache's runtime does not normally call
 * msc_apache_map_request; this record never claims that it does. */
int i12_apache_fault_request_metadata(request_rec *r) {
    int saved=errno; int returned=1;
    if (selected(r,"null-headers")) {
        const apr_array_header_t *headers=apr_table_elts(r->headers_in);
        if (headers && headers->nelts>0 && claim()) {
            msconnector_request input; msconnector_request_mapper_contract contract;
            msconnector_request_init(&input); msconnector_request_mapper_contract_init(&contract);
            input.method=r->method; input.uri=r->unparsed_uri; input.http_version=r->protocol;
            input.client.address=r->connection->client_ip;
            input.server.address=r->server?r->server->server_hostname:NULL;
            input.headers=NULL; input.header_count=(size_t)headers->nelts;
            char diagnostic[128]; errno=saved;
            int actual=msconnector_request_mapper_validate_output(&contract,&input,diagnostic,sizeof(diagnostic));
            int actual_errno=errno; char fields[640];
            (void)snprintf(fields,sizeof(fields),"\"boundary\":\"msconnector_request_mapper_validate_output\","
                "\"operation\":\"real_common_validation_of_controlled_header_input\","
                "\"actual_apr_header_count\":%zu,\"effective_header_count\":%zu,\"effective_headers_present\":false,"
                "\"actual_validator_result\":%d,\"actual_validator_errno\":%d,"
                "\"request_key\":\"%p\",\"actual_validator_reports_missing_headers\":%s,"
                "\"runtime_mapper_called\":false,\"return_value_injected\":false",
                (size_t)headers->nelts,input.header_count,actual,actual_errno,(void *)r,
                actual==0 && !strcmp(diagnostic,"missing headers")?"true":"false");
            if (emit("controlled_input_validation",fields)) returned=actual;
        }
    }
    errno=saved; return returned;
}

struct native_call {
    request_rec *request; Transaction *transaction; const char *function;
    int original;
    int actual_errno;
    int committed;
    uint64_t entered;
    uint64_t returned;
    unsigned ordinal;
};
static int record_original(const struct native_call *call) {
    char fields[896];
    (void)snprintf(fields,sizeof(fields),"\"function\":\"%s\",\"transaction_key\":\"%p\","
        "\"request_key\":\"%p\",\"actual_original_result\":%d,\"actual_original_errno\":%d,"
        "\"entered_ns\":%" PRIu64 ",\"returned_ns\":%" PRIu64 ",\"sdk_called\":true,"
        "\"actual_host_committed_flag\":%s,\"principal_append_ordinal\":%u,\"return_value_injected\":false",
        call->function,(void *)call->transaction,(void *)call->request,call->original,call->actual_errno,
        call->entered,call->returned,call->committed?"true":"false",call->ordinal);
    return emit("actual_native_original_return",fields);
}
static int timeout_ready(void *opaque,int phase,int committed) {
    const msconnector_transaction_contract *contract=opaque;
    return contract && contract->error_class==MSCONNECTOR_TRANSACTION_ERROR_NONE &&
        contract->active_phase==phase && contract->response_committed==(committed!=0) &&
        !strcmp(contract->transaction_id,principal);
}
static int actual_timeout(void *opaque,const struct native_call *call) {
    msconnector_transaction_contract *contract=opaque;
    int before_error=contract->error_class; int before_decision=contract->engine_decision;
    int before_status=contract->status; int before_phase=contract->active_phase;
    uint64_t timestamp=now()/UINT64_C(1000000);
    int result=msconnector_transaction_contract_timeout(contract,timestamp);
    char fields[1280];
    (void)snprintf(fields,sizeof(fields),"\"function\":\"msconnector_transaction_contract_timeout\","
        "\"contract_key\":\"%p\",\"transaction_key\":\"%p\",\"actual_transition_result\":%d,"
        "\"before_error_class\":%d,\"after_error_class\":%d,\"before_engine_decision\":%d,"
        "\"after_engine_decision\":%d,\"before_status\":%d,\"after_status\":%d,"
        "\"before_active_phase\":%d,\"after_active_phase\":%d,\"actual_error_phase\":%d,"
        "\"requested_timestamp_ms\":%" PRIu64 ",\"actual_completed_at_ms\":%" PRIu64 ","
        "\"actual_host_committed_flag\":%s,\"actual_contract_committed_flag\":%s,"
        "\"real_common_function_called\":true,\"common_return_value_injected\":false,"
        "\"phase_value_kind\":\"msconnector_phase_enum_not_rule_phase\","
        "\"elapsed_budget_enforcement_claimed\":false",
        opaque,(void *)call->transaction,result,before_error,(int)contract->error_class,before_decision,
        (int)contract->engine_decision,before_status,(int)contract->status,before_phase,contract->active_phase,
        contract->error_phase,timestamp,contract->completed_at_ms,call->committed?"true":"false",
        contract->response_committed?"true":"false");
    /* Once the real transition mutated the live contract, never hide it by
     * returning a normal path if its diagnostic write fails. Missing receipts
     * forbid qualification; caller failure still seals this transaction. */
    (void)emit("actual_common_timeout_decision",fields);
    return result==MSCONNECTOR_TRANSACTION_TRANSITION_OK &&
        contract->error_class==MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT;
}
static int native_return(const struct native_call *call,const char *kind,int effective,
    void *contract,int phase) {
    if (!selected(call->request,kind)) return call->original;
    if (!record_original(call)) return call->original;
    if (contract && !(phase==MSCONNECTOR_PHASE_RESPONSE_BODY
        ? msconnector_native_body_append_can_continue(call->original)
        : msconnector_native_phase_succeeded(call->original))) return call->original;
    if (contract && !timeout_ready(contract,phase,call->committed)) return call->original;
    if (!claim()) return call->original;
    if (contract && !actual_timeout(contract,call)) return call->original;
    char fields[768];
    (void)snprintf(fields,sizeof(fields),"\"function\":\"%s\",\"transaction_key\":\"%p\","
        "\"actual_original_result\":%d,\"actual_original_errno\":%d,\"effective_result\":%d,"
        "\"actual_host_committed_flag\":%s,\"principal_append_ordinal\":%u,"
        "\"effective_result_is_sdk_result\":false,\"return_value_injected\":true",
        call->function,(void *)call->transaction,call->original,call->actual_errno,effective,
        call->committed?"true":"false",call->ordinal);
    int recorded=emit("controlled_return",fields);
    return recorded || contract ? effective : call->original;
}
int i12_apache_fault_process_request_headers(request_rec *r,Transaction *tx,void *contract,int committed) {
    int initial=errno; struct native_call call={.request=r,.transaction=tx,.function="msc_process_request_headers",.committed=committed};
    call.entered=now(); errno=initial; call.original=msc_process_request_headers(tx);
    call.actual_errno=errno; call.returned=now(); int result=call.original;
    if (!strcmp(mode,"timeout-decision-precommit")) {
        if (contract && !committed) result=native_return(&call,mode,0,contract,MSCONNECTOR_PHASE_REQUEST_HEADERS);
    } else if (!strcmp(mode,"technical-precommit")) {
        if (!committed) result=native_return(&call,mode,0,NULL,0);
    } else result=native_return(&call,"invalid-native-return",-77,NULL,0);
    errno=call.actual_errno; return result;
}
int i12_apache_fault_append_response_body(request_rec *r,Transaction *tx,const unsigned char *body,
    size_t length,void *contract,int committed) {
    int initial=errno; struct native_call call={.request=r,.transaction=tx,.function="msc_append_response_body",.committed=committed};
    call.entered=now(); errno=initial; call.original=msc_append_response_body(tx,body,length);
    call.actual_errno=errno; call.returned=now(); int result=call.original;
    if (selected(r,"technical-postcommit") || selected(r,"timeout-decision-postcommit")) {
        call.ordinal=atomic_fetch_add(&state->response_appends,1)+1;
        if (call.ordinal==2 && committed) {
            if (!strcmp(mode,"technical-postcommit")) result=native_return(&call,mode,-1,NULL,0);
            else if (contract) result=native_return(&call,mode,-1,contract,MSCONNECTOR_PHASE_RESPONSE_BODY);
        }
    }
    errno=call.actual_errno; return result;
}
int i12_apache_fault_add_request_header(request_rec *r,Transaction *tx,
    const unsigned char *key,const unsigned char *value) {
    int initial=errno; struct native_call call={.request=r,.transaction=tx,.function="msc_add_request_header"};
    call.entered=now(); errno=initial; call.original=msc_add_request_header(tx,key,value);
    call.actual_errno=errno; call.returned=now();
    int result=native_return(&call,"mapping-failure",0,NULL,0); errno=call.actual_errno; return result;
}
int i12_apache_fault_process_logging(request_rec *r,Transaction *tx) {
    int initial=errno; struct native_call call={.request=r,.transaction=tx,.function="msc_process_logging"};
    call.entered=now(); errno=initial; call.original=msc_process_logging(tx);
    call.actual_errno=errno; call.returned=now();
    int result=native_return(&call,"finish-failure",0,NULL,0); errno=call.actual_errno; return result;
}
