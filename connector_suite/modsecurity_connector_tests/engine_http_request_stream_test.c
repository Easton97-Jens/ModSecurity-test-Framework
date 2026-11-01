#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common/runtime/http_authorization_service.c"
#include "connectors/profile_registry.h"

static msconnector_runtime_transaction *retained;
static size_t expected_length;
static size_t expected_retained;
static int handoff_calls;
static int handoff(const msconnector_runtime *runtime, msconnector_runtime_transaction *transaction,
    void *userdata, char handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE], msconnector_error *error) {
    msconnector_runtime_transaction_snapshot snapshot;
    (void)runtime; (void)userdata;
    msconnector_error_init(error);
    assert(msconnector_runtime_transaction_snapshot_get(transaction, &snapshot));
    assert(snapshot.request_body.finished);
    assert(snapshot.request_body.bytes_seen == expected_length);
    assert(snapshot.request_body.bytes_inspected == 0U);
    assert(snapshot.request_body.bytes_retained == expected_retained);
    assert(snapshot.contract.last_completed_phase == MSCONNECTOR_PHASE_REQUEST_BODY);
    assert(retained == NULL);
    retained = transaction; ++handoff_calls;
    memset(handle, 'a', MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE - 1U);
    handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE - 1U] = '\0';
    return 1;
}
typedef struct writer { int fd; size_t length; size_t marker; int expected_status; } writer;
static void *client(void *opaque) {
    const writer *input = opaque;
    char header[512];
    char response[4096];
    unsigned char chunk[65536];
    connection_deadline deadline;
    size_t offset = 0U;
    size_t used = 0U;
    assert(connection_deadline_init(&deadline, 15000UL));
    int length = snprintf(header, sizeof(header), "POST /stream HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n", input->length);
    assert(length > 0 && send_all(input->fd, header, (size_t)length, &deadline));
    while (offset < input->length) {
        size_t amount = input->length - offset < sizeof(chunk) ? input->length - offset : sizeof(chunk);
        memset(chunk, 'a', amount);
        for (size_t index=0U; index<amount; ++index) {
            size_t position = offset+index;
            if (position < 6U) chunk[index] = (unsigned char)"PREFIX"[position];
            if (input->marker > 0U && position >= input->marker && position < input->marker+6U)
                chunk[index] = (unsigned char)"MARKER"[position-input->marker];
        }
        assert(send_all(input->fd, (const char *)chunk, amount, &deadline));
        offset += amount;
    }
    while (used < sizeof(response)-1U) {
        ssize_t amount = recv(input->fd, response+used, sizeof(response)-1U-used, 0);
        assert(amount >= 0);
        if (!amount) break;
        used += (size_t)amount;
    }
    response[used] = '\0';
    snprintf(header, sizeof(header), "HTTP/1.1 %d ", input->expected_status);
    assert(strncmp(response, header, strlen(header)) == 0);
    assert((strstr(response, "x-msconnector-response-handle:") != NULL) == (input->expected_status == 200));
    close(input->fd);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 8) { fprintf(stderr, "required: directory request-limit no-files-limit action body-length marker expected-status\n"); return 2; }
    char rules_path[4096];
    char config_path[4096];
    char error_text[512];
    size_t limit = (size_t)strtoull(argv[2], NULL, 10);
    size_t no_files_limit = (size_t)strtoull(argv[3], NULL, 10);
    assert(limit > 0U && no_files_limit > 0U &&
        (strcmp(argv[4], "Reject") == 0 || strcmp(argv[4], "ProcessPartial") == 0));
    snprintf(rules_path, sizeof(rules_path), "%s/http.rules", argv[1]);
    snprintf(config_path, sizeof(config_path), "%s/http.conf", argv[1]);
    FILE *file = fopen(rules_path, "w"); assert(file);
    assert(fprintf(file, "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit %zu\nSecRequestBodyNoFilesLimit %zu\nSecRequestBodyLimitAction %s\nSecAction \"id:93010,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On\"\nSecRule REQUEST_BODY \"@rx PREFIX.*PREFIX\" \"id:93011,phase:2,deny,status:452,nolog\"\nSecRule REQUEST_BODY \"@contains MARKER\" \"id:93012,phase:2,deny,status:451,nolog\"\n", limit, no_files_limit, argv[4]) > 0); assert(fclose(file) == 0);
    file=fopen(config_path,"w"); assert(file);
    assert(fprintf(file,"enabled=on\nrules_file=%s\nrequest_body_mode=buffered\nresponse_body_mode=none\nphase4_mode=safe\n",rules_path)>0); assert(fclose(file)==0);
    authorization_service service; memset(&service,0,sizeof(service));
    msconnector_http_authorization_profile profile; memset(&profile,0,sizeof(profile));
    msconnector_error error; msconnector_error_init(&error);
    profile.connector_name="lighttpd"; profile.integration_mode="native-test";
    profile.transaction_profile=msconnector_profile_registry_find("lighttpd-stock");
    profile.map_request=msconnector_generic_map_request;
    profile.handoff_response_companion=handoff;
    service.profile=&profile; service.connection_timeout_ms=15000UL;
    assert(msconnector_runtime_create("lighttpd", config_path, &service.runtime, error_text, sizeof(error_text)));
    assert(msconnector_runtime_set_transaction_profile(service.runtime,profile.transaction_profile));
    assert(pthread_mutex_init(&service.runtime_lock,NULL)==0);
    service.request_limits.total_header_limit = msconnector_runtime_total_header_limit(service.runtime);
    service.request_limits.header_count_limit = msconnector_runtime_header_count_limit(service.runtime);
    msconnector_runtime_request_contract(service.runtime, &service.request_limits.mapper_contract);
    int sockets[2]; assert(socketpair(AF_UNIX,SOCK_STREAM,0,sockets)==0);
    writer input={sockets[1],(size_t)strtoull(argv[5],NULL,10),(size_t)strtoull(argv[6],NULL,10),atoi(argv[7])};
    expected_length=input.length;
    expected_retained = strcmp(argv[4], "ProcessPartial") == 0 && limit < input.length
        ? limit : input.length;
    pthread_t thread; assert(pthread_create(&thread,NULL,client,&input)==0);
    struct sockaddr_in endpoint; memset(&endpoint,0,sizeof(endpoint)); endpoint.sin_family=AF_INET;
    endpoint.sin_addr.s_addr=htonl(INADDR_LOOPBACK); endpoint.sin_port=htons(12345);
    connection_deadline deadline; assert(connection_deadline_init(&deadline,15000UL));
    authorization_connection connection={sockets[0],&endpoint,&endpoint,&deadline};
    assert(handle_authorization_request(&connection,&service));
    close(sockets[0]); assert(pthread_join(thread,NULL)==0);
    assert(handoff_calls==(input.expected_status==200));
    if (retained) {
        assert(msconnector_runtime_transaction_cancel(retained,0,&error));
        assert(msconnector_runtime_transaction_finish(retained,&error));
        msconnector_runtime_transaction_destroy(&retained);
    }
    msconnector_runtime_destroy(&service.runtime);
    assert(pthread_mutex_destroy(&service.runtime_lock)==0);
    puts("genuine HTTP authorization stream PASS: full byte accounting, P2 before handoff, no duplicate prefix");
    return 0;
}
