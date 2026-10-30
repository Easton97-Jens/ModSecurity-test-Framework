/*
 * Minimal connector-free libmodsecurity v3 case oracle.
 *
 * The program intentionally uses only public libmodsecurity C API calls. The
 * Python runner materializes rules.conf, headers.tsv, and body.bin, then this
 * binary executes the request phases without Apache, NGINX, or HAProxy.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "modsecurity/intervention.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"

struct observed_intervention {
    int found;
    int status;
    char phase[64];
    char log[2048];
    char url[1024];
};

struct byte_buffer {
    unsigned char *data;
    size_t size;
};

struct request_inputs {
    const char *headers_path;
    const char *body_path;
    const char *method;
    const char *uri;
};

struct result_context {
    const char *path;
    const struct observed_intervention *observed;
    int expected_status;
    int actual_status;
    const char *whoami;
};

static void server_log_cb(void *data, const void *message)
{
    FILE *log_file = (FILE *)data;
    if (log_file == NULL || message == NULL) {
        return;
    }
    fprintf(log_file, "%s\n", (const char *)message);
    fflush(log_file);
}

static void set_observed(struct observed_intervention *observed,
    const char *phase, ModSecurityIntervention *intervention)
{
    observed->found = 1;
    observed->status = intervention->status;
    snprintf(observed->phase, sizeof(observed->phase), "%s", phase);
    if (intervention->log != NULL) {
        snprintf(observed->log, sizeof(observed->log), "%s", intervention->log);
    }
    if (intervention->url != NULL) {
        snprintf(observed->url, sizeof(observed->url), "%s", intervention->url);
    }
}

static void check_intervention(Transaction *transaction, const char *phase,
    struct observed_intervention *observed)
{
    ModSecurityIntervention intervention;

    if (observed->found != 0) {
        return;
    }

    memset(&intervention, 0, sizeof(intervention));
    intervention.status = 200;

    if (msc_intervention(transaction, &intervention) != 0) {
        set_observed(observed, phase, &intervention);
        msc_intervention_cleanup(&intervention);
    }
}

static int read_file_bytes(const char *path, struct byte_buffer *buffer)
{
    FILE *file = NULL;
    long size = 0;

    buffer->data = NULL;
    buffer->size = 0;

    file = fopen(path, "rb");
    if (file == NULL) {
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    size = ftell(file);
    if (size < 0) {
        fclose(file);
        return -1;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    if (size == 0) {
        fclose(file);
        return 0;
    }
    buffer->data = (unsigned char *)malloc((size_t)size);
    if (buffer->data == NULL) {
        fclose(file);
        return -1;
    }
    if (fread(buffer->data, 1, (size_t)size, file) != (size_t)size) {
        free(buffer->data);
        buffer->data = NULL;
        fclose(file);
        return -1;
    }
    fclose(file);
    buffer->size = (size_t)size;
    return 0;
}

static void json_string(FILE *out, const char *value)
{
    const unsigned char *cursor;

    if (value == NULL) {
        fputs("\"\"", out);
        return;
    }
    cursor = (const unsigned char *)value;

    fputc('"', out);
    while (*cursor != '\0') {
        unsigned char ch = *cursor++;
        switch (ch) {
        case '\\':
            fputs("\\\\", out);
            break;
        case '"':
            fputs("\\\"", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (ch < 0x20) {
                fprintf(out, "\\u%04x", ch);
            } else {
                fputc(ch, out);
            }
            break;
        }
    }
    fputc('"', out);
}

static void write_result(const struct result_context *result,
    const char *status, const char *reason)
{
    FILE *out = fopen(result->path, "w");
    if (out == NULL) {
        fprintf(stderr, "native-oracle: failed to write result: %s\n", result->path);
        return;
    }
    fputs("{\n", out);
    fputs("  \"status\": ", out);
    json_string(out, status);
    fputs(",\n  \"reason\": ", out);
    json_string(out, reason);
    fputs(",\n  \"libmodsecurity\": ", out);
    json_string(out, result->whoami);
    fprintf(out, ",\n  \"expected_status\": %d", result->expected_status);
    fprintf(out, ",\n  \"actual_status\": %d", result->actual_status);
    fputs(",\n  \"native_match\": ", out);
    fputs(result->observed->found ? "true" : "false", out);
    fputs(",\n  \"matched_phase\": ", out);
    json_string(out, result->observed->phase);
    fputs(",\n  \"intervention_log\": ", out);
    json_string(out, result->observed->log);
    fputs(",\n  \"intervention_url\": ", out);
    json_string(out, result->observed->url);
    fputs("\n}\n", out);
    fclose(out);
}

static int add_headers(Transaction *transaction, const char *headers_path)
{
    FILE *file = fopen(headers_path, "r");
    char line[8192];
    if (file == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *tab = NULL;
        char *key = line;
        char *value = NULL;
        size_t key_len = 0;
        size_t value_len = 0;

        while (*key && isspace((unsigned char)*key)) {
            key++;
        }
        if (*key == '\0' || *key == '#') {
            continue;
        }
        tab = strchr(key, '\t');
        if (tab == NULL) {
            continue;
        }
        *tab = '\0';
        value = tab + 1;
        key_len = strlen(key);
        value_len = strlen(value);
        while (key_len > 0 && isspace((unsigned char)key[key_len - 1])) {
            key[--key_len] = '\0';
        }
        while (value_len > 0 &&
            (value[value_len - 1] == '\n' || value[value_len - 1] == '\r')) {
            value[--value_len] = '\0';
        }
        if (key_len == 0) {
            continue;
        }
        if (msc_add_n_request_header(transaction, (const unsigned char *)key,
                key_len, (const unsigned char *)value, value_len) == 0) {
            fclose(file);
            return -1;
        }
    }
    fclose(file);
    return 0;
}

static const char *process_request(Transaction *transaction,
    const struct request_inputs *request,
    struct observed_intervention *observed, struct byte_buffer *body)
{
    if (msc_process_connection(transaction, "127.0.0.1", 12345,
            "127.0.0.1", 80) == 0) {
        return "msc_process_connection failed";
    }
    check_intervention(transaction, "connection", observed);

    if (msc_process_uri(transaction, request->uri, request->method, "1.1") == 0) {
        return "msc_process_uri failed";
    }
    check_intervention(transaction, "uri", observed);

    if (add_headers(transaction, request->headers_path) != 0) {
        return "adding request headers failed";
    }
    if (msc_process_request_headers(transaction) == 0) {
        return "msc_process_request_headers failed";
    }
    check_intervention(transaction, "request_headers", observed);

    if (read_file_bytes(request->body_path, body) != 0) {
        return "reading request body failed";
    }
    if (body->size > 0 &&
        msc_append_request_body(transaction, body->data, body->size) == 0) {
        return "msc_append_request_body failed";
    }
    free(body->data);
    body->data = NULL;
    body->size = 0;

    if (msc_process_request_body(transaction) == 0) {
        return "msc_process_request_body failed";
    }
    check_intervention(transaction, "request_body", observed);
    msc_process_logging(transaction);
    return NULL;
}

static void cleanup_oracle(struct byte_buffer *body, Transaction *transaction,
    RulesSet *rules, ModSecurity *modsec, FILE *server_log)
{
    if (body->data != NULL) {
        free(body->data);
        body->data = NULL;
        body->size = 0;
    }
    if (transaction != NULL) {
        msc_transaction_cleanup(transaction);
    }
    if (rules != NULL) {
        msc_rules_cleanup(rules);
    }
    if (modsec != NULL) {
        msc_cleanup(modsec);
    }
    if (server_log != NULL) {
        fclose(server_log);
    }
}

int main(int argc, char **argv)
{
    const char *rules_path = NULL;
    const char *server_log_path = NULL;
    const char *error = NULL;
    const char *whoami = NULL;
    const char *request_error = NULL;
    int expected_status = 403;
    int actual_status = 200;
    int rc = 0;
    FILE *server_log = NULL;
    ModSecurity *modsec = NULL;
    RulesSet *rules = NULL;
    Transaction *transaction = NULL;
    struct byte_buffer body;
    struct observed_intervention observed;
    struct request_inputs request;
    struct result_context result;

    memset(&body, 0, sizeof(body));
    memset(&observed, 0, sizeof(observed));
    observed.status = 200;
    snprintf(observed.phase, sizeof(observed.phase), "%s", "none");

    if (argc != 9) {
        fprintf(stderr,
            "usage: %s RULES HEADERS BODY METHOD URI EXPECTED RESULT LOG\n",
            argv[0]);
        return 2;
    }
    rules_path = argv[1];
    request.headers_path = argv[2];
    request.body_path = argv[3];
    request.method = argv[4];
    request.uri = argv[5];
    expected_status = atoi(argv[6]);
    result.path = argv[7];
    result.observed = &observed;
    result.expected_status = expected_status;
    result.actual_status = actual_status;
    result.whoami = whoami;
    server_log_path = argv[8];

    server_log = fopen(server_log_path, "w");
    if (server_log == NULL) {
        fprintf(stderr, "native-oracle: failed to open log: %s\n",
            server_log_path);
        return 2;
    }

    modsec = msc_init();
    if (modsec == NULL) {
        write_result(&result, "setup_error", "msc_init returned NULL");
        cleanup_oracle(&body, transaction, rules, modsec, server_log);
        return 2;
    }
    msc_set_connector_info(modsec, "ModSecurity-conector native semantics oracle");
    msc_set_log_cb(modsec, server_log_cb);
    whoami = msc_who_am_i(modsec);
    result.whoami = whoami;

    rules = msc_create_rules_set();
    if (rules == NULL) {
        write_result(&result, "setup_error", "msc_create_rules_set failed");
        cleanup_oracle(&body, transaction, rules, modsec, server_log);
        return 2;
    }
    rc = msc_rules_add_file(rules, rules_path, &error);
    if (rc < 0) {
        char reason[4096];
        snprintf(reason, sizeof(reason), "rules parse failed: %s",
            error ? error : "unknown");
        write_result(&result, "not_executable", reason);
        if (error != NULL) {
            fprintf(server_log, "%s\n", error);
            msc_rules_error_cleanup(error);
        }
        cleanup_oracle(&body, transaction, rules, modsec, server_log);
        return 2;
    }

    transaction = msc_new_transaction(modsec, rules, server_log);
    if (transaction == NULL) {
        write_result(&result, "setup_error", "msc_new_transaction failed");
        cleanup_oracle(&body, transaction, rules, modsec, server_log);
        return 2;
    }

    request_error = process_request(transaction, &request, &observed, &body);
    if (request_error != NULL) {
        write_result(&result, "setup_error", request_error);
        cleanup_oracle(&body, transaction, rules, modsec, server_log);
        return 2;
    }

    actual_status = observed.found ? observed.status : 200;
    result.actual_status = actual_status;
    write_result(&result,
        (actual_status == expected_status) ? "pass" : "fail",
        observed.found ? "native intervention observed" : "no native intervention");

    cleanup_oracle(&body, transaction, rules, modsec, server_log);
    return (actual_status == expected_status) ? 0 : 1;
}
