/* Independent real APR merge and libModSecurity rule evaluation. No httpd or
 * Common lifecycle is inferred from this bounded native primitive test. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <apr_general.h>
#include <apr_tables.h>
#include <apr_version.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>

/* The legacy public intervention contract transfers malloc-owned strings.
 * SDK 3.0.12 has no msc_intervention_cleanup API; release the same resources
 * and reset all fields explicitly, as the newer SDK helper does. */
static void release_intervention(ModSecurityIntervention *intervention) {
    free(intervention->url);
    free(intervention->log);
    intervention->url = NULL;
    intervention->log = NULL;
    intervention->status = 200;
    intervention->pause = 0;
    intervention->disruptive = 0;
}

static const char *selected_rule(const char *name) {
    if (strcmp(name, "original") != 0 && strcmp(name, "corrected") != 0) return NULL;
    const char *rule = strcmp(name, "original") == 0 ?
        "SecRuleEngine On\n"
        "SecRule &REQUEST_HEADERS:X-No-Crs-Duplicate \"@eq 2\" "
        "\"id:1100504,phase:1,deny,status:451,log,t:none,chain\"\n"
        "SecRule REQUEST_HEADERS:X-No-Crs-Duplicate \"@streq one\" \"t:none,chain\"\n"
        "SecRule REQUEST_HEADERS:X-No-Crs-Duplicate \"@streq two\" \"t:none\"\n" :
        "SecRuleEngine On\n"
        "SecRule &REQUEST_HEADERS:X-No-Crs-Duplicate \"@eq 1\" "
        "\"id:1100504,phase:1,deny,status:451,log,t:none,chain\"\n"
        "SecRule REQUEST_HEADERS:X-No-Crs-Duplicate \"@streq one, two\" \"t:none\"\n";
    return rule;
}

static int process_headers(Transaction *transaction, const apr_table_t *headers) {
    const apr_array_header_t *array = apr_table_elts(headers);
    const apr_table_entry_t *entries = (const apr_table_entry_t *)array->elts;
    for (int i = 0; i < array->nelts; ++i) {
        if (msc_add_request_header(transaction, (const unsigned char *)entries[i].key,
                (const unsigned char *)entries[i].val) != 1) return 0;
    }
    if (msc_process_request_headers(transaction) != 1) return 0;
    return 1;
}

static int report_observation(ModSecurity *engine, const apr_table_t *headers,
    const ModSecurityIntervention *intervention) {
    const apr_array_header_t *array = apr_table_elts(headers);
    const apr_table_entry_t *entries = (const apr_table_entry_t *)array->elts;
    printf("apr=%s\nsdk=%s\ncount=%d\n", apr_version_string(), msc_who_am_i(engine), array->nelts);
    Dl_info sdk_image = {0};
    Dl_info apr_image = {0};
    if (!dladdr((const void *)&msc_init, &sdk_image) ||
        !dladdr((const void *)&apr_table_compress, &apr_image)) return 0;
    printf("sdk_image=%s\napr_image=%s\n", sdk_image.dli_fname, apr_image.dli_fname);
    for (int i = 0; i < array->nelts; ++i) {
        printf("header=%s\t%s\n", entries[i].key, entries[i].val);
    }
    printf("matched=%d\nstatus=%d\n", intervention->disruptive != 0, intervention->status);
    return 1;
}

static int observe_transaction(Transaction *transaction, ModSecurity *engine,
    const apr_table_t *headers, ModSecurityIntervention *intervention) {
    if (transaction == NULL ||
        msc_process_connection(transaction, "127.0.0.1", 1111, "127.0.0.1", 2222) != 1 ||
        msc_process_uri(transaction, "/header-semantics", "GET", "1.1") != 1) return 1;
    if (!process_headers(transaction, headers)) return 1;
    intervention->status = 200;
    int native_result = msc_intervention(transaction, intervention);
    if (native_result != 0 && native_result != 1) return 1;
    if (!report_observation(engine, headers, intervention)) return 1;
    return 0;
}

static void release_resources(ModSecurityIntervention *intervention,
    Transaction *transaction, RulesSet *rules, ModSecurity *engine, apr_pool_t *pool) {
    release_intervention(intervention);
    if (transaction != NULL) msc_transaction_cleanup(transaction);
    if (rules != NULL) msc_rules_cleanup(rules);
    if (engine != NULL) msc_cleanup(engine);
    if (pool != NULL) apr_pool_destroy(pool);
    apr_terminate();
}

int main(int argc, char **argv) {
    apr_pool_t *pool = NULL;
    ModSecurity *engine = NULL;
    RulesSet *rules = NULL;
    Transaction *transaction = NULL;
    ModSecurityIntervention intervention = {0};
    const char *diagnostic = NULL;
    int result = 1;
    if (argc < 3 || (argc - 3) % 2 != 0) return 2;
    if (apr_initialize() != APR_SUCCESS) return 3;
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) goto cleanup;
    apr_table_t *headers = apr_table_make(pool, argc);
    for (int i = 3; i < argc; i += 2) apr_table_add(headers, argv[i], argv[i + 1]);
    if (strcmp(argv[1], "merge") == 0) {
        apr_table_compress(headers, APR_OVERLAP_TABLES_MERGE);
    } else if (strcmp(argv[1], "raw") != 0) {
        result = 2;
        goto cleanup;
    }
    engine = msc_init();
    rules = msc_create_rules_set();
    if (engine == NULL || rules == NULL) goto cleanup;
    const char *rule = selected_rule(argv[2]);
    if (rule == NULL) {
        result = 2;
        goto cleanup;
    }
    if (msc_rules_add(rules, rule, &diagnostic) < 0) {
        fprintf(stderr, "%s\n", diagnostic != NULL ? diagnostic : "rule load failed");
        goto cleanup;
    }
    transaction = msc_new_transaction(engine, rules, NULL);
    result = observe_transaction(transaction, engine, headers, &intervention);
cleanup:
    release_resources(&intervention, transaction, rules, engine, pool);
    return result;
}
