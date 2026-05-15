/*
 * Minimal libmodsecurity v3 C API smoke probe.
 *
 * This file is original scaffold code for this repository. It imports no
 * ModSecurity source files and uses only public libmodsecurity v3 C API
 * headers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"

enum scenario_result {
    SCENARIO_PASS = 0,
    SCENARIO_FAIL = 1,
    SCENARIO_SETUP_ERROR = 2
};

struct scenario {
    const char *name;
    const char *rules;
    const char *uri;
    const char *method;
    const char *http_version;
    int expected_status;
};

struct observed_intervention {
    int found;
    int status;
    const char *phase;
};

static void reset_observed(struct observed_intervention *observed)
{
    observed->found = 0;
    observed->status = 200;
    observed->phase = "none";
}

static void check_intervention(Transaction *transaction,
    const char *phase, struct observed_intervention *observed)
{
    ModSecurityIntervention intervention;

    if (observed->found != 0) {
        return;
    }

    memset(&intervention, 0, sizeof(intervention));
    intervention.status = 200;

    if (msc_intervention(transaction, &intervention) != 0) {
        observed->found = 1;
        observed->status = intervention.status;
        observed->phase = phase;
        msc_intervention_cleanup(&intervention);
    }
}

static int load_rules(RulesSet *rules, const char *rules_text,
    const char *scenario_name)
{
    int ret;
    const char *error = NULL;

    ret = msc_rules_add(rules, rules_text, &error);
    if (ret < 0) {
        fprintf(stderr, "%s: setup_error loading rules\n", scenario_name);
        if (error != NULL) {
            fprintf(stderr, "%s\n", error);
            msc_rules_error_cleanup(error);
        }
        return SCENARIO_SETUP_ERROR;
    }

    return SCENARIO_PASS;
}

static int run_scenario(const struct scenario *scenario,
    struct observed_intervention *observed)
{
    int ret;
    int setup_status;
    ModSecurity *modsec = NULL;
    RulesSet *rules = NULL;
    Transaction *transaction = NULL;

    reset_observed(observed);

    modsec = msc_init();
    if (modsec == NULL) {
        fprintf(stderr, "%s: setup_error msc_init returned NULL\n",
            scenario->name);
        return SCENARIO_SETUP_ERROR;
    }
    msc_set_connector_info(modsec,
        "ModSecurity-test-Framework v3 API smoke probe");

    rules = msc_create_rules_set();
    if (rules == NULL) {
        fprintf(stderr,
            "%s: setup_error msc_create_rules_set returned NULL\n",
            scenario->name);
        msc_cleanup(modsec);
        return SCENARIO_SETUP_ERROR;
    }

    setup_status = load_rules(rules, scenario->rules, scenario->name);
    if (setup_status != SCENARIO_PASS) {
        msc_rules_cleanup(rules);
        msc_cleanup(modsec);
        return setup_status;
    }

    transaction = msc_new_transaction(modsec, rules, NULL);
    if (transaction == NULL) {
        fprintf(stderr,
            "%s: setup_error msc_new_transaction returned NULL\n",
            scenario->name);
        msc_rules_cleanup(rules);
        msc_cleanup(modsec);
        return SCENARIO_SETUP_ERROR;
    }

    ret = msc_process_connection(transaction, "127.0.0.1", 12345,
        "127.0.0.1", 80);
    if (ret == 0) {
        fprintf(stderr, "%s: setup_error msc_process_connection failed\n",
            scenario->name);
        msc_transaction_cleanup(transaction);
        msc_rules_cleanup(rules);
        msc_cleanup(modsec);
        return SCENARIO_SETUP_ERROR;
    }
    check_intervention(transaction, "connection", observed);

    ret = msc_process_uri(transaction, scenario->uri, scenario->method,
        scenario->http_version);
    if (ret == 0) {
        fprintf(stderr, "%s: setup_error msc_process_uri failed\n",
            scenario->name);
        msc_transaction_cleanup(transaction);
        msc_rules_cleanup(rules);
        msc_cleanup(modsec);
        return SCENARIO_SETUP_ERROR;
    }
    check_intervention(transaction, "uri", observed);

    ret = msc_process_request_headers(transaction);
    if (ret == 0) {
        fprintf(stderr,
            "%s: setup_error msc_process_request_headers failed\n",
            scenario->name);
        msc_transaction_cleanup(transaction);
        msc_rules_cleanup(rules);
        msc_cleanup(modsec);
        return SCENARIO_SETUP_ERROR;
    }
    check_intervention(transaction, "request_headers", observed);

    ret = msc_process_request_body(transaction);
    if (ret == 0) {
        fprintf(stderr,
            "%s: setup_error msc_process_request_body failed\n",
            scenario->name);
        msc_transaction_cleanup(transaction);
        msc_rules_cleanup(rules);
        msc_cleanup(modsec);
        return SCENARIO_SETUP_ERROR;
    }
    check_intervention(transaction, "request_body", observed);

    msc_transaction_cleanup(transaction);
    msc_rules_cleanup(rules);
    msc_cleanup(modsec);

    if (observed->found != 0 && observed->status == scenario->expected_status) {
        printf("%s: pass status=%d phase=%s\n", scenario->name,
            observed->status, observed->phase);
        return SCENARIO_PASS;
    }

    if (observed->found != 0) {
        printf("%s: fail expected_status=%d observed_status=%d phase=%s\n",
            scenario->name, scenario->expected_status, observed->status,
            observed->phase);
    } else {
        printf("%s: fail expected_status=%d observed_status=none\n",
            scenario->name, scenario->expected_status);
    }

    return SCENARIO_FAIL;
}

int main(void)
{
    const struct scenario primary_args_phase2 = {
        "primary_args_phase2",
        "SecRuleEngine On\n"
        "SecRule ARGS:test \"@streq attack\" "
        "\"id:1001,phase:2,deny,status:403\"\n",
        "/?test=attack",
        "GET",
        "1.1",
        403
    };
    const struct scenario fallback_request_uri_phase1 = {
        "fallback_request_uri_phase1",
        "SecRuleEngine On\n"
        "SecRule REQUEST_URI \"@contains test=attack\" "
        "\"id:1002,phase:1,deny,status:403\"\n",
        "/?test=attack",
        "GET",
        "1.1",
        403
    };
    struct observed_intervention observed;
    int primary_result;
    int fallback_result;

    primary_result = run_scenario(&primary_args_phase2, &observed);
    if (primary_result == SCENARIO_PASS) {
        printf("fallback_request_uri_phase1: skipped primary_passed\n");
        return 0;
    }
    if (primary_result == SCENARIO_SETUP_ERROR) {
        return 2;
    }

    fallback_result = run_scenario(&fallback_request_uri_phase1, &observed);
    if (fallback_result == SCENARIO_PASS) {
        printf("fallback passed, primary failed\n");
        return 1;
    }
    if (fallback_result == SCENARIO_SETUP_ERROR) {
        return 2;
    }

    return 1;
}

