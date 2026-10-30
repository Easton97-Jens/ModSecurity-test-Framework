/* Framework-owned native regression definitions. Product source is supplied explicitly by the runner. */

int haproxy_modsecurity_phase1_header_self_test(
        haproxy_modsecurity_decision *decision) {
    int rc;

    rc = haproxy_modsecurity_phase1_header_eval("GET",
        "/haproxy-binding-self-test", "localhost", "block", decision);
    if (rc != 0) {
        return rc;
    }
    if (decision != 0 && decision->disruptive != 0 &&
            decision->status == HAPROXY_MODSECURITY_EXPECTED_STATUS &&
            decision->rule_id == 1000001) {
        return 0;
    }
    if (decision != 0) {
        snprintf(decision->log_message, sizeof(decision->log_message),
            "expected disruptive status %d and Rule-ID 1000001, got disruptive=%d status=%d rule_id=%d",
            HAPROXY_MODSECURITY_EXPECTED_STATUS, decision->disruptive,
            decision->status, decision->rule_id);
    }
    return 1;
}

static int haproxy_modsecurity_request_body_eval(
        const char *uri,
        const char *rules_text,
        haproxy_modsecurity_decision *decision) {
    static const unsigned char body[] = "token=block";
    haproxy_modsecurity_header headers[3];
    haproxy_modsecurity_request request;

    headers[0].name = "Host";
    headers[0].value = "localhost";
    headers[1].name = "Content-Type";
    headers[1].value = "application/x-www-form-urlencoded";
    headers[2].name = "Content-Length";
    headers[2].value = "11";
    memset(&request, 0, sizeof(request));
    request.method = "POST";
    request.http_version = "1.1";
    request.uri = uri;
    request.client_ip = "192.0.2.10";
    request.client_port = 12345;
    request.server_ip = "198.51.100.20";
    request.server_port = 8080;
    request.headers = headers;
    request.header_count = 3U;
    request.body = body;
    request.body_len = (unsigned int)(sizeof(body) - 1U);
    return eval_request_internal(&request, rules_text, decision);
}

static int haproxy_modsecurity_request_body_limit_self_test(
        haproxy_modsecurity_decision *decision) {
    static const char rules_text[] =
        "SecRuleEngine On\n"
        "SecRequestBodyAccess On\n"
        "SecRequestBodyLimit 8\n"
        "SecRequestBodyNoFilesLimit 8\n"
        "SecRequestBodyLimitAction Reject\n";
    int rc;

    rc = haproxy_modsecurity_request_body_eval(
        "/haproxy-binding-request-body-limit-self-test", rules_text, decision);
    if (rc != 0) {
        return rc;
    }
    if (decision != 0 && decision->phase == 2 && decision->disruptive != 0 &&
            decision->body_limit != 0 && decision->status == 403 &&
            decision->rule_id == 0 && strcmp(decision->action, "deny") == 0 &&
            decision->redirect_url[0] == '\0') {
        return 0;
    }
    if (decision != 0) {
        snprintf(decision->log_message, sizeof(decision->log_message),
            "expected native request-body-limit deny status 403 without Rule-ID, got phase=%d disruptive=%d body_limit=%d status=%d rule_id=%d",
            decision->phase, decision->disruptive, decision->body_limit,
            decision->status, decision->rule_id);
    }
    return 1;
}

int haproxy_modsecurity_request_body_self_test(
        haproxy_modsecurity_decision *decision) {
    static const char rules_text[] =
        "SecRuleEngine On\n"
        "SecRequestBodyAccess On\n"
        "SecRequestBodyLimit 1048576\n"
        "SecRequestBodyNoFilesLimit 1048576\n"
        "SecRequestBodyLimitAction Reject\n"
        "SecRule ARGS:token \"@streq block\" "
        "\"id:1000002,phase:2,deny,status:403,"
        "msg:'HAProxy ModSecurity binding request-body self-test block'\"\n";
    static const unsigned char body[] = "token=block";
    haproxy_modsecurity_header headers[3];
    haproxy_modsecurity_request request;
    int rc;

    headers[0].name = "Host";
    headers[0].value = "localhost";
    headers[1].name = "Content-Type";
    headers[1].value = "application/x-www-form-urlencoded";
    headers[2].name = "Content-Length";
    headers[2].value = "11";
    memset(&request, 0, sizeof(request));
    request.method = "POST";
    request.http_version = "1.1";
    request.uri = "/haproxy-binding-body-self-test";
    request.client_ip = "192.0.2.10";
    request.client_port = 12345;
    request.server_ip = "198.51.100.20";
    request.server_port = 8080;
    request.headers = headers;
    request.header_count = 3U;
    request.body = body;
    request.body_len = (unsigned int)(sizeof(body) - 1U);
    rc = eval_request_internal(&request, rules_text, decision);
    if (rc != 0) {
        return rc;
    }
    if (decision != 0 && decision->disruptive != 0 &&
            decision->status == HAPROXY_MODSECURITY_EXPECTED_STATUS &&
            decision->rule_id == 1000002) {
        return haproxy_modsecurity_request_body_limit_self_test(decision);
    }
    if (decision != 0) {
        snprintf(decision->log_message, sizeof(decision->log_message),
            "expected request-body disruptive status %d and Rule-ID 1000002, got disruptive=%d status=%d rule_id=%d",
            HAPROXY_MODSECURITY_EXPECTED_STATUS, decision->disruptive,
            decision->status, decision->rule_id);
    }
    return 1;
}

int haproxy_modsecurity_crs_sqli_self_test(
        const char *crs_preamble_file,
        haproxy_modsecurity_decision *decision) {
    haproxy_modsecurity_decision pass_decision;
    int rc;

    rc = haproxy_modsecurity_crs_sqli_eval("GET",
        "/?id=1%20UNION%20SELECT%20password%20FROM%20users",
        "localhost", crs_preamble_file, decision);
    if (rc != 0) {
        return rc;
    }
    if (decision == 0 || decision->disruptive == 0 ||
            decision->status != HAPROXY_MODSECURITY_EXPECTED_STATUS) {
        if (decision != 0) {
            snprintf(decision->log_message, sizeof(decision->log_message),
                "expected CRS disruptive status %d, got disruptive=%d status=%d",
                HAPROXY_MODSECURITY_EXPECTED_STATUS,
                decision->disruptive, decision->status);
        }
        return 1;
    }

    rc = haproxy_modsecurity_crs_sqli_eval("GET", "/diagnostic.txt",
        "localhost", crs_preamble_file, &pass_decision);
    if (rc != 0) {
        if (decision != 0) {
            copy_message(decision->log_message, sizeof(decision->log_message),
                pass_decision.log_message);
        }
        return rc;
    }
    if (pass_decision.disruptive != 0) {
        if (decision != 0) {
            snprintf(decision->log_message, sizeof(decision->log_message),
                "expected CRS pass probe to be non-disruptive, got status=%d",
                pass_decision.status);
        }
        return 1;
    }
    return 0;
}
