/* Framework-owned native regression definitions. Product source is supplied explicitly by the runner. */

int msconnector_traefik_decision_service_self_test(void) {
    const msconnector_header block_header = {
        "X-ModSecurity-Connector-Decision",
        sizeof("X-ModSecurity-Connector-Decision") - 1,
        "block",
        sizeof("block") - 1
    };
    const msconnector_request allow_request = {
        "GET",
        "/",
        "HTTP/1.1",
        "example.test",
        {"127.0.0.1", 12345},
        {"127.0.0.1", 8080},
        0,
        0,
        {0, 0}
    };
    const msconnector_request uri_block_request = {
        "GET",
        "/__traefik_decision_service_block",
        "HTTP/1.1",
        "example.test",
        {"127.0.0.1", 12345},
        {"127.0.0.1", 8080},
        0,
        0,
        {0, 0}
    };
    const msconnector_request header_block_request = {
        "GET",
        "/",
        "HTTP/1.1",
        "example.test",
        {"127.0.0.1", 12345},
        {"127.0.0.1", 8080},
        &block_header,
        1,
        {0, 0}
    };
    msconnector_traefik_decision_result result;

    result = msconnector_traefik_decide_request(&allow_request);
    if (result.status != MSCONNECTOR_STATUS_OK ||
        msconnector_intervention_is_disruptive(&result.intervention)) {
        return 1;
    }

    result = msconnector_traefik_decide_request(&uri_block_request);
    if (result.status != MSCONNECTOR_STATUS_BLOCKED ||
        !msconnector_intervention_is_disruptive(&result.intervention) ||
        result.intervention.status != 403) {
        return 1;
    }

    result = msconnector_traefik_decide_request(&header_block_request);
    if (result.status != MSCONNECTOR_STATUS_BLOCKED ||
        !msconnector_intervention_is_disruptive(&result.intervention) ||
        result.intervention.status != 403) {
        return 1;
    }

    return 0;
}
