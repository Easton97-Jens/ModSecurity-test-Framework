/* Framework-owned native regression definitions. Product source is supplied explicitly by the runner. */

int msconnector_envoy_bridge_self_test(void) {
    const msconnector_header block_headers[] = {
        {MSCONNECTOR_ENVOY_BRIDGE_BLOCK_HEADER,
            sizeof(MSCONNECTOR_ENVOY_BRIDGE_BLOCK_HEADER) - 1,
            "1",
            1}
    };
    const msconnector_request allow_request = {
        "GET",
        "/allowed",
        "HTTP/1.1",
        "example.test",
        {"127.0.0.1", 12345},
        {"127.0.0.1", 10000},
        0,
        0,
        {0, 0}
    };
    const msconnector_request header_block_request = {
        "GET",
        "/blocked-by-header",
        "HTTP/1.1",
        "example.test",
        {"127.0.0.1", 12345},
        {"127.0.0.1", 10000},
        block_headers,
        sizeof(block_headers) / sizeof(block_headers[0]),
        {0, 0}
    };
    const msconnector_request uri_block_request = {
        "GET",
        "/blocked?msconnector_block=1",
        "HTTP/1.1",
        "example.test",
        {"127.0.0.1", 12345},
        {"127.0.0.1", 10000},
        0,
        0,
        {0, 0}
    };
    msconnector_envoy_bridge_decision allow_result;
    msconnector_envoy_bridge_decision header_block_result;
    msconnector_envoy_bridge_decision uri_block_result;

    allow_result = msconnector_envoy_bridge_evaluate(&allow_request);
    header_block_result = msconnector_envoy_bridge_evaluate(&header_block_request);
    uri_block_result = msconnector_envoy_bridge_evaluate(&uri_block_request);

    if (allow_result.status != MSCONNECTOR_STATUS_OK ||
        msconnector_intervention_is_disruptive(&allow_result.intervention)) {
        return 1;
    }
    if (header_block_result.status != MSCONNECTOR_STATUS_BLOCKED ||
        !msconnector_intervention_is_disruptive(&header_block_result.intervention) ||
        header_block_result.intervention.status != 403) {
        return 1;
    }
    if (uri_block_result.status != MSCONNECTOR_STATUS_BLOCKED ||
        !msconnector_intervention_is_disruptive(&uri_block_result.intervention) ||
        uri_block_result.intervention.status != 403) {
        return 1;
    }
    return 0;
}
