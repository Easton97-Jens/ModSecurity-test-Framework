/* Framework-owned native regression definitions. Product source is supplied explicitly by the runner. */

int haproxy_spoa_agent_starter_self_test(void) {
    haproxy_spoa_agent_starter_config config = haproxy_spoa_agent_starter_default_config();
    msconnector_request allowed_request;
    msconnector_request blocked_request;
    msconnector_intervention intervention;
    enum msconnector_status status;

    memset(&allowed_request, 0, sizeof(allowed_request));
    allowed_request.method = "GET";
    allowed_request.uri = "/";
    allowed_request.http_version = "HTTP/1.1";

    status = haproxy_spoa_agent_starter_evaluate_request(&config, &allowed_request, &intervention);
    if (status != MSCONNECTOR_STATUS_OK || msconnector_intervention_is_disruptive(&intervention)) {
        return 1;
    }

    memset(&blocked_request, 0, sizeof(blocked_request));
    blocked_request.method = "GET";
    blocked_request.uri = config.block_path;
    blocked_request.http_version = "HTTP/1.1";

    status = haproxy_spoa_agent_starter_evaluate_request(&config, &blocked_request, &intervention);
    if (status != MSCONNECTOR_STATUS_OK || !msconnector_intervention_is_disruptive(&intervention)) {
        return 1;
    }
    if (intervention.status != config.block_status) {
        return 1;
    }

    status = haproxy_spoa_agent_starter_evaluate_request(&config, 0, &intervention);
    if (status != MSCONNECTOR_STATUS_BLOCKED) {
        return 1;
    }

    return 0;
}
