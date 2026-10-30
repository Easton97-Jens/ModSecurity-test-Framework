/* Framework-owned native regression definitions. Product source is supplied explicitly by the runner. */

enum msconnector_status msconnector_lighttpd_bridge_self_test(void) {
    msconnector_capabilities capabilities;
    msconnector_request request;
    msconnector_lighttpd_bridge_decision decision;

    capabilities = msconnector_lighttpd_bridge_starter_capabilities();
    if (capabilities.flags != MSCONNECTOR_CAPABILITY_NONE) {
        return MSCONNECTOR_STATUS_ERROR;
    }
    if (strcmp(msconnector_lighttpd_bridge_starter_kind(), "decision-service-bridge-starter") != 0) {
        return MSCONNECTOR_STATUS_ERROR;
    }

    request = msconnector_lighttpd_bridge_make_probe_request("GET", "/");
    decision = msconnector_lighttpd_bridge_evaluate_probe(&request);
    if (decision.status != MSCONNECTOR_STATUS_BLOCKED) {
        return MSCONNECTOR_STATUS_ERROR;
    }
    if (msconnector_intervention_is_disruptive(&decision.intervention)) {
        return MSCONNECTOR_STATUS_ERROR;
    }
    return MSCONNECTOR_STATUS_OK;
}
