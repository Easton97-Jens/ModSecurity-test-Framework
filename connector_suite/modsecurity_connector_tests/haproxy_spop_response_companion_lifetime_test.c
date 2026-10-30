#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define main haproxy_spop_diagnostic_runtime_program_main
#include "connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c"
#undef main

static void assert_delayed_owner_cannot_use_callback_storage(
    haproxy_spop_response_companion_owner_operation operation) {
    haproxy_spop_response_companion_decision_storage *callback_storage;
    haproxy_spop_response_companion_owner_command command;
    haproxy_modsecurity_decision native_decision;
    msconnector_decision callback_decision;
    msconnector_error error;
    msconnector_response response;
    spop_bridge_task_context context;
    spop_bridge_task_result result;

    memset(&command, 0, sizeof(command));
    memset(&native_decision, 0, sizeof(native_decision));
    memset(&response, 0, sizeof(response));
    memset(&context, 0, sizeof(context));
    callback_storage = calloc(1U, sizeof(*callback_storage));
    assert(callback_storage != NULL);
    command.operation = operation;
    command.lease = 1U;
    command.decision_storage = callback_storage;
    if (operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_HEADERS) {
        response.status = 200;
        command.response = &response;
    }
    msconnector_error_init(&error);
    assert(prepare_spop_bridge_context(&context, &command, &error) == 0);
    assert(context.command.decision_storage == &context.decision_storage);
    assert(context.command.decision_storage != callback_storage);

    /* Model a caller timeout: its callback-owned decision storage is gone
     * before the delayed owner task evaluates a disruptive response. */
    free(callback_storage);
    callback_storage = NULL;
    native_decision.disruptive = 1;
    native_decision.status = 302;
    memcpy(native_decision.action, "redirect", sizeof("redirect"));
    memcpy(native_decision.redirect_url, "/delayed-owner",
           sizeof("/delayed-owner"));
    memcpy(native_decision.log_message, "delayed owner decision",
           sizeof("delayed owner decision"));
    assert(set_bridge_native_decision(&context, &native_decision) == 1);
    assert(context.decision.redirect_url != NULL);
    assert(strcmp(context.decision.redirect_url, "/delayed-owner") == 0);
    context.success = 1;
    memset(&result, 0, sizeof(result));
    copy_spop_bridge_result(&context, &result);
    assert(result.success == 1);
    assert(result.decision.redirect_url == result.decision_storage.redirect_url);
    assert(result.decision.reason == result.decision_storage.log_message);
    memset(&context.decision_storage, 0, sizeof(context.decision_storage));
    assert(strcmp(result.decision.redirect_url, "/delayed-owner") == 0);
    callback_storage = calloc(1U, sizeof(*callback_storage));
    assert(callback_storage != NULL);
    msconnector_error_init(&error);
    assert(copy_spop_bridge_decision(&callback_decision, callback_storage,
        &result.decision, &error) == 1);
    assert(callback_decision.redirect_url == callback_storage->redirect_url);
    assert(callback_decision.reason == callback_storage->log_message);
    assert(strcmp(callback_decision.redirect_url, "/delayed-owner") == 0);
    free(callback_storage);
}

int main(void) {
    assert_delayed_owner_cannot_use_callback_storage(
        HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_HEADERS);
    assert_delayed_owner_cannot_use_callback_storage(
        HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_EOS);
    return 0;
}
