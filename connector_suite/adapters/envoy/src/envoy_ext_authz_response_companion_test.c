#include "envoy_ext_authz_response_companion.h"

#include <assert.h>
#include <string.h>

int main(void)
{
    msconnector_envoy_ext_authz_response_companion companion;

    assert(msconnector_envoy_ext_authz_response_companion_init(&companion, NULL, 100U));
    assert(!msconnector_envoy_ext_authz_response_companion_init(&companion,
        "relative.sock", 100U));
    assert(!msconnector_envoy_ext_authz_response_companion_init(&companion,
        "/run/modsecurity/invalid\nname.sock", 100U));
    assert(msconnector_envoy_ext_authz_response_companion_set_limits(
        &companion, 4U, 64U));
    assert(companion.max_header_count == 4U);
    assert(companion.max_header_bytes == 64U);
    assert(strstr(companion.socket_path, "/run/modsecurity/") == companion.socket_path);
    return 0;
}
