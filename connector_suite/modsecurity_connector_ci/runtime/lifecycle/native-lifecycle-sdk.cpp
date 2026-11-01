/* Optional test-artifact-only accessor; compile against the explicitly
 * selected SDK and qualify both real constructors before host use. This uses
 * the SDK's public member, never an assumed offset into an opaque C handle. */
#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <cerrno>
#include <cstring>

#ifndef MSCONNECTOR_LIFECYCLE_SDK_EXPECTED_VERSION
#define MSCONNECTOR_LIFECYCLE_SDK_EXPECTED_VERSION MODSECURITY_VERSION
#endif

static int restore_errno(int saved, int result) {
    errno = saved;
    return result;
}

extern "C" int msconnector_lifecycle_sdk_transaction_id(
    void *engine, const void *transaction, char *output, size_t capacity) {
    const int saved = errno;
    if (constexpr size_t maximum_capacity = 256U; engine == nullptr || transaction == nullptr || output == nullptr ||
        capacity == 0U || capacity > maximum_capacity)
        return restore_errno(saved, -1);
    output[0] = '\0';
    const char *identity = modsecurity::msc_who_am_i(static_cast<modsecurity::ModSecurity *>(engine));
    constexpr char version_prefix[] = "ModSecurity v";
    const char *prefix = identity == nullptr ? nullptr : std::strstr(identity, version_prefix);
    if (prefix == nullptr) return restore_errno(saved, -2);
    const char *version = prefix + sizeof(version_prefix) - 1U;
    constexpr char expected[] = MSCONNECTOR_LIFECYCLE_SDK_EXPECTED_VERSION;
    if (constexpr size_t expected_length = sizeof(expected) - 1U;
        std::strncmp(version, expected, expected_length) != 0 ||
        (version[expected_length] != '\0' && version[expected_length] != ' ' && version[expected_length] != '('))
        return restore_errno(saved, -2);
    /* The version rejection above precedes every Transaction dereference. */
    const auto *native = static_cast<const modsecurity::Transaction *>(transaction);
    const std::string &id = native->m_id;
#if defined(__cpp_lib_string_contains) && __cpp_lib_string_contains >= 202011L
    if (const bool embedded_nul = id.contains('\0');
#else
    if (const bool embedded_nul = id.find('\0') != std::string::npos;
#endif
        id.empty() || id.size() >= capacity || embedded_nul)
        return restore_errno(saved, -1);
    std::memcpy(output, id.data(), id.size());
    output[id.size()] = '\0';
    return restore_errno(saved, 1);
}
