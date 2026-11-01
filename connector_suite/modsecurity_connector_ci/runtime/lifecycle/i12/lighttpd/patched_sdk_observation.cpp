/* Test-only public SDK3.0.14 MIME accessor for the existing I12 collector.
 * No opaque offsets, decision changes, API replacement or body data capture. */
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <locale>
#include <sstream>
#include <string>
#include <string_view>

static bool quoted_metadata(const std::string& value, std::string& output) {
    if (value.size() > 256U) return false;
    output = "\"";
    for (char character : value) {
        const auto byte = static_cast<std::byte>(character);
        if (byte < std::byte{32} || byte >= std::byte{127}
                || byte == std::byte{'"'} || byte == std::byte{'\\'}) {
            constexpr std::string_view hex = "0123456789abcdef";
            output += "\\u00";
            output += hex[std::to_integer<size_t>(byte >> 4U)];
            output += hex[std::to_integer<size_t>(byte & std::byte{15})];
        } else {
            output += character;
        }
    }
    output += '"';
    return true;
}

static bool expected_version(const char* identity) {
    constexpr char expected[] = "ModSecurity v3.0.14";
    constexpr size_t length = sizeof(expected) - 1U;
    const char* version = identity == nullptr ? nullptr : std::strstr(identity, expected);
    return version != nullptr && (version[length] == '\0' || version[length] == ' ' || version[length] == '(');
}

static int observe_transaction(const modsecurity::Transaction& native, char* output, size_t capacity) {
    int result = -1;
    const std::string& mime = native.m_variableResponseContentType.m_value;
    auto response_header = native.m_variableResponseHeaders.find("Content-Type");
    auto request_header = native.m_variableRequestHeaders.find("Content-Type");
    const std::string raw_response = response_header == native.m_variableResponseHeaders.end()
        ? "" : response_header->second->getValue();
    const std::string raw_request = request_header == native.m_variableRequestHeaders.end()
        ? "" : request_header->second->getValue();
    const auto& policy = native.m_rules->m_responseBodyTypeToBeInspected;
    std::string types = "[";
    bool first = true;
    for (const auto& value : policy.m_value) {
        std::string encoded;
        if (!quoted_metadata(value, encoded) || types.size() + encoded.size() > 1024U) {
            return -1;
        }
        if (!first) types += ',';
        first = false;
        types += encoded;
    }
    types += ']';
    std::string qmime;
    std::string qresponse;
    if (std::string qrequest; quoted_metadata(mime, qmime) && quoted_metadata(raw_response, qresponse)
            && quoted_metadata(raw_request, qrequest)) {
#if __cplusplus >= 202002L
        const bool selected = policy.m_value.contains(mime);
#else
        const bool selected = policy.m_value.find(mime) != policy.m_value.end();
#endif
        std::ostringstream json;
        json.imbue(std::locale::classic());
        json << R"({"sdk_version":"3.0.14","response_content_type":)" << qmime
             << R"(,"response_header_content_type":)" << qresponse
             << R"(,"request_header_content_type":)" << qrequest
             << R"(,"request_body_type":)" << static_cast<int>(native.m_requestBodyType)
             << R"(,"request_body_processor":)" << static_cast<int>(native.m_requestBodyProcessor)
             << R"(,"response_body_access":)" << static_cast<int>(native.m_rules->m_secResponseBodyAccess)
             << R"(,"mime_policy_set":)" << (policy.m_set ? "true" : "false")
             << R"(,"mime_policy_clear":)" << (policy.m_clear ? "true" : "false")
             << R"(,"mime_types":)" << types
             << R"(,"mime_selected":)" << (selected ? "true" : "false") << '}';
        const std::string encoded = json.str();
        const size_t count = encoded.copy(output, capacity - 1U);
        output[count] = '\0';
        if (!encoded.empty() && encoded.size() < capacity) result = 1;
    }
    return result;
}

extern "C" int msconnector_lifecycle_sdk_mime_selection(
        void* engine, const void* transaction, char* output, size_t capacity) {
    const int saved = errno;
    int result = -1;
    if (engine == nullptr || transaction == nullptr || output == nullptr || capacity < 2U) {
        errno = saved;
        return result;
    }
    output[0] = '\0';
    if (const char* identity = modsecurity::msc_who_am_i(static_cast<modsecurity::ModSecurity*>(engine));
            !expected_version(identity)) {
        errno = saved;
        return -2;
    }
    /* Runtime version rejection precedes every native Transaction dereference. */
    if (const auto* native = static_cast<const modsecurity::Transaction*>(transaction);
            native->m_rules != nullptr) {
        result = observe_transaction(*native, output, capacity);
    }
    errno = saved;
    return result;
}
