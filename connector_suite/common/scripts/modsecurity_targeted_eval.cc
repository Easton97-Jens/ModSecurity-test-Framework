#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>

namespace {

constexpr const char *kTargetedRuleId = "1000001";
constexpr const char *kRequestBodyRuleId = "1000002";
using ArgumentMap = std::map<std::string, std::string, std::less<>>;

struct EvaluatorOptions {
    std::string rule_file;
    std::string decision_log;
    std::string ruleset;
    std::string smoke_case;
    std::string header_value;
    std::string uri;
    std::string method;
    std::string body;
    std::string content_type;
    std::string request_body_marker;
};

std::string json_escape(const std::string &value) {
    std::string out;
    out.reserve(value.size() + 8U);
    for (char ch : value) {
        switch (ch) {
            case '\\':
                out += R"(\\)";
                break;
            case '"':
                out += R"(\")";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += ch;
                break;
        }
    }
    return out;
}

void json_string(std::ostream &out, const char *key, const std::string &value, bool comma = true) {
    out << "\"" << key << "\":\"" << json_escape(value) << "\"";
    if (comma) {
        out << ",";
    }
}

void json_bool(std::ostream &out, const char *key, bool value, bool comma = true) {
    out << "\"" << key << "\":" << (value ? "true" : "false");
    if (comma) {
        out << ",";
    }
}

void json_int(std::ostream &out, const char *key, int value, bool comma = true) {
    out << "\"" << key << "\":" << value;
    if (comma) {
        out << ",";
    }
}

ArgumentMap parse_args(int argc, char **argv) {
    ArgumentMap args;
    for (int argument_index = 1; argument_index < argc; argument_index += 2) {
        const std::string key = argv[argument_index];
        if (key.rfind("--", 0) != 0 || argument_index + 1 >= argc) {
            std::cerr << "usage: " << argv[0]
                      << " --rule-file <path> --decision-log <path>"
                      << " [--ruleset targeted|crs] [--smoke-case targeted|request_body]"
                      << " [--header-value <value>] [--uri <uri>] [--method <method>]"
                      << " [--body <body>] [--content-type <content-type>]\n";
            std::exit(2);
        }
        args[key.substr(2)] = argv[argument_index + 1];
    }
    return args;
}

std::string argument_or(const ArgumentMap &arguments, std::string_view key, std::string_view fallback) {
    const auto iterator = arguments.lower_bound(std::string(key));
    if (iterator == arguments.end() || std::string_view(iterator->first) != key) {
        return std::string(fallback);
    }
    return iterator->second;
}

EvaluatorOptions parse_options(const ArgumentMap &arguments) {
    return {
        argument_or(arguments, "rule-file", ""),
        argument_or(arguments, "decision-log", ""),
        argument_or(arguments, "ruleset", "targeted"),
        argument_or(arguments, "smoke-case", "targeted"),
        argument_or(arguments, "header-value", ""),
        argument_or(arguments, "uri", "/targeted"),
        argument_or(arguments, "method", "GET"),
        argument_or(arguments, "body", ""),
        argument_or(arguments, "content-type", ""),
        argument_or(arguments, "request-body-marker", "modsec-request-body-block"),
    };
}

std::string invalid_option_message(const EvaluatorOptions &options) {
    if (options.rule_file.empty()) {
        return "missing --rule-file";
    }
    if (options.ruleset != "targeted" && options.ruleset != "crs") {
        return "unsupported --ruleset: " + options.ruleset;
    }
    if (options.smoke_case != "targeted" && options.smoke_case != "request_body") {
        return "unsupported --smoke-case: " + options.smoke_case;
    }
    return "";
}

std::string bracket_value(std::string_view intervention_log, std::string_view field_key) {
    const std::string marker = "[" + std::string(field_key) + R"marker( ")marker";
    const std::size_t start = intervention_log.find(marker);
    if (start == std::string::npos) {
        return "";
    }
    const std::size_t value_start = start + marker.size();
    const std::size_t end = intervention_log.find(R"marker("])marker", value_start);
    if (end == std::string::npos || end <= value_start) {
        return "";
    }
    return std::string(intervention_log.substr(value_start, end - value_start));
}

bool string_contains(std::string_view value, std::string_view searched_value) {
    if (searched_value.size() > value.size()) {
        return false;
    }
    const std::size_t last_start = value.size() - searched_value.size();
    for (std::size_t start = 0; start <= last_start; ++start) {
        if (value.substr(start, searched_value.size()) == searched_value) {
            return true;
        }
    }
    return false;
}

struct DecisionLogInput {
    std::string path;
    std::string ruleset;
    std::string whoami;
    std::string rule_file;
    std::string header_value;
    std::string smoke_case;
    std::string method;
    std::string content_type;
    std::string request_body_marker;
    bool request_body_access_enabled = false;
    bool request_body_marker_present = false;
    bool rule_loaded = false;
    bool disruptive = false;
    int intervention_status = 200;
    std::string intervention_log;
    std::string rule_id;
    std::string rule_message;
};

struct EvaluationResult {
    bool disruptive = false;
    int intervention_status = 200;
    std::string intervention_log;
    std::string observed_rule_id;
    std::string observed_rule_message;
    bool request_body_access_enabled = false;
    bool request_body_marker_present = false;
};

struct RequestSetupContext {
    modsecurity::Transaction *transaction;
};

struct RequestEvaluationContext {
    modsecurity::Transaction *transaction;
    modsecurity::ModSecurityIntervention *intervention;
};

void add_request_header(
    modsecurity::Transaction *transaction,
    std::string_view name,
    std::string_view value) {
    modsecurity::msc_add_n_request_header(
        transaction,
        reinterpret_cast<const unsigned char *>(name.data()),
        name.size(),
        reinterpret_cast<const unsigned char *>(value.data()),
        value.size());
}

void configure_request(const RequestSetupContext &setup_context, const EvaluatorOptions &options) {
    modsecurity::msc_process_connection(setup_context.transaction, "127.0.0.1", 12345, "127.0.0.1", 8080);
    modsecurity::msc_process_uri(setup_context.transaction, options.uri.c_str(), options.method.c_str(), "1.1");
    add_request_header(setup_context.transaction, "Host", "example.test");
    if (!options.header_value.empty()) {
        add_request_header(setup_context.transaction, "X-Modsec-Smoke", options.header_value);
    }
    if (!options.body.empty()) {
        if (!options.content_type.empty()) {
            add_request_header(setup_context.transaction, "Content-Type", options.content_type);
        }
        const std::string content_length = std::to_string(options.body.size());
        add_request_header(setup_context.transaction, "Content-Length", content_length);
    }
    modsecurity::msc_process_request_headers(setup_context.transaction);
}

EvaluationResult evaluate_request(
    const RequestEvaluationContext &evaluation_context,
    const EvaluatorOptions &options) {
    modsecurity::intervention::clean(evaluation_context.intervention);
    int intervention_rc = modsecurity::msc_intervention(
        evaluation_context.transaction, evaluation_context.intervention);
    bool disruptive = evaluation_context.intervention->disruptive != 0 || intervention_rc != 0;
    if (!disruptive) {
        if (!options.body.empty()) {
            modsecurity::msc_append_request_body(
                evaluation_context.transaction,
                reinterpret_cast<const unsigned char *>(options.body.c_str()),
                options.body.size());
        }
        modsecurity::msc_process_request_body(evaluation_context.transaction);
        intervention_rc = modsecurity::msc_intervention(
            evaluation_context.transaction, evaluation_context.intervention);
        disruptive = evaluation_context.intervention->disruptive != 0 || intervention_rc != 0;
    }
    const std::string intervention_log = evaluation_context.intervention->log == nullptr
                                             ? ""
                                             : evaluation_context.intervention->log;
    std::string observed_rule_id = bracket_value(intervention_log, "id");
    if (observed_rule_id.empty() && options.ruleset != "crs") {
        observed_rule_id = options.smoke_case == "request_body" ? kRequestBodyRuleId : kTargetedRuleId;
    }
    modsecurity::msc_process_logging(evaluation_context.transaction);
    return {
        disruptive,
        disruptive ? evaluation_context.intervention->status : 200,
        intervention_log,
        observed_rule_id,
        options.ruleset == "crs" ? bracket_value(intervention_log, "msg") : "",
        options.smoke_case == "request_body" && !options.body.empty(),
        !options.request_body_marker.empty() && string_contains(options.body, options.request_body_marker),
    };
}

DecisionLogInput decision_log_input(
    const EvaluatorOptions &options,
    const std::string &whoami,
    bool rule_loaded,
    const EvaluationResult &result) {
    return {
        options.decision_log,
        options.ruleset,
        whoami,
        options.rule_file,
        options.header_value,
        options.smoke_case,
        options.method,
        options.content_type,
        options.request_body_marker,
        result.request_body_access_enabled,
        result.request_body_marker_present,
        rule_loaded,
        result.disruptive,
        result.intervention_status,
        result.intervention_log,
        result.observed_rule_id,
        result.observed_rule_message,
    };
}

void append_decision_log(const DecisionLogInput &input) {
    if (input.path.empty()) {
        return;
    }
    std::ofstream out(input.path, std::ios::app);
    out << "decision_backend=libmodsecurity\n";
    out << "modsecurity_ruleset=" << input.ruleset << "\n";
    out << "libmodsecurity=" << input.whoami << "\n";
    out << "rule_file=" << input.rule_file << "\n";
    out << "rule_id=" << input.rule_id << "\n";
    out << "modsecurity_smoke_case=" << input.smoke_case << "\n";
    out << "request_method=" << input.method << "\n";
    if (!input.content_type.empty()) {
        out << "request_content_type=" << input.content_type << "\n";
    }
    if (input.smoke_case == "request_body") {
        out << "request_body_access_enabled=" << (input.request_body_access_enabled ? "true" : "false") << "\n";
        out << "request_body_rule_id=" << kRequestBodyRuleId << "\n";
        out << "request_body_rule_loaded=" << (input.rule_loaded ? "true" : "false") << "\n";
        out << "blocked_body_marker=" << input.request_body_marker << "\n";
        out << "blocked_body_marker_present=" << (input.request_body_marker_present ? "true" : "false") << "\n";
    }
    if (input.ruleset == "crs") {
        out << "crs_rule_id=" << input.rule_id << "\n";
        out << "crs_rule_message=" << input.rule_message << "\n";
    }
    out << "rule_loaded=" << (input.rule_loaded ? "true" : "false") << "\n";
    out << "request_header_x_modsec_smoke=" << input.header_value << "\n";
    out << "intervention_disruptive=" << (input.disruptive ? "true" : "false") << "\n";
    out << "intervention_status=" << input.intervention_status << "\n";
    if (!input.intervention_log.empty()) {
        out << "intervention_log=" << input.intervention_log << "\n";
    }
    out << "\n";
}

int fail_json(const std::string &message) {
    std::cout << "{";
    json_bool(std::cout, "ok", false);
    json_string(std::cout, "error", message, false);
    std::cout << "}\n";
    return 1;
}

void write_success_json(
    const EvaluatorOptions &options,
    const std::string &whoami,
    bool rule_loaded,
    const EvaluationResult &result) {
    std::cout << "{";
    json_bool(std::cout, "ok", true);
    json_string(std::cout, "decision_backend", "libmodsecurity");
    json_string(std::cout, "modsecurity_ruleset", options.ruleset);
    json_string(std::cout, "modsecurity_smoke_case", options.smoke_case);
    json_string(std::cout, "libmodsecurity", whoami);
    json_bool(std::cout, "modsecurity_rule_loaded", rule_loaded);
    json_string(std::cout, "modsecurity_rule_file", options.rule_file);
    json_string(std::cout, "modsecurity_rule_id", result.observed_rule_id);
    json_bool(std::cout, "request_body_access_enabled", result.request_body_access_enabled);
    json_string(
        std::cout,
        "request_body_rule_file",
        options.smoke_case == "request_body" ? options.rule_file : "");
    json_string(
        std::cout,
        "request_body_rule_id",
        options.smoke_case == "request_body" ? kRequestBodyRuleId : "");
    json_bool(
        std::cout,
        "request_body_rule_loaded",
        options.smoke_case == "request_body" && rule_loaded);
    json_string(std::cout, "request_method", options.method);
    json_string(
        std::cout,
        "blocked_body_marker",
        options.smoke_case == "request_body" ? options.request_body_marker : "");
    json_bool(std::cout, "blocked_body_marker_present", result.request_body_marker_present);
    json_string(
        std::cout,
        "crs_rule_id",
        options.ruleset == "crs" ? result.observed_rule_id : "");
    json_string(
        std::cout,
        "crs_rule_message",
        options.ruleset == "crs" ? result.observed_rule_message : "");
    json_bool(std::cout, "intervention_disruptive", result.disruptive);
    json_int(std::cout, "intervention_status", result.intervention_status);
    json_string(std::cout, "intervention_log", result.intervention_log, false);
    std::cout << "}\n";
}

struct RuleErrorCleanup {
    const char *value = nullptr;

    RuleErrorCleanup() = default;
    RuleErrorCleanup(const RuleErrorCleanup &) = delete;
    RuleErrorCleanup &operator=(const RuleErrorCleanup &) = delete;
    RuleErrorCleanup(RuleErrorCleanup &&) = delete;
    RuleErrorCleanup &operator=(RuleErrorCleanup &&) = delete;

    ~RuleErrorCleanup() {
        if (value != nullptr) {
            modsecurity::msc_rules_error_cleanup(value);
        }
    }
};

using ModSecurityHandle = std::unique_ptr<
    modsecurity::ModSecurity,
    decltype(&modsecurity::msc_cleanup)>;
using RulesSetHandle = std::unique_ptr<
    modsecurity::RulesSet,
    decltype(&modsecurity::msc_rules_cleanup)>;
using TransactionHandle = std::unique_ptr<
    modsecurity::Transaction,
    decltype(&modsecurity::msc_transaction_cleanup)>;

}  // namespace

int main(int argc, char **argv) {
    const EvaluatorOptions options = parse_options(parse_args(argc, argv));
    if (const std::string option_error = invalid_option_message(options);
            !option_error.empty()) {
        return fail_json(option_error);
    }

    const ModSecurityHandle modsec(modsecurity::msc_init(), &modsecurity::msc_cleanup);
    if (modsec == nullptr) {
        return fail_json("msc_init failed");
    }
    modsecurity::msc_set_connector_info(modsec.get(), "ModSecurity-conector targeted smoke");
    const char *who = modsecurity::msc_who_am_i(modsec.get());
    const std::string whoami = who == nullptr ? "unknown" : who;

    const RulesSetHandle rules(
        modsecurity::msc_create_rules_set(), &modsecurity::msc_rules_cleanup);
    if (rules == nullptr) {
        return fail_json("msc_create_rules_set failed");
    }

    RuleErrorCleanup rule_error;
    const int rule_count = modsecurity::msc_rules_add_file(
        rules.get(), options.rule_file.c_str(), &rule_error.value);
    const bool rule_loaded = rule_count >= 0;
    if (!rule_loaded) {
        const std::string message = rule_error.value == nullptr
                                        ? "msc_rules_add_file failed"
                                        : rule_error.value;
        return fail_json(message);
    }

    const TransactionHandle tx(
        modsecurity::msc_new_transaction(modsec.get(), rules.get(), nullptr),
        &modsecurity::msc_transaction_cleanup);
    if (tx == nullptr) {
        return fail_json("msc_new_transaction failed");
    }

    const RequestSetupContext setup_context{tx.get()};
    configure_request(setup_context, options);

    modsecurity::ModSecurityIntervention intervention{};
    const RequestEvaluationContext evaluation_context{tx.get(), &intervention};
    const EvaluationResult result = evaluate_request(evaluation_context, options);
    append_decision_log(decision_log_input(options, whoami, rule_loaded, result));
    write_success_json(options, whoami, rule_loaded, result);

    modsecurity::msc_intervention_cleanup(&intervention);
    return 0;
}
