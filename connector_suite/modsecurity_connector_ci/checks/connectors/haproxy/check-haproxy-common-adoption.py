#!/usr/bin/env python3
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import re
import sys
ROOT = connector_root()
paths = [p for p in (source_path('connectors/haproxy', root=ROOT)).rglob('*') if p.is_file() and p.suffix in {'.c','.h','.md',''}]
text = '\n'.join(p.read_text(errors='ignore') for p in paths)
binding = (source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)).read_text()
mapper = (source_path('connectors/haproxy/src/haproxy_modsecurity_mapper.c', root=ROOT)).read_text()
runtime_text = '\n'.join(p.read_text(errors='ignore') for p in (source_path('connectors/haproxy', root=ROOT)).rglob('*.c') if p.name != 'haproxy_modsecurity_mapper.c')
spop_runtime = (source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)).read_text()
haproxy_harness = (source_path('connectors/haproxy/harness/run_haproxy_smoke.sh', root=ROOT)).read_text()


def mask_c_comments(source):
    """Preserve code offsets while preventing comments from satisfying checks."""
    def mask(match):
        return ''.join('\n' if char == '\n' else ' ' for char in match.group(0))

    return re.sub(r'/\*.*?\*/|//[^\n]*', mask, source, flags=re.DOTALL)


def c_function(source, signature):
    """Return one complete function from comment-masked C source."""
    start = source.index(signature)
    body_start = source.index('{', start)
    depth = 0
    for index in range(body_start, len(source)):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise ValueError(f'unterminated function: {signature}')


mapper_checked = mask_c_comments(mapper)
binding_checked = mask_c_comments(binding)
request_mapper = c_function(mapper_checked, 'int haproxy_modsecurity_map_owned_request(')
response_mapper = c_function(mapper_checked, 'int haproxy_modsecurity_map_owned_response(')
header_validator = c_function(mapper_checked, 'static int haproxy_validate_source_headers(')
engine_creator = c_function(binding_checked, 'int haproxy_modsecurity_engine_create(')
rule_id_decoder = c_function(binding_checked, 'static void capture_log_rule_id(')
intervention_capture = c_function(binding_checked, 'static int capture_intervention(')
# Match the reviewed helper, not the former inline spelling. An exact body
# comparison rejects early returns, missing guards and unchecked conversions;
# compiled helper tests separately exercise native/Common behavior.
expected_rule_id_decoder = r'''static void capture_log_rule_id(haproxy_modsecurity_decision *decision,
        const char *log) {
    char common_rule_id[64] = {0};
    char *end = 0;
    long parsed;

    if (msconnector_rule_id_extract_from_message(log, common_rule_id,
            sizeof(common_rule_id)) <= 0) {
        return;
    }
    parsed = strtol(common_rule_id, &end, 10);
    if (end != common_rule_id && end != 0 && *end == '\0' &&
            parsed >= 0L && parsed <= (long)INT_MAX) {
        decision->rule_id = (int)parsed;
    }
}'''
rule_id_decoder_is_bounded = (
    re.sub(r'\s+', ' ', rule_id_decoder).strip()
    == re.sub(r'\s+', ' ', expected_rule_id_decoder).strip()
    and 'capture_log_rule_id(decision, intervention.log);' in intervention_capture
)
spop_checked = mask_c_comments(spop_runtime)
decision_log_writer = c_function(spop_checked, 'static int decision_log_write(')
decision_log_renderer = c_function(spop_checked, 'static void decision_log_render_metadata(')
metadata_renderer_call = (
    'decision_log_render_metadata(file, state, request, decision, '
    'modsecurity_processed, decision_text, phase4_disruptive);'
)
common_event_call = (
    'event_serialized = phase4_common_event_write(file, request, decision, '
    'phase4_requested_action(decision, decision_text), "", '
    'safe_decision_reason_code(decision, modsecurity_processed, decision_text), &error);'
)
decision_log_writer_flat = re.sub(r'\s+', ' ', decision_log_writer)
decision_log_metadata = decision_log_writer + decision_log_renderer
phase4_event_writer = c_function(spop_checked, 'static int phase4_common_event_write(')
ok = True
def check(cond,msg):
    global ok
    print(('PASS' if cond else 'FAIL')+': '+msg)
    ok = ok and cond
check(metadata_renderer_call in decision_log_writer_flat,
      'HAProxy mandatory decision writer invokes the metadata renderer with current operation state')
check('msconnector_config common_config' in text, 'HAProxy config/runtime embeds msconnector_config common_config')
check('msconnector_config_init' in text and 'msconnector_config_merge' in text and 'msconnector_config_validate' in text, 'HAProxy uses Common config init/merge/validate')
for sym in ['msconnector_parse_bool','msconnector_parse_phase4_mode','msconnector_parse_size']:
    check(sym in text or 'BLOCKED' in text, f'HAProxy uses or documents {sym}')
check('msconnector_parse_bool("on", &bool_value) != 1' in binding, 'Common parser success is treated as return value 1')
check('msconnector_parse_size("1048576", &size_value) != 1' in binding and 'msconnector_parse_size("1m"' not in binding, 'size parser probe uses decimal bytes, not 1m')
check('config_error[0] = \'\\0\';' in binding, 'config error buffer is initialized before use')
check('MSCONNECTOR_DIRECTIVE_' in text or 'msconnector_directive_spec' in text or 'msconnector_directive_adapter' in text, 'HAProxy references Common directive macros/specs/adapters')
check('haproxy_modsecurity_map_owned_request' in text and 'msconnector_request_mapper_contract' in text and 'msconnector_request_mapper_validate_output' in text, 'HAProxy request mapper uses Common request contract')
check('haproxy_modsecurity_map_owned_response' in text and 'msconnector_response_mapper_contract' in text and 'msconnector_response_mapper_validate_output' in text, 'HAProxy response mapper uses Common response contract')
check('haproxy_modsecurity_map_owned_request(' in runtime_text, 'request mapper has a callsite outside mapper.c/.h')
check('haproxy_modsecurity_map_owned_response(' in runtime_text, 'response mapper has a callsite outside mapper.c/.h')
check('haproxy_modsecurity_mapped_request_cleanup(&mapped_request)' in binding, 'request mapper callsite cleans up mapped header array')
check('haproxy_modsecurity_mapped_response_cleanup(&mapped_response)' in binding, 'response mapper callsite cleans up mapped header array')
check('haproxy_modsecurity_mapped_request_cleanup' in mapper and 'haproxy_modsecurity_mapped_response_cleanup' in mapper, 'owned mapper cleanup APIs exist')
check('free(mapped->owned_headers)' in mapper and 'free((void *)' not in mapper, 'cleanup frees non-const owned_headers without const casts')
check('(void *)request->headers' not in mapper and '(void *)response->headers' not in mapper, 'mapper does not cast const request/response headers for free')
host_validation_call = 'haproxy_validate_source_headers(src->headers, src->header_count, 1,'
headers_to_common_call = 'haproxy_headers_to_common(src->headers, src->header_count,'
request_header_validation = '''if (haproxy_validate_source_headers(src->headers, src->header_count, 1,
            error, error_len) != 1) {
        return 0;
    }'''
host_rejection = '''if (host_header == 0 || host_header->value == 0 ||
            host_header->value_size == 0U) {
        haproxy_mapper_error(error, error_len, "missing or invalid Host header");
        haproxy_modsecurity_mapped_request_cleanup(out);
        return 0;
    }'''
request_validation = '''rc = msconnector_request_mapper_validate_output(contract, &out->request, error, error_len);
    if (rc != 1) {
        haproxy_modsecurity_mapped_request_cleanup(out);
        return 0;
    }'''
common_request_validation = '''if (msconnector_request_validate(&out->request) != 1) {
        haproxy_mapper_error(error, error_len, "invalid mapped request headers");
        haproxy_modsecurity_mapped_request_cleanup(out);
        return 0;
    }'''
response_validation = '''rc = msconnector_response_mapper_validate_output(contract, &out->response, error, error_len);
    if (rc != 1) {
        haproxy_modsecurity_mapped_response_cleanup(out);
        return 0;
    }'''
common_response_validation = '''if (msconnector_response_validate(&out->response) != 1) {
        haproxy_mapper_error(error, error_len, "invalid mapped response headers");
        haproxy_modsecurity_mapped_response_cleanup(out);
        return 0;
    }'''
config_merge_validation = '''if (msconnector_config_merge(&created->common_config, &created->common_config,
                &config->common_config) != 1 ||
                msconnector_config_validate(&created->common_config, config_error,
                    sizeof(config_error)) != 1) {
            copy_message(decision->log_message, sizeof(decision->log_message),
                config_error[0] != '\\0' ? config_error : "Common config validation failed");
            haproxy_modsecurity_engine_destroy(created);
            return 1;
        }'''
check(config_merge_validation in engine_creator,
      'engine configuration treats Common merge and validation return 1 as success')
check(request_header_validation in request_mapper and
      request_mapper.index(request_header_validation) < request_mapper.index(headers_to_common_call),
      'request mapper validates exactly one Host before owned-header allocation')
check('if (haproxy_header_name_is(name, "host")) {' in header_validator and
      '++host_count;' in header_validator and
      'if (require_host && host_count != 1U) {' in header_validator and
      '"missing or duplicate Host header"' in header_validator,
      'header validation rejects missing or duplicate Host before mapper allocation')
check('msconnector_headers_find_first(out->request.headers' in request_mapper,
      'request mapper looks up Host header explicitly')
check(host_rejection in request_mapper,
      'request mapper rejects empty Host and cleans allocated mapper state')
check('out->request.server.address = src->server_ip;' in request_mapper and
      'out->request.hostname = host_header->value;' in request_mapper and
      'out->request.hostname = src->server_ip;' not in request_mapper and
      request_mapper.index(host_rejection) < request_mapper.index('out->request.hostname = host_header->value;'),
      'request mapper derives hostname from validated Host and keeps server_ip as server address')
check(request_validation in request_mapper and common_request_validation in request_mapper,
      'request mapper evaluates Common validation returns and cleans failures')
check(response_validation in response_mapper and common_response_validation in response_mapper,
      'response mapper evaluates Common validation returns and cleans failures')
check('return 1;' in mapper, 'request/response mappers return 1 on success')
check('msconnector_headers_find_first' in text, 'HAProxy uses Common header lookup helpers')
check('msconnector_event_write_jsonl_line' in text or 'msconnector_rule_id_extract_from_message' in text or 'msconnector_json_escape' in text or 'msconnector_sanitize_log_message' in text, 'HAProxy uses Common event/rule/json/log primitives or documents gap')
check('char common_rule_id[64] = {0};' in rule_id_decoder,
      'rule-id buffer is initialized before extraction')
check(rule_id_decoder_is_bounded, 'rule-id extraction only uses positive results')
for field in [
    'rule_message', 'matched_variable', 'matched_value_snippet', 'redirect_url',
    'client_ip', 'method', 'uri', 'host',
]:
    check(f'JSON_FIELD_STRING("{field}"' not in decision_log_metadata,
          f'HAProxy decision JSONL omits payload-bearing field {field}')
check(metadata_renderer_call in decision_log_writer_flat and
      'safe_decision_reason_code' in decision_log_renderer and
      'json_write_string(file, reason_code)' in decision_log_renderer,
      'HAProxy decision JSONL emits a bounded safe reason code')
check(metadata_renderer_call in decision_log_writer_flat and
      common_event_call in decision_log_writer_flat and
      'actual_action = "";' in decision_log_renderer and
      'actual_action = phase4_actual_action' not in decision_log_metadata and
      'JSON_FIELD_STRING("transport_result", "not_observable")' in decision_log_renderer and
      'event.decision.actual_action = actual_action;' in phase4_event_writer and
      'event.http.transport_result = "not_observable";' in phase4_event_writer,
      'HAProxy pre-ACK response metadata leaves actual host action and transport unobserved')
check('phase4_common_event_write' in spop_runtime and
      'msconnector_event_write_jsonl_line' in spop_runtime and
      'event.meta.event = "phase4_intervention"' in spop_runtime and
      'event.meta.message_id' in spop_runtime,
      'HAProxy Phase4 diagnostics also emit the Common metadata-only event model')
check('http-response wait-for-body' not in haproxy_harness,
      'HAProxy host harness does not delay output with a response-body wait-for-body sample')
check('decision->log_message' not in decision_log_metadata and
      'reason != 0 ? reason' not in decision_log_metadata,
      'HAProxy decision JSONL does not serialize intervention log text')
check('NOTIFY header[%u] name=%s value=%s' not in spop_runtime and
      'method=%s path=%s uri=%s host=%s test_header=%s' not in spop_runtime,
      'HAProxy agent log does not serialize raw request header or URI values')
check('build_decision_ack_payload(&ack_payload, &decision,\n                        safe_decision_reason_code(' in spop_runtime,
      'HAProxy ACK error variable uses a safe classification instead of intervention text')
for bad in ['haproxy_parse_bool(', 'haproxy_parse_phase4(', 'haproxy_parse_size(', 'haproxy_json_escape(', 'haproxy_rule_id_extract(']:
    check(bad not in text, f'no duplicate helper {bad}')
for forbidden in ['production verified claim', 'runtime verified claim', 'full-matrix verified claim', 'crs verified claim']:
    check(forbidden not in text.lower(), f'no unsupported {forbidden}')
sys.exit(0 if ok else 1)
