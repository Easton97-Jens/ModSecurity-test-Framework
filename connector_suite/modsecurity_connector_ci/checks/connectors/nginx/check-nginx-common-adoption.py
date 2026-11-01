#!/usr/bin/env python3
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import re, sys
ROOT = connector_root()
nginx = source_path('connectors/nginx/src', root=ROOT)
common_h = (nginx/'ngx_http_modsecurity_common.h').read_text()
module_c = (nginx/'ngx_http_modsecurity_module.c').read_text()
mapper_h = (nginx/'ngx_http_modsecurity_mapper.h').read_text() if (nginx/'ngx_http_modsecurity_mapper.h').exists() else ''
mapper_c = (nginx/'ngx_http_modsecurity_mapper.c').read_text() if (nginx/'ngx_http_modsecurity_mapper.c').exists() else ''
body_c = (nginx/'ngx_http_modsecurity_body_filter.c').read_text()
access_c = (nginx/'ngx_http_modsecurity_access.c').read_text()
header_c = (nginx/'ngx_http_modsecurity_header_filter.c').read_text()
log_c = (nginx/'ngx_http_modsecurity_log.c').read_text()
nginx_config = (source_path('connectors/nginx/config', root=ROOT)).read_text()
ddebug_h = (nginx/'ddebug.h').read_text()
EVENT_BODY_BYTES_SEEN = 'event.body.bytes_seen'
EVENT_BODY_BYTES_INSPECTED = 'event.body.bytes_inspected'
REQUEST_BODY_ACCESS = 'r->request_body'
EVENT_JSONL_HEADER = '"msconnector/event_jsonl.h"'
EVENT_JSONL_LINE_BUFFER = 'char line[4096];'
RETURN_NGX_OK = 'return NGX_OK;'
CTX_NULL_GUARD = 'if (ctx == NULL)'
CTX_INTERVENTION_GUARD = 'if (ctx->intervention_triggered)'
CTX_BODY_MAPPER_SKIP_GUARD = 'if (ctx->intervention_triggered || ctx->phase4_processed)'
CTX_RESPONSE_VALIDATED_GUARD = 'if (ctx->common_response_validated)'
CTX_RESPONSE_VALIDATED_ASSIGNMENT = 'ctx->common_response_validated = 1;'
ERR_STATUS_PRESENT = 'r->err_status != 0'
BODY_RESPONSE_CHAIN_APPEND_CONTRACT_PATTERN = re.compile(
    r'static\s+ngx_int_t\s+'
    r'ngx_http_modsecurity_append_response_chain_buffer\s*\(\s*'
    r'ngx_http_request_t\s*\*\s*r\s*,\s*'
    r'ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*,\s*'
    r'const\s+ngx_http_modsecurity_conf_t\s*\*\s*mcf\s*,\s*'
    r'const\s+ngx_chain_t\s*\*\s*chain\s*\)\s*\{\s*'
    r'return\s+ngx_http_modsecurity_append_response_body_buffer\s*\(\s*'
    r'r\s*,\s*ctx\s*,\s*mcf\s*,\s*chain\s*->\s*buf\s*\)\s*;\s*\}'
)
BODY_RESPONSE_CHAIN_CALL_PATTERN = re.compile(
    r'\bngx_http_modsecurity_append_response_chain_buffer\s*\(\s*'
    r'r\s*,\s*ctx\s*,\s*mcf\s*,\s*chain\s*\)'
)
BODY_FILTER_DIRECT_CHAIN_CONTRACT_PATTERN = re.compile(
    r'ngx_int_t\s+ngx_http_modsecurity_body_filter\s*\(\s*'
    r'ngx_http_request_t\s*\*\s*r\s*,\s*ngx_chain_t\s*\*\s*in\s*\)\s*\{\s*'
    r'ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*;\s*'
    r'ngx_int_t\s+status\s*;\s*'
    r'status\s*=\s*ngx_http_modsecurity_prepare_response_body_filter\s*\(\s*'
    r'r\s*,\s*in\s*,\s*&ctx\s*\)\s*;\s*'
    r'if\s*\(\s*status\s*==\s*NGX_DECLINED\s*\)\s*\{\s*'
    r'return\s+ngx_http_next_body_filter\s*\(\s*r\s*,\s*in\s*\)\s*;\s*\}\s*'
    r'if\s*\(\s*status\s*!=\s*NGX_OK\s*\)\s*\{\s*'
    r'return\s+status\s*;\s*\}\s*'
    r'return\s+ngx_http_modsecurity_process_response_body_chain\s*\(\s*'
    r'r\s*,\s*in\s*,\s*ctx\s*\)\s*;\s*\}'
)
BODY_RESPONSE_BUFFER_CONTRACT_PATTERN = re.compile(
    r'static\s+ngx_int_t\s+'
    r'ngx_http_modsecurity_append_response_body_buffer\s*\(\s*'
    r'ngx_http_request_t\s*\*\s*r\s*,\s*'
    r'ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*,\s*'
    r'const\s+ngx_http_modsecurity_conf_t\s*\*\s*mcf\s*,\s*'
    r'const\s+ngx_buf_t\s*\*\s*buffer\s*\)\s*\{\s*'
    r'if\s*\(\s*ngx_buf_in_memory\s*\(\s*buffer\s*\)\s*\)\s*\{\s*'
    r'const\s+u_char\s*\*\s*data\s*=\s*buffer\s*->\s*pos\s*;\s*'
    r'size_t\s+len\s*=\s*buffer\s*->\s*last\s*>=\s*buffer\s*->\s*pos\s*'
    r'\?\s*\(\s*size_t\s*\)\s*\(\s*buffer\s*->\s*last\s*-\s*'
    r'buffer\s*->\s*pos\s*\)\s*:\s*0\s*;\s*'
    r'return\s+ngx_http_modsecurity_append_accounted_response_body\s*\(\s*'
    r'ctx\s*,\s*mcf\s*,\s*data\s*,\s*len\s*\)\s*;\s*\}\s*'
    r'if\s*\(\s*buffer\s*->\s*in_file\s*\)\s*\{\s*'
    r'return\s+ngx_http_modsecurity_append_file_response_body\s*\(\s*'
    r'r\s*,\s*ctx\s*,\s*mcf\s*,\s*buffer\s*\)\s*;\s*\}\s*'
    r'return\s+NGX_OK\s*;\s*\}'
)
BODY_RESPONSE_LIMITED_CONTRACT_PATTERN = re.compile(
    r'static\s+ngx_int_t\s+'
    r'ngx_http_modsecurity_append_accounted_response_body\s*\(\s*'
    r'ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*,\s*'
    r'const\s+ngx_http_modsecurity_conf_t\s*\*\s*mcf\s*,\s*'
    r'const\s+u_char\s*\*\s*data\s*,\s*size_t\s+len\s*\)\s*\{\s*'
    r'size_t\s+allowed\s*;\s*'
    r'if\s*\(\s*ngx_http_modsecurity_account_response_body\s*\(\s*'
    r'ctx\s*,\s*mcf\s*,\s*len\s*,\s*&\s*allowed\s*\)\s*'
    r'!=\s*NGX_OK\s*\)\s*\{\s*return\s+NGX_ERROR\s*;\s*\}\s*'
    r'return\s+ngx_http_modsecurity_append_response_body_chunk\s*\(\s*'
    r'ctx\s*,\s*data\s*,\s*allowed\s*\)\s*;\s*\}'
)
BODY_RESPONSE_CHAIN_CALL_CONTRACT_PATTERN = re.compile(
    r'static\s+ngx_int_t\s+'
    r'ngx_http_modsecurity_process_response_body_chain\s*\(\s*'
    r'ngx_http_request_t\s*\*\s*r\s*,\s*'
    r'ngx_chain_t\s*\*\s*in\s*,\s*'
    r'ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*\)\s*\{\s*'
    r'ngx_chain_t\s*\*\s*segment_start\s*=\s*in\s*;\s*'
    r'ngx_chain_t\s*\*\s*segment_previous\s*=\s*NULL\s*;\s*'
    r'const\s+ngx_http_modsecurity_conf_t\s*\*\s*mcf\s*;\s*'
    r'int\s+is_request_processed\s*=\s*0\s*;\s*'
    r'mcf\s*=\s*ngx_http_get_module_loc_conf\s*\(\s*r\s*,\s*'
    r'ngx_http_modsecurity_module\s*\)\s*;\s*'
    r'for\s*\(\s*ngx_chain_t\s*\*\s*chain\s*=\s*in\s*;\s*chain\s*!=\s*NULL\s*;\s*'
    r'chain\s*=\s*chain\s*->\s*next\s*\)\s*\{\s*'
    r'ngx_int_t\s+ret\s*;\s*'
    r'ngx_uint_t\s+final_body_forwarded\s*;\s*'
    r'ngx_uint_t\s+terminal_processed\s*;\s*'
    r'ret\s*=\s*ngx_http_modsecurity_append_response_chain_buffer\s*\(\s*'
    r'r\s*,\s*ctx\s*,\s*mcf\s*,\s*chain\s*\)\s*;\s*'
    r'if\s*\(\s*ret\s*!=\s*NGX_OK\s*\)\s*\{\s*'
    r'return\s+ngx_http_modsecurity_phase4_fail_control\s*\(\s*'
    r'r\s*,\s*mcf\s*,\s*ctx\s*,\s*'
    r'MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR\s*\)\s*;\s*\}'
)
BODY_RESPONSE_RAW_SINK_PATTERN = re.compile(
    r'\bmsc_append_response_body\s*\(\s*ctx\s*->\s*modsec_transaction\s*,\s*'
    r'data\s*,\s*bytes\s*\)'
)
BODY_RESPONSE_RAW_SINK_NAME_PATTERN = re.compile(
    r'\bmsc_append_response_body\b'
)
BODY_RESPONSE_MAPPER_ONCE_CONTRACT_PATTERN = re.compile(
    r'static\s+ngx_int_t\s+'
    r'ngx_http_modsecurity_validate_response_mapper_once\s*\(\s*'
    r'ngx_http_request_t\s*\*\s*r\s*,\s*'
    r'ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*\)\s*\{\s*'
    r'if\s*\(\s*ctx\s*->\s*common_response_validated\s*\)\s*\{\s*'
    r'return\s+NGX_OK\s*;\s*\}\s*'
    r'ngx_http_modsecurity_validate_response_mapper\s*\(\s*ctx\s*,\s*r\s*,\s*'
    r'NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_BODY\s*\)\s*;\s*'
    r'ctx\s*->\s*common_response_validated\s*=\s*1\s*;\s*'
    r'return\s+NGX_OK\s*;\s*\}'
)
RESPONSE_MAPPER_BODY_CALL_PATTERN = re.compile(
    r'ngx_http_modsecurity_validate_response_mapper\s*\(\s*ctx\s*,\s*r\s*,\s*'
    r'NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_BODY\s*\)\s*;'
)
RESPONSE_MAPPER_HEADER_CALL_PATTERN = re.compile(
    r'ngx_http_modsecurity_validate_response_mapper\s*\(\s*ctx\s*,\s*r\s*,\s*'
    r'NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_HEADER\s*\)\s*;'
)
RESPONSE_VALIDATED_ASSIGNMENT_PATTERN = re.compile(
    r'ctx\s*->\s*common_response_validated\s*=\s*1\s*;'
)
RESPONSE_VALIDATED_GUARD_PATTERN = re.compile(
    r'if\s*\(\s*ctx\s*->\s*common_response_validated\s*\)\s*\{'
)
HEADER_CTX_NULL_GUARD_PATTERN = re.compile(
    r'if\s*\(\s*ctx\s*==\s*NULL\s*\)\s*\{'
    r'[^{}]*?return\s+ngx_http_next_header_filter\s*\(\s*r\s*\)\s*;\s*\}'
)
HEADER_CTX_ACQUISITION_PATTERN = re.compile(
    r'ctx\s*=\s*ngx_http_modsecurity_get_module_ctx\s*\(\s*r\s*\)\s*;'
)
HEADER_CTX_DECLARATION_PREFIX_PATTERN = re.compile(
    r'\s*ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*;\s*'
    r'int\s+ret\s*=\s*0\s*;\s*'
    r'ngx_uint_t\s+status\s*;\s*'
    r'const\s+char\s*\*\s*http_response_ver\s*;\s*'
    r'ngx_http_modsecurity_pcre_pool_snapshot_t\s+old_pool\s*;\s*'
    r'const\s+ngx_http_modsecurity_conf_t\s*\*\s*mcf\s*;\s*'
    r'size_t\s+response_header_count\s*;\s*'
    r'size_t\s+response_header_bytes\s*;\s*'
    r'const\s+char\s*\*\s*response_content_type\s*=\s*NULL\s*;\s*'
    r'ngx_http_modsecurity_engine_call_measurement\s+measurement\s*;\s*'
)
HEADER_CTX_DIAGNOSTIC_CALL_PATTERN = re.compile(
    r'\bdd\s*\(\s*,\s*ctx\s*\)\s*;'
)
HEADER_CTX_DIAGNOSTIC_FORMAT_LITERAL = '"header filter, recovering ctx: %p"'
HEADER_CTX_DIAGNOSTIC_VISIBLE_CALL_PATTERN = re.compile(
    r'\bdd\s*\(\s*'
    + re.escape(HEADER_CTX_DIAGNOSTIC_FORMAT_LITERAL)
    + r'\s*,\s*ctx\s*\)\s*;'
)
HEADER_RESPONSE_HEADER_FAILURE_GUARD_PATTERN = re.compile(
    r'if\s*\(\s*ctx\s*->\s*response_headers_processing_failed\s*\)\s*\{'
    r'\s*return\s+NGX_ERROR\s*;\s*\}'
)
HEADER_INTERVENTION_GUARD_PATTERN = re.compile(
    r'if\s*\(\s*ctx\s*->\s*intervention_triggered\s*\)\s*\{'
    r'\s*return\s+ngx_http_next_header_filter\s*\(\s*r\s*\)\s*;\s*\}'
)
HEADER_PROCESSED_GUARD_PATTERN = re.compile(
    r'if\s*\(\s*ctx\s*&&\s*ctx\s*->\s*processed\s*\)\s*\{'
)
HEADER_PROCESSED_ASSIGNMENT_PATTERN = re.compile(
    r'ctx\s*->\s*processed\s*=\s*1\s*;'
)
HEADER_RESPONSE_HEADER_COLLECTION_CONTRACT_PATTERN = re.compile(
    r'if\s*\(\s*ctx\s*&&\s*ctx\s*->\s*processed\s*\)\s*\{\s*'
    r'dd\s*\([^;]*\)\s*;\s*'
    r'return\s+ngx_http_next_header_filter\s*\(\s*r\s*\)\s*;\s*\}\s*'
    r'r\s*->\s*filter_need_in_memory\s*=\s*1\s*;\s*'
    r'ctx\s*->\s*processed\s*=\s*1\s*;\s*'
    r'if\s*\(\s*ngx_http_modsecurity_add_response_headers\s*\(\s*'
    r'r\s*,\s*ctx\s*\)\s*!=\s*NGX_OK\s*\)\s*\{\s*'
    r'ctx\s*->\s*response_headers_processing_failed\s*=\s*1\s*;\s*'
    r'ctx\s*->\s*intervention_triggered\s*=\s*1\s*;\s*'
    r'return\s+NGX_ERROR\s*;\s*\}\s*'
    r'if\s*\(\s*r\s*->\s*err_status\s*\)\s*\{'
)
HEADER_RESPONSE_HEADER_COLLECTION_WRAPPER_CONTRACT_PATTERN = re.compile(
    r'if\s*\(\s*ngx_http_modsecurity_add_n_response_header\s*\(\s*'
    r'ctx\s*,\s*\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*'
    r'header\s*->\s*key\s*\.\s*data\s*,\s*header\s*->\s*key\s*\.\s*len\s*,\s*'
    r'\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*header\s*->\s*value\s*\.\s*data\s*,\s*'
    r'header\s*->\s*value\s*\.\s*len\s*\)\s*!=\s*1\s*\)\s*\{\s*'
    r'[^{}]*\breturn\s+NGX_ERROR\s*;\s*\}'
)
HEADER_RESPONSE_HEADER_COLLECTION_SYNTHETIC_CONTRACT_PATTERN = re.compile(
    r'for\s*\(\s*i\s*=\s*0\s*;\s*'
    r'ngx_http_modsecurity_headers_out\s*\[\s*i\s*\]\s*\.\s*name\s*\.\s*len\s*;\s*'
    r'i\s*\+\+\s*\)\s*\{\s*'
    r'dd\s*\([^;]*\)\s*;\s*'
    r'if\s*\(\s*ngx_http_modsecurity_headers_out\s*\[\s*i\s*\]\s*'
    r'\.\s*resolver\s*\(\s*r\s*,\s*'
    r'ngx_http_modsecurity_headers_out\s*\[\s*i\s*\]\s*\.\s*name\s*,\s*'
    r'ngx_http_modsecurity_headers_out\s*\[\s*i\s*\]\s*\.\s*offset\s*\)\s*'
    r'!=\s*1\s*\)\s*\{\s*[^{}]*\breturn\s+NGX_ERROR\s*;\s*\}\s*\}'
)
HEADER_RESPONSE_HEADER_COLLECTION_PREFIX_CONTRACT_PATTERN = re.compile(
    r'static\s+ngx_int_t\s+'
    r'ngx_http_modsecurity_add_response_headers\s*\(\s*'
    r'ngx_http_request_t\s*\*\s*r\s*,\s*'
    r'ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*\)\s*\{\s*'
    r'ngx_list_part_t\s*\*\s*part\s*=\s*&\s*r\s*->\s*headers_out\s*'
    r'\.\s*headers\s*\.\s*part\s*;\s*'
    r'ngx_table_elt_t\s*\*\s*data\s*=\s*part\s*->\s*elts\s*;\s*'
    r'const\s+ngx_table_elt_t\s*\*\s*header\s*;\s*'
    r'ngx_uint_t\s+i\s*;\s*'
    r'for\s*\(\s*i\s*=\s*0\s*;\s*'
    r'ngx_http_modsecurity_headers_out\s*\[\s*i\s*\]\s*\.\s*name\s*\.\s*len\s*;\s*'
    r'i\s*\+\+\s*\)\s*\{\s*'
    r'dd\s*\([^;]*\)\s*;\s*'
    r'if\s*\(\s*ngx_http_modsecurity_headers_out\s*\[\s*i\s*\]\s*'
    r'\.\s*resolver\s*\(\s*r\s*,\s*'
    r'ngx_http_modsecurity_headers_out\s*\[\s*i\s*\]\s*\.\s*name\s*,\s*'
    r'ngx_http_modsecurity_headers_out\s*\[\s*i\s*\]\s*\.\s*offset\s*\)\s*'
    r'!=\s*1\s*\)\s*\{\s*[^{}]*\breturn\s+NGX_ERROR\s*;\s*\}\s*\}\s*'
    r'i\s*=\s*0U\s*;\s*'
    r'while\s*\(\s*\(\s*header\s*=\s*'
    r'ngx_http_modsecurity_next_header\s*\(\s*&part\s*,\s*&data\s*,\s*&i\s*\)\s*\)\s*'
    r'!=\s*NULL\s*\)\s*\{'
)
HEADER_RESPONSE_HEADER_COLLECTION_CHAIN_TRAVERSAL_PATTERN = re.compile(
    r'i\s*=\s*0U\s*;\s*'
    r'while\s*\(\s*\(\s*header\s*=\s*'
    r'ngx_http_modsecurity_next_header\s*\(\s*&part\s*,\s*&data\s*,\s*&i\s*\)\s*\)\s*'
    r'!=\s*NULL\s*\)\s*\{\s*'
    r'if\s*\(\s*ngx_http_modsecurity_add_n_response_header\s*\(\s*'
    r'ctx\s*,\s*\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*'
    r'header\s*->\s*key\s*\.\s*data\s*,\s*header\s*->\s*key\s*\.\s*len\s*,\s*'
    r'\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*header\s*->\s*value\s*\.\s*data\s*,\s*'
    r'header\s*->\s*value\s*\.\s*len\s*\)\s*!=\s*1\s*\)\s*\{\s*'
    r'[^{}]*\breturn\s+NGX_ERROR\s*;\s*\}\s*\}\s*'
    r'return\s+NGX_OK\s*;\s*\}'
)
HEADER_SYNTHETIC_RESOLVER_TABLE_PATTERN = re.compile(
    r'ngx_http_modsecurity_header_out_t\s+ngx_http_modsecurity_headers_out\s*'
    r'\[\s*\]\s*=\s*\{\s*'
    r'\{\s*ngx_string\s*\(\s*"Server"\s*\)\s*,\s*'
    r'offsetof\s*\(\s*ngx_http_headers_out_t\s*,\s*server\s*\)\s*,\s*'
    r'ngx_http_modsecurity_resolv_header_server\s*\}\s*,\s*'
    r'\{\s*ngx_string\s*\(\s*"Date"\s*\)\s*,\s*'
    r'offsetof\s*\(\s*ngx_http_headers_out_t\s*,\s*date\s*\)\s*,\s*'
    r'ngx_http_modsecurity_resolv_header_date\s*\}\s*,\s*'
    r'\{\s*ngx_string\s*\(\s*"Content-Length"\s*\)\s*,\s*'
    r'offsetof\s*\(\s*ngx_http_headers_out_t\s*,\s*content_length_n\s*\)\s*,\s*'
    r'ngx_http_modsecurity_resolv_header_content_length\s*\}\s*,\s*'
    r'\{\s*ngx_string\s*\(\s*"Content-Type"\s*\)\s*,\s*'
    r'offsetof\s*\(\s*ngx_http_headers_out_t\s*,\s*content_type\s*\)\s*,\s*'
    r'ngx_http_modsecurity_resolv_header_content_type\s*\}\s*,\s*'
    r'\{\s*ngx_string\s*\(\s*"Last-Modified"\s*\)\s*,\s*'
    r'offsetof\s*\(\s*ngx_http_headers_out_t\s*,\s*last_modified\s*\)\s*,\s*'
    r'ngx_http_modsecurity_resolv_header_last_modified\s*\}\s*,\s*'
    r'\{\s*ngx_string\s*\(\s*"Connection"\s*\)\s*,\s*0\s*,\s*'
    r'ngx_http_modsecurity_resolv_header_connection\s*\}\s*,\s*'
    r'\{\s*ngx_string\s*\(\s*"Transfer-Encoding"\s*\)\s*,\s*0\s*,\s*'
    r'ngx_http_modsecurity_resolv_header_transfer_encoding\s*\}\s*,\s*'
    r'\{\s*ngx_string\s*\(\s*"Vary"\s*\)\s*,\s*0\s*,\s*'
    r'ngx_http_modsecurity_resolv_header_vary\s*\}\s*,\s*'
    r'\{\s*ngx_null_string\s*,\s*0\s*,\s*0\s*\}\s*,?\s*\}\s*;'
)
HEADER_DATE_RESOLVER_CONTRACT_PATTERN = re.compile(
    r'static\s+ngx_int_t\s+ngx_http_modsecurity_resolv_header_date\s*\(\s*'
    r'ngx_http_request_t\s*\*\s*r\s*,\s*ngx_str_t\s+name\s*,\s*'
    r'off_t\s+offset\s*\)\s*\{\s*'
    r'\(\s*void\s*\)\s*offset\s*;\s*'
    r'ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*=\s*NULL\s*;\s*'
    r'ngx_str_t\s+date\s*;\s*'
    r'ctx\s*=\s*ngx_http_modsecurity_get_module_ctx\s*\(\s*r\s*\)\s*;\s*'
    r'if\s*\(\s*r\s*->\s*headers_out\s*\.\s*date\s*==\s*NULL\s*\)\s*\{\s*'
    r'date\s*\.\s*data\s*=\s*ngx_cached_http_time\s*\.\s*data\s*;\s*'
    r'date\s*\.\s*len\s*=\s*ngx_cached_http_time\s*\.\s*len\s*;\s*\}\s*'
    r'else\s*\{\s*ngx_table_elt_t\s*\*\s*h\s*=\s*r\s*->\s*headers_out\s*\.\s*date\s*;\s*'
    r'date\s*\.\s*data\s*=\s*h\s*->\s*value\s*\.\s*data\s*;\s*'
    r'date\s*\.\s*len\s*=\s*h\s*->\s*value\s*\.\s*len\s*;\s*\}\s*'
    r'return\s+ngx_http_modsecurity_add_n_response_header\s*\(\s*ctx\s*,\s*'
    r'\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*name\s*\.\s*data\s*,\s*'
    r'name\s*\.\s*len\s*,\s*'
    r'\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*date\s*\.\s*data\s*,\s*'
    r'date\s*\.\s*len\s*\)\s*;\s*\}'
)
COMMON_NEXT_HEADER_CONTRACT_PATTERN = re.compile(
    r'static\s+ngx_inline\s+ngx_table_elt_t\s*\*\s*'
    r'ngx_http_modsecurity_next_header\s*\(\s*'
    r'ngx_list_part_t\s*\*\*\s*part\s*,\s*'
    r'ngx_table_elt_t\s*\*\*\s*data\s*,\s*'
    r'ngx_uint_t\s*\*\s*index\s*\)\s*\{\s*'
    r'for\s*\(\s*;\s*;\s*\)\s*\{\s*'
    r'if\s*\(\s*\*\s*index\s*<\s*\(\s*\*\s*part\s*\)\s*->\s*nelts\s*\)\s*\{\s*'
    r'return\s+&\s*\(\s*\*\s*data\s*\)\s*\[\s*\(\s*\*\s*index\s*\)\s*\+\+\s*\]\s*;\s*\}\s*'
    r'if\s*\(\s*\(\s*\*\s*part\s*\)\s*->\s*next\s*==\s*NULL\s*\)\s*\{\s*'
    r'return\s+NULL\s*;\s*\}\s*'
    r'\*\s*part\s*=\s*\(\s*\*\s*part\s*\)\s*->\s*next\s*;\s*'
    r'\*\s*data\s*=\s*\(\s*\*\s*part\s*\)\s*->\s*elts\s*;\s*'
    r'\*\s*index\s*=\s*0U\s*;\s*\}\s*\}'
)
HEADER_RESPONSE_HEADER_COLLECTION_SANITY_BLOCK_PATTERN = re.compile(
    r'#[ \t]*if\s+defined\s*\(\s*MODSECURITY_SANITY_CHECKS\s*\)\s*&&\s*'
    r'\(\s*MODSECURITY_SANITY_CHECKS\s*\)\s*'
    r'ngx_http_modsecurity_store_ctx_header\s*\(\s*r\s*,\s*'
    r'&header\s*->\s*key\s*,\s*&header\s*->\s*value\s*\)\s*;\s*'
    r'#[ \t]*endif\b'
)
HEADER_VALIDATED_RESPONSE_HEADER_WRAPPER_CALL_PATTERN = re.compile(
    r'\bngx_http_modsecurity_add_n_response_header\s*\(\s*ctx\s*,'
)
EXPECTED_HEADER_VALIDATED_RESPONSE_HEADER_WRAPPER_CALLS = 10
EXPECTED_RESPONSE_HEADER_COLLECTION_DIRECTIVES = (
    '#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)',
    '#endif',
)
BODY_LIMIT_PLAN_CHUNK_CALL_PATTERN = re.compile(
    r'if\s*\(\s*!msconnector_body_limit_plan_chunk\s*\(\s*'
    r'ctx\s*->\s*response_body_bytes_seen\s*,\s*'
    r'ctx\s*->\s*response_body_bytes_inspected\s*,\s*limit\s*,\s*'
    r'MSCONNECTOR_BODY_LIMIT_ACTION_REJECT\s*,\s*len\s*,\s*&plan\s*\)\s*\)\s*\{'
)
BODY_LIMIT_BYTES_SEEN_ASSIGNMENT_PATTERN = re.compile(
    r'ctx\s*->\s*response_body_bytes_seen\s*=\s*plan\s*\.\s*bytes_seen\s*;'
)
BODY_LIMIT_BYTES_SEEN_INCREMENT_PATTERN = re.compile(
    r'ctx\s*->\s*response_body_bytes_seen\s*\+=\s*len\s*;'
)
nginx_source_paths = (
    tuple(sorted(nginx.glob('*.c')))
    + tuple(sorted(nginx.glob('*.h')))
    + tuple(sorted(nginx.glob('*.hpp')))
)
common_include = source_path('common/include', root=ROOT)
common_header_paths = (
    tuple(sorted(common_include.rglob('*.h')))
    + tuple(sorted(common_include.rglob('*.hpp')))
) if common_include.is_dir() else ()
profile_registry_header = source_path('connectors/profile_registry.h', root=ROOT)
profile_registry_header_paths = (
    (profile_registry_header,) if profile_registry_header.is_file() else ()
)
critical_macro_source_paths = (
    nginx_source_paths + common_header_paths + profile_registry_header_paths
)
critical_macro_source_resolved_paths = frozenset(
    path.resolve() for path in critical_macro_source_paths
)
critical_macro_source_inputs = tuple(
    (path, path.read_text(errors='ignore')) for path in critical_macro_source_paths
)
all_nginx = '\n'.join(p.read_text(errors='ignore') for p in nginx.glob('*.c')) + common_h + mapper_h
log_event_start = log_c.index('void\nngx_http_modsecurity_log_rule_match_event')
log_event_end = log_c.index('\n\nvoid\nngx_http_modsecurity_log(', log_event_start)
log_event = log_c[log_event_start:log_event_end]
server_header_resolver_marker = 'static ngx_int_t\nngx_http_modsecurity_resolv_header_server'
C_TRIGRAPHS = {
    '??=': '#',
    '??/': '\\',
    "??'": '^',
    '??(': '[',
    '??)': ']',
    '??!': '|',
    '??<': '{',
    '??>': '}',
    '??-': '~',
}
C_CONDITIONAL_OPEN_DIRECTIVES = frozenset(('if', 'ifdef', 'ifndef'))

def c_function_bounds(source, signature):
    start = source.find(signature)
    if start == -1:
        return None
    opening_brace = source.find('{', start)
    if opening_brace == -1:
        return None
    depth = 0
    for position in range(opening_brace, len(source)):
        if source[position] == '{':
            depth += 1
        elif source[position] == '}':
            depth -= 1
            if depth == 0:
                return start, position + 1
    return None

def c_function(source, signature):
    """Select bounds from active code and return the matching visible view."""
    active, visible = c_lexical_views(source)
    bounds = c_function_bounds(active, signature)
    if bounds is None:
        return ''
    start, end = bounds
    return visible[start:end]

def c_all_branch_function(source, signature):
    """Return normalized code across branches using masked structural bounds."""
    active, _ = c_noncode_views(source)
    bounds = c_function_bounds(c_mask_conditional_branches(active), signature)
    if bounds is None:
        return ''
    start, end = bounds
    return active[start:end]

def c_mask_non_newline(characters, start, end):
    for position in range(start, end):
        if characters[position] != '\n':
            characters[position] = ' '

def c_mask_all(source):
    return ''.join('\n' if character == '\n' else ' ' for character in source)

def c_translation_phase_view(source):
    """Apply the C translation phases that affect lexical source selection."""
    translated = []
    position = 0
    while position < len(source):
        replacement = C_TRIGRAPHS.get(source[position:position + 3])
        if replacement is not None:
            translated.append(replacement)
            position += 3
        else:
            translated.append(source[position])
            position += 1
    spliced = re.sub(r'\\\r?\n', '', ''.join(translated))
    return spliced.replace('%:', '#')

def c_outer_include_guard_lines(source):
    lines = source.splitlines(keepends=True)
    nonempty = [(index, line) for index, line in enumerate(lines) if line.strip()]
    if len(nonempty) < 3:
        return None
    first_index, first_line = nonempty[0]
    match = re.match(r'^[ \t\f\v]*#\s*ifndef\s+([A-Za-z_]\w*)\s*$',
        first_line.rstrip('\r\n'))
    if match is None:
        return None
    _, second_line = nonempty[1]
    if not re.match(r'^[ \t\f\v]*#\s*define\s+' + re.escape(match.group(1))
            + r'\s*$', second_line.rstrip('\r\n')):
        return None
    last_index, last_line = nonempty[-1]
    if not re.match(r'^[ \t\f\v]*#\s*endif\b', last_line):
        return None
    return first_index, last_index

def c_conditional_directive_name(line):
    directive = re.match(r'^[ \t\f\v]*#\s*([A-Za-z_]\w*)\b', line)
    return directive.group(1) if directive is not None else None

def c_update_conditional_stack(conditional_stack, name, is_outer_guard):
    """Update one conditional directive and report malformed nesting."""
    if name in C_CONDITIONAL_OPEN_DIRECTIVES:
        conditional_stack.append((not is_outer_guard, is_outer_guard))
        return True
    if name in ('elif', 'else'):
        if not conditional_stack:
            return False
        _, outer_guard = conditional_stack[-1]
        if outer_guard:
            conditional_stack[-1] = (True, True)
        return True
    if name == 'endif':
        if not conditional_stack:
            return False
        conditional_stack.pop()
    return True

def c_conditional_stack_masks_contents(conditional_stack):
    return any(masks_contents for masks_contents, _ in conditional_stack)

def c_mask_conditional_branches(source, allow_outer_include_guard=False):
    characters = list(source)
    outer_guard = c_outer_include_guard_lines(source) if allow_outer_include_guard else None
    conditional_stack = []
    offset = 0

    for line_index, line in enumerate(source.splitlines(keepends=True)):
        line_end = offset + len(line)
        name = c_conditional_directive_name(line)
        if name is not None:
            c_mask_non_newline(characters, offset, line_end)
            is_outer_guard = outer_guard is not None and line_index == outer_guard[0]
            if not c_update_conditional_stack(
                    conditional_stack, name, is_outer_guard):
                return c_mask_all(source)
        elif c_conditional_stack_masks_contents(conditional_stack):
            c_mask_non_newline(characters, offset, line_end)
        offset = line_end

    return c_mask_all(source) if conditional_stack else ''.join(characters)

def c_line_splice_end(source, position):
    if source[position] != '\\':
        return None
    if source.startswith('\r\n', position + 1):
        return position + 3
    if source.startswith('\n', position + 1):
        return position + 2
    return None

def c_block_comment_end(source, position):
    end = source.find('*/', position + 2)
    return len(source) if end == -1 else end + 2

def c_line_comment_end(source, position):
    position += 2
    while position < len(source) and source[position] != '\n':
        spliced_position = c_line_splice_end(source, position)
        position = spliced_position if spliced_position is not None else position + 1
    return position

def c_quoted_literal_end(source, position):
    quote = source[position]
    position += 1
    while position < len(source):
        if source[position] == '\\':
            spliced_position = c_line_splice_end(source, position)
            if spliced_position is not None:
                position = spliced_position
            elif position + 1 < len(source):
                position += 2
            else:
                position += 1
            continue
        if source[position] == quote:
            return position + 1
        position += 1
    return position

def c_noncode_views(source):
    """Return C translation-phase-normalized lexical views without non-code text."""
    source = c_translation_phase_view(source)
    active = list(source)
    visible = list(source)
    position = 0

    while position < len(source):
        start = position
        if source.startswith('/*', position):
            position = c_block_comment_end(source, position)
            c_mask_non_newline(active, start, position)
            c_mask_non_newline(visible, start, position)
        elif source.startswith('//', position):
            position = c_line_comment_end(source, position)
            c_mask_non_newline(active, start, position)
            c_mask_non_newline(visible, start, position)
        elif source[position] in "'\"":
            position = c_quoted_literal_end(source, position)
            c_mask_non_newline(active, start, position)
        else:
            position += 1

    return ''.join(active), ''.join(visible)

def c_lexical_views(source, allow_outer_include_guard=False):
    active, visible = c_noncode_views(source)
    return (
        c_mask_conditional_branches(active, allow_outer_include_guard),
        c_mask_conditional_branches(visible, allow_outer_include_guard),
    )

def c_checked_function(source, signature, allow_outer_include_guard=False):
    active, visible = c_lexical_views(source, allow_outer_include_guard)
    bounds = c_function_bounds(active, signature)
    if bounds is None:
        return '', ''
    start, end = bounds
    return active[start:end], visible[start:end]

def c_event_jsonl_pipeline(active, strict=False):
    """Require the live bounded projection/serializer/write pipeline, not tokens."""
    if not active:
        return False
    log = r'ngx_log_error\([^;{}]*\);\s*'
    failure = 'NGX_ERROR' if strict else '0'
    prefix = (
        r'\{\s*char\s+line\[4096\];\s*'
        r'char\s+uri\[MSCONNECTOR_EVENT_URI_SAFE_BUFFER_SIZE\];\s*'
        r'char\s+connection_id\[32\];\s*'
        r'msconnector_event\s+projected;\s*int\s+json_truncated\s*=\s*0;\s*'
        r'size_t\s+line_length;\s*ssize_t\s+written;\s*'
        r'if\s*\(\s*!ngx_http_modsecurity_bounded_event_uri\(\s*event\s*,\s*'
        r'&projected\s*,\s*uri\s*,\s*sizeof\(uri\)\s*\)\s*\|\|\s*'
        r'!ngx_http_modsecurity_apply_event_provenance\(\s*r\s*,\s*&projected\s*,\s*'
        r'connection_id\s*,\s*sizeof\(connection_id\)\s*\)\s*\|\|\s*'
        r'!msconnector_event_write_jsonl_line\(\s*&projected\s*,\s*line\s*,\s*'
        r'sizeof\(line\)\s*,\s*&json_truncated\s*\)\s*\)\s*\{\s*'
        + log + r'return\s+' + failure + r';\s*\}\s*'
        r'line_length\s*=\s*ngx_strlen\(line\);\s*'
        r'written\s*=\s*ngx_write_fd\(mcf->phase4_log_file->fd,\s*'
        r'\(u_char\s*\*\)line,\s*line_length\);\s*'
    )
    if strict:
        tail = (r'if\s*\(written\s*<\s*0\)\s*\{\s*' + log
                + r'return\s+NGX_ERROR;\s*\}\s*'
                r'if\s*\(\(size_t\)written\s*!=\s*line_length\)\s*\{\s*'
                + log + r'return\s+NGX_ERROR;\s*\}\s*return\s+NGX_OK;\s*\}')
    else:
        tail = (r'if\s*\(written\s*<\s*0\s*\|\|\s*\(size_t\)written\s*'
                r'!=\s*line_length\)\s*\{\s*' + log
                + r'return\s+0;\s*\}\s*return\s+1;\s*\}')
    return re.fullmatch(prefix + tail, active[active.index('{'):]) is not None

_, event_metadata_helper = c_checked_function(common_h,
    'static ngx_inline ngx_http_modsecurity_event_request_metadata_t\nngx_http_modsecurity_event_request_metadata', True)
event_jsonl_active, event_jsonl_helper = c_checked_function(common_h,
    'static ngx_inline int\nngx_http_modsecurity_write_event_jsonl', True)
phase_event_jsonl_active, phase_event_jsonl_helper = c_checked_function(common_h,
    'static ngx_inline ngx_int_t\nngx_http_modsecurity_write_phase_event_jsonl', True)
event_jsonl_serialization_end = event_jsonl_helper.find('line_length = ngx_strlen(line);')
event_jsonl_serialization = event_jsonl_helper[:event_jsonl_serialization_end] if event_jsonl_serialization_end >= 0 else ''
event_jsonl_write = event_jsonl_helper[event_jsonl_serialization_end:] if event_jsonl_serialization_end >= 0 else ''

def c_unmasked_function(source, signature):
    """Return one function after translation/non-code masking, before branch masking."""
    active, visible = c_noncode_views(source)
    bounds = c_function_bounds(active, signature)
    if bounds is None:
        return '', ''
    start, end = bounds
    return active[start:end], visible[start:end]

def c_brace_depth_at(source, position):
    depth = 0
    for character in source[:position]:
        if character == '{':
            depth += 1
        elif character == '}':
            depth -= 1
    return depth

def c_direct_matches(source, pattern):
    return c_matches_at_brace_depth(source, pattern, 1)

def c_matches_at_brace_depth(source, pattern, depth):
    return [match for match in pattern.finditer(source)
            if c_brace_depth_at(source, match.start()) == depth]

def c_only_whitespace_between(source, start, end):
    return source[start:end].strip() == ''

def c_only_header_ctx_diagnostic_or_whitespace(active, visible, start, end):
    active_gap = active[start:end]
    visible_gap = visible[start:end]
    calls = list(HEADER_CTX_DIAGNOSTIC_CALL_PATTERN.finditer(active_gap))
    visible_calls = list(
        HEADER_CTX_DIAGNOSTIC_VISIBLE_CALL_PATTERN.finditer(visible_gap)
    )
    return (
        len(calls) == 1
        and HEADER_CTX_DIAGNOSTIC_CALL_PATTERN.sub('', active_gap).strip() == ''
        and len(visible_calls) == 1
        and HEADER_CTX_DIAGNOSTIC_VISIBLE_CALL_PATTERN.sub(
            '', visible_gap
        ).strip() == ''
    )

def c_direct_visible_matches(active, visible, pattern):
    if len(active) != len(visible):
        return []
    return [match for match in pattern.finditer(visible)
            if c_brace_depth_at(active, match.start()) == 1]

C_UNIVERSAL_CHARACTER_NAME = re.compile(
    r'\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})'
)
C_PREPROCESSOR_DIRECTIVE = re.compile(r'^[ \t\f\v]*#', re.MULTILINE)
C_RETURN_STATEMENT = re.compile(r'\breturn\b(?P<expression>[^;]*);')
C_INCLUDE_DIRECTIVE = re.compile(
    r'^[ \t\f\v]*#\s*(include(?:_next)?|import)\b(.*)$'
)
C_QUOTED_INCLUDE_PAYLOAD = re.compile(r'"([^"\r\n]+)"\s*$')
C_ANGLE_INCLUDE_PAYLOAD = re.compile(r'<([^>\r\n]+)>\s*$')
C_LOCAL_INCLUDE_SUFFIXES = ('.h', '.hpp')
C_ALLOWED_EXTERNAL_QUOTED_INCLUDES = frozenset(('stdio.h',))
C_ALLOWED_EXTERNAL_ANGLE_INCLUDES = frozenset((
    'atomic',
    'ctype.h',
    'inttypes.h',
    'limits.h',
    'modsecurity/modsecurity.h',
    'modsecurity/rules.h',
    'modsecurity/rules_set.h',
    'modsecurity/transaction.h',
    'nginx.h',
    'ngx_config.h',
    'ngx_core.h',
    'ngx_http.h',
    'stdarg.h',
    'stdatomic.h',
    'stdbool.h',
    'stddef.h',
    'stdint.h',
    'stdio.h',
    'string.h',
    'time.h',
))
CONTROL_FLOW_KEYWORDS = re.compile(r'\b(?:if|for|while|switch)\b')
ELSE_OR_DO_KEYWORDS = re.compile(r'\b(?:else|do)\b')
NON_LINEAR_CONTROL_FLOW = re.compile(r'\b(?:goto|case|default)\b')

def c_skip_whitespace(source, position):
    while position < len(source) and source[position].isspace():
        position += 1
    return position

def c_matching_parenthesis(source, opening):
    depth = 0
    for position in range(opening, len(source)):
        if source[position] == '(':
            depth += 1
        elif source[position] == ')':
            depth -= 1
            if depth == 0:
                return position
    return None

def c_has_unstructured_control_flow(source):
    for match in CONTROL_FLOW_KEYWORDS.finditer(source):
        opening = c_skip_whitespace(source, match.end())
        if opening == len(source) or source[opening] != '(':
            return True
        closing = c_matching_parenthesis(source, opening)
        if closing is None:
            return True
        following = c_skip_whitespace(source, closing + 1)
        if following == len(source) or source[following] != '{':
            return True
    for match in ELSE_OR_DO_KEYWORDS.finditer(source):
        following = c_skip_whitespace(source, match.end())
        if following == len(source) or source[following] != '{':
            return True
    return NON_LINEAR_CONTROL_FLOW.search(source) is not None

def c_has_ucn_escape(source):
    return C_UNIVERSAL_CHARACTER_NAME.search(source) is not None

def c_local_include_candidates(source_path, include_name):
    return (
        source_path.parent / include_name,
        ROOT / include_name,
        common_include / include_name,
    )

def c_has_existing_local_include_candidate(source_path, include_name):
    for candidate in c_local_include_candidates(source_path, include_name):
        try:
            if candidate.exists():
                return True
        except OSError:
            return True
    return False

def c_resolves_to_scanned_source(source_path, include_name):
    for candidate in c_local_include_candidates(source_path, include_name):
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved in critical_macro_source_resolved_paths:
            return True
    return False

def c_is_safe_angle_include(source_path, include_name):
    if include_name not in C_ALLOWED_EXTERNAL_ANGLE_INCLUDES:
        return False
    return (
        not c_has_existing_local_include_candidate(source_path, include_name)
        or c_resolves_to_scanned_source(source_path, include_name)
    )

def c_is_safe_local_include_name(include_name):
    components = include_name.split('/')
    return not (
        include_name.startswith('/')
        or '\\' in include_name
        or not include_name.endswith(C_LOCAL_INCLUDE_SUFFIXES)
        or any(component in ('', '.', '..') for component in components)
    )

def c_is_safe_quoted_include(source_path, include_name):
    if (
        include_name in C_ALLOWED_EXTERNAL_QUOTED_INCLUDES
        and not c_has_existing_local_include_candidate(source_path, include_name)
    ):
        return True
    return (
        c_is_safe_local_include_name(include_name)
        and c_resolves_to_scanned_source(source_path, include_name)
    )

def c_is_safe_include_directive(source_path, directive):
    if directive.group(1) != 'include':
        return False
    payload = directive.group(2).strip()
    angle = C_ANGLE_INCLUDE_PAYLOAD.fullmatch(payload)
    if angle is not None:
        return c_is_safe_angle_include(source_path, angle.group(1))
    quoted = C_QUOTED_INCLUDE_PAYLOAD.fullmatch(payload)
    return (
        quoted is not None
        and c_is_safe_quoted_include(source_path, quoted.group(1))
    )

def c_has_unsafe_local_include_directive(source_path, source):
    """Reject quoted local includes outside the source-level macro proof."""
    _, visible = c_noncode_views(source)
    return any(
        directive is not None
        and not c_is_safe_include_directive(source_path, directive)
        for line in visible.splitlines()
        for directive in (C_INCLUDE_DIRECTIVE.match(line),)
    )

SECURITY_CRITICAL_MACRO_SYMBOLS = frozenset((
    'NULL',
    'NGX_ERROR',
    'NGX_HTTP_BAD_REQUEST',
    'NGX_HTTP_INTERNAL_SERVER_ERROR',
    'NGX_OK',
    'msc_add_n_response_header',
    'msconnector_rule_id_extract_from_message',
    'ngx_http_modsecurity_extract_intervention_rule_id',
    'ngx_http_modsecurity_process_intervention',
    'last_intervention_rule_id',
    'sizeof',
    'ctx',
    'mapper_status',
    'failure_status',
    'intervention',
    'log',
    'ngx_http_modsecurity_add_n_response_header',
    'ngx_http_modsecurity_initialize_request',
    'ngx_http_modsecurity_map_request',
    'ngx_http_modsecurity_map_response_from_ctx',
    'ngx_http_modsecurity_validate_common_request_mapper',
    'ngx_http_modsecurity_validate_header',
    'ngx_http_modsecurity_validate_response_mapper',
))
C_ASCII_IDENTIFIER_SUFFIX = r'(?a:\w*)'
RESPONSE_MAPPER_HELPER_SIGNATURE = (
    'void\nngx_http_modsecurity_validate_response_mapper'
)
HEADER_FILTER_SIGNATURE = (
    'ngx_int_t\nngx_http_modsecurity_header_filter(ngx_http_request_t *r)'
)
C_RESPONSE_MAPPER_FORBIDDEN_ALL_BRANCH_PATTERNS = (
    re.compile(r'\bcommon_response_validated\b'),
    re.compile(r'\bprocessed\b'),
    re.compile(r'\bintervention_triggered\b'),
    re.compile(r'\bphase4_' + C_ASCII_IDENTIFIER_SUFFIX + r'\b'),
    re.compile(r'\bresponse_body_' + C_ASCII_IDENTIFIER_SUFFIX + r'\b'),
    re.compile(r'\bresponse_committed\b'),
    re.compile(r'\bmsc_process_response_headers\b'),
    re.compile(r'\bmsc_process_response_body\b'),
    re.compile(r'\bmsc_add_n_response_header\b'),
    re.compile(r'\bngx_http_next_' + C_ASCII_IDENTIFIER_SUFFIX + r'\b'),
    re.compile(r'\bngx_http_filter_finalize_request\b'),
    re.compile(r'\bngx_palloc\b'),
    re.compile(r'\bngx_pnalloc\b'),
    re.compile(r'\bngx_pcalloc\b'),
)
C_RESPONSE_BODY_PRE_GATE_FORBIDDEN_PATTERNS = (
    re.compile(r'\bngx_http_modsecurity_append_response_body_buffer\b'),
    re.compile(r'\bngx_http_modsecurity_append_accounted_response_body\b'),
    re.compile(r'\bngx_http_modsecurity_append_file_response_body\b'),
    re.compile(r'\bngx_http_modsecurity_append_response_body_chunk\b'),
    re.compile(r'\bmsc_append_response_body\b'),
)
C_FORBIDDEN_MACRO_REPLACEMENT_PATTERN = re.compile(
    r'(?:' + '|'.join(
        pattern.pattern
        for pattern in (
            C_RESPONSE_MAPPER_FORBIDDEN_ALL_BRANCH_PATTERNS
            + C_RESPONSE_BODY_PRE_GATE_FORBIDDEN_PATTERNS
        )
    ) + r')'
)
C_FORBIDDEN_MACRO_REPLACEMENT_COMPONENT_PATTERN = re.compile(
    r'(?:->|\b(?:ctx|common_response_validated|processed|'
    r'intervention_triggered|phase4_' + C_ASCII_IDENTIFIER_SUFFIX + r'|'
    r'response_body_' + C_ASCII_IDENTIFIER_SUFFIX + r'|response_committed)\b)'
)
C_SECURITY_CRITICAL_MACRO_TOKEN = re.compile(
    r'\b(?:' + '|'.join(
        re.escape(symbol) for symbol in sorted(SECURITY_CRITICAL_MACRO_SYMBOLS)
    ) + r')\b'
)
C_DDEBUG_FALLBACK_IDENTIFIER = re.compile(r'\bdd\b')
C_DDEBUG_FORBIDDEN_OPERATOR = re.compile(
    r'\b(?:_Pragma|asm|__asm|__asm__)\b'
)
C_DDEBUG_ALLOWED_DIRECTIVE = re.compile(
    r'^[ \t\f\v]*#\s*(?:define|else|endif|if|ifndef|include)\b'
)
C_MACRO_DIRECTIVE = re.compile(
    r'^[ \t\f\v]*#\s*(define|undef)\s+([A-Za-z_]\w*)\b'
    r'(?P<parameters>\([^)]*\))?'
)
C_ALLOWED_LOCAL_MACRO_NAME = re.compile(
    r'(?:'
    r'MSCONN(?:ECTOR)?_[A-Z0-9_]*|'
    r'MODSECURITY_[A-Z0-9_]*|'
    r'NGX_HTTP_MODSECURITY_[A-Z0-9_]*|'
    r'_NGX_HTTP_MODSECURITY_COMMON_H_INCLUDED_|'
    r'MSC_USE_RULES_SET|'
    r'dd(?:_check_(?:read|write)_event_handler)?|'
    r'ngx_http_modsecurity_pcre_malloc_(?:init|done)|'
    r'strdup'
    r')\Z'
)
C_MACRO_CONTROL_FLOW_TOKEN = re.compile(
    r'\b(?:break|case|continue|default|do|else|for|goto|if|return|switch|while)\b'
)
C_DIAGNOSTIC_STATEMENT_MACRO_NAME = re.compile(
    r'dd(?:_check_(?:read|write)_event_handler)?\Z'
)
C_SAFE_DIAGNOSTIC_STATEMENT_MACRO_PARAMETERS = {
    'dd': '(...)',
    'dd_check_read_event_handler': '(r)',
    'dd_check_write_event_handler': '(r)',
}
C_SAFE_DIAGNOSTIC_STATEMENT_MACRO = re.compile(
    r'\s*do\s*\{(?P<body>.*)\}\s*while\s*\(\s*0\s*\)\s*\Z'
)
C_DDEBUG_PREFIX_FORMAT_LITERAL = '"modsec *** %s: "'
C_DDEBUG_SUFFIX_FORMAT_LITERAL = r'" at %s line %d.\n"'
C_DDEBUG_CHECK_READ_FORMAT_LITERAL = '"r->read_event_handler = %s"'
C_DDEBUG_CHECK_WRITE_FORMAT_LITERAL = '"r->write_event_handler = %s"'
C_SAFE_DDEBUG_FPRINTF_BODY = re.compile(
    r'\s*fprintf\s*\(\s*stderr\s*,\s*,\s*__func__\s*\)\s*;\s*'
    r'fprintf\s*\(\s*stderr\s*,\s*__VA_ARGS__\s*\)\s*;\s*'
    r'fprintf\s*\(\s*stderr\s*,\s*,\s*__FILE__\s*,\s*'
    r'__LINE__\s*\)\s*;\s*\Z'
)
C_SAFE_DDEBUG_FPRINTF_VISIBLE_BODY = re.compile(
    r'\s*fprintf\s*\(\s*stderr\s*,\s*'
    + re.escape(C_DDEBUG_PREFIX_FORMAT_LITERAL)
    + r'\s*,\s*__func__\s*\)\s*;\s*'
    r'fprintf\s*\(\s*stderr\s*,\s*__VA_ARGS__\s*\)\s*;\s*'
    r'fprintf\s*\(\s*stderr\s*,\s*'
    + re.escape(C_DDEBUG_SUFFIX_FORMAT_LITERAL)
    + r'\s*,\s*__FILE__\s*,\s*__LINE__\s*\)\s*;\s*\Z'
)
C_SAFE_DDEBUG_CHECK_READ_VISIBLE_FORMAT = re.compile(
    r'\s*dd\s*\(\s*'
    + re.escape(C_DDEBUG_CHECK_READ_FORMAT_LITERAL)
    + r'\s*,'
)
C_SAFE_DDEBUG_CHECK_WRITE_VISIBLE_FORMAT = re.compile(
    r'\s*dd\s*\(\s*'
    + re.escape(C_DDEBUG_CHECK_WRITE_FORMAT_LITERAL)
    + r'\s*,'
)
C_SAFE_DDEBUG_CHECK_READ_BODY = re.compile(
    r'\s*dd\s*\(\s*,\s*'
    r'\(\s*r\s*\)\s*->\s*read_event_handler\s*==\s*'
    r'ngx_http_block_reading\s*\?\s*:\s*'
    r'\(\s*r\s*\)\s*->\s*read_event_handler\s*==\s*'
    r'ngx_http_test_reading\s*\?\s*:\s*'
    r'\(\s*r\s*\)\s*->\s*read_event_handler\s*==\s*'
    r'ngx_http_request_empty_handler\s*\?\s*:\s*\)\s*;\s*\Z'
)
C_SAFE_DDEBUG_CHECK_WRITE_BODY = re.compile(
    r'\s*dd\s*\(\s*,\s*'
    r'\(\s*r\s*\)\s*->\s*write_event_handler\s*==\s*'
    r'ngx_http_handler\s*\?\s*:\s*'
    r'\(\s*r\s*\)\s*->\s*write_event_handler\s*==\s*'
    r'ngx_http_core_run_phases\s*\?\s*:\s*'
    r'\(\s*r\s*\)\s*->\s*write_event_handler\s*==\s*'
    r'ngx_http_request_empty_handler\s*\?\s*:\s*\)\s*;\s*\Z'
)
C_SAFE_DDEBUG_VOID_CHECK_BODY = re.compile(
    r'\s*\(\s*void\s*\)\s*\(\s*r\s*\)\s*;\s*\Z'
)
C_SAFE_FUNCTION_LIKE_MACRO_REPLACEMENTS = frozenset((
    ('ngx_http_modsecurity_pcre_malloc_init', '(x)', 'NULL'),
    ('ngx_http_modsecurity_pcre_malloc_done', '(x)', '(void)x'),
))
C_SAFE_FUNCTION_LIKE_MACRO_NAMES = frozenset(
    name for name, _, _ in C_SAFE_FUNCTION_LIKE_MACRO_REPLACEMENTS
)
C_STATIC_DDEBUG_FALLBACK_PATTERN = re.compile(
    r'static\s+void\s+dd\s*\(\s*const\s+char\s*\*\s*fmt\s*,\s*'
    r'\.\.\.\s*\)\s*\{\s*\(\s*void\s*\)\s*fmt\s*;\s*\}'
)
C_DDEBUG_FALLBACK_MAX_SOURCE_CHARACTERS = 4096
RESPONSE_MAPPER_HELPER_IMMUTABLE_CONTRACT_PATTERN = re.compile(
    r'void\s+ngx_http_modsecurity_validate_response_mapper\s*\(\s*'
    r'const\s+ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*,\s*'
    r'ngx_http_request_t\s*\*\s*r\s*,\s*'
    r'ngx_http_modsecurity_response_mapper_diagnostic_t\s+diagnostic\s*\)\s*'
    r'\{\s*msconnector_response_mapper_contract\s+contract\s*;\s*'
    r'msconnector_response\s+mapped_response\s*;\s*'
    r'char\s+mapper_error\s*\[\s*128\s*\]\s*;\s*'
    r'msconnector_response_mapper_contract_init\s*\(\s*&contract\s*\)\s*;\s*'
    r'if\s*\(\s*ngx_http_modsecurity_map_response_from_ctx\s*\(\s*'
    r'ctx\s*,\s*r\s*,\s*&contract\s*,\s*&mapped_response\s*,\s*'
    r'mapper_error\s*,\s*sizeof\s*\(\s*mapper_error\s*\)\s*\)\s*\)\s*'
    r'\{\s*return\s*;\s*\}\s*'
    r'if\s*\(\s*diagnostic\s*==\s*'
    r'NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_BODY\s*\)\s*\{\s*'
    r'ngx_log_error\s*\(\s*NGX_LOG_WARN\s*,\s*r\s*->\s*connection\s*'
    r'->\s*log\s*,\s*0\s*,\s*,\s*mapper_error\s*\)\s*;\s*'
    r'return\s*;\s*\}\s*'
    r'ngx_log_error\s*\(\s*NGX_LOG_WARN\s*,\s*r\s*->\s*connection\s*'
    r'->\s*log\s*,\s*0\s*,\s*,\s*mapper_error\s*\)\s*;\s*\}\s*\Z'
)
C_CTX_IDENTIFIER = re.compile(r'\bctx\b')
C_CTX_VOID_CAST_PATTERN = re.compile(r'\(\s*void\s*\)\s*ctx\s*;')

def c_function_body(source):
    opening = source.find('{')
    closing = source.rfind('}')
    if opening == -1 or closing <= opening:
        return ''
    return source[opening + 1:closing]

def c_ddebug_static_fallbacks_are_inert(source):
    """Allow only the two exact inert non-directive dd fallback definitions."""
    if len(source) > C_DDEBUG_FALLBACK_MAX_SOURCE_CHARACTERS:
        return False
    inert_matches = list(C_STATIC_DDEBUG_FALLBACK_PATTERN.finditer(source))
    if len(inert_matches) != 2:
        return False

    remaining = list(source)
    for match in inert_matches:
        c_mask_non_newline(remaining, match.start(), match.end())
    return all(
        C_DDEBUG_FORBIDDEN_OPERATOR.search(line) is None
        and (
            not line.lstrip(' \t\f\v').startswith('#')
            or C_DDEBUG_ALLOWED_DIRECTIVE.match(line) is not None
        )
        and (
            C_DDEBUG_FALLBACK_IDENTIFIER.search(line) is None
            or C_MACRO_DIRECTIVE.match(line) is not None
        )
        for line in ''.join(remaining).splitlines()
    )

def c_is_safe_diagnostic_body(name, body, visible_body):
    if name == 'dd':
        return (
            C_SAFE_DDEBUG_FPRINTF_BODY.fullmatch(body) is not None
            and C_SAFE_DDEBUG_FPRINTF_VISIBLE_BODY.fullmatch(visible_body)
            is not None
        )
    if name == 'dd_check_read_event_handler':
        return (
            (
                C_SAFE_DDEBUG_CHECK_READ_BODY.fullmatch(body) is not None
                and C_SAFE_DDEBUG_CHECK_READ_VISIBLE_FORMAT.match(visible_body)
                is not None
            )
            or C_SAFE_DDEBUG_VOID_CHECK_BODY.fullmatch(body) is not None
        )
    return (
        (
            C_SAFE_DDEBUG_CHECK_WRITE_BODY.fullmatch(body) is not None
            and C_SAFE_DDEBUG_CHECK_WRITE_VISIBLE_FORMAT.match(visible_body)
            is not None
        )
        or C_SAFE_DDEBUG_VOID_CHECK_BODY.fullmatch(body) is not None
    )

def c_is_safe_diagnostic_statement_macro(
        directive, replacement, visible_replacement=None):
    """Permit only the existing bounded do/while(0) diagnostic macro form."""
    name = directive.group(2)
    if (
        C_DIAGNOSTIC_STATEMENT_MACRO_NAME.fullmatch(name) is None
        or directive.group('parameters')
        != C_SAFE_DIAGNOSTIC_STATEMENT_MACRO_PARAMETERS[name]
    ):
        return False
    if name == 'dd' and not replacement.strip():
        return True
    if visible_replacement is None:
        visible_replacement = replacement
    match = C_SAFE_DIAGNOSTIC_STATEMENT_MACRO.fullmatch(replacement)
    visible_match = C_SAFE_DIAGNOSTIC_STATEMENT_MACRO.fullmatch(
        visible_replacement
    )
    return (
        match is not None
        and visible_match is not None
        and C_MACRO_CONTROL_FLOW_TOKEN.search(match.group('body')) is None
        and c_is_safe_diagnostic_body(
            name, match.group('body'), visible_match.group('body')
        )
    )

def c_is_safe_function_like_macro(
        directive, replacement, visible_replacement=None):
    """Accept only existing bounded function-like macro semantics."""
    return (
        c_is_safe_diagnostic_statement_macro(
            directive, replacement, visible_replacement
        )
        or (
            directive.group(2), directive.group('parameters'), replacement.strip()
        ) in C_SAFE_FUNCTION_LIKE_MACRO_REPLACEMENTS
    )

def c_has_forbidden_pattern(source, patterns):
    return any(pattern.search(source) is not None for pattern in patterns)

def c_is_safe_macro_replacement(directive, replacement):
    if (
        '##' in replacement
        or C_SECURITY_CRITICAL_MACRO_TOKEN.search(replacement)
        or C_DDEBUG_FALLBACK_IDENTIFIER.search(replacement)
        or C_FORBIDDEN_MACRO_REPLACEMENT_PATTERN.search(replacement)
        or (
            C_FORBIDDEN_MACRO_REPLACEMENT_COMPONENT_PATTERN.search(replacement)
            and not c_is_safe_function_like_macro(directive, replacement)
        )
    ):
        return False
    if (
        directive.group('parameters') is not None
        and not c_is_safe_function_like_macro(directive, replacement)
    ):
        return False
    return (
        C_MACRO_CONTROL_FLOW_TOKEN.search(replacement) is None
        or c_is_safe_function_like_macro(directive, replacement)
    )

def c_is_safe_macro_directive(line, visible_line, directive):
    name = directive.group(2)
    if directive.group(1) != 'define':
        return False
    if (
        C_ALLOWED_LOCAL_MACRO_NAME.fullmatch(name) is None
        or name in SECURITY_CRITICAL_MACRO_SYMBOLS
        or C_UNIVERSAL_CHARACTER_NAME.search(line) is not None
    ):
        return False
    replacement = line[directive.end():]
    visible_replacement = visible_line[directive.end():]
    if C_DIAGNOSTIC_STATEMENT_MACRO_NAME.fullmatch(name) is not None:
        return c_is_safe_diagnostic_statement_macro(
            directive, replacement, visible_replacement
        )
    if name in C_SAFE_FUNCTION_LIKE_MACRO_NAMES:
        return c_is_safe_function_like_macro(
            directive, replacement, visible_replacement
        )
    return c_is_safe_macro_replacement(directive, replacement)

def c_has_security_critical_macro_mutation(source):
    """Reject macro forms that can change or indirectly supply a checked token."""
    active, visible = c_noncode_views(source)
    if C_UNIVERSAL_CHARACTER_NAME.search(active) is not None:
        return True
    for line, visible_line in zip(active.splitlines(), visible.splitlines()):
        directive = C_MACRO_DIRECTIVE.match(line)
        if directive is not None and not c_is_safe_macro_directive(
                line, visible_line, directive):
            return True
    return False

critical_macro_controls_are_safe = not any(
    path.is_symlink()
    or c_has_security_critical_macro_mutation(source)
    or c_has_unsafe_local_include_directive(path, source)
    for path, source in critical_macro_source_inputs
)

RULE_ID_HELPER = 'ngx_http_modsecurity_extract_intervention_rule_id'
RULE_ID_HELPER_PATTERN = re.compile(
    r'static\s+void\s+' + RULE_ID_HELPER + r'\s*\(\s*'
    r'ngx_http_modsecurity_ctx_t\s*\*\s*ctx\s*,\s*'
    r'const\s+ModSecurityIntervention\s*\*\s*intervention\s*\)\s*\{\s*'
    r'if\s*\(\s*intervention\s*->\s*log\s*!=\s*NULL\s*\)\s*\{\s*'
    r'\(\s*void\s*\)\s*msconnector_rule_id_extract_from_message\s*\(\s*'
    r'intervention\s*->\s*log\s*,\s*ctx\s*->\s*last_intervention_rule_id\s*,\s*'
    r'sizeof\s*\(\s*ctx\s*->\s*last_intervention_rule_id\s*\)\s*\)\s*;\s*'
    r'\}\s*\}'
)
RULE_ID_CALL_PATTERN = re.compile(
    r'\b' + RULE_ID_HELPER + r'\s*\(\s*ctx\s*,\s*&\s*intervention\s*\)\s*;'
)
RULE_ID_RESET_AND_CALL_PATTERN = re.compile(
    r'ctx\s*->\s*last_intervention_status\s*=\s*intervention\s*\.\s*status\s*;\s*'
    r'ctx\s*->\s*last_intervention_rule_id\s*\[\s*0\s*\]\s*=\s*'
    r"'\\0'\s*;\s*" + RULE_ID_CALL_PATTERN.pattern
)

def c_rule_id_delegation_is_bounded():
    """Accept only the reviewed Common delegation and its live ordered caller."""
    helper, _ = c_checked_function(module_c, 'static void\n' + RULE_ID_HELPER)
    unmasked_helper, _ = c_unmasked_function(module_c, 'static void\n' + RULE_ID_HELPER)
    caller, visible_caller = c_checked_function(
        module_c, 'int\nngx_http_modsecurity_process_intervention')
    connector_code = '\n'.join(
        c_noncode_views(path.read_text(errors='ignore'))[0]
        for path in nginx_source_paths
    )
    rule_helpers = re.findall(
        r'\bngx_http_modsecurity_[a-z0-9_]*rule_id\s*\(', connector_code)
    calls = c_direct_matches(caller, RULE_ID_CALL_PATTERN)
    reset_calls = c_direct_matches(visible_caller, RULE_ID_RESET_AND_CALL_PATTERN)
    if (RULE_ID_HELPER_PATTERN.fullmatch(helper) is None
            or RULE_ID_HELPER_PATTERN.fullmatch(unmasked_helper) is None
            or len(rule_helpers) != 2
            or any(re.sub(r'\s+', '', match) != RULE_ID_HELPER + '(' for match in rule_helpers)
            or len(re.findall(r'\bmsconnector_rule_id_extract_from_message\s*\(',
                              c_noncode_views(module_c)[0])) != 1
            or len(calls) != 1 or len(reset_calls) != 1):
        return False
    if c_direct_matches(caller[:calls[0].start()], re.compile(r'\b(?:return|goto)\b')):
        return False
    # Each use must be live and after extraction, including classification of
    # native limits, terminal recording, host dispatch, and message cleanup.
    for name in (
        'ngx_http_modsecurity_is_response_body_limit_rejection',
        'ngx_http_modsecurity_contract_record_intervention',
        'ngx_http_modsecurity_process_redirect_intervention',
        'ngx_http_modsecurity_process_status_intervention',
    ):
        sinks = list(re.finditer(r'\b' + name + r'\s*\(', caller))
        if len(sinks) != 1 or calls[0].end() >= sinks[0].start():
            return False
    # EOS may replace the just-collected result with an owned native request
    # result retained during append. Only this exact ownership transfer may
    # clean up before extracting the final intervention's bounded rule ID.
    pending_restore = re.compile(
        r'if\s*\(\s*ctx->native_event_phase\s*==\s*MSCONNECTOR_PHASE_REQUEST_BODY\s*&&\s*'
        r'ctx->request_intervention_pending\s*\)\s*\{\s*'
        r'msc_intervention_cleanup\s*\(\s*&intervention\s*\)\s*;\s*'
        r'intervention\s*=\s*ctx->pending_request_intervention\s*;\s*'
        r'ngx_memzero\s*\(\s*&ctx->pending_request_intervention\s*,\s*'
        r'sizeof\s*\(\s*ctx->pending_request_intervention\s*\)\s*\)\s*;\s*'
        r'ctx->request_intervention_pending\s*=\s*0\s*;\s*'
        r'native_result\s*=\s*1\s*;\s*\}'
    )
    restores = list(pending_restore.finditer(caller))
    cleanups = list(re.finditer(r'\bmsc_intervention_cleanup\s*\(', caller))
    direct_cleanups = c_direct_matches(caller, re.compile(r'\bmsc_intervention_cleanup\s*\('))
    if (len(restores) != 1 or len(cleanups) != 2 or len(direct_cleanups) != 1
            or not restores[0].start() < cleanups[0].start() < restores[0].end() < calls[0].start()
            or calls[0].end() >= direct_cleanups[0].start()):
        return False
    return True

server_header_resolver, _ = c_checked_function(header_c, server_header_resolver_marker)
custom_server_header_marker = 'ngx_table_elt_t *h = r->headers_out.server;'
custom_server_header_start = server_header_resolver.find(custom_server_header_marker)
custom_server_header_match = re.search(
    r'value\.len\s*=\s*h->value\.len;', server_header_resolver[
        custom_server_header_start:]) if custom_server_header_start != -1 else None
custom_server_header_branch = server_header_resolver[custom_server_header_start:
    custom_server_header_start + custom_server_header_match.end()] if (
        custom_server_header_match is not None) else ''
header_all_code, _ = c_noncode_views(header_c)
nginx_source_contract_code = '\n'.join(
    c_noncode_views(source)[0] for _, source in critical_macro_source_inputs
)

access_event = c_function(access_c,
    'static void\nngx_http_modsecurity_request_intervention_log_event')
request_mapper_validator_unmasked, _ = c_unmasked_function(access_c,
    'static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper')
request_mapper_validator, request_mapper_validator_visible = c_checked_function(access_c,
    'static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper')
request_initializer_unmasked, _ = c_unmasked_function(access_c,
    'static ngx_int_t\nngx_http_modsecurity_initialize_request')
request_initializer, _ = c_checked_function(access_c,
    'static ngx_int_t\nngx_http_modsecurity_initialize_request')
response_mapper_helper, response_mapper_helper_visible = c_checked_function(
    mapper_c, RESPONSE_MAPPER_HELPER_SIGNATURE)
response_mapper_helper_all_branches = c_all_branch_function(
    mapper_c, RESPONSE_MAPPER_HELPER_SIGNATURE)
response_mapper_from_ctx, _ = c_checked_function(mapper_c,
    'int ngx_http_modsecurity_map_response_from_ctx')
response_mapper_from_ctx_all_branches = c_all_branch_function(mapper_c,
    'int ngx_http_modsecurity_map_response_from_ctx')
response_mapper_from_ctx_all_branches_body = c_function_body(
    response_mapper_from_ctx_all_branches)
body_response_mapper_once, _ = c_checked_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_validate_response_mapper_once')
body_response_mapper_once_unmasked, _ = c_unmasked_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_validate_response_mapper_once')
body_filter_prepare, _ = c_checked_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_prepare_response_body_filter')
body_limited_response_plan, _ = c_checked_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_account_response_body')
body_response_append_chunk, _ = c_checked_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_append_response_body_chunk')
body_response_append_buffer, _ = c_checked_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_append_response_body_buffer')
body_response_append_limited, _ = c_checked_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_append_accounted_response_body')
body_response_chain_append, _ = c_checked_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_append_response_chain_buffer')
body_response_chain_append_all_branches = c_all_branch_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_append_response_chain_buffer')
body_response_chain, _ = c_checked_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_process_response_body_chain')
body_response_chain_all_branches = c_all_branch_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_process_response_body_chain')
body_filter, _ = c_checked_function(body_c,
    'ngx_int_t\nngx_http_modsecurity_body_filter(ngx_http_request_t *r, ngx_chain_t *in)')
header_filter, header_filter_visible = c_checked_function(
    header_c, HEADER_FILTER_SIGNATURE
)
header_filter_unmasked, _ = c_unmasked_function(
    header_c, HEADER_FILTER_SIGNATURE)
header_filter_all_branches = c_all_branch_function(
    header_c, HEADER_FILTER_SIGNATURE)
response_header_collection, _ = c_checked_function(header_c,
    'static ngx_int_t\nngx_http_modsecurity_add_response_headers')
response_header_collection_unmasked, _ = c_unmasked_function(header_c,
    'static ngx_int_t\nngx_http_modsecurity_add_response_headers')
header_date_resolver, _ = c_checked_function(header_c,
    'static ngx_int_t\nngx_http_modsecurity_resolv_header_date')
_, header_lexical_visible = c_lexical_views(header_c)
common_next_header, _ = c_checked_function(common_h,
    'static ngx_inline ngx_table_elt_t *\nngx_http_modsecurity_next_header',
    allow_outer_include_guard=True)
phase3_log_event = c_function(header_c,
    'static ngx_int_t\nngx_http_modsecurity_phase3_log_event')
phase4_log_event = c_function(body_c,
    'static ngx_int_t\nngx_http_modsecurity_phase4_log_event')
response_header_sink_unmasked, _ = c_unmasked_function(
    common_h,
    'static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header',
)
response_header_sink, _ = c_checked_function(
    common_h,
    'static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header',
    allow_outer_include_guard=True,
)
request_mapper_call_pattern = re.compile(
    r'ngx_http_modsecurity_map_request\s*\(\s*r\s*,\s*&contract\s*,\s*'
    r'&mapped_request\s*,\s*&mapper_status\s*,\s*mapper_error\s*,\s*'
    r'sizeof\s*\(\s*mapper_error\s*\)\s*\)'
)
request_mapper_any_call_pattern = re.compile(
    r'\bngx_http_modsecurity_map_request\s*\('
)
request_mapper_contract_init_pattern = re.compile(
    r'msconnector_request_mapper_contract_init\s*\(\s*&contract\s*\)\s*;'
)
request_mapper_failure_rejection_pattern = re.compile(
    r'if\s*\(\s*!ngx_http_modsecurity_map_request\s*\(\s*'
    r'r\s*,\s*&contract\s*,\s*&mapped_request\s*,\s*&mapper_status\s*,\s*mapper_error\s*,\s*'
    r'sizeof\s*\(\s*mapper_error\s*\)\s*\)\s*\)\s*\{\s*'
    r'ngx_log_error\s*\(\s*NGX_LOG_ERR\s*,\s*r->connection->log\s*,\s*0\s*,\s*'
    r'"modsecurity common request mapper validation failed: %s"\s*,\s*'
    r'mapper_error\s*\)\s*;\s*return\s+mapper_status\s*;\s*\}'
)
request_mapper_failure_propagation_pattern = re.compile(
    r'rc\s*=\s*ngx_http_modsecurity_validate_common_request_mapper\(r\);\s*'
    r'if\s*\(rc\s*!=\s*NGX_OK\)\s*\{\s*'
    r'ctx->intervention_triggered\s*=\s*1;\s*'
    r'return\s+rc;\s*\}',
)
response_header_validation_rejection_pattern = re.compile(
    r'if\s*\(\s*ngx_http_modsecurity_validate_header\s*\(\s*'
    r'ctx\s*,\s*name\s*,\s*name_len\s*,\s*value\s*,\s*'
    r'value_len\s*,\s*1\s*\)\s*!=\s*NGX_OK\s*\)\s*\{\s*'
    r'return\s+NGX_ERROR;\s*\}',
)
response_header_raw_sink_pattern = re.compile(
    r'msc_add_n_response_header\s*\(\s*ctx->modsec_transaction\s*,\s*'
    r'name\s*,\s*name_len\s*,\s*value\s*,\s*value_len\s*\)'
)
response_header_raw_sink_return_pattern = re.compile(
    r'return\s+msc_add_n_response_header\s*\(\s*ctx->modsec_transaction\s*,\s*'
    r'name\s*,\s*name_len\s*,\s*value\s*,\s*value_len\s*\)\s*'
    r'==\s*1\s*\?\s*1\s*:\s*NGX_ERROR\s*;'
)
response_header_raw_sink_name_pattern = re.compile(
    r'\bmsc_add_n_response_header\b'
)
request_mapper_calls = list(request_mapper_call_pattern.finditer(request_mapper_validator))
request_mapper_any_calls = list(
    request_mapper_any_call_pattern.finditer(request_mapper_validator))
request_mapper_direct_calls = c_direct_matches(
    request_mapper_validator, request_mapper_call_pattern)
request_mapper_contract_inits = c_direct_matches(
    request_mapper_validator, request_mapper_contract_init_pattern)
request_mapper_failure_rejections = c_direct_visible_matches(
    request_mapper_validator, request_mapper_validator_visible,
    request_mapper_failure_rejection_pattern)
request_mapper_failure_propagations = c_direct_matches(
    request_initializer, request_mapper_failure_propagation_pattern)
request_mapper_failure_propagations_unmasked = c_direct_matches(
    request_initializer_unmasked, request_mapper_failure_propagation_pattern)
request_mapper_initializer_calls = list(re.finditer(
    r'ngx_http_modsecurity_validate_common_request_mapper\s*\(\s*r\s*\)',
    request_initializer))
request_mapper_initializer_direct_calls = c_direct_matches(
    request_initializer,
    re.compile(r'ngx_http_modsecurity_validate_common_request_mapper\s*\(\s*r\s*\)'))
response_header_validation_rejections = c_direct_matches(
    response_header_sink, response_header_validation_rejection_pattern)
response_header_raw_sinks = c_direct_matches(
    response_header_sink, response_header_raw_sink_pattern)
response_header_raw_sink_occurrences = list(
    response_header_raw_sink_pattern.finditer(response_header_sink))
response_header_raw_sink_name_occurrences = list(
    response_header_raw_sink_name_pattern.finditer(response_header_sink))
response_header_raw_sink_returns = c_direct_matches(
    response_header_sink, response_header_raw_sink_return_pattern)
body_response_chain_append_calls = list(
    BODY_RESPONSE_CHAIN_CALL_PATTERN.finditer(body_response_chain_all_branches))
body_response_chain_call_contracts = list(
    BODY_RESPONSE_CHAIN_CALL_CONTRACT_PATTERN.finditer(
        body_response_chain_all_branches))
body_response_chunk_raw_sinks = list(
    BODY_RESPONSE_RAW_SINK_PATTERN.finditer(body_response_append_chunk))
body_response_raw_sink_occurrences = list(
    BODY_RESPONSE_RAW_SINK_NAME_PATTERN.finditer(nginx_source_contract_code))
header_response_header_collection_contracts = c_direct_matches(
    header_filter_all_branches,
    HEADER_RESPONSE_HEADER_COLLECTION_CONTRACT_PATTERN,
)
header_response_header_collection_wrapper_contracts = list(
    c_matches_at_brace_depth(
        response_header_collection,
        HEADER_RESPONSE_HEADER_COLLECTION_WRAPPER_CONTRACT_PATTERN,
        2,
    ))
header_response_header_collection_synthetic_contracts = c_direct_matches(
    response_header_collection,
    HEADER_RESPONSE_HEADER_COLLECTION_SYNTHETIC_CONTRACT_PATTERN,
)
header_response_header_collection_prefix_contracts = list(
    HEADER_RESPONSE_HEADER_COLLECTION_PREFIX_CONTRACT_PATTERN.finditer(
        response_header_collection))
header_response_header_collection_chain_traversals = c_direct_matches(
    response_header_collection,
    HEADER_RESPONSE_HEADER_COLLECTION_CHAIN_TRAVERSAL_PATTERN,
)
header_response_header_collection_sanity_blocks = list(
    HEADER_RESPONSE_HEADER_COLLECTION_SANITY_BLOCK_PATTERN.finditer(
        response_header_collection_unmasked))
header_response_header_collection_directive_lines = tuple(
    line.strip()
    for line in response_header_collection_unmasked.splitlines()
    if C_PREPROCESSOR_DIRECTIVE.match(line) is not None
)
header_response_header_collection_return_expressions = tuple(
    match.group('expression').strip()
    for match in C_RETURN_STATEMENT.finditer(response_header_collection)
)
header_validated_response_header_wrapper_calls = list(
    HEADER_VALIDATED_RESPONSE_HEADER_WRAPPER_CALL_PATTERN.finditer(
        header_all_code))
response_header_raw_sink_source_occurrences = list(
    response_header_raw_sink_name_pattern.finditer(nginx_source_contract_code))
header_synthetic_resolver_table_contracts = list(
    HEADER_SYNTHETIC_RESOLVER_TABLE_PATTERN.finditer(header_lexical_visible))
request_mapper_return_statements = list(
    C_RETURN_STATEMENT.finditer(request_mapper_validator_unmasked))
request_initializer_return_statements = list(
    C_RETURN_STATEMENT.finditer(request_initializer_unmasked))
request_initializer_pre_mapper_return_statements = [
    statement for statement in request_initializer_return_statements
    if request_mapper_failure_propagations_unmasked
    and statement.start() < request_mapper_failure_propagations_unmasked[0].start()
]
response_header_return_occurrences = list(
    C_RETURN_STATEMENT.finditer(response_header_sink_unmasked))
body_response_mapper_calls = list(
    RESPONSE_MAPPER_BODY_CALL_PATTERN.finditer(body_response_mapper_once))
body_response_mapper_direct_calls = c_direct_matches(
    body_response_mapper_once, RESPONSE_MAPPER_BODY_CALL_PATTERN)
body_response_validated_assignments = list(
    RESPONSE_VALIDATED_ASSIGNMENT_PATTERN.finditer(body_response_mapper_once))
body_response_validated_direct_assignments = c_direct_matches(
    body_response_mapper_once, RESPONSE_VALIDATED_ASSIGNMENT_PATTERN)
header_response_mapper_calls = list(
    RESPONSE_MAPPER_HEADER_CALL_PATTERN.finditer(header_filter))
header_response_mapper_direct_calls = c_direct_matches(
    header_filter, RESPONSE_MAPPER_HEADER_CALL_PATTERN)
header_response_validated_assignments = list(
    RESPONSE_VALIDATED_ASSIGNMENT_PATTERN.finditer(header_filter))
header_response_validated_direct_assignments = c_direct_matches(
    header_filter, RESPONSE_VALIDATED_ASSIGNMENT_PATTERN)
header_pre_mapper_unmasked = (
    header_filter_unmasked[:header_response_mapper_direct_calls[0].start()]
    if header_response_mapper_direct_calls else ''
)
header_ctx_acquisitions = c_direct_matches(
    header_filter, HEADER_CTX_ACQUISITION_PATTERN)
header_ctx_declaration_prefix = (
    header_filter[header_filter.find('{') + 1:header_ctx_acquisitions[0].start()]
    if header_ctx_acquisitions else ''
)
header_ctx_null_guards = c_direct_matches(header_filter, HEADER_CTX_NULL_GUARD_PATTERN)
header_response_header_failure_guards = c_direct_matches(
    header_filter, HEADER_RESPONSE_HEADER_FAILURE_GUARD_PATTERN)
header_intervention_guards = c_direct_matches(
    header_filter, HEADER_INTERVENTION_GUARD_PATTERN)
header_processed_guards = c_direct_matches(
    header_filter, HEADER_PROCESSED_GUARD_PATTERN)
header_processed_assignments = c_direct_matches(
    header_filter, HEADER_PROCESSED_ASSIGNMENT_PATTERN)
header_mapper_to_validated = (
    header_filter[
        header_response_mapper_direct_calls[0].end():
        header_response_validated_direct_assignments[0].start()
    ]
    if (
        header_response_mapper_direct_calls
        and header_response_validated_direct_assignments
    )
    else ''
)
header_validated_to_processed_guard = (
    header_filter[
        header_response_validated_direct_assignments[0].end():
        header_processed_guards[0].start()
    ]
    if (
        header_response_validated_direct_assignments
        and header_processed_guards
    )
    else ''
)
header_mapper_to_processed_unmasked = (
    header_filter_unmasked[
        header_response_mapper_direct_calls[0].end():
        header_processed_guards[0].start()
    ]
    if header_response_mapper_direct_calls and header_processed_guards
    else ''
)
header_pre_mapper_control_flows = [
    match for match in c_direct_matches(header_filter, CONTROL_FLOW_KEYWORDS)
    if header_response_mapper_direct_calls
    and match.start() < header_response_mapper_direct_calls[0].start()
]
header_pre_mapper_returns = [
    match for match in C_RETURN_STATEMENT.finditer(header_filter)
    if header_response_mapper_direct_calls
    and match.start() < header_response_mapper_direct_calls[0].start()
]
body_limit_plan_chunk_calls = c_direct_matches(
    body_limited_response_plan, BODY_LIMIT_PLAN_CHUNK_CALL_PATTERN)
body_limit_bytes_seen_assignments = c_direct_matches(
    body_limited_response_plan, BODY_LIMIT_BYTES_SEEN_ASSIGNMENT_PATTERN)
ddebug_active, _ = c_noncode_views(ddebug_h)
ddebug_static_fallbacks_are_inert = c_ddebug_static_fallbacks_are_inert(
    ddebug_active
)
response_mapper_helper_is_immutable = (
    RESPONSE_MAPPER_HELPER_IMMUTABLE_CONTRACT_PATTERN.fullmatch(
        response_mapper_helper_all_branches) is not None
)
response_mapper_from_ctx_ignores_ctx = (
    C_PREPROCESSOR_DIRECTIVE.search(response_mapper_from_ctx_all_branches) is None
    and not c_has_ucn_escape(response_mapper_from_ctx_all_branches)
    and len(C_CTX_IDENTIFIER.findall(
        response_mapper_from_ctx_all_branches_body)) == 1
    and len(C_CTX_VOID_CAST_PATTERN.findall(
        response_mapper_from_ctx_all_branches_body)) == 1
)
request_hostname_call = request_initializer.find(
    'ngx_http_modsecurity_set_request_hostname')
request_headers_call = request_initializer.find(
    'ngx_http_modsecurity_process_request_headers')
request_mapper_status_function, _ = c_checked_function(
    mapper_c, 'int ngx_http_modsecurity_map_request')
request_mapper_status_all_branches = c_all_branch_function(
    mapper_c, 'int ngx_http_modsecurity_map_request')
# Count every target, including assignments whose RHS is not an enum token.
request_mapper_status_assignment_targets = re.findall(
    r'\*failure_status\s*=', request_mapper_status_function)
request_mapper_status_assignments = re.findall(
    r'\*failure_status\s*=\s*([A-Z_]{1,64});', request_mapper_status_function)
request_mapper_client_limit_pattern = re.compile(
    r'if\s*\(\s*contract->max_header_count\s*>\s*0U\s*&&\s*'
    r'ngx_http_modsecurity_count_list_headers\s*\(\s*&r->headers_in.headers\s*\)\s*>\s*'
    r'contract->max_header_count\s*\)\s*\{\s*'
    r'if\s*\(\s*failure_status\s*!=\s*NULL\s*\)\s*\{\s*'
    r'\*failure_status\s*=\s*NGX_HTTP_BAD_REQUEST\s*;\s*\}\s*'
    r'ngx_http_modsecurity_mapper_error\s*\(\s*error\s*,\s*error_len\s*,\s*\)\s*;\s*'
    r'return\s+0\s*;\s*\}')
request_mapper_client_limit = request_mapper_client_limit_pattern.search(request_mapper_status_function)
request_mapper_typed_status_is_fail_closed = (
    critical_macro_controls_are_safe
    and C_PREPROCESSOR_DIRECTIVE.search(request_mapper_status_all_branches) is None
    and not c_has_unstructured_control_flow(request_mapper_status_function)
    and not c_has_ucn_escape(request_mapper_status_all_branches)
    and len(request_mapper_status_assignment_targets) == len(request_mapper_status_assignments)
    and request_mapper_status_assignments == ['NGX_HTTP_INTERNAL_SERVER_ERROR', 'NGX_HTTP_BAD_REQUEST']
    and re.search(r'if\s*\(\s*failure_status\s*!=\s*NULL\s*\)\s*\{\s*'
                  r'\*failure_status\s*=\s*NGX_HTTP_INTERNAL_SERVER_ERROR\s*;\s*\}',
                  request_mapper_status_function) is not None
    and request_mapper_client_limit is not None
    and request_mapper_client_limit.end() < request_mapper_status_function.find('ngx_http_modsecurity_copy_headers')
    and 'if (!msconnector_request_mapper_validate_output(contract, out, error, error_len))' in request_mapper_status_function
)
request_mapper_contract_is_fail_closed = (
    critical_macro_controls_are_safe
    and
    len(request_mapper_calls) == 1
    and len(request_mapper_any_calls) == 1
    and len(request_mapper_direct_calls) == 1
    and len(request_mapper_contract_inits) == 1
    and len(request_mapper_failure_rejections) == 1
    and request_mapper_contract_inits[0].start()
    < request_mapper_failure_rejections[0].start()
    <= request_mapper_direct_calls[0].start()
    < request_mapper_failure_rejections[0].end()
    and C_PREPROCESSOR_DIRECTIVE.search(request_mapper_validator_unmasked) is None
    and len(request_mapper_return_statements) == 2
    and request_mapper_return_statements[0].group('expression').strip()
    == 'mapper_status'
    and re.search(r'ngx_int_t\s+mapper_status\s*=\s*NGX_HTTP_INTERNAL_SERVER_ERROR\s*;',
                  request_mapper_validator) is not None
    and len(re.findall(r'\bmapper_status\s*=', request_mapper_validator)) == 1
    and request_mapper_return_statements[1].group('expression').strip()
    == 'NGX_OK'
    and not c_has_unstructured_control_flow(request_mapper_validator)
    and not c_has_ucn_escape(request_mapper_validator)
    and 'validation skipped' not in request_mapper_validator_visible
    and len(request_mapper_failure_propagations) == 1
    and len(request_mapper_failure_propagations_unmasked) == 1
    and C_PREPROCESSOR_DIRECTIVE.search(request_initializer_unmasked) is None
    and len(request_initializer_pre_mapper_return_statements) == 1
    and request_initializer_pre_mapper_return_statements[0].group(
        'expression').strip() == 'NGX_HTTP_INTERNAL_SERVER_ERROR'
    and len(request_mapper_initializer_calls) == 1
    and len(request_mapper_initializer_direct_calls) == 1
    and request_mapper_failure_propagations[0].start()
    <= request_mapper_initializer_direct_calls[0].start()
    < request_mapper_failure_propagations[0].end()
    and not c_has_unstructured_control_flow(request_initializer)
    and not c_has_ucn_escape(request_initializer)
    and request_mapper_failure_propagations[0].start() < request_hostname_call
    < request_headers_call
)
response_header_sink_is_bounded = (
    critical_macro_controls_are_safe
    and 'return ngx_http_modsecurity_add_n_response_header(ctx,' in server_header_resolver
    and '(const unsigned char *) value.data,' in server_header_resolver
    and 'value.len);' in server_header_resolver
    and 'msc_add_n_response_header' not in header_all_code
    and not c_has_ucn_escape(header_all_code)
    and len(response_header_validation_rejections) == 1
    and len(response_header_raw_sinks) == 1
    and len(response_header_raw_sink_occurrences) == 1
    and len(response_header_raw_sink_name_occurrences) == 1
    and len(response_header_raw_sink_returns) == 1
    and len(response_header_return_occurrences) == 2
    and C_PREPROCESSOR_DIRECTIVE.search(response_header_sink_unmasked) is None
    and response_header_return_occurrences[0].group('expression').strip()
    == 'NGX_ERROR'
    and response_header_validation_rejections[0].start()
    < response_header_raw_sink_returns[0].start()
    and response_header_return_occurrences[-1].start()
    == response_header_raw_sink_returns[0].start()
    and not c_has_unstructured_control_flow(response_header_sink)
    and not c_has_ucn_escape(response_header_sink)
)
body_response_mapper_contract_is_direct = (
    BODY_RESPONSE_MAPPER_ONCE_CONTRACT_PATTERN.fullmatch(
        body_response_mapper_once) is not None
    and C_PREPROCESSOR_DIRECTIVE.search(body_response_mapper_once_unmasked) is None
    and len(body_response_mapper_calls) == 1
    and len(body_response_mapper_direct_calls) == 1
    and len(body_response_validated_assignments) == 1
    and len(body_response_validated_direct_assignments) == 1
)
body_mapper_validation_is_once = (
    body_response_mapper_contract_is_direct
    and all(marker in body_filter_prepare for marker in (
        CTX_NULL_GUARD,
        CTX_BODY_MAPPER_SKIP_GUARD,
        'ngx_http_modsecurity_validate_response_mapper_once(r, ctx)',
    ))
    and body_filter_prepare.find(CTX_NULL_GUARD)
    < body_filter_prepare.find(CTX_BODY_MAPPER_SKIP_GUARD)
    < body_filter_prepare.find(
        'ngx_http_modsecurity_validate_response_mapper_once(r, ctx)')
    and 'ngx_http_modsecurity_prepare_response_body_filter(r, in, &ctx)' in body_filter
)
header_response_mapper_contract_is_direct = (
    len(header_response_mapper_calls) == 1
    and len(header_response_mapper_direct_calls) == 1
    and len(header_response_validated_assignments) == 1
    and len(header_response_validated_direct_assignments) == 1
    and RESPONSE_VALIDATED_GUARD_PATTERN.search(header_filter) is None
    and len(header_ctx_acquisitions) == 1
    and HEADER_CTX_DECLARATION_PREFIX_PATTERN.fullmatch(
        header_ctx_declaration_prefix) is not None
    and len(header_ctx_null_guards) == 1
    and len(header_response_header_failure_guards) == 1
    and len(header_intervention_guards) == 1
    and len(header_processed_guards) == 1
    and len(header_processed_assignments) == 1
    and C_PREPROCESSOR_DIRECTIVE.search(header_pre_mapper_unmasked) is None
    and len(header_pre_mapper_control_flows) == 3
    and len(header_pre_mapper_returns) == 3
    and [match.start() for match in header_pre_mapper_control_flows] == [
        header_ctx_null_guards[0].start(),
        header_response_header_failure_guards[0].start(),
        header_intervention_guards[0].start(),
    ]
    and all(
        header_ctx_null_guards[0].start() <= match.start()
        < header_ctx_null_guards[0].end()
        or header_response_header_failure_guards[0].start() <= match.start()
        < header_response_header_failure_guards[0].end()
        or header_intervention_guards[0].start() <= match.start()
        < header_intervention_guards[0].end()
        for match in header_pre_mapper_returns
    )
    and header_ctx_acquisitions[0].start() < header_ctx_null_guards[0].start()
    and header_ctx_null_guards[0].start()
    < header_response_header_failure_guards[0].start()
    < header_intervention_guards[0].start()
    < header_response_mapper_direct_calls[0].start()
    < header_response_validated_direct_assignments[0].start()
    < header_processed_guards[0].start()
    < header_processed_assignments[0].start()
    and c_only_header_ctx_diagnostic_or_whitespace(
        header_filter,
        header_filter_visible,
        header_ctx_acquisitions[0].end(),
        header_ctx_null_guards[0].start(),
    )
    and c_only_whitespace_between(
        header_filter,
        header_ctx_null_guards[0].end(),
        header_response_header_failure_guards[0].start(),
    )
    and c_only_whitespace_between(
        header_filter,
        header_response_header_failure_guards[0].end(),
        header_intervention_guards[0].start(),
    )
    and c_only_whitespace_between(
        header_filter,
        header_intervention_guards[0].end(),
        header_response_mapper_direct_calls[0].start(),
    )
    and not header_mapper_to_validated.strip()
    and not header_validated_to_processed_guard.strip()
    and C_PREPROCESSOR_DIRECTIVE.search(
        header_mapper_to_processed_unmasked) is None
    and not c_has_unstructured_control_flow(header_filter)
)
filter_callers_delegate_to_mapper = (
    body_response_mapper_contract_is_direct
    and header_response_mapper_contract_is_direct
    and not c_has_forbidden_pattern(
        body_response_mapper_once + header_filter,
        (
            re.compile(r'\bmsconnector_response_mapper_contract\s+contract\b'),
            re.compile(r'\bmsconnector_response\s+mapped_response\b'),
            re.compile(r'\bchar\s+mapper_error\s*\[\s*128\s*\]'),
            re.compile(r'\bmsconnector_response_mapper_contract_init\s*\('),
            re.compile(r'\bngx_http_modsecurity_map_response_from_ctx\s*\('),
        ),
    )
)
body_filter_direct_chain_is_direct = (
    BODY_FILTER_DIRECT_CHAIN_CONTRACT_PATTERN.fullmatch(body_filter) is not None
)
body_response_buffer_is_limited = (
    BODY_RESPONSE_BUFFER_CONTRACT_PATTERN.fullmatch(
        body_response_append_buffer) is not None
)
body_response_limited_is_direct = (
    BODY_RESPONSE_LIMITED_CONTRACT_PATTERN.fullmatch(
        body_response_append_limited) is not None
)
phase4_mime_is_engine_owned = (
    'phase4_in_scope' not in body_c
    and 'phase4_content_types' not in body_c
    and 'phase4_content_types' not in common_h
    and 'phase4_content_types' not in module_c
    and 'modsecurity_phase4_content_types_file' not in module_c
)
body_response_chain_append_is_direct_wrapper = (
    BODY_RESPONSE_CHAIN_APPEND_CONTRACT_PATTERN.fullmatch(
        body_response_chain_append) is not None
)
body_response_limit_contract_is_direct = (
    body_response_chain_append_is_direct_wrapper
    and C_PREPROCESSOR_DIRECTIVE.search(
        body_response_chain_append_all_branches) is None
    and not body_limit_plan_chunk_calls
    and len(c_direct_matches(body_limited_response_plan,
        BODY_LIMIT_BYTES_SEEN_INCREMENT_PATTERN)) == 1
    and '*allowed = len;' in body_limited_response_plan
    and 'SIZE_MAX - ctx->response_body_bytes_seen' in body_limited_response_plan
    and 'SIZE_MAX - ctx->response_body_bytes_inspected' in body_limited_response_plan
    and 'phase4_mode' not in body_limited_response_plan
)

body_response_chain_call_is_direct = (
    len(body_response_chain_append_calls) == 1
    and len(body_response_chain_call_contracts) == 1
    and C_PREPROCESSOR_DIRECTIVE.search(body_response_chain_all_branches) is None
)
body_response_raw_sink_is_owned = (
    len(body_response_raw_sink_occurrences) == 1
    and len(body_response_chunk_raw_sinks) == 1
)
header_response_header_collection_is_direct = (
    len(header_response_header_collection_contracts) == 1
)
header_response_header_collection_wrapper_surface_is_direct = (
    len(header_response_header_collection_wrapper_contracts) == 1
    and len(header_validated_response_header_wrapper_calls)
    == EXPECTED_HEADER_VALIDATED_RESPONSE_HEADER_WRAPPER_CALLS
)
header_response_header_collection_traversal_is_direct = (
    len(header_response_header_collection_synthetic_contracts) == 1
    and len(header_response_header_collection_prefix_contracts) == 1
    and len(header_response_header_collection_chain_traversals) == 1
    and len(header_response_header_collection_wrapper_contracts) == 1
    and len(header_response_header_collection_sanity_blocks) == 1
    and header_response_header_collection_directive_lines
    == EXPECTED_RESPONSE_HEADER_COLLECTION_DIRECTIVES
    and header_response_header_collection_return_expressions
    == ('NGX_ERROR', 'NGX_ERROR', 'NGX_OK')
    and header_response_header_collection_synthetic_contracts[0].start()
    < header_response_header_collection_chain_traversals[0].start()
    < header_response_header_collection_wrapper_contracts[0].start()
    and not c_has_unstructured_control_flow(response_header_collection)
)
header_synthetic_resolvers_are_direct = (
    len(header_synthetic_resolver_table_contracts) == 1
    and HEADER_DATE_RESOLVER_CONTRACT_PATTERN.fullmatch(
        header_date_resolver) is not None
)
common_next_header_is_direct = (
    COMMON_NEXT_HEADER_CONTRACT_PATTERN.fullmatch(common_next_header) is not None
)
response_header_raw_sink_is_owned = (
    response_header_sink_is_bounded
    and len(response_header_raw_sink_source_occurrences) == 1
)
checks = [
(c_event_jsonl_pipeline(event_jsonl_active), 'NGINX request JSONL projection and serialization retain the active ordered fail-closed pipeline'),
(c_event_jsonl_pipeline(phase_event_jsonl_active, True), 'NGINX strict JSONL projection and serialization retain the active ordered fail-closed pipeline'),
(critical_macro_controls_are_safe, 'NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls'),
('msconnector_config common_config' in common_h or 'msconnector_config        common_config' in common_h, 'NGINX config embeds msconnector_config common_config'),
('"msconnector/phase.h"' in common_h and 'enum msconnector_phase native_event_phase;' in common_h, 'NGINX native event phase has its complete Common enum declaration'),
('#if (NGX_PCRE) && !(NGX_PCRE2)' in module_c and '#if !(NGX_PCRE) || (NGX_PCRE2)' in common_h, 'NGINX PCRE allocation shim is disabled for PCRE2 and no-PCRE builds'),
('msconnector_config_init' in module_c and 'msconnector_config_merge' in module_c and 'msconnector_config_validate' in module_c, 'NGINX config init/merge/validate uses Common'),
(
    'conf->phase4_log_file = NGX_CONF_UNSET_PTR;' in module_c
    and 'if (c->phase4_log_file == NGX_CONF_UNSET_PTR)' in module_c
    and 'if (p->phase4_log_file == NGX_CONF_UNSET_PTR)' in module_c
    and 'c->phase4_log_file = p->phase4_log_file;' in module_c
    and 'c->phase4_log_path = p->phase4_log_path;' in module_c
    and 'ngx_conf_merge_ptr_value(c->phase4_log_file, p->phase4_log_file, NULL);' not in module_c,
    'NGINX inherits server-level Phase4 log settings by borrowing the parent-owned descriptor',
),
('msconnector_parse_bool' in module_c, 'NGINX bool parsing uses Common parser'),
('msconnector_parse_phase4_mode' in module_c, 'NGINX phase4 parsing uses Common parser'),
('msconnector_parse_size' in module_c or 'config_parser.h' in module_c, 'NGINX size parser is available through Common config surface'),
('MSCONNECTOR_DIRECTIVE_' in module_c and ('directive_adapter.h' in module_c or 'directive_spec.h' in module_c), 'NGINX directive registration is tied to Common macros/specs/adapters'),
('ngx_http_request_t' in mapper_h and 'msconnector_request' in mapper_h and 'msconnector_request_mapper_contract' in mapper_h and 'msconnector_request_mapper_validate_output' in mapper_c, 'NGINX request mapper contract is present'),
('ngx_http_modsecurity_map_request' in access_c and 'msconnector_request_mapper_contract_init' in access_c, 'NGINX request mapper is exercised in access path'),
(request_mapper_typed_status_is_fail_closed, 'NGINX mapper propagates internal failure 500 and independently bounded client header-count failure 400'),
(
    request_mapper_contract_is_fail_closed,
    'NGINX request mapper validation fails closed before request-header initialization',
),
('msconnector_response' in mapper_h and 'msconnector_response_mapper_contract' in mapper_h and 'msconnector_response_mapper_validate_output' in mapper_c, 'NGINX response mapper contract is present'),
('typedef enum {' in mapper_h and 'NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_HEADER' in mapper_h and 'NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_BODY' in mapper_h and 'void ngx_http_modsecurity_validate_response_mapper(' in mapper_h, 'NGINX mapper owns an internal compile-time response diagnostic discriminator'),
('msconnector_response_mapper_contract contract;' in response_mapper_helper and 'msconnector_response mapped_response;' in response_mapper_helper and 'char mapper_error[128];' in response_mapper_helper and 'msconnector_response_mapper_contract_init(&contract);' in response_mapper_helper and response_mapper_helper.count('ngx_http_modsecurity_map_response_from_ctx') == 1, 'NGINX mapper helper exclusively owns the common response mapper contract/map tail'),
(RESPONSE_MAPPER_HELPER_SIGNATURE in response_mapper_helper and 'NGX_LOG_WARN' in response_mapper_helper and 'NGX_ERROR' not in response_mapper_helper and 'NGX_HTTP_INTERNAL_SERVER_ERROR' not in response_mapper_helper, 'NGINX response mapper helper is void and warning-only'),
(not c_has_forbidden_pattern(
    response_mapper_helper_all_branches,
    C_RESPONSE_MAPPER_FORBIDDEN_ALL_BRANCH_PATTERNS,
) and response_mapper_helper_is_immutable and response_mapper_from_ctx_ignores_ctx, 'NGINX response mapper helper excludes caller lifecycle, body, enforcement, filter-chain, and allocation control'),
(filter_callers_delegate_to_mapper, 'NGINX filter callers delegate instead of retaining a direct mapper-tail duplicate'),
(body_mapper_validation_is_once, 'NGINX body mapper validation remains once-only, post-guard, and non-fatal'),
(header_response_mapper_contract_is_direct, 'NGINX header mapper validation retains its existing eligibility and ordering without a once gate'),
(header_response_header_collection_is_direct, 'NGINX header filter directly collects validated response headers before metadata processing'),
(header_response_header_collection_wrapper_surface_is_direct, 'NGINX response-header collection retains the reviewed validated wrapper surface'),
(header_response_header_collection_traversal_is_direct, 'NGINX response-header collection retains the reviewed synthetic and chained traversal'),
(header_synthetic_resolvers_are_direct, 'NGINX synthetic response-header resolver table and Date route retain the validated Common wrapper'),
(common_next_header_is_direct, 'NGINX chained response-header traversal retains the canonical Common iterator'),
(ddebug_static_fallbacks_are_inert, 'NGINX nonvariadic diagnostic fallbacks remain inert and bounded'),
('if (diagnostic == NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_BODY)' in response_mapper_helper and '"modsecurity common response-body mapper validation skipped: %s"' in response_mapper_helper_visible and '"modsecurity common response mapper validation skipped: %s"' in response_mapper_helper_visible and 'const char *' not in response_mapper_helper and body_response_mapper_contract_is_direct and header_response_mapper_contract_is_direct, 'NGINX response mapper helper retains fixed caller-specific warning diagnostics'),
('ngx_http_modsecurity_add_synthetic_response_headers(r, headers, &header_count)' in response_mapper_from_ctx and response_mapper_from_ctx.find(ERR_STATUS_PRESENT) < response_mapper_from_ctx.find('r->headers_out.status != 0') and 'out->status = (int) r->err_status' in response_mapper_from_ctx, 'NGINX response mapper retains synthetic-header and err_status contracts'),
('msconnector_headers_find_first' in mapper_c, 'NGINX mapper uses Common header helpers'),
(phase4_mime_is_engine_owned, 'NGINX leaves Phase4 MIME selection to the ModSecurity engine'),
(not re.search(r'ngx_http_modsecurity_[a-z0-9_]*json_escape\s*\(', all_nginx), 'Duplicate NGINX JSON escape helper is absent'),
(c_rule_id_delegation_is_bounded(), 'NGINX rule-id extraction delegates only to bounded Common parsing before intervention sinks'),
('ngx_http_modsecurity_pool_strndup' in mapper_c and 'out->method = ngx_http_modsecurity_pool_strndup' in mapper_c and 'out->uri = ngx_http_modsecurity_pool_strndup' in mapper_c, 'NGINX request mapper NUL-terminates request string fields'),
('Content-Type' in mapper_c and 'Content-Length' in mapper_c and 'msconnector_headers_find_first' in mapper_c, 'NGINX response mapper preserves synthetic special headers'),
(mapper_c.find(ERR_STATUS_PRESENT) != -1 and mapper_c.find('headers_out.status != 0') != -1 and mapper_c.find(ERR_STATUS_PRESENT) < mapper_c.find('headers_out.status != 0') and 'out->status = (int) r->err_status' in mapper_c, 'NGINX response mapper preserves err_status before headers_out fallback status'),
('msconnector_event_init' in body_c and 'msconnector_event_write_jsonl_line' not in body_c and 'msconnector_event_write_jsonl_line' in phase_event_jsonl_helper and '"intervention_log"' not in body_c, 'NGINX Phase4 log uses the strict Common metadata-only event serialization without intervention text'),
('typedef struct {\n    const char *method;\n    const char *uri;\n    const char *content_type;\n} ngx_http_modsecurity_event_request_metadata_t;' in common_h and 'ngx_http_modsecurity_event_request_metadata_t metadata = {\n        "", "", ""\n    };' in event_metadata_helper and 'if (r == NULL)' in event_metadata_helper and 'r->method_name.len > 0U' in event_metadata_helper and 'r->unparsed_uri.len > 0U' in event_metadata_helper and 'r->headers_in.content_type != NULL' in event_metadata_helper and 'value != (char *)-1 && value != NULL' in event_metadata_helper and 'metadata.method = value;' in event_metadata_helper and 'metadata.uri = value;' in event_metadata_helper and 'metadata.content_type = value;' in event_metadata_helper, 'NGINX event request-metadata helper preserves empty fallbacks for absent, empty, NULL, and allocation-failure values'),
(EVENT_JSONL_HEADER in common_h and EVENT_JSONL_HEADER not in access_c and EVENT_JSONL_HEADER not in log_c, 'NGINX common header owns the event JSONL serialization dependency'),
(EVENT_JSONL_LINE_BUFFER in event_jsonl_helper and 'int json_truncated = 0;' in event_jsonl_helper and event_jsonl_helper.count('msconnector_event_write_jsonl_line') == 1 and 'line_length = ngx_strlen(line);' in event_jsonl_helper and event_jsonl_helper.count('ngx_write_fd') == 1 and 'written < 0 || (size_t)written != line_length' in event_jsonl_helper and 'written < 0 ? ngx_errno : 0' in event_jsonl_helper and '"%s", write_failure_message' in event_jsonl_write and EVENT_BODY_BYTES_SEEN not in event_jsonl_helper and EVENT_BODY_BYTES_INSPECTED not in event_jsonl_helper and REQUEST_BODY_ACCESS not in event_jsonl_helper, 'NGINX common JSONL helper retains one bounded serialization and one warning-only write without body data'),
('"%s%s", serialization_failure_message' in event_jsonl_serialization and 'json_truncated ? " (truncated)" : ""' in event_jsonl_serialization and 'return 0;' in event_jsonl_serialization and 'return 0;' in event_jsonl_write and 'return 1;' in event_jsonl_write, 'NGINX common JSONL helper reports serialization and physical-write failures while diagnostic callers retain warning-only host behavior'),
('ngx_http_modsecurity_write_event_jsonl' not in body_c and 'ngx_http_modsecurity_write_event_jsonl' not in header_c, 'NGINX common JSONL helper is not extended to body or header event paths'),
(EVENT_JSONL_LINE_BUFFER in phase_event_jsonl_helper and 'int json_truncated = 0;' in phase_event_jsonl_helper and phase_event_jsonl_helper.count('msconnector_event_write_jsonl_line') == 1 and phase_event_jsonl_helper.count('ngx_write_fd') == 1 and 'return NGX_ERROR;' in phase_event_jsonl_helper and RETURN_NGX_OK in phase_event_jsonl_helper and 'written < 0' in phase_event_jsonl_helper and '(size_t)written != line_length' in phase_event_jsonl_helper and 'modsecurity %s common event serialization failed%s' in phase_event_jsonl_helper and 'modsecurity %s log write failed' in phase_event_jsonl_helper and 'modsecurity %s log short write: %z of %uz bytes' in phase_event_jsonl_helper and EVENT_BODY_BYTES_SEEN not in phase_event_jsonl_helper and EVENT_BODY_BYTES_INSPECTED not in phase_event_jsonl_helper and REQUEST_BODY_ACCESS not in phase_event_jsonl_helper, 'NGINX strict Phase3/4 JSONL helper has one bounded write tail and propagates serialization, write, and short-write failures without body data'),
('ngx_http_modsecurity_write_phase_event_jsonl(r, mcf, &event,\n        "phase3");' in phase3_log_event and 'msconnector_event_write_jsonl_line' not in phase3_log_event and 'ngx_write_fd' not in phase3_log_event and EVENT_JSONL_LINE_BUFFER not in phase3_log_event, 'NGINX Phase3 event construction delegates only the strict JSONL tail and retains its phase-specific diagnostics'),
('ngx_http_modsecurity_write_phase_event_jsonl(r, mcf, &event,\n        "phase4");' in phase4_log_event and 'msconnector_event_write_jsonl_line' not in phase4_log_event and 'ngx_write_fd' not in phase4_log_event and EVENT_JSONL_LINE_BUFFER not in phase4_log_event, 'NGINX Phase4 event construction delegates only the strict JSONL tail and retains its phase-specific diagnostics'),
('ngx_http_modsecurity_event_request_metadata(r)' in access_event and 'ngx_http_modsecurity_event_request_metadata(r)' in log_event and 'ngx_str_to_char(' not in access_event and 'ngx_str_to_char(' not in log_event and 'event.request.method = request_metadata.method;' in access_event and 'event.request.method = request_metadata.method;' in log_event and 'event.request.uri = request_metadata.uri;' in access_event and 'event.request.uri = request_metadata.uri;' in log_event and 'event.body.content_type = request_metadata.content_type;' in access_event and 'event.body.content_type = request_metadata.content_type;' in log_event, 'NGINX access and native rule-match loggers share only request-metadata conversion'),
((EVENT_BODY_BYTES_SEEN not in access_event and EVENT_BODY_BYTES_SEEN not in log_event and EVENT_BODY_BYTES_INSPECTED not in access_event and EVENT_BODY_BYTES_INSPECTED not in log_event and REQUEST_BODY_ACCESS not in access_event and REQUEST_BODY_ACCESS not in log_event), 'NGINX request event loggers keep helper output metadata-only and exclude request-body data'),
('MSCONN_EVENT_REQUEST_BLOCKED' in access_event and 'MSCONNECTOR_STATUS_BLOCKED' in access_event and 'event.decision.action = wanted;' in access_event and 'MSCONN_EVENT_RULE_MATCHED' in log_event and 'MSCONNECTOR_STATUS_OK' in log_event and 'event.decision.action = "pass";' in log_event and 'event.decision.rule_id = rule_id;' in log_event, 'NGINX event construction and decision semantics remain source-specific'),
('"modsecurity request intervention event serialization failed"' in access_event and '"modsecurity request intervention log write failed"' in access_event and '"modsecurity native rule-match event serialization failed"' in log_event and '"modsecurity native rule-match log write failed"' in log_event, 'NGINX request event callers retain exact source-specific serialization and write diagnostics'),
('if (r == NULL || mcf == NULL || mcf->phase4_log_file == NULL ||' in access_event and 'if (r == NULL || !msconnector_rule_id_validate(rule_id))' in log_event and 'ctx == NULL || mcf == NULL || mcf->phase4_log_file == NULL ||' in log_event and 'if (!ngx_http_modsecurity_write_event_jsonl(' in access_event and 'if (!ngx_http_modsecurity_write_event_jsonl(' in log_event and 'msconnector_event_write_jsonl_line' not in access_event and 'msconnector_event_write_jsonl_line' not in log_event and 'ngx_write_fd' not in access_event and 'ngx_write_fd' not in log_event and EVENT_JSONL_LINE_BUFFER not in access_event and EVENT_JSONL_LINE_BUFFER not in log_event and 'json_truncated' not in access_event and 'json_truncated' not in log_event and 'line_length' not in access_event and 'line_length' not in log_event and 'ssize_t written' not in access_event and 'ssize_t written' not in log_event, 'NGINX request event loggers retain source-specific guards and rule-ID validation while delegating the direct JSONL tail'),
('msconnector_late_intervention_policy_init' in body_c and 'msconnector_late_intervention_resolve' in body_c and 'msconnector_late_intervention_action_name' in body_c, 'NGINX Phase4 handling uses the Common late-intervention policy'),
('last_intervention_rule_id' in common_h and 'msconnector_rule_id_extract_from_message' in module_c and 'last_intervention_log' not in common_h + module_c + body_c and 'last_intervention_rule_id' in body_c, 'NGINX retains only a bounded extracted rule ID instead of copying the full intervention log'),
('log_result = ngx_http_modsecurity_phase4_log_event' in body_c and 'if (log_result != NGX_OK)' in body_c and 'return ngx_http_modsecurity_phase4_log_event' in body_c and 'return NGX_ERROR;' in phase_event_jsonl_helper and '"phase4"' in phase4_log_event, 'NGINX Phase4 event write and short-write failures are observable and propagated'),
('MSCONNECTOR_COMMON_SRC' in nginx_config and '$MSCONNECTOR_COMMON_SRC/event.c' in nginx_config and '$MSCONNECTOR_COMMON_SRC/transaction_state.c' in nginx_config and '$MSCONNECTOR_COMMON_SRC/late_intervention.c' in nginx_config, 'NGINX build uses stable Common source root and links event and late-intervention support'),
('common_response_validated' in common_h and ('if (!ctx->common_response_validated)' in body_c or CTX_RESPONSE_VALIDATED_GUARD in body_c) and 'ctx->common_response_validated = 1' in body_c, 'NGINX response mapper validation is gated once per response in body path'),
('response_body_bytes_inspected' in common_h and 'ngx_http_modsecurity_append_accounted_response_body' in body_c and 'msconnector_phase4_effective_body_limit(' not in body_c and 'msconnector_body_limit_plan_chunk(' not in body_c and 'common_config.phase4_body_limit' not in body_c and 'SIZE_MAX - ctx->response_body_bytes_seen' in body_c, 'NGINX preserves checked response accounting without a connector-owned inspection limit'),
(body_response_buffer_is_limited, 'NGINX response-body buffer route retains the bounded memory/file planner paths'),
(body_response_limited_is_direct, 'NGINX response-body helper passes each accounted complete chunk to the raw route'),
(phase4_mime_is_engine_owned, 'NGINX has no connector-owned Phase4 content-type allowlist'),
('chain->buf->last_buf ||' in body_c and 'chain->buf->last_in_chain' in body_c and 'ctx->phase4_processed' in body_c, 'NGINX finalizes Phase4 once at the actual main or subrequest end-of-stream'),
(body_response_limit_contract_is_direct, 'NGINX records response-body bytes with checked full-chunk accounting before append'),
('ngx_http_modsecurity_phase4_actual_action(action, wanted)' in body_c and '"redirect" : "deny"' in body_c, 'NGINX preserves redirect as the requested pre-commit action'),
('event.body.content_type' in body_c and EVENT_BODY_BYTES_SEEN in body_c and EVENT_BODY_BYTES_INSPECTED in body_c, 'NGINX Phase4 events include payload-free content-type and body-byte metadata'),
('ngx_str_t event_transaction_id' in common_h and 'ctx->event_transaction_id' in module_c and 'ctx->event_transaction_id' in body_c and 'event.meta.transaction_id = ctx != NULL' in body_c, 'NGINX Phase4 events retain a request-level transaction ID instead of a connection-only identifier'),
('MSCONNECTOR_DIRECTIVE_TRANSACTION_ID_EXPR' not in module_c, 'NGINX does not register Apache-style transaction_id_expr'),
(
    'value.data = (u_char *)ngx_http_server_full_string;' in server_header_resolver
    and 'value.len = sizeof(ngx_http_server_full_string) - 1U;' in server_header_resolver
    and 'value.len = sizeof(ngx_http_server_full_string);' not in server_header_resolver,
    'NGINX server_tokens default excludes the terminating NUL from the explicit Server header length',
),
(
    'value.data = (u_char *)ngx_http_server_string;' in server_header_resolver
    and 'value.len = sizeof(ngx_http_server_string) - 1U;' in server_header_resolver
    and 'value.len = sizeof(ngx_http_server_string);' not in server_header_resolver,
    'NGINX non-tokenized default excludes the terminating NUL from the explicit Server header length',
),
(
    'ngx_table_elt_t *h = r->headers_out.server;' in custom_server_header_branch
    and 'value.data = h->value.data;' in custom_server_header_branch
    and re.search(r'value\.len\s*=\s*h->value\.len;', custom_server_header_branch) is not None
    and '- 1U' not in custom_server_header_branch
    and 'strlen(' not in custom_server_header_branch
    and 'ngx_strlen(' not in custom_server_header_branch,
    'NGINX custom Server headers retain the host-provided explicit length',
),
(
    response_header_sink_is_bounded,
    'NGINX Server resolver preserves the bounded explicit-length response-header sink',
),
(
    response_header_raw_sink_is_owned,
    'NGINX response-header raw sink remains owned by the canonical validated Common wrapper',
),
(
    body_response_raw_sink_is_owned,
    'NGINX response-body raw sink remains owned by the bounded append helper',
),
(
    body_response_chain_call_is_direct,
    'NGINX response-body chain loop directly calls the reviewed bounded wrapper',
),
(
    body_filter_direct_chain_is_direct,
    'NGINX response-body filter retains only the direct prepared chain path',
),
]
claims = ['production verified','runtime verified','full-matrix verified','crs verified']
text = '\n'.join((ROOT/p).read_text(errors='ignore') for p in ['connectors/nginx/README.md','docs/connectors/nginx.md'] if (ROOT/p).exists()).lower()
checks.append((not any(c in text for c in claims), 'NGINX docs avoid production/runtime/CRS/full-matrix claims'))
ok=True
for passed,msg in checks:
    print(('PASS' if passed else 'FAIL')+': '+msg)
    ok = ok and passed
sys.exit(0 if ok else 1)
