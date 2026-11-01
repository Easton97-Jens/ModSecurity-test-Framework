#!/usr/bin/env python3
"""Static contract checks for connector-neutral common SDK files."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path
from pathlib import Path
import re
import sys

ROOT = connector_root()
COMMON = source_path('common', root=ROOT)
CHECK_COMMON_HELPERS = source_path('ci/checks/common/check-common-helpers.sh', root=ROOT)
MAKEFILE = test_root() / 'connector_suite/connector.mk'
TEST_RESULT_HEADERS = [source_path(f"common/include/msconnector/{name}.h", root=ROOT)
                       for name in ("test_result", "test_result_json")]
TEST_RESULT_SOURCES = [source_path(f"common/src/{name}.c", root=ROOT)
                       for name in ("test_result", "test_result_json")]
SEARCH_ROOTS = [COMMON / "include", COMMON / "src",
                TEST_RESULT_HEADERS[0].parent, TEST_RESULT_SOURCES[0].parent]
FORBIDDEN_INCLUDES = (
    "#include <ngx_",
    "#include \"ngx_",
    "#include <httpd.h>",
    "#include \"httpd.h\"",
    "#include <haproxy",
    "#include \"haproxy",
    "#include <envoy",
    "#include \"envoy",
    "#include <traefik",
    "#include \"traefik",
    "#include <lighttpd",
    "#include \"lighttpd",
)
SERVER_TOKENS = ("nginx", "apache", "haproxy", "envoy", "traefik", "lighttpd")
NON_INTEGRATION_TERMS = ("not integrate", "not imply", "future", "separately", "no connector")
SUCCESS_RETURN_LITERAL = "return 0"


def fail(message: str) -> None:
    print(f"common-sdk-contract: {message}", file=sys.stderr)
    sys.exit(1)


def text_without_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


for header in [*(COMMON / "include" / "msconnector").glob("*.h"), *TEST_RESULT_HEADERS]:
    text = header.read_text(encoding="utf-8")
    guard = "MSCONNECTOR_" + header.stem.upper() + "_H"
    if f"#ifndef {guard}" not in text or f"#define {guard}" not in text:
        fail(f"missing include guard {guard} in {header.relative_to(ROOT)}")

for source in [*(COMMON / "src").glob("*.c"), *TEST_RESULT_SOURCES]:
    text = source.read_text(encoding="utf-8")
    expected = f'#include "msconnector/{source.stem}.h"'
    if expected not in text:
        fail(f"missing matching header include {expected} in {source.relative_to(ROOT)}")

for required_header in (
    "decision.h",
    "error.h",
    "rule_loader.h",
    "modsecurity_engine.h",
    "transaction_id.h",
    "adapter.h",
    "adapter_contract.h",
    "capability_matrix.h",
    "event_jsonl.h",
    "artifact_layout.h",
    "runtime_paths.h",
    "config_parser.h",
    "request_helpers.h",
    "response_helpers.h",
    "rule_merge.h",
    "rule_error.h",
    "rule_event.h",
    "test_result_json.h",
    "connector_manifest.h",
    "runtime_report.h",
    "origin_governance.h",
    "build_contract.h",
    "limits.h",
    "rule_id.h",
    "log_sanitize.h",
    "generic_mapper.h",
):
    if not (source_path(Path("common/include/msconnector") / required_header, root=ROOT)).is_file():
        fail(f"missing common SDK header {required_header}")
    if not (source_path(Path("common/src") / required_header.replace(".h", ".c"), root=ROOT)).is_file():
        fail(f"missing common SDK source {required_header.replace('.h', '.c')}")


for required_wrapper in (
    "request.hpp",
    "response.hpp",
    "transaction.hpp",
    "status.hpp",
    "capabilities.hpp",
    "origin.hpp",
    "logging.hpp",
):
    wrapper = COMMON / "include" / "msconnector" / required_wrapper
    if not wrapper.is_file():
        fail(f"missing C++ wrapper {required_wrapper}")
    wrapper_text = wrapper.read_text(encoding="utf-8")
    if "namespace msconnector" not in wrapper_text or "#include" not in wrapper_text:
        fail(f"C++ wrapper {required_wrapper} must be lightweight and include the C header")

for required_script in (
    "ci/checks/common/check-origin-governance.py",
    "ci/checks/common/check-build-contracts.py",
    "ci/evidence/reports/generate-connector-contract-report.py",
):
    if not (source_path(required_script, root=ROOT)).is_file():
        fail(f"missing common package script {required_script}")

for required_doc in (
    "docs/generated/connector-contract.md",
    "docs/generated/connector-contract.de.md",
    "docs/generated/origin-governance.md",
    "docs/generated/origin-governance.de.md",
):
    if not (ROOT / required_doc).is_file():
        fail(f"missing generated common package doc {required_doc}")


generic_header = (COMMON / "include" / "msconnector" / "generic_mapper.h").read_text(encoding="utf-8")
generic_source = (COMMON / "src" / "generic_mapper.c").read_text(encoding="utf-8")
if "msconnector_generic_map_request" not in generic_header or "msconnector_generic_map_response" not in generic_header:
    fail("generic mapper header must expose request and response mapping APIs")
for token in ("ngx_", "request_rec", "apr_", "haproxy", "envoy", "traefik", "lighttpd"):
    if token in generic_header or token in generic_source:
        fail(f"generic mapper contains server-specific token {token!r}")

if "msconnector_headers_find_first" in generic_source or "out->hostname = host" in generic_source or "host->value" in generic_source:
    fail("generic mapper must not expose header value slices as C-string hostnames")
if "hostname must be NUL-terminated" not in generic_header:
    fail("generic mapper header must document NUL-terminated hostname requirement")
if "body.size > 0U && src->body.data == 0" not in generic_source:
    fail("generic mapper must reject nonzero body sizes with null body data")
if "header_count > 0U && src->headers == 0" not in generic_source:
    fail("generic mapper must reject nonzero header counts with null header arrays")
if "msconnector_generic_config_init" in generic_source and "msconnector_config_apply_defaults(config)" in generic_source:
    fail("generic init must not apply defaults before merge/finalization")

log_sanitize_source = (source_path('common/src/log_sanitize.c', root=ROOT)).read_text(encoding="utf-8")
if "redacted body" not in log_sanitize_source or "src;" not in log_sanitize_source:
    fail("body-snippet redaction must not copy payload bytes")

for root in SEARCH_ROOTS:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        uncommented = text_without_comments(text).lower()
        lowered = text.lower()
        for token in FORBIDDEN_INCLUDES:
            if token in lowered:
                fail(f"forbidden connector-specific include {token!r} in {path.relative_to(ROOT)}")
        for token in SERVER_TOKENS:
            if token in uncommented:
                fail(f"server-specific token {token!r} outside comments in {path.relative_to(ROOT)}")
            if token in lowered and not any(term in lowered for term in NON_INTEGRATION_TERMS):
                fail(f"server-specific token {token!r} lacks non-integration context in {path.relative_to(ROOT)}")

helper_text = CHECK_COMMON_HELPERS.read_text(encoding="utf-8")
makefile_text = MAKEFILE.read_text(encoding="utf-8")
combined_check_text = helper_text + "\n" + makefile_text
if "common/src/*.c" not in helper_text:
    fail("check-common-helpers.sh does not compile all common/src/*.c files")
if "-std=c99" in helper_text:
    fail("hardcoded -std=c99 remains in check-common-helpers.sh")
if "MSCONNECTOR_C_STD" not in helper_text or "MSCONNECTOR_CFLAGS" not in helper_text:
    fail("check-common-helpers.sh does not expose configurable common C standard flags")
if "MSCONNECTOR_C_STD ?= c17" not in makefile_text:
    fail("Makefile does not define c17 as the default common C standard")
if "-std=c20" in combined_check_text:
    fail("common C checks must not use -std=c20")
if "-std=c26" in combined_check_text:
    fail("common C checks must not use -std=c26")
if "--profile c23" not in makefile_text or "c2x" not in makefile_text:
    fail("optional c23/c2x common helper check is not wired")
if "--profile c2y" not in makefile_text or "gnu2y" not in makefile_text:
    fail("optional future-C c2y/gnu2y common helper check is not wired")

if "MSCONNECTOR_COMPILER_ID ?=" not in makefile_text:
    fail("Makefile must derive a common smoke compiler id for optional standard probes")
if '--compiler "$(MSCONNECTOR_COMPILER_ID)"' not in makefile_text:
    fail("optional C standard probes must use the same compiler id as the smoke")
if 'check-common-helpers CC="$(MSCONNECTOR_COMPILER_ID)"' not in makefile_text:
    fail("optional C standard smokes must compile with the probed compiler id")


detect_text = (source_path('ci/provisioning/toolchains/detect-c-standard.py', root=ROOT)).read_text(encoding="utf-8")
if "args.cc" in detect_text or 'parser.add_argument("--cc"' in detect_text:
    fail("detect-c-standard.py must not accept or use raw --cc command paths")
if "shell=True" in detect_text:
    fail("detect-c-standard.py must not use shell=True")
if "[0-9]" in detect_text:
    fail("detect-c-standard.py compiler regex must not use [0-9]")
if detect_text.count('"-std=c17"') > 1:
    fail("detect-c-standard.py duplicates the -std=c17 literal outside its constant")
if detect_text.count('"-std=c2x"') > 1:
    fail("detect-c-standard.py duplicates the -std=c2x literal outside its constant")
if "--compiler" not in detect_text or "COMPILER_ID_PATTERN" not in detect_text or "shutil.which" not in detect_text:
    fail("detect-c-standard.py must expose only a validated compiler-id selector")
if "gcc-\\d+" not in detect_text or "clang-\\d+" not in detect_text:
    fail("detect-c-standard.py must support safe versioned gcc/clang compiler ids")
if detect_text.count("subprocess.run(") != 1 or "def compiler_supports" not in detect_text:
    fail("detect-c-standard.py subprocess.run must appear only in the compiler probe helper")




def count_direct_fields(header_text: str, struct_name: str) -> int:
    match = re.search(
        rf"typedef\s+struct\s+{struct_name}\s*\{{(?P<body>.*?)\}}\s*{struct_name}\s*;",
        header_text,
        flags=re.S,
    )
    if match is None:
        fail(f"common event model is missing {struct_name}")
    body = text_without_comments(match.group("body"))
    return sum(1 for line in body.splitlines() if line.strip().endswith(";"))

def extract_http_status_table_statuses(source_text: str) -> set[int]:
    table_match = re.search(
        r"static\s+const\s+msconnector_http_status_info\s+http_statuses\[\]\s*=\s*\{(?P<body>.*?)\};",
        source_text,
        flags=re.S,
    )
    if table_match is None:
        fail("common/src/http_status.c does not expose a parseable http_statuses table")
    return {
        int(match.group(1))
        for match in re.finditer(r"\{\s*(\d{3})\s*,[^{}]*,\s*1\s*\}", table_match.group("body"))
    }


def extract_generator_statuses(source_text: str) -> set[int]:
    list_match = re.search(
        r"ALLOWED_BLOCK_STATUSES\s*=\s*\((?P<body>.*?)\)",
        source_text,
        flags=re.S,
    )
    if list_match is None:
        fail("ci/tools/generate-block-status-config.py does not expose a parseable ALLOWED_BLOCK_STATUSES tuple")
    return {int(value) for value in re.findall(r"\b(\d{3})\b", list_match.group("body"))}


http_status_source = (source_path('common/src/http_status.c', root=ROOT)).read_text(encoding="utf-8")
block_status_source = (source_path('common/src/block_statuses.c', root=ROOT)).read_text(encoding="utf-8")
generator_source = (source_path('ci/tools/generate-block-status-config.py', root=ROOT)).read_text(encoding="utf-8")
http_statuses = extract_http_status_table_statuses(http_status_source)
generator_statuses = extract_generator_statuses(generator_source)
if http_statuses != generator_statuses:
    fail(
        "HTTP status metadata and generator ALLOWED_BLOCK_STATUSES drift: "
        f"http_status.c={sorted(http_statuses)} generator={sorted(generator_statuses)}"
    )
if "case 400:" in block_status_source or "case 403:" in block_status_source:
    fail("common/src/block_statuses.c must delegate block status decisions instead of keeping a divergent switch list")
if "msconnector_http_status_is_block_response" not in block_status_source:
    fail("common/src/block_statuses.c does not delegate block status allow checks to HTTP status metadata")


headers_source = (source_path('common/src/headers.c', root=ROOT)).read_text(encoding="utf-8")
config_source = (source_path('common/src/config.c', root=ROOT)).read_text(encoding="utf-8")
path_policy_source = (source_path('common/src/path_policy.c', root=ROOT)).read_text(encoding="utf-8")
if "value_index" not in headers_source or "is_ows" not in headers_source or "header->value[suffix_index] == ';'" not in headers_source:
    fail("Content-Type matching must trim leading OWS and reject garbage after the media type")
if "msconnector_block_status_is_allowed" not in config_source or "validate_block_status_value" not in config_source:
    fail("default_block_status validation must use block-status allowance metadata")
if "merge_remote_rules_pair" not in config_source or "merge_transaction_id_pair" not in config_source:
    fail("config merge must preserve paired remote-rule and transaction-id fields")
if "is_path_separator" not in path_policy_source or "\\" not in path_policy_source:
    fail("path policy must treat backslash as a parent-traversal separator")

if "set-cookie" not in headers_source or "content-length" not in headers_source or "msconnector_headers_parse_content_length" not in headers_source:
    fail("headers.c must contain Set-Cookie and Content-Length duplicate-header policy")

adapter_metadata_source = (source_path('common/src/adapter_metadata.c', root=ROOT)).read_text(encoding="utf-8")
event_source = (source_path('common/src/event.c', root=ROOT)).read_text(encoding="utf-8")
if "string_is_nonempty" not in adapter_metadata_source or "imported_path" not in adapter_metadata_source:
    fail("adapter metadata completeness must reject empty required fields")
if "validate_error_status_value" not in config_source or "msconnector_http_status_is_error" not in config_source:
    fail("config validation must reject success/redirect default error and unsupported statuses")
if "format_event_json" not in event_source or "json_bool(was_truncated)" not in event_source:
    fail("event writer must recompute the truncation marker before final JSON output")
for required_doc in (
    "docs/architecture.md",
    "docs/architecture.de.md",
    "docs/connectors/README.md",
    "docs/connectors/README.de.md",
    "docs/generated/common-sdk.md",
    "docs/generated/common-sdk.de.md",
    "docs/generated/directives.md",
    "docs/generated/directives.de.md",
    "docs/generated/capabilities.md",
    "docs/generated/capabilities.de.md",
):
    if not (ROOT / required_doc).is_file():
        fail(f"missing bilingual/common generated document {required_doc}")
for required_script in (
    "ci/runtime/common/common-harness.sh",
    "ci/runtime/common/port_allocator.py",
    "ci/runtime/common/process_helper.py",
    "ci/evidence/reports/generate-common-docs.py",
    "ci/checks/common/check-adapter-contracts.py",
    "ci/checks/evidence/check-capability-truthfulness.py",
):
    if not (source_path(required_script, root=ROOT)).is_file():
        fail(f"missing common helper script {required_script}")
if not (source_path('config/testing/capability-contract.json', root=ROOT)).is_file():
    fail("missing capability contract JSON")
event_jsonl_source = (source_path('common/src/event_jsonl.c', root=ROOT)).read_text(encoding="utf-8")
runtime_paths_source = (source_path('common/src/runtime_paths.c', root=ROOT)).read_text(encoding="utf-8")
if "msconnector_event_write_json_ex" not in event_jsonl_source or "request_body" in event_jsonl_source or "response_body" in event_jsonl_source:
    fail("event_jsonl writer must use event JSON and avoid body payload fields")
if "msconnector_path_is_absolute" not in runtime_paths_source or "msconnector_path_has_parent_reference" not in runtime_paths_source:
    fail("runtime path join must reject absolute and parent-traversal artifact names")
decision_source = (source_path('common/src/decision.c', root=ROOT)).read_text(encoding="utf-8")
error_source = (source_path('common/src/error.c', root=ROOT)).read_text(encoding="utf-8")
rule_loader_source = (source_path('common/src/rule_loader.c', root=ROOT)).read_text(encoding="utf-8")
engine_source = (source_path('common/src/modsecurity_engine.c', root=ROOT)).read_text(encoding="utf-8")
transaction_id_source = (source_path('common/src/transaction_id.c', root=ROOT)).read_text(encoding="utf-8")
if "msconnector_decision_to_event" not in decision_source:
    fail("decision.c must expose decision_to_event integration")
if "msconnector_error_to_event" not in error_source:
    fail("error.c must expose error_to_event integration")
if "backend.add_inline" not in rule_loader_source or "msconnector_rule_load_stats_add_inline" not in rule_loader_source:
    fail("rule_loader.c must use backend callbacks and rule_load_stats")
if "modsecurity/" in engine_source.lower() or "modsecurity.h" in engine_source.lower():
    fail("modsecurity_engine.c must not include libmodsecurity headers directly")
if "ops." not in engine_source:
    fail("modsecurity_engine.c must use backend ops")
if "msconnector_transaction_contract_begin_phase" not in engine_source or \
        "msconnector_transaction_contract_complete_phase" not in engine_source or \
        "msconnector_transaction_state_note_phase" not in engine_source:
    fail("modsecurity_engine.c must drive the canonical transaction contract and retain legacy phase flags")
if "msconnector_transaction_state_mark_phase" in engine_source:
    fail("modsecurity_engine.c must not bypass canonical transaction phase validation")
if "\\n" not in transaction_id_source and "< 32U" not in transaction_id_source:
    fail("transaction_id.c must reject CR/LF/control characters")
if "expr_eval" not in transaction_id_source:
    fail("transaction_id.c must support callback expression resolution")

event_header = (source_path('common/include/msconnector/event.h', root=ROOT)).read_text(encoding="utf-8")
if count_direct_fields(event_header, "msconnector_event") > 20:
    fail("top-level msconnector_event must not exceed 20 direct fields")
for nested_struct in (
    "msconnector_event_meta",
    "msconnector_event_decision",
    "msconnector_event_http",
    "msconnector_event_protocol",
    "msconnector_event_request",
    "msconnector_event_flags",
):
    if count_direct_fields(event_header, nested_struct) > 20:
        fail(f"{nested_struct} must not exceed 20 direct fields")
for required_field in (
    "message_id",
    "message",
    "run_id",
    "transport_case_id",
    "requested_action",
    "actual_action",
    "http_reason_phrase",
    "http_default_message",
    "late_intervention",
    "connection_aborted",
    "truncated",
    "content_type",
    "bytes_seen",
    "bytes_inspected",
    "requested_protocol",
    "downstream_protocol",
    "upstream_protocol",
    "negotiated_protocol",
    "stream_id",
    "quic_connection_id_present",
    "fallback_used",
    "stream_reset",
    "client_disconnected",
    "upstream_disconnected",
    "cancelled",
    "eos_seen",
    "reset_by",
    "reset_code",
    "timeout_stage",
    "write_result",
    "cleanup_reason",
):
    if required_field not in event_header:
        fail(f"common event model must retain {required_field} metadata")
if re.search(r"\bquic_connection_id\s*;", text_without_comments(event_header)):
    fail("common event model must not retain a raw QUIC connection ID")
if "msconnector_event_set_phase4_hard_abort_after_200" not in event_header or "MSCONN_EVENT_PHASE4_HARD_ABORT_AFTER_200" not in event_source:
    fail("common event model must expose the Phase 4 hard-abort-after-200 helper")
if "body_payload" in event_source or "request_body" in event_source or "response_body" in event_source:
    fail("common event JSON writer must not include request/response body payload fields")
if "event->meta.message_id" not in event_source or "event->decision.requested_action" not in event_source:
    fail("common event JSON writer must use nested event metadata")
if "truncated" not in event_header or "truncated" not in event_source:
    fail("common event JSON writer must expose truncation")
if ("limit_outcome" not in event_header or
        "body_limit_outcome" not in event_source or
        "body_limit_outcome_json" not in event_source):
    fail("common event JSON writer must expose optional payload-free body-limit outcomes")
if "msconnector_event_write_json_ex" not in event_source or "return was_truncated ? 0 : 1" not in event_source:
    fail("common event JSON writer must fail success status when truncation is detected")
if "if ((dst_size == 0 || needed >= dst_size) && truncated != 0)" not in event_source:
    fail("common event JSON escaping helper must merge the truncation nested-if condition")
if '{200, "OK", "Request succeeded", MSCONNECTOR_HTTP_STATUS_CLASS_SUCCESS, 0}' not in http_status_source:
    fail("common HTTP status metadata must include non-blocking 200 OK metadata")

# Review hardening checks for PR 27 common SDK correctness.
decision_action_source = (source_path('common/src/decision_action.c', root=ROOT)).read_text(encoding="utf-8")
adapter_contract_source = (source_path('common/src/adapter_contract.c', root=ROOT)).read_text(encoding="utf-8")
rule_event_source = (source_path('common/src/rule_event.c', root=ROOT)).read_text(encoding="utf-8")
transaction_header = (source_path('common/include/msconnector/transaction.h', root=ROOT)).read_text(encoding="utf-8")
decision_header = (source_path('common/include/msconnector/decision.h', root=ROOT)).read_text(encoding="utf-8")
harness_source = (source_path('ci/runtime/common/common-harness.sh', root=ROOT)).read_text(encoding="utf-8")
if "decision_message_id" not in decision_source or "MSCONNECTOR_DECISION_KIND_ALLOW" not in decision_source or SUCCESS_RETURN_LITERAL not in decision_source:
    fail("decision_to_event must not map ALLOW/LOG_ONLY decisions to blocked events")
if "MSCONNECTOR_DECISION_KIND_DROP" not in decision_action_source or "MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION" not in decision_action_source:
    fail("decision_action must preserve specific decision kinds")
if "validate_n" not in transaction_id_source or "header->value_size" not in transaction_id_source or "msconnector_headers_find_first" not in transaction_id_source:
    fail("transaction ID header fallback must use bounded header value_size")
if "new_rules_set" not in engine_source or "old_rules_set" not in engine_source or "engine->rules_set = new_rules_set" not in engine_source:
    fail("modsecurity_engine_create_rules must preserve the old rules set until reload succeeds")
if ("msconnector_modsecurity_append_request_body" not in engine_source or
        "msconnector_modsecurity_finish_request_body" not in engine_source or
        "msconnector_modsecurity_append_response_body" not in engine_source or
        "msconnector_modsecurity_finish_response_body" not in engine_source):
    fail("modsecurity engine must expose borrowed chunk append and explicit body finalization APIs")
runtime_header = (source_path('common/runtime/msconnector_runtime.h', root=ROOT)).read_text(encoding="utf-8")
runtime_source = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(encoding="utf-8")
if "msconnector_runtime_phase4_mode" not in runtime_header or "msconnector_runtime_phase4_mode" not in runtime_source:
    fail("common runtime must expose the parsed Phase-4 policy mode without connector-local mirrors")
for transport_result in (
    "completed", "connection_aborted", "stream_reset", "client_cancelled",
    "client_disconnected", "upstream_reset", "upstream_disconnected", "timeout",
    "short_write", "write_would_block", "engine_error", "host_error",
):
    if f'"{transport_result}"' not in runtime_source:
        fail(f"common runtime must retain canonical transport result {transport_result}")
body_policy_header = (source_path('common/include/msconnector/body_policy.h', root=ROOT)).read_text(encoding="utf-8")
body_policy_source = (source_path('common/src/body_policy.c', root=ROOT)).read_text(encoding="utf-8")
config_header = (source_path('common/include/msconnector/config.h', root=ROOT)).read_text(encoding="utf-8")
config_source = (source_path('common/src/config.c', root=ROOT)).read_text(encoding="utf-8")
for lifecycle_api in (
    "msconnector_runtime_transaction_begin_request_stream",
    "msconnector_runtime_transaction_append_request_body_chunk",
    "msconnector_runtime_transaction_finish_request_body",
    "msconnector_runtime_transaction_process_response_headers",
    "msconnector_runtime_transaction_append_response_body_chunk",
    "msconnector_runtime_transaction_finish_response_body",
):
    if lifecycle_api not in runtime_header or lifecycle_api not in runtime_source:
        fail(f"common runtime is missing explicit lifecycle API {lifecycle_api}")
transaction_match = re.search(
    r"struct\s+msconnector_runtime_transaction\s*\{(?P<body>.*?)\};",
    runtime_source,
    flags=re.S,
)
if transaction_match is None:
    fail("common runtime transaction storage is not parseable")
transaction_storage = text_without_comments(transaction_match.group("body"))
if "const msconnector_request *" in transaction_storage or "const msconnector_response *" in transaction_storage:
    fail("common runtime transaction must not retain host-owned request/response pointers")
legacy_body_progress = (
    "request_body_bytes_seen" in runtime_source and
    "response_body_bytes_seen" in runtime_source and
    "request_body_limit_outcome" in runtime_source and
    "response_body_limit_outcome" in runtime_source and
    "response_body_finished" in runtime_source
)
grouped_body_progress = (
    "msconnector_runtime_body_progress request_body;" in transaction_storage and
    "msconnector_runtime_body_progress response_body;" in transaction_storage and
    "bytes_seen" in runtime_header and
    "bytes_inspected" in runtime_header and
    "limit_outcome" in runtime_header and
    "finished" in runtime_header
)
if not (legacy_body_progress or grouped_body_progress):
    fail("common runtime must track chunk progress, native limit outcomes and explicit EOS state")
for retired in ("apply_body_limit_plan", "msconnector_body_limit_plan_chunk",
                "MSCONNECTOR_BODY_LIMIT_ACTION_REJECT",
                "MSCONNECTOR_BODY_LIMIT_ACTION_PROCESS_PARTIAL"):
    if retired in runtime_source + body_policy_header + body_policy_source:
        fail(f"common must not select a connector body-limit policy: {retired}")
for retired in ("request_body_limit;", "response_body_limit;", "body_limit_action;"):
    if retired in config_header:
        fail(f"common config retains removed connector policy {retired}")
if ("pending_request_decision" not in runtime_source or
        "request_decision_pending" not in runtime_source):
    fail("common must retain native request append intervention through EOS")
if ("late_intervention_timeout" not in runtime_source or
        "phase4_event_log" not in runtime_source or
        "late_intervention_timeout_ms" not in runtime_header or
        "late_intervention_timeout_ms" not in config_header or
        "merge_late_intervention_timeout" not in config_source):
    fail("common runtime must carry late-intervention timeout and event configuration")
if '".."' not in harness_source or '../*' not in harness_source or '*/..' not in harness_source or '*\\\\..' not in harness_source:
    fail("common-harness must reject terminal parent-directory artifact segments")
if "validate_phase_callbacks" not in adapter_contract_source or "MSCONNECTOR_CAPABILITY_REQUEST_HEADERS" not in adapter_contract_source or "process_response_body" not in adapter_contract_source:
    fail("adapter contract must compare advertised phase capabilities with callbacks")
if "static char" in rule_event_source or "rule_event_reason" in rule_event_source:
    fail("rule_event must not use static mutable reason storage")
if "msconnector_rule_load_event_ex" not in rule_event_source or "reason_buffer" not in rule_event_source:
    fail("rule_event must require caller-owned reason storage")
rule_event_header = (source_path('common/include/msconnector/rule_event.h', root=ROOT)).read_text(encoding="utf-8")
if "msconnector_rule_load_event(const msconnector_rule_load_stats *stats, const msconnector_event *event" not in rule_event_header:
    fail("legacy rule_load_event wrapper must take a const event pointer")
if "msconnector_rule_load_event(const msconnector_rule_load_stats *stats, const msconnector_event *event" not in rule_event_source:
    fail("legacy rule_load_event implementation must take a const event pointer")
if '#include "msconnector/decision.h"' not in transaction_header:
    fail("transaction.h must preserve compatibility with msconnector_decision declarations")
if transaction_header.find('#include "msconnector/decision.h"') > transaction_header.find("#ifdef __cplusplus"):
    fail("transaction.h must keep decision.h in the top include block")
if "Compatibility: starter headers" in transaction_header:
    fail("transaction.h must not keep a late compatibility include")
if not (source_path('common/include/msconnector/phase.h', root=ROOT)).is_file():
    fail("phase.h must provide shared phase declarations for transaction/decision include order")
if '#include "msconnector/phase.h"' not in decision_header:
    fail("decision.h must include phase.h instead of depending on transaction.h")
if '#include "msconnector/transaction.h"' in decision_header:
    fail("decision.h must not include transaction.h")
if "MSCONNECTOR_ERROR_NONE" not in error_source or "error == 0" not in error_source or SUCCESS_RETURN_LITERAL not in error_source:
    fail("error_to_event must handle MSCONNECTOR_ERROR_NONE without emitting an error event")

transaction_source = (source_path('common/src/transaction.c', root=ROOT)).read_text(encoding="utf-8")
request_helpers_header = (source_path('common/include/msconnector/request_helpers.h', root=ROOT)).read_text(encoding="utf-8")
response_helpers_header = (source_path('common/include/msconnector/response_helpers.h', root=ROOT)).read_text(encoding="utf-8")
request_helpers_source = (source_path('common/src/request_helpers.c', root=ROOT)).read_text(encoding="utf-8")
response_helpers_source = (source_path('common/src/response_helpers.c', root=ROOT)).read_text(encoding="utf-8")
if "msconnector_decision_allow" not in transaction_source or "msconnector_decision_block" not in transaction_source:
    fail("transaction.c must keep decision compatibility constructors linkable for starter builds")
if "msconnector_decision_allow" in decision_source or "msconnector_decision_block" in decision_source:
    fail("decision compatibility constructors must not require linking decision.c for starter builds")
if "msconnector_headers_find_value_slice" not in headers_source or "msconnector_headers_copy_value" not in headers_source:
    fail("headers helpers must expose bounded value slice/copy APIs for pointer+length header values")
if "msconnector_request_content_type_slice" not in request_helpers_header or "msconnector_headers_find_value_slice" not in request_helpers_source:
    fail("request content-type helper must expose bounded header value slices")
if "msconnector_response_content_type_slice" not in response_helpers_header or "msconnector_headers_find_value_slice" not in response_helpers_source:
    fail("response content-type helper must expose bounded header value slices")
remote_pair_index = rule_loader_source.find("incomplete remote rules pair")
inline_load_index = rule_loader_source.find("rules_inline")
if remote_pair_index == -1 or inline_load_index == -1 or remote_pair_index > inline_load_index:
    fail("rule_loader_load_config must validate remote key/url pairing before inline/file mutations")
if "bounded_cstr_len" not in transaction_id_source or "memset(out->value" not in transaction_id_source:
    fail("transaction ID expression callback results must be bounded before validation")

# Current PR 27 review hardening checks.
json_escape_source = (source_path('common/src/json_escape.c', root=ROOT)).read_text(encoding="utf-8")
if "append_json_bytes" not in json_escape_source or "*position + value_size < dst_size" not in json_escape_source:
    fail("json_escape must avoid writing partial JSON escape sequences")
if "terminate_at_current" not in json_escape_source:
    fail("json_escape must terminate safely when an escape sequence does not fit")
if "tx->native_transaction = 0" not in engine_source:
    fail("modsecurity transaction cleanup must clear native_transaction even without a free callback")
if "response_phase" not in decision_source or "MSCONN_EVENT_RESPONSE_BLOCKED" not in decision_source or "MSCONN_EVENT_REQUEST_BLOCKED" not in decision_source:
    fail("decision_to_event must choose blocked event IDs from decision phase")
if "remote_pair_requested" not in rule_loader_source or "remote_pair_complete" not in rule_loader_source or "empty(config->rules_remote_key)" not in rule_loader_source:
    fail("rule_loader_load_config must reject empty incomplete remote rule fields before mutation")
if "msconnector_harness_has_parent_segment" not in harness_source or "if msconnector_harness_has_parent_segment" not in harness_source:
    fail("common-harness under-root checks must reject parent traversal before prefix acceptance")
request_hpp = (source_path('common/include/msconnector/request.hpp', root=ROOT)).read_text(encoding="utf-8")
for alias in ("using Bytes = msconnector_bytes", "using Header = msconnector_header", "using Endpoint = msconnector_endpoint", "using Request = msconnector_request"):
    if alias not in request_hpp:
        fail("request.hpp must preserve C++ wrapper aliases")
for unsafe_getter in (
    "msconnector_headers_find_value(",
    "msconnector_headers_host(",
    "msconnector_request_header_value(",
    "msconnector_request_content_type(",
    "msconnector_response_header_value(",
    "msconnector_response_content_type(",
):
    if unsafe_getter in headers_source + request_helpers_source + response_helpers_source + request_helpers_header + response_helpers_header:
        fail("raw header getters must not expose pointer+length slices as C strings")

# PR 29 review hardening checks.
late_intervention_source = (source_path('common/src/late_intervention.c', root=ROOT)).read_text(encoding="utf-8")
transaction_source = (source_path('common/src/transaction.c', root=ROOT)).read_text(encoding="utf-8")
if "ch > 126U" not in transaction_id_source:
    fail("transaction ID validation must reject non-ASCII bytes above 126")
if "remote_pair_requested" not in config_source or "remote_pair_complete" not in config_source or "string_empty(config->rules_remote_key)" not in config_source:
    fail("config validation must reject empty remote rule key/url mismatches")
if "if (response_headers_committed || response_body_started)" not in late_intervention_source or "if (strict_mode)" not in late_intervention_source:
    fail("strict late intervention must be gated on response output having begun")
if "kind_from_status" not in transaction_source or "MSCONNECTOR_STATUS_BLOCKED" not in transaction_source or "MSCONNECTOR_DECISION_KIND_ERROR" not in transaction_source:
    fail("compatibility decision constructors must preserve blocked/error status kinds")
if '{302, "Found", "Redirect response", MSCONNECTOR_HTTP_STATUS_CLASS_REDIRECTION, 0}' not in http_status_source:
    fail("HTTP status metadata must include non-blocking 302 Found")

print("common-sdk-contract: pass")
