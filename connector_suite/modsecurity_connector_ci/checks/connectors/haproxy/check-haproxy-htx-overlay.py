#!/usr/bin/env python3
"""Static contract checks for the version-pinned HAProxy HTX overlay.

The overlay is intentionally optional until a host runtime verifies it.  These
checks prevent an apparently incremental implementation from regressing back
to a buffered SPOE sample or from evaluating Phase 4 before HTTP EOS.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
from pathlib import Path
import re
import sys


ROOT = connector_root()
OVERLAY = source_path('connectors/haproxy/htx-overlay', root=ROOT)
SOURCE = OVERLAY / "haproxy_modsecurity_htx_filter.c"
CONTRACT = OVERLAY / "version-contract.json"
BUILD = OVERLAY / "build-overlay.sh"
BINDING = source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)
BINDING_HEADER = source_path('connectors/haproxy/src/haproxy_modsecurity_binding.h', root=ROOT)
HTX_HELPER = source_path('connectors/haproxy/harness/haproxy_htx_smoke_helper.py', root=ROOT)
HTX_RUNTIME = source_path('connectors/haproxy/harness/run_haproxy_htx_runtime.sh', root=ROOT)


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    open_brace = text.index("{", start)
    depth = 0
    for position in range(open_brace, len(text)):
        if text[position] == "{":
            depth += 1
        elif text[position] == "}":
            depth -= 1
            if depth == 0:
                return text[start : position + 1]
    raise ValueError(f"unterminated function: {signature}")


def overlay_function_bodies(source: str) -> dict[str, str]:
    # Keep the body names explicit: lifecycle_checks() consumes this exact
    # set, and a duplicate dictionary key would silently discard one entry.
    body_specs = (
        ("headers", "static int haproxy_modsecurity_htx_filter_http_headers("),
        ("request_headers", "static int haproxy_modsecurity_htx_handle_request_headers("),
        ("request_callback", "static int haproxy_modsecurity_htx_filter_request_payload("),
        ("request_append", "static int haproxy_modsecurity_htx_append_request_payload("),
        ("response_callback", "static int haproxy_modsecurity_htx_filter_response_payload("),
        ("response_append", "static int haproxy_modsecurity_htx_append_response_payload("),
        ("response_end", "static int haproxy_modsecurity_htx_finish_response("),
        ("precommit_deny", "static int haproxy_modsecurity_htx_apply_precommit_deny("),
        ("precommit_redirect", "static int haproxy_modsecurity_htx_apply_precommit_redirect("),
        ("precommit_decision", "static int haproxy_modsecurity_htx_apply_precommit_decision("),
        ("precommit_action", "static int haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed("),
        ("request_begin", "static int haproxy_modsecurity_htx_begin_request("),
        ("response_headers", "static int haproxy_modsecurity_htx_process_response_headers("),
        ("request_end", "static int haproxy_modsecurity_htx_finish_request("),
    )
    return {name: function_body(source, signature) for name, signature in body_specs}


def load_contract() -> tuple[str, Path]:
    payload = json.loads(CONTRACT.read_text(encoding="utf-8"))
    version = payload.get("version") if isinstance(payload, dict) else None
    patch_name = payload.get("makefile_patch") if isinstance(payload, dict) else None
    source_url = payload.get("source_url") if isinstance(payload, dict) else None
    sha256 = payload.get("sha256") if isinstance(payload, dict) else None
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("invalid HAProxy HTX version contract")
    if not isinstance(patch_name, str) or not re.fullmatch(r"[A-Za-z0-9._-]+\.patch", patch_name):
        raise ValueError("invalid HAProxy HTX patch contract")
    series = ".".join(version.split(".")[:2])
    if source_url != f"https://www.haproxy.org/download/{series}/src/haproxy-{version}.tar.gz":
        raise ValueError("invalid HAProxy HTX source URL contract")
    if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise ValueError("invalid HAProxy HTX SHA-256 contract")
    return version, OVERLAY / patch_name


def runtime_selection_checks(source: str, helper: str, runtime: str, bodies: dict[str, str]) -> list[tuple[bool, str]]:
    precommit_deny = bodies["precommit_deny"]
    precommit_redirect = bodies["precommit_redirect"]
    precommit_decision = bodies["precommit_decision"]
    precommit_action = bodies["precommit_action"]
    request_begin = bodies["request_begin"]
    response_headers = bodies["response_headers"]
    response_append = bodies["response_append"]
    response_callback = bodies["response_callback"]
    return [
        ("haproxy_modsecurity_htx_filter_http_payload" in source and "haproxy_modsecurity_htx_filter_http_end" in source, "HAProxy HTX filter exposes http_payload and http_end hooks"),
        ("CANONICAL_RULES_PATH" in helper and all(f"id:{rule_id}" in helper for rule_id in (1100001, 1100002, 1100201)) and all(f"id:{rule_id}" not in helper and f"id:{rule_id}" not in runtime for rule_id in (910001, 910002, 910003, 910004)), "HTX runtime selects canonical No-CRS rule IDs instead of temporary 91000x probes"),
        ("HAPROXY_HTX_CANONICAL_RULES_FILE" in runtime and "phase1_403" in runtime and "phase1_429" in runtime and "phase3_403" in runtime and "enforced_reply" in runtime and "forwarded)" in runtime and "only the explicit allow control may be forwarded" in runtime and "capability_promotion=not_permitted" in runtime, "runtime permits forwarding only for the explicit allow control while keeping real P1/P3 host replies explicit"),
        ("phase2_client_deny" in runtime and "0-or-1" in runtime and "phase2_upstream_request_count=%s" in runtime and "phase2_request_dispatch_observed=%s" in runtime and "phase2_incremental_forwarding_claimed=false" in runtime and "phase2_host_action=enforced_reply" in runtime, "runtime records either observed P2 dispatch outcome without claiming incremental forwarding"),
        ("phase4_safe_host_action=log_only" in runtime and "resolved_policy_action=log_only host_action=log_only" in runtime and '"$SYNCHRONIZED_UPSTREAM" --serve' in runtime and '--control-root "$case_root"' in runtime and "safe_log_only" in helper and "host_action = action == MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY" in source, "runtime distinguishes the safe P4 log-only outcome from an unattempted Strict abort and gives its upstream a trusted control root"),
        ("#include <haproxy/http_ana.h>" in source and "#include \"msconnector/block_statuses.h\"" in source, "overlay imports HAProxy's normal HTTP-reply API and shared block-status policy"),
        ("strcmp(decision->action, \"deny\")" in precommit_deny and "strcmp(decision->action, \"redirect\")" not in precommit_deny and "msconnector_block_status_is_allowed(decision->status)" in precommit_deny and "msconnector_block_status_normalize(decision->status)" in precommit_deny, "precommit host action accepts only validated deny interventions"),
        ("s->txn->status = (short)status;" in precommit_deny and "http_set_term_flags(s);" in precommit_deny and "http_reply_and_close(s, (short)status, http_error_message(s));" in precommit_deny and "http_reply_and_close(s, (short)status, NULL)" not in precommit_deny, "precommit deny uses HAProxy's concrete error-reply path, never the NULL-reply truncation path"),
        ("haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed(s, ctx," in request_begin and "haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed(s, ctx," in response_headers and "haproxy_modsecurity_htx_apply_precommit_decision(s, ctx, decision)" in precommit_action and "haproxy_modsecurity_htx_apply_precommit_deny(s, ctx, decision)" in precommit_decision, "both Phase 1 and pre-forward Phase 3 route deny through the validated dispatcher"),
        ("haproxy_modsecurity_redirect_url_length" in precommit_redirect and "rule.type = REDIRECT_TYPE_LOCATION;" in precommit_redirect and "rule.rdr_str = location;" in precommit_redirect and "http_apply_redirect_rule(&rule, s, s->txn) == 1" in precommit_redirect and precommit_redirect.index("haproxy_modsecurity_htx_finish_context(ctx)") < precommit_redirect.index("ctx->lifecycle.disabled = 1;") < precommit_redirect.index("http_apply_redirect_rule("), "precommit redirect uses a bounded literal Location after native finish and reentry suppression"),
        ("HTX_BLK_DATA" in source and "htx_find_offset" in source and "htx_get_blk_value" in source, "response hook walks current HTX DATA slices instead of materializing a body"),
        ("haproxy_modsecurity_transaction_append_response_body_chunk" in response_append and "return (int)len;" in response_callback, "response payload forwards borrowed chunks and never holds HAProxy output"),
    ]


def lifecycle_checks(source: str, binding: str, binding_header: str, bodies: dict[str, str]) -> list[tuple[bool, str]]:
    headers = bodies["headers"]
    request_headers = bodies["request_headers"]
    request_callback = bodies["request_callback"]
    request_append = bodies["request_append"]
    request_end = bodies["request_end"]
    response_end = bodies["response_end"]
    return [
        ("haproxy_modsecurity_transaction_begin_request" in binding_header and "haproxy_modsecurity_transaction_append_request_body_chunk" in binding_header and "haproxy_modsecurity_transaction_finish_request_body" in binding_header and "int haproxy_modsecurity_transaction_begin_request(" in binding and "int haproxy_modsecurity_transaction_append_request_body_chunk(" in binding and "int haproxy_modsecurity_transaction_finish_request_body(" in binding, "binding exposes an explicit Phase-1/request-chunk/request-EOS lifecycle"),
        (
            "return haproxy_modsecurity_htx_handle_request_headers(s, filter, msg);" in headers
            and "haproxy_modsecurity_htx_begin_request(s, filter)" in request_headers
            and request_headers.index("haproxy_modsecurity_htx_begin_request(s, filter)")
            < request_headers.rindex("register_data_filter(s, msg->chn, filter);"),
            "request headers dispatch to the current handler, which starts the per-stream transaction before payload forwarding",
        ),
        ("haproxy_modsecurity_transaction_append_request_body_chunk" in request_append and "return (int)len;" in request_callback, "request payload forwards borrowed chunks without a connector-owned body buffer"),
        (
            "if (ctx->request.finished)" in request_end
            and "ctx->request.finished = 1;" in request_end
            and "haproxy_modsecurity_transaction_finish_request_body" in request_end
            and request_end.index("if (ctx->request.finished)")
            < request_end.index("ctx->request.finished = 1;")
            < request_end.index("haproxy_modsecurity_transaction_finish_request_body"),
            "request Phase 2 finalization is guarded before the sole request EOS call",
        ),
        (source.count("haproxy_modsecurity_transaction_finish_request_body(") == 1, "source has one binding finish_request_body callsite"),
        (
            "haproxy_modsecurity_htx_report_decision(\"request-body\"" in request_end
            and "if (!ctx->response.headers_seen)" in request_end
            and "haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed(" in request_end
            and request_end.index("if (!ctx->response.headers_seen)")
            < request_end.index("haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed(")
            and "haproxy_modsecurity_htx_fail_closed_postcommit(" in request_end,
            "request EOS can use the native reply path only before this filter sees response headers",
        ),
        ("zero-or-one" in source and "incremental-request-forwarding evidence" in source, "P2 source contract records scheduler-dependent dispatch without an incremental-forwarding claim"),
        (
            "if (ctx->response.finished)" in response_end
            and "ctx->response.finished = 1;" in response_end
            and "haproxy_modsecurity_transaction_finish_response_body" in response_end
            and response_end.index("if (ctx->response.finished)")
            < response_end.index("ctx->response.finished = 1;")
            < response_end.index("haproxy_modsecurity_transaction_finish_response_body"),
            "response Phase 4 finalization is guarded before the sole EOS call",
        ),
        (source.count("haproxy_modsecurity_transaction_finish_response_body(") == 1, "source has one binding finish_response_body callsite"),
        ("msconnector_late_intervention_policy_init" in source and "msconnector_late_intervention_resolve" in source and "msconnector_late_intervention_action_name" in source and "resolved_policy_action" in source, "post-commit Phase 4 outcomes use the shared late-intervention policy"),
        (all(token not in source for token in ("bodyless", "request_advertises_body", "request_body_bytes", "wait-for-body", "res.body", "chunk_memcat")), "overlay has no bodyless-request bypass or connector-owned response buffer"),
        ("register_data_filter" in source and "unregister_data_filter" in source, "overlay registers only the active HAProxy data callbacks"),
    ]


def build_contract_checks(makefile_patch: str, build: str, version: str) -> list[tuple[bool, str]]:
    return [
        (
            '"$version" = "$HAPROXY_VERSION"' in build
            and "HAPROXY_VERSION=$(contract_field version)" in build
            and "haproxy_modsecurity_htx_filter.c" in build
            and "version-contract.json" in build
            and "USE_OPENSSL=1" in build,
            f"build script follows the HAProxy HTX contract version {version}, stages a separate worktree, and enables the harness TLS listener",
        ),
        ("canonical_path()" in build and "HAPROXY_HTX_BUILD_DIR must be outside the verified source tree" in build and '"$SOURCE_DIR"/*' in build and "patch --dry-run -p1" in build, "build script rejects source-tree output and validates the disposable patch"),
        ("common/src/header_validation_internal.h" in build and '"$WORKTREE/src/header_validation_internal.h"' in build, "build script stages the Common private header required by copied request/response helpers"),
        ("connectors/profile_registry.c" in build and "connectors/profile_registry.h" in build and '"$WORKTREE/src/msconnector_profile_registry.c"' in build and '"$WORKTREE/src/connectors/profile_registry.h"' in build and "-I$WORKTREE/src/connectors" in build, "build script stages the connector profile registry with the include path required by the copied binding"),
        ("haproxy_modsecurity_htx_filter.o" in makefile_patch and "haproxy_modsecurity_binding.o" in makefile_patch and "msconnector_profile_registry.o" in makefile_patch, "source-linked Makefile patch includes the HTX filter, binding, and profile registry"),
    ]


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    version, patch = load_contract()
    makefile_patch = patch.read_text(encoding="utf-8")
    build = BUILD.read_text(encoding="utf-8")
    binding = BINDING.read_text(encoding="utf-8")
    binding_header = BINDING_HEADER.read_text(encoding="utf-8")
    helper = HTX_HELPER.read_text(encoding="utf-8")
    runtime = HTX_RUNTIME.read_text(encoding="utf-8")
    bodies = overlay_function_bodies(source)
    checks = (
        runtime_selection_checks(source, helper, runtime, bodies)
        + lifecycle_checks(source, binding, binding_header, bodies)
        + build_contract_checks(makefile_patch, build, version)
    )
    ok = True
    for condition, message in checks:
        print(f"{'PASS' if condition else 'FAIL'}: {message}")
        ok = ok and condition
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
