#!/usr/bin/env python3
"""Verify live Common SDK adoption by Envoy, Traefik and lighttpd."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import re
import sys
from pathlib import Path


ROOT = connector_root()
CONNECTORS = ("envoy", "traefik", "lighttpd")
ALLOWED_EVIDENCE_STATUS = {
    "not_verified",
    "connector-gap",
    "compile_verified",
    "link_verified",
    "config_load_verified",
    "start_smoke_verified",
    "minimal_runtime_smoke",
    "partial_runtime_path",
    "requires_runtime_evidence",
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def mapper_checks(connector: str, base: Path, errors: list[str]) -> None:
    mapper_header = base / "src" / f"{connector}_modsecurity_mapper.h"
    mapper_source = base / "src" / f"{connector}_modsecurity_mapper.c"
    header_text = read(mapper_header)
    source_text = read(mapper_source)
    require(errors, mapper_header.is_file(), f"{connector}: mapper header missing")
    require(errors, mapper_source.is_file(), f"{connector}: mapper source missing")
    require(
        errors,
        "msconnector_generic_map_request" in source_text,
        f"{connector}: request mapper does not call Common generic mapper",
    )
    require(
        errors,
        "msconnector_generic_map_response" in source_text,
        f"{connector}: response mapper does not call Common generic mapper",
    )
    require(
        errors,
        "msconnector_generic_config_init" in source_text + header_text,
        f"{connector}: config is not initialized through Common",
    )


def configuration_checks(connector: str, base: Path, errors: list[str]) -> None:

    config_dir = base / "config"
    configs = list(config_dir.glob("*.conf")) if config_dir.is_dir() else []
    require(errors, bool(configs), f"{connector}: connector runtime config missing")
    config_text = "\n".join(read(path) for path in configs)
    for key in (
        "enabled=",
        "rules_file=",
        "transaction_id_header=",
        "request_body_mode=",
        "response_body_mode=",
        "default_block_status=",
        "default_error_status=",
        "event_path=",
        "max_header_count=",
        "max_total_header_bytes=",
    ):
        require(errors, key in config_text, f"{connector}: config does not map {key[:-1]}")


def evidence_metadata_checks(connector: str, base: Path, errors: list[str]) -> None:

    metadata = read(base / "metadata.c")
    require(
        errors,
        '"connector-gap"' in metadata or '"partial_runtime_path"' in metadata,
        f"{connector}: connector-gap or partial-runtime boundary missing",
    )
    require(
        errors,
        any(f'"{status}"' in metadata for status in ALLOWED_EVIDENCE_STATUS),
        f"{connector}: metadata has no allowed evidence status",
    )
    source_map = read(base / "SOURCE_MAP.json")
    require(
        errors,
        any(status in source_map for status in ALLOWED_EVIDENCE_STATUS),
        f"{connector}: SOURCE_MAP has no allowed evidence status",
    )


def generic_source_contract_checks(connector: str, base: Path, errors: list[str]) -> None:

    tree_text = "\n".join(
        read(path)
        for path in base.rglob("*")
        if path.is_file() and path.suffix.lower() in {".c", ".h", ".md", ".json", ".sh", ".py"}
    )
    forbidden_positive_claims = (
        r'production_ready[" ]*[:=][" ]*true',
        r'full_matrix_ready[" ]*[:=][" ]*true',
        r'crs_complete[" ]*[:=][" ]*true',
        r'response_body_verified[" ]*[:=][" ]*true',
        r'security_verified[" ]*[:=][" ]*true',
    )
    for pattern in forbidden_positive_claims:
        require(
            errors,
            re.search(pattern, tree_text, flags=re.IGNORECASE) is None,
            f"{connector}: forbidden positive claim matches {pattern}",
        )
    require(
        errors,
        "free((void *)" not in tree_text,
        f"{connector}: const-dropping ownership cleanup found",
    )


def connector_specific_checks(connector: str, base: Path, errors: list[str]) -> None:

    if connector == "envoy":
        host = read(base / "src" / "envoy_ext_authz_service_main.c")
        runtime = read(base / "harness" / "run_envoy_connector_runtime.sh")
        require(errors, '"ext_authz"' in host, "envoy: ext_authz profile missing")
        require(
            errors,
            "msconnector_http_authorization_service_main" in host,
            "envoy: connector-owned authorization service missing",
        )
        require(errors, "ENVOY_BIN" in runtime and "403" in runtime, "envoy: real host runtime smoke missing")
    elif connector == "traefik":
        host = read(base / "src" / "traefik_forwardauth_service_main.c")
        runtime = read(base / "scripts" / "runtime-smoke.sh") + read(base / "scripts" / "runtime_smoke.py")
        require(errors, '"forwardAuth"' in host, "traefik: forwardAuth profile missing")
        require(
            errors,
            "msconnector_http_authorization_service_main" in host,
            "traefik: connector-owned authorization service missing",
        )
        require(errors, "TRAEFIK_BIN" in runtime and "403" in runtime, "traefik: real host runtime smoke missing")
    else:
        module = read(base / "module" / "mod_msconnector.c")
        for token in (
            "mod_msconnector_plugin_init",
            "handle_uri_clean",
            "handle_response_start",
            "handle_request_reset",
            "config_plugin_values_init",
            "msconnector_runtime_transaction_begin",
            "msconnector_runtime_transaction_process_response_headers",
            "msconnector_runtime_transaction_finish",
        ):
            require(errors, token in module, f"lighttpd: native module missing {token}")
        # The Framework-version-synchronized patched core supplies borrowed HTTP/1.x entity ranges at
        # http_chunk append time, before transfer framing or socket writes.
        # It is therefore a real incremental-ingest path, but Strict remains
        # non-promotable until a real client proves the post-commit abort.
        core_patch = read(base / "patches" / "0001-lighttpd-msconnector-stream-hooks.patch")
        require(
            errors,
            "mod_msconnector_handle_response_body" in module,
            "lighttpd: patched response-body hook is not registered",
        )
        require(
            errors,
            "msconnector_runtime_transaction_append_response_body_chunk" in module and
            "msconnector_runtime_transaction_finish_response_body" in module and
            "msconnector_runtime_transaction_set_response_commit_state" in module,
            "lighttpd: entity-body hook does not expose the explicit Common P4 lifecycle",
        )
        require(
            errors,
            "http_chunk_msconnector_entity_body" in core_patch and
            "http_chunk_msconnector_entity_close" in core_patch and
            "--- a/src/connections.c" not in core_patch and
            "network_write" not in core_patch,
            "lighttpd: response callback is not pinned to entity-before-wire rather than socket-write ranges",
        )
        require(
            errors,
            "resp_body_entity_hook_eos_sent" in core_patch and
            "response_body_next_offset" in module and
            "no synthetic Phase-4 finalization" in module,
            "lighttpd: entity EOS or disconnect cleanup is not once-only",
        )
        require(
            errors,
            "msconnector_late_intervention_resolve" in module and
            "msconnector_runtime_phase4_mode" in module and
            "strict Phase-4 intervention is NOT EXECUTED" in module and
            "MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION" not in module,
            "lighttpd: strict P4 must remain non-promoted without a client-visible abort",
        )


def connector_checks(connector: str, errors: list[str]) -> None:
    base = source_path('connectors', root=ROOT) / connector
    mapper_checks(connector, base, errors)
    configuration_checks(connector, base, errors)
    evidence_metadata_checks(connector, base, errors)
    generic_source_contract_checks(connector, base, errors)
    connector_specific_checks(connector, base, errors)


def shared_runtime_checks(errors: list[str]) -> None:
    runtime = read(source_path('common/runtime/msconnector_runtime.c', root=ROOT))
    service = read(source_path('common/runtime/http_authorization_service.c', root=ROOT))
    for token in (
        "msconnector_config_init",
        "msconnector_config_apply_defaults",
        "msconnector_config_validate",
        "msconnector_parse_bool",
        "msconnector_directive_adapter_validate_all",
        "msconnector_rule_loader_load_config",
        "msconnector_modsecurity_engine_start",
        "msconnector_modsecurity_transaction_init",
        "msconnector_transaction_id_resolve",
        "msconnector_decision_action_from_decision",
        "msconnector_event_write_jsonl_line",
        "msconnector_resource_limits_init",
        "msconnector_dos_guard_check_request",
        "msconnector_flow_guard_mark_validated",
        "msconnector_integrity_event_hash",
        "msconnector_alloc_checked",
    ):
        require(errors, token in runtime, f"shared remaining-connector runtime missing {token}")
    for invariant in (
        "header_count > 0U",
        "request->body.size > 0U",
    ):
        require(errors, invariant in runtime + service, f"shared runtime missing invariant {invariant}")
    require(errors, "body_payload" not in runtime, "shared event path exposes a body payload field")
    require(errors, "request_body_payload" not in runtime, "shared event path exposes request body payload")
    require(errors, "response_body_payload" not in runtime, "shared event path exposes response body payload")
    for retired in (
        "msconnector_runtime_request_body_limit(",
        "runtime->config.request_body_limit",
        "runtime->config.body_limit_action",
        "msconnector_runtime_body_limit_action(",
        "apply_body_limit_plan",
    ):
        require(errors, retired not in runtime, f"shared runtime retains connector policy {retired}")
    require(
        errors,
        "msconnector_runtime_transaction_begin_request_stream" in service,
        "authorization service must stream body input before native P2 completion",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector", choices=CONNECTORS)
    args = parser.parse_args()
    errors: list[str] = []
    shared_runtime_checks(errors)
    selected = (args.connector,) if args.connector else CONNECTORS
    for connector in selected:
        connector_checks(connector, errors)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    label = args.connector or "all"
    print(f"remaining connector common adoption: ok ({label})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
