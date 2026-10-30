"""Mutation coverage for NGINX's helper-aware Common-adoption checker."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
CHECKER = source_path('ci/checks/connectors/nginx/check-nginx-common-adoption.py', root=ROOT)
NGINX = source_path('connectors/nginx', root=ROOT)
CHAIN_APPEND_ANCHOR = "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,"
RULE_ID_CONTRACT_MESSAGE = (
    "NGINX rule-id extraction delegates only to bounded Common parsing before intervention sinks"
)
RULE_ID_SIGNATURE = "static void\nngx_http_modsecurity_extract_intervention_rule_id"
RULE_ID_CALL = "ngx_http_modsecurity_extract_intervention_rule_id(ctx, &intervention);"
INTERVENTION_SIGNATURE = "int\nngx_http_modsecurity_process_intervention"
BODY_LIMIT_CONTRACT_MESSAGE = (
    "NGINX records response-body bytes with checked full-chunk accounting before append"
)
CHAIN_CALL_CONTRACT_MESSAGE = (
    "NGINX response-body chain loop directly calls the reviewed bounded wrapper"
)
CHAIN_ERROR_RETURN = (
    "        if (ret != NGX_OK) {\n"
    "            return ngx_http_modsecurity_phase4_fail_control(r, mcf, ctx,\n"
    "                MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);\n"
    "        }\n"
)
PHASE4_ERROR_HEADER = "ngx_http_modsecurity_phase4_error.h"
SOURCES = (
    "ngx_http_modsecurity_common.h",
    "ngx_http_modsecurity_event_uri.h",
    "ngx_http_modsecurity_engine_call_budget.h",
    "ngx_http_modsecurity_request_completion.h",
    "ngx_http_modsecurity_response_body_limit.h",
    "ngx_http_modsecurity_cleanup_observation.h",
    "ngx_http_modsecurity_phase4_observation.h",
    PHASE4_ERROR_HEADER,
    "ngx_http_modsecurity_module.c",
    "ngx_http_modsecurity_mapper.h",
    "ngx_http_modsecurity_mapper.c",
    "ngx_http_modsecurity_body_filter.c",
    "ngx_http_modsecurity_access.c",
    "ngx_http_modsecurity_header_filter.c",
    "ngx_http_modsecurity_log.c",
    "ddebug.h",
)


def function_bounds(source: str, signature: str) -> tuple[int, int]:
    """Return exactly one synthetic function definition's source bounds."""
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for position in range(opening, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return start, position + 1
    raise AssertionError(f"unbalanced synthetic function: {signature}")


def replace_in_function(
    path: Path, signature: str, old: str, new: str
) -> None:
    """Replace one source fragment in the selected synthetic function."""
    source = path.read_text(encoding="utf-8")
    start, end = function_bounds(source, signature)
    original = source[start:end]
    if original.count(old) != 1:
        raise AssertionError(f"expected one mutable fragment in {path}: {old!r}")
    path.write_text(
        source[:start] + original.replace(old, new, 1) + source[end:],
        encoding="utf-8",
    )


def replace_all_in_function(
    path: Path, signature: str, old: str, new: str, expected_count: int
) -> None:
    """Replace every expected instance of a fragment in one function."""
    source = path.read_text(encoding="utf-8")
    start, end = function_bounds(source, signature)
    original = source[start:end]
    if original.count(old) != expected_count:
        raise AssertionError(
            f"expected {expected_count} mutable fragments in {path}: {old!r}"
        )
    path.write_text(
        source[:start] + original.replace(old, new) + source[end:],
        encoding="utf-8",
    )


def insert_before_signature(path: Path, signature: str, directive: str) -> None:
    """Insert one preprocessing directive immediately before a C definition."""
    source = path.read_text(encoding="utf-8")
    start = source.index(signature)
    path.write_text(
        source[:start] + directive + "\n" + source[start:], encoding="utf-8"
    )


def prepend_directive(path: Path, directive: str) -> None:
    """Add one preprocessing directive before a local included header's guard."""
    source = path.read_text(encoding="utf-8")
    path.write_text(directive + "\n" + source, encoding="utf-8")


def inject_inactive_decoy(
    path: Path,
    signature: str,
    old: str,
    new: str,
    opening: str = "#if 0\n",
    closing: str = "#endif\n",
) -> None:
    """Hide a safe twin in an inactive branch while corrupting the live one."""
    source = path.read_text(encoding="utf-8")
    start, end = function_bounds(source, signature)
    original = source[start:end]
    if original.count(old) != 1:
        raise AssertionError(f"expected one mutable fragment in {path}: {old!r}")
    malformed = original.replace(old, new, 1)
    path.write_text(
        source[:start] + opening + original + "\n" + closing + malformed + source[end:],
        encoding="utf-8",
    )


def inject_outer_guard_else_decoy(
    path: Path, signature: str, old: str, new: str
) -> None:
    """Put a safe twin in the outer include guard's inactive else branch."""
    source = path.read_text(encoding="utf-8")
    start, end = function_bounds(source, signature)
    original = source[start:end]
    if original.count(old) != 1:
        raise AssertionError(f"expected one mutable fragment in {path}: {old!r}")
    terminal_endif = source.rfind("#endif")
    if terminal_endif < end:
        raise AssertionError(f"expected outer include guard in {path}")
    malformed = original.replace(old, new, 1)
    path.write_text(
        source[:start]
        + malformed
        + source[end:terminal_endif]
        + "#else\n"
        + original
        + "\n"
        + source[terminal_endif:],
        encoding="utf-8",
    )


class NginxCommonAdoptionCheckerTests(unittest.TestCase):
    """Exercise semantic contracts against isolated inactive-branch decoys."""

    def _copy_repository(self, destination: Path) -> Path:
        (destination / "Makefile").write_text(
            "# synthetic checker repository\n", encoding="utf-8"
        )
        checker = destination / "ci" / "checks" / "connectors" / "nginx" / CHECKER.name
        checker.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CHECKER, checker)
        source_directory = destination / "connectors" / "nginx" / "src"
        source_directory.mkdir(parents=True, exist_ok=True)
        for name in SOURCES:
            shutil.copy2(NGINX / "src" / name, source_directory / name)
        shutil.copy2(
            source_path('connectors/profile_registry.h', root=ROOT),
            destination / "connectors" / "profile_registry.h",
        )
        shutil.copytree(
            source_path('common/include', root=ROOT), destination / "common" / "include"
        )
        shutil.copy2(NGINX / "config", destination / "connectors" / "nginx" / "config")
        return destination

    def _run_checker(self, mutate=None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="nginx-common-adoption-") as temporary:
            repository = self._copy_repository(Path(temporary))
            if mutate is not None:
                mutate(repository)
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            return subprocess.run(
                [sys.executable, str(repository / "ci" / "checks" / "connectors" / "nginx" / CHECKER.name)],
                cwd=repository,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

    def _assert_rejected(self, mutate, message: str) -> None:
        result = self._run_checker(mutate)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"FAIL: {message}", result.stdout.splitlines())

    def test_current_helper_aware_contract_is_accepted(self) -> None:
        result = self._run_checker()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "PASS: NGINX Server resolver preserves the bounded explicit-length response-header sink",
            result.stdout,
        )
        self.assertIn(f"PASS: {RULE_ID_CONTRACT_MESSAGE}", result.stdout)

    def test_rule_id_delegation_rejects_mutated_wrapper_and_inactive_twins(self) -> None:
        cases = (
            ("null guard omitted", "if (intervention->log != NULL)", "if (1)"),
            ("changed input", "intervention->log,", '"[id 123]",'),
            ("changed output", "ctx->last_intervention_rule_id,", "other_buffer,"),
            ("changed size", "sizeof(ctx->last_intervention_rule_id)", "4096"),
            ("local parser", "(void)msconnector_rule_id_extract_from_message", "(void)strstr"),
            ("log configuration gate", "if (intervention->log != NULL)",
             "if (ctx->r && intervention->log != NULL)"),
        )
        for label, old, new in cases:
            with self.subTest(case=label):
                self._assert_rejected(
                    lambda repo: replace_in_function(
                        repo / "connectors/nginx/src/ngx_http_modsecurity_module.c",
                        RULE_ID_SIGNATURE, old, new),
                    RULE_ID_CONTRACT_MESSAGE,
                )
            with self.subTest(case=label, inactive_twin=True):
                self._assert_rejected(
                    lambda repo: inject_inactive_decoy(
                        repo / "connectors/nginx/src/ngx_http_modsecurity_module.c",
                        RULE_ID_SIGNATURE, old, new),
                    RULE_ID_CONTRACT_MESSAGE,
                )

    def test_rule_id_delegation_rejects_missing_gated_or_late_caller(self) -> None:
        def mutate(repo: Path, case: str) -> None:
            path = repo / "connectors/nginx/src/ngx_http_modsecurity_module.c"
            if case == "omitted":
                replace_in_function(path, INTERVENTION_SIGNATURE, RULE_ID_CALL, "")
            elif case == "gated":
                replace_in_function(path, INTERVENTION_SIGNATURE, RULE_ID_CALL,
                    "if (mcf->phase4_log_file != NULL) { " + RULE_ID_CALL + " }")
            elif case == "reset omitted":
                replace_in_function(path, INTERVENTION_SIGNATURE,
                    "ctx->last_intervention_rule_id[0] = '\\0';", "")
            elif case == "reset nonempty":
                replace_in_function(path, INTERVENTION_SIGNATURE,
                    "ctx->last_intervention_rule_id[0] = '\\0';",
                    "ctx->last_intervention_rule_id[0] = '1';")
            else:
                replace_in_function(path, INTERVENTION_SIGNATURE, RULE_ID_CALL, "")
                anchor = {
                    "after record": "// logging to nginx error log",
                    "after dispatch": "cleanup:",
                    "after cleanup": "    return result;",
                }[case]
                replace_in_function(path, INTERVENTION_SIGNATURE, anchor,
                    RULE_ID_CALL + "\n" + anchor)

        for case in ("omitted", "gated", "reset omitted", "reset nonempty",
                     "after record", "after dispatch", "after cleanup"):
            with self.subTest(case=case):
                self._assert_rejected(lambda repo: mutate(repo, case), RULE_ID_CONTRACT_MESSAGE)

    def test_rule_id_delegation_rejects_extra_local_helpers_and_direct_parsers(self) -> None:
        for extra in (
            "static void ngx_http_modsecurity_duplicate_rule_id(void) {}\n",
            "static void duplicate_parser(void) {\n"
            " (void)msconnector_rule_id_extract_from_message(0, 0, 0);\n}\n",
        ):
            with self.subTest(extra=extra):
                self._assert_rejected(
                    lambda repo: insert_before_signature(
                        repo / "connectors/nginx/src/ngx_http_modsecurity_module.c",
                    RULE_ID_SIGNATURE, extra), RULE_ID_CONTRACT_MESSAGE)

    def test_rule_id_delegation_rejects_direct_early_exits_before_extraction(self) -> None:
        anchor = "ctx->last_intervention_status = intervention.status;"
        for early_exit in ("goto cleanup;", "return NGX_ERROR;", "return result;"):
            with self.subTest(early_exit=early_exit):
                self._assert_rejected(
                    lambda repo: replace_in_function(
                        repo / "connectors/nginx/src/ngx_http_modsecurity_module.c",
                        INTERVENTION_SIGNATURE, anchor, early_exit + "\n    " + anchor),
                    RULE_ID_CONTRACT_MESSAGE,
                )

    def test_rule_id_delegation_rejects_macro_overrides(self) -> None:
        for symbol in ("msconnector_rule_id_extract_from_message",
                       "ngx_http_modsecurity_extract_intervention_rule_id",
                       "ngx_http_modsecurity_process_intervention",
                       "last_intervention_rule_id", "sizeof", "NULL",
                       "ctx", "intervention", "log"):
            with self.subTest(symbol=symbol):
                self._assert_rejected(
                    lambda repo: prepend_directive(
                        repo / "connectors/nginx/src/ngx_http_modsecurity_common.h",
                        f"#define {symbol}(...) 0"),
                    "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls")

    def test_current_projected_jsonl_pipelines_are_reported_without_traceback(self) -> None:
        result = self._run_checker()
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        for caller in ("request", "strict"):
            self.assertIn(
                f"PASS: NGINX {caller} JSONL projection and serialization retain "
                "the active ordered fail-closed pipeline",
                result.stdout,
            )

    def test_projected_jsonl_pipeline_rejects_active_bypasses_and_decoys(self) -> None:
        signature = "static ngx_inline int\nngx_http_modsecurity_write_event_jsonl"
        anchor = "!ngx_http_modsecurity_bounded_event_uri(event, &projected, uri, sizeof(uri)) ||"
        cases = (
            ("projection removed", anchor, "0 ||"),
            ("provenance bypassed",
             "!ngx_http_modsecurity_apply_event_provenance(r, &projected,\n            connection_id, sizeof(connection_id)) ||",
             "0 ||"),
            ("short circuit inverted", anchor, anchor.replace("||", "&&")),
            ("raw event serialized", "msconnector_event_write_jsonl_line(&projected,", "msconnector_event_write_jsonl_line(event,"),
            ("write before projection", "    if (" + anchor, "    ngx_write_fd(mcf->phase4_log_file->fd, line, 1);\n    if (" + anchor),
            ("serialization failure ignored",
             'json_truncated ? " (truncated)" : "");\n        return 0;',
             'json_truncated ? " (truncated)" : "");\n        return 1;'),
            ("physical write failure ignored",
             '%s", write_failure_message);\n        return 0;',
             '%s", write_failure_message);\n        return 1;'),
        )
        for name, old, new in cases:
            for decoy in (False, True):
                with self.subTest(case=name, inactive_decoy=decoy):
                    def mutate(repository, old=old, new=new, decoy=decoy):
                        path = repository / "connectors/nginx/src/ngx_http_modsecurity_common.h"
                        if decoy:
                            inject_inactive_decoy(path, signature, old, new)
                        else:
                            replace_in_function(path, signature, old, new)
                    self._assert_rejected(mutate, "NGINX request JSONL projection and serialization retain the active ordered fail-closed pipeline")

    def test_strict_projected_jsonl_pipeline_rejects_raw_event_and_early_success(self) -> None:
        signature = "static ngx_inline ngx_int_t\nngx_http_modsecurity_write_phase_event_jsonl"
        for old, new in (
            ("!ngx_http_modsecurity_apply_event_provenance(r, &projected,\n            connection_id, sizeof(connection_id)) ||", "0 ||"),
            ("msconnector_event_write_jsonl_line(&projected,", "msconnector_event_write_jsonl_line(event,"),
            ("        return NGX_ERROR;", "        return NGX_OK;"),
        ):
            with self.subTest(fragment=old):
                def mutate(repository, old=old, new=new):
                    path = repository / "connectors/nginx/src/ngx_http_modsecurity_common.h"
                    replace_all_in_function(path, signature, old, new, 3 if "return" in old else 1)
                self._assert_rejected(mutate, "NGINX strict JSONL projection and serialization retain the active ordered fail-closed pipeline")

    def test_inactive_mapper_validator_decoy_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            inject_inactive_decoy(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "mapper_error);\n        return mapper_status;",
                "mapper_error);\n        return NGX_OK;",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_inactive_initializer_propagation_decoy_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            inject_inactive_decoy(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_initialize_request",
                "ctx->intervention_triggered = 1;\n        return rc;",
                "ctx->intervention_triggered = 1;\n        return NGX_OK;",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_inactive_response_wrapper_decoy_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            inject_inactive_decoy(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header",
                "value_len, 1) != NGX_OK) {\n        return NGX_ERROR;",
                "value_len, 1) != NGX_OK) {\n        return NGX_OK;",
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_active_preprocessor_mapper_early_return_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "    msconnector_request_mapper_contract_init(&contract);\n",
                "#if 1\n"
                "    return NGX_OK;\n"
                "#endif\n\n"
                "    msconnector_request_mapper_contract_init(&contract);\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_unconditional_mapper_early_return_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "    msconnector_request_mapper_contract_init(&contract);\n",
                "    return NGX_OK;\n\n"
                "    msconnector_request_mapper_contract_init(&contract);\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_permitted_macro_early_return_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_access.c"
            )
            signature = (
                "static ngx_int_t\n"
                "ngx_http_modsecurity_validate_common_request_mapper"
            )
            insert_before_signature(
                path, signature, "#define MSCONNECTOR_EARLY_RETURN return 0"
            )
            replace_in_function(
                path,
                signature,
                "    msconnector_request_mapper_contract_init(&contract);\n",
                "    MSCONNECTOR_EARLY_RETURN;\n"
                "    msconnector_request_mapper_contract_init(&contract);\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_ucn_macro_name_early_return_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_access.c"
            )
            signature = (
                "static ngx_int_t\n"
                "ngx_http_modsecurity_validate_common_request_mapper"
            )
            insert_before_signature(
                path, signature, "#define \\u004dSCONNECTOR_EARLY_RETURN return 0"
            )
            replace_in_function(
                path,
                signature,
                "    msconnector_request_mapper_contract_init(&contract);\n",
                "    MSCONNECTOR_EARLY_RETURN;\n"
                "    msconnector_request_mapper_contract_init(&contract);\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_permitted_macro_control_flow_capture_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_access.c"
            )
            signature = (
                "static ngx_int_t\n"
                "ngx_http_modsecurity_validate_common_request_mapper"
            )
            insert_before_signature(
                path,
                signature,
                "#define MSCONNECTOR_SKIP_NEXT_STATEMENT if (1) ; else",
            )
            replace_in_function(
                path,
                signature,
                "    msconnector_request_mapper_contract_init(&contract);\n",
                "    MSCONNECTOR_SKIP_NEXT_STATEMENT\n"
                "    msconnector_request_mapper_contract_init(&contract);\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_active_preprocessor_response_early_return_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header",
                "    if (ngx_http_modsecurity_validate_header(ctx, name, name_len, value,\n",
                "#if 1\n"
                "    return NGX_ERROR;\n"
                "#endif\n\n"
                "    if (ngx_http_modsecurity_validate_header(ctx, name, name_len, value,\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_line_spliced_inactive_mapper_decoy_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            inject_inactive_decoy(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "mapper_error);\n        return mapper_status;",
                "mapper_error);\n        return NGX_OK;",
                "#\\\nif 0\n",
                "#\\\nendif\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_trigraph_inactive_response_wrapper_decoy_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            inject_inactive_decoy(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header",
                "value_len, 1) != NGX_OK) {\n        return NGX_ERROR;",
                "value_len, 1) != NGX_OK) {\n        return NGX_OK;",
                "??=if 0\n",
                "??=endif\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_digraph_inactive_response_wrapper_decoy_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            inject_inactive_decoy(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header",
                "value_len, 1) != NGX_OK) {\n        return NGX_ERROR;",
                "value_len, 1) != NGX_OK) {\n        return NGX_OK;",
                "%:if 0\n",
                "%:endif\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_outer_include_guard_else_decoy_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            inject_outer_guard_else_decoy(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header",
                "value_len, 1) != NGX_OK) {\n        return NGX_ERROR;",
                "value_len, 1) != NGX_OK) {\n        return NGX_OK;",
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_mapper_rejection_is_bound_to_the_mapper_call(self) -> None:
        def mutate(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c"
            signature = "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper"
            replace_in_function(
                path,
                signature,
                "mapper_error);\n        return mapper_status;",
                "mapper_error);\n        return NGX_OK;",
            )
            replace_in_function(
                path,
                signature,
                "\n    return NGX_OK;\n}",
                "\n    if (r == NULL) {\n"
                "        return NGX_HTTP_BAD_REQUEST;\n"
                "    }\n\n"
                "    return NGX_OK;\n}",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_mapper_typed_error_status_cannot_be_success_or_client_default(self) -> None:
        for replacement in ("NGX_OK", "NGX_HTTP_BAD_REQUEST"):
            with self.subTest(replacement=replacement):
                def mutate(repository, replacement=replacement):
                    path = repository / "connectors/nginx/src/ngx_http_modsecurity_mapper.c"
                    replace_in_function(path, "int ngx_http_modsecurity_map_request",
                        "*failure_status = NGX_HTTP_INTERNAL_SERVER_ERROR;",
                        "*failure_status = " + replacement + ";")
                self._assert_rejected(mutate,
                    "NGINX mapper propagates internal failure 500 and independently bounded client header-count failure 400")

    def test_mapper_client_header_limit_cannot_be_removed_or_unbounded(self) -> None:
        for old, new in (("contract->max_header_count > 0U", "contract->max_header_count == 0U"),
                         ("*failure_status = NGX_HTTP_BAD_REQUEST;", "*failure_status = NGX_OK;")):
            with self.subTest(fragment=old):
                def mutate(repository, old=old, new=new):
                    replace_in_function(repository / "connectors/nginx/src/ngx_http_modsecurity_mapper.c",
                                        "int ngx_http_modsecurity_map_request", old, new)
                self._assert_rejected(mutate,
                    "NGINX mapper propagates internal failure 500 and independently bounded client header-count failure 400")

    def test_extra_unparseable_mapper_status_assignment_is_rejected(self) -> None:
        for expression in ("NGX_OK + 1", "unknown_status()", "A" * 65, ""):
            with self.subTest(expression=expression):
                def mutate(repository, expression=expression):
                    path = repository / "connectors/nginx/src/ngx_http_modsecurity_mapper.c"
                    source = path.read_text(encoding="utf-8")
                    _, end = function_bounds(source, "int ngx_http_modsecurity_map_request")
                    source = source[:end - 1] + "    *failure_status = " + expression + ";\n" + source[end - 1:]
                    path.write_text(source, encoding="utf-8")

                self._assert_rejected(mutate,
                    "NGINX mapper propagates internal failure 500 and independently bounded client header-count failure 400")

    def test_large_mapper_assignment_without_semicolon_is_bounded_and_rejected(self) -> None:
        def mutate(repository):
            path = repository / "connectors/nginx/src/ngx_http_modsecurity_mapper.c"
            source = path.read_text(encoding="utf-8")
            _, end = function_bounds(source, "int ngx_http_modsecurity_map_request")
            # The existing 30s subprocess deadline catches the old quadratic
            # whitespace/RHS backtracking; this does not time tiny inputs.
            source = source[:end - 1] + "    *failure_status = " + " " * 262144 + "X\n" + source[end - 1:]
            path.write_text(source, encoding="utf-8")

        self._assert_rejected(mutate,
            "NGINX mapper propagates internal failure 500 and independently bounded client header-count failure 400")

    def test_mapper_caller_default_must_remain_internal_server_error(self) -> None:
        def mutate(repository):
            replace_in_function(repository / "connectors/nginx/src/ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "mapper_status = NGX_HTTP_INTERNAL_SERVER_ERROR;", "mapper_status = NGX_OK;")
        self._assert_rejected(mutate,
            "NGINX request mapper validation fails closed before request-header initialization")

    def test_unbraced_mapper_rejection_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "    if (!ngx_http_modsecurity_map_request(r, &contract, &mapped_request,\n",
                "    if (r != NULL)\n"
                "        if (!ngx_http_modsecurity_map_request(r, &contract, &mapped_request,\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_nested_initializer_propagation_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_initialize_request",
                "    rc = ngx_http_modsecurity_validate_common_request_mapper(r);\n"
                "    if (rc != NGX_OK) {\n"
                "        ctx->intervention_triggered = 1;\n"
                "        return rc;\n"
                "    }",
                "    if (ctx->processed) {\n"
                "        rc = ngx_http_modsecurity_validate_common_request_mapper(r);\n"
                "        if (rc != NGX_OK) {\n"
                "            ctx->intervention_triggered = 1;\n"
                "            return rc;\n"
                "        }\n"
                "    }",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_unbraced_initializer_propagation_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_initialize_request",
                "    rc = ngx_http_modsecurity_validate_common_request_mapper(r);\n",
                "    if (ctx->processed)\n"
                "        rc = ngx_http_modsecurity_validate_common_request_mapper(r);\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_nested_response_validation_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header",
                "    if (ngx_http_modsecurity_validate_header(ctx, name, name_len, value,\n"
                "            value_len, 1) != NGX_OK) {\n"
                "        return NGX_ERROR;\n"
                "    }",
                "    if (ctx->response_header_count > 0U) {\n"
                "        if (ngx_http_modsecurity_validate_header(ctx, name, name_len, value,\n"
                "                value_len, 1) != NGX_OK) {\n"
                "            return NGX_ERROR;\n"
                "        }\n"
                "    }",
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_unbraced_response_validation_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header",
                "    if (ngx_http_modsecurity_validate_header(ctx, name, name_len, value,\n"
                "            value_len, 1) != NGX_OK) {\n"
                "        return NGX_ERROR;\n"
                "    }",
                "    if (ctx->response_header_count > 0U)\n"
                "        if (ngx_http_modsecurity_validate_header(ctx, name, name_len, value,\n"
                "                value_len, 1) != NGX_OK) {\n"
                "            return NGX_ERROR;\n"
                "        }",
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def _replace_date_wrapper_with_raw_sink(
        self, repository: Path, raw_sink_name: str
    ) -> None:
        replace_in_function(
            repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_header_filter.c",
            "static ngx_int_t\nngx_http_modsecurity_resolv_header_date",
            "    return ngx_http_modsecurity_add_n_response_header(ctx,\n"
            "        (const unsigned char *) name.data,\n"
            "        name.len,\n"
            "        (const unsigned char *) date.data,\n"
            "        date.len);",
            "    return "
            + raw_sink_name
            + "(ctx->modsec_transaction,\n"
            "        (const unsigned char *) name.data,\n"
            "        name.len,\n"
            "        (const unsigned char *) date.data,\n"
            "        date.len) == 1 ? 1 : NGX_ERROR;",
        )

    def test_line_spliced_raw_response_sink_is_rejected(self) -> None:
        self._assert_rejected(
            lambda repository: self._replace_date_wrapper_with_raw_sink(
                repository, "msc_add_n_response_\\\nheader"
            ),
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_ucn_raw_response_sink_is_rejected(self) -> None:
        self._assert_rejected(
            lambda repository: self._replace_date_wrapper_with_raw_sink(
                repository, "msc_add_n_response_\\u0068eader"
            ),
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_alternate_common_wrapper_raw_sink_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_common.h"
            signature = "static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header"
            raw_return = (
                "    return msc_add_n_response_header(ctx->modsec_transaction, name, name_len,\n"
                "        value, value_len) == 1 ? 1 : NGX_ERROR;"
            )
            replace_in_function(
                path,
                signature,
                raw_return,
                "    if (name_len == 0U) {\n"
                "        return msc_add_n_response_header((ctx)->modsec_transaction, name, name_len,\n"
                "            value, value_len) == 1 ? 1 : NGX_ERROR;\n"
                "    }\n\n"
                + raw_return,
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_comment_brace_cannot_hide_response_mapper_lifecycle_call(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_mapper.c"
            )
            replace_in_function(
                path,
                "void\nngx_http_modsecurity_validate_response_mapper",
                "    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,\n"
                "        \"modsecurity common response mapper validation skipped: %s\", mapper_error);\n"
                "}",
                "    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,\n"
                "        \"modsecurity common response mapper validation skipped: %s\", mapper_error);\n"
                "    /* } */\n"
                "    ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module,\n"
                "        NGX_ERROR);\n"
                "}",
            )

        self._assert_rejected(
            mutate,
            "NGINX response mapper helper excludes caller lifecycle, body, enforcement, filter-chain, and allocation control",
        )

    def test_string_brace_cannot_hide_response_mapper_lifecycle_call(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_mapper.c"
            )
            replace_in_function(
                path,
                "void\nngx_http_modsecurity_validate_response_mapper",
                "    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,\n"
                "        \"modsecurity common response mapper validation skipped: %s\", mapper_error);\n"
                "}",
                "    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,\n"
                "        \"modsecurity common response mapper validation skipped: %s\", mapper_error);\n"
                "    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, \"}\");\n"
                "    ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module,\n"
                "        NGX_ERROR);\n"
                "}",
            )

        self._assert_rejected(
            mutate,
            "NGINX response mapper helper excludes caller lifecycle, body, enforcement, filter-chain, and allocation control",
        )

    def test_comment_brace_cannot_hide_unbounded_response_body_append(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c"
            )
            replace_in_function(
                path,
                "static ngx_int_t\nngx_http_modsecurity_append_response_chain_buffer",
                "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,\n"
                "        chain->buf);",
                "    /* return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,\n"
                "        chain->buf); */\n"
                "    /* } */\n"
                "    return ngx_http_modsecurity_append_response_body_chunk(ctx,\n"
                "        chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));",
            )

        self._assert_rejected(
            mutate,
            BODY_LIMIT_CONTRACT_MESSAGE,
        )

    def test_inactive_brace_cannot_hide_unbounded_response_body_append(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c"
            )
            replace_in_function(
                path,
                "static ngx_int_t\nngx_http_modsecurity_append_response_chain_buffer",
                "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,\n"
                "        chain->buf);",
                "#if 0\n"
                "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,\n"
                "        chain->buf);\n"
                "}\n"
                "#endif\n"
                "    return ngx_http_modsecurity_append_response_body_chunk(ctx,\n"
                "        chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));",
            )

        self._assert_rejected(
            mutate,
            BODY_LIMIT_CONTRACT_MESSAGE,
        )

    def test_active_conditional_cannot_hide_response_mapper_lifecycle_call(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_mapper.c",
                "void\nngx_http_modsecurity_validate_response_mapper",
                "    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,\n"
                "        \"modsecurity common response mapper validation skipped: %s\", mapper_error);\n"
                "}",
                "    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,\n"
                "        \"modsecurity common response mapper validation skipped: %s\", mapper_error);\n"
                "#if 1\n"
                "    ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module, NGX_ERROR);\n"
                "#endif\n"
                "}",
            )

        self._assert_rejected(
            mutate,
            "NGINX response mapper helper excludes caller lifecycle, body, enforcement, filter-chain, and allocation control",
        )

    def test_each_direct_response_body_append_route_before_wrapper_is_rejected(
        self,
    ) -> None:
        cases = (
            (
                "buffer wrapper",
                "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,\n"
                "        chain->buf);\n\n",
            ),
            (
                "limited body wrapper",
                "    return ngx_http_modsecurity_append_accounted_response_body(ctx, mcf,\n"
                "        chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));\n\n",
            ),
            (
                "file body wrapper",
                "    return ngx_http_modsecurity_append_file_response_body(r, ctx, mcf,\n"
                "        chain->buf);\n\n",
            ),
            (
                "bounded chunk helper",
                "    return ngx_http_modsecurity_append_response_body_chunk(ctx,\n"
                "        chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));\n\n",
            ),
            (
                "raw ModSecurity append",
                "    return msc_append_response_body(ctx->modsec_transaction,\n"
                "        chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));\n\n",
            ),
        )
        path_name = "ngx_http_modsecurity_body_filter.c"
        signature = (
            "static ngx_int_t\n"
            "ngx_http_modsecurity_append_response_chain_buffer"
        )

        for name, invocation in cases:
            with self.subTest(route=name):
                def mutate(
                    repository: Path,
                    invocation: str = invocation,
                ) -> None:
                    replace_in_function(
                        repository / "connectors" / "nginx" / "src" / path_name,
                        signature,
                        "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
                        invocation + "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
                    )

                self._assert_rejected(
                    mutate,
                    BODY_LIMIT_CONTRACT_MESSAGE,
                )

    def test_any_pre_wrapper_helper_call_is_rejected(self) -> None:
        cases = (
            (
                "response-body helper",
                "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,\n"
                "        buffer);\n",
                "ngx_http_modsecurity_pre_wrapper_helper",
            ),
            (
                "harmless helper",
                "    return NGX_OK;\n",
                "ngx_http_modsecurity_pre_wrapper_helper",
            ),
            (
                "object macro helper alias",
                "    return NGX_OK;\n",
                "MSCONNECTOR_PRE_WRAPPER_HELPER",
            ),
        )
        path_name = "ngx_http_modsecurity_body_filter.c"
        signature = (
            "static ngx_int_t\n"
            "ngx_http_modsecurity_append_response_chain_buffer"
        )
        helper_signature = (
            "static ngx_int_t\n"
            "ngx_http_modsecurity_pre_wrapper_helper(ngx_http_request_t *r,\n"
            "    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf,\n"
            "    ngx_buf_t *buffer)\n"
        )

        for name, helper_body, invocation_name in cases:
            with self.subTest(helper=name):
                def mutate(
                    repository: Path,
                    helper_body: str = helper_body,
                    invocation_name: str = invocation_name,
                ) -> None:
                    path = repository / "connectors" / "nginx" / "src" / path_name
                    insert_before_signature(
                        path,
                        signature,
                        helper_signature + "{\n" + helper_body + "}",
                    )
                    if invocation_name == "MSCONNECTOR_PRE_WRAPPER_HELPER":
                        insert_before_signature(
                            path,
                            signature,
                            "#define MSCONNECTOR_PRE_WRAPPER_HELPER "
                            "ngx_http_modsecurity_pre_wrapper_helper",
                        )
                    replace_in_function(
                        path,
                        signature,
                        "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
                        "    return " + invocation_name
                        + "(r, ctx, mcf, chain->buf);\n\n"
                        + "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
                    )

                self._assert_rejected(
                    mutate,
                    BODY_LIMIT_CONTRACT_MESSAGE,
                )

    def test_active_conditional_direct_response_body_append_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\nngx_http_modsecurity_append_response_chain_buffer",
                "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
                "#if 1\n"
                "    return ngx_http_modsecurity_append_response_body_chunk(ctx,\n"
                "        chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));\n"
                "#endif\n\n"
                "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
            )

        self._assert_rejected(
            mutate,
            BODY_LIMIT_CONTRACT_MESSAGE,
        )

    def test_object_macro_alias_of_each_response_mapper_marker_is_rejected(
        self,
    ) -> None:
        default_use = "    MSCONNECTOR_FORBIDDEN_MAPPER_ALIAS;\n"
        cases = (
            ("response validation", "ctx->common_response_validated", default_use),
            ("processed state", "ctx->processed", default_use),
            ("intervention state", "ctx->intervention_triggered", default_use),
            ("phase4 state", "ctx->phase4_processed", default_use),
            ("response-body state", "ctx->response_body_bytes_seen", default_use),
            ("response-commit state", "ctx->response_committed", default_use),
            ("response-header processing", "msc_process_response_headers", default_use),
            ("response-body processing", "msc_process_response_body", default_use),
            ("raw response-header sink", "msc_add_n_response_header", default_use),
            ("next-filter chain", "ngx_http_next_header_filter", default_use),
            (
                "request finalizer",
                "ngx_http_filter_finalize_request",
                "    MSCONNECTOR_FORBIDDEN_MAPPER_ALIAS(r,\n"
                "        &ngx_http_modsecurity_module, 0);\n",
            ),
            ("pool allocation", "ngx_palloc", default_use),
            ("nonzeroing pool allocation", "ngx_pnalloc", default_use),
            ("zeroing pool allocation", "ngx_pcalloc", default_use),
        )
        path_name = "ngx_http_modsecurity_mapper.c"
        signature = "void\nngx_http_modsecurity_validate_response_mapper"
        warning = (
            "    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,\n"
            "        \"modsecurity common response mapper validation skipped: %s\", mapper_error);\n"
        )

        for name, replacement, use in cases:
            with self.subTest(marker=name):
                def mutate(
                    repository: Path,
                    replacement: str = replacement,
                    use: str = use,
                ) -> None:
                    path = repository / "connectors" / "nginx" / "src" / path_name
                    insert_before_signature(
                        path,
                        signature,
                        "#define MSCONNECTOR_FORBIDDEN_MAPPER_ALIAS " + replacement,
                    )
                    replace_in_function(
                        path,
                        signature,
                        warning,
                        warning + use,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
                )

    def test_object_macro_alias_of_each_pre_wrapper_response_body_append_route_is_rejected(
        self,
    ) -> None:
        cases = (
            (
                "buffer wrapper",
                "ngx_http_modsecurity_append_response_body_buffer",
                "    MSCONNECTOR_FORBIDDEN_BODY_ALIAS(r, ctx, mcf, chain->buf);\n\n",
            ),
            (
                "limited body wrapper",
                "ngx_http_modsecurity_append_accounted_response_body",
                "    MSCONNECTOR_FORBIDDEN_BODY_ALIAS(ctx, mcf, chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));\n\n",
            ),
            (
                "file body wrapper",
                "ngx_http_modsecurity_append_file_response_body",
                "    MSCONNECTOR_FORBIDDEN_BODY_ALIAS(r, ctx, mcf, chain->buf);\n\n",
            ),
            (
                "bounded chunk helper",
                "ngx_http_modsecurity_append_response_body_chunk",
                "    MSCONNECTOR_FORBIDDEN_BODY_ALIAS(ctx, chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));\n\n",
            ),
            (
                "raw ModSecurity append",
                "msc_append_response_body",
                "    MSCONNECTOR_FORBIDDEN_BODY_ALIAS(ctx->modsec_transaction,\n"
                "        chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));\n\n",
            ),
        )
        path_name = "ngx_http_modsecurity_body_filter.c"
        signature = (
            "static ngx_int_t\n"
            "ngx_http_modsecurity_append_response_chain_buffer"
        )

        for name, replacement, invocation in cases:
            with self.subTest(marker=name):
                def mutate(
                    repository: Path,
                    replacement: str = replacement,
                    invocation: str = invocation,
                ) -> None:
                    path = repository / "connectors" / "nginx" / "src" / path_name
                    insert_before_signature(
                        path,
                        signature,
                        "#define MSCONNECTOR_FORBIDDEN_BODY_ALIAS " + replacement,
                    )
                    replace_in_function(
                        path,
                        signature,
                        "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
                        invocation + "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
                )

    def test_chained_object_macro_alias_to_direct_response_body_append_is_rejected(
        self,
    ) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c"
            )
            signature = (
                "static ngx_int_t\n"
                "ngx_http_modsecurity_append_response_chain_buffer"
            )
            insert_before_signature(
                path,
                signature,
                "#define MSCONNECTOR_FORBIDDEN_BODY_ALIAS "
                "MSCONNECTOR_FORBIDDEN_BODY_TERMINAL\n"
                "#define MSCONNECTOR_FORBIDDEN_BODY_TERMINAL "
                "msc_append_response_body",
            )
            replace_in_function(
                path,
                signature,
                "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
                "    MSCONNECTOR_FORBIDDEN_BODY_ALIAS(ctx->modsec_transaction,\n"
                "        chain->buf->pos,\n"
                "        (size_t)(chain->buf->last - chain->buf->pos));\n\n"
                "    return ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,",
            )

        self._assert_rejected(
            mutate,
            "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
        )

    def test_harmless_object_macro_remains_accepted(self) -> None:
        def mutate(repository: Path) -> None:
            insert_before_signature(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_mapper.c",
                "void\nngx_http_modsecurity_validate_response_mapper",
                "#define MSCONNECTOR_HARMLESS_ALIAS 1U",
            )

        result = self._run_checker(mutate)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "PASS: NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
            result.stdout,
        )

    def test_macro_redefined_request_mapper_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "#define ngx_http_modsecurity_map_request(...) (1)",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_diagnostic_macro_control_flow_mutation_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            old = "#define dd(...) do { \\\n"
            new = "#define dd(...) if (1) ; else \\\n"
            if source.count(old) != 1:
                raise AssertionError("expected one mutable diagnostic macro")
            path.write_text(source.replace(old, new, 1), encoding="utf-8")

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_unapproved_local_macro_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "    msconnector_request_mapper_contract_init(&contract);\n",
                "    msconnector_request_mapper_contract_init(&contract);\n"
                "#define r ((ngx_http_request_t *) 0)\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_macro_redefined_initializer_validator_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_initialize_request",
                "#define ngx_http_modsecurity_validate_common_request_mapper(r) NGX_OK",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_macro_redefined_bad_request_status_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            prepend_directive(
                repository / "connectors" / "nginx" / "src" / "ddebug.h",
                "#define NGX_HTTP_BAD_REQUEST NGX_OK",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_macro_redefined_response_validator_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_int_t\nngx_http_modsecurity_add_n_response_header",
                "#define ngx_http_modsecurity_validate_header(...) NGX_OK",
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_critical_macro_undefinition_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "#undef NGX_HTTP_BAD_REQUEST",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_token_pasted_raw_response_sink_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_header_filter.c",
                "static ngx_int_t\nngx_http_modsecurity_resolv_header_date",
                "#define MSCONNECTOR_RAW_HEADER_SINK msc_add_n_response_ ## header",
            )
            self._replace_date_wrapper_with_raw_sink(
                repository, "MSCONNECTOR_RAW_HEADER_SINK"
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_permitted_common_macro_raw_response_sink_alias_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            prepend_directive(
                repository / "common" / "include" / "msconnector" / "limits.h",
                "#define MSCONNECTOR_RAW_HEADER_SINK msc_add_n_response_header",
            )
            self._replace_date_wrapper_with_raw_sink(
                repository, "MSCONNECTOR_RAW_HEADER_SINK"
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_early_macro_return_with_unreachable_raw_sink_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_common.h"
            )
            signature = (
                "static ngx_inline ngx_int_t\n"
                "ngx_http_modsecurity_add_n_response_header"
            )
            raw_return = (
                "    return msc_add_n_response_header(ctx->modsec_transaction, name, name_len,\n"
                "        value, value_len) == 1 ? 1 : NGX_ERROR;"
            )
            insert_before_signature(
                path,
                signature,
                "#define MSCONNECTOR_BYPASS(...) 1",
            )
            replace_in_function(
                path,
                signature,
                raw_return,
                "    return MSCONNECTOR_BYPASS(ctx->modsec_transaction, name, name_len,\n"
                "        value, value_len);\n\n"
                + raw_return,
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_permitted_macro_parameterized_raw_sink_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_common.h"
            )
            signature = (
                "static ngx_inline ngx_int_t\n"
                "ngx_http_modsecurity_add_n_response_header"
            )
            raw_return = (
                "    return msc_add_n_response_header(ctx->modsec_transaction, name, name_len,\n"
                "        value, value_len) == 1 ? 1 : NGX_ERROR;"
            )
            insert_before_signature(
                path,
                signature,
                "#define MSCONNECTOR_RETURN_APPLIED(fn, args) return fn args",
            )
            replace_in_function(
                path,
                signature,
                raw_return,
                "    MSCONNECTOR_RETURN_APPLIED(msc_add_n_response_header,\n"
                "        (ctx->modsec_transaction, name, name_len, value, value_len));\n\n"
                + raw_return,
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_permitted_macro_parameterized_prevalidation_sink_is_rejected(
        self,
    ) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_common.h"
            )
            signature = (
                "static ngx_inline ngx_int_t\n"
                "ngx_http_modsecurity_add_n_response_header"
            )
            insert_before_signature(
                path,
                signature,
                "#define MSCONNECTOR_APPLY(fn, args) fn args",
            )
            replace_in_function(
                path,
                signature,
                "    if (ngx_http_modsecurity_validate_header(ctx, name, name_len, value,\n",
                "    MSCONNECTOR_APPLY(msc_add_n_response_header,\n"
                "        (ctx->modsec_transaction, name, name_len, value, value_len));\n\n"
                "    if (ngx_http_modsecurity_validate_header(ctx, name, name_len, value,\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX Server resolver preserves the bounded explicit-length response-header sink",
        )

    def test_unscanned_local_include_extension_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            decoy = repository / "connectors" / "nginx" / "src" / "checker-decoy.inc"
            decoy.write_text(
                "#define r ((ngx_http_request_t *) 0)\n", encoding="utf-8"
            )
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                '#include "checker-decoy.inc"',
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_traversal_local_include_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            decoy = repository / "connectors" / "nginx" / "checker-decoy.h"
            decoy.write_text(
                "#define r ((ngx_http_request_t *) 0)\n", encoding="utf-8"
            )
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                '#include "../checker-decoy.h"',
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_unscanned_out_of_root_local_header_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            decoy = repository / "connectors" / "checker-decoy.h"
            decoy.write_text(
                "#define r ((ngx_http_request_t *) 0)\n", encoding="utf-8"
            )
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                '#include "connectors/checker-decoy.h"',
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_external_quoted_include_local_shadow_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            decoy = repository / "stdio.h"
            decoy.write_text(
                "#define NGX_HTTP_BAD_REQUEST NGX_OK\n", encoding="utf-8"
            )
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                '#include "stdio.h"',
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_unknown_angle_include_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            decoy = repository / "checker-decoy.inc"
            decoy.write_text(
                "#define NGX_HTTP_BAD_REQUEST NGX_OK\n", encoding="utf-8"
            )
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "#include <checker-decoy.inc>",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_include_next_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "#include_next <ngx_config.h>",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_import_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                "#import <ngx_config.h>",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_new_standard_header_local_shadows_and_symlinks_are_rejected(self) -> None:
        for header in ("inttypes.h", "stdbool.h", "time.h"):
            for symlink in (False, True):
                with self.subTest(header=header, symlink=symlink):
                    def mutate(repository: Path) -> None:
                        shadow = repository / header
                        if symlink:
                            target = repository / "checker-shadow.inc"
                            target.write_text("#define NGX_OK NGX_ERROR\n", encoding="utf-8")
                            shadow.symlink_to(target)
                        else:
                            shadow.write_text("#define NGX_OK NGX_ERROR\n", encoding="utf-8")
                    self._assert_rejected(
                        mutate,
                        "NGINX critical macro inputs reject aliases of checked lifecycle "
                        "and response-body controls",
                    )

    def test_header_measurement_initializer_and_early_timing_are_rejected(self) -> None:
        signature = "ngx_int_t\nngx_http_modsecurity_header_filter("
        declaration = "ngx_http_modsecurity_engine_call_measurement measurement;"
        controls = (
            declaration.replace(";", " = ngx_http_modsecurity_engine_call_begin();"),
            declaration + "\n    ngx_http_modsecurity_engine_call_begin(ctx, mcf, &measurement);",
        )
        for replacement in controls:
            with self.subTest(replacement=replacement):
                def mutate(repository: Path) -> None:
                    replace_in_function(
                        repository / "connectors/nginx/src/ngx_http_modsecurity_header_filter.c",
                        signature, declaration, replacement,
                    )
                self._assert_rejected(
                    mutate,
                    "NGINX header mapper validation retains its existing eligibility "
                    "and ordering without a once gate",
                )

    def test_external_angle_include_local_shadow_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            decoy = repository / "ngx_config.h"
            decoy.write_text(
                "#define NGX_HTTP_BAD_REQUEST NGX_OK\n", encoding="utf-8"
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_macro_expanded_local_include_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            decoy = repository / "connectors" / "nginx" / "src" / "checker-decoy.inc"
            decoy.write_text(
                "#define r ((ngx_http_request_t *) 0)\n", encoding="utf-8"
            )
            insert_before_signature(
                repository / "connectors" / "nginx" / "src" / "ngx_http_modsecurity_access.c",
                "static ngx_int_t\nngx_http_modsecurity_validate_common_request_mapper",
                '#define MSCONNECTOR_CHECKER_DECOY "checker-decoy.inc"\n'
                "#include MSCONNECTOR_CHECKER_DECOY",
            )

        self._assert_rejected(
            mutate,
            "NGINX request mapper validation fails closed before request-header initialization",
        )

    def test_string_literal_cannot_replace_bounded_chain_call(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors/nginx/src/ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\nngx_http_modsecurity_process_response_body_chain",
                "        ret = ngx_http_modsecurity_append_response_chain_buffer(r, ctx, mcf,\n"
                "            chain);\n",
                "        ret = NGX_OK;\n"
                '        (void) "ngx_http_modsecurity_append_response_chain_buffer(r, ctx, mcf, chain)";\n',
            )
        self._assert_rejected(mutate, CHAIN_CALL_CONTRACT_MESSAGE)

    def test_string_literal_body_limit_accounting_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c"
            )
            signature = (
                "static ngx_int_t\n"
                "ngx_http_modsecurity_account_response_body"
            )
            replace_all_in_function(
                path,
                signature,
                "ctx->response_body_bytes_seen += len;",
                "ctx->response_body_bytes_seen = 0U;",
                1,
            )
            replace_in_function(
                path,
                signature,
                "    *allowed = len;\n",
                "    (void) \"ctx->response_body_bytes_seen = "
                "len;\";\n"
                "    *allowed = len;\n",
            )

        self._assert_rejected(
            mutate,
            BODY_LIMIT_CONTRACT_MESSAGE,
        )

    def test_unreachable_body_response_mapper_calls_are_rejected(self) -> None:
        call = (
            "    ngx_http_modsecurity_validate_response_mapper(ctx, r,\n"
            "        NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_BODY);\n"
        )
        cases = (
            ("braced if zero", "    if (0) {\n" + "    " + call + "    }\n"),
            ("unbraced if zero", "    if (0)\n" + "    " + call),
            ("preprocessor if one", "#if 1\n" + call + "#endif\n"),
        )

        for name, replacement in cases:
            with self.subTest(wrapper=name):
                def mutate(
                    repository: Path, replacement: str = replacement
                ) -> None:
                    replace_in_function(
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_body_filter.c",
                        "static ngx_int_t\n"
                        "ngx_http_modsecurity_validate_response_mapper_once",
                        call,
                        replacement,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX body mapper validation remains once-only, post-guard, and non-fatal",
                )

    def test_unreachable_header_response_mapper_calls_are_rejected(self) -> None:
        call = (
            "    ngx_http_modsecurity_validate_response_mapper(ctx, r,\n"
            "        NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_HEADER);\n"
        )
        cases = (
            ("braced if zero", "    if (0) {\n" + "    " + call + "    }\n"),
            ("unbraced if zero", "    if (0)\n" + "    " + call),
            ("preprocessor if one", "#if 1\n" + call + "#endif\n"),
        )

        for name, replacement in cases:
            with self.subTest(wrapper=name):
                def mutate(
                    repository: Path, replacement: str = replacement
                ) -> None:
                    replace_in_function(
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_header_filter.c",
                        "ngx_int_t\n"
                        "ngx_http_modsecurity_header_filter(ngx_http_request_t *r)\n{",
                        call,
                        replacement,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX header mapper validation retains its existing eligibility and ordering without a once gate",
                )

    def test_preprocessor_early_return_before_body_mapper_is_rejected(self) -> None:
        guard = (
            "    if (ctx->common_response_validated) {\n"
            "        return NGX_OK;\n"
            "    }\n\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_validate_response_mapper_once",
                guard,
                guard + "#if 1\n    return NGX_OK;\n#endif\n\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX body mapper validation remains once-only, post-guard, and non-fatal",
        )

    def test_early_return_before_header_mapper_is_rejected(self) -> None:
        guard = (
            "    if (ctx->intervention_triggered) {\n"
            "        return ngx_http_next_header_filter(r);\n"
            "    }\n\n"
        )
        cases = (
            (
                "preprocessor",
                "#if 1\n    return ngx_http_next_header_filter(r);\n#endif\n\n",
            ),
            (
                "structured conditional",
                "    if (1) {\n"
                "        return ngx_http_next_header_filter(r);\n"
                "    }\n\n",
            ),
        )

        for name, insertion in cases:
            with self.subTest(wrapper=name):
                def mutate(
                    repository: Path, insertion: str = insertion
                ) -> None:
                    replace_in_function(
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_header_filter.c",
                        "ngx_int_t\n"
                        "ngx_http_modsecurity_header_filter(ngx_http_request_t *r)\n{",
                        guard,
                        guard + insertion,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX header mapper validation retains its existing eligibility and ordering without a once gate",
                )

    def test_header_filter_requires_terminal_response_header_failure_guard(self) -> None:
        guard = (
            "    if (ctx->response_headers_processing_failed) {\n"
            "        return NGX_ERROR;\n"
            "    }\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_header_filter.c",
                "ngx_int_t\n"
                "ngx_http_modsecurity_header_filter(ngx_http_request_t *r)\n{",
                guard,
                "    if (ctx->response_headers_processing_failed) {\n"
                "        return ngx_http_next_header_filter(r);\n"
                "    }\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX header mapper validation retains its existing eligibility and ordering without a once gate",
        )

    def test_pre_guard_header_mapper_bypasses_are_rejected(self) -> None:
        context_acquisition = (
            "    ctx = ngx_http_modsecurity_get_module_ctx(r);\n"
        )
        diagnostic = "    dd(\"header filter, recovering ctx: %p\", ctx);\n"
        anchor = context_acquisition + "\n" + diagnostic
        cases = (
            (
                "direct context lookup state mutation before acquisition",
                "    ngx_http_modsecurity_get_module_ctx(r)->"
                "intervention_triggered = 1;\n"
                + context_acquisition
                + "\n"
                + diagnostic,
            ),
            (
                "diagnostic argument intervention-state mutation",
                context_acquisition
                + "\n"
                + "    dd(\"header filter, recovering ctx: %p\", "
                + "(ctx->intervention_triggered = 1, ctx));\n",
            ),
            (
                "diagnostic argument context null assignment",
                context_acquisition
                + "\n"
                + "    dd(\"header filter, recovering ctx: %p\", "
                + "(ctx = NULL));\n",
            ),
            (
                "intervention-state mutation",
                context_acquisition
                + "    ctx->intervention_triggered = 1;\n\n"
                + diagnostic,
            ),
            (
                "context null assignment",
                context_acquisition + "    ctx = NULL;\n\n" + diagnostic,
            ),
            (
                "compound early return after context acquisition",
                context_acquisition
                + "    {\n"
                + "        return ngx_http_next_header_filter(r);\n"
                + "    }\n\n"
                + diagnostic,
            ),
            (
                "compound early return before context acquisition",
                "    {\n"
                + "        return ngx_http_next_header_filter(r);\n"
                + "    }\n"
                + context_acquisition
                + "\n"
                + diagnostic,
            ),
        )

        for name, replacement in cases:
            with self.subTest(bypass=name):
                def mutate(
                    repository: Path, replacement: str = replacement
                ) -> None:
                    replace_in_function(
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_header_filter.c",
                        "ngx_int_t\n"
                        "ngx_http_modsecurity_header_filter(ngx_http_request_t *r)\n{",
                        anchor,
                        replacement,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX header mapper validation retains its existing eligibility and ordering without a once gate",
                )

    def test_diagnostic_format_literal_side_effect_is_rejected(self) -> None:
        header_path = (
            "connectors/nginx/src/ngx_http_modsecurity_header_filter.c"
        )
        header_signature = (
            "ngx_int_t\n"
            "ngx_http_modsecurity_header_filter(ngx_http_request_t *r)\n{"
        )
        header_call = "    dd(\"header filter, recovering ctx: %p\", ctx);"
        header_message = (
            "NGINX header mapper validation retains its existing eligibility "
            "and ordering without a once gate"
        )
        macro_message = (
            "NGINX critical macro inputs reject aliases of checked lifecycle "
            "and response-body controls"
        )
        cases = (
            (
                "header diagnostic format",
                header_path,
                header_signature,
                header_call,
                "    dd(\"%n\", ctx);",
                header_message,
            ),
            (
                "dd prefix format",
                "connectors/nginx/src/ddebug.h",
                None,
                "\"modsec *** %s: \"",
                "\"%n\"",
                macro_message,
            ),
            (
                "dd suffix format",
                "connectors/nginx/src/ddebug.h",
                None,
                "\" at %s line %d.\\n\"",
                "\"%n\"",
                macro_message,
            ),
            (
                "read-handler diagnostic format",
                "connectors/nginx/src/ddebug.h",
                None,
                "\"r->read_event_handler = %s\"",
                "\"%n\"",
                macro_message,
            ),
            (
                "write-handler diagnostic format",
                "connectors/nginx/src/ddebug.h",
                None,
                "\"r->write_event_handler = %s\"",
                "\"%n\"",
                macro_message,
            ),
        )

        for name, path_name, signature, old, new, message in cases:
            with self.subTest(format=name):
                def mutate(
                    repository: Path,
                    path_name: str = path_name,
                    signature=signature,
                    old: str = old,
                    new: str = new,
                ) -> None:
                    path = repository / path_name
                    if signature is not None:
                        replace_in_function(path, signature, old, new)
                        return
                    source = path.read_text(encoding="utf-8")
                    if source.count(old) != 1:
                        raise AssertionError(
                            f"expected one mutable format literal in {path}"
                        )
                    path.write_text(
                        source.replace(old, new, 1), encoding="utf-8"
                    )

                self._assert_rejected(mutate, message)

    def test_critical_macro_source_symlink_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            source = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            target = source.with_name("ddebug-regular-target.h")
            source.rename(target)
            source.symlink_to(target.name)

        self._assert_rejected(
            mutate,
            "NGINX critical macro inputs reject aliases of checked lifecycle "
            "and response-body controls",
        )

    def test_diagnostic_macro_side_effect_is_rejected(self) -> None:
        macro_path_name = "ddebug.h"
        original_macro = (
            "#define dd(...) do { \\\n"
            "    fprintf(stderr, \"modsec *** %s: \", __func__); \\\n"
            "    fprintf(stderr, __VA_ARGS__); \\\n"
            "    fprintf(stderr, \" at %s line %d.\\n\", __FILE__, __LINE__); \\\n"
            "} while (0)"
        )
        replacement_macro = (
            "#define dd(...) do { "
            "msconnector_header_debug_bypass(__VA_ARGS__); "
            "} while (0)"
        )
        object_like_redirect_macro = (
            "#define dd msconnector_header_debug_bypass"
        )
        noncall_side_effect_macro = (
            "#define dd(...) do { \\\n"
            "    *((volatile unsigned char *)0) = 1U; \\\n"
            "    fprintf(stderr, \"modsec *** %s: \", __func__); \\\n"
            "    fprintf(stderr, __VA_ARGS__); \\\n"
            "    fprintf(stderr, \" at %s line %d.\\n\", __FILE__, __LINE__); \\\n"
            "} while (0)"
        )
        helper = (
            "static void\n"
            "msconnector_header_debug_bypass(const char *format,\n"
            "    ngx_http_modsecurity_ctx_t *ctx)\n"
            "{\n"
            "    (void)format;\n"
            "    ctx->intervention_triggered = 1;\n"
            "}\n\n"
        )
        signature = (
            "ngx_int_t\n"
            "ngx_http_modsecurity_header_filter(ngx_http_request_t *r)\n{"
        )

        cases = (
            ("helper call", replacement_macro, helper),
            ("object-like diagnostic redirect", object_like_redirect_macro, helper),
            ("direct non-call side effect", noncall_side_effect_macro, ""),
        )

        for name, replacement, source_helper in cases:
            with self.subTest(side_effect=name):
                def mutate(
                    repository: Path,
                    replacement: str = replacement,
                    source_helper: str = source_helper,
                ) -> None:
                    macro_path = (
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / macro_path_name
                    )
                    macro_source = macro_path.read_text(encoding="utf-8")
                    if macro_source.count(original_macro) != 1:
                        raise AssertionError(
                            "expected one mutable dd macro definition"
                        )
                    macro_path.write_text(
                        macro_source.replace(original_macro, replacement, 1),
                        encoding="utf-8",
                    )
                    if source_helper:
                        insert_before_signature(
                            repository
                            / "connectors"
                            / "nginx"
                            / "src"
                            / "ngx_http_modsecurity_header_filter.c",
                            signature,
                            source_helper,
                        )

                self._assert_rejected(
                    mutate,
                    "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
                )

    def test_nonvariadic_diagnostic_fallback_side_effect_is_rejected(self) -> None:
        original_fallback = (
            "static void dd(const char *fmt, ...) {\n"
            "    (void)fmt;\n"
            "}"
        )
        mutated_fallback = (
            "static void dd(const char *fmt, ...) {\n"
            "    va_list arguments;\n"
            "    va_start(arguments, fmt);\n"
            "    *(volatile unsigned char *)va_arg(arguments, void *) = 0U;\n"
            "    va_end(arguments);\n"
            "}"
        )

        def mutate(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            if source.count(original_fallback) != 2:
                raise AssertionError("expected two inert static dd fallbacks")
            path.write_text(
                source.replace(original_fallback, mutated_fallback, 1),
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate,
            "NGINX nonvariadic diagnostic fallbacks remain inert and bounded",
        )

    def test_additional_conditional_diagnostic_fallback_is_rejected(self) -> None:
        original_nondebug_fallback = (
            "#if (NGX_HAVE_VARIADIC_MACROS)\n"
            "#define dd(...)\n"
            "#else\n"
            "static void dd(const char *fmt, ...) {\n"
            "    (void)fmt;\n"
            "}\n"
            "#endif"
        )
        alternate_nondebug_fallback = (
            "#if (NGX_HAVE_VARIADIC_MACROS)\n"
            "#define dd(...)\n"
            "#elif 1\n"
            "static void dd(\n"
            "    const char *fmt,\n"
            "    ...\n"
            ") {\n"
            "    (void)fmt;\n"
            "    *((volatile unsigned char *)0) = 1U;\n"
            "}\n"
            "#else\n"
            "static void dd(const char *fmt, ...) {\n"
            "    (void)fmt;\n"
            "}\n"
            "#endif"
        )

        def mutate(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            if source.count(original_nondebug_fallback) != 1:
                raise AssertionError("expected one mutable nondebug dd fallback")
            path.write_text(
                source.replace(
                    original_nondebug_fallback, alternate_nondebug_fallback, 1
                ),
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate,
            "NGINX nonvariadic diagnostic fallbacks remain inert and bounded",
        )

        def mutate_oversized_candidate(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            terminal_endif = source.rfind("#endif")
            if terminal_endif == -1:
                raise AssertionError("expected terminal ddebug include guard")
            path.write_text(
                source[:terminal_endif]
                + "\nstatic void "
                + "dd(" * 2048
                + "\n"
                + source[terminal_endif:],
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate_oversized_candidate,
            "NGINX nonvariadic diagnostic fallbacks remain inert and bounded",
        )

        original_fallback = (
            "static void dd(const char *fmt, ...) {\n"
            "    (void)fmt;\n"
            "}"
        )
        aliased_noninert_fallback = (
            "#define MSCONNECTOR_DDEBUG_NAME dd\n"
            "static void MSCONNECTOR_DDEBUG_NAME(const char *fmt, ...) {\n"
            "    *((volatile unsigned char *)0) = 1U;\n"
            "}"
        )
        inert_decoy = (
            "#if 0\n"
            "static void dd(const char *fmt, ...) {\n"
            "    (void)fmt;\n"
            "}\n"
            "#endif\n"
        )

        def mutate_macro_alias(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            if source.count(original_fallback) != 2:
                raise AssertionError("expected two inert static dd fallbacks")
            mutated = source.replace(original_fallback, aliased_noninert_fallback, 1)
            terminal_endif = mutated.rfind("#endif")
            if terminal_endif == -1:
                raise AssertionError("expected terminal ddebug include guard")
            path.write_text(
                mutated[:terminal_endif]
                + inert_decoy
                + mutated[terminal_endif:],
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate_macro_alias,
            "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
        )

        trailing_macro_noninert_fallback = (
            "#define MSCONNECTOR_DDEBUG_ATTRIBUTE\n"
            "static void dd(const char *fmt, ...) MSCONNECTOR_DDEBUG_ATTRIBUTE {\n"
            "    *((volatile unsigned char *)0) = 1U;\n"
            "}"
        )

        def mutate_trailing_macro_suffix(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            if source.count(original_fallback) != 2:
                raise AssertionError("expected two inert static dd fallbacks")
            mutated = source.replace(
                original_fallback, trailing_macro_noninert_fallback, 1
            )
            terminal_endif = mutated.rfind("#endif")
            if terminal_endif == -1:
                raise AssertionError("expected terminal ddebug include guard")
            path.write_text(
                mutated[:terminal_endif]
                + inert_decoy
                + mutated[terminal_endif:],
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate_trailing_macro_suffix,
            "NGINX nonvariadic diagnostic fallbacks remain inert and bounded",
        )

        parenthesized_noninert_fallback = (
            "static void (dd)(const char *fmt, ...) {\n"
            "    *((volatile unsigned char *)0) = 1U;\n"
            "}"
        )

        def mutate_parenthesized_declarator(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            if source.count(original_fallback) != 2:
                raise AssertionError("expected two inert static dd fallbacks")
            mutated = source.replace(
                original_fallback, parenthesized_noninert_fallback, 1
            )
            terminal_endif = mutated.rfind("#endif")
            if terminal_endif == -1:
                raise AssertionError("expected terminal ddebug include guard")
            path.write_text(
                mutated[:terminal_endif]
                + inert_decoy
                + mutated[terminal_endif:],
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate_parenthesized_declarator,
            "NGINX nonvariadic diagnostic fallbacks remain inert and bounded",
        )

        indirect_noninert_fallback = (
            "static void dd_side_effect(const char *fmt, ...) {\n"
            "    *((volatile unsigned char *)0) = 1U;\n"
            "}\n"
            "static void (*dd)(const char *fmt, ...) = dd_side_effect;"
        )

        def mutate_indirect_fallback(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            if source.count(original_fallback) != 2:
                raise AssertionError("expected two inert static dd fallbacks")
            mutated = source.replace(original_fallback, indirect_noninert_fallback, 1)
            terminal_endif = mutated.rfind("#endif")
            if terminal_endif == -1:
                raise AssertionError("expected terminal ddebug include guard")
            path.write_text(
                mutated[:terminal_endif]
                + inert_decoy
                + mutated[terminal_endif:],
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate_indirect_fallback,
            "NGINX nonvariadic diagnostic fallbacks remain inert and bounded",
        )

        pragma_alias_noninert_fallback = (
            "static void msconnector_ddebug_side_effect(const char *fmt, ...) {\n"
            "    *((volatile unsigned char *)0) = 1U;\n"
            "}\n"
            "#pragma GCC diagnostic ignored \"-Wimplicit-function-declaration\"\n"
            "#pragma weak dd = msconnector_ddebug_side_effect"
        )

        def mutate_pragma_alias(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            if source.count(original_fallback) != 2:
                raise AssertionError("expected two inert static dd fallbacks")
            mutated = source.replace(
                original_fallback, pragma_alias_noninert_fallback, 1
            )
            terminal_endif = mutated.rfind("#endif")
            if terminal_endif == -1:
                raise AssertionError("expected terminal ddebug include guard")
            path.write_text(
                mutated[:terminal_endif]
                + inert_decoy
                + mutated[terminal_endif:],
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate_pragma_alias,
            "NGINX nonvariadic diagnostic fallbacks remain inert and bounded",
        )

        pragma_operator_noninert_fallback = (
            "static void msconnector_ddebug_side_effect(const char *fmt, ...) {\n"
            "    *((volatile unsigned char *)0) = 1U;\n"
            "}\n"
            "_Pragma(\"weak dd = msconnector_ddebug_side_effect\")"
        )

        def mutate_pragma_operator_alias(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            if source.count(original_fallback) != 2:
                raise AssertionError("expected two inert static dd fallbacks")
            mutated = source.replace(
                original_fallback, pragma_operator_noninert_fallback, 1
            )
            terminal_endif = mutated.rfind("#endif")
            if terminal_endif == -1:
                raise AssertionError("expected terminal ddebug include guard")
            path.write_text(
                mutated[:terminal_endif]
                + inert_decoy
                + mutated[terminal_endif:],
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate_pragma_operator_alias,
            "NGINX nonvariadic diagnostic fallbacks remain inert and bounded",
        )

        pragma_operator_macro_noninert_fallback = (
            "#define MSCONNECTOR_DDEBUG_PRAGMA "
            "_Pragma(\"weak dd = msconnector_ddebug_side_effect\")\n"
            "static void msconnector_ddebug_side_effect(const char *fmt, ...) {\n"
            "    *((volatile unsigned char *)0) = 1U;\n"
            "}\n"
            "MSCONNECTOR_DDEBUG_PRAGMA"
        )

        def mutate_pragma_operator_macro_alias(repository: Path) -> None:
            path = repository / "connectors" / "nginx" / "src" / "ddebug.h"
            source = path.read_text(encoding="utf-8")
            if source.count(original_fallback) != 2:
                raise AssertionError("expected two inert static dd fallbacks")
            mutated = source.replace(
                original_fallback, pragma_operator_macro_noninert_fallback, 1
            )
            terminal_endif = mutated.rfind("#endif")
            if terminal_endif == -1:
                raise AssertionError("expected terminal ddebug include guard")
            path.write_text(
                mutated[:terminal_endif]
                + inert_decoy
                + mutated[terminal_endif:],
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate_pragma_operator_macro_alias,
            "NGINX nonvariadic diagnostic fallbacks remain inert and bounded",
        )

    def test_object_like_pcre_allocator_macro_is_rejected(self) -> None:
        cases = (
            (
                "init",
                "#define ngx_http_modsecurity_pcre_malloc_init(x) NULL",
                "#define ngx_http_modsecurity_pcre_malloc_init "
                "((ngx_pool_t *(*)(ngx_pool_t *))0)",
            ),
            (
                "done",
                "#define ngx_http_modsecurity_pcre_malloc_done(x) (void)x",
                "#define ngx_http_modsecurity_pcre_malloc_done "
                "((void (*)(ngx_pool_t *))0)",
            ),
        )

        for name, original, replacement in cases:
            with self.subTest(macro=name):
                def mutate(
                    repository: Path,
                    original: str = original,
                    replacement: str = replacement,
                ) -> None:
                    path = (
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_common.h"
                    )
                    source = path.read_text(encoding="utf-8")
                    if source.count(original) != 1:
                        raise AssertionError(
                            "expected one mutable PCRE allocator macro"
                        )
                    path.write_text(
                        source.replace(original, replacement, 1),
                        encoding="utf-8",
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
                )

    def test_response_body_chain_requires_direct_bounded_wrapper(self) -> None:
        wrapper_call = (
            "        ret = ngx_http_modsecurity_append_response_chain_buffer(r, ctx, mcf,\n"
            "            chain);\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_process_response_body_chain",
                wrapper_call,
                "        ret = NGX_OK;\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX response-body chain loop directly calls the reviewed bounded wrapper",
        )

    def test_response_body_raw_sink_outside_bounded_helper_is_rejected(self) -> None:
        wrapper_call = (
            "        ret = ngx_http_modsecurity_append_response_chain_buffer(r, ctx, mcf,\n"
            "            chain);\n"
        )
        raw_helper = (
            "static ngx_int_t\n"
            "msconnector_unchecked_response_body(ngx_http_modsecurity_ctx_t *ctx,\n"
            "    const u_char *data, size_t amount)\n"
            "{\n"
            "    return msc_append_response_body(ctx->modsec_transaction, data, amount) < 0\n"
            "        ? NGX_ERROR : NGX_OK;\n"
            "}\n\n"
        )

        def mutate(repository: Path) -> None:
            path = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c"
            )
            insert_before_signature(
                path,
                "static ngx_int_t\n"
                "ngx_http_modsecurity_process_response_body_chain",
                raw_helper,
            )
            replace_in_function(
                path,
                "static ngx_int_t\n"
                "ngx_http_modsecurity_process_response_body_chain",
                wrapper_call,
                "        ret = msconnector_unchecked_response_body(ctx,\n"
                "            chain->buf->pos, (size_t)(chain->buf->last - chain->buf->pos));\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX response-body raw sink remains owned by the bounded append helper",
        )

    def test_header_filter_requires_response_header_collection(self) -> None:
        collection_call = (
            "    if (ngx_http_modsecurity_add_response_headers(r, ctx) != NGX_OK) {\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_header_filter.c",
                "ngx_int_t\n"
                "ngx_http_modsecurity_header_filter(ngx_http_request_t *r)\n{",
                collection_call,
                "    if (NGX_OK != NGX_OK) {\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX header filter directly collects validated response headers before metadata processing",
        )

    def test_header_collection_failure_sets_terminal_retry_guard(self) -> None:
        failure = (
            "        ctx->response_headers_processing_failed = 1;\n"
            "        ctx->intervention_triggered = 1;\n"
            "        return NGX_ERROR;\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_header_filter.c",
                "ngx_int_t\n"
                "ngx_http_modsecurity_header_filter(ngx_http_request_t *r)\n{",
                failure,
                "        ctx->intervention_triggered = 1;\n"
                "        return NGX_ERROR;\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX header filter directly collects validated response headers before metadata processing",
        )

    def test_response_header_collection_uses_validated_wrapper(self) -> None:
        wrapper_call = "        if (ngx_http_modsecurity_add_n_response_header(ctx,\n"

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_header_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_add_response_headers",
                wrapper_call,
                "        if (NGX_OK != NGX_OK) {\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX response-header collection retains the reviewed validated wrapper surface",
        )

    def test_response_header_collection_keeps_synthetic_resolver_loop(self) -> None:
        resolver_loop = (
            "    for (i = 0; ngx_http_modsecurity_headers_out[i].name.len; i++) {\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_header_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_add_response_headers",
                resolver_loop,
                "    for (i = 0; 0; i++) {\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX response-header collection retains the reviewed synthetic and chained traversal",
        )

    def test_response_header_raw_sink_outside_common_wrapper_is_rejected(self) -> None:
        raw_helper = (
            "static ngx_inline ngx_int_t\n"
            "msconnector_unchecked_response_header(ngx_http_modsecurity_ctx_t *ctx,\n"
            "    const u_char *name, size_t name_len, const u_char *value, size_t value_len)\n"
            "{\n"
            "    return msc_add_n_response_header(ctx->modsec_transaction, name, name_len,\n"
            "        value, value_len);\n"
            "}\n\n"
        )

        def mutate(repository: Path) -> None:
            common_header = (
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_common.h"
            )
            insert_before_signature(
                common_header,
                "static ngx_inline ngx_int_t\n"
                "ngx_http_modsecurity_add_n_response_header",
                raw_helper,
            )
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_header_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_add_response_headers",
                "        if (ngx_http_modsecurity_add_n_response_header(ctx,\n",
                "        if (msconnector_unchecked_response_header(ctx,\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX response-header raw sink remains owned by the canonical validated Common wrapper",
        )

    def test_response_body_raw_sink_function_pointer_alias_is_rejected(self) -> None:
        bounded_call = (
            "        ret = ngx_http_modsecurity_append_response_chain_buffer(r, ctx, mcf,\n"
            "            chain);\n"
        )
        error_return = CHAIN_ERROR_RETURN
        raw_alias = (
            bounded_call
            + error_return
            + "        static int (*const raw_body)(Transaction *, const unsigned char *, size_t) =\n"
            "            msc_append_response_body;\n"
            "        (void) raw_body(ctx->modsec_transaction, chain->buf->pos,\n"
            "            (size_t)(chain->buf->last - chain->buf->pos));\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_process_response_body_chain",
                bounded_call + error_return,
                raw_alias,
            )

        self._assert_rejected(
            mutate,
            "NGINX response-body raw sink remains owned by the bounded append helper",
        )

    def test_response_header_raw_sink_function_pointer_alias_is_rejected(self) -> None:
        validator = (
            "    if (ngx_http_modsecurity_validate_header(ctx, name, name_len, value,\n"
            "            value_len, 1) != NGX_OK) {\n"
        )
        raw_alias = (
            "    static int (*const raw_header)(Transaction *, const unsigned char *, size_t,\n"
            "        const unsigned char *, size_t) = &msc_add_n_response_header;\n"
            "    (void) raw_header(ctx->modsec_transaction, name, name_len, value, value_len);\n"
            + validator
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_int_t\n"
                "ngx_http_modsecurity_add_n_response_header",
                validator,
                raw_alias,
            )

        self._assert_rejected(
            mutate,
            "NGINX response-header raw sink remains owned by the canonical validated Common wrapper",
        )

    def test_response_body_chain_cannot_return_before_scope_gate(self) -> None:
        assignment = (
            "    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_process_response_body_chain",
                assignment,
                "    if (0) {\n"
                "        return NGX_OK;\n"
                "    }\n"
                + assignment,
            )

        self._assert_rejected(
            mutate,
            "NGINX response-body chain loop directly calls the reviewed bounded wrapper",
        )

    def test_response_header_collection_cannot_neutralize_traversal_state(self) -> None:
        resolver_loop = (
            "    for (i = 0; ngx_http_modsecurity_headers_out[i].name.len; i++) {\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_header_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_add_response_headers",
                resolver_loop,
                "    ngx_http_modsecurity_headers_out[0].name.len = 0U;\n"
                "    part->nelts = 0U;\n"
                "    part->next = NULL;\n"
                + resolver_loop,
            )

        self._assert_rejected(
            mutate,
            "NGINX response-header collection retains the reviewed synthetic and chained traversal",
        )

    def test_body_filter_cannot_invoke_chunk_before_direct_chain(self) -> None:
        direct_chain = (
            "    return ngx_http_modsecurity_process_response_body_chain(r, in, ctx);\n"
        )
        intermediate_caller = (
            "    static ngx_int_t (*const raw_chunk)(ngx_http_modsecurity_ctx_t *,\n"
            "        u_char *, size_t) = ngx_http_modsecurity_append_response_body_chunk;\n"
            "    (void)raw_chunk(ctx, in->buf->pos,\n"
            "        (size_t)(in->buf->last - in->buf->pos));\n"
            + direct_chain
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c",
                "ngx_int_t\nngx_http_modsecurity_body_filter(ngx_http_request_t *r, ngx_chain_t *in)",
                direct_chain,
                intermediate_caller,
            )

        self._assert_rejected(
            mutate,
            "NGINX response-body filter retains only the direct prepared chain path",
        )

    def test_response_body_buffer_requires_limited_memory_path(self) -> None:
        limited_memory_path = (
            "        return ngx_http_modsecurity_append_accounted_response_body(ctx, mcf,\n"
            "            data, len);\n"
        )
        direct_chunk = (
            "        return ngx_http_modsecurity_append_response_body_chunk(ctx, data, len);\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_append_response_body_buffer",
                limited_memory_path,
                direct_chunk,
            )

        self._assert_rejected(
            mutate,
            "NGINX response-body buffer route retains the bounded memory/file planner paths",
        )

    def test_limited_response_body_cannot_ignore_planned_allowance(self) -> None:
        planned_allowance = (
            "    return ngx_http_modsecurity_append_response_body_chunk(ctx, data, allowed);\n"
        )
        unbounded_length = (
            "    return ngx_http_modsecurity_append_response_body_chunk(ctx, data, len);\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\n"
                "ngx_http_modsecurity_append_accounted_response_body",
                planned_allowance,
                unbounded_length,
            )

        self._assert_rejected(
            mutate,
            "NGINX response-body helper passes each accounted complete chunk to the raw route",
        )

    def test_connector_mime_bypass_cannot_be_reintroduced(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors/nginx/src/ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\nngx_http_modsecurity_append_response_chain_buffer",
                CHAIN_APPEND_ANCHOR,
                "    if (r->headers_out.content_type.len == 0) {\n"
                "        return NGX_OK;\n"
                "    }\n" + CHAIN_APPEND_ANCHOR,
            )
        self._assert_rejected(mutate, BODY_LIMIT_CONTRACT_MESSAGE)

    def test_synthetic_date_resolver_cannot_return_before_wrapper(self) -> None:
        context_lookup = (
            "    ctx = ngx_http_modsecurity_get_module_ctx(r);\n\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_header_filter.c",
                "static ngx_int_t\nngx_http_modsecurity_resolv_header_date",
                context_lookup,
                context_lookup
                + "    if (r != NULL) {\n"
                "        return 1;\n"
                "    }\n\n",
            )

        self._assert_rejected(
            mutate,
            "NGINX synthetic response-header resolver table and Date route retain the validated Common wrapper",
        )

    def test_synthetic_resolver_table_cannot_rebind_date(self) -> None:
        table_path = (
            Path("connectors")
            / "nginx"
            / "src"
            / "ngx_http_modsecurity_header_filter.c"
        )
        old_resolver = "            ngx_http_modsecurity_resolv_header_date },"
        new_resolver = "            ngx_http_modsecurity_resolv_header_server },"

        def mutate(repository: Path) -> None:
            path = repository / table_path
            source = path.read_text(encoding="utf-8")
            if source.count(old_resolver) != 1:
                raise AssertionError("expected exactly one Date resolver table entry")
            path.write_text(
                source.replace(old_resolver, new_resolver, 1),
                encoding="utf-8",
            )

        self._assert_rejected(
            mutate,
            "NGINX synthetic response-header resolver table and Date route retain the validated Common wrapper",
        )

    def test_next_header_cannot_terminate_chained_traversal_early(self) -> None:
        iterator = "    for (;;) {\n"
        terminated_iterator = (
            iterator
            + "        if (part != NULL) {\n"
            "            return NULL;\n"
            "        }\n"
        )

        def mutate(repository: Path) -> None:
            replace_in_function(
                repository
                / "connectors"
                / "nginx"
                / "src"
                / "ngx_http_modsecurity_common.h",
                "static ngx_inline ngx_table_elt_t *\n"
                "ngx_http_modsecurity_next_header",
                iterator,
                terminated_iterator,
            )

        self._assert_rejected(
            mutate,
            "NGINX chained response-header traversal retains the canonical Common iterator",
        )

    def test_post_mapper_header_corridor_bypasses_are_rejected(self) -> None:
        mapper_call = (
            "    ngx_http_modsecurity_validate_response_mapper(ctx, r,\n"
            "        NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_HEADER);\n"
        )
        marker = mapper_call + "    ctx->common_response_validated = 1;\n"
        cases = (
            (
                "processed state assignment",
                mapper_call
                + "    ctx->processed = 1;\n"
                + "    ctx->common_response_validated = 1;\n",
            ),
            (
                "conditional early return",
                mapper_call
                + "#if 1\n"
                + "    return NGX_OK;\n"
                + "#endif\n"
                + "    ctx->common_response_validated = 1;\n",
            ),
            (
                "post-validation context null assignment",
                marker + "    ctx = NULL;\n",
            ),
        )

        for name, replacement in cases:
            with self.subTest(bypass=name):
                def mutate(
                    repository: Path, replacement: str = replacement
                ) -> None:
                    replace_in_function(
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_header_filter.c",
                        "ngx_int_t\n"
                        "ngx_http_modsecurity_header_filter(ngx_http_request_t *r)\n{",
                        marker,
                        replacement,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX header mapper validation retains its existing eligibility and ordering without a once gate",
                )

    def test_response_mapper_context_mutations_are_rejected(self) -> None:
        cases = (
            (
                "mapper helper",
                "void\nngx_http_modsecurity_validate_response_mapper",
                "    msconnector_response_mapper_contract_init(&contract);\n",
                "    memset((void *)ctx, 0, sizeof(*ctx));\n"
                "    msconnector_response_mapper_contract_init(&contract);\n",
            ),
            (
                "mapper implementation",
                "int ngx_http_modsecurity_map_response_from_ctx",
                "    (void)ctx;\n",
                "    memset((void *)ctx, 0, sizeof(*ctx));\n",
            ),
        )

        for name, signature, anchor, replacement in cases:
            with self.subTest(mutation=name):
                def mutate(
                    repository: Path,
                    signature: str = signature,
                    anchor: str = anchor,
                    replacement: str = replacement,
                ) -> None:
                    replace_in_function(
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_mapper.c",
                        signature,
                        anchor,
                        replacement,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX response mapper helper excludes caller lifecycle, body, enforcement, filter-chain, and allocation control",
                )

    def test_indirect_calls_are_rejected(self) -> None:
        mapper_cases = (
            (
                "nested cast",
                "",
                "    typedef void (*msconnector_mapper_hook_type)(void);\n"
                "    static msconnector_mapper_hook_type msconnector_mapper_hook;\n"
                "    (*(msconnector_mapper_hook_type)msconnector_mapper_hook)();\n",
            ),
            (
                "indexed function pointer",
                "static void (*msconnector_mapper_hooks[1])(void);\n\n",
                "    msconnector_mapper_hooks[0]();\n",
            ),
            (
                "member function pointer",
                "struct msconnector_mapper_hook_table {\n"
                "    void (*msconnector_response_mapper_contract_init)(void);\n"
                "};\n"
                "static struct msconnector_mapper_hook_table "
                "msconnector_mapper_hooks;\n\n",
                "    msconnector_mapper_hooks."
                "msconnector_response_mapper_contract_init();\n",
            ),
        )

        for name, declaration, indirect_call in mapper_cases:
            with self.subTest(mapper=name):
                def mutate_mapper(
                    repository: Path,
                    declaration: str = declaration,
                    indirect_call: str = indirect_call,
                ) -> None:
                    path = (
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_mapper.c"
                    )
                    if declaration:
                        insert_before_signature(
                            path,
                            "void\nngx_http_modsecurity_validate_response_mapper",
                            declaration,
                        )
                    replace_in_function(
                        path,
                        "void\nngx_http_modsecurity_validate_response_mapper",
                        "    msconnector_response_mapper_contract_init(&contract);\n",
                        indirect_call
                        + "    msconnector_response_mapper_contract_init(&contract);\n",
                    )

                self._assert_rejected(
                    mutate_mapper,
                    "NGINX response mapper helper excludes caller lifecycle, body, enforcement, filter-chain, and allocation control",
                )

        nested_indirect_call = mapper_cases[0][2]

        macro_cases = (
            (
                "read",
                "#define dd_check_read_event_handler(r)",
                "\n\n#define dd_check_write_event_handler(r)",
            ),
            (
                "write",
                "#define dd_check_write_event_handler(r)",
                "\n\n#else\n\n#if (NGX_HAVE_VARIADIC_MACROS)",
            ),
        )

        for name, macro_start, macro_end in macro_cases:
            with self.subTest(macro=name):
                def mutate_macro(
                    repository: Path,
                    macro_start: str = macro_start,
                    macro_end: str = macro_end,
                ) -> None:
                    path = (
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ddebug.h"
                    )
                    source = path.read_text(encoding="utf-8")
                    start = source.index(macro_start)
                    end = source.index(macro_end, start)
                    replacement = (
                        macro_start
                        + " do { \\\n"
                        + "    typedef void (*msconnector_mapper_hook_type)(void); \\\n"
                        + "    static msconnector_mapper_hook_type msconnector_mapper_hook; \\\n"
                        + "    (*(msconnector_mapper_hook_type)"
                        + "msconnector_mapper_hook)(); \\\n"
                        + "} while (0)"
                    )
                    path.write_text(
                        source[:start] + replacement + source[end:],
                        encoding="utf-8",
                    )

                self._assert_rejected(
                    mutate_macro,
                    "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
                )

    def test_forbidden_response_mapper_member_access_variants_are_rejected(
        self,
    ) -> None:
        cases = (
            ("whitespace arrow", "ctx -> processed"),
            ("parenthesized arrow", "(ctx) -> processed"),
            ("dereferenced dot", "(*ctx).processed"),
            ("indexed member", "ctx[0].processed"),
            ("parenthesized dereferenced dot", "(*(ctx)).processed"),
        )
        signature = "void\nngx_http_modsecurity_validate_response_mapper"
        anchor = "    msconnector_response_mapper_contract_init(&contract);\n"

        for name, member_access in cases:
            with self.subTest(member_access=name):
                def mutate(
                    repository: Path, member_access: str = member_access
                ) -> None:
                    replace_in_function(
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_mapper.c",
                        signature,
                        anchor,
                        "    if (ctx != NULL && " + member_access + ") {\n"
                        "        (void)(" + member_access + ");\n"
                        "    }\n\n"
                        + anchor,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX response mapper helper excludes caller lifecycle, body, enforcement, filter-chain, and allocation control",
                )

    def test_forbidden_macro_member_access_variants_are_rejected(self) -> None:
        cases = (
            ("whitespace arrow", "ctx -> processed"),
            ("dereferenced dot", "(*ctx).processed"),
            ("indexed member", "ctx[0].processed"),
            ("parenthesized dereferenced dot", "(*(ctx)).processed"),
        )
        signature = "void\nngx_http_modsecurity_validate_response_mapper"

        for name, replacement in cases:
            with self.subTest(member_access=name):
                def mutate(
                    repository: Path, replacement: str = replacement
                ) -> None:
                    insert_before_signature(
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_mapper.c",
                        signature,
                        "#define MSCONNECTOR_FORBIDDEN_MEMBER_ACCESS "
                        + replacement,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
                )

    def test_forbidden_macro_member_component_aliases_are_rejected(self) -> None:
        cases = (
            (
                "context alias",
                "#define MSCONNECTOR_MAPPER_CONTEXT ctx",
                "MSCONNECTOR_MAPPER_CONTEXT -> processed",
            ),
            (
                "member alias",
                "#define MSCONNECTOR_MAPPER_MEMBER processed",
                "ctx -> MSCONNECTOR_MAPPER_MEMBER",
            ),
        )
        signature = "void\nngx_http_modsecurity_validate_response_mapper"
        anchor = "    msconnector_response_mapper_contract_init(&contract);\n"

        for name, directive, member_access in cases:
            with self.subTest(alias=name):
                def mutate(
                    repository: Path,
                    directive: str = directive,
                    member_access: str = member_access,
                ) -> None:
                    path = (
                        repository
                        / "connectors"
                        / "nginx"
                        / "src"
                        / "ngx_http_modsecurity_mapper.c"
                    )
                    insert_before_signature(path, signature, directive)
                    replace_in_function(
                        path,
                        signature,
                        anchor,
                        "    if (ctx != NULL && " + member_access + ") {\n"
                        "        (void)(" + member_access + ");\n"
                        "    }\n\n"
                        + anchor,
                    )

                self._assert_rejected(
                    mutate,
                    "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
                )



    def test_unreachable_or_unchecked_chain_call_is_rejected(self) -> None:
        original = (
            "        ret = ngx_http_modsecurity_append_response_chain_buffer(r, ctx, mcf,\n"
            "            chain);\n"
        )
        cases = (
            "        if (0) {\n" + original + "        }\n",
            "        (void)ngx_http_modsecurity_append_response_chain_buffer(r, ctx, mcf,\n"
            "            chain);\n        ret = NGX_OK;\n",
            "        ret = NGX_OK;\n        if (ret != NGX_OK) {\n"
            + original + "        }\n",
        )
        for replacement in cases:
            with self.subTest(replacement=replacement):
                def mutate(repository: Path, replacement: str = replacement) -> None:
                    replace_in_function(
                        repository / "connectors/nginx/src/ngx_http_modsecurity_body_filter.c",
                        "static ngx_int_t\nngx_http_modsecurity_process_response_body_chain",
                        original, replacement,
                    )
                self._assert_rejected(mutate, CHAIN_CALL_CONTRACT_MESSAGE)

    def test_chain_failure_cannot_be_converted_to_success(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors/nginx/src/ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\nngx_http_modsecurity_process_response_body_chain",
                CHAIN_ERROR_RETURN,
                "        if (ret != NGX_OK) {\n"
                "            return NGX_OK;\n"
                "        }\n",
            )
        self._assert_rejected(mutate, CHAIN_CALL_CONTRACT_MESSAGE)

    def test_fixture_copies_the_actual_phase4_error_header(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-common-adoption-") as temporary:
            repository = self._copy_repository(Path(temporary))
            self.assertEqual(
                (repository / "connectors/nginx/src" / PHASE4_ERROR_HEADER).read_bytes(),
                (NGINX / "src" / PHASE4_ERROR_HEADER).read_bytes(),
            )

    def test_missing_phase4_error_header_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            (repository / "connectors/nginx/src" / PHASE4_ERROR_HEADER).unlink()
        self._assert_rejected(
            mutate,
            "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
        )

    def test_phase4_error_header_macro_mutation_is_rejected(self) -> None:
        def mutate(repository: Path) -> None:
            prepend_directive(
                repository / "connectors/nginx/src" / PHASE4_ERROR_HEADER,
                "#define NGX_ERROR NGX_OK",
            )
        self._assert_rejected(
            mutate,
            "NGINX critical macro inputs reject aliases of checked lifecycle and response-body controls",
        )

    def test_chain_error_dispatch_result_cannot_be_discarded(self) -> None:
        def mutate(repository: Path) -> None:
            replace_in_function(
                repository / "connectors/nginx/src/ngx_http_modsecurity_body_filter.c",
                "static ngx_int_t\nngx_http_modsecurity_process_response_body_chain",
                CHAIN_ERROR_RETURN,
                "        if (ret != NGX_OK) {\n"
                "            (void)ngx_http_modsecurity_phase4_fail_control(r, mcf, ctx,\n"
                "                MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);\n"
                "            return NGX_OK;\n"
                "        }\n",
            )
        self._assert_rejected(mutate, CHAIN_CALL_CONTRACT_MESSAGE)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
