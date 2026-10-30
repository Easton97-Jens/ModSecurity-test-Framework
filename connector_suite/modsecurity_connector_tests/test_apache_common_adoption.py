"""Mutation coverage for Apache's helper-aware Common-adoption checker."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import ast
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
CHECKER_DIRECTORY = source_path('ci/checks/connectors/apache', root=ROOT)
APACHE_DIRECTORY = source_path('connectors/apache', root=ROOT)
FILTERS_RELATIVE_PATH = Path("connectors/apache/src/msc_filters.c")


import modsecurity_connector_ci.checks.connectors.apache.apache_common_adoption_base as checker_base


def replace_once(path: Path, old: str, new: str) -> None:
    """Replace one expected source fragment or fail the test setup loudly."""
    source = path.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise AssertionError(f"expected one mutable fragment in {path}: {old!r}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def is_check_call(node: ast.AST, method: str) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and isinstance(node.value.func.value, ast.Name)
        and node.value.func.value.id == "checks"
        and node.value.func.attr == method
    )


def reviewed_ast_dump(node: object) -> str:
    """Keep the reviewed 3.14 field format independent of ast.dump defaults."""
    if isinstance(node, list):
        return "[" + ", ".join(reviewed_ast_dump(item) for item in node) + "]"
    if not isinstance(node, ast.AST):
        return repr(node)
    fields = []
    for name, value in ast.iter_fields(node):
        # Python 3.15 adds eager/lazy import state. Only its eager default is
        # equivalent to the reviewed schema; lazy imports must change the hash.
        if isinstance(node, (ast.Import, ast.ImportFrom)) and name == "is_lazy" and value == 0:
            continue
        if value is None and getattr(type(node), name, ...) is None:
            continue
        field_type = type(node)._field_types.get(name, object)
        if value == [] and getattr(field_type, "__origin__", ...) is list:
            continue
        fields.append(f"{name}={reviewed_ast_dump(value)}")
    return f"{type(node).__name__}(" + ", ".join(fields) + ")"


class ApacheAdoptionCheckBatchingTests(unittest.TestCase):
    def test_consecutive_module_checks_are_batched(self) -> None:
        tree = ast.parse((CHECKER_DIRECTORY / "apache_common_adoption_base.py").read_text())
        for first, second in zip(tree.body, tree.body[1:]):
            self.assertFalse(is_check_call(first, "append") and is_check_call(second, "append"))

    def test_batching_preserves_every_predicate_message_and_order(self) -> None:
        tree = ast.parse((CHECKER_DIRECTORY / "apache_common_adoption_base.py").read_text())
        normalized = []
        for node in tree.body:
            if is_check_call(node, "extend"):
                self.assertEqual(len(node.value.args), 1)
                self.assertIsInstance(node.value.args[0], ast.List)
                self.assertFalse(node.value.keywords)
                normalized.extend(ast.Expr(value=ast.Call(
                    func=ast.Attribute(value=ast.Name(id="checks", ctx=ast.Load()),
                                       attr="append", ctx=ast.Load()),
                    args=[item], keywords=[])) for item in node.value.args[0].elts)
            else:
                normalized.append(node)
        tree.body = normalized
        # Reviewed full-chunk engine-owned policy and combined I09/I11 AST; positions are omitted and only the
        # batching seam is expanded.
        digest = hashlib.sha256(reviewed_ast_dump(tree).encode()).hexdigest()
        self.assertEqual(digest, "2ea7f8e9c46f644deea24fe8879d7f9e30f2d820ce355302c0901779a762c49b")

    def test_reviewed_dump_retains_every_semantic_change(self) -> None:
        source = "checks.append((predicate == 1, 'first'))\nchecks.append((other, 'second'))"
        baseline = ast.parse(source)
        predicate = ast.parse(source.replace("== 1", "!= 1"))
        message = ast.parse(source.replace("'first'", "'changed'"))
        order = ast.parse(source)
        order.body.reverse()
        context = ast.parse(source)
        next(node for node in ast.walk(context) if isinstance(node, ast.Name)).ctx = ast.Store()
        eager = ast.parse("import dependency")
        lazy = ast.parse("import dependency")
        if "is_lazy" not in lazy.body[0]._fields:
            lazy.body[0]._fields += ("is_lazy",)
        lazy.body[0].is_lazy = 1
        for label, before, after in (
            ("predicate", baseline, predicate),
            ("message", baseline, message),
            ("order", baseline, order),
            ("context", baseline, context),
            ("lazy import", eager, lazy),
        ):
            with self.subTest(label=label):
                self.assertNotEqual(reviewed_ast_dump(before), reviewed_ast_dump(after))

    def test_status_comparison_is_not_a_second_assignment(self) -> None:
        source = """void apache_log_intervention_event(void) {
            event.decision.status = technical ? MSCONNECTOR_STATUS_ERROR : MSCONNECTOR_STATUS_BLOCKED;
            if (event.decision.status == MSCONNECTOR_STATUS_ERROR) event.decision.rule_id = "";
        }"""
        self.assertTrue(checker_base.typed_event_status_assignment(source))
        self.assertFalse(checker_base.typed_event_status_assignment(source.replace(
            "if (event.decision.status ==", "event.decision.status = 0; if (event.decision.status ==")))
        self.assertFalse(checker_base.typed_event_status_assignment(source.replace(
            "technical ? MSCONNECTOR_STATUS_ERROR : MSCONNECTOR_STATUS_BLOCKED",
            "MSCONNECTOR_STATUS_BLOCKED")))


class ApacheCommonAdoptionCheckerTests(unittest.TestCase):
    """Exercise the checker against compact, isolated source mutations."""

    def _copy_repository(self, destination: Path) -> Path:
        (destination / "Makefile").write_text(
            "# synthetic checker repository\n", encoding="utf-8"
        )
        checker_destination = destination / "ci" / "checks" / "connectors" / "apache"
        checker_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(CHECKER_DIRECTORY, checker_destination)
        apache_destination = destination / "connectors" / "apache"
        apache_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(APACHE_DIRECTORY, apache_destination)
        for relative_path in (
            Path("docs/connectors/apache.md"),
            Path("reports/audits/architecture-and-evidence.md"),
        ):
            source = ROOT / relative_path
            target = destination / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return destination / FILTERS_RELATIVE_PATH

    def _run_checker(self, mutate=None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="apache-common-adoption-") as temporary:
            repository = Path(temporary)
            filters = self._copy_repository(repository)
            if mutate is not None:
                mutate(filters)
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            return subprocess.run(
                [
                    sys.executable,
                    str(
                        repository
                        / "ci"
                        / "checks"
                        / "connectors"
                        / "apache"
                        / "check-apache-common-adoption.py"
                    ),
                ],
                cwd=repository,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

    def _assert_rejected(self, mutate, message: str) -> None:
        result = self._run_checker(mutate)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stdout + result.stderr)

    def test_current_helper_based_input_filter_is_accepted(self) -> None:
        result = self._run_checker()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "apache-common-adoption: scoped review guards passed",
            result.stdout,
        )

    def test_masking_keeps_code_offsets_while_hiding_decoy_tokens(self) -> None:
        source = (
            "int active = 1; // append decoy\n"
            "/* block\ncomment */ int tail = 2;\n"
            'const char *literal = "// not a comment";\n'
            "const char quote = '\\''; // after literal\n"
            '"unterminated literal\n'
        )

        masked = checker_base._mask_c_comments_and_literals(source)

        self.assertEqual(len(masked), len(source))
        self.assertEqual(masked.count("\n"), source.count("\n"))
        self.assertIn("int active = 1;", masked)
        self.assertIn("int tail = 2;", masked)
        self.assertNotIn("append decoy", masked)
        self.assertNotIn("block", masked)
        self.assertNotIn("not a comment", masked)
        self.assertNotIn("after literal", masked)
        self.assertNotIn("unterminated literal", masked)

    def test_missing_eos_helper_call_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(
                filters,
                "            return apache_input_filter_handle_eos(msr, r, f, pbbOut, pbktIn);\n",
                "            return APR_EGENERAL;\n",
            )

        self._assert_rejected(
            mutate,
            "Apache input-filter errors enter Apache core through the input-side terminal bridge",
        )

    def test_forwarding_before_validation_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(
                filters,
                "    if (ret != APR_SUCCESS)\n        return ret;\n",
                "    if (ret != APR_SUCCESS)\n        return ret;\n"
                "    APR_BUCKET_REMOVE(bucket);\n"
                "    APR_BRIGADE_INSERT_TAIL(output, bucket);\n",
            )
            replace_once(
                filters,
                "    APR_BUCKET_REMOVE(bucket);\n"
                "    APR_BRIGADE_INSERT_TAIL(output, bucket);\n"
                "    return APR_SUCCESS;\n",
                "    return APR_SUCCESS;\n",
            )

        self._assert_rejected(
            mutate,
            "Apache Phase2 bucket helper validates pointers and arithmetic, records and appends complete chunks, captures intervention, and forwards after native success",
        )

    def test_unreachable_pipeline_decoy_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(
                filters,
                "    if (msr->contract.active_phase != MSCONNECTOR_PHASE_REQUEST_BODY &&\n"
                "        !msc_apache_contract_begin(msr, MSCONNECTOR_PHASE_REQUEST_BODY)) {\n",
                "    if (0) {\n"
                "    if (msr->contract.active_phase != MSCONNECTOR_PHASE_REQUEST_BODY &&\n"
                "        !msc_apache_contract_begin(msr, MSCONNECTOR_PHASE_REQUEST_BODY)) {\n",
            )
            replace_once(
                filters,
                "    msr->request_body_bytes_inspected += len;\n"
                "    APR_BUCKET_REMOVE(bucket);\n",
                "    msr->request_body_bytes_inspected += len;\n"
                "    }\n"
                "    APR_BUCKET_REMOVE(bucket);\n",
            )

        self._assert_rejected(
            mutate,
            "Apache Phase2 direct bucket pipeline cannot satisfy its bounded-forwarding contract",
        )

    def test_removed_eos_finalization_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(
                filters,
                "        intervention = msc_finalize_request_body(msr, r);\n",
                "        intervention = N_INTERVENTION_STATUS;\n",
            )

        self._assert_rejected(
            mutate,
            "Apache request chunks are borrowed and phase 2 finalizes once at EOS",
        )

    def test_unreachable_eos_finalization_decoy_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(
                filters,
                "        intervention = msc_finalize_request_body(msr, r);\n",
                "        if (0)\n"
                "        {\n"
                "            intervention = msc_finalize_request_body(msr, r);\n"
                "        }\n"
                "        intervention = N_INTERVENTION_STATUS;\n",
            )

        self._assert_rejected(
            mutate,
            "Apache Phase2 EOS helper has one direct canonical success tail and no dead-code control transfer",
        )

    def test_removed_duplicate_eos_terminal_bridge_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(
                filters,
                "        ap_remove_input_filter(filter);\n"
                "        return apache_input_filter_terminal_error(msr, r,\n"
                "            HTTP_INTERNAL_SERVER_ERROR);\n",
                "        ap_remove_input_filter(filter);\n"
                "        return APR_EGENERAL;\n",
            )

        self._assert_rejected(
            mutate,
            "Apache input-filter errors enter Apache core through the input-side terminal bridge",
        )

    def test_comment_only_eos_helper_token_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(
                filters,
                "            return apache_input_filter_handle_eos(msr, r, f, pbbOut, pbktIn);\n",
                "            return APR_EGENERAL;\n",
            )
            with filters.open("a", encoding="utf-8") as source:
                source.write(
                    "\n/* apache_input_filter_handle_eos(msr, r, f, pbbOut, pbktIn); */\n"
                )

        self._assert_rejected(
            mutate,
            "Apache input-filter errors enter Apache core through the input-side terminal bridge",
        )

    def test_foreign_function_eos_helper_token_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(
                filters,
                "            return apache_input_filter_handle_eos(msr, r, f, pbbOut, pbktIn);\n",
                "            return APR_EGENERAL;\n",
            )
            with filters.open("a", encoding="utf-8") as source:
                source.write(
                    "\nstatic void apache_input_filter_decoy(void)\n"
                    "{\n"
                    "    (void)apache_input_filter_handle_eos(NULL, NULL, NULL, NULL, NULL);\n"
                    "}\n"
                )

        self._assert_rejected(
            mutate,
            "Apache input-filter errors enter Apache core through the input-side terminal bridge",
        )

    def test_prefix_truncation_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(
                filters,
                "            (const unsigned char *)data, len))) {\n",
                "            (const unsigned char *)data, len / 2U))) {\n",
            )

        self._assert_rejected(
            mutate,
            "Apache Phase2 bucket helper validates pointers and arithmetic, records and appends complete chunks, captures intervention, and forwards after native success",
        )

    def test_inverted_shared_request_append_guard_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(filters,
                "!msconnector_native_body_append_can_continue(msc_append_request_body(msr->t,",
                "msconnector_native_body_append_can_continue(msc_append_request_body(msr->t,")
        self._assert_rejected(mutate, "Apache Phase2 bucket helper validates pointers and arithmetic, records and appends complete chunks, captures intervention, and forwards after native success")

    def test_inverted_shared_phase_guard_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(filters,
                "if (!msconnector_native_phase_succeeded(msc_process_request_body(msr->t)))",
                "if (msconnector_native_phase_succeeded(msc_process_request_body(msr->t)))")
        self._assert_rejected(mutate, "Apache Phase2 one-shot gate precedes processing")

    def test_missing_serialization_failure_return_is_rejected(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(filters,
                "        return apache_event_sink_result(msr, r,\n"
                "            json_truncated ? MSCONNECTOR_ERROR_EVENT_TOO_LARGE\n"
                "                : MSCONNECTOR_ERROR_INTERNAL, mandatory);\n",
                "")
        self._assert_rejected(mutate, "Apache P3/P4 events reject serialization failure")

    def test_unchecked_or_incomplete_physical_write_is_rejected(self) -> None:
        for original, changed in (
            ("rc = apr_file_write_full(file, line, length, &written);",
             "(void)apr_file_write_full(file, line, length, &written);"),
            ("rc != APR_SUCCESS || written != length", "rc != APR_SUCCESS"),
            ("close_rc != APR_SUCCESS", "close_rc == APR_SUCCESS"),
        ):
            with self.subTest(original=original):
                def mutate(filters: Path) -> None:
                    replace_once(filters, original, changed)
                self._assert_rejected(mutate, "Apache P3/P4 events reject serialization failure")

    def test_technical_errors_cannot_be_logged_as_rule_blocks(self) -> None:
        def mutate(filters: Path) -> None:
            replace_once(filters,
                "? MSCONNECTOR_STATUS_ERROR : MSCONNECTOR_STATUS_BLOCKED;",
                "? MSCONNECTOR_STATUS_BLOCKED : MSCONNECTOR_STATUS_BLOCKED;")
        self._assert_rejected(mutate, "Apache P3/P4 intervention events distinguish technical errors")

    def test_phase3_response_header_failures_are_not_ignored(self) -> None:
        mutations = (
            (
                "    error_headers_added = apache_add_response_headers(msr, r->err_headers_out);\n",
                "    error_headers_added = 1;\n",
            ),
            (
                "    response_headers_added = apache_add_response_headers(msr, r->headers_out);\n",
                "    response_headers_added = 1;\n",
            ),
            (
                "                (const unsigned char *)content_type) != 1))\n",
                "                (const unsigned char *)content_type) == 1))\n",
            ),
        )

        for original, replacement in mutations:
            with self.subTest(original=original.strip()):
                def mutate(filters: Path) -> None:
                    replace_once(filters, original, replacement)

                self._assert_rejected(
                    mutate,
                    "Apache Phase3 checks both response-header tables",
                )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
