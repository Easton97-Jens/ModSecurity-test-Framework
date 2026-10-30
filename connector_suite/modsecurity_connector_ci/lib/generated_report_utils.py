#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import stat
import inspect
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from modsecurity_connector_ci.lib.verified_run_id import validate_verified_run_id


GENERATED_ROOT = Path("reports/testing/generated")
GENERATED_NOTICE = "Generated file - do not edit manually."
DATA_SOURCE_POLICY = "verified-inputs-only"
_LOCAL_HOME_ROOT = "<local-home-root>"
_PATH_SEPARATOR = "/"
_PUBLIC_VAR_TMP = os.path.join(_PATH_SEPARATOR, "var", "tmp")
_PUBLIC_TMP = os.path.join(_PATH_SEPARATOR, "tmp")
_JSON_SUFFIX = ".json"
_MARKDOWN_SUFFIX = ".md"
_GERMAN_MARKDOWN_SUFFIX = ".de.md"
_FRAMEWORK_REFERENCE_PREFIX = "framework:"
_BUILD_ROOT_REFERENCE_PREFIX = "BUILD_ROOT:"
_REFRESH_CONNECTOR_REPORTS_GENERATOR = "ci/evidence/reports/refresh-connector-reports.py"
_REMAINING_FAILURE_ANALYSIS_GENERATOR = "ci/evidence/reports/generate-remaining-failure-analysis.py"
_FRAMEWORK_CASE_MATRIX_GENERATOR = "framework:ci/reporting/generate-case-matrix.py"
_FRAMEWORK_MRTS_NATIVE_REPORT_GENERATOR = "framework:ci/reporting/generate-mrts-native-report.py"
UNKNOWN_VALUES = {
    "unknown",
    "missing",
    "blocked",
    "skipped",
    "skipped_missing_input",
    "not_run",
    "not_available",
}

# Generated Markdown is committed and reviewed across machines.  Runtime roots
# are intentionally local implementation details, so render them as portable
# references while keeping the raw values available to runtime code and JSON
# evidence producers.  The placeholders are documented in reports/README.*.
_LOCAL_PATH_TOKEN_RE = re.compile(
    r"(?:(?<![A-Za-z0-9_>])|(?<=-I)|(?<=-L))"
    r"(?P<path>/(?:var/tmp|tmp|root|home|Users)(?:/[^\s`<>()\[\]{}|,;]*)?)"
)
_HISTORICAL_RUN_ROOT_RE = re.compile(
    rf"^{re.escape(_PUBLIC_VAR_TMP)}/(?P<run>ModSecurity-conector-(?!verified(?:/|$))[^/]+)(?P<suffix>/.*)?$"
)


def _portable_prefixed_reference(
    raw: str,
    prefixes: tuple[tuple[str, str], ...],
) -> str | None:
    for prefix, replacement in prefixes:
        if raw == prefix or raw.startswith(prefix + _PATH_SEPARATOR):
            return replacement + raw[len(prefix) :]
    return None


def _portable_temporary_reference(raw: str) -> str | None:
    return _portable_prefixed_reference(
        raw,
        (
            (_PUBLIC_VAR_TMP, "<temporary-work-root>"),
            (_PUBLIC_TMP, "<temporary-work-root>"),
        ),
    )


def _portable_home_reference(raw: str) -> str | None:
    if raw == "/root" or raw.startswith("/root/"):
        return _LOCAL_HOME_ROOT + raw[len("/root") :]
    for prefix in ("/home/", "/Users/"):
        if raw.startswith(prefix):
            parts = raw.split(_PATH_SEPARATOR, 3)
            return _LOCAL_HOME_ROOT + (_PATH_SEPARATOR + parts[3] if len(parts) == 4 else "")
    return None


def portable_path_reference(value: str | Path) -> str:
    """Return a human-readable, machine-independent path reference.

    This is a presentation helper only: callers continue to resolve and hash
    the original filesystem path before rendering it.  Keeping the run slug in
    historical references preserves provenance without publishing a developer
    machine's temporary directory.
    """

    raw = str(value)
    known_reference = _portable_prefixed_reference(
        raw,
        (
            ("/root/.local/state/ModSecurity-conector-build", "<local-state-root>"),
            (os.path.join(_PUBLIC_VAR_TMP, "ModSecurity-conector-verified"), "<verified-run-root>"),
            (os.path.join(_PUBLIC_TMP, "ModSecurity-conector-verified"), "<verified-run-root>"),
        ),
    )
    if known_reference is not None:
        return known_reference

    historical = _HISTORICAL_RUN_ROOT_RE.match(raw)
    if historical:
        return f"<historical-run-root:{historical.group('run')}>{historical.group('suffix') or ''}"
    temporary_reference = _portable_temporary_reference(raw)
    if temporary_reference is not None:
        return temporary_reference
    home_reference = _portable_home_reference(raw)
    if home_reference is not None:
        return home_reference
    return raw


def portable_markdown_text(markdown: str) -> str:
    """Replace local filesystem tokens in display text with portable aliases."""

    def replace(match: re.Match[str]) -> str:
        token = match.group("path")
        trailing = ""
        while token and token[-1] in ".,;:!?":
            trailing = token[-1] + trailing
            token = token[:-1]
        return portable_path_reference(token) + trailing

    return _LOCAL_PATH_TOKEN_RE.sub(replace, markdown)


def sanitize_generated_markdown_tree(generated_root: Path) -> list[Path]:
    """Apply presentation-only path normalization to committed report Markdown.

    Some optional or historical report producers are intentionally not rerun by
    a partial refresh.  Their Markdown remains valuable provenance, but local
    filesystem paths must still be portable.  This sweep is idempotent and
    changes only rendered path tokens; it never alters JSON evidence, report
    status, run IDs, or hashes.
    """

    changed: list[Path] = []
    if not generated_root.is_dir():
        return changed
    for path in sorted(generated_root.rglob("*.generated*.md")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        sanitized = portable_markdown_text(text)
        if sanitized == text:
            continue
        path.write_text(sanitized, encoding="utf-8")
        changed.append(path)
    return changed


@dataclass(frozen=True)
class GeneratedReport:
    key: str
    category: str
    stem: str
    formats: tuple[str, ...]
    purpose: str
    kind: str
    generator: str
    make_target: str
    owner: str = "connector"
    severity: str = "informational"
    data_origin: str = "connector"
    data_kind: str = "report"
    commit_policy: str = "versioned-generated"
    inputs: tuple[str, ...] = ()
    requires_runtime: bool = False
    requires_full_matrix: bool = False
    requires_native_mrts: bool = False
    optional: bool = False

    def filename(self, ext: str) -> str:
        clean_ext = ext.removeprefix(".")
        if clean_ext not in self.formats:
            raise ValueError(f"{self.key} does not produce .{clean_ext}")
        return f"{self.stem}.{clean_ext}"


GENERATED_REPORTS: dict[str, GeneratedReport] = {
    "report_refresh_manifest": GeneratedReport(
        "report_refresh_manifest",
        "manifest",
        "report-refresh-manifest.generated",
        ("json", "md"),
        "Canonical catalog of report generators, outputs, inputs, and refresh status.",
        "canonical",
        _REFRESH_CONNECTOR_REPORTS_GENERATOR,
        "refresh-connector-reports",
        owner="manifest",
        severity="critical",
        data_origin="manifest",
        data_kind="manifest",
    ),
    "report_freshness": GeneratedReport(
        "report_freshness",
        "manifest",
        "report-freshness.generated",
        ("json", "md"),
        "Freshness and stale-status report for generated reports.",
        "canonical",
        _REFRESH_CONNECTOR_REPORTS_GENERATOR,
        "refresh-connector-reports",
        owner="manifest",
        severity="important",
        data_origin="manifest",
        data_kind="manifest",
    ),
    "verified_run_manifest": GeneratedReport(
        "verified_run_manifest",
        "manifest",
        "verified-run-manifest.generated",
        ("json", "md"),
        "Verified run manifest with producer, consumer, input, output, and log evidence.",
        "canonical",
        "ci/runtime/lifecycle/run-verified-report-run.py",
        "verified-report-run",
        owner="manifest",
        severity="critical",
        data_origin="manifest",
        data_kind="manifest",
    ),
    "merge_readiness_dashboard": GeneratedReport(
        "merge_readiness_dashboard",
        "manifest",
        "merge-readiness-dashboard.generated",
        ("json", "md"),
        "Top-level merge-readiness dashboard.",
        "canonical",
        _REFRESH_CONNECTOR_REPORTS_GENERATOR,
        "refresh-connector-reports",
        owner="manifest",
        severity="critical",
        data_origin="manifest",
        data_kind="dashboard",
    ),
    "connector_capabilities": GeneratedReport(
        "connector_capabilities",
        "canonical",
        "connector-capabilities.generated",
        ("json", "md"),
        "Canonical capability and evidence-stage declarations for all six connectors.",
        "canonical",
        "ci/evidence/collectors/connector_capabilities.py",
        "capabilities-all-connectors",
        owner="connector",
        severity="informational",
        data_origin="repository",
        data_kind="capability-catalog",
        inputs=tuple(f"connectors/{name}/capabilities.json" for name in ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")),
        requires_runtime=False,
        requires_full_matrix=False,
    ),
    "verified_runtime_mismatch_analysis": GeneratedReport(
        "verified_runtime_mismatch_analysis",
        "manifest",
        "verified-runtime-mismatch-analysis.generated",
        ("json", "md"),
        "Verified runtime mismatch analysis from producer result files.",
        "canonical",
        "ci/evidence/reports/generate-verified-runtime-mismatch-analysis.py",
        "generate-verified-runtime-mismatch-analysis",
        owner="manifest",
        severity="critical",
        data_origin="runtime",
        data_kind="analysis",
        requires_runtime=True,
    ),
    "remaining_critical_batch_analysis": GeneratedReport(
        "remaining_critical_batch_analysis",
        "manifest",
        "remaining-critical-batch-analysis.generated",
        ("json", "md"),
        "Batch analysis for selected remaining critical mismatch clusters.",
        "canonical",
        "ci/evidence/reports/generate-remaining-critical-batch-analysis.py",
        "generate-remaining-critical-batch-analysis",
        owner="manifest",
        severity="important",
        data_origin="runtime",
        data_kind="analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "native_semantics_comparison": GeneratedReport(
        "native_semantics_comparison",
        "manifest",
        "native-semantics-comparison.generated",
        ("json", "md"),
        "Targeted connector-free libmodsecurity native semantics comparison.",
        "canonical",
        "ci/runtime/lifecycle/run-native-case-comparison.py",
        "generate-native-semantics-comparison",
        owner="manifest",
        severity="important",
        data_origin="native",
        data_kind="analysis",
        requires_runtime=True,
        requires_full_matrix=True,
        optional=True,
    ),
    "full_matrix_job_completeness": GeneratedReport(
        "full_matrix_job_completeness",
        "manifest",
        "full-matrix-job-completeness.generated",
        ("json", "md"),
        "Full-matrix job completeness, missing-job, and slow-job evidence.",
        "canonical",
        "ci/evidence/reports/generate-full-matrix-job-completeness.py",
        "generate-full-matrix-job-completeness",
        owner="manifest",
        severity="critical",
        data_origin="runtime",
        data_kind="analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "nginx_mrts_http500_cluster_analysis": GeneratedReport(
        "nginx_mrts_http500_cluster_analysis",
        "manifest",
        "nginx-mrts-http500-cluster-analysis.generated",
        ("json", "md"),
        "NGINX with-crs/with-mrts HTTP-500 cluster root-cause analysis.",
        "canonical",
        "ci/evidence/reports/generate-nginx-mrts-http500-cluster-analysis.py",
        "generate-nginx-mrts-http500-cluster-analysis",
        owner="manifest",
        severity="critical",
        data_origin="runtime",
        data_kind="analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "system_environment_proof": GeneratedReport(
        "system_environment_proof",
        "manifest",
        "system-environment-proof.generated",
        ("json", "md"),
        "System, tool-version, git, and check-execution proof.",
        "canonical",
        "ci/evidence/reports/generate-system-environment-proof.py",
        "generate-system-environment-proof",
        owner="system",
        severity="critical",
        data_origin="external-local",
        data_kind="system-proof",
    ),
    "full_runtime_matrix": GeneratedReport(
        "full_runtime_matrix",
        "canonical",
        "full-runtime-matrix.generated",
        ("json", "md"),
        "Complete connector full-runtime matrix summary.",
        "canonical",
        "ci/evidence/reports/generate-full-runtime-matrix.py",
        "generate-full-runtime-matrix",
        severity="critical",
        data_origin="runtime",
        data_kind="matrix",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "full_run_evidence": GeneratedReport(
        "full_run_evidence",
        "canonical",
        "full-run-evidence.generated",
        ("json", "md"),
        "Evidence rollup shared by focused analysis and consistency checks.",
        "canonical",
        _REMAINING_FAILURE_ANALYSIS_GENERATOR,
        "refresh-connector-reports",
        severity="critical",
        data_origin="runtime",
        data_kind="evidence",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "final_consistency_audit": GeneratedReport(
        "final_consistency_audit",
        "canonical",
        "final-consistency-audit.generated",
        ("json", "md"),
        "Merge-readiness consistency gate across generated evidence.",
        "canonical",
        "ci/evidence/reports/generate-final-consistency-audit.py",
        "generate-final-consistency-audit",
        severity="critical",
        data_origin="connector",
        data_kind="evidence",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "remaining_failure_analysis": GeneratedReport(
        "remaining_failure_analysis",
        "canonical",
        "remaining-failure-analysis.generated",
        ("json", "md"),
        "Remaining failure clustering and classification.",
        "canonical",
        _REMAINING_FAILURE_ANALYSIS_GENERATOR,
        "generate-remaining-failure-analysis",
        severity="important",
        data_origin="runtime",
        data_kind="focused-analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "next_fix_plan": GeneratedReport(
        "next_fix_plan",
        "canonical",
        "next-fix-plan.generated",
        ("json", "md"),
        "Current recommended next fix cluster.",
        "canonical",
        _REMAINING_FAILURE_ANALYSIS_GENERATOR,
        "generate-remaining-failure-analysis",
        severity="important",
        data_origin="runtime",
        data_kind="focused-analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "connector_work_queue": GeneratedReport(
        "connector_work_queue",
        "work-queues",
        "connector-work-queue.generated",
        ("json", "md"),
        "Connector-scoped queue and classification state.",
        "focused",
        "framework:ci/reporting/generate-connector-work-queue.py",
        "generate-work-queue",
        owner="framework",
        severity="important",
        data_origin="framework",
        data_kind="work-queue",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "phase_work_queue": GeneratedReport(
        "phase_work_queue",
        "work-queues",
        "phase-work-queue.generated",
        ("json", "md"),
        "Phase-scoped queue and classification state.",
        "focused",
        "framework:ci/reporting/generate-phase-work-queue.py",
        "generate-phase-work-queue",
        owner="framework",
        severity="important",
        data_origin="framework",
        data_kind="work-queue",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "case_matrix": GeneratedReport(
        "case_matrix",
        "coverage",
        "case-matrix.generated",
        ("md",),
        "Framework/connector case matrix.",
        "focused",
        _FRAMEWORK_CASE_MATRIX_GENERATOR,
        "generate-test-matrix",
        owner="framework",
        data_origin="framework",
        data_kind="report",
        requires_runtime=True,
    ),
    "connector_gap_summary": GeneratedReport(
        "connector_gap_summary",
        "coverage",
        "connector-gap-summary.generated",
        ("md",),
        "Connector gap summary.",
        "focused",
        _FRAMEWORK_CASE_MATRIX_GENERATOR,
        "generate-test-matrix",
        owner="framework",
        data_origin="framework",
        data_kind="report",
        requires_runtime=True,
    ),
    "coverage_summary": GeneratedReport(
        "coverage_summary",
        "coverage",
        "coverage-summary.generated",
        ("md",),
        "Coverage summary by scope, status, runtime, phase, and variable.",
        "focused",
        _FRAMEWORK_CASE_MATRIX_GENERATOR,
        "generate-test-matrix",
        owner="framework",
        data_origin="framework",
        data_kind="report",
        requires_runtime=True,
    ),
    "phase_coverage": GeneratedReport(
        "phase_coverage",
        "coverage",
        "phase-coverage.generated",
        ("md",),
        "Phase coverage summary.",
        "focused",
        _FRAMEWORK_CASE_MATRIX_GENERATOR,
        "generate-test-matrix",
        owner="framework",
        data_origin="framework",
        data_kind="report",
        requires_runtime=True,
    ),
    "xfail_summary": GeneratedReport(
        "xfail_summary",
        "coverage",
        "xfail-summary.generated",
        ("md",),
        "Expected-failure and import-status summary.",
        "focused",
        _FRAMEWORK_CASE_MATRIX_GENERATOR,
        "generate-test-matrix",
        owner="framework",
        data_origin="framework",
        data_kind="report",
        requires_runtime=True,
    ),
    "body_processor_analysis": GeneratedReport(
        "body_processor_analysis",
        "focused-analysis",
        "body-processor-analysis.generated",
        ("json", "md"),
        "Request-body, multipart, and XML processor classification.",
        "focused",
        "ci/evidence/reports/generate-body-processor-analysis.py",
        "generate-body-processor-analysis",
        data_kind="focused-analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "intervention_blocking_analysis": GeneratedReport(
        "intervention_blocking_analysis",
        "focused-analysis",
        "intervention-blocking-analysis.generated",
        ("json", "md"),
        "Intervention blocking classification and no-match separation.",
        "focused",
        "ci/evidence/reports/generate-intervention-blocking-analysis.py",
        "generate-intervention-blocking-analysis",
        data_kind="focused-analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "no_mrts_intervention_nomatch_analysis": GeneratedReport(
        "no_mrts_intervention_nomatch_analysis",
        "focused-analysis",
        "no-mrts-intervention-nomatch-analysis.generated",
        ("json", "md"),
        "Framework-owned no-MRTS no-match semantics.",
        "focused",
        "ci/evidence/reports/generate-no-mrts-intervention-nomatch-analysis.py",
        "generate-no-mrts-intervention-nomatch-analysis",
        data_kind="focused-analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "nolog_audit_evidence": GeneratedReport(
        "nolog_audit_evidence",
        "focused-analysis",
        "nolog-audit-evidence.generated",
        ("json", "md"),
        "Explicit nolog audit-evidence classification.",
        "focused",
        "ci/evidence/reports/generate-nolog-audit-evidence-analysis.py",
        "generate-nolog-audit-evidence-analysis",
        data_kind="focused-analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "phase4_hard_abort_capability": GeneratedReport(
        "phase4_hard_abort_capability",
        "focused-analysis",
        "phase4-hard-abort-capability.generated",
        ("json", "md"),
        "Phase 4 hard-abort capability evidence.",
        "focused",
        "ci/evidence/reports/generate-phase4-hard-abort-capability.py",
        "generate-phase4-hard-abort-capability",
        data_kind="focused-analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "response_header_hook_analysis": GeneratedReport(
        "response_header_hook_analysis",
        "focused-analysis",
        "response-header-hook-analysis.generated",
        ("json", "md"),
        "Response-header hook and backend setup analysis.",
        "focused",
        "ci/evidence/reports/generate-response-header-hook-analysis.py",
        "generate-response-header-hook-analysis",
        data_kind="focused-analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "rule_chain_semantics_analysis": GeneratedReport(
        "rule_chain_semantics_analysis",
        "focused-analysis",
        "rule-chain-semantics-analysis.generated",
        ("json", "md"),
        "Rule-chain semantics and runtime-fixability analysis.",
        "focused",
        "ci/evidence/reports/generate-rule-chain-semantics-analysis.py",
        "generate-rule-chain-semantics-analysis",
        data_kind="focused-analysis",
        requires_runtime=True,
        requires_full_matrix=True,
    ),
    "apache_runtime_results": GeneratedReport(
        "apache_runtime_results",
        "runtime",
        "apache-runtime-results.generated",
        ("md",),
        "Apache runtime result details.",
        "runtime",
        _FRAMEWORK_CASE_MATRIX_GENERATOR,
        "generate-test-matrix",
        owner="runtime",
        data_origin="runtime",
        data_kind="report",
        requires_runtime=True,
    ),
    "nginx_runtime_results": GeneratedReport(
        "nginx_runtime_results",
        "runtime",
        "nginx-runtime-results.generated",
        ("md",),
        "NGINX runtime result details.",
        "runtime",
        _FRAMEWORK_CASE_MATRIX_GENERATOR,
        "generate-test-matrix",
        owner="runtime",
        data_origin="runtime",
        data_kind="report",
        requires_runtime=True,
    ),
    "haproxy_runtime_results": GeneratedReport(
        "haproxy_runtime_results",
        "runtime",
        "haproxy-runtime-results.generated",
        ("md",),
        "HAProxy runtime result details.",
        "runtime",
        _FRAMEWORK_CASE_MATRIX_GENERATOR,
        "generate-test-matrix",
        owner="runtime",
        data_origin="runtime",
        data_kind="report",
        requires_runtime=True,
    ),
    "runtime_matrix": GeneratedReport(
        "runtime_matrix",
        "runtime",
        "runtime-matrix.generated",
        ("md",),
        "Default runtime matrix summary.",
        "runtime",
        _FRAMEWORK_CASE_MATRIX_GENERATOR,
        "generate-test-matrix",
        owner="runtime",
        data_origin="runtime",
        data_kind="matrix",
        requires_runtime=True,
    ),
    "mrts_native_full": GeneratedReport(
        "mrts_native_full",
        "mrts-native",
        "mrts-native-full.generated",
        ("json", "md"),
        "Combined native MRTS infrastructure evidence.",
        "optional",
        _FRAMEWORK_MRTS_NATIVE_REPORT_GENERATOR,
        "mrts-native-full-run",
        owner="mrts",
        severity="optional",
        data_origin="mrts",
        data_kind="evidence",
        commit_policy="optional-generated",
        requires_native_mrts=True,
        optional=True,
    ),
    "mrts_native_apache": GeneratedReport(
        "mrts_native_apache",
        "mrts-native",
        "mrts-native-apache.generated",
        ("json", "md"),
        "Apache native MRTS infrastructure evidence.",
        "optional",
        _FRAMEWORK_MRTS_NATIVE_REPORT_GENERATOR,
        "mrts-native-full-run",
        owner="mrts",
        severity="optional",
        data_origin="mrts",
        data_kind="evidence",
        commit_policy="optional-generated",
        requires_native_mrts=True,
        optional=True,
    ),
    "mrts_native_nginx": GeneratedReport(
        "mrts_native_nginx",
        "mrts-native",
        "mrts-native-nginx.generated",
        ("json", "md"),
        "NGINX native MRTS infrastructure evidence.",
        "optional",
        _FRAMEWORK_MRTS_NATIVE_REPORT_GENERATOR,
        "mrts-native-full-run",
        owner="mrts",
        severity="optional",
        data_origin="mrts",
        data_kind="evidence",
        commit_policy="optional-generated",
        requires_native_mrts=True,
        optional=True,
    ),
    "mrts_native_summary": GeneratedReport(
        "mrts_native_summary",
        "mrts-native",
        "mrts-native-summary.generated",
        ("json", "md"),
        "Native MRTS summary.",
        "optional",
        _FRAMEWORK_MRTS_NATIVE_REPORT_GENERATOR,
        "mrts-native-full-run",
        owner="mrts",
        severity="optional",
        data_origin="mrts",
        data_kind="evidence",
        commit_policy="optional-generated",
        requires_native_mrts=True,
        optional=True,
    ),
    "runtime_build_cache": GeneratedReport(
        "runtime_build_cache",
        "cache",
        "runtime-build-cache.generated",
        ("json", "md"),
        "Runtime build-cache report.",
        "cache",
        "ci/provisioning/components/prepare-runtime-components.py",
        "prepare-runtime-components",
        owner="cache",
        severity="cache",
        data_origin="cache",
        data_kind="cache",
        commit_policy="local-only",
        requires_runtime=True,
        optional=True,
    ),
    "runtime_component_cache": GeneratedReport(
        "runtime_component_cache",
        "cache",
        "runtime-component-cache.generated",
        ("json", "md"),
        "Runtime component-cache report.",
        "cache",
        "ci/provisioning/components/prepare-runtime-components.py",
        "prepare-runtime-components",
        owner="cache",
        severity="cache",
        data_origin="cache",
        data_kind="cache",
        commit_policy="local-only",
        requires_runtime=True,
        optional=True,
    ),
    "runtime_cache_index": GeneratedReport(
        "runtime_cache_index",
        "cache",
        "runtime-cache-index.generated",
        ("json", "md"),
        "Runtime cache provenance index.",
        "cache",
        "ci/evidence/reports/update-runtime-reports.py",
        "prepare-runtime-components",
        owner="cache",
        severity="cache",
        data_origin="cache",
        data_kind="cache-index",
        commit_policy="versioned-generated",
        requires_runtime=True,
        optional=True,
    ),
}

FILENAME_TO_KEY = {
    report.filename(ext): key
    for key, report in GENERATED_REPORTS.items()
    for ext in report.formats
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def current_verified_run_id(connector_root: Path | None = None) -> str:
    value = os.environ.get("VERIFIED_RUN_ID", "")
    if value:
        return validate_verified_run_id(value)
    stamp = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H-%M-%SZ")
    sha = git_sha(connector_root) if connector_root is not None else "unknown"
    if not sha or sha == "unknown":
        return f"{stamp}-unknown"
    return f"{stamp}-{sha[:8]}"


def git_worktree_root(root: Path | None) -> Path | None:
    """Return ``root`` only when it is itself a checked-out Git worktree.

    ``git -C <empty-submodule-directory>`` silently walks upward to the Parent
    repository.  Generated evidence must never relabel that Parent revision as
    Framework provenance, so callers first require Git's reported worktree
    root to equal the requested path.
    """

    if root is None:
        return None
    try:
        expected_root = root.resolve(strict=True)
        result = subprocess.run(
            ["git", "-C", str(expected_root), "rev-parse", "--show-toplevel"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    try:
        actual_root = Path(result.stdout.strip()).resolve(strict=True)
    except (OSError, ValueError):
        return None
    if actual_root != expected_root:
        return None
    return expected_root


def git_sha(root: Path | None) -> str:
    checkout_root = git_worktree_root(root)
    if checkout_root is None:
        return "unknown"
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout_root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except Exception:
        return "unknown"
    return result.stdout.strip() or "unknown"


def git_dirty(root: Path | None) -> str:
    checkout_root = git_worktree_root(root)
    if checkout_root is None:
        return "unknown"
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout_root), "status", "--short"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except Exception:
        return "unknown"
    return "dirty" if result.stdout.strip() else "clean"


def gitlink_sha(connector_root: Path, nested_root: Path | None) -> str:
    """Read a nested repository's recorded gitlink without checking it out."""

    parent_root = git_worktree_root(connector_root)
    if parent_root is None or nested_root is None:
        return "unknown"
    try:
        relative = nested_root.resolve(strict=False).relative_to(parent_root)
    except (OSError, ValueError):
        return "unknown"
    try:
        result = subprocess.run(
            ["git", "-C", str(parent_root), "ls-tree", "HEAD", "--", relative.as_posix()],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except Exception:
        return "unknown"
    fields = result.stdout.strip().split(None, 2)
    if len(fields) != 3 or fields[0] != "160000" or fields[1] != "commit":
        return "unknown"
    candidate = fields[2].split("\t", 1)[0]
    return candidate if re.fullmatch(r"[0-9a-f]{40}", candidate) else "unknown"


def framework_provenance(
    connector_root: Path,
    framework_root: Path | None,
) -> dict[str, str]:
    """Describe Framework provenance without a Parent-worktree fallback."""

    if framework_root is None:
        return {
            "sha": "unknown",
            "gitlink_sha": "unknown",
            "checkout_status": "not_configured",
            "gitlink_status": "unknown",
            "working_tree_dirty": "unknown",
        }
    recorded_gitlink = gitlink_sha(connector_root, framework_root)
    if git_worktree_root(framework_root) is not None:
        checkout_sha = git_sha(framework_root)
        if recorded_gitlink == "unknown":
            gitlink_status = "not_a_gitlink"
        elif recorded_gitlink == checkout_sha:
            gitlink_status = "matches_checkout"
        else:
            gitlink_status = "checkout_mismatch"
        return {
            "sha": checkout_sha,
            "gitlink_sha": recorded_gitlink,
            "checkout_status": "checked_out",
            "gitlink_status": gitlink_status,
            "working_tree_dirty": git_dirty(framework_root),
        }
    if recorded_gitlink != "unknown":
        return {
            "sha": "unknown",
            "gitlink_sha": recorded_gitlink,
            "checkout_status": "not_checked_out",
            "gitlink_status": "not_checked_out",
            "working_tree_dirty": "unknown",
        }
    return {
        "sha": "unknown",
        "gitlink_sha": "unknown",
        "checkout_status": "unavailable",
        "gitlink_status": "unknown",
        "working_tree_dirty": "unknown",
    }


def infer_framework_root(connector_root: Path, framework_root: Path | None = None) -> Path | None:
    if framework_root is not None:
        return framework_root
    return connector_root / "modules/ModSecurity-test-Framework"


def is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)
    except OSError:
        return False


def report_key_for_filename(filename: str | Path) -> str:
    name = Path(filename).name
    key = FILENAME_TO_KEY.get(name)
    if not key:
        raise KeyError(f"unknown generated report filename: {name}")
    return key


def generated_root(connector_root: Path) -> Path:
    return connector_root / GENERATED_ROOT


def report_filename(key: str, ext: str) -> str:
    return GENERATED_REPORTS[key].filename(ext)


def report_relpath(key: str, ext: str) -> str:
    report = GENERATED_REPORTS[key]
    return str(GENERATED_ROOT / report.category / report.filename(ext))


def report_path(connector_root: Path, key: str, ext: str) -> Path:
    return connector_root / report_relpath(key, ext)


def report_path_from_root(report_root: Path, key: str, ext: str) -> Path:
    report = GENERATED_REPORTS[key]
    return report_root / report.category / report.filename(ext)


def report_relpath_for_filename(filename: str | Path) -> str:
    key = report_key_for_filename(filename)
    ext = Path(filename).suffix.removeprefix(".")
    return report_relpath(key, ext)


def report_path_for_filename(report_root: Path, filename: str | Path) -> Path:
    key = report_key_for_filename(filename)
    ext = Path(filename).suffix.removeprefix(".")
    return report_path_from_root(report_root, key, ext)


def legacy_report_relpath(key: str, ext: str) -> str:
    return str(GENERATED_ROOT / GENERATED_REPORTS[key].filename(ext))


def legacy_report_path(connector_root: Path, key: str, ext: str) -> Path:
    return connector_root / legacy_report_relpath(key, ext)


def rewrite_generated_relpath(value: str | Path) -> str:
    text = str(value)
    prefix = GENERATED_ROOT.as_posix() + "/"
    if not text.startswith(prefix):
        return text
    rest = text[len(prefix) :]
    if "/" in rest:
        return text
    try:
        return report_relpath_for_filename(rest)
    except KeyError:
        return text


def generated_report_outputs(keys: Iterable[str]) -> tuple[str, ...]:
    outputs: list[str] = []
    for key in keys:
        report = GENERATED_REPORTS[key]
        outputs.extend(report_relpath(key, ext) for ext in report.formats)
    return tuple(outputs)


def report_outputs(key: str) -> tuple[str, ...]:
    report = GENERATED_REPORTS[key]
    return tuple(report_relpath(key, ext) for ext in report.formats)


def registry_record(key: str) -> dict[str, Any]:
    report = GENERATED_REPORTS[key]
    return {
        "key": report.key,
        "category": report.category,
        "owner": report.owner,
        "severity": report.severity,
        "stem": report.stem,
        "formats": list(report.formats),
        "purpose": report.purpose,
        "kind": report.kind,
        "generator": report.generator,
        "make_target": report.make_target,
        "inputs": list(report.inputs),
        "outputs": list(report_outputs(key)),
        "data_origin": report.data_origin,
        "data_kind": report.data_kind,
        "commit_policy": report.commit_policy,
        "runtime_required": report.requires_runtime,
        "full_matrix_required": report.requires_full_matrix,
        "native_mrts_required": report.requires_native_mrts,
        "optional": report.optional,
    }


def infer_report_key(generated_by: str, make_target: str) -> str | None:
    matches = [
        key
        for key, report in GENERATED_REPORTS.items()
        if report.generator == generated_by and report.make_target == make_target
    ]
    if not matches and not generated_by.startswith(_FRAMEWORK_REFERENCE_PREFIX):
        framework_generated_by = f"{_FRAMEWORK_REFERENCE_PREFIX}{generated_by}"
        matches = [
            key
            for key, report in GENERATED_REPORTS.items()
            if report.generator == framework_generated_by and report.make_target == make_target
        ]
    if not matches:
        return None
    severity_order = {"critical": 0, "important": 1, "informational": 2, "optional": 3, "cache": 4, "debug": 5}
    matches.sort(key=lambda key: (severity_order.get(GENERATED_REPORTS[key].severity, 99), key))
    return matches[0]


def display_path(path: Path, connector_root: Path, framework_root: Path | None = None, build_root: Path | None = None) -> str:
    resolved = path.resolve(strict=False)
    roots: list[tuple[Path, str]] = [(connector_root.resolve(strict=False), "")]
    if framework_root is not None:
        roots.append((framework_root.resolve(strict=False), _FRAMEWORK_REFERENCE_PREFIX))
    if build_root is not None:
        roots.append((build_root.resolve(strict=False), _BUILD_ROOT_REFERENCE_PREFIX))
    for root, prefix in roots:
        try:
            return prefix + str(resolved.relative_to(root))
        except ValueError:
            continue
    return portable_path_reference(path)


def resolve_input_reference(
    raw: str | Path,
    connector_root: Path,
    framework_root: Path | None = None,
    build_root: Path | None = None,
) -> Path:
    text = str(raw)
    if text.startswith(_FRAMEWORK_REFERENCE_PREFIX) and framework_root is not None:
        return framework_root / text.removeprefix(_FRAMEWORK_REFERENCE_PREFIX)
    if text.startswith(_BUILD_ROOT_REFERENCE_PREFIX) and build_root is not None:
        return build_root / text.removeprefix(_BUILD_ROOT_REFERENCE_PREFIX)
    path = Path(text)
    if path.is_absolute():
        return path
    rewritten = rewrite_generated_relpath(text)
    return connector_root / rewritten


def _report_status(path: Path, metadata: dict[str, Any]) -> str:
    if path.suffix != _JSON_SUFFIX:
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("status") or metadata.get("run_status") or "")


def _report_provenance(metadata: dict[str, Any]) -> dict[str, str]:
    fields = (
        "verified_run_id",
        "connector_sha",
        "framework_sha",
        "framework_gitlink_sha",
        "framework_checkout_status",
        "framework_gitlink_status",
    )
    return {
        field: str(metadata.get(field) or "")
        for field in fields
        if metadata.get(field)
    }


def _source_expects_framework(provenance: dict[str, str]) -> bool:
    return any(
        (
            provenance.get("framework_sha") not in {None, "", "unknown"},
            provenance.get("framework_gitlink_sha") not in {None, "", "unknown"},
            provenance.get("framework_checkout_status") in {"checked_out", "not_checked_out"},
            provenance.get("framework_gitlink_status")
            in {"matches_checkout", "checkout_mismatch", "not_checked_out"},
        )
    )


def _framework_staleness_reasons(
    provenance: dict[str, str],
    current_framework: dict[str, str],
) -> list[str]:
    if not _source_expects_framework(provenance):
        return []

    reasons = _source_framework_staleness_reasons(provenance)
    reasons.extend(_current_framework_staleness_reasons(provenance, current_framework))
    reasons.extend(_framework_revision_staleness_reasons(provenance, current_framework))
    return reasons


def _source_framework_staleness_reasons(provenance: dict[str, str]) -> list[str]:
    reasons: list[str] = []
    source_checkout = provenance.get("framework_checkout_status", "")
    source_gitlink = provenance.get("framework_gitlink_status", "")
    if source_checkout and source_checkout != "checked_out":
        reasons.append(f"source framework checkout is not verified ({source_checkout})")
    if source_gitlink == "checkout_mismatch":
        reasons.append("source framework checkout differs from its recorded gitlink")
    return reasons


def _current_framework_staleness_reasons(
    provenance: dict[str, str],
    current_framework: dict[str, str],
) -> list[str]:
    reasons: list[str] = []
    current_checkout = current_framework["checkout_status"]
    current_gitlink = current_framework["gitlink_status"]
    if current_checkout != "checked_out":
        reasons.append(f"framework checkout is not verified ({current_checkout})")
    elif current_gitlink == "checkout_mismatch":
        reasons.append("framework checkout differs from its recorded gitlink")
    elif (
        provenance.get("framework_gitlink_sha", "") not in {"", "unknown"}
        and current_gitlink != "matches_checkout"
    ):
        reasons.append("framework gitlink is not verified")
    return reasons


def _framework_revision_staleness_reasons(
    provenance: dict[str, str],
    current_framework: dict[str, str],
) -> list[str]:
    reasons: list[str] = []
    source_sha = provenance.get("framework_sha", "")
    source_gitlink_sha = provenance.get("framework_gitlink_sha", "")
    current_sha = current_framework["sha"]
    if source_sha not in {"", "unknown"} and current_sha != "unknown" and source_sha != current_sha:
        reasons.append("framework_sha differs")
    current_gitlink_sha = current_framework["gitlink_sha"]
    if (
        source_gitlink_sha not in {"", "unknown"}
        and current_gitlink_sha not in {"", "unknown"}
        and source_gitlink_sha != current_gitlink_sha
    ):
        reasons.append("framework_gitlink_sha differs")
    return reasons


def _report_staleness_reasons(
    provenance: dict[str, str],
    expected_verified_run_id: str,
    connector_root: Path,
    framework_root: Path | None,
) -> list[str]:
    reasons: list[str] = []
    source_run_id = provenance.get("verified_run_id", "")
    if source_run_id and source_run_id != expected_verified_run_id:
        reasons.append("verified_run_id differs")
    source_connector_sha = provenance.get("connector_sha", "")
    current_connector_sha = git_sha(connector_root)
    if source_connector_sha and current_connector_sha != "unknown" and source_connector_sha != current_connector_sha:
        reasons.append("connector_sha differs")
    current_framework = framework_provenance(connector_root, framework_root)
    reasons.extend(_framework_staleness_reasons(provenance, current_framework))
    return reasons


def _unusable_source_status(status: str) -> bool:
    return (
        status in {"blocked", "failed", "interrupted"}
        or status.startswith("blocked")
        or status.startswith("skipped")
    )


def _apply_report_input_status(
    record: dict[str, str],
    path: Path,
    expected_verified_run_id: str,
    connector_root: Path,
    framework_root: Path | None,
) -> None:
    metadata = read_report_metadata(path)
    provenance = _report_provenance(metadata)
    record.update(provenance)
    stale_reasons = _report_staleness_reasons(
        provenance, expected_verified_run_id, connector_root, framework_root
    )
    source_run_id = provenance.get("verified_run_id", "")
    source_status = _report_status(path, metadata)
    if stale_reasons:
        record["status"] = "stale"
        record["notes"] = "generated report input is stale: " + "; ".join(stale_reasons)
    elif not source_run_id:
        record["status"] = "stale"
        record["notes"] = "generated report input has no verified_run_id"
    elif source_status and _unusable_source_status(source_status):
        record["status"] = "blocked" if source_status.startswith("blocked") else source_status
        record["notes"] = f"generated report input is not usable: status={source_status}"


def _regular_input_record(
    path: Path,
    shown: str,
    expected_verified_run_id: str,
    connector_root: Path,
    framework_root: Path | None,
) -> dict[str, str]:
    try:
        if path.stat().st_size == 0:
            file_hash = sha256_file(path)
            return {
                "path": shown,
                "status": "empty",
                "sha256": file_hash,
                "source_hash": file_hash,
                "notes": "input file exists but is empty",
            }
    except OSError as exc:
        return {"path": shown, "status": "unknown", "notes": f"could not stat input: {exc}"}
    file_hash = sha256_file(path)
    record = {
        "path": shown,
        "status": "present",
        "sha256": file_hash,
        "source_hash": file_hash,
        "notes": "input file available",
    }
    if path.name in FILENAME_TO_KEY:
        _apply_report_input_status(
            record, path, expected_verified_run_id, connector_root, framework_root
        )
    return record


def _directory_input_record(path: Path, shown: str) -> dict[str, str]:
    try:
        if not any(path.iterdir()):
            return {"path": shown, "status": "empty", "notes": "input directory exists but is empty"}
    except OSError as exc:
        return {"path": shown, "status": "unknown", "notes": f"could not inspect input directory: {exc}"}
    return {
        "path": shown,
        "status": "present",
        "source_hash": directory_fingerprint(path),
        "notes": "input directory available",
    }


def input_record(
    raw: str | Path,
    connector_root: Path,
    framework_root: Path | None = None,
    build_root: Path | None = None,
) -> dict[str, str]:
    expected_verified_run_id = current_verified_run_id(connector_root)
    effective_framework_root = infer_framework_root(connector_root, framework_root)
    try:
        path = resolve_input_reference(raw, connector_root, effective_framework_root, build_root)
    except Exception as exc:
        return {"path": str(raw), "status": "unknown", "notes": f"could not resolve input: {exc}"}
    shown = display_path(path, connector_root, effective_framework_root, build_root)
    if not path.exists():
        return {"path": shown, "status": "missing", "notes": "input file missing"}
    if is_regular_file(path):
        return _regular_input_record(
            path, shown, expected_verified_run_id, connector_root, effective_framework_root
        )
    if path.is_dir():
        return _directory_input_record(path, shown)
    return {"path": shown, "status": "unknown", "notes": "input exists but is not a regular file or directory"}


def input_records(
    raw_inputs: Iterable[str | Path],
    connector_root: Path,
    framework_root: Path | None = None,
    build_root: Path | None = None,
) -> list[dict[str, str]]:
    return [input_record(raw, connector_root, framework_root, build_root) for raw in raw_inputs]


def input_status_summary(records: list[dict[str, str]]) -> str:
    if not records:
        return "unknown"
    statuses = [record.get("status", "unknown") for record in records]
    if any(status in {"blocked", "failed", "interrupted"} or status.startswith("blocked") or status.startswith("skipped") for status in statuses):
        return "blocked"
    if any(status == "stale" for status in statuses):
        return "stale"
    if all(status in {"missing", "empty"} for status in statuses):
        return "missing"
    if any(status in {"missing", "empty", "unknown", "stale", "blocked", "failed", "interrupted"} or status.startswith("blocked") or status.startswith("skipped") for status in statuses):
        return "partial"
    return "complete"


def build_metadata(
    *,
    generated_by: str,
    make_target: str,
    connector_root: Path,
    framework_root: Path | None = None,
    inputs: Iterable[str | Path] = (),
    generated_at: str | None = None,
    report_key: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    framework_root = infer_framework_root(connector_root, framework_root)
    framework = framework_provenance(connector_root, framework_root)
    records = input_records(inputs, connector_root, framework_root)
    registry_key = report_key or infer_report_key(generated_by, make_target)
    registry = registry_record(registry_key) if registry_key else {}
    metadata: dict[str, Any] = {
        "generated_notice": GENERATED_NOTICE,
        "generated_at": generated_at or utc_now(),
        "verified_run_id": current_verified_run_id(connector_root),
        "data_source_policy": DATA_SOURCE_POLICY,
        "generated_by": generated_by,
        "make_target": make_target,
        "report_key": registry_key or "unknown",
        "category": registry.get("category", "unknown"),
        "owner": registry.get("owner", "unknown"),
        "severity": registry.get("severity", "unknown"),
        "data_origin": registry.get("data_origin", "unknown"),
        "data_kind": registry.get("data_kind", "unknown"),
        "commit_policy": registry.get("commit_policy", "unknown"),
        "connector_sha": git_sha(connector_root),
        "framework_sha": framework["sha"],
        "framework_gitlink_sha": framework["gitlink_sha"],
        "framework_checkout_status": framework["checkout_status"],
        "framework_gitlink_status": framework["gitlink_status"],
        "working_tree_dirty": git_dirty(connector_root),
        "framework_working_tree_dirty": framework["working_tree_dirty"],
        "input_status": input_status_summary(records),
        "inputs": records,
        "missing_inputs": [record["path"] for record in records if record["status"] == "missing"],
        "empty_inputs": [record["path"] for record in records if record["status"] == "empty"],
        "unknown_inputs": [record["path"] for record in records if record["status"] == "unknown"],
        "schema_version": 1,
    }
    if extra:
        metadata.update(extra)
    if report_key and "output_name" not in metadata:
        report = GENERATED_REPORTS.get(report_key)
        if report is not None and "md" in report.formats:
            metadata["output_name"] = report.filename("md")
    return metadata


def attach_metadata(payload: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["metadata"] = metadata
    result.setdefault("generated_at", metadata["generated_at"])
    return result


def generated_json_text(payload: dict[str, Any], metadata: dict[str, Any]) -> str:
    return json.dumps(attach_metadata(payload, metadata), indent=2, sort_keys=True) + "\n"


def metadata_block(metadata: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"> {GENERATED_NOTICE}",
            ">",
            f"> Generated at: `{metadata.get('generated_at', 'unknown')}`",
            f"> Verified run id: `{metadata.get('verified_run_id', 'unknown')}`",
            f"> Data source policy: `{metadata.get('data_source_policy', DATA_SOURCE_POLICY)}`",
            f"> Generator: `{metadata.get('generated_by', 'unknown')}`",
            f"> Make target: `{metadata.get('make_target', 'unknown')}`",
            f"> Owner: `{metadata.get('owner', 'unknown')}`",
            f"> Severity: `{metadata.get('severity', 'unknown')}`",
            f"> Connector SHA: `{metadata.get('connector_sha', 'unknown')}`",
            f"> Framework SHA: `{metadata.get('framework_sha', 'unknown')}`",
            f"> Framework gitlink SHA: `{metadata.get('framework_gitlink_sha', 'unknown')}`",
            f"> Framework checkout: `{metadata.get('framework_checkout_status', 'unknown')}`",
            f"> Framework gitlink status: `{metadata.get('framework_gitlink_status', 'unknown')}`",
            *([f"> MRTS SHA: `{metadata.get('mrts_sha', 'unknown')}`"] if metadata.get("mrts_sha") else []),
            f"> Input status: `{metadata.get('input_status', 'unknown')}`",
        ]
    )


def data_sources_section(metadata: dict[str, Any]) -> str:
    lines = [
        "## Data Sources",
        "",
        "| Value | Source | Source Hash | Verified Run ID | Status |",
        "|---|---|---|---|---|",
    ]
    records = metadata.get("inputs")
    if not isinstance(records, list) or not records:
        lines.append("| Declared inputs | `-` | `unknown` | `unknown` | unknown |")
    else:
        for record in records:
            source = portable_markdown_text(str(record.get("path", "-"))).replace("|", "\\|")
            source_hash = str(record.get("source_hash") or record.get("sha256") or "unknown")
            source_run_id = str(record.get("verified_run_id") or metadata.get("verified_run_id") or "unknown")
            status = str(record.get("status", "unknown"))
            lines.append(f"| Declared input | `{source}` | `{source_hash}` | `{source_run_id}` | {status} |")
    return "\n".join(lines)


def render_empty_table_note(reason: str) -> str:
    return f"_No rows available. Reason: {reason}_"


def missing_information_section(metadata: dict[str, Any]) -> str:
    lines = [
        "## Data Availability / Missing Information",
        "",
        "| Input | Status | Notes |",
        "|---|---|---|",
    ]
    records = metadata.get("inputs")
    if not isinstance(records, list) or not records:
        lines.append("| `-` | unknown | no input files were declared for this generated report |")
    else:
        for record in records:
            path = portable_markdown_text(str(record.get("path", "-"))).replace("|", "\\|")
            status = str(record.get("status", "unknown"))
            notes = portable_markdown_text(str(record.get("notes", ""))).replace("|", "\\|") or "-"
            lines.append(f"| `{path}` | {status} | {notes} |")
    return "\n".join(lines)


def _caller_output_name() -> str:
    frame = inspect.currentframe()
    caller = frame.f_back if frame is not None else None
    while caller is not None:
        candidate = caller.f_locals.get("path")
        if isinstance(candidate, Path):
            return candidate.name
        caller = caller.f_back
    return ""


def _language_switch(output_name: str) -> tuple[str, str] | None:
    if not output_name.endswith(_MARKDOWN_SUFFIX):
        return None
    if output_name.endswith(_GERMAN_MARKDOWN_SUFFIX):
        english_name = output_name.removesuffix(_GERMAN_MARKDOWN_SUFFIX) + _MARKDOWN_SUFFIX
        return "**Sprache:**", f"**Sprache:** [English]({english_name}) | Deutsch"
    german_name = output_name.removesuffix(_MARKDOWN_SUFFIX) + _GERMAN_MARKDOWN_SUFFIX
    return "**Language:**", f"**Language:** English | [Deutsch]({german_name})"


def _insert_language_switch(markdown: str, switch: str, prefix: str) -> str:
    lines = [line for line in markdown.splitlines() if not line.startswith(prefix)]
    try:
        heading_index = next(index for index, line in enumerate(lines) if line.startswith("# "))
    except StopIteration:
        heading_index = -1
    if heading_index < 0:
        return "\n".join([switch, "", *lines]).strip()
    before = lines[: heading_index + 1]
    after = lines[heading_index + 1 :]
    while after and not after[0].strip():
        after.pop(0)
    return "\n".join([*before, "", switch, "", *after]).strip()


def generated_markdown_text(markdown: str, metadata: dict[str, Any]) -> str:
    body = markdown.strip()
    if body.startswith(f"> {GENERATED_NOTICE}"):
        lines = body.splitlines()
        index = 0
        while index < len(lines):
            if index > 0 and not lines[index].strip():
                index += 1
                break
            index += 1
        body = "\n".join(lines[index:]).strip()
    marker = "\n## Data Availability / Missing Information"
    if marker in body:
        body = body.split(marker, 1)[0].rstrip()
    if body.startswith("## Data Availability / Missing Information"):
        body = ""
    data_marker = "\n## Data Sources"
    if data_marker in body:
        body = body.split(data_marker, 1)[0].rstrip()
    if body.startswith("## Data Sources"):
        body = ""
    output_name = str(metadata.get("output_name") or "")
    if not output_name and metadata.get("make_target") == "generate-test-matrix":
        output_name = _caller_output_name()
    switch = _language_switch(output_name)
    if switch is not None:
        body = _insert_language_switch(body, switch[1], switch[0])
    body = portable_markdown_text(body)
    return (
        metadata_block(metadata)
        + "\n\n"
        + body
        + "\n\n"
        + data_sources_section(metadata)
        + "\n\n"
        + missing_information_section(metadata)
        + "\n"
    )


def generated_at_from_json(data: dict[str, Any]) -> str:
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    return str(metadata.get("generated_at") or data.get("generated_at") or "-")


def generated_at_from_report(path: Path) -> str:
    if path.suffix == _JSON_SUFFIX and is_regular_file(path):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return "-"
        return generated_at_from_json(data if isinstance(data, dict) else {})
    if is_regular_file(path):
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()[:20]:
            if "Generated at:" in line:
                return line.split("Generated at:", 1)[1].strip().strip("` ")
    return "-"


def sha256_file(path: Path) -> str:
    import hashlib

    if not is_regular_file(path):
        return "special"
    fallback = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            fallback.update(chunk)
    return fallback.hexdigest()


def directory_fingerprint(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    seen = False
    for item in sorted(path.rglob("*")):
        try:
            item_stat = item.stat(follow_symlinks=False)
        except OSError:
            continue
        seen = True
        try:
            rel = item.relative_to(path)
        except ValueError:
            rel = item
        digest.update(str(rel).encode("utf-8", errors="replace"))
        digest.update(b"\0")
        if stat.S_ISREG(item_stat.st_mode):
            digest.update(sha256_file(item).encode("ascii"))
        else:
            digest.update(f"special:{stat.S_IFMT(item_stat.st_mode):o}".encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest() if seen else "empty"


def _json_report_metadata(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    metadata = data.get("metadata") if isinstance(data, dict) else {}
    return metadata if isinstance(metadata, dict) else {}


def _markdown_report_metadata(path: Path) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    labels = (
        ("Verified run id:", "verified_run_id"),
        ("Connector SHA:", "connector_sha"),
        ("Framework SHA:", "framework_sha"),
        ("Framework gitlink SHA:", "framework_gitlink_sha"),
        ("Framework checkout:", "framework_checkout_status"),
        ("Framework gitlink status:", "framework_gitlink_status"),
    )
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:30]:
        stripped = line.strip()
        for label, field in labels:
            if label in stripped:
                metadata[field] = stripped.split(label, 1)[1].strip().strip("` ")
                break
    return metadata


def read_report_metadata(path: Path) -> dict[str, Any]:
    if path.suffix == _JSON_SUFFIX:
        return _json_report_metadata(path)
    if path.suffix == _MARKDOWN_SUFFIX:
        return _markdown_report_metadata(path)
    return {}
