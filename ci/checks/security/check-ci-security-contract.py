#!/usr/bin/env python3
"""Validate Framework-owned GitHub Actions security contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable
from urllib.parse import urlparse

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from common_canonical_pins import canonical_action, load_canonical_ci_pins


SHA = re.compile(r"^[0-9a-f]{40}$")
UNSAFE_TRIGGER = re.compile(r"\bpull_request_target\b", re.ASCII)
UNTRUSTED_INTERPOLATION = re.compile(r"github\.event\.pull_request\.(?:title|body)\b")
ID_TOKEN_WRITE = re.compile(r"\bid-token\s*:\s*['\"]?write['\"]?", re.IGNORECASE)
ARCHIVE_TYPE_TAR_GZ = "tar.gz"
ARCHIVE_TYPE_RAW = "raw"
LAYOUT_EXECUTABLE = "executable"
LAYOUT_TREE = "tree"
CHECK_JSON_RESULT = "check-json-result.py"
UPLOAD_ARTIFACT = "actions" + "/upload-artifact@"
DOWNLOAD_ARTIFACT = "actions" + "/download-artifact@"
RETENTION_DAYS_ONE = "retention-days: 1"
IF_NO_FILES_FOUND_ERROR = "if-no-files-found: error"
SECURITY_EVENTS_WRITE = "security-events: write"
SECURITY_TOOL_DOWNLOADER = "ci/tools/fetch-security-tool.py"
HASH_LOCKED_CI_REQUIREMENTS = "--require-hashes -r requirements-ci.lock"
WORKFLOW_TOOL_UPDATER = "update-workflow-tools.yml"
SUBMODULE_UPDATER = "update-submodules.yml"
# Canonical JSON SHA-256 of jobs.create-submodule-update-pr. The publisher has
# repository write permissions, so every key, step, action input, environment,
# and run body must remain review-bound rather than merely contain snippets.
SUBMODULE_UPDATER_PUBLISHER_SHA256 = (
    "8be2dc3f6e837524937aeff6c6b8d4571202923c20603e1d93016a7850b402af"
)
CHECKOUT_WITHOUT_SUBMODULES = "submodules: false"
CHECKOUT_WITHOUT_PERSISTED_CREDENTIALS = "persist-credentials: false"
COMMON_VERSION_WORKFLOW = "check-common-versions.yml"
COMMON_VERSION_DISPATCH_INPUTS = {
    "component": {
        "description": "Optional exact common-version component name to resolve",
        "required": False,
        "type": "string",
        "default": "",
    }
}
PYTHON_VERSION_MAINTENANCE_WORKFLOW = "check-python-version.yml"
SETUP_PYTHON_ACTION = "actions" + "/setup-python"
SETUP_PYTHON_REFERENCE = f"{SETUP_PYTHON_ACTION}@"
CHECKOUT_ACTION = "actions" + "/checkout"
GITHUB_SCRIPT_ACTION = "actions" + "/github-script"
CREATE_PULL_REQUEST_ACTION = "peter" + "-evans/create-pull-request"
CHECKOUT_REPOSITORY_STEP = "Checkout repository"
GITHUB_TOKEN_EXPRESSION = "${{ github.token }}"
DEFAULT_BRANCH_EXPRESSION = "${{ github.event.repository.default_branch }}"
WORKFLOW_UPDATER_APP_TOKEN_ACTION = "actions" + "/create-github-app-token"
WORKFLOW_UPDATER_APP_TOKEN_EXPRESSION = "${{ steps.publisher_app_token.outputs.token }}"
WORKFLOW_UPDATER_APP_CLIENT_ID_EXPRESSION = "${{ vars.WORKFLOW_UPDATER_APP_CLIENT_ID }}"
WORKFLOW_UPDATER_APP_PRIVATE_KEY_EXPRESSION = (
    "${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY }}"
)
GITHUB_REPOSITORY_OWNER_EXPRESSION = "${{ github.repository_owner }}"
GITHUB_REPOSITORY_EXPRESSION = "${{ github.repository }}"
DEFAULT_BRANCH_CONTEXT = "github.event.repository.default_branch"
UPDATER_PUBLISH_TOKEN_ENV = "PUBLISH_TOKEN"
STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION = "Checkout trusted default revision"
STEP_SETUP_REVIEWED_PYTHON = "Set up reviewed Python"
STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY = "Install hash-locked CI dependency"
STEP_FETCH_CHECKSUM_VERIFIED_SHELLCHECK = "Fetch checksum-verified ShellCheck"
STEP_VALIDATE_EPHEMERAL_COMMON_SH_CANDIDATE = (
    "Validate an ephemeral common.sh candidate"
)
STEP_RESOLVE_EPHEMERAL_COMMON_SH_CANDIDATE = "Resolve an ephemeral common.sh candidate"
STEP_SYNTAX_AND_SHELLCHECK = "Syntax and ShellCheck"
STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST = (
    "Inspect matching Draft maintenance pull request"
)
STEP_MINT_WORKFLOW_PUBLISHER_APP_TOKEN = (
    "Mint repository-limited workflow publisher App token"
)
STEP_MINT_ISSUE_RECONCILER_APP_TOKEN = (
    "Mint repository-limited issue reconciler App token"
)
STEP_MINT_PUBLISHER_APP_TOKEN = "Mint repository-limited publisher App token"
STEP_VERIFY_WORKFLOW_PUBLISHER_APP_CONFIGURATION = (
    "Verify workflow publisher GitHub App configuration"
)
STEP_REPORT_WORKFLOW_TOOL_OUTCOME = "Report explicit workflow-tool maintenance outcome"
STEP_VERIFY_PYTHON_PUBLISHER_APP_CONFIGURATION = (
    "Verify CPython publisher GitHub App configuration"
)
STEP_MINT_PYTHON_PUBLISHER_APP_TOKEN = (
    "Mint repository-limited CPython publisher App token"
)
STEP_INSPECT_PYTHON_DRAFT_MAINTENANCE_PULL_REQUEST = (
    "Inspect matching CPython Draft maintenance pull request"
)
STEP_PREPARE_PYTHON_MAINTENANCE_BRANCH = (
    "Prepare the constrained CPython maintenance branch"
)
STEP_REVALIDATE_PYTHON_DRAFT_BRANCH = (
    "Revalidate the reusable CPython Draft branch before modifying it"
)
STEP_RESTORE_PYTHON_PUBLISHER_BASE = "Restore the trusted CPython publisher base"
STEP_APPLY_PYTHON_CANDIDATE = "Independently revalidate and apply the candidate"
STEP_BUILD_PYTHON_DRAFT_PULL_REQUEST_BODY = "Build Draft pull request body"
STEP_CREATE_OR_UPDATE_PYTHON_DRAFT_PULL_REQUEST = "Create or update Draft pull request"
STEP_REPORT_PYTHON_OUTCOME = "Report explicit CPython maintenance outcome"
STEP_PREPARE_CONSTRAINED_MAINTENANCE_BRANCH = (
    "Prepare the constrained maintenance branch"
)
STEP_REVALIDATE_REUSABLE_DRAFT_BRANCH = (
    "Revalidate the reusable Draft branch before modifying it"
)
STEP_RERESOLVE_CURRENT_CANDIDATES = "Re-resolve and narrowly apply current candidates"
STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS = (
    "Commit and push only approved updater paths"
)
STEP_CREATE_DRAFT_PULL_REQUEST = "Create the matching Draft pull request"
STEP_KEYS_ACTION = frozenset({"name", "uses", "with"})
STEP_KEYS_RUN = frozenset({"name", "run"})
STEP_KEYS_ENV_RUN = frozenset({"env", "name", "run"})
STEP_KEYS_ENV_ACTION = frozenset({"env", "name", "uses", "with"})
STEP_KEYS_SCRIPT = frozenset({"id", "name", "uses", "with"})
STEP_KEYS_ENV_ID_RUN = frozenset({"env", "id", "name", "run"})
STEP_KEYS_ID_ACTION = frozenset({"id", "name", "uses", "with"})
STEP_KEYS_CONDITIONAL_SCRIPT = frozenset({"if", "name", "uses", "with"})
STEP_KEYS_CONDITIONAL_RUN = frozenset({"if", "name", "run"})
STEP_KEYS_CONDITIONAL_ENV_RUN = frozenset({"env", "if", "name", "run"})
COMMON_RECORD_FIELDS = {
    "name",
    "version",
    "immutable_commit",
    "upstream_release",
    "license",
    "purpose",
    "platform",
    "update_procedure",
}
ACTION_RELEASE_RESOLUTION_LATEST = "latest-release"
ACTION_RELEASE_RESOLUTION_SAME_MAJOR = "same-major-release"
ACTION_RELEASE_RESOLUTIONS = {
    ACTION_RELEASE_RESOLUTION_LATEST,
    ACTION_RELEASE_RESOLUTION_SAME_MAJOR,
}
REVIEWED_ACTION_RELEASE_RESOLUTIONS = {}
CODEQL_ACTION_SERIES_TAG = re.compile(r"^v\d+\.\d+\.\d+$", re.ASCII)
ACTION_FIELDS = COMMON_RECORD_FIELDS | {"release_resolution"}
TOOL_FIELDS = COMMON_RECORD_FIELDS | {
    "asset",
    "asset_url",
    "sha256",
    "archive_type",
    "layout",
}
EXECUTABLE_TOOL_FIELDS = TOOL_FIELDS | {"executable"}
TAR_EXECUTABLE_TOOL_FIELDS = EXECUTABLE_TOOL_FIELDS | {"archive_member"}
TREE_TOOL_FIELDS = TOOL_FIELDS | {"archive_root", "entrypoint"}
ALLOWED_ARCHIVE_TYPES = {ARCHIVE_TYPE_TAR_GZ, ARCHIVE_TYPE_RAW}
ALLOWED_PERMISSION_LEVELS = {"read", "write", "none"}
WRITE_PERMISSION_ALLOWLIST = {
    PYTHON_VERSION_MAINTENANCE_WORKFLOW: {"contents", "pull-requests"},
    "cleanup-artifacts.yml": {"actions"},
    "ci-security-codeql.yml": {"security-events"},
    WORKFLOW_TOOL_UPDATER: {"contents", "pull-requests"},
    SUBMODULE_UPDATER: {"contents", "pull-requests"},
}
TOKEN_REFERENCE_ALLOWLIST = {
    PYTHON_VERSION_MAINTENANCE_WORKFLOW,
    COMMON_VERSION_WORKFLOW,
    "ci-security-dependency-review.yml",
    WORKFLOW_TOOL_UPDATER,
    SUBMODULE_UPDATER,
}
TOKEN_REFERENCE = re.compile(
    r"(?:github(?:\s*\.\s*token|\s*\[\s*['\"]token['\"]\s*\])|"
    r"secrets(?:\s*\.\s*GITHUB_TOKEN|\s*\[\s*['\"]GITHUB_TOKEN['\"]\s*\])|"
    r"\$\{?GITHUB_TOKEN\}?)"
)
GITHUB_EXPRESSION = re.compile(r"\$\{\{(?P<expression>.*?)\}\}", re.DOTALL)
SECRET_CONTEXT_REFERENCE = re.compile(r"\bsecrets\b", re.IGNORECASE)
GITHUB_TOKEN_REFERENCE = re.compile(r"\bgithub\s*(?:\.\s*token\b|\[)", re.IGNORECASE)
BARE_GITHUB_CONTEXT_REFERENCE = re.compile(r"\bgithub\b(?!\s*[.\[])", re.IGNORECASE)
SHELL_GITHUB_TOKEN_REFERENCE = re.compile(r"\$\{?GITHUB_TOKEN\}?", re.IGNORECASE)
CANONICAL_PYTHON_VERSION_FILE = ".python-version"
COMMON_SH_PATH = "ci/lib/common.sh"
PYTHON_PUBLISHER_SOURCE_FILE = COMMON_SH_PATH
PYTHON_CANDIDATE_EXPRESSION = "${{ needs.resolve.outputs.candidate }}"
PYTHON_PUBLISHER_CHANGED_PATHS = (
    f"{CANONICAL_PYTHON_VERSION_FILE}\n{PYTHON_PUBLISHER_SOURCE_FILE}"
)
PYTHON_PUBLISHER_ADD_PATHS = (
    f"{PYTHON_PUBLISHER_SOURCE_FILE}\n{CANONICAL_PYTHON_VERSION_FILE}\n"
)
PYTHON_VERSION_CANDIDATE_FILE = "${{ runner.temp }}/framework-python-3.14-candidate"
PYTHON_VERSION_PR_BODY_FILE = "${{ runner.temp }}/framework-python-version-pr-body.md"
PYTHON_VERSION_PR_BODY_RUN_PATH = "$RUNNER_TEMP/framework-python-version-pr-body.md"
OSV_WORKFLOW = "ci-security-osv.yml"
OSV_TRUSTED_BASE_PYTHON_VERSION_FILE = (
    "${{ runner.temp }}/framework-osv-trusted-base-python-version"
)
OSV_LEGACY_BASE_SHA = "f73f8842f45318e2df8aff1d31855eeb7c20a22" + "f"
OSV_LEGACY_BASE_VERSION = "3.13." + "14"
GITHUB_COMPONENT = r"[A-Za-z0-9_.-]+"
GITHUB_RELEASE_URL = re.compile(
    rf"^https://github\.com/(?P<owner>{GITHUB_COMPONENT})/"
    rf"(?P<repository>{GITHUB_COMPONENT})/releases/tag/(?P<tag>[^/?#]+)$"
)
GITHUB_RELEASE_ASSET_URL = re.compile(
    rf"^https://github\.com/(?P<owner>{GITHUB_COMPONENT})/"
    rf"(?P<repository>{GITHUB_COMPONENT})/releases/download/"
    rf"(?P<tag>[^/?#]+)/(?P<asset>{GITHUB_COMPONENT})$"
)
UPDATER_READ_ONLY_PERMISSIONS = {"contents": "read"}
UPDATER_PUBLISHER_PERMISSIONS = {"contents": "read"}
UPDATER_OUTCOME_PERMISSIONS: dict[str, str] = {}
UPDATER_JOB_NAMES = frozenset({"resolver", "validator", "publisher", "outcome"})
DEFAULT_BRANCH_REF_CONDITION = (
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
)
RESOLVER_UPDATE_AVAILABLE_CONDITION = "needs.resolve.outputs.update_available == 'true'"
CANDIDATE_SHA256_LENGTH_CHECK = 'test "${#candidate_sha256}" -eq 64'
UPDATER_HAS_UPDATES_CONDITION = "needs.resolver.outputs.has_updates == 'true'"
UPDATER_DEFAULT_BRANCH_ENV = "DEFAULT_BRANCH"
UPDATER_TRIGGERS = {
    "workflow_dispatch": None,
    "schedule": [{"cron": "17 5 * * 1"}],
}
COMMON_VERSION_READER_PERMISSIONS = {"contents": "read"}
COMMON_VERSION_PUBLISHER_PERMISSIONS = {"contents": "read"}
COMMON_VERSION_JOB_NAMES = {
    "canonical-maintenance",
    "candidate",
    "reconcile-trusted",
    "publish",
    "result",
}
COMMON_VERSION_PLAN_ARTIFACT_NAME = (
    "canonical-maintenance-plan-${{ github.run_id }}-${{ github.run_attempt }}"
)
COMMON_VERSION_PLAN_ARTIFACT_DOWNLOAD_PATH = "${{ runner.temp }}"
COMMON_VERSION_PLAN_ARTIFACT_UPLOAD_PATHS = (
    "${{ runner.temp }}/canonical-maintenance-plan.json",
    "${{ runner.temp }}/canonical-maintenance-plan.md",
)
COMMON_VERSION_PLAN_JSON_RUN_PATH = "$RUNNER_TEMP/canonical-maintenance-plan.json"
COMMON_VERSION_REVIEWED_RUN_SHA256 = {
    (
        "canonical-maintenance",
        "Resolve mandatory global and selected runtime scopes",
    ): "671e37c65ab0314dfe0ef383126deed805d449e5b746f94a37c382564654d403",
    (
        "canonical-maintenance",
        "Validate review issue reconciliation without writes",
    ): "26806d5e329e4892ab5b8fa7dd7005e46a59d36d47e8e8f76b9d6a4c5477bf30",
    (
        "reconcile-trusted",
        "Validate caller-bound canonical maintenance plan",
    ): "b9f2ed3bdcba48595a4f4b67e149eddc7a52627053d8aff0d92fd3f99020f913",
    (
        "reconcile-trusted",
        "Require distinct review-issue App configuration",
    ): "e1c1805fc9250e20af66baa0480a7931e0823fd53dd41e67e37b15660037c4d2",
    (
        "reconcile-trusted",
        "Reconcile review issues from caller-bound plan on trusted default branch",
    ): "366c48ee28b5285f6410cc7c9c4945399382b59410be22d3b54faa13f313ec8a",
    (
        "candidate",
        "Validate and apply caller-bound canonical plan",
    ): "f4610ce0e58163a78e1d7c94ccddcdc1087e363e255dd60d66a13f5e38963e0f",
    (
        "candidate",
        "Validate candidate path policy and focused controls",
    ): "fc8a521cecf641305534044ba424ddd9cd9a2069bb8e646d16892aee4fc75a88",
    (
        "publish",
        "Validate and apply caller-bound canonical plan",
    ): "54845f224c86186044c1e834cb5882bbc3cdfcdad4750d8047d7e7292e880b5c",
    (
        "publish",
        "Require publisher App configuration",
    ): "5433724ca5a8642ef7f8bee6a67adb2f1a0b17d69d69413ea581a1519efca413",
    (
        "result",
        "Summarize outcome, updates, reviews, issues, PR, and fatal findings",
    ): "4a8667a3ce2063a78d3d64ca1124014cf19d2ae938f093ccc74a4b2bf45b818b",
}
COMMON_VERSION_GENERATED_PATHS = frozenset(
    {
        COMMON_SH_PATH,
        CANONICAL_PYTHON_VERSION_FILE,
        "requirements-ci.lock",
        "ci/tooling/security-tools.lock.yml",
        "ci/provisioning/runtime-components.manifest.json",
        "ci/provisioning/runtime-component-lock.json",
        "docs/reference/variables.md",
        "docs/reference/variables.de.md",
        "docs/github-actions-workflow-security.md",
        "docs/github-actions-workflow-security.de.md",
        ".github/workflows/check-action-versions.yml",
        ".github/workflows/check-common-versions.yml",
        ".github/workflows/check-python-version.yml",
        ".github/workflows/ci-security-codeql-pr.yml",
        ".github/workflows/ci-security-codeql.yml",
        ".github/workflows/ci-security-dependency-review.yml",
        ".github/workflows/ci-security-osv.yml",
        ".github/workflows/ci-security-quality.yml",
        ".github/workflows/ci-security-scorecard.yml",
        ".github/workflows/ci-security-secrets.yml",
        ".github/workflows/ci-security-workflow-lint.yml",
        ".github/workflows/cleanup-artifacts.yml",
        ".github/workflows/five-connectors-with-crs-no-mrts-contract.yml",
        ".github/workflows/lint.yml",
        ".github/workflows/test-common.yml",
        ".github/workflows/update-submodules.yml",
        ".github/workflows/update-workflow-tools.yml",
        "tests/schemas/five-connectors-with-crs-no-mrts/normalized-event.schema.json",
        "tests/schemas/five-connectors-with-crs-no-mrts/manifest.schema.json",
        "tests/schemas/five-connectors-with-crs-no-mrts/receipt.schema.json",
        "tests/cases/security/crs/crs_sqli_anomaly_block.yaml",
    }
)
COMMON_VERSION_UPDATE_BRANCH = "automation/update-framework-common-versions"
COMMON_VERSION_UPDATE_PATH = COMMON_SH_PATH
COMMON_VERSION_PR_TITLE = "chore(ci): update common.sh versions"
COMMON_VERSION_PR_MARKER = "<!-- framework-common-version-updater -->"
COMMON_VERSION_PR_BODY_FILE = "${{ runner.temp }}/framework-common-version-pr-body.md"
COMMON_VERSION_PR_BODY_RUN_PATH = "$RUNNER_TEMP/framework-common-version-pr-body.md"
COMMON_VERSION_DRAFT_PULL_REQUEST_URL_EXPRESSION = (
    "${{ steps.draft_pull_request.outputs.pull-request-url }}"
)
COMMON_VERSION_DRAFT_PULL_REQUEST_NUMBER_EXPRESSION = (
    "${{ steps.draft_pull_request.outputs.pull-request-number }}"
)
COMMON_VERSION_APP_CONFIG_SECRET_PRESENT_EXPRESSION = (
    "${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY != '' }}"
)
COMMON_VERSION_APP_CONFIG_ENV = {
    "WORKFLOW_UPDATER_APP_PRIVATE_KEY_CONFIGURED": (
        COMMON_VERSION_APP_CONFIG_SECRET_PRESENT_EXPRESSION
    )
}
COMMON_VERSION_APP_CONFIG_MISSING_CONDITION = (
    "${{ vars.WORKFLOW_UPDATER_APP_CLIENT_ID == '' || "
    "env.WORKFLOW_UPDATER_APP_PRIVATE_KEY_CONFIGURED != 'true' }}"
)
COMMON_VERSION_RESOLVER_OUTPUTS = {
    "maintenance_outcome": "${{ steps.resolve.outputs.maintenance_outcome }}",
    "update_available": "${{ steps.resolve.outputs.update_available }}",
    "candidate_sha256": "${{ steps.resolve.outputs.candidate_sha256 }}",
    "manual_review_required": "${{ steps.resolve.outputs.manual_review_required }}",
    "manual_review_components_b64": (
        "${{ steps.resolve.outputs.manual_review_components_b64 }}"
    ),
    "automatic_update_variables_b64": (
        "${{ steps.resolve.outputs.automatic_update_variables_b64 }}"
    ),
    "manual_review_pins_sha256": (
        "${{ steps.resolve.outputs.manual_review_pins_sha256 }}"
    ),
}
COMMON_VERSION_PUBLISHER_IF = (
    "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') "
    "&& github.repository == 'Easton97-Jens/ModSecurity-test-Framework' && "
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch) "
    "&& needs.resolve.outputs.update_available == 'true' && "
    "(needs.resolve.outputs.maintenance_outcome == 'safe_updates' || "
    "needs.resolve.outputs.maintenance_outcome == 'safe_updates_with_manual_review') && "
    "needs.candidate-validate.outputs.candidate_validated == 'true'"
)
COMMON_VERSION_PUBLISHER_ENV = {
    "CANDIDATE_SHA256": "${{ needs.resolve.outputs.candidate_sha256 }}",
    "MAINTENANCE_OUTCOME": "${{ needs.resolve.outputs.maintenance_outcome }}",
    "MANUAL_REVIEW_REQUIRED": "${{ needs.resolve.outputs.manual_review_required }}",
    "MANUAL_REVIEW_COMPONENTS_B64": (
        "${{ needs.resolve.outputs.manual_review_components_b64 }}"
    ),
    "AUTOMATIC_UPDATE_VARIABLES_B64": (
        "${{ needs.resolve.outputs.automatic_update_variables_b64 }}"
    ),
    "MANUAL_REVIEW_PINS_SHA256": (
        "${{ needs.resolve.outputs.manual_review_pins_sha256 }}"
    ),
}
COMMON_VERSION_CANDIDATE_ENV = COMMON_VERSION_PUBLISHER_ENV
STEP_REVALIDATE_COMMON_VERSION_CANDIDATE = (
    "Independently revalidate and apply the candidate"
)
STEP_BUILD_BOUNDED_COMMON_VERSION_PR_BODY = "Build bounded Draft pull request body"
STEP_FAIL_CLOSED_COMMON_VERSION_APP_CONFIGURATION = (
    "Fail closed when common-version publisher App configuration is unavailable"
)
STEP_MINT_COMMON_VERSION_PUBLISHER_APP_TOKEN = (
    "Mint repository-limited common-version publisher App token"
)
STEP_INSPECT_COMMON_VERSION_DRAFT_PULL_REQUEST = (
    "Inspect matching common-version Draft pull request"
)
STEP_CREATE_OR_UPDATE_COMMON_VERSION_DRAFT_PULL_REQUEST = (
    "Create or update Draft pull request"
)

# The Common-version publisher is a purpose-bound App-token write boundary.
# Its exact profile prevents a credential or a reviewed state check from being
# silently repurposed by adding a step, option, or shell command.
COMMON_VERSION_PUBLISHER_JOB_KEYS = frozenset(
    {
        "needs",
        "if",
        "runs-on",
        "timeout-minutes",
        "permissions",
        "outputs",
        "env",
        "steps",
    }
)
COMMON_VERSION_PUBLISHER_STEP_PROFILE = (
    (STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION, STEP_KEYS_ACTION),
    (STEP_SETUP_REVIEWED_PYTHON, STEP_KEYS_ACTION),
    (STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY, STEP_KEYS_RUN),
    (STEP_FETCH_CHECKSUM_VERIFIED_SHELLCHECK, STEP_KEYS_ENV_RUN),
    (STEP_REVALIDATE_COMMON_VERSION_CANDIDATE, STEP_KEYS_ENV_ID_RUN),
    (STEP_BUILD_BOUNDED_COMMON_VERSION_PR_BODY, STEP_KEYS_RUN),
    (
        STEP_FAIL_CLOSED_COMMON_VERSION_APP_CONFIGURATION,
        STEP_KEYS_CONDITIONAL_ENV_RUN,
    ),
    (STEP_MINT_COMMON_VERSION_PUBLISHER_APP_TOKEN, STEP_KEYS_SCRIPT),
    (STEP_INSPECT_COMMON_VERSION_DRAFT_PULL_REQUEST, STEP_KEYS_ENV_ACTION),
    (
        STEP_CREATE_OR_UPDATE_COMMON_VERSION_DRAFT_PULL_REQUEST,
        STEP_KEYS_ID_ACTION,
    ),
)
COMMON_VERSION_PUBLISHER_ACTIONS = {
    STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION: CHECKOUT_ACTION,
    STEP_SETUP_REVIEWED_PYTHON: SETUP_PYTHON_ACTION,
    STEP_MINT_COMMON_VERSION_PUBLISHER_APP_TOKEN: WORKFLOW_UPDATER_APP_TOKEN_ACTION,
    STEP_INSPECT_COMMON_VERSION_DRAFT_PULL_REQUEST: GITHUB_SCRIPT_ACTION,
    STEP_CREATE_OR_UPDATE_COMMON_VERSION_DRAFT_PULL_REQUEST: (
        CREATE_PULL_REQUEST_ACTION
    ),
}
COMMON_VERSION_PUBLISHER_WITH_VALUES = {
    STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION: {
        "ref": DEFAULT_BRANCH_EXPRESSION,
        "fetch-depth": 1,
        "persist-credentials": False,
        "submodules": False,
    },
    STEP_SETUP_REVIEWED_PYTHON: {
        "python-version-file": CANONICAL_PYTHON_VERSION_FILE,
        "check-latest": False,
    },
    STEP_MINT_COMMON_VERSION_PUBLISHER_APP_TOKEN: {
        "client-id": WORKFLOW_UPDATER_APP_CLIENT_ID_EXPRESSION,
        "private-key": WORKFLOW_UPDATER_APP_PRIVATE_KEY_EXPRESSION,
        "owner": GITHUB_REPOSITORY_OWNER_EXPRESSION,
        "repositories": GITHUB_REPOSITORY_EXPRESSION,
        "permission-contents": "write",
        "permission-pull-requests": "write",
        "permission-workflows": "write",
    },
    STEP_CREATE_OR_UPDATE_COMMON_VERSION_DRAFT_PULL_REQUEST: {
        "token": WORKFLOW_UPDATER_APP_TOKEN_EXPRESSION,
        "commit-message": COMMON_VERSION_PR_TITLE,
        "title": COMMON_VERSION_PR_TITLE,
        "body-path": COMMON_VERSION_PR_BODY_FILE,
        "branch": COMMON_VERSION_UPDATE_BRANCH,
        "base": DEFAULT_BRANCH_EXPRESSION,
        "delete-branch": False,
        "draft": True,
        "add-paths": f"{COMMON_VERSION_UPDATE_PATH}\n",
    },
}
COMMON_VERSION_PUBLISHER_WITH_KEYS = {
    **{
        name: frozenset(values)
        for name, values in COMMON_VERSION_PUBLISHER_WITH_VALUES.items()
    },
    STEP_INSPECT_COMMON_VERSION_DRAFT_PULL_REQUEST: frozenset(
        {"github-token", "script"}
    ),
}
COMMON_VERSION_PUBLISHER_ENV_VALUES = {
    STEP_FETCH_CHECKSUM_VERIFIED_SHELLCHECK: {
        "TOOLS_DIR": "${{ runner.temp }}/framework-ci-security-tools"
    },
    STEP_REVALIDATE_COMMON_VERSION_CANDIDATE: {
        "TOOLS_DIR": "${{ runner.temp }}/framework-ci-security-tools",
        "REQUESTED_COMPONENT": "${{ inputs.component }}",
    },
    STEP_FAIL_CLOSED_COMMON_VERSION_APP_CONFIGURATION: COMMON_VERSION_APP_CONFIG_ENV,
    STEP_INSPECT_COMMON_VERSION_DRAFT_PULL_REQUEST: {
        "TRUSTED_BASE_SHA": "${{ steps.candidate_revalidation.outputs.trusted_base_sha }}"
    },
}
COMMON_VERSION_PUBLISHER_FIELD_VALUES = {
    STEP_REVALIDATE_COMMON_VERSION_CANDIDATE: {"id": "candidate_revalidation"},
    STEP_FAIL_CLOSED_COMMON_VERSION_APP_CONFIGURATION: {
        "if": COMMON_VERSION_APP_CONFIG_MISSING_CONDITION
    },
    STEP_MINT_COMMON_VERSION_PUBLISHER_APP_TOKEN: {"id": "publisher_app_token"},
    STEP_CREATE_OR_UPDATE_COMMON_VERSION_DRAFT_PULL_REQUEST: {
        "id": "draft_pull_request"
    },
}
COMMON_VERSION_PUBLISHER_OUTPUTS = {
    "draft_pull_request_number": COMMON_VERSION_DRAFT_PULL_REQUEST_NUMBER_EXPRESSION,
    "draft_pull_request_url": COMMON_VERSION_DRAFT_PULL_REQUEST_URL_EXPRESSION,
}
COMMON_VERSION_PUBLISHER_RUN_SHA256 = {
    STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY: "bd13dd746985e7fc0aeb48e4966da62abc3775685f8c16117911fe3c3ba5399e",
    STEP_FETCH_CHECKSUM_VERIFIED_SHELLCHECK: "f4e26f8af7f41a9e425a9416c78f0ff7ca2b4e8faa0837acd94c91b26a4ecb7d",
    STEP_REVALIDATE_COMMON_VERSION_CANDIDATE: "67d99000eaf72e26d8d8999994c53d42db77f7fe31b4652881be5a411448f6da",
    STEP_BUILD_BOUNDED_COMMON_VERSION_PR_BODY: "d32906bb8fff4feb518395fcfedb566b32a80930084ec3489577ba3c4e6da609",
    STEP_FAIL_CLOSED_COMMON_VERSION_APP_CONFIGURATION: "89dbee536c4566a0f64ee9ae5f1363fbeca67f6a7f6b2b02d86158b5955ede1b",
}
COMMON_VERSION_PUBLISHER_SCRIPT_SHA256 = {
    STEP_INSPECT_COMMON_VERSION_DRAFT_PULL_REQUEST: "dbc2602d7b9ba62c2310792d53b12a6bc0fdab637b02f8ea3c2945db6a599071"
}
COMMON_VERSION_EXPECTED_SENSITIVE_PATHS = frozenset(
    {
        (
            "jobs",
            "publish",
            "steps",
            "6",
            "env",
            "WORKFLOW_UPDATER_APP_PRIVATE_KEY_CONFIGURED",
        ),
        ("jobs", "publish", "steps", "7", "with", "private-key"),
    }
)
COMMON_VERSION_RESULT_JOB_KEYS = frozenset(
    {"needs", "if", "runs-on", "timeout-minutes", "permissions", "env", "steps"}
)
COMMON_VERSION_RESULT_NEEDS = {
    "resolve",
    "candidate-validate",
    "publish",
}
ALWAYS_CONDITION = "${{ always() }}"
COMMON_VERSION_RESULT_ENV = {
    "RESOLVER_RESULT": "${{ needs.resolve.result }}",
    "MAINTENANCE_OUTCOME": "${{ needs.resolve.outputs.maintenance_outcome }}",
    "UPDATE_AVAILABLE": "${{ needs.resolve.outputs.update_available }}",
    "CANDIDATE_SHA256": "${{ needs.resolve.outputs.candidate_sha256 }}",
    "MANUAL_REVIEW_REQUIRED": "${{ needs.resolve.outputs.manual_review_required }}",
    "MANUAL_REVIEW_COMPONENTS_B64": (
        "${{ needs.resolve.outputs.manual_review_components_b64 }}"
    ),
    "MANUAL_REVIEW_PINS_SHA256": (
        "${{ needs.resolve.outputs.manual_review_pins_sha256 }}"
    ),
    "VALIDATOR_RESULT": "${{ needs.candidate-validate.result }}",
    "PUBLISHER_RESULT": "${{ needs.publish.result }}",
    "DRAFT_PULL_REQUEST_NUMBER": (
        "${{ needs.publish.outputs.draft_pull_request_number }}"
    ),
    "DRAFT_PULL_REQUEST_URL": "${{ needs.publish.outputs.draft_pull_request_url }}",
}
STEP_REPORT_COMMON_VERSION_OUTCOME = "Report reviewed common-version outcome"
COMMON_VERSION_RESULT_STEP_PROFILE = (
    (STEP_REPORT_COMMON_VERSION_OUTCOME, STEP_KEYS_RUN),
)
COMMON_VERSION_RESULT_RUN_SHA256 = {
    STEP_REPORT_COMMON_VERSION_OUTCOME: "ca4afb210ae1e7eda774adbd3bc1bde4c650bf6689cc341957c786c4f24b5af8",
}
# The publisher is the updater's only write-capable trust boundary.  Its run and
# github-script bodies are intentionally static: updating an Action pin does not
# change them.  Hashing the YAML-parsed bodies, together with the exact step
# profile below, fails closed on aliases, shell prefixes, comments, or extra
# publisher behavior instead of attempting to recognize every unsafe spelling.
UPDATER_PUBLISHER_JOB_KEYS = frozenset(
    {"needs", "if", "runs-on", "timeout-minutes", "permissions", "steps"}
)
UPDATER_PUBLISHER_STEP_PROFILE = (
    (STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION, STEP_KEYS_ACTION),
    (STEP_SETUP_REVIEWED_PYTHON, STEP_KEYS_ACTION),
    (STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY, STEP_KEYS_RUN),
    (STEP_VERIFY_WORKFLOW_PUBLISHER_APP_CONFIGURATION, STEP_KEYS_ENV_RUN),
    (STEP_MINT_WORKFLOW_PUBLISHER_APP_TOKEN, STEP_KEYS_SCRIPT),
    (
        STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST,
        STEP_KEYS_SCRIPT,
    ),
    (
        STEP_PREPARE_CONSTRAINED_MAINTENANCE_BRANCH,
        STEP_KEYS_ENV_RUN,
    ),
    (STEP_REVALIDATE_REUSABLE_DRAFT_BRANCH, STEP_KEYS_ENV_RUN),
    (STEP_RERESOLVE_CURRENT_CANDIDATES, STEP_KEYS_ENV_RUN),
    (STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS, STEP_KEYS_ENV_ID_RUN),
    (
        STEP_CREATE_DRAFT_PULL_REQUEST,
        STEP_KEYS_CONDITIONAL_SCRIPT,
    ),
)
UPDATER_PUBLISHER_ACTIONS = {
    STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION: CHECKOUT_ACTION,
    STEP_SETUP_REVIEWED_PYTHON: SETUP_PYTHON_ACTION,
    STEP_MINT_WORKFLOW_PUBLISHER_APP_TOKEN: WORKFLOW_UPDATER_APP_TOKEN_ACTION,
    STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST: GITHUB_SCRIPT_ACTION,
    STEP_CREATE_DRAFT_PULL_REQUEST: GITHUB_SCRIPT_ACTION,
}
UPDATER_PUBLISHER_WITH_VALUES = {
    STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION: {
        "ref": DEFAULT_BRANCH_EXPRESSION,
        "fetch-depth": 1,
        "persist-credentials": False,
        "submodules": False,
    },
    STEP_SETUP_REVIEWED_PYTHON: {
        "python-version-file": CANONICAL_PYTHON_VERSION_FILE,
        "check-latest": False,
    },
    STEP_MINT_WORKFLOW_PUBLISHER_APP_TOKEN: {
        "client-id": WORKFLOW_UPDATER_APP_CLIENT_ID_EXPRESSION,
        "private-key": WORKFLOW_UPDATER_APP_PRIVATE_KEY_EXPRESSION,
        "owner": GITHUB_REPOSITORY_OWNER_EXPRESSION,
        "repositories": GITHUB_REPOSITORY_EXPRESSION,
        "permission-contents": "write",
        "permission-pull-requests": "write",
        "permission-workflows": "write",
    },
}
UPDATER_PUBLISHER_WITH_KEYS = {
    **{
        name: frozenset(values)
        for name, values in UPDATER_PUBLISHER_WITH_VALUES.items()
    },
    STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST: frozenset({"github-token", "script"}),
    STEP_CREATE_DRAFT_PULL_REQUEST: frozenset({"github-token", "script"}),
}
UPDATER_PUBLISHER_ENV_VALUES = {
    STEP_VERIFY_WORKFLOW_PUBLISHER_APP_CONFIGURATION: {
        "WORKFLOW_UPDATER_APP_CLIENT_ID": WORKFLOW_UPDATER_APP_CLIENT_ID_EXPRESSION,
        "WORKFLOW_UPDATER_APP_PRIVATE_KEY": WORKFLOW_UPDATER_APP_PRIVATE_KEY_EXPRESSION,
    },
    STEP_PREPARE_CONSTRAINED_MAINTENANCE_BRANCH: {
        UPDATER_DEFAULT_BRANCH_ENV: DEFAULT_BRANCH_EXPRESSION,
        "MAINTENANCE_PR_EXISTS": "${{ steps.maintenance_pr.outputs.existing }}",
        UPDATER_PUBLISH_TOKEN_ENV: WORKFLOW_UPDATER_APP_TOKEN_EXPRESSION,
    },
    STEP_REVALIDATE_REUSABLE_DRAFT_BRANCH: {
        UPDATER_DEFAULT_BRANCH_ENV: DEFAULT_BRANCH_EXPRESSION,
    },
    STEP_RERESOLVE_CURRENT_CANDIDATES: {
        "CANDIDATE_B64": "${{ needs.resolver.outputs.candidate_b64 }}",
        "CANDIDATE_SHA256": "${{ needs.resolver.outputs.candidate_sha256 }}",
    },
    STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS: {
        UPDATER_PUBLISH_TOKEN_ENV: WORKFLOW_UPDATER_APP_TOKEN_EXPRESSION,
    },
}
UPDATER_PUBLISHER_FIELD_VALUES = {
    STEP_MINT_WORKFLOW_PUBLISHER_APP_TOKEN: {"id": "publisher_app_token"},
    STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST: {"id": "maintenance_pr"},
    STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS: {"id": "commit"},
    STEP_CREATE_DRAFT_PULL_REQUEST: {
        "if": "steps.commit.outputs.changed == 'true' && "
        "steps.maintenance_pr.outputs.existing == 'false'",
    },
}
UPDATER_PUBLISHER_RUN_SHA256 = {
    STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY: "bd13dd746985e7fc0aeb48e4966da62abc3775685f8c16117911fe3c3ba5399e",
    STEP_VERIFY_WORKFLOW_PUBLISHER_APP_CONFIGURATION: "c01127376f95819c3abb8f99815aa9877ed4c5fd6ab248f0968feb458bdec033",
    STEP_PREPARE_CONSTRAINED_MAINTENANCE_BRANCH: "f2ac933375a5809a264b99461a0df96292e8bcf474a6c1bf390be8931c9a9474",
    STEP_REVALIDATE_REUSABLE_DRAFT_BRANCH: "e87da1dc670eb4fcd0bad20fcb11f93e46eb2774679c886b9e129cb383d78047",
    STEP_RERESOLVE_CURRENT_CANDIDATES: "dde36fd8ab4cf1864a6cd030ea2a3135ed31e9d96c453922cf05fb35bdabc727",
    STEP_COMMIT_AND_PUSH_APPROVED_UPDATER_PATHS: "ec7208d68b8e2f5c9f812515ed908b14e2a56ba1ef4ddca5479a315b356c54ad",
}
UPDATER_PUBLISHER_SCRIPT_SHA256 = {
    STEP_INSPECT_DRAFT_MAINTENANCE_PULL_REQUEST: "3d51794a9c57865efd999657eb78214383cf3c81f7575498eebb1ef9dcbf4699",
    STEP_CREATE_DRAFT_PULL_REQUEST: "83d13cd70cdb643a924d7a79abc1d52bb58f9e2979d5b1e925c7595446fe806c",
}
UPDATER_OUTCOME_JOB_KEYS = frozenset(
    {"needs", "if", "runs-on", "timeout-minutes", "permissions", "env", "steps"}
)
UPDATER_OUTCOME_ENV_VALUES = {
    "RESOLVER_RESULT": "${{ needs.resolver.result }}",
    "VALIDATOR_RESULT": "${{ needs.validator.result }}",
    "PUBLISHER_RESULT": "${{ needs.publisher.result }}",
    "RESOLVER_STATUS": "${{ needs.resolver.outputs.resolver_status }}",
    "HAS_UPDATES": "${{ needs.resolver.outputs.has_updates }}",
    "CANDIDATE_B64": "${{ needs.resolver.outputs.candidate_b64 }}",
    "CANDIDATE_SHA256": "${{ needs.resolver.outputs.candidate_sha256 }}",
}
UPDATER_OUTCOME_RUN_SHA256 = (
    "e60c38e06b2bde55e19a6ea1cc62667863093b3b0c31edbe9e98d71cb62c1012"
)
PYTHON_READER_PERMISSIONS = UPDATER_READ_ONLY_PERMISSIONS
PYTHON_PUBLISHER_PERMISSIONS = UPDATER_READ_ONLY_PERMISSIONS
PYTHON_WORKFLOW_PERMISSIONS: dict[str, str] = {}
PYTHON_OUTCOME_PERMISSIONS = PYTHON_WORKFLOW_PERMISSIONS
PYTHON_JOB_NAMES = frozenset({"resolve", "candidate-validate", "publish", "outcome"})
PYTHON_PUBLISHER_JOB_KEYS = frozenset(
    {"needs", "if", "runs-on", "timeout-minutes", "permissions", "env", "steps"}
)
PYTHON_PUBLISHER_ENV_VALUES = {
    "CANDIDATE": PYTHON_CANDIDATE_EXPRESSION,
}
PYTHON_PUBLISHER_STEP_PROFILE = (
    (CHECKOUT_REPOSITORY_STEP, STEP_KEYS_ACTION),
    (STEP_SETUP_REVIEWED_PYTHON, STEP_KEYS_ACTION),
    (STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY, STEP_KEYS_RUN),
    (STEP_VERIFY_PYTHON_PUBLISHER_APP_CONFIGURATION, STEP_KEYS_ENV_RUN),
    (STEP_MINT_PYTHON_PUBLISHER_APP_TOKEN, STEP_KEYS_SCRIPT),
    (STEP_INSPECT_PYTHON_DRAFT_MAINTENANCE_PULL_REQUEST, STEP_KEYS_SCRIPT),
    (STEP_PREPARE_PYTHON_MAINTENANCE_BRANCH, STEP_KEYS_ENV_RUN),
    (STEP_REVALIDATE_PYTHON_DRAFT_BRANCH, STEP_KEYS_CONDITIONAL_ENV_RUN),
    (STEP_RESTORE_PYTHON_PUBLISHER_BASE, STEP_KEYS_ENV_RUN),
    (STEP_APPLY_PYTHON_CANDIDATE, STEP_KEYS_ENV_RUN),
    (STEP_BUILD_PYTHON_DRAFT_PULL_REQUEST_BODY, STEP_KEYS_RUN),
    (STEP_CREATE_OR_UPDATE_PYTHON_DRAFT_PULL_REQUEST, STEP_KEYS_ACTION),
)
PYTHON_PUBLISHER_ACTIONS = {
    CHECKOUT_REPOSITORY_STEP: CHECKOUT_ACTION,
    STEP_SETUP_REVIEWED_PYTHON: SETUP_PYTHON_ACTION,
    STEP_MINT_PYTHON_PUBLISHER_APP_TOKEN: WORKFLOW_UPDATER_APP_TOKEN_ACTION,
    STEP_INSPECT_PYTHON_DRAFT_MAINTENANCE_PULL_REQUEST: GITHUB_SCRIPT_ACTION,
    STEP_CREATE_OR_UPDATE_PYTHON_DRAFT_PULL_REQUEST: CREATE_PULL_REQUEST_ACTION,
}
PYTHON_PUBLISHER_WITH_VALUES = {
    CHECKOUT_REPOSITORY_STEP: {
        "ref": "${{ github.sha }}",
        "fetch-depth": 1,
        "persist-credentials": False,
        "submodules": False,
    },
    STEP_SETUP_REVIEWED_PYTHON: {
        "python-version-file": CANONICAL_PYTHON_VERSION_FILE,
        "check-latest": False,
    },
    STEP_MINT_PYTHON_PUBLISHER_APP_TOKEN: {
        "client-id": WORKFLOW_UPDATER_APP_CLIENT_ID_EXPRESSION,
        "private-key": WORKFLOW_UPDATER_APP_PRIVATE_KEY_EXPRESSION,
        "owner": GITHUB_REPOSITORY_OWNER_EXPRESSION,
        "repositories": GITHUB_REPOSITORY_EXPRESSION,
        "permission-contents": "write",
        "permission-pull-requests": "write",
    },
    STEP_CREATE_OR_UPDATE_PYTHON_DRAFT_PULL_REQUEST: {
        "token": WORKFLOW_UPDATER_APP_TOKEN_EXPRESSION,
        "commit-message": "chore: update reviewed CPython 3.14",
        "title": "chore: update reviewed CPython 3.14",
        "body-path": PYTHON_VERSION_PR_BODY_FILE,
        "base": "master",
        "branch": "automation/update-framework-python-314",
        "delete-branch": False,
        "draft": True,
        "add-paths": PYTHON_PUBLISHER_ADD_PATHS,
    },
}
PYTHON_PUBLISHER_WITH_KEYS = {
    **{
        name: frozenset(values) for name, values in PYTHON_PUBLISHER_WITH_VALUES.items()
    },
    STEP_INSPECT_PYTHON_DRAFT_MAINTENANCE_PULL_REQUEST: frozenset(
        {"github-token", "script"}
    ),
}
PYTHON_PUBLISHER_STEP_ENV_VALUES = {
    STEP_VERIFY_PYTHON_PUBLISHER_APP_CONFIGURATION: {
        "WORKFLOW_UPDATER_APP_CLIENT_ID": WORKFLOW_UPDATER_APP_CLIENT_ID_EXPRESSION,
        "WORKFLOW_UPDATER_APP_PRIVATE_KEY": WORKFLOW_UPDATER_APP_PRIVATE_KEY_EXPRESSION,
    },
    STEP_PREPARE_PYTHON_MAINTENANCE_BRANCH: {
        "DEFAULT_BRANCH": DEFAULT_BRANCH_EXPRESSION,
        "MAINTENANCE_PR_EXISTS": "${{ steps.maintenance_pr.outputs.existing }}",
        UPDATER_PUBLISH_TOKEN_ENV: WORKFLOW_UPDATER_APP_TOKEN_EXPRESSION,
        "CANDIDATE": PYTHON_CANDIDATE_EXPRESSION,
    },
    STEP_REVALIDATE_PYTHON_DRAFT_BRANCH: {
        "DEFAULT_BRANCH": DEFAULT_BRANCH_EXPRESSION,
    },
    STEP_RESTORE_PYTHON_PUBLISHER_BASE: {
        "DEFAULT_BRANCH": DEFAULT_BRANCH_EXPRESSION,
    },
    STEP_APPLY_PYTHON_CANDIDATE: {
        "DEFAULT_BRANCH": DEFAULT_BRANCH_EXPRESSION,
    },
}
PYTHON_PUBLISHER_FIELD_VALUES = {
    STEP_MINT_PYTHON_PUBLISHER_APP_TOKEN: {"id": "publisher_app_token"},
    STEP_INSPECT_PYTHON_DRAFT_MAINTENANCE_PULL_REQUEST: {"id": "maintenance_pr"},
    STEP_REVALIDATE_PYTHON_DRAFT_BRANCH: {
        "if": "steps.maintenance_pr.outputs.existing == 'true'",
    },
}
PYTHON_PUBLISHER_RUN_SHA256 = {
    STEP_INSTALL_HASH_LOCKED_CI_DEPENDENCY: "bd13dd746985e7fc0aeb48e4966da62abc3775685f8c16117911fe3c3ba5399e",
    STEP_VERIFY_PYTHON_PUBLISHER_APP_CONFIGURATION: "c01127376f95819c3abb8f99815aa9877ed4c5fd6ab248f0968feb458bdec033",
    STEP_PREPARE_PYTHON_MAINTENANCE_BRANCH: "653ecd3a5d752b06c5bb69999b7138e3af259d8bd8ef88c647738081a3d6c7b4",
    STEP_REVALIDATE_PYTHON_DRAFT_BRANCH: "55bbd20d483361dcdb598d1100afc54c40b22d31909c143fdf1b8bdeeb531b1d",
    STEP_RESTORE_PYTHON_PUBLISHER_BASE: "dd3deb33caa76d77617755ad6ea7d7f64e940dd9114a97586cd035a567a01e54",
    STEP_APPLY_PYTHON_CANDIDATE: "2ab398b7a68d6124283d52fd2b57510158b5ab089e47f657cd70b3a2a19c5fed",
    STEP_BUILD_PYTHON_DRAFT_PULL_REQUEST_BODY: "d9ded799979e2ad7b3e1100cb33df4524a30233029fb3496b8d5019de472eeee",
}
PYTHON_PUBLISHER_SCRIPT_SHA256 = {
    STEP_INSPECT_PYTHON_DRAFT_MAINTENANCE_PULL_REQUEST: (
        "18cdf3715900c5a7c72eba2ca22afb4e75bfe6365a708f4f63251825f3e0e5d7"
    ),
}
PYTHON_OUTCOME_JOB_KEYS = frozenset(
    {"needs", "if", "runs-on", "timeout-minutes", "permissions", "env", "steps"}
)
PYTHON_OUTCOME_ENV_VALUES = {
    "RESOLVER_RESULT": "${{ needs.resolve.result }}",
    "CANDIDATE_RESULT": "${{ needs.candidate-validate.result }}",
    "PUBLISHER_RESULT": "${{ needs.publish.result }}",
    "RESOLVER_STATUS": "${{ needs.resolve.outputs.resolver_status }}",
    "UPDATE_AVAILABLE": "${{ needs.resolve.outputs.update_available }}",
    "CANDIDATE": PYTHON_CANDIDATE_EXPRESSION,
    "CANDIDATE_VALIDATED": "${{ needs.candidate-validate.outputs.candidate_validated }}",
}
PYTHON_OUTCOME_RUN_SHA256 = (
    "7ee08de961161f56f6989d3c02ad2e336c0f4c8d0d70b2522398bd079add3ff5"
)
UPDATER_SENSITIVE_KEY = re.compile(r"(?:secret|token)", re.IGNORECASE)
UPDATER_SENSITIVE_VALUE = re.compile(
    r"(?:\$\{\{[^}]*\b(?:secrets|token)\b[^}]*\}\}|"
    r"\bgithub\s*\.\s*token\b|\bsecrets\s*(?:\.|\[)|"
    r"\b(?:GITHUB_TOKEN|PUBLISH_TOKEN)\b|"
    r"\$(?:\{)?[A-Za-z_]*TOKEN[A-Za-z_]*\}?)",
    re.IGNORECASE,
)
PYTHON_VERSION_DECLARATION = re.compile(
    r"^\s*python-version:\s*['\"]?([^\s'\"#]+)['\"]?\s*(?:#.*)?$",
    re.MULTILINE,
)
CHECK_LATEST_FALSE = re.compile(r"^\s*check-latest:\s*false\s*(?:#.*)?$", re.MULTILINE)

OSV_JOB_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "pull-request-head": (
        "github.event.pull_request.base.sha",
        "github.event.pull_request.head.sha",
        "github.event.pull_request.number",
        "fetch-depth: 1",
        "Materialize trusted base Python version",
        'test "$(git rev-parse HEAD)" = "$BASE_SHA"',
        'git cat-file -e "$BASE_SHA^{commit}"',
        "git -c protocol.file.allow=never fetch --depth=1 --no-tags origin",
        '"+refs/pull/$PR_NUMBER/head:refs/remotes/origin/pr-$PR_NUMBER"',
        'test "$resolved_head" = "$HEAD_SHA"',
        'git cat-file -e "$HEAD_SHA^{commit}"',
        'if git cat-file -e "$BASE_SHA:.python-version" 2>/dev/null; then',
        'test "$(git cat-file -t "$BASE_SHA:.python-version")" = "blob"',
        'git cat-file -s "$BASE_SHA:.python-version"',
        '[ "$version_size" -le 32 ]',
        '[ ! -e "$PYTHON_VERSION_FILE" ]',
        '[ ! -L "$PYTHON_VERSION_FILE" ]',
        "umask 077",
        "set -C",
        'git show "$BASE_SHA:.python-version" > "$PYTHON_VERSION_FILE"',
        f"OSV_LEGACY_BASE_SHA: {OSV_LEGACY_BASE_SHA}",
        f"OSV_LEGACY_BASE_VERSION: {OSV_LEGACY_BASE_VERSION}",
        'test "$BASE_SHA" = "$OSV_LEGACY_BASE_SHA"',
        'version="$OSV_LEGACY_BASE_VERSION"',
        'if [ "$BASE_SHA" = "$OSV_LEGACY_BASE_SHA" ]; then',
        '[ "$version" = "$OSV_LEGACY_BASE_VERSION" ]',
        '[ -f "$PYTHON_VERSION_FILE" ]',
        '[[ "$version" =~ ^3\\.14\\.(0|[1-9][0-9]*)$ ]]',
        'printf \'%s\\n\' "$version" | cmp -s - "$PYTHON_VERSION_FILE"',
        OSV_TRUSTED_BASE_PYTHON_VERSION_FILE,
        'git cat-file -e "$HEAD_SHA:requirements-ci.lock"',
        "write_osv_input requirements-dev.txt requirements-dev.txt false",
        "write_osv_input requirements-ci.lock requirements-ci.txt true",
        "--format json",
        '--lockfile "$input_directory/requirements-dev.txt"',
        '--lockfile "$input_directory/requirements-ci.txt"',
        "compare-osv-results.py",
        CHECK_JSON_RESULT,
        "id: compare_osv",
        'echo "evidence_valid=true" >> "$GITHUB_OUTPUT"',
        UPLOAD_ARTIFACT,
        RETENTION_DAYS_ONE,
        IF_NO_FILES_FOUND_ERROR,
        "steps.compare_osv.outputs.evidence_valid == 'true'",
        "framework-ci-security-results/osv/base.json",
        "framework-ci-security-results/osv/head.json",
        "framework-ci-security-results/osv/comparison.json",
    ),
    "scheduled-advisory": (
        "ref: ${{ github.sha }}",
        "--format json",
        CHECK_JSON_RESULT,
        "id: scan_current_osv",
        'echo "evidence_valid=true" >> "$GITHUB_OUTPUT"',
        UPLOAD_ARTIFACT,
        RETENTION_DAYS_ONE,
        IF_NO_FILES_FOUND_ERROR,
        "steps.scan_current_osv.outputs.evidence_valid == 'true'",
        "framework-ci-security-results/osv/current.json",
    ),
}
OSV_PROHIBITED_SNIPPETS = (
    "--allow-no-lockfiles",
    "--recursive",
    SECURITY_EVENTS_WRITE,
    "$HEAD_SHA:.python-version",
    "framework-osv-pr-python-version",
)
SCORECARD_JOB_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "pull-request-head": (
        "github.event.pull_request.head.sha",
        CHECK_JSON_RESULT,
        "scorecard-results.json",
    ),
    "current-revision-advisory": (
        DEFAULT_BRANCH_CONTEXT,
        "ref: ${{ github.sha }}",
        CHECK_JSON_RESULT,
        UPLOAD_ARTIFACT,
        "path: ${{ runner.temp }}/scorecard-results.json",
        RETENTION_DAYS_ONE,
        IF_NO_FILES_FOUND_ERROR,
    ),
}


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot parse YAML: {exc}") from exc


def pull_request_target_errors(path: Path, text: str) -> list[str]:
    if not UNSAFE_TRIGGER.search(text):
        return []

    errors = [f"{path}: pull_request_target is forbidden"]
    if UNTRUSTED_INTERPOLATION.search(text):
        errors.append(
            f"{path}: pull_request_target must not interpolate PR title or body"
        )
    return errors


def id_token_permission_errors(path: Path, text: str) -> list[str]:
    if ID_TOKEN_WRITE.search(text):
        return [f"{path}: id-token: write is not allowed by this Framework CI contract"]
    return []


def github_token_reference_errors(path: Path, text: str) -> list[str]:
    if TOKEN_REFERENCE.search(text) and path.name not in TOKEN_REFERENCE_ALLOWLIST:
        return [f"{path}: GitHub token reference is not allow-listed for this workflow"]
    return []


def trust_boundary_errors(path: Path, text: str) -> list[str]:
    return [
        *pull_request_target_errors(path, text),
        *id_token_permission_errors(path, text),
        *github_token_reference_errors(path, text),
    ]


def is_safe_archive_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def is_safe_path_component(value: str) -> bool:
    path = PurePosixPath(value)
    return is_safe_archive_path(value) and len(path.parts) == 1


def required_record_fields(group: str, record: dict[str, Any]) -> set[str]:
    if group != "tool":
        return ACTION_FIELDS

    layout = record.get("layout")
    archive_type = record.get("archive_type")
    if layout == LAYOUT_EXECUTABLE and archive_type == ARCHIVE_TYPE_TAR_GZ:
        return TAR_EXECUTABLE_TOOL_FIELDS
    if layout == LAYOUT_EXECUTABLE:
        return EXECUTABLE_TOOL_FIELDS
    if layout == LAYOUT_TREE:
        return TREE_TOOL_FIELDS
    return TOOL_FIELDS


def action_release_resolution_errors(
    path: Path, name: str, record: dict[str, Any]
) -> list[str]:
    resolution = record.get("release_resolution")
    expected_resolution = ACTION_RELEASE_RESOLUTION_LATEST
    common = path.parents[2] / "ci" / "lib" / "common.sh"
    if common.is_file():
        try:
            values = load_canonical_ci_pins(path.parents[2])
            if name == values.get("CI_ACTION_CODEQL_REPOSITORY"):
                expected_resolution = ACTION_RELEASE_RESOLUTION_SAME_MAJOR
        except ValueError:
            pass

    errors: list[str] = []
    if not isinstance(resolution, str) or resolution not in ACTION_RELEASE_RESOLUTIONS:
        errors.append(f"{path}: action {name!r} has an unsupported release resolution")
    elif resolution != expected_resolution:
        errors.append(
            f"{path}: action {name!r} must use release resolution "
            f"{expected_resolution!r}"
        )
    if (
        resolution == ACTION_RELEASE_RESOLUTION_SAME_MAJOR
        and not CODEQL_ACTION_SERIES_TAG.fullmatch(str(record.get("version", "")))
    ):
        errors.append(
            f"{path}: action {name!r} same-major release resolution requires "
            "a v<major>.<minor>.<patch> version"
        )
    return errors


def common_record_errors(
    path: Path, group: str, name: str, record: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    if record.get("name") != name:
        errors.append(f"{path}: {group} {name!r} has a mismatched name")
    if not SHA.fullmatch(str(record.get("immutable_commit", ""))):
        errors.append(f"{path}: {group} {name!r} has no immutable commit SHA")
    release_url = str(record.get("upstream_release", ""))
    if not release_url.startswith("https://github.com/"):
        errors.append(f"{path}: {group} {name!r} has no GitHub upstream release")
    for field in ("version", "license", "purpose", "platform", "update_procedure"):
        if not isinstance(record.get(field), str) or not record[field].strip():
            errors.append(f"{path}: {group} {name!r} has an empty {field}")
    if group == "action":
        errors.extend(action_release_resolution_errors(path, name, record))
    return errors


def release_provenance_errors(
    path: Path, group: str, name: str, record: dict[str, Any]
) -> list[str]:
    """Bind every static lock record to one exact official release tuple."""

    errors: list[str] = []
    version = record.get("version")
    release = record.get("upstream_release")
    release_match = (
        GITHUB_RELEASE_URL.fullmatch(release) if isinstance(release, str) else None
    )
    if release_match is None:
        return [f"{path}: {group} {name!r} has no exact GitHub release URL"]
    release_identity = (
        release_match.group("owner"),
        release_match.group("repository"),
        release_match.group("tag"),
    )
    if not isinstance(version, str) or release_identity[2] != version:
        errors.append(
            f"{path}: {group} {name!r} release URL tag must match record.version"
        )
    if group == "action" and "/".join(release_identity[:2]) != name:
        errors.append(
            f"{path}: action {name!r} upstream release owner/repository must match its name"
        )
    if group != "tool":
        return errors

    asset_url = record.get("asset_url")
    asset_match = (
        GITHUB_RELEASE_ASSET_URL.fullmatch(asset_url)
        if isinstance(asset_url, str)
        else None
    )
    if asset_match is None:
        return [
            *errors,
            f"{path}: tool {name!r} has no exact GitHub release asset URL",
        ]
    asset_identity = (
        asset_match.group("owner"),
        asset_match.group("repository"),
        asset_match.group("tag"),
    )
    if asset_identity != release_identity:
        errors.append(
            f"{path}: tool {name!r} asset URL owner/repository/tag must match "
            "upstream_release and record.version"
        )
    if asset_match.group("asset") != record.get("asset"):
        errors.append(
            f"{path}: tool {name!r} asset URL must end in its exact locked asset"
        )
    return errors


def tool_asset_errors(path: Path, name: str, record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not is_safe_path_component(name):
        errors.append(f"{path}: tool {name!r} is not a safe output path component")
    if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", ""))):
        errors.append(f"{path}: tool {name!r} has no SHA-256 asset digest")

    archive_type = record.get("archive_type")
    layout = record.get("layout")
    if archive_type not in ALLOWED_ARCHIVE_TYPES:
        errors.append(f"{path}: tool {name!r} has an unsupported archive type")
    if layout not in {LAYOUT_EXECUTABLE, LAYOUT_TREE}:
        errors.append(f"{path}: tool {name!r} has an unsupported archive layout")
    if archive_type == ARCHIVE_TYPE_RAW and layout != LAYOUT_EXECUTABLE:
        errors.append(f"{path}: tool {name!r} raw assets must use executable layout")

    asset = str(record.get("asset", ""))
    if not is_safe_path_component(asset):
        errors.append(f"{path}: tool {name!r} has an unsafe release asset name")
    asset_url = str(record.get("asset_url", ""))
    parsed = urlparse(asset_url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or "/releases/download/" not in parsed.path
        or not parsed.path.endswith(f"/{asset}")
    ):
        errors.append(f"{path}: tool {name!r} has no direct GitHub release asset URL")
    return errors


def executable_tool_errors(path: Path, name: str, record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    archive_type = record.get("archive_type")
    if archive_type == ARCHIVE_TYPE_TAR_GZ and not is_safe_archive_path(
        str(record.get("archive_member", ""))
    ):
        errors.append(f"{path}: tool {name!r} has an unsafe executable archive member")
    if archive_type == ARCHIVE_TYPE_RAW and "archive_member" in record:
        errors.append(
            f"{path}: tool {name!r} raw assets must not declare an archive member"
        )
    if not is_safe_path_component(str(record.get("executable", ""))):
        errors.append(f"{path}: tool {name!r} has an unsafe executable output name")
    return errors


def tree_tool_errors(path: Path, name: str, record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if record.get("archive_type") != ARCHIVE_TYPE_TAR_GZ:
        errors.append(f"{path}: tool {name!r} tree layout requires a tar.gz asset")
    if not is_safe_path_component(str(record.get("archive_root", ""))):
        errors.append(f"{path}: tool {name!r} has an unsafe tree archive root")
    if not is_safe_archive_path(str(record.get("entrypoint", ""))):
        errors.append(f"{path}: tool {name!r} has an unsafe tree entrypoint")
    return errors


def tool_record_errors(path: Path, name: str, record: dict[str, Any]) -> list[str]:
    errors = tool_asset_errors(path, name, record)
    layout = record.get("layout")
    if layout == LAYOUT_EXECUTABLE:
        errors.extend(executable_tool_errors(path, name, record))
    if layout == LAYOUT_TREE:
        errors.extend(tree_tool_errors(path, name, record))
    return errors


def record_errors(path: Path, group: str, name: str, record: Any) -> list[str]:
    if not isinstance(record, dict):
        return [f"{path}: {group} {name!r} must be a mapping"]

    missing = sorted(required_record_fields(group, record).difference(record))
    if missing:
        return [f"{path}: {group} {name!r} lacks {', '.join(missing)}"]

    errors = [
        *common_record_errors(path, group, name, record),
        *release_provenance_errors(path, group, name, record),
    ]
    if group == "tool":
        errors.extend(tool_record_errors(path, name, record))
    return errors


def valid_lock_records(
    path: Path, group: str, records: Any
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if not isinstance(records, dict):
        return {}, [f"{path}: {group}s must be a mapping"]

    valid_records: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for raw_name, record in records.items():
        name = str(raw_name)
        record_validation_errors = record_errors(path, group, name, record)
        errors.extend(record_validation_errors)
        if not record_validation_errors and isinstance(record, dict):
            valid_records[name] = record
    return valid_records, errors


def load_lock(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    loaded = load_yaml(path)
    if not isinstance(loaded, dict):
        return {}, {}, [f"{path}: lock must be a mapping"]

    action_lock, action_errors = valid_lock_records(
        path, "action", loaded.get("actions")
    )
    tool_lock, tool_errors = valid_lock_records(path, "tool", loaded.get("tools"))
    errors = [*action_errors, *tool_errors]
    return action_lock, tool_lock, errors


def workflow_paths(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    return sorted(
        path
        for path in workflow_dir.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )


def uses_reference_and_comment(line: str) -> tuple[str, str] | None:
    """Return a workflow uses reference and its trailing version comment."""

    content = line.lstrip()
    if content.startswith("- "):
        content = content[2:].lstrip()
    if not content.startswith("uses:"):
        return None

    reference, separator, comment = (
        content.removeprefix("uses:").strip().partition(" #")
    )
    reference = reference.strip()
    if reference.startswith(("'", '"')):
        quote = reference[:1]
        if len(reference) < 2 or not reference.endswith(quote):
            return "", comment.strip()
        reference = reference[1:-1]
    return reference, comment.strip() if separator else ""


def locked_action_details(reference: str) -> tuple[str, str] | None:
    source, separator, pin = reference.partition("@")
    source_parts = source.split("/")
    if (
        not separator
        or not SHA.fullmatch(pin)
        or reference.startswith("docker://")
        or len(source_parts) < 2
        or not source_parts[0]
        or not source_parts[1]
    ):
        return None
    return "/".join(source_parts[:2]), pin


def action_pin_errors(
    path: Path,
    line_number: int,
    reference: str,
    comment: str,
    actions: dict[str, dict[str, Any]],
) -> list[str]:
    details = locked_action_details(reference)
    if details is None:
        return [
            f"{path}:{line_number}: {reference} must be a locked GitHub Action "
            "with a full immutable commit SHA"
        ]

    action, pin = details
    record = actions.get(action)
    if record is None:
        return [f"{path}:{line_number}: {action} is absent from the action lock"]

    errors: list[str] = []
    if pin != record["immutable_commit"]:
        errors.append(
            f"{path}:{line_number}: {action} SHA differs from the reviewed lock"
        )
    if comment != record["version"]:
        errors.append(
            f"{path}:{line_number}: {action} must have exact version comment "
            f"{record['version']!r}"
        )
    return errors


def line_pin_errors(
    path: Path,
    line_number: int,
    line: str,
    actions: dict[str, dict[str, Any]],
) -> list[str]:
    parsed = uses_reference_and_comment(line)
    if parsed is None:
        return []

    reference, comment = parsed
    if reference.startswith("./"):
        return []
    return action_pin_errors(path, line_number, reference, comment, actions)


def pin_errors(path: Path, text: str, actions: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        errors.extend(line_pin_errors(path, line_number, line, actions))
    return errors


def parsed_uses_references(node: Any, seen: set[int] | None = None) -> Iterable[Any]:
    """Yield every parsed workflow ``uses`` value without trusting YAML spelling."""

    if seen is None:
        seen = set()
    if isinstance(node, dict):
        identity = id(node)
        if identity in seen:
            return
        seen.add(identity)
        if "uses" in node:
            yield node["uses"]
        for value in node.values():
            yield from parsed_uses_references(value, seen)
    elif isinstance(node, list):
        identity = id(node)
        if identity in seen:
            return
        seen.add(identity)
        for value in node:
            yield from parsed_uses_references(value, seen)


def parsed_action_lock_errors(
    path: Path, data: Any, actions: dict[str, dict[str, Any]]
) -> list[str]:
    """Bind every parsed external Action reference to the reviewed action lock.

    Raw source checks remain responsible for the adjacent release-comment
    convention. This parsed pass is deliberately independent of YAML key
    spelling, so quoted keys and flow mappings cannot bypass SHA provenance.
    """

    errors: list[str] = []
    for reference in parsed_uses_references(data):
        if not isinstance(reference, str):
            errors.append(f"{path}: workflow uses references must be strings")
            continue
        if reference.startswith("./"):
            continue
        details = locked_action_details(reference)
        if details is None:
            errors.append(
                f"{path}: {reference} must be a locked GitHub Action with a "
                "full immutable commit SHA"
            )
            continue
        action, pin = details
        record = actions.get(action)
        if record is None:
            errors.append(f"{path}: {action} is absent from the action lock")
        elif pin != record["immutable_commit"]:
            errors.append(f"{path}: {action} SHA differs from the reviewed lock")
    return errors


def run_shell_default(data: dict[str, Any]) -> bool:
    defaults = data.get("defaults")
    return (
        isinstance(defaults, dict)
        and isinstance(defaults.get("run"), dict)
        and defaults["run"].get("shell") == "bash"
    )


def permission_definitions(data: dict[str, Any]) -> Iterable[tuple[str, Any]]:
    if "permissions" in data:
        yield "top-level", data["permissions"]
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if isinstance(job, dict) and "permissions" in job:
                yield f"job {job_name!r}", job["permissions"]


def permission_entry_errors(
    path: Path,
    scope: str,
    permission: Any,
    level: Any,
    allowed_writes: set[str],
) -> list[str]:
    if level not in ALLOWED_PERMISSION_LEVELS:
        return [
            f"{path}: {scope} {permission}: {level!r} is not an explicit permission level"
        ]
    if level != "write":
        return []
    if scope == "top-level":
        return [
            f"{path}: top-level write permissions are forbidden; scope them to a job"
        ]
    if permission not in allowed_writes:
        return [f"{path}: {permission}: write is not allow-listed for this workflow"]
    return []


def permission_scope_errors(
    path: Path,
    scope: str,
    permissions: Any,
    allowed_writes: set[str],
) -> list[str]:
    if not isinstance(permissions, dict):
        return [f"{path}: {scope} permissions must be a mapping"]

    errors: list[str] = []
    for permission, level in permissions.items():
        errors.extend(
            permission_entry_errors(path, scope, permission, level, allowed_writes)
        )
    return errors


def permission_errors(path: Path, data: dict[str, Any]) -> list[str]:
    allowed_writes = WRITE_PERMISSION_ALLOWLIST.get(path.name, set())
    errors: list[str] = []
    for scope, permissions in permission_definitions(data):
        errors.extend(permission_scope_errors(path, scope, permissions, allowed_writes))
    return errors


def concurrency_errors(path: Path, data: dict[str, Any]) -> list[str]:
    concurrency = data.get("concurrency")
    if not isinstance(concurrency, dict):
        return [f"{path}: workflow must declare a concurrency mapping"]
    errors: list[str] = []
    if (
        not isinstance(concurrency.get("group"), str)
        or not concurrency["group"].strip()
    ):
        errors.append(f"{path}: concurrency must declare a non-empty group")
    if type(concurrency.get("cancel-in-progress")) is not bool:
        errors.append(
            f"{path}: concurrency must declare cancel-in-progress as a boolean"
        )
    return errors


def python_version_file_value(line: str) -> str | None:
    """Parse one simple ``python-version-file`` declaration without regex backtracking."""

    declaration = line.lstrip()
    prefix = "python-version-file:"
    if not declaration.startswith(prefix):
        return None
    value = declaration.removeprefix(prefix).strip()
    if not value:
        return ""
    if value[0] not in {"'", '"'}:
        return value.split("#", 1)[0].rstrip()

    quote = value[0]
    closing_quote = value.find(quote, 1)
    if closing_quote < 0:
        return value
    trailing = value[closing_quote + 1 :].strip()
    if trailing and not trailing.startswith("#"):
        return value
    return value[1:closing_quote]


def python_version_file_values(text: str) -> list[str]:
    """Return version-file values from workflow text using linear line parsing."""

    values: list[str] = []
    for line in text.splitlines():
        value = python_version_file_value(line)
        if value is not None:
            values.append(value)
    return values


def setup_python_errors(path: Path, text: str) -> list[str]:
    if SETUP_PYTHON_REFERENCE not in text:
        return []

    errors: list[str] = []
    setup_count = text.count(SETUP_PYTHON_REFERENCE)
    if PYTHON_VERSION_DECLARATION.search(text):
        errors.append(
            f"{path}: setup-python must select {CANONICAL_PYTHON_VERSION_FILE} "
            "through python-version-file, never python-version"
        )
    version_files = python_version_file_values(text)
    allowed_files = {CANONICAL_PYTHON_VERSION_FILE}
    if path.name == PYTHON_VERSION_MAINTENANCE_WORKFLOW:
        allowed_files.add(PYTHON_VERSION_CANDIDATE_FILE)
    if path.name == OSV_WORKFLOW:
        allowed_files.add(OSV_TRUSTED_BASE_PYTHON_VERSION_FILE)
    if len(version_files) != setup_count or any(
        version_file not in allowed_files for version_file in version_files
    ):
        errors.append(
            f"{path}: every setup-python use must select the canonical "
            f"{CANONICAL_PYTHON_VERSION_FILE} file"
        )
    if len(CHECK_LATEST_FALSE.findall(text)) < setup_count:
        errors.append(f"{path}: setup-python must set check-latest: false")
    return errors


def security_tool_downloader_errors(path: Path, text: str) -> list[str]:
    if SECURITY_TOOL_DOWNLOADER not in text:
        return []

    errors: list[str] = []
    if SETUP_PYTHON_REFERENCE not in text:
        errors.append(
            f"{path}: the security-tool downloader requires reviewed setup-python"
        )
    normalized = " ".join(text.split())
    if (
        "python3 -m pip install" not in normalized
        or HASH_LOCKED_CI_REQUIREMENTS not in normalized
    ):
        errors.append(
            f"{path}: the security-tool downloader requires hash-locked "
            "requirements-ci.lock installation"
        )
    return errors


def python_provisioning_errors(path: Path, text: str) -> list[str]:
    return [
        *setup_python_errors(path, text),
        *security_tool_downloader_errors(path, text),
    ]


def workflow_events(data: dict[Any, Any]) -> dict[str, Any] | None:
    raw_events = data.get("on", data.get(True))
    return raw_events if isinstance(raw_events, dict) else None


def as_job_steps(
    path: Path, job_name: str, job: Any
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(job, dict):
        return [], [f"{path}: Python maintenance job {job_name!r} must be a mapping"]
    steps = job.get("steps")
    if not isinstance(steps, list):
        return [], [f"{path}: Python maintenance job {job_name!r} must define steps"]
    mappings = [step for step in steps if isinstance(step, dict)]
    if len(mappings) != len(steps):
        return [], [f"{path}: Python maintenance job {job_name!r} has a malformed step"]
    return mappings, []


def job_run_text(steps: Iterable[dict[str, Any]]) -> str:
    return "\n".join(str(step.get("run", "")) for step in steps)


def contains_sensitive_reference(value: str) -> bool:
    """Reject secret contexts and GitHub-context forms that can expose its token."""

    if SHELL_GITHUB_TOKEN_REFERENCE.search(value):
        return True
    for match in GITHUB_EXPRESSION.finditer(value):
        expression = match.group("expression")
        if (
            SECRET_CONTEXT_REFERENCE.search(expression)
            or GITHUB_TOKEN_REFERENCE.search(expression)
            or BARE_GITHUB_CONTEXT_REFERENCE.search(expression)
        ):
            return True
    return False


def sensitive_reference_paths(
    value: Any, path: tuple[str, ...] = ()
) -> list[tuple[str, ...]]:
    """Return parsed locations containing an explicit token or secret reference."""

    if isinstance(value, str):
        return [path] if contains_sensitive_reference(value) else []
    if isinstance(value, dict):
        paths: list[tuple[str, ...]] = []
        for key, item in value.items():
            paths.extend(sensitive_reference_paths(item, (*path, str(key))))
        return paths
    if isinstance(value, list):
        paths = []
        for index, item in enumerate(value):
            paths.extend(sensitive_reference_paths(item, (*path, str(index))))
        return paths
    return []


def normalized_needs(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def read_only_job_errors(path: Path, job_name: str, job: Any) -> list[str]:
    if not isinstance(job, dict):
        return []
    if job.get("permissions") != PYTHON_READER_PERMISSIONS:
        return [
            f"{path}: Python maintenance job {job_name!r} must remain contents: read only"
        ]
    return []


def create_pull_request_steps(
    steps: Iterable[dict[str, Any]],
) -> list[tuple[int, dict[str, Any]]]:
    matches: list[tuple[int, dict[str, Any]]] = []
    for index, step in enumerate(steps):
        reference = step.get("uses")
        if isinstance(reference, str) and reference.startswith(
            "peter" + "-evans/create-pull-request@"
        ):
            matches.append((index, step))
    return matches


def python_version_trigger_errors(path: Path, data: dict[str, Any]) -> list[str]:
    events = workflow_events(data)
    if not isinstance(events, dict) or set(events) != {"workflow_dispatch", "schedule"}:
        return [
            f"{path}: Python maintenance must be scheduled/manual only with no other trigger"
        ]
    if not isinstance(events.get("schedule"), list) or not events["schedule"]:
        return [f"{path}: Python maintenance must declare a schedule"]
    return []


def python_version_jobs(
    path: Path, data: dict[str, Any]
) -> tuple[tuple[Any, Any, Any, Any] | None, list[str]]:
    jobs = data.get("jobs")
    required_jobs = PYTHON_JOB_NAMES
    if not isinstance(jobs, dict) or set(jobs) != required_jobs:
        return None, [
            f"{path}: Python maintenance must define exactly resolve, candidate-validate, publish, and outcome jobs"
        ]
    return (
        jobs["resolve"],
        jobs["candidate-validate"],
        jobs["publish"],
        jobs["outcome"],
    ), []


def python_version_job_access_errors(
    path: Path, resolve: Any, candidate: Any, publish: Any, outcome: Any
) -> list[str]:
    errors: list[str] = []
    errors.extend(read_only_job_errors(path, "resolve", resolve))
    errors.extend(read_only_job_errors(path, "candidate-validate", candidate))
    if (
        not isinstance(publish, dict)
        or publish.get("permissions") != PYTHON_PUBLISHER_PERMISSIONS
    ):
        errors.append(
            f"{path}: Python maintenance publish job must retain only native contents: read"
        )
    if (
        not isinstance(outcome, dict)
        or outcome.get("permissions") != PYTHON_OUTCOME_PERMISSIONS
    ):
        errors.append(
            f"{path}: Python maintenance outcome job must declare empty permissions"
        )
    if isinstance(candidate, dict) and normalized_needs(candidate.get("needs")) != {
        "resolve"
    }:
        errors.append(
            f"{path}: Python maintenance candidate job must need resolve only"
        )
    if isinstance(publish, dict) and normalized_needs(publish.get("needs")) != {
        "resolve",
        "candidate-validate",
    }:
        errors.append(
            f"{path}: Python maintenance publish job must need both prior jobs"
        )
    if isinstance(outcome, dict) and normalized_needs(outcome.get("needs")) != {
        "resolve",
        "candidate-validate",
        "publish",
    }:
        errors.append(
            f"{path}: Python maintenance outcome job must need resolve, candidate-validate, and publish"
        )
    if not isinstance(outcome, dict) or outcome.get("if") != ALWAYS_CONDITION:
        errors.append(
            f"{path}: Python maintenance outcome job must always report the terminal result"
        )
    return errors


def python_version_resolver_errors(
    path: Path, resolve: Any, resolve_run: str
) -> list[str]:
    expected_outputs = {
        "resolver_status": "${{ steps.resolve.outputs.status }}",
        "update_available": "${{ steps.resolve.outputs.update_available }}",
        "candidate": "${{ steps.resolve.outputs.candidate }}",
    }
    errors: list[str] = []
    if not isinstance(resolve, dict) or resolve.get("outputs") != expected_outputs:
        errors.append(
            f"{path}: resolve must expose reviewed status, update_available, and candidate outputs"
        )
    if "update-python-version.py --check --write-github-output" not in resolve_run:
        errors.append(
            f"{path}: resolve must use the no-write updater check with GitHub outputs"
        )
    return errors


def python_version_read_only_secret_errors(
    path: Path, resolve: Any, candidate: Any
) -> list[str]:
    errors: list[str] = []
    for job_name, job in (("resolve", resolve), ("candidate-validate", candidate)):
        if sensitive_reference_paths(job):
            errors.append(
                f"{path}: Python maintenance read-only job {job_name!r} must not "
                "declare a GitHub token or secret"
            )
    return errors


def python_version_candidate_run_errors(path: Path, candidate_run: str) -> list[str]:
    candidate_file_lines = [
        line.strip().rstrip("\\").strip()
        for line in candidate_run.splitlines()
        if "--write-candidate-file" in line
    ]
    if (
        "update-python-version.py --check" not in candidate_run
        or "--update" in candidate_run
        or '--expected-candidate "$CANDIDATE"' not in candidate_run
        or candidate_file_lines != ["--write-candidate-file"]
    ):
        return [
            f"{path}: candidate validation must independently validate and materialize only "
            "the fixed controlled RUNNER_TEMP candidate file without a caller path"
        ]
    return []


def python_version_candidate_gate_errors(path: Path, candidate: Any) -> list[str]:
    candidate_if = candidate.get("if") if isinstance(candidate, dict) else None
    if (
        not isinstance(candidate_if, str)
        or RESOLVER_UPDATE_AVAILABLE_CONDITION not in candidate_if
    ):
        return [f"{path}: candidate job must be gated on an available resolver update"]
    return []


def python_version_publisher_gate_errors(path: Path, publish: Any) -> list[str]:
    publish_if = publish.get("if") if isinstance(publish, dict) else None
    publisher_conditions = (
        "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
        RESOLVER_UPDATE_AVAILABLE_CONDITION,
        "needs.candidate-validate.outputs.candidate_validated == 'true'",
        "github.repository == 'Easton97-Jens/ModSecurity-test-Framework'",
        "github.ref == 'refs/heads/master'",
    )
    if not isinstance(publish_if, str) or any(
        condition not in publish_if for condition in publisher_conditions
    ):
        return [
            f"{path}: publisher must be gated on trusted repository/default-ref and validated candidate"
        ]
    return []


def python_publisher_step_error(path: Path, name: str, detail: str) -> str:
    return f"{path}: CPython publisher step {name!r} {detail}"


def python_version_publisher_step_key_errors(
    path: Path, step: dict[str, Any], name: str, expected_keys: frozenset[str]
) -> list[str]:
    if set(step) == expected_keys:
        return []
    return [
        python_publisher_step_error(path, name, "must match its reviewed key profile")
    ]


def python_version_publisher_step_action_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_action = PYTHON_PUBLISHER_ACTIONS.get(name)
    if expected_action is None:
        return []
    uses = step.get("uses")
    action = uses.split("@", 1)[0] if isinstance(uses, str) else None
    if action == expected_action:
        return []
    return [python_publisher_step_error(path, name, f"must use {expected_action}")]


def python_version_publisher_script_errors(
    path: Path, name: str, with_values: dict[Any, Any]
) -> list[str]:
    if name != STEP_INSPECT_PYTHON_DRAFT_MAINTENANCE_PULL_REQUEST:
        return []
    errors: list[str] = []
    if with_values.get("github-token") != WORKFLOW_UPDATER_APP_TOKEN_EXPRESSION:
        errors.append(
            f"{path}: CPython Draft inspection must use the scoped GitHub App token"
        )
    script = with_values.get("script")
    if not isinstance(script, str) or (
        publisher_body_digest(script) != PYTHON_PUBLISHER_SCRIPT_SHA256[name]
    ):
        errors.append(
            f"{path}: CPython Draft inspection script must match the reviewed SHA-256"
        )
    return errors


def python_version_publisher_step_with_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_with_keys = PYTHON_PUBLISHER_WITH_KEYS.get(name)
    if expected_with_keys is None:
        return []
    errors: list[str] = []
    with_values = step.get("with")
    if not isinstance(with_values, dict) or set(with_values) != expected_with_keys:
        errors.append(
            python_publisher_step_error(
                path, name, "must match its reviewed with profile"
            )
        )
        with_values = {}
    expected_with_values = PYTHON_PUBLISHER_WITH_VALUES.get(name)
    if expected_with_values is not None and with_values != expected_with_values:
        errors.append(
            python_publisher_step_error(path, name, "must use reviewed with values")
        )
    if name == STEP_CREATE_OR_UPDATE_PYTHON_DRAFT_PULL_REQUEST:
        base = with_values.get("base")
        branch = with_values.get("branch")
        if isinstance(base, str) and isinstance(branch, str) and base == branch:
            errors.append(
                python_publisher_step_error(
                    path, name, "must use distinct base and maintenance branches"
                )
            )
    errors.extend(python_version_publisher_script_errors(path, name, with_values))
    return errors


def python_version_publisher_step_environment_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_environment = PYTHON_PUBLISHER_STEP_ENV_VALUES.get(name)
    if expected_environment is None or step.get("env") == expected_environment:
        return []
    return [
        python_publisher_step_error(path, name, "must use the reviewed environment")
    ]


def python_version_publisher_step_field_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    return [
        python_publisher_step_error(path, name, f"must use the reviewed {field}")
        for field, expected_value in PYTHON_PUBLISHER_FIELD_VALUES.get(name, {}).items()
        if step.get(field) != expected_value
    ]


def python_version_publisher_step_run_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_digest = PYTHON_PUBLISHER_RUN_SHA256.get(name)
    if expected_digest is None:
        return []
    run = step.get("run")
    if isinstance(run, str) and publisher_body_digest(run) == expected_digest:
        return []
    return [
        f"{path}: CPython publisher run body {name!r} must match the reviewed SHA-256"
    ]


def python_version_publisher_step_errors(
    path: Path, step: dict[str, Any], name: str, expected_keys: frozenset[str]
) -> list[str]:
    return [
        *python_version_publisher_step_key_errors(path, step, name, expected_keys),
        *python_version_publisher_step_action_errors(path, step, name),
        *python_version_publisher_step_with_errors(path, step, name),
        *python_version_publisher_step_environment_errors(path, step, name),
        *python_version_publisher_step_field_errors(path, step, name),
        *python_version_publisher_step_run_errors(path, step, name),
    ]


def python_version_publisher_profile_errors(path: Path, publish: Any) -> list[str]:
    if not isinstance(publish, dict):
        return [f"{path}: CPython publisher job must be a mapping"]
    errors: list[str] = []
    if set(publish) != PYTHON_PUBLISHER_JOB_KEYS:
        errors.append(
            f"{path}: CPython publisher job must match its reviewed key profile"
        )
    if publish.get("runs-on") != "ubuntu-latest":
        errors.append(f"{path}: CPython publisher must use the reviewed runner")
    if publish.get("timeout-minutes") != 15:
        errors.append(f"{path}: CPython publisher must use the reviewed timeout")
    if publish.get("env") != PYTHON_PUBLISHER_ENV_VALUES:
        errors.append(
            f"{path}: CPython publisher must use the reviewed candidate input"
        )
    steps = publish.get("steps")
    if not isinstance(steps, list):
        return [*errors, f"{path}: CPython publisher steps must be a list"]
    expected_names = [name for name, _keys in PYTHON_PUBLISHER_STEP_PROFILE]
    actual_names = [
        step.get("name") if isinstance(step, dict) else None for step in steps
    ]
    if actual_names != expected_names:
        return [
            *errors,
            f"{path}: CPython publisher steps must match the reviewed order and count",
        ]
    for step, (name, expected_keys) in zip(steps, PYTHON_PUBLISHER_STEP_PROFILE):
        assert isinstance(step, dict)
        errors.extend(
            python_version_publisher_step_errors(path, step, name, expected_keys)
        )
    return errors


def python_version_outcome_errors(path: Path, outcome: Any) -> list[str]:
    if not isinstance(outcome, dict):
        return [f"{path}: CPython maintenance outcome job must be a mapping"]
    errors: list[str] = []
    if set(outcome) != PYTHON_OUTCOME_JOB_KEYS:
        errors.append(
            f"{path}: CPython maintenance outcome must match its reviewed key profile"
        )
    if outcome.get("runs-on") != "ubuntu-latest" or outcome.get("timeout-minutes") != 5:
        errors.append(
            f"{path}: CPython maintenance outcome must use the reviewed runner and timeout"
        )
    if outcome.get("env") != PYTHON_OUTCOME_ENV_VALUES:
        errors.append(
            f"{path}: CPython maintenance outcome must use reviewed terminal-state inputs"
        )
    if sensitive_reference_paths(outcome):
        errors.append(
            f"{path}: CPython maintenance outcome must not receive a token or secret"
        )
    steps = outcome.get("steps")
    if not isinstance(steps, list) or len(steps) != 1 or not isinstance(steps[0], dict):
        return [
            *errors,
            f"{path}: CPython maintenance outcome must have exactly one reviewed report step",
        ]
    step = steps[0]
    if set(step) != STEP_KEYS_RUN or step.get("name") != STEP_REPORT_PYTHON_OUTCOME:
        errors.append(
            f"{path}: CPython maintenance outcome step must match the reviewed profile"
        )
    run = step.get("run")
    if (
        not isinstance(run, str)
        or publisher_body_digest(run) != PYTHON_OUTCOME_RUN_SHA256
    ):
        errors.append(
            f"{path}: CPython maintenance outcome must match the reviewed fail-closed report"
        )
    return errors


def python_version_sensitive_reference_errors(
    path: Path, data: dict[str, Any]
) -> list[str]:
    expected = {
        (
            "jobs",
            "publish",
            "steps",
            "3",
            "env",
            "WORKFLOW_UPDATER_APP_PRIVATE_KEY",
        ),
        (
            "jobs",
            "publish",
            "steps",
            "4",
            "with",
            "private-key",
        ),
    }
    if set(sensitive_reference_paths(data)) != expected:
        return [
            f"{path}: CPython publisher may use only the reviewed GitHub App private-key references"
        ]
    return []


def python_version_maintenance_errors(path: Path, data: dict[str, Any]) -> list[str]:
    if path.name != PYTHON_VERSION_MAINTENANCE_WORKFLOW:
        return []

    errors = python_version_trigger_errors(path, data)
    if data.get("permissions") != PYTHON_WORKFLOW_PERMISSIONS:
        errors.append(
            f"{path}: Python maintenance must deny workflow-level permissions and scope read access to its jobs"
        )
    jobs, job_errors = python_version_jobs(path, data)
    errors.extend(job_errors)
    if jobs is None:
        return errors

    resolve, candidate, publish, outcome = jobs
    errors.extend(
        python_version_job_access_errors(path, resolve, candidate, publish, outcome)
    )

    resolve_steps, resolve_step_errors = as_job_steps(path, "resolve", resolve)
    candidate_steps, candidate_step_errors = as_job_steps(
        path, "candidate-validate", candidate
    )
    _, publish_step_errors = as_job_steps(path, "publish", publish)
    _outcome_steps, outcome_step_errors = as_job_steps(path, "outcome", outcome)
    errors.extend(resolve_step_errors)
    errors.extend(candidate_step_errors)
    errors.extend(publish_step_errors)
    errors.extend(outcome_step_errors)
    resolve_run = job_run_text(resolve_steps)
    candidate_run = job_run_text(candidate_steps)
    errors.extend(python_version_resolver_errors(path, resolve, resolve_run))
    errors.extend(python_version_read_only_secret_errors(path, resolve, candidate))
    errors.extend(python_version_candidate_run_errors(path, candidate_run))
    errors.extend(python_version_candidate_gate_errors(path, candidate))
    errors.extend(python_version_publisher_gate_errors(path, publish))
    errors.extend(python_version_publisher_profile_errors(path, publish))
    errors.extend(python_version_outcome_errors(path, outcome))
    errors.extend(python_version_sensitive_reference_errors(path, data))
    return errors


def is_job_header(line: str) -> bool:
    stripped = line.rstrip()
    return (
        line.startswith("  ")
        and not line.startswith("   ")
        and not stripped.lstrip().startswith("#")
        and stripped.endswith(":")
    )


def job_text(text: str, name: str) -> str | None:
    selected: list[str] = []
    collecting = False
    for line in text.splitlines(keepends=True):
        if is_job_header(line):
            if collecting:
                return "".join(selected)
            collecting = line.strip() == f"{name}:"
        if collecting:
            selected.append(line)
    return "".join(selected) if selected else None


def require_workflow_text(
    path: Path, section_name: str, section: str | None, snippets: Iterable[str]
) -> list[str]:
    if section is None:
        return [f"{path}: required job {section_name!r} is absent"]
    return [
        f"{path}: job {section_name!r} must contain {snippet!r}"
        for snippet in snippets
        if snippet not in section
    ]


def job_requirement_errors(
    path: Path, text: str, requirements: dict[str, tuple[str, ...]]
) -> list[str]:
    errors: list[str] = []
    for job_name, snippets in requirements.items():
        errors.extend(
            require_workflow_text(path, job_name, job_text(text, job_name), snippets)
        )
    return errors


def updater_sensitive_references(value: Any, location: str = "job") -> list[str]:
    """Find token-bearing values/keys after YAML parsing, never by comments."""

    if isinstance(value, dict):
        references: list[str] = []
        for raw_key, child in value.items():
            key = str(raw_key)
            child_location = f"{location}.{key}"
            if UPDATER_SENSITIVE_KEY.search(key):
                references.append(child_location)
            references.extend(updater_sensitive_references(child, child_location))
        return references
    if isinstance(value, list):
        return [
            reference
            for index, child in enumerate(value)
            for reference in updater_sensitive_references(child, f"{location}[{index}]")
        ]
    if isinstance(value, str) and UPDATER_SENSITIVE_VALUE.search(value):
        return [location]
    return []


def updater_read_only_job_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Enforce least privilege for named non-publishing updater jobs."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [f"{path}: updater must define resolver, validator, and outcome jobs"]

    errors: list[str] = []
    for name in ("resolver", "validator"):
        job = jobs.get(name)
        if not isinstance(job, dict):
            errors.append(f"{path}: updater {name} job must be a mapping")
            continue
        if job.get("permissions") != UPDATER_READ_ONLY_PERMISSIONS:
            errors.append(
                f"{path}: updater {name} must declare exactly "
                "{contents: read} permissions"
            )
        references = updater_sensitive_references(job, f"jobs.{name}")
        if references:
            errors.append(
                f"{path}: updater {name} must not contain secrets or token "
                f"expressions ({', '.join(sorted(set(references)))})"
            )
    outcome = jobs.get("outcome")
    if not isinstance(outcome, dict):
        errors.append(f"{path}: updater outcome job must be a mapping")
    else:
        if outcome.get("permissions") != UPDATER_OUTCOME_PERMISSIONS:
            errors.append(
                f"{path}: updater outcome must declare exactly empty permissions"
            )
        references = updater_sensitive_references(outcome, "jobs.outcome")
        if references:
            errors.append(
                f"{path}: updater outcome must not contain secrets or token "
                f"expressions ({', '.join(sorted(set(references)))})"
            )
    return errors


def updater_job_topology_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Keep all token-bearing or write-capable updater work in publisher only."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [
            f"{path}: updater must define exactly resolver, validator, publisher, and outcome jobs"
        ]
    errors: list[str] = []
    if set(jobs) != UPDATER_JOB_NAMES:
        errors.append(
            f"{path}: updater must define exactly resolver, validator, publisher, and outcome jobs"
        )
    if data.get("permissions") != UPDATER_READ_ONLY_PERMISSIONS:
        errors.append(
            f"{path}: updater top-level permissions must be exactly {UPDATER_READ_ONLY_PERMISSIONS}"
        )
    top_level_references = updater_sensitive_references(data.get("env", {}), "env")
    if top_level_references:
        errors.append(
            f"{path}: updater must not contain secrets or token expressions outside "
            f"publisher ({', '.join(sorted(set(top_level_references)))})"
        )
    publisher = jobs.get("publisher")
    if not isinstance(publisher, dict):
        errors.append(f"{path}: updater publisher job must be a mapping")
    elif publisher.get("permissions") != UPDATER_PUBLISHER_PERMISSIONS:
        errors.append(
            f"{path}: updater publisher must declare exactly "
            f"{UPDATER_PUBLISHER_PERMISSIONS} permissions"
        )
    return errors


def job_needs(job: dict[str, Any]) -> set[str] | None:
    value = job.get("needs")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return None


def updater_ordering_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Require the parsed resolver → validator → publisher trust ordering."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [
            f"{path}: updater must define ordered resolver/validator/publisher/outcome jobs"
        ]
    validator = jobs.get("validator")
    publisher = jobs.get("publisher")
    outcome = jobs.get("outcome")
    errors: list[str] = []
    if not isinstance(validator, dict):
        errors.append(f"{path}: updater validator job must be a mapping")
    elif job_needs(validator) != {"resolver"}:
        errors.append(f"{path}: updater validator must need exactly resolver")
    if not isinstance(publisher, dict):
        errors.append(f"{path}: updater publisher job must be a mapping")
        return errors
    if job_needs(publisher) != {"resolver", "validator"}:
        errors.append(f"{path}: updater publisher must need resolver and validator")
    expected_if = f"{DEFAULT_BRANCH_REF_CONDITION} && {UPDATER_HAS_UPDATES_CONDITION}"
    actual_if = publisher.get("if")
    if not isinstance(actual_if, str) or " ".join(actual_if.split()) != expected_if:
        errors.append(
            f"{path}: updater publisher must be gated to the default branch and "
            "resolver has_updates output"
        )
    if not isinstance(outcome, dict):
        errors.append(f"{path}: updater outcome job must be a mapping")
        return errors
    if job_needs(outcome) != {"resolver", "validator", "publisher"}:
        errors.append(
            f"{path}: updater outcome must need resolver, validator, and publisher"
        )
    if outcome.get("if") != ALWAYS_CONDITION:
        errors.append(f"{path}: updater outcome must always report the terminal result")
    return errors


def updater_trigger_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Allow the write-capable updater to start only by schedule or dispatch."""

    yaml_data: dict[Any, Any] = data
    has_string_on = "on" in yaml_data
    has_yaml_boolean_on = True in yaml_data
    if has_string_on and has_yaml_boolean_on:
        return [f"{path}: updater trigger declaration is ambiguous"]
    triggers = yaml_data.get("on") if has_string_on else yaml_data.get(True)
    if triggers != UPDATER_TRIGGERS:
        return [
            f"{path}: updater triggers must be exactly the reviewed schedule and workflow_dispatch"
        ]
    return []


def publisher_body_digest(value: str) -> str:
    """Return the fixed digest for a YAML-parsed publisher program body."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def publisher_job_setting_errors(path: Path, publisher: dict[str, Any]) -> list[str]:
    """Validate the reviewed publisher job fields before checking its steps."""

    errors: list[str] = []
    if set(publisher) != UPDATER_PUBLISHER_JOB_KEYS:
        errors.append(
            f"{path}: updater publisher job must match its reviewed key profile"
        )
    if publisher.get("runs-on") != "ubuntu-latest":
        errors.append(f"{path}: updater publisher must use the reviewed runner")
    if publisher.get("timeout-minutes") != 25:
        errors.append(f"{path}: updater publisher must use the reviewed timeout")
    return errors


def publisher_step_key_errors(
    path: Path, step: dict[str, Any], name: str, expected_keys: frozenset[str]
) -> list[str]:
    if set(step) == expected_keys:
        return []
    return [f"{path}: publisher step {name!r} must match its reviewed key profile"]


def publisher_step_action_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_action = UPDATER_PUBLISHER_ACTIONS.get(name)
    if expected_action is None:
        return []
    uses = step.get("uses")
    action_name = uses.split("@", 1)[0] if isinstance(uses, str) else None
    if action_name == expected_action:
        return []
    return [f"{path}: publisher step {name!r} must use {expected_action}"]


def publisher_script_body_errors(
    path: Path, name: str, with_values: dict[Any, Any]
) -> list[str]:
    if name not in UPDATER_PUBLISHER_SCRIPT_SHA256:
        return []

    errors: list[str] = []
    if with_values.get("github-token") != WORKFLOW_UPDATER_APP_TOKEN_EXPRESSION:
        errors.append(
            f"{path}: publisher step {name!r} must use the scoped GitHub App token"
        )
    script = with_values.get("script")
    if not isinstance(script, str) or (
        publisher_body_digest(script) != UPDATER_PUBLISHER_SCRIPT_SHA256[name]
    ):
        errors.append(
            f"{path}: publisher github-script body {name!r} must match the reviewed SHA-256"
        )
    return errors


def publisher_step_with_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_with_keys = UPDATER_PUBLISHER_WITH_KEYS.get(name)
    if expected_with_keys is None:
        return []

    errors: list[str] = []
    with_values = step.get("with")
    if not isinstance(with_values, dict) or set(with_values) != expected_with_keys:
        errors.append(
            f"{path}: publisher step {name!r} must match its reviewed with profile"
        )
        with_values = {}
    expected_with_values = UPDATER_PUBLISHER_WITH_VALUES.get(name)
    if expected_with_values is not None and with_values != expected_with_values:
        errors.append(f"{path}: publisher step {name!r} must use reviewed with values")
    errors.extend(publisher_script_body_errors(path, name, with_values))
    return errors


def publisher_step_environment_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    expected_environment = UPDATER_PUBLISHER_ENV_VALUES.get(name)
    if expected_environment is None or step.get("env") == expected_environment:
        return []
    return [f"{path}: publisher step {name!r} must use the reviewed environment"]


def publisher_step_field_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    return [
        f"{path}: publisher step {name!r} must use the reviewed {field}"
        for field, expected_value in UPDATER_PUBLISHER_FIELD_VALUES.get(
            name, {}
        ).items()
        if step.get(field) != expected_value
    ]


def publisher_step_run_errors(path: Path, step: dict[str, Any], name: str) -> list[str]:
    expected_run_digest = UPDATER_PUBLISHER_RUN_SHA256.get(name)
    if expected_run_digest is None:
        return []
    run = step.get("run")
    if isinstance(run, str) and publisher_body_digest(run) == expected_run_digest:
        return []
    return [f"{path}: publisher run body {name!r} must match the reviewed SHA-256"]


def publisher_step_profile_errors(
    path: Path, step: dict[str, Any], name: str, expected_keys: frozenset[str]
) -> list[str]:
    """Return all exact-profile errors for one already identified publisher step."""

    return [
        *publisher_step_key_errors(path, step, name, expected_keys),
        *publisher_step_action_errors(path, step, name),
        *publisher_step_with_errors(path, step, name),
        *publisher_step_environment_errors(path, step, name),
        *publisher_step_field_errors(path, step, name),
        *publisher_step_run_errors(path, step, name),
    ]


def updater_publisher_profile_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Fail closed if the write-capable publisher differs from its reviewed profile."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [f"{path}: updater publisher profile requires jobs to be a mapping"]
    publisher = jobs.get("publisher")
    if not isinstance(publisher, dict):
        return [f"{path}: updater publisher profile requires a publisher job mapping"]

    errors = publisher_job_setting_errors(path, publisher)

    steps = publisher.get("steps")
    if not isinstance(steps, list):
        return [*errors, f"{path}: updater publisher steps must be a list"]
    expected_names = [name for name, _keys in UPDATER_PUBLISHER_STEP_PROFILE]
    actual_names = [
        step.get("name") if isinstance(step, dict) else None for step in steps
    ]
    if actual_names != expected_names:
        return [
            *errors,
            f"{path}: updater publisher steps must match the reviewed order and count",
        ]

    for step, (name, expected_keys) in zip(steps, UPDATER_PUBLISHER_STEP_PROFILE):
        assert isinstance(step, dict)
        errors.extend(publisher_step_profile_errors(path, step, name, expected_keys))
    return errors


def updater_outcome_profile_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Fail closed unless the terminal updater status job stays read-only and exact."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [f"{path}: updater outcome profile requires jobs to be a mapping"]
    outcome = jobs.get("outcome")
    if not isinstance(outcome, dict):
        return [f"{path}: updater outcome profile requires an outcome job mapping"]

    errors: list[str] = []
    if set(outcome) != UPDATER_OUTCOME_JOB_KEYS:
        errors.append(f"{path}: updater outcome must match its reviewed key profile")
    if outcome.get("runs-on") != "ubuntu-latest":
        errors.append(f"{path}: updater outcome must use the reviewed runner")
    if outcome.get("timeout-minutes") != 5:
        errors.append(f"{path}: updater outcome must use the reviewed timeout")
    if outcome.get("env") != UPDATER_OUTCOME_ENV_VALUES:
        errors.append(
            f"{path}: updater outcome must use reviewed terminal-state inputs"
        )
    steps = outcome.get("steps")
    if not isinstance(steps, list) or len(steps) != 1 or not isinstance(steps[0], dict):
        return [
            *errors,
            f"{path}: updater outcome must have exactly one reviewed report step",
        ]
    step = steps[0]
    if (
        set(step) != STEP_KEYS_RUN
        or step.get("name") != STEP_REPORT_WORKFLOW_TOOL_OUTCOME
    ):
        errors.append(f"{path}: updater outcome step must match the reviewed profile")
    run = step.get("run")
    if (
        not isinstance(run, str)
        or publisher_body_digest(run) != UPDATER_OUTCOME_RUN_SHA256
    ):
        errors.append(
            f"{path}: updater outcome must match the reviewed fail-closed report"
        )
    return errors


def workflow_tool_updater_errors(
    path: Path, text: str, data: dict[str, Any]
) -> list[str]:
    """Enforce resolver/validator/publisher separation for the CI updater."""

    if path.name != WORKFLOW_TOOL_UPDATER:
        return []

    errors: list[str] = []
    errors.extend(updater_read_only_job_errors(path, data))
    errors.extend(updater_job_topology_errors(path, data))
    errors.extend(updater_ordering_errors(path, data))
    errors.extend(updater_trigger_errors(path, data))
    errors.extend(updater_publisher_profile_errors(path, data))
    errors.extend(updater_outcome_profile_errors(path, data))
    resolver = job_text(text, "resolver")
    validator = job_text(text, "validator")
    errors.extend(
        require_workflow_text(
            path,
            "resolver",
            resolver,
            (
                "contents: read",
                "resolve --root . --github-output",
                "resolver_status",
                "candidate_sha256",
                CHECKOUT_WITHOUT_PERSISTED_CREDENTIALS,
                CHECKOUT_WITHOUT_SUBMODULES,
            ),
        )
    )
    errors.extend(
        require_workflow_text(
            path,
            "validator",
            validator,
            (
                "contents: read",
                "--candidate-b64",
                "--expected-candidate-sha256",
                "--require-updates",
                "HAS_UPDATES",
                "--verify-tool-assets",
                CHECKOUT_WITHOUT_PERSISTED_CREDENTIALS,
                CHECKOUT_WITHOUT_SUBMODULES,
            ),
        )
    )
    return errors


def submodule_updater_metadata_errors(
    path: Path, text: str, data: dict[str, Any]
) -> list[str]:
    """Validate top-level controls for the MRTS updater."""

    errors: list[str] = []
    expected_environment = {
        "SUBMODULE_PATH": "tools/MRTS",
        "SUBMODULE_URL": "https://github.com/Easton97-Jens/MRTS.git",
        "SUBMODULE_REF": "refs/heads/main",
        "UPDATE_BRANCH": "automation/update-framework-mrts-submodule",
        "UPDATE_TITLE": "chore: update MRTS submodule",
    }
    if data.get("permissions") != {"contents": "read"}:
        errors.append(f"{path}: MRTS updater must be top-level contents: read")
    if data.get("env") != expected_environment:
        errors.append(f"{path}: MRTS updater must use the reviewed environment")
    if "pull_request:" in text or "pull_request_target:" in text:
        errors.append(f"{path}: MRTS updater must not run from a pull request")
    if "--force" in text:
        errors.append(f"{path}: MRTS updater must not force-push")
    return errors


def submodule_updater_jobs(
    path: Path, data: dict[str, Any]
) -> tuple[list[str], dict[str, Any] | None]:
    """Return the fixed MRTS updater job topology or its errors."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [f"{path}: MRTS updater jobs must be a mapping"], None
    expected_jobs = {
        "resolve-submodule-update",
        "validate-submodule-update",
        "create-submodule-update-pr",
    }
    if set(jobs) != expected_jobs:
        return [f"{path}: MRTS updater jobs must match the reviewed topology"], None
    return [], jobs


def submodule_updater_reader_job_errors(
    path: Path, text: str, jobs: dict[str, Any]
) -> list[str]:
    """Keep resolver and validator jobs read-only and credential-free."""

    errors: list[str] = []
    for job_name in ("resolve-submodule-update", "validate-submodule-update"):
        job = jobs[job_name]
        if not isinstance(job, dict):
            errors.append(f"{path}: {job_name} must be a job mapping")
            continue
        if job.get("permissions") != {"contents": "read"}:
            errors.append(f"{path}: {job_name} must remain contents: read")
        if job.get("runs-on") != "ubuntu-latest":
            errors.append(f"{path}: {job_name} must use the reviewed runner")
        reader_text = job_text(text, job_name)
        if reader_text is not None and any(
            reference in reader_text
            for reference in ("github.token", "GH_TOKEN:", "PUBLISH_TOKEN:", "secrets.")
        ):
            errors.append(f"{path}: {job_name} must remain credential-free")
    return errors


def submodule_updater_validator_errors(path: Path, jobs: dict[str, Any]) -> list[str]:
    """Bind the validator to immutable resolver output."""

    validator = jobs["validate-submodule-update"]
    if (
        isinstance(validator, dict)
        and validator.get("needs") != "resolve-submodule-update"
    ):
        return [f"{path}: MRTS validator must depend on the resolver"]
    return []


def submodule_updater_publisher_errors(path: Path, jobs: dict[str, Any]) -> list[str]:
    """Validate publisher permissions, dependencies, and execution gate."""

    errors: list[str] = []
    publisher = jobs["create-submodule-update-pr"]
    if not isinstance(publisher, dict):
        return [f"{path}: MRTS publisher must be a job mapping"]
    canonical_publisher = json.dumps(
        publisher, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    if hashlib.sha256(canonical_publisher.encode("utf-8")).hexdigest() != (
        SUBMODULE_UPDATER_PUBLISHER_SHA256
    ):
        errors.append(
            f"{path}: MRTS publisher must exactly match the reviewed write-capable profile"
        )
    if publisher.get("permissions") != {
        "contents": "write",
        "pull-requests": "write",
    }:
        errors.append(
            f"{path}: MRTS publisher must use only reviewed write permissions"
        )
    if publisher.get("needs") != [
        "resolve-submodule-update",
        "validate-submodule-update",
    ]:
        errors.append(f"{path}: MRTS publisher must depend on resolver and validator")
    publisher_gate = publisher.get("if")
    if not isinstance(publisher_gate, str) or (
        DEFAULT_BRANCH_REF_CONDITION not in publisher_gate
        or "needs.resolve-submodule-update.outputs.changed == 'true'"
        not in publisher_gate
        or "needs.validate-submodule-update.result == 'success'" not in publisher_gate
    ):
        errors.append(
            f"{path}: MRTS publisher must be default-branch and validation gated"
        )
    return errors


def submodule_updater_errors(path: Path, text: str, data: dict[str, Any]) -> list[str]:
    """Enforce the Framework-only MRTS gitlink updater boundary."""

    if path.name != SUBMODULE_UPDATER:
        return []

    errors = submodule_updater_metadata_errors(path, text, data)
    topology_errors, jobs = submodule_updater_jobs(path, data)
    errors.extend(topology_errors)
    if jobs is None:
        return errors
    errors.extend(submodule_updater_reader_job_errors(path, text, jobs))
    errors.extend(submodule_updater_validator_errors(path, jobs))
    errors.extend(submodule_updater_publisher_errors(path, jobs))
    errors.extend(
        job_requirement_errors(
            path,
            text,
            {
                "resolve-submodule-update": (
                    'git ls-remote --exit-code "$SUBMODULE_URL" "$SUBMODULE_REF"',
                    'git ls-tree HEAD -- "$SUBMODULE_PATH"',
                    "candidate_sha=%s",
                    "changed=false",
                    "changed=true",
                ),
                "validate-submodule-update": (
                    CHECKOUT_WITHOUT_SUBMODULES,
                    CHECKOUT_WITHOUT_PERSISTED_CREDENTIALS,
                    "--require-hashes -r requirements-ci.lock",
                    'git submodule update --init -- "$SUBMODULE_PATH"',
                    'git -C "$SUBMODULE_PATH" checkout --detach "$CANDIDATE_SHA"',
                    "quick-check",
                ),
                "create-submodule-update-pr": (
                    CHECKOUT_WITHOUT_PERSISTED_CREDENTIALS,
                    'git update-index --add --cacheinfo "160000,$CANDIDATE_SHA,$SUBMODULE_PATH"',
                    'git push origin "HEAD:refs/heads/$UPDATE_BRANCH"',
                    "--draft",
                    "staged maintenance update changes paths outside $SUBMODULE_PATH",
                    "existing MRTS maintenance branch changes paths outside $SUBMODULE_PATH",
                ),
            },
        )
    )
    return errors


def common_version_trigger_errors(path: Path, data: dict[str, Any]) -> list[str]:
    events = workflow_events(data)
    if not isinstance(events, dict) or set(events) != {"workflow_dispatch", "schedule"}:
        return [
            f"{path}: common-version maintenance must be scheduled/manual only with no other trigger"
        ]
    if not isinstance(events.get("schedule"), list) or not events["schedule"]:
        return [f"{path}: common-version maintenance must declare a schedule"]
    if events.get("workflow_dispatch") != {"inputs": COMMON_VERSION_DISPATCH_INPUTS}:
        return [
            f"{path}: common-version maintenance must expose only the reviewed optional component dispatch input"
        ]
    return []


def common_version_jobs(
    path: Path, data: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[str]]:
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != COMMON_VERSION_JOB_NAMES:
        return None, [
            f"{path}: common-version maintenance must define exactly canonical-maintenance, candidate, reconcile-trusted, publish, and result jobs"
        ]
    return jobs, []


def common_version_reader_errors(path: Path, resolve: Any, candidate: Any) -> list[str]:
    errors: list[str] = []
    for job_name, job in (("resolve", resolve), ("candidate-validate", candidate)):
        if not isinstance(job, dict):
            continue
        if job.get("permissions") != COMMON_VERSION_READER_PERMISSIONS:
            errors.append(
                f"{path}: common-version {job_name} job must remain contents: read only"
            )
        if sensitive_reference_paths(job):
            errors.append(
                f"{path}: common-version {job_name} job must not declare a GitHub token or secret"
            )
    return errors


def common_version_checkout_errors(
    path: Path, job_name: str, steps: Iterable[dict[str, Any]]
) -> list[str]:
    checkout_steps = [
        step
        for step in steps
        if isinstance(step.get("uses"), str)
        and step["uses"].split("@", 1)[0] == CHECKOUT_ACTION
    ]
    if len(checkout_steps) != 1:
        return [
            f"{path}: common-version {job_name} job must use exactly one trusted default-revision checkout"
        ]
    checkout = checkout_steps[0].get("with")
    if not isinstance(checkout, dict) or any(
        checkout.get(key) != expected
        for key, expected in {
            "ref": DEFAULT_BRANCH_EXPRESSION,
            "fetch-depth": 1,
            "persist-credentials": False,
            "submodules": False,
        }.items()
    ):
        return [
            f"{path}: common-version {job_name} checkout must be pinned to the trusted default revision without credentials or submodules"
        ]
    return []


def common_version_resolver_component_errors(path: Path, resolve: Any) -> list[str]:
    resolve_steps = resolve.get("steps") if isinstance(resolve, dict) else None
    resolver_steps = (
        [
            step
            for step in resolve_steps
            if isinstance(step, dict)
            and step.get("name") == STEP_RESOLVE_EPHEMERAL_COMMON_SH_CANDIDATE
        ]
        if isinstance(resolve_steps, list)
        else []
    )
    if len(resolver_steps) != 1 or resolver_steps[0].get("env") != {
        "REQUESTED_COMPONENT": "${{ inputs.component }}"
    }:
        return [
            f"{path}: common-version resolver must pass the optional dispatch component only through its reviewed environment"
        ]
    return []


def common_version_candidate_errors(
    path: Path, resolve: Any, candidate: Any, resolve_run: str, candidate_run: str
) -> list[str]:
    errors: list[str] = []
    if (
        not isinstance(resolve, dict)
        or resolve.get("outputs") != COMMON_VERSION_RESOLVER_OUTPUTS
    ):
        errors.append(
            f"{path}: common-version resolver must expose only the reviewed maintenance outputs"
        )
    if not isinstance(candidate, dict) or normalized_needs(candidate.get("needs")) != {
        "resolve"
    }:
        errors.append(f"{path}: common-version candidate job must need resolve only")
    if (
        isinstance(candidate, dict)
        and candidate.get("env") != COMMON_VERSION_CANDIDATE_ENV
    ):
        errors.append(
            f"{path}: common-version candidate job must use the reviewed resolver-bound environment"
        )
    errors.extend(common_version_resolver_component_errors(path, resolve))
    candidate_if = candidate.get("if") if isinstance(candidate, dict) else None
    if (
        not isinstance(candidate_if, str)
        or RESOLVER_UPDATE_AVAILABLE_CONDITION not in candidate_if
    ):
        errors.append(
            f"{path}: common-version candidate job must be gated on an available resolver update"
        )
    resolver_requirements = (
        'cp ci/lib/common.sh "$BUILD_ROOT/common.sh"',
        '--common-sh "$BUILD_ROOT/common.sh"',
        "--update",
        "--defer-reviewed-provenance",
        "candidate_sha256 = hashlib.sha256(candidate).hexdigest()",
        "maintenance_outcome",
        "manual_review_required",
        "manual_review_components_b64",
        "automatic_update_variables_b64",
        "manual_review_pins_sha256",
        '"update_available": str(safe_updates).lower()',
        "component_args=()",
        'component_args+=(--component "$REQUESTED_COMPONENT")',
        '"${component_args[@]}"',
        "resolver_exit=0",
        "|| resolver_exit=$?",
        'cp "$BUILD_ROOT/results/common-version-check/summary.md"',
        "Common-version resolver diagnostic",
        "::error title=Common-version resolver failed for",
        "if (( resolver_exit != 0 )); then",
        'exit "$resolver_exit"',
    )
    if any(requirement not in resolve_run for requirement in resolver_requirements):
        errors.append(
            f"{path}: common-version resolver must update only an ephemeral candidate and emit its SHA-256"
        )
    candidate_requirements = (
        'cp ci/lib/common.sh "$BUILD_ROOT/common.sh"',
        '--common-sh "$BUILD_ROOT/common.sh"',
        "--update",
        "--defer-reviewed-provenance",
        'candidate_sha256="$(sha256sum "$BUILD_ROOT/common.sh"',
        CANDIDATE_SHA256_LENGTH_CHECK,
        'test "$candidate_sha256" = "$CANDIDATE_SHA256"',
        "candidate validator maintenance outcome mismatch",
        "candidate validator manual components mismatch",
        "candidate validator automatic variables mismatch",
        "candidate validator manual-pin proof mismatch",
        "candidate validator candidate SHA-256 mismatch",
        '"$TOOLS_DIR/shellcheck" -x "$BUILD_ROOT/common.sh"',
        "tests.security_regression.test_common_version_atomic_provenance",
        "candidate_validated=true",
    )
    if any(requirement not in candidate_run for requirement in candidate_requirements):
        errors.append(
            f"{path}: common-version candidate job must independently validate the expected ephemeral candidate"
        )
    return errors


def common_version_publisher_gate_errors(path: Path, publish: Any) -> list[str]:
    if not isinstance(publish, dict):
        return [f"{path}: common-version publisher must be a mapping"]
    errors: list[str] = []
    if publish.get("permissions") != COMMON_VERSION_PUBLISHER_PERMISSIONS:
        errors.append(
            f"{path}: common-version publisher native permissions must remain contents: read only"
        )
    if normalized_needs(publish.get("needs")) != {"resolve", "candidate-validate"}:
        errors.append(f"{path}: common-version publisher must need both prior jobs")
    if publish.get("if") != COMMON_VERSION_PUBLISHER_IF:
        errors.append(
            f"{path}: common-version publisher must use the reviewed trusted-repository/default-ref/update gate"
        )
    return errors


def common_version_publisher_profile_errors(
    path: Path, data: dict[str, Any]
) -> list[str]:
    """Fail closed if the App-token publisher differs from its reviewed profile."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return [
            f"{path}: common-version publisher profile requires jobs to be a mapping"
        ]
    publish = jobs.get("publish")
    if not isinstance(publish, dict):
        return [
            f"{path}: common-version publisher profile requires a publish job mapping"
        ]

    errors = common_version_publisher_job_setting_errors(path, publish)

    steps = publish.get("steps")
    if not isinstance(steps, list):
        return [*errors, f"{path}: common-version publisher steps must be a list"]
    expected_names = [name for name, _keys in COMMON_VERSION_PUBLISHER_STEP_PROFILE]
    actual_names = [
        step.get("name") if isinstance(step, dict) else None for step in steps
    ]
    if actual_names != expected_names:
        return [
            *errors,
            f"{path}: common-version publisher steps must match the reviewed order and count",
        ]

    for step, (name, expected_keys) in zip(
        steps, COMMON_VERSION_PUBLISHER_STEP_PROFILE
    ):
        assert isinstance(step, dict)
        errors.extend(
            common_version_publisher_step_profile_errors(
                path, step, name, expected_keys
            )
        )
    return errors


def common_version_publisher_job_setting_errors(
    path: Path, publish: dict[str, Any]
) -> list[str]:
    """Validate the static publisher job settings before inspecting its steps."""

    errors: list[str] = []
    if set(publish) != COMMON_VERSION_PUBLISHER_JOB_KEYS:
        errors.append(
            f"{path}: common-version publisher job must match its reviewed key profile"
        )
    if publish.get("runs-on") != "ubuntu-latest":
        errors.append(f"{path}: common-version publisher must use the reviewed runner")
    if publish.get("timeout-minutes") != 30:
        errors.append(f"{path}: common-version publisher must use the reviewed timeout")
    if publish.get("env") != COMMON_VERSION_PUBLISHER_ENV:
        errors.append(
            f"{path}: common-version publisher must use only the reviewed candidate environment"
        )
    if publish.get("outputs") != COMMON_VERSION_PUBLISHER_OUTPUTS:
        errors.append(
            f"{path}: common-version publisher must expose only the reviewed Draft pull request outputs"
        )
    return errors


def common_version_publisher_step_profile_errors(
    path: Path, step: dict[str, Any], name: str, expected_keys: frozenset[str]
) -> list[str]:
    """Validate one exact-profile Common-version publisher step."""

    errors = common_version_publisher_step_key_errors(path, step, name, expected_keys)

    errors.extend(common_version_publisher_step_action_errors(path, step, name))

    errors.extend(common_version_publisher_step_with_errors(path, step, name))
    expected_environment = COMMON_VERSION_PUBLISHER_ENV_VALUES.get(name)
    if expected_environment is not None and step.get("env") != expected_environment:
        errors.append(
            f"{path}: common-version publisher step {name!r} must use the reviewed environment"
        )

    for field, expected_value in COMMON_VERSION_PUBLISHER_FIELD_VALUES.get(
        name, {}
    ).items():
        if step.get(field) != expected_value:
            errors.append(
                f"{path}: common-version publisher step {name!r} must use the reviewed {field}"
            )

    expected_run_digest = COMMON_VERSION_PUBLISHER_RUN_SHA256.get(name)
    if expected_run_digest is not None:
        run = step.get("run")
        if not isinstance(run, str) or (
            publisher_body_digest(run) != expected_run_digest
        ):
            errors.append(
                f"{path}: common-version publisher run body {name!r} must match the reviewed SHA-256"
            )
    return errors


def common_version_publisher_step_key_errors(
    path: Path, step: dict[str, Any], name: str, expected_keys: frozenset[str]
) -> list[str]:
    """Validate the reviewed key set for one publisher step."""

    if set(step) == expected_keys:
        return []
    return [
        f"{path}: common-version publisher step {name!r} must match its reviewed key profile"
    ]


def common_version_publisher_step_action_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    """Validate a reviewed Action reference when the step uses one."""

    expected_action = COMMON_VERSION_PUBLISHER_ACTIONS.get(name)
    if expected_action is None:
        return []
    uses = step.get("uses")
    action_name = uses.split("@", 1)[0] if isinstance(uses, str) else None
    if action_name == expected_action:
        return []
    return [
        f"{path}: common-version publisher step {name!r} must use {expected_action}"
    ]


def common_version_publisher_state_check_with_errors(
    path: Path, name: str, with_values: dict[str, Any]
) -> list[str]:
    """Bind GitHub-script state checks to the scoped token and reviewed script."""

    expected_script_digest = COMMON_VERSION_PUBLISHER_SCRIPT_SHA256.get(name)
    if expected_script_digest is None:
        return []

    errors: list[str] = []
    if with_values.get("github-token") != WORKFLOW_UPDATER_APP_TOKEN_EXPRESSION:
        errors.append(
            f"{path}: common-version state check must use only the scoped GitHub App token"
        )
    script = with_values.get("script")
    if (
        not isinstance(script, str)
        or publisher_body_digest(script) != expected_script_digest
    ):
        errors.append(
            f"{path}: common-version state-check script must match the reviewed SHA-256"
        )
    return errors


def common_version_publisher_step_with_errors(
    path: Path, step: dict[str, Any], name: str
) -> list[str]:
    """Validate the reviewed Action-input profile for one publisher step."""

    expected_with_keys = COMMON_VERSION_PUBLISHER_WITH_KEYS.get(name)
    if expected_with_keys is None:
        return []

    errors: list[str] = []
    with_values = step.get("with")
    if not isinstance(with_values, dict) or set(with_values) != expected_with_keys:
        errors.append(
            f"{path}: common-version publisher step {name!r} must match the reviewed with profile"
        )
        with_values = {}
    expected_with_values = COMMON_VERSION_PUBLISHER_WITH_VALUES.get(name)
    if expected_with_values is not None and with_values != expected_with_values:
        errors.append(
            f"{path}: common-version publisher step {name!r} must use reviewed with values"
        )
    errors.extend(
        common_version_publisher_state_check_with_errors(path, name, with_values)
    )
    return errors


def common_version_result_errors(path: Path, result: Any) -> list[str]:
    """Require a credential-free, fail-closed terminal outcome job."""

    if not isinstance(result, dict):
        return [f"{path}: common-version result job must be a mapping"]

    errors = common_version_result_job_setting_errors(path, result)

    steps = result.get("steps")
    if not isinstance(steps, list):
        return [*errors, f"{path}: common-version result steps must be a list"]
    expected_names = [name for name, _keys in COMMON_VERSION_RESULT_STEP_PROFILE]
    actual_names = [
        step.get("name") if isinstance(step, dict) else None for step in steps
    ]
    if actual_names != expected_names:
        return [
            *errors,
            f"{path}: common-version result steps must match the reviewed order and count",
        ]
    for step, (name, expected_keys) in zip(steps, COMMON_VERSION_RESULT_STEP_PROFILE):
        assert isinstance(step, dict)
        if set(step) != expected_keys:
            errors.append(
                f"{path}: common-version result step {name!r} must match its reviewed key profile"
            )
        run = step.get("run")
        expected_digest = COMMON_VERSION_RESULT_RUN_SHA256[name]
        if not isinstance(run, str) or publisher_body_digest(run) != expected_digest:
            errors.append(
                f"{path}: common-version result run body {name!r} must match the reviewed SHA-256"
            )
    return errors


def common_version_result_job_setting_errors(
    path: Path, result: dict[str, Any]
) -> list[str]:
    """Validate the static credential-free terminal-job profile."""

    errors: list[str] = []
    if set(result) != COMMON_VERSION_RESULT_JOB_KEYS:
        errors.append(
            f"{path}: common-version result job must match its reviewed key profile"
        )
    if normalized_needs(result.get("needs")) != COMMON_VERSION_RESULT_NEEDS:
        errors.append(
            f"{path}: common-version result job must need resolver, validator, and publisher"
        )
    if result.get("if") != ALWAYS_CONDITION:
        errors.append(f"{path}: common-version result job must always run")
    if result.get("runs-on") != "ubuntu-latest":
        errors.append(f"{path}: common-version result job must use the reviewed runner")
    if result.get("timeout-minutes") != 5:
        errors.append(
            f"{path}: common-version result job must use the reviewed timeout"
        )
    if result.get("permissions") != COMMON_VERSION_READER_PERMISSIONS:
        errors.append(
            f"{path}: common-version result job must remain contents: read only"
        )
    if result.get("env") != COMMON_VERSION_RESULT_ENV:
        errors.append(
            f"{path}: common-version result job must use the reviewed non-secret environment"
        )
    if sensitive_reference_paths(result):
        errors.append(
            f"{path}: common-version result job must not declare a GitHub token or secret"
        )
    return errors


def common_version_unexpected_sensitive_errors(
    path: Path, data: dict[str, Any]
) -> list[str]:
    if (
        frozenset(sensitive_reference_paths(data))
        != COMMON_VERSION_EXPECTED_SENSITIVE_PATHS
    ):
        return [
            f"{path}: common-version publisher may reference the App secret only in the reviewed configuration gate and App-token action"
        ]
    return []


def common_version_maintenance_errors(path: Path, data: dict[str, Any]) -> list[str]:
    if path.name != COMMON_VERSION_WORKFLOW:
        return []

    errors = common_version_strict_profile_errors(path, data)
    return errors


def _common_version_profile_errors(path: Path, jobs: dict[str, Any]) -> list[str]:
    job_profiles = {
        "canonical-maintenance": {
            "runs-on",
            "timeout-minutes",
            "permissions",
            "outputs",
            "steps",
        },
        "candidate": {
            "needs",
            "if",
            "runs-on",
            "timeout-minutes",
            "permissions",
            "outputs",
            "steps",
        },
        "reconcile-trusted": {
            "needs",
            "if",
            "runs-on",
            "timeout-minutes",
            "permissions",
            "steps",
        },
        "publish": {
            "needs",
            "if",
            "runs-on",
            "timeout-minutes",
            "permissions",
            "steps",
        },
        "result": {"needs", "if", "runs-on", "timeout-minutes", "permissions", "steps"},
    }
    step_profiles = {
        "canonical-maintenance": [
            (STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION, {"name", "uses", "with"}),
            (STEP_SETUP_REVIEWED_PYTHON, {"name", "uses", "with"}),
            (
                "Resolve mandatory global and selected runtime scopes",
                {"name", "id", "env", "run"},
            ),
            ("Validate review issue reconciliation without writes", {"name", "run"}),
            ("Retain caller-bound canonical maintenance plan", {"name", "uses", "with"}),
        ],
        "candidate": [
            (STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION, {"name", "uses", "with"}),
            (STEP_SETUP_REVIEWED_PYTHON, {"name", "uses", "with"}),
            ("Download caller-bound canonical maintenance plan", {"name", "uses", "with"}),
            (
                "Validate and apply caller-bound canonical plan",
                {"name", "env", "run"},
            ),
            (
                "Validate candidate path policy and focused controls",
                {"name", "id", "run"},
            ),
        ],
        "reconcile-trusted": [
            (STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION, {"name", "uses", "with"}),
            (STEP_SETUP_REVIEWED_PYTHON, {"name", "uses", "with"}),
            ("Download caller-bound canonical maintenance plan", {"name", "uses", "with"}),
            ("Validate caller-bound canonical maintenance plan", {"name", "env", "run"}),
            ("Require distinct review-issue App configuration", {"name", "env", "run"}),
            (STEP_MINT_ISSUE_RECONCILER_APP_TOKEN, {"name", "id", "uses", "with"}),
            (
                "Reconcile review issues from caller-bound plan on trusted default branch",
                {"name", "env", "run"},
            ),
        ],
        "publish": [
            (STEP_CHECKOUT_TRUSTED_DEFAULT_REVISION, {"name", "uses", "with"}),
            (STEP_SETUP_REVIEWED_PYTHON, {"name", "uses", "with"}),
            ("Download caller-bound canonical maintenance plan", {"name", "uses", "with"}),
            ("Validate and apply caller-bound canonical plan", {"name", "env", "run"}),
            ("Require publisher App configuration", {"name", "env", "run"}),
            (STEP_MINT_PUBLISHER_APP_TOKEN, {"name", "id", "uses", "with"}),
            (
                "Create or update Draft PR from the full generated allowlist",
                {"name", "uses", "with"},
            ),
        ],
        "result": [
            (
                "Summarize outcome, updates, reviews, issues, PR, and fatal findings",
                {"name", "env", "run"},
            )
        ],
    }
    errors: list[str] = []
    for name, job in jobs.items():
        if not isinstance(job, dict):
            errors.append(f"{path}: common-version {name} job must be a mapping")
            continue
        if set(job) != job_profiles[name]:
            errors.append(f"{path}: common-version {name} job key profile changed")
        steps = job.get("steps")
        if not isinstance(steps, list) or len(steps) != len(step_profiles[name]):
            errors.append(f"{path}: common-version {name} step profile changed")
            continue
        for step, (expected_name, expected_keys) in zip(steps, step_profiles[name]):
            if (
                not isinstance(step, dict)
                or step.get("name") != expected_name
                or set(step) != expected_keys
            ):
                errors.append(
                    f"{path}: common-version {name} step profile changed at {expected_name!r}"
                )
    return errors


def _common_version_permission_errors(path: Path, jobs: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for name in ("canonical-maintenance", "candidate", "result"):
        job = jobs[name]
        if (
            not isinstance(job, dict)
            or job.get("permissions") != COMMON_VERSION_READER_PERMISSIONS
        ):
            errors.append(
                f"{path}: common-version {name} must have contents: read only"
            )
    reconcile = jobs["reconcile-trusted"]
    if (
        isinstance(reconcile, dict)
        and reconcile.get("permissions") != COMMON_VERSION_READER_PERMISSIONS
    ):
        errors.append(f"{path}: reconcile-trusted permission profile changed")
    publish = jobs["publish"]
    if (
        isinstance(publish, dict)
        and publish.get("permissions") != COMMON_VERSION_PUBLISHER_PERMISSIONS
    ):
        errors.append(f"{path}: publisher native permission profile changed")
    return errors


def _common_version_checkout_errors(
    path: Path, name: str, steps: list[Any]
) -> list[str]:
    checkouts = [
        step
        for step in steps
        if isinstance(step, dict)
        and str(step.get("uses", "")).split("@", 1)[0] == CHECKOUT_ACTION
    ]
    if len(checkouts) != 1:
        return [f"{path}: {name} must contain exactly one checkout"]
    expected = {
        "ref": DEFAULT_BRANCH_EXPRESSION,
        "fetch-depth": 1,
        "persist-credentials": False,
        "submodules": False,
    }
    if checkouts[0].get("with") != expected:
        return [
            f"{path}: {name} checkout must match the trusted default-revision profile"
        ]
    return []


def _common_version_action_reference_errors(
    path: Path, name: str, steps: list[Any]
) -> list[str]:
    errors: list[str] = []
    allowed_actions = {
        CHECKOUT_ACTION,
        SETUP_PYTHON_ACTION,
        UPLOAD_ARTIFACT.removesuffix("@"),
        DOWNLOAD_ARTIFACT.removesuffix("@"),
        WORKFLOW_UPDATER_APP_TOKEN_ACTION,
        CREATE_PULL_REQUEST_ACTION,
    }
    for step in steps:
        if not isinstance(step, dict) or "uses" not in step:
            continue
        reference = step["uses"]
        action = reference.split("@", 1)[0] if isinstance(reference, str) else ""
        if action not in allowed_actions:
            errors.append(f"{path}: {name} contains an unreviewed Action identity")
        elif (
            not isinstance(reference, str)
            or "@" not in reference
            or not SHA.fullmatch(reference.rsplit("@", 1)[1].split(" ", 1)[0])
        ):
            errors.append(
                f"{path}: {name} Action references must use a full immutable commit SHA"
            )
    return errors


def _common_version_action_errors(path: Path, jobs: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for name in ("canonical-maintenance", "candidate", "reconcile-trusted", "publish"):
        job = jobs[name]
        steps = job.get("steps", []) if isinstance(job, dict) else []
        errors.extend(_common_version_checkout_errors(path, name, steps))
        errors.extend(_common_version_action_reference_errors(path, name, steps))
    return errors


def _common_version_setup_errors(path: Path, jobs: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for name in ("canonical-maintenance", "candidate", "reconcile-trusted", "publish"):
        job = jobs[name]
        for step in job.get("steps", []) if isinstance(job, dict) else []:
            if not isinstance(step, dict):
                continue
            with_values = step.get("with")
            if str(step.get("uses", "")).split("@", 1)[
                0
            ] == SETUP_PYTHON_ACTION and with_values != {
                "python-version-file": CANONICAL_PYTHON_VERSION_FILE,
                "check-latest": False,
            }:
                errors.append(f"{path}: {name} setup-python profile changed")
    return errors


def _common_version_named_steps(job: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        return []
    return [
        step
        for step in job["steps"]
        if isinstance(step, dict) and step.get("name") == name
    ]


def _common_version_plan_artifact_errors(
    path: Path, jobs: dict[str, Any]
) -> list[str]:
    """Bind every downstream consumer to one immutable same-run plan artifact."""

    errors: list[str] = []
    uploads = _common_version_named_steps(
        jobs["canonical-maintenance"],
        "Retain caller-bound canonical maintenance plan",
    )
    if len(uploads) != 1:
        errors.append(f"{path}: canonical-maintenance must retain exactly one plan artifact")
    else:
        upload = uploads[0]
        with_values = upload.get("with")
        upload_paths = (
            tuple(
                line.strip()
                for line in with_values.get("path", "").splitlines()
                if line.strip()
            )
            if isinstance(with_values, dict)
            else ()
        )
        if (
            str(upload.get("uses", "")).split("@", 1)[0]
            != UPLOAD_ARTIFACT.removesuffix("@")
            or not isinstance(with_values, dict)
            or set(with_values) != {"name", "path", "retention-days", "if-no-files-found"}
            or with_values.get("name") != COMMON_VERSION_PLAN_ARTIFACT_NAME
            or upload_paths != COMMON_VERSION_PLAN_ARTIFACT_UPLOAD_PATHS
            or with_values.get("retention-days") != 1
            or with_values.get("if-no-files-found") != "error"
        ):
            errors.append(
                f"{path}: canonical-maintenance plan artifact profile changed"
            )

    for name, validation_step in (
        ("candidate", "Validate and apply caller-bound canonical plan"),
        ("reconcile-trusted", "Validate caller-bound canonical maintenance plan"),
        ("publish", "Validate and apply caller-bound canonical plan"),
    ):
        job = jobs[name]
        downloads = _common_version_named_steps(
            job, "Download caller-bound canonical maintenance plan"
        )
        if len(downloads) != 1:
            errors.append(f"{path}: {name} must download exactly one plan artifact")
            continue
        download = downloads[0]
        if (
            str(download.get("uses", "")).split("@", 1)[0]
            != DOWNLOAD_ARTIFACT.removesuffix("@")
            or download.get("with")
            != {
                "name": COMMON_VERSION_PLAN_ARTIFACT_NAME,
                "path": COMMON_VERSION_PLAN_ARTIFACT_DOWNLOAD_PATH,
            }
        ):
            errors.append(f"{path}: {name} plan artifact download profile changed")
        run_steps = _common_version_named_steps(job, validation_step)
        run = run_steps[0].get("run") if len(run_steps) == 1 else None
        if (
            not isinstance(run, str)
            or COMMON_VERSION_PLAN_JSON_RUN_PATH not in run
            or "--expected-plan-sha256" not in run
        ):
            errors.append(f"{path}: {name} must validate the downloaded plan digest")

    reconcile_text = job_run_text(jobs["reconcile-trusted"].get("steps", []))
    if "resolve-canonical-maintenance.py" in reconcile_text:
        errors.append(f"{path}: reconcile-trusted must not re-resolve live sources")
    for name in ("candidate", "reconcile-trusted", "publish"):
        downstream_text = job_run_text(jobs[name].get("steps", []))
        if "REQUESTED_COMPONENT" in downstream_text or "GITHUB_TOKEN" in downstream_text:
            errors.append(
                f"{path}: {name} must not receive live-resolution inputs or the read token"
            )
    return errors


def _common_version_run_step_errors(
    path: Path, name: str, steps: Any
) -> tuple[list[str], set[tuple[str, str]]]:
    if not isinstance(steps, list):
        return [
            f"{path}: {name} run steps must match the reviewed common-version profile"
        ], set()

    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    for step in steps:
        if not isinstance(step, dict) or "run" not in step:
            continue
        step_name = step.get("name")
        if not isinstance(step_name, str):
            errors.append(
                f"{path}: {name} run step {step_name!r} must match the reviewed "
                "hash-locked common-version profile"
            )
            continue
        key: tuple[str, str] = (name, step_name)
        expected = COMMON_VERSION_REVIEWED_RUN_SHA256.get(key)
        run = step.get("run")
        if (
            expected is None
            or not isinstance(run, str)
            or publisher_body_digest(run) != expected
        ):
            errors.append(
                f"{path}: {name} run step {step_name!r} must match the reviewed "
                "hash-locked common-version profile"
            )
            continue
        seen.add(key)
    return errors, seen


def _common_version_resolver_dependency_errors(
    path: Path, jobs: dict[str, Any]
) -> list[str]:
    """Bind every common-version run body so a resolver cannot be added elsewhere."""
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    for name in (
        "canonical-maintenance",
        "reconcile-trusted",
        "candidate",
        "publish",
        "result",
    ):
        job = jobs.get(name)
        steps = job.get("steps") if isinstance(job, dict) else None
        step_errors, step_seen = _common_version_run_step_errors(path, name, steps)
        errors.extend(step_errors)
        seen.update(step_seen)
    missing = set(COMMON_VERSION_REVIEWED_RUN_SHA256).difference(seen)
    if missing:
        errors.append(f"{path}: common-version workflow is missing a reviewed run step")
    return errors


def _common_version_token_reference_errors(
    path: Path, data: dict[str, Any]
) -> list[str]:
    allowed_sensitive_paths = frozenset(
        {
            ("jobs", "canonical-maintenance", "steps", "2", "env", "GITHUB_TOKEN"),
            ("jobs", "reconcile-trusted", "steps", "4", "env", "ISSUE_APP_PRIVATE_KEY"),
            ("jobs", "reconcile-trusted", "steps", "5", "with", "private-key"),
            ("jobs", "publish", "steps", "4", "env", "PUBLISHER_PRIVATE_KEY"),
            ("jobs", "publish", "steps", "5", "with", "private-key"),
        }
    )
    if (
        frozenset(tuple(item) for item in sensitive_reference_paths(data))
        != allowed_sensitive_paths
    ):
        return [
            f"{path}: common-version secret or token references are outside the reviewed read-token and App-token profiles"
        ]
    return []


def _common_version_job_token_errors(path: Path, jobs: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    job = jobs["canonical-maintenance"]
    steps = job.get("steps", []) if isinstance(job, dict) else []
    value = steps[2].get("env", {}).get("GITHUB_TOKEN") if len(steps) > 2 else None
    if value != GITHUB_TOKEN_EXPRESSION:
        errors.append(
            f"{path}: common-version read-token environment must use the exact github.token expression"
        )
    return errors


def _common_version_token_errors(
    path: Path, data: dict[str, Any], jobs: dict[str, Any]
) -> list[str]:
    return [
        *_common_version_token_reference_errors(path, data),
        *_common_version_job_token_errors(path, jobs),
    ]


def _common_version_canonical_candidate_errors(
    path: Path, jobs: dict[str, Any]
) -> list[str]:
    canonical = jobs["canonical-maintenance"]
    candidate = jobs["candidate"]
    errors: list[str] = []
    canonical_text = (
        job_run_text(canonical.get("steps", [])) if isinstance(canonical, dict) else ""
    )
    for required in (
        "REQUESTED_COMPONENT",
        "--component",
        "resolve-canonical-maintenance.py",
        "--check",
        "--plan",
        "global_inventory_complete",
        "plan_sha256",
    ):
        if required not in canonical_text:
            errors.append(f"{path}: canonical-maintenance missing {required!r}")
    if "--apply-safe-updates" in canonical_text:
        errors.append(f"{path}: canonical-maintenance must be read-only")
    if isinstance(canonical, dict) and set(canonical.get("outputs", {})) != {
        "plan_sha256",
        "maintenance_outcome",
        "safe_updates",
        "reviews",
        "fatal",
    }:
        errors.append(f"{path}: canonical-maintenance outputs changed")
    candidate_text = (
        job_run_text(candidate.get("steps", [])) if isinstance(candidate, dict) else ""
    )
    if (
        not isinstance(candidate, dict)
        or normalized_needs(candidate.get("needs")) != {"canonical-maintenance"}
        or "safe_updates" not in str(candidate.get("if", ""))
    ):
        errors.append(f"{path}: candidate must be gated by canonical safe updates")
    for required in (
        "--expected-plan-sha256",
        "--apply-safe-updates",
        "git diff --name-only",
        "git diff --check",
    ):
        if required not in candidate_text:
            errors.append(f"{path}: candidate missing {required!r}")
    return errors


def _common_version_reconcile_profile_text(reconcile: Any) -> str:
    reconcile_text = (
        job_run_text(reconcile.get("steps", [])) if isinstance(reconcile, dict) else ""
    )
    profile_text = reconcile_text + json.dumps(reconcile, sort_keys=True)
    if isinstance(reconcile, dict):
        for step in reconcile.get("steps", []):
            if (
                isinstance(step, dict)
                and step.get("name") == STEP_MINT_ISSUE_RECONCILER_APP_TOKEN
                and isinstance(step.get("with"), dict)
            ):
                profile_text += "\n" + "\n".join(
                    f"{key}: {value}" for key, value in sorted(step["with"].items())
                )
    return profile_text


def _common_version_reconcile_condition_errors(path: Path, reconcile: Any) -> list[str]:
    reconcile_if = str(reconcile.get("if", "")) if isinstance(reconcile, dict) else ""
    if (
        "github.event_name == 'schedule'" not in reconcile_if
        or "github.event_name == 'workflow_dispatch'" not in reconcile_if
        or DEFAULT_BRANCH_CONTEXT not in reconcile_if
    ):
        return [
            f"{path}: reconcile-trusted must be scheduled/manual and default-branch gated"
        ]
    return []


def _common_version_reconcile_required_errors(
    path: Path, profile_text: str
) -> list[str]:
    errors: list[str] = []
    for required in (
        "MAINTENANCE_ISSUE_APP_CLIENT_ID",
        "MAINTENANCE_ISSUE_APP_PRIVATE_KEY",
        "permission-issues: write",
        "--trusted-default-branch",
        "--apply",
        "--expected-plan-sha256",
    ):
        if required not in profile_text:
            errors.append(f"{path}: reconcile-trusted missing {required!r}")
    if (
        "WORKFLOW_UPDATER_APP" in profile_text
        or "permission-contents: write" in profile_text
    ):
        errors.append(
            f"{path}: reconcile-trusted may use only issue-reconciler credentials"
        )
    return errors


def _common_version_reconcile_token_errors(path: Path, reconcile: Any) -> list[str]:
    issue_token = next(
        (
            step
            for step in reconcile.get("steps", [])
            if isinstance(step, dict)
            and step.get("name") == STEP_MINT_ISSUE_RECONCILER_APP_TOKEN
        ),
        {},
    )
    if issue_token.get("with") != {
        "client-id": "${{ vars.MAINTENANCE_ISSUE_APP_CLIENT_ID }}",
        "private-key": "${{ secrets.MAINTENANCE_ISSUE_APP_PRIVATE_KEY }}",
        "owner": GITHUB_REPOSITORY_OWNER_EXPRESSION,
        "repositories": "${{ github.event.repository.name }}",
        "permission-issues": "write",
    }:
        return [f"{path}: reconcile-trusted App token input profile changed"]
    return []


def _common_version_reconcile_errors(path: Path, reconcile: Any) -> list[str]:
    profile_text = _common_version_reconcile_profile_text(reconcile)
    return [
        *_common_version_reconcile_condition_errors(path, reconcile),
        *_common_version_reconcile_required_errors(path, profile_text),
        *_common_version_reconcile_token_errors(path, reconcile),
    ]


def _common_version_publish_profile_text(publish: Any) -> tuple[str, str]:
    publish_text = (
        job_run_text(publish.get("steps", [])) if isinstance(publish, dict) else ""
    )
    profile_text = publish_text + json.dumps(publish, sort_keys=True)
    if isinstance(publish, dict):
        for step in publish.get("steps", []):
            if (
                isinstance(step, dict)
                and step.get("name") == STEP_MINT_PUBLISHER_APP_TOKEN
                and isinstance(step.get("with"), dict)
            ):
                profile_text += "\n" + "\n".join(
                    f"{key}: {value}" for key, value in sorted(step["with"].items())
                )
    return publish_text, profile_text


def _common_version_publish_dependency_errors(path: Path, publish: Any) -> list[str]:
    if not isinstance(publish, dict) or normalized_needs(publish.get("needs")) != {
        "canonical-maintenance",
        "candidate",
        "reconcile-trusted",
    }:
        return [f"{path}: publisher dependency profile changed"]
    return []


def _common_version_publish_required_errors(
    path: Path, publish: Any, publish_text: str, profile_text: str
) -> list[str]:
    publish_if = str(publish.get("if", "")) if isinstance(publish, dict) else ""
    errors: list[str] = []
    for required in (
        "github.repository == 'Easton97-Jens/ModSecurity-test-Framework'",
        DEFAULT_BRANCH_CONTEXT,
        "needs.candidate.result == 'success'",
        "WORKFLOW_UPDATER_APP_CLIENT_ID",
        "WORKFLOW_UPDATER_APP_PRIVATE_KEY",
        "permission-contents: write",
        "permission-pull-requests: write",
        "permission-workflows: write",
        "--expected-plan-sha256",
        "--apply-safe-updates",
    ):
        if required not in publish_if + profile_text:
            errors.append(f"{path}: publisher missing {required!r}")
    if any(
        token in publish_text.lower()
        for token in (
            "github.token",
            "secrets.github_token",
            "git push ",
            "git add .",
            "git add -a",
            "--force",
            "auto-merge: true",
            "auto-merge=true",
        )
    ):
        errors.append(
            f"{path}: publisher contains an unapproved token or merge/push control"
        )
    return errors


def _common_version_publish_token_errors(path: Path, publish: Any) -> list[str]:
    publisher_token = next(
        (
            step
            for step in publish.get("steps", [])
            if isinstance(step, dict)
            and step.get("name") == STEP_MINT_PUBLISHER_APP_TOKEN
        ),
        {},
    )
    if publisher_token.get("with") != {
        "client-id": "${{ vars.WORKFLOW_UPDATER_APP_CLIENT_ID }}",
        "private-key": "${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY }}",
        "owner": GITHUB_REPOSITORY_OWNER_EXPRESSION,
        "repositories": "${{ github.event.repository.name }}",
        "permission-contents": "write",
        "permission-pull-requests": "write",
        "permission-workflows": "write",
    }:
        return [f"{path}: publisher App token input profile changed"]
    return []


def _common_version_publish_pr_errors(path: Path, publish: Any) -> list[str]:
    create_pr = next(
        (
            step
            for step in publish.get("steps", [])
            if isinstance(step, dict)
            and step.get("name")
            == "Create or update Draft PR from the full generated allowlist"
        ),
        {},
    )
    create_pr_with = create_pr.get("with")
    expected_create_pr = {
        "token": "${{ steps.publisher_app_token.outputs.token }}",
        "commit-message": "chore(ci): update canonical maintenance pins",
        "title": "chore(ci): update canonical maintenance pins",
        "body-path": "${{ runner.temp }}/common-maintenance-pr-body.md",
        "branch": "automation/update-framework-common-versions",
        "base": DEFAULT_BRANCH_EXPRESSION,
        "delete-branch": False,
        "draft": True,
    }
    if (
        not isinstance(create_pr_with, dict)
        or set(create_pr_with) != {*expected_create_pr, "add-paths"}
        or any(
            create_pr_with.get(key) != value
            for key, value in expected_create_pr.items()
        )
    ):
        return [f"{path}: publisher Draft PR input profile changed"]
    add_paths = next(
        (
            step.get("with", {}).get("add-paths")
            for step in publish.get("steps", [])
            if isinstance(step, dict)
            and isinstance(step.get("with"), dict)
            and "add-paths" in step["with"]
        ),
        None,
    )
    actual_paths = (
        {line.strip() for line in add_paths.splitlines() if line.strip()}
        if isinstance(add_paths, str)
        else None
    )
    if actual_paths != set(COMMON_VERSION_GENERATED_PATHS):
        return [f"{path}: publisher generated-path allowlist changed"]
    return []


def _common_version_publish_errors(path: Path, publish: Any) -> list[str]:
    publish_text, profile_text = _common_version_publish_profile_text(publish)
    return [
        *_common_version_publish_dependency_errors(path, publish),
        *_common_version_publish_required_errors(
            path, publish, publish_text, profile_text
        ),
        *_common_version_publish_token_errors(path, publish),
        *_common_version_publish_pr_errors(path, publish),
    ]


def _common_version_result_profile_errors(path: Path, result: Any) -> list[str]:
    errors: list[str] = []
    if (
        not isinstance(result, dict)
        or result.get("if") != "${{ always() }}"
        or normalized_needs(result.get("needs"))
        != {"canonical-maintenance", "candidate", "reconcile-trusted", "publish"}
    ):
        errors.append(f"{path}: result must always summarize all maintenance stages")
    result_text = (
        job_run_text(result.get("steps", [])) if isinstance(result, dict) else ""
    )
    if (
        "GITHUB_STEP_SUMMARY" not in result_text
        or "OUTCOME" not in result_text
        or "FATAL" not in result_text
    ):
        errors.append(f"{path}: result must emit the terminal outcome summary")
    if isinstance(result, dict) and sensitive_reference_paths(result):
        errors.append(f"{path}: result must remain credential-free")
    return errors


def common_version_strict_profile_errors(path: Path, data: dict[str, Any]) -> list[str]:
    """Validate the unified maintenance workflow's closed security profile."""
    errors = common_version_trigger_errors(path, data)
    if data.get("permissions") != COMMON_VERSION_READER_PERMISSIONS:
        errors.append(
            f"{path}: common-version workflow must declare exactly {{contents: read}} top-level permissions"
        )
    jobs, job_errors = common_version_jobs(path, data)
    errors.extend(job_errors)
    if jobs is None:
        return errors
    errors.extend(_common_version_profile_errors(path, jobs))
    errors.extend(_common_version_permission_errors(path, jobs))
    errors.extend(_common_version_action_errors(path, jobs))
    errors.extend(_common_version_setup_errors(path, jobs))
    errors.extend(_common_version_plan_artifact_errors(path, jobs))
    errors.extend(_common_version_resolver_dependency_errors(path, jobs))
    errors.extend(_common_version_token_errors(path, data, jobs))
    errors.extend(_common_version_canonical_candidate_errors(path, jobs))
    errors.extend(_common_version_reconcile_errors(path, jobs["reconcile-trusted"]))
    errors.extend(_common_version_publish_errors(path, jobs["publish"]))
    errors.extend(_common_version_result_profile_errors(path, jobs["result"]))
    return errors


def forbidden_workflow_snippet_errors(
    path: Path, text: str, workflow_name: str, snippets: Iterable[str]
) -> list[str]:
    return [
        f"{path}: {workflow_name} workflow must not contain {snippet!r}"
        for snippet in snippets
        if snippet in text
    ]


def osv_scanner_evidence_errors(path: Path, text: str) -> list[str]:
    return [
        *job_requirement_errors(path, text, OSV_JOB_REQUIREMENTS),
        *forbidden_workflow_snippet_errors(path, text, "OSV", OSV_PROHIBITED_SNIPPETS),
    ]


def scorecard_pull_request_artifact_errors(path: Path, text: str) -> list[str]:
    pull_request = job_text(text, "pull-request-head")
    if pull_request is not None and UPLOAD_ARTIFACT in pull_request:
        return [f"{path}: pull-request Scorecard evidence must remain artifact-free"]
    return []


def scorecard_current_revision_errors(path: Path, text: str) -> list[str]:
    current_revision = job_text(text, "current-revision-advisory")
    if current_revision is not None and "continue-on-error" in current_revision:
        return [
            f"{path}: current-revision Scorecard evidence must fail on scanner errors"
        ]
    return []


def scorecard_evidence_errors(path: Path, text: str) -> list[str]:
    return [
        *job_requirement_errors(path, text, SCORECARD_JOB_REQUIREMENTS),
        *scorecard_pull_request_artifact_errors(path, text),
        *scorecard_current_revision_errors(path, text),
        *forbidden_workflow_snippet_errors(
            path, text, "Scorecard", (SECURITY_EVENTS_WRITE,)
        ),
    ]


def scanner_evidence_errors(path: Path, text: str) -> list[str]:
    if path.name == "ci-security-osv.yml":
        return osv_scanner_evidence_errors(path, text)
    if path.name == "ci-security-scorecard.yml":
        return scorecard_evidence_errors(path, text)
    return []


def top_level_permission_errors(path: Path, data: dict[str, Any]) -> list[str]:
    if "permissions" not in data:
        return [f"{path}: workflow must declare explicit top-level permissions"]
    return []


def codeql_tool_bundle_errors(path: Path, text: str) -> list[str]:
    if (
        path.name in {"ci-security-codeql.yml", "ci-security-codeql-pr.yml"}
        and "tools: linked" not in text
    ):
        return [f"{path}: CodeQL init must select the linked tool bundle"]
    return []


def run_shell_default_errors(path: Path, text: str, data: dict[str, Any]) -> list[str]:
    if "run:" in text and not run_shell_default(data):
        return [f"{path}: shell-running workflow must set defaults.run.shell to bash"]
    return []


def workflow_token_environment_errors(path: Path, data: dict[str, Any]) -> list[str]:
    environment = data.get("env")
    if isinstance(environment, dict) and "GITHUB_TOKEN" in environment:
        return [f"{path}: GITHUB_TOKEN must not be exposed at workflow scope"]
    return []


def workflow_metadata_errors(path: Path, text: str, data: dict[str, Any]) -> list[str]:
    return [
        *top_level_permission_errors(path, data),
        *concurrency_errors(path, data),
        *python_provisioning_errors(path, text),
        *python_version_maintenance_errors(path, data),
        *scanner_evidence_errors(path, text),
        *codeql_tool_bundle_errors(path, text),
        *run_shell_default_errors(path, text, data),
        *permission_errors(path, data),
        *workflow_token_environment_errors(path, data),
        *workflow_tool_updater_errors(path, text, data),
        *submodule_updater_errors(path, text, data),
        *common_version_maintenance_errors(path, data),
    ]


def checkout_safety_errors(path: Path, step: dict[str, Any]) -> list[str]:
    checkout = step.get("with")
    if not isinstance(checkout, dict):
        return [f"{path}: checkout step must declare safe checkout settings"]

    errors: list[str] = []
    if checkout.get("persist-credentials") is not False:
        errors.append(f"{path}: checkout must set persist-credentials: false")
    if checkout.get("submodules") is not False:
        errors.append(f"{path}: checkout must set submodules: false")
    return errors


def job_contract_errors(path: Path, job_name: str, job: Any) -> list[str]:
    if not isinstance(job, dict):
        return [f"{path}: job {job_name!r} must be a mapping"]

    errors: list[str] = []
    timeout = job.get("timeout-minutes")
    if type(timeout) is not int or timeout <= 0:
        errors.append(
            f"{path}: job {job_name!r} must set a positive integer timeout-minutes"
        )
    if isinstance(job.get("env"), dict) and "GITHUB_TOKEN" in job["env"]:
        errors.append(f"{path}: job {job_name!r} must not expose GITHUB_TOKEN")

    steps = job.get("steps", [])
    if not isinstance(steps, list):
        return errors
    for step in steps:
        if not isinstance(step, dict):
            continue
        reference = str(step.get("uses", ""))
        if reference.startswith(f"{CHECKOUT_ACTION}@"):
            errors.extend(checkout_safety_errors(path, step))
    return errors


def jobs_contract_errors(path: Path, data: dict[str, Any]) -> list[str]:
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return [f"{path}: workflow must define jobs"]

    errors: list[str] = []
    for job_name, job in jobs.items():
        errors.extend(job_contract_errors(path, str(job_name), job))
    return errors


def workflow_contract_errors(path: Path, text: str, data: Any) -> list[str]:
    errors = trust_boundary_errors(path, text)
    if not isinstance(data, dict):
        return [*errors, f"{path}: workflow must be a mapping"]
    errors.extend(workflow_metadata_errors(path, text, data))
    errors.extend(jobs_contract_errors(path, data))
    return errors


def configure_canonical_actions(root: Path) -> None:
    """Bind action identities from common.sh using the non-executing reader."""

    values = load_canonical_ci_pins(root)
    global OSV_LEGACY_BASE_SHA, OSV_LEGACY_BASE_VERSION
    if "CI_OSV_LEGACY_BASE_SHA" in values:
        OSV_LEGACY_BASE_SHA = values["CI_OSV_LEGACY_BASE_SHA"]
    if "CI_OSV_LEGACY_BASE_VERSION" in values:
        OSV_LEGACY_BASE_VERSION = values["CI_OSV_LEGACY_BASE_VERSION"]
    identities = {
        "checkout": canonical_action(values, "CHECKOUT"),
        "setup_python": canonical_action(values, "SETUP_PYTHON"),
        "github_script": canonical_action(values, "GITHUB_SCRIPT"),
        "app_token": canonical_action(values, "CREATE_GITHUB_APP_TOKEN"),
        "create_pr": canonical_action(values, "CREATE_PULL_REQUEST"),
        "upload_artifact": canonical_action(values, "UPLOAD_ARTIFACT"),
        "download_artifact": canonical_action(values, "DOWNLOAD_ARTIFACT"),
        "codeql": canonical_action(values, "CODEQL"),
    }
    global CHECKOUT_ACTION, SETUP_PYTHON_ACTION, SETUP_PYTHON_REFERENCE
    global GITHUB_SCRIPT_ACTION, WORKFLOW_UPDATER_APP_TOKEN_ACTION, UPLOAD_ARTIFACT
    global DOWNLOAD_ARTIFACT
    global CREATE_PULL_REQUEST_ACTION
    CHECKOUT_ACTION = identities["checkout"]
    SETUP_PYTHON_ACTION = identities["setup_python"]
    SETUP_PYTHON_REFERENCE = f"{SETUP_PYTHON_ACTION}@"
    GITHUB_SCRIPT_ACTION = identities["github_script"]
    WORKFLOW_UPDATER_APP_TOKEN_ACTION = identities["app_token"]
    UPLOAD_ARTIFACT = f"{identities['upload_artifact']}@"
    DOWNLOAD_ARTIFACT = f"{identities['download_artifact']}@"
    CREATE_PULL_REQUEST_ACTION = identities["create_pr"]
    REVIEWED_ACTION_RELEASE_RESOLUTIONS.clear()
    REVIEWED_ACTION_RELEASE_RESOLUTIONS[identities["codeql"]] = (
        ACTION_RELEASE_RESOLUTION_SAME_MAJOR
    )
    for requirements in (OSV_JOB_REQUIREMENTS, SCORECARD_JOB_REQUIREMENTS):
        for job_name, snippets in requirements.items():
            requirements[job_name] = tuple(
                identities["upload_artifact"] + "@"
                if item == "CI_ACTION_UPLOAD_ARTIFACT_REPOSITORY@"
                else item
                for item in snippets
            )
    COMMON_VERSION_PUBLISHER_ACTIONS[
        STEP_CREATE_OR_UPDATE_COMMON_VERSION_DRAFT_PULL_REQUEST
    ] = identities["create_pr"]
    PYTHON_PUBLISHER_ACTIONS[STEP_CREATE_OR_UPDATE_PYTHON_DRAFT_PULL_REQUEST] = (
        identities["create_pr"]
    )


def validate(root: Path, lock_path: Path) -> list[str]:
    try:
        configure_canonical_actions(root)
    except ValueError as exc:
        # Unit fixtures intentionally contain only a workflow/lock.  The real
        # checkout must provide common.sh and therefore fails closed there.
        if (root / "ci" / "lib" / "common.sh").exists():
            return [str(exc)]
    actions, _tools, errors = load_lock(lock_path)
    for path in workflow_paths(root):
        text = path.read_text(encoding="utf-8")
        try:
            data = load_yaml(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        errors.extend(pin_errors(path, text, actions))
        errors.extend(parsed_action_lock_errors(path, data, actions))
        errors.extend(workflow_contract_errors(path, text, data))
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[3]
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=Path("ci/tooling/security-tools.lock.yml"),
        help="Lock path that must resolve inside --root.",
    )
    return parser.parse_args()


def resolve_root_path(root: Path) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ValueError(
            f"{root}: --root must resolve to an existing directory"
        ) from exc
    if not resolved.is_dir():
        raise ValueError(f"{root}: --root must resolve to an existing directory")
    return resolved


def resolve_lock_path(root: Path, lock: Path) -> Path:
    candidate = lock if lock.is_absolute() else root / lock
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{lock}: --lock must resolve inside --root") from exc
    if not resolved.is_relative_to(root):
        raise ValueError(f"{lock}: --lock must resolve inside --root")
    if not resolved.is_file():
        raise ValueError(f"{lock}: --lock must resolve to a regular file")
    return resolved


def main() -> int:
    args = parse_args()
    try:
        root = resolve_root_path(args.root)
        lock_path = resolve_lock_path(root, args.lock)
    except ValueError as exc:
        print("CI security contract violations:")
        print(f"- {exc}")
        return 1
    errors = validate(root, lock_path)
    if errors:
        print("CI security contract violations:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print("CI security contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
